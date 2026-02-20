//! Predictive local echo engine.
//!
//! This module mirrors upstream mosh `terminaloverlay.cc` behavior closely:
//! - predictions are tied to transport frame numbers (`local_frame_sent + 1`)
//! - confirmation uses host late echo ack (`local_frame_late_acked`)
//! - tentative epochs gate risky predictions
//! - backspace/insert predictions follow mosh's non-overwrite model

use crate::terminal::{Cell, Framebuffer};
use std::time::{Duration, Instant};

/// Prediction display mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictionMode {
    /// Never predict.
    Never,
    /// Always display predictions.
    Always,
    /// Display predictions adaptively from timing heuristics.
    Adaptive,
}

impl Default for PredictionMode {
    fn default() -> Self {
        PredictionMode::Adaptive
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Validity {
    Pending,
    Correct,
    CorrectNoCredit,
    IncorrectOrExpired,
    Inactive,
}

// Matches upstream mosh prediction hysteresis.
const SRTT_TRIGGER_LOW_MS: u64 = 20;
const SRTT_TRIGGER_HIGH_MS: u64 = 30;
const FLAG_TRIGGER_LOW_MS: u64 = 50;
const FLAG_TRIGGER_HIGH_MS: u64 = 80;
const GLITCH_THRESHOLD_MS: u64 = 250;
const GLITCH_REPAIR_COUNT: u32 = 10;
const GLITCH_REPAIR_MIN_INTERVAL_MS: u64 = 150;
const GLITCH_FLAG_THRESHOLD_MS: u64 = 5000;

#[derive(Debug, Clone)]
struct PredictedCell {
    expiration_frame: u64,
    col: usize,
    active: bool,
    tentative_until_epoch: u64,
    prediction_time: Instant,
    replacement: Cell,
    unknown: bool,
    original_contents: Vec<Cell>,
}

impl PredictedCell {
    fn new(col: usize) -> Self {
        Self {
            expiration_frame: 0,
            col,
            active: false,
            tentative_until_epoch: 0,
            prediction_time: Instant::now(),
            replacement: Cell::default(),
            unknown: false,
            original_contents: Vec::new(),
        }
    }

    fn tentative(&self, confirmed_epoch: u64) -> bool {
        self.tentative_until_epoch > confirmed_epoch
    }

    fn reset(&mut self) {
        self.expiration_frame = 0;
        self.tentative_until_epoch = 0;
        self.active = false;
        self.unknown = false;
        self.original_contents.clear();
    }

    fn reset_with_orig(&mut self) {
        if !self.active || self.unknown {
            self.reset();
            return;
        }

        self.original_contents.push(self.replacement.clone());
        self.expiration_frame = 0;
        self.tentative_until_epoch = 0;
        self.active = false;
    }

    fn expire(&mut self, expiration_frame: u64, now: Instant) {
        self.expiration_frame = expiration_frame;
        self.prediction_time = now;
    }
}

#[derive(Debug, Clone)]
struct PredictedRow {
    row_num: usize,
    overlay_cells: Vec<PredictedCell>,
}

#[derive(Debug, Clone)]
struct PredictedCursor {
    expiration_frame: u64,
    row: usize,
    col: usize,
    active: bool,
    tentative_until_epoch: u64,
}

impl PredictedCursor {
    fn tentative(&self, confirmed_epoch: u64) -> bool {
        self.tentative_until_epoch > confirmed_epoch
    }

    fn expire(&mut self, expiration_frame: u64) {
        self.expiration_frame = expiration_frame;
    }
}

/// The prediction engine.
pub struct PredictionEngine {
    mode: PredictionMode,
    overlays: Vec<PredictedRow>,
    cursors: Vec<PredictedCursor>,
    local_frame_sent: u64,
    local_frame_acked: u64,
    local_frame_late_acked: u64,
    prediction_epoch: u64,
    confirmed_epoch: u64,
    send_interval_ms: u64,
    srtt_trigger: bool,
    flagging: bool,
    glitch_trigger: u32,
    last_quick_confirmation: Option<Instant>,
    esc_state: u8,
    width: usize,
    height: usize,
    last_width: usize,
    last_height: usize,
    predict_overwrite: bool,
}

impl PredictionEngine {
    pub fn new(mode: PredictionMode, width: usize, height: usize) -> Self {
        Self {
            mode,
            overlays: Vec::new(),
            cursors: Vec::new(),
            local_frame_sent: 0,
            local_frame_acked: 0,
            local_frame_late_acked: 0,
            prediction_epoch: 1,
            confirmed_epoch: 0,
            send_interval_ms: 250,
            srtt_trigger: false,
            flagging: false,
            glitch_trigger: 0,
            last_quick_confirmation: None,
            esc_state: 0,
            width,
            height,
            last_width: width,
            last_height: height,
            predict_overwrite: false,
        }
    }

    pub fn resize(&mut self, width: usize, height: usize) {
        self.width = width;
        self.height = height;
        self.last_width = width;
        self.last_height = height;
        self.reset();
    }

    pub fn reset(&mut self) {
        self.overlays.clear();
        self.cursors.clear();
        self.esc_state = 0;
        self.become_tentative();
    }

    /// Compatibility no-op; upstream infers cursor from the passed framebuffer.
    pub fn set_cursor_from_server(&mut self, _row: usize, _col: usize) {}

    pub fn set_local_frame_sent(&mut self, frame_num: u64) {
        self.local_frame_sent = frame_num;
    }

    pub fn set_local_frame_acked(&mut self, frame_num: u64) {
        self.local_frame_acked = frame_num;
    }

    pub fn set_local_frame_late_acked(&mut self, frame_num: u64) {
        if frame_num > self.local_frame_late_acked {
            self.local_frame_late_acked = frame_num;
        }
    }

    pub fn set_send_interval(&mut self, send_interval_ms: u64) {
        self.send_interval_ms = send_interval_ms;
    }

    /// Compatibility shim: call sites may still refer to server_ack().
    pub fn server_ack(&mut self, echo_ack_num: u64) {
        self.set_local_frame_late_acked(echo_ack_num);
    }

    /// Handle a batch of input. Like upstream, large pastes disable predictions.
    pub fn new_user_input_batch(&mut self, data: &[u8], base_fb: &Framebuffer) {
        if data.len() > 100 {
            self.reset();
            return;
        }

        for &byte in data {
            self.new_user_byte(byte, base_fb);
        }
    }

    fn new_user_byte(&mut self, mut the_byte: u8, fb: &Framebuffer) {
        if self.mode == PredictionMode::Never {
            return;
        }

        self.cull(fb);

        // Translate application-cursor-key prefix: ESC O X -> ESC [ X.
        if self.esc_state == 1 && the_byte == b'O' {
            the_byte = b'[';
        }

        let now = Instant::now();
        match self.esc_state {
            0 => {
                if the_byte == 0x1B {
                    self.esc_state = 1;
                    return;
                }
                match the_byte {
                    0x7F => self.predict_backspace(fb, now),
                    0x0D => {
                        self.become_tentative();
                        self.newline_carriage_return(fb, now);
                    }
                    0x20..=0x7E => self.predict_printable(the_byte as char, fb, now),
                    _ => self.become_tentative(),
                }
            }
            1 => {
                if the_byte == b'[' {
                    self.esc_state = 2;
                } else {
                    // Generic ESC dispatch: no safe prediction.
                    self.become_tentative();
                    self.esc_state = 0;
                }
            }
            _ => {
                // CSI sequence: only predict left/right (like upstream).
                if (0x40..=0x7E).contains(&the_byte) {
                    if the_byte == b'C' {
                        self.predict_move_right(now, fb);
                    } else if the_byte == b'D' {
                        self.predict_move_left(now, fb);
                    } else {
                        self.become_tentative();
                    }
                    self.esc_state = 0;
                }
            }
        }
    }

    fn become_tentative(&mut self) {
        self.prediction_epoch = self.prediction_epoch.saturating_add(1);
    }

    fn active(&self) -> bool {
        if !self.cursors.is_empty() {
            return true;
        }
        self.overlays
            .iter()
            .any(|row| row.overlay_cells.iter().any(|cell| cell.active))
    }

    fn should_display_predictions(&self) -> bool {
        match self.mode {
            PredictionMode::Never => false,
            PredictionMode::Always => true,
            PredictionMode::Adaptive => self.srtt_trigger || self.glitch_trigger > 0,
        }
    }

    fn get_or_make_row(&mut self, row_num: usize, num_cols: usize) -> &mut PredictedRow {
        if let Some(idx) = self.overlays.iter().position(|r| r.row_num == row_num) {
            return &mut self.overlays[idx];
        }

        let mut row = PredictedRow {
            row_num,
            overlay_cells: Vec::with_capacity(num_cols),
        };
        for col in 0..num_cols {
            row.overlay_cells.push(PredictedCell::new(col));
        }
        self.overlays.push(row);
        self.overlays.last_mut().expect("overlays non-empty after push")
    }

    fn init_cursor(&mut self, fb: &Framebuffer) {
        if fb.width == 0 || fb.height == 0 {
            return;
        }

        if self.cursors.is_empty() {
            self.cursors.push(PredictedCursor {
                expiration_frame: self.local_frame_sent.saturating_add(1),
                row: fb.cursor_row.min(fb.height.saturating_sub(1)),
                col: fb.cursor_col.min(fb.width.saturating_sub(1)),
                active: true,
                tentative_until_epoch: self.prediction_epoch,
            });
        } else if self
            .cursors
            .last()
            .map(|c| c.tentative_until_epoch != self.prediction_epoch)
            .unwrap_or(false)
        {
            let prev = self.cursors.last().cloned().expect("cursor exists");
            self.cursors.push(PredictedCursor {
                expiration_frame: self.local_frame_sent.saturating_add(1),
                row: prev.row,
                col: prev.col,
                active: true,
                tentative_until_epoch: self.prediction_epoch,
            });
        }
    }

    fn cursor(&self) -> &PredictedCursor {
        self.cursors.last().expect("cursor prediction not initialized")
    }

    fn cursor_mut(&mut self) -> &mut PredictedCursor {
        self.cursors
            .last_mut()
            .expect("cursor prediction not initialized")
    }

    fn kill_epoch(&mut self, epoch: u64, fb: &Framebuffer) {
        self.cursors
            .retain(|c| !c.tentative(epoch.saturating_sub(1)));

        if fb.width > 0 && fb.height > 0 {
            self.cursors.push(PredictedCursor {
                expiration_frame: self.local_frame_sent.saturating_add(1),
                row: fb.cursor_row.min(fb.height.saturating_sub(1)),
                col: fb.cursor_col.min(fb.width.saturating_sub(1)),
                active: true,
                tentative_until_epoch: self.prediction_epoch,
            });
        }

        for row in &mut self.overlays {
            for cell in &mut row.overlay_cells {
                if cell.tentative(epoch.saturating_sub(1)) {
                    cell.reset();
                }
            }
        }

        self.become_tentative();
    }

    fn newline_carriage_return(&mut self, fb: &Framebuffer, now: Instant) {
        if fb.width == 0 || fb.height == 0 {
            return;
        }

        self.init_cursor(fb);

        let expiration_frame = self.local_frame_sent.saturating_add(1);
        {
            let cursor = self.cursor_mut();
            cursor.col = 0;
            cursor.expire(expiration_frame);
        }

        if self.cursor().row == fb.height.saturating_sub(1) {
            let row_num = self.cursor().row;
            let tentative = self.prediction_epoch;
            let row = self.get_or_make_row(row_num, fb.width);
            for cell in &mut row.overlay_cells {
                cell.active = true;
                cell.tentative_until_epoch = tentative;
                cell.expire(expiration_frame, now);
                cell.unknown = false;
                cell.replacement = Cell::default();
                cell.replacement.character = ' ';
                cell.replacement.dirty = true;
            }
        } else {
            let cursor = self.cursor_mut();
            cursor.row += 1;
        }
    }

    fn predict_move_right(&mut self, _now: Instant, fb: &Framebuffer) {
        if fb.width == 0 || fb.height == 0 {
            return;
        }

        self.init_cursor(fb);
        if self.cursor().col < fb.width.saturating_sub(1) {
            let expiration = self.local_frame_sent.saturating_add(1);
            let cursor = self.cursor_mut();
            cursor.col += 1;
            cursor.expire(expiration);
        }
    }

    fn predict_move_left(&mut self, _now: Instant, fb: &Framebuffer) {
        if fb.width == 0 || fb.height == 0 {
            return;
        }

        self.init_cursor(fb);
        if self.cursor().col > 0 {
            let expiration = self.local_frame_sent.saturating_add(1);
            let cursor = self.cursor_mut();
            cursor.col -= 1;
            cursor.expire(expiration);
        }
    }

    fn predict_backspace(&mut self, fb: &Framebuffer, now: Instant) {
        if fb.width == 0 || fb.height == 0 {
            return;
        }

        self.init_cursor(fb);
        if self.cursor().col == 0 || self.cursor().row >= fb.height {
            return;
        }

        let expiration_frame = self.local_frame_sent.saturating_add(1);
        {
            let cursor = self.cursor_mut();
            cursor.col -= 1;
            cursor.expire(expiration_frame);
        }

        let row_num = self.cursor().row;
        let col = self.cursor().col;
        let tentative = self.prediction_epoch;
        let predict_overwrite = self.predict_overwrite;
        let row = self.get_or_make_row(row_num, fb.width);

        if predict_overwrite {
            let cell = &mut row.overlay_cells[col];
            cell.reset_with_orig();
            cell.active = true;
            cell.tentative_until_epoch = tentative;
            cell.expire(expiration_frame, now);
            let orig_cell = fb.cells[row_num][col].clone();
            cell.original_contents.push(orig_cell.clone());
            cell.unknown = false;
            cell.replacement = orig_cell;
            cell.replacement.character = ' ';
            cell.replacement.dirty = true;
            return;
        }

        for i in col..fb.width {
            let (unknown, replacement) = if i + 2 < fb.width {
                let next = &row.overlay_cells[i + 1];
                let next_actual = &fb.cells[row_num][i + 1];
                if next.active {
                    if next.unknown {
                        (true, None)
                    } else {
                        (false, Some(next.replacement.clone()))
                    }
                } else {
                    (false, Some(next_actual.clone()))
                }
            } else {
                (true, None)
            };

            let cell = &mut row.overlay_cells[i];
            cell.reset_with_orig();
            cell.active = true;
            cell.tentative_until_epoch = tentative;
            cell.expire(expiration_frame, now);
            cell.original_contents.push(fb.cells[row_num][i].clone());
            cell.unknown = unknown;
            if let Some(replacement) = replacement {
                cell.replacement = replacement;
            }
        }
    }

    fn predict_printable(&mut self, ch: char, fb: &Framebuffer, now: Instant) {
        if fb.width == 0 || fb.height == 0 {
            return;
        }

        self.init_cursor(fb);
        let row_num = self.cursor().row;
        let col = self.cursor().col;

        if row_num >= fb.height || col >= fb.width {
            return;
        }

        let expiration_frame = self.local_frame_sent.saturating_add(1);
        let tentative = self.prediction_epoch;

        if col + 1 >= fb.width {
            self.become_tentative();
        }

        let rightmost_column = if self.predict_overwrite {
            col
        } else {
            fb.width.saturating_sub(1)
        };

        let row = self.get_or_make_row(row_num, fb.width);

        for i in ((col + 1)..=rightmost_column).rev() {
            let (unknown, replacement) = if i == fb.width.saturating_sub(1) {
                (true, None)
            } else {
                let prev = &row.overlay_cells[i - 1];
                let prev_actual = &fb.cells[row_num][i - 1];
                if prev.active {
                    if prev.unknown {
                        (true, None)
                    } else {
                        (false, Some(prev.replacement.clone()))
                    }
                } else {
                    (false, Some(prev_actual.clone()))
                }
            };

            let cell = &mut row.overlay_cells[i];
            cell.reset_with_orig();
            cell.active = true;
            cell.tentative_until_epoch = tentative;
            cell.expire(expiration_frame, now);
            cell.original_contents.push(fb.cells[row_num][i].clone());
            cell.unknown = unknown;
            if let Some(replacement) = replacement {
                cell.replacement = replacement;
            }
        }

        let mut replacement = fb.cells[row_num][col].clone();
        if col > 0 {
            let prev = &row.overlay_cells[col - 1];
            let prev_actual = &fb.cells[row_num][col - 1];
            if prev.active && !prev.unknown {
                replacement.fg = prev.replacement.fg;
                replacement.bg = prev.replacement.bg;
                replacement.attrs = prev.replacement.attrs;
            } else {
                replacement.fg = prev_actual.fg;
                replacement.bg = prev_actual.bg;
                replacement.attrs = prev_actual.attrs;
            }
        }
        replacement.character = ch;
        replacement.dirty = true;

        let cell = &mut row.overlay_cells[col];
        cell.reset_with_orig();
        cell.active = true;
        cell.tentative_until_epoch = tentative;
        cell.expire(expiration_frame, now);
        cell.replacement = replacement;
        cell.unknown = false;
        cell.original_contents.push(fb.cells[row_num][col].clone());

        {
            let cursor = self.cursor_mut();
            cursor.expire(expiration_frame);
            if cursor.col < fb.width.saturating_sub(1) {
                cursor.col += 1;
                return;
            }
        }

        self.become_tentative();
        self.newline_carriage_return(fb, now);
    }

    fn cell_validity(
        late_ack: u64,
        fb: &Framebuffer,
        row: usize,
        cell: &PredictedCell,
    ) -> Validity {
        if !cell.active {
            return Validity::Inactive;
        }

        if row >= fb.height || cell.col >= fb.width {
            return Validity::IncorrectOrExpired;
        }

        if late_ack < cell.expiration_frame {
            return Validity::Pending;
        }

        if cell.unknown {
            return Validity::CorrectNoCredit;
        }

        let current = &fb.cells[row][cell.col];

        if cell_is_blank(&cell.replacement) {
            return Validity::CorrectNoCredit;
        }

        if cell_contents_match(current, &cell.replacement) {
            if cell
                .original_contents
                .iter()
                .any(|orig| cell_contents_match(orig, &cell.replacement))
            {
                Validity::CorrectNoCredit
            } else {
                Validity::Correct
            }
        } else {
            Validity::IncorrectOrExpired
        }
    }

    fn cursor_validity(late_ack: u64, fb: &Framebuffer, cursor: &PredictedCursor) -> Validity {
        if !cursor.active {
            return Validity::Inactive;
        }

        if cursor.row >= fb.height || cursor.col >= fb.width {
            return Validity::IncorrectOrExpired;
        }

        if late_ack >= cursor.expiration_frame {
            if fb.cursor_row == cursor.row && fb.cursor_col == cursor.col {
                Validity::Correct
            } else {
                Validity::IncorrectOrExpired
            }
        } else {
            Validity::Pending
        }
    }

    /// Cull predictions using latest authoritative server framebuffer.
    pub fn cull(&mut self, server_fb: &Framebuffer) {
        if self.mode == PredictionMode::Never {
            return;
        }

        if self.last_height != server_fb.height || self.last_width != server_fb.width {
            self.last_height = server_fb.height;
            self.last_width = server_fb.width;
            self.reset();
            return;
        }

        // control srtt_trigger with hysteresis
        if self.send_interval_ms > SRTT_TRIGGER_HIGH_MS {
            self.srtt_trigger = true;
        } else if self.srtt_trigger
            && self.send_interval_ms <= SRTT_TRIGGER_LOW_MS
            && !self.active()
        {
            self.srtt_trigger = false;
        }

        // control underlining with hysteresis
        if self.send_interval_ms > FLAG_TRIGGER_HIGH_MS {
            self.flagging = true;
        } else if self.send_interval_ms <= FLAG_TRIGGER_LOW_MS {
            self.flagging = false;
        }

        // really big glitches also activate underlining
        if self.glitch_trigger > GLITCH_REPAIR_COUNT {
            self.flagging = true;
        }

        loop {
            self.overlays.retain(|row| row.row_num < server_fb.height);

            let mut kill_epoch: Option<u64> = None;
            let mut full_reset = false;
            let now = Instant::now();

            'scan: for row in &mut self.overlays {
                let row_num = row.row_num;
                for idx in 0..row.overlay_cells.len() {
                    let validity = {
                        let cell = &row.overlay_cells[idx];
                        Self::cell_validity(self.local_frame_late_acked, server_fb, row_num, cell)
                    };

                    match validity {
                        Validity::IncorrectOrExpired => {
                            let cell = &row.overlay_cells[idx];
                            if cell.tentative(self.confirmed_epoch) {
                                kill_epoch = Some(cell.tentative_until_epoch);
                            } else {
                                full_reset = true;
                            }
                            break 'scan;
                        }
                        Validity::Correct => {
                            let (tentative_until_epoch, prediction_time, col) = {
                                let cell = &row.overlay_cells[idx];
                                (cell.tentative_until_epoch, cell.prediction_time, cell.col)
                            };

                            if tentative_until_epoch > self.confirmed_epoch {
                                self.confirmed_epoch = tentative_until_epoch;
                            }

                            if now.duration_since(prediction_time)
                                < Duration::from_millis(GLITCH_THRESHOLD_MS)
                            {
                                let enough_time_elapsed = self
                                    .last_quick_confirmation
                                    .map(|last| {
                                        now.duration_since(last)
                                            >= Duration::from_millis(
                                                GLITCH_REPAIR_MIN_INTERVAL_MS,
                                            )
                                    })
                                    .unwrap_or(true);
                                if self.glitch_trigger > 0 && enough_time_elapsed {
                                    self.glitch_trigger -= 1;
                                    self.last_quick_confirmation = Some(now);
                                }
                            }

                            let actual = server_fb.cells[row_num][col].clone();
                            for k in idx..row.overlay_cells.len() {
                                let replacement = &mut row.overlay_cells[k].replacement;
                                replacement.fg = actual.fg;
                                replacement.bg = actual.bg;
                                replacement.attrs = actual.attrs;
                            }

                            row.overlay_cells[idx].reset();
                        }
                        Validity::CorrectNoCredit => {
                            row.overlay_cells[idx].reset();
                        }
                        Validity::Pending => {
                            let age = now.duration_since(row.overlay_cells[idx].prediction_time);
                            if age >= Duration::from_millis(GLITCH_FLAG_THRESHOLD_MS) {
                                self.glitch_trigger = GLITCH_REPAIR_COUNT * 2;
                            } else if age >= Duration::from_millis(GLITCH_THRESHOLD_MS)
                                && self.glitch_trigger < GLITCH_REPAIR_COUNT
                            {
                                self.glitch_trigger = GLITCH_REPAIR_COUNT;
                            }
                        }
                        Validity::Inactive => {}
                    }
                }
            }

            if full_reset {
                self.reset();
                return;
            }

            if let Some(epoch) = kill_epoch {
                self.kill_epoch(epoch, server_fb);
                continue;
            }

            break;
        }

        if let Some(last_cursor) = self.cursors.last() {
            if Self::cursor_validity(self.local_frame_late_acked, server_fb, last_cursor)
                == Validity::IncorrectOrExpired
            {
                self.reset();
                return;
            }
        }

        self.cursors
            .retain(|c| {
                Self::cursor_validity(self.local_frame_late_acked, server_fb, c)
                    == Validity::Pending
            });
    }

    pub fn apply_overlays(&self, fb: &mut Framebuffer) -> Option<(usize, usize)> {
        if !self.should_display_predictions() {
            return None;
        }

        let mut predicted_cursor = None;

        for cursor in &self.cursors {
            if !cursor.active || cursor.tentative(self.confirmed_epoch) {
                continue;
            }
            if cursor.row < fb.height && cursor.col < fb.width {
                predicted_cursor = Some((cursor.row, cursor.col));
            }
        }

        for row in &self.overlays {
            if row.row_num >= fb.height {
                continue;
            }

            for cell in &row.overlay_cells {
                if !cell.active || cell.tentative(self.confirmed_epoch) {
                    continue;
                }
                if cell.col >= fb.width {
                    continue;
                }

                if cell.unknown {
                    if self.flagging && cell.col != fb.width.saturating_sub(1) {
                        fb.cells[row.row_num][cell.col].attrs.underline = true;
                        fb.cells[row.row_num][cell.col].dirty = true;
                    }
                    continue;
                }

                let mut underline = self.flagging;
                if cell_is_blank(&cell.replacement) && cell_is_blank(&fb.cells[row.row_num][cell.col]) {
                    underline = false;
                }

                if fb.cells[row.row_num][cell.col] != cell.replacement {
                    fb.cells[row.row_num][cell.col] = cell.replacement.clone();
                    if underline {
                        fb.cells[row.row_num][cell.col].attrs.underline = true;
                    }
                    fb.cells[row.row_num][cell.col].dirty = true;
                }
            }
        }

        predicted_cursor
    }

    #[allow(dead_code)]
    pub fn has_predictions(&self) -> bool {
        self.active()
    }
}

fn cell_is_blank(cell: &Cell) -> bool {
    cell.character == ' '
}

fn cell_contents_match(a: &Cell, b: &Cell) -> bool {
    (cell_is_blank(a) && cell_is_blank(b)) || a.character == b.character
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal::Framebuffer;

    fn blank_fb() -> Framebuffer {
        Framebuffer::new(80, 24)
    }

    #[test]
    fn clears_predictions_on_late_ack_frame() {
        let mut p = PredictionEngine::new(PredictionMode::Always, 80, 24);
        p.set_local_frame_sent(0);
        let fb = blank_fb();
        p.new_user_input_batch(b"abc", &fb);
        assert!(p.has_predictions());

        p.set_local_frame_late_acked(1);
        p.cull(&fb);
        assert!(!p.has_predictions());
    }

    #[test]
    fn keeps_predictions_when_late_ack_not_reached() {
        let mut p = PredictionEngine::new(PredictionMode::Always, 80, 24);
        p.set_local_frame_sent(5);
        let fb = blank_fb();
        p.new_user_input_batch(b"a", &fb);
        assert!(p.has_predictions());

        p.set_local_frame_late_acked(5);
        p.cull(&fb);
        assert!(p.has_predictions());
    }

    #[test]
    fn adaptive_mode_uses_srtt_hysteresis() {
        let mut p = PredictionEngine::new(PredictionMode::Adaptive, 80, 24);
        p.set_send_interval(31);
        p.set_local_frame_sent(0);
        let fb = blank_fb();
        p.new_user_input_batch(b"a", &fb);
        assert!(p.has_predictions());

        p.set_local_frame_late_acked(1);
        p.cull(&fb);
        p.set_send_interval(20);
        p.cull(&fb);
        assert!(!p.should_display_predictions());
    }

    #[test]
    fn does_not_cull_on_early_transport_ack_only() {
        let mut p = PredictionEngine::new(PredictionMode::Always, 80, 24);
        let fb = blank_fb();
        p.set_local_frame_sent(10);
        p.new_user_input_batch(b"d", &fb);
        assert!(p.has_predictions());

        p.set_local_frame_acked(11);
        p.cull(&fb);
        assert!(p.has_predictions());
    }

    #[test]
    fn predicts_backspace_by_erasing_previous_cell() {
        let mut p = PredictionEngine::new(PredictionMode::Always, 80, 24);
        let prime_fb = blank_fb();
        p.set_local_frame_sent(0);
        p.new_user_input_batch(b"x", &prime_fb);

        // Confirm epoch 1 so subsequent safe predictions are displayable.
        let mut confirmed_fb = prime_fb.clone();
        confirmed_fb.cells[0][0].character = 'x';
        confirmed_fb.cursor_col = 1;
        p.set_local_frame_late_acked(1);
        p.cull(&confirmed_fb);

        let mut fb = blank_fb();
        fb.cells[0][0].character = 'a';
        fb.cells[0][1].character = 'b';
        fb.cells[0][2].character = 'c';
        fb.cursor_row = 0;
        fb.cursor_col = 3;

        p.set_local_frame_sent(1);
        p.new_user_input_batch(&[0x7f], &fb);

        let mut overlay = fb.clone();
        let predicted_cursor = p.apply_overlays(&mut overlay).unwrap();
        assert_eq!(predicted_cursor, (0, 2));
        assert_eq!(overlay.cells[0][2].character, ' ');
    }
}
