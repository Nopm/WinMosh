//! Terminal emulator state machine: character-cell framebuffer with VT parser.
//!
//! Maintains the terminal display state (character grid, cursor position, colors)
//! and processes VT escape sequences from the remote host.

use std::fmt;

/// Terminal cell attributes (SGR).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attributes {
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub blink: bool,
    pub inverse: bool,
    pub invisible: bool,
    pub strikethrough: bool,
}

/// Terminal color representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Default,
    Indexed(u8),
    Rgb(u8, u8, u8),
}

impl Default for Color {
    fn default() -> Self {
        Color::Default
    }
}

/// A single cell in the terminal framebuffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub character: char,
    pub fg: Color,
    pub bg: Color,
    pub attrs: Attributes,
    /// Whether this cell has been modified since last diff.
    pub dirty: bool,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            character: ' ',
            fg: Color::Default,
            bg: Color::Default,
            attrs: Attributes::default(),
            dirty: true,
        }
    }
}

/// Cursor style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CursorStyle {
    Block,
    Underline,
    Bar,
}

impl Default for CursorStyle {
    fn default() -> Self {
        CursorStyle::Block
    }
}

/// The terminal framebuffer: a 2D grid of cells plus cursor state.
#[derive(Clone)]
pub struct Framebuffer {
    pub width: usize,
    pub height: usize,
    pub cells: Vec<Vec<Cell>>,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub cursor_visible: bool,
    pub cursor_style: CursorStyle,
    /// Current drawing attributes for new characters.
    current_attrs: Attributes,
    current_fg: Color,
    current_bg: Color,
    /// Scroll region (top, bottom) - 0-indexed, inclusive.
    scroll_top: usize,
    scroll_bottom: usize,
    /// Alternate screen buffer.
    alternate_screen: Option<Vec<Vec<Cell>>>,
    /// Saved cursor position (for DECSC/DECRC).
    saved_cursor: (usize, usize),
    /// Origin mode (DECOM).
    origin_mode: bool,
    /// Auto-wrap mode.
    auto_wrap: bool,
    /// Insert mode (IRM).
    insert_mode: bool,
    /// Whether cursor is in the "pending wrap" state.
    wrap_pending: bool,
    /// Tab stops.
    tab_stops: Vec<bool>,
    /// Window title.
    pub title: String,
}

impl Framebuffer {
    /// Create a new framebuffer with the given dimensions.
    pub fn new(width: usize, height: usize) -> Self {
        let cells = vec![vec![Cell::default(); width]; height];
        let mut tab_stops = vec![false; width];
        for i in (0..width).step_by(8) {
            tab_stops[i] = true;
        }

        Self {
            width,
            height,
            cells,
            cursor_row: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_style: CursorStyle::default(),
            current_attrs: Attributes::default(),
            current_fg: Color::Default,
            current_bg: Color::Default,
            scroll_top: 0,
            scroll_bottom: height.saturating_sub(1),
            alternate_screen: None,
            saved_cursor: (0, 0),
            origin_mode: false,
            auto_wrap: true,
            insert_mode: false,
            wrap_pending: false,
            tab_stops,
            title: String::new(),
        }
    }

    /// Resize the framebuffer. Preserves content where possible.
    pub fn resize(&mut self, new_width: usize, new_height: usize) {
        let mut new_cells = vec![vec![Cell::default(); new_width]; new_height];
        let copy_rows = self.height.min(new_height);
        let copy_cols = self.width.min(new_width);
        for row in 0..copy_rows {
            for col in 0..copy_cols {
                new_cells[row][col] = self.cells[row][col].clone();
            }
        }
        self.cells = new_cells;
        self.width = new_width;
        self.height = new_height;
        self.scroll_top = 0;
        self.scroll_bottom = new_height.saturating_sub(1);
        self.cursor_row = self.cursor_row.min(new_height.saturating_sub(1));
        self.cursor_col = self.cursor_col.min(new_width.saturating_sub(1));
        self.wrap_pending = false;
        self.tab_stops = vec![false; new_width];
        for i in (0..new_width).step_by(8) {
            self.tab_stops[i] = true;
        }
        self.mark_all_dirty();
    }

    /// Mark all cells as dirty (needs full redraw).
    pub fn mark_all_dirty(&mut self) {
        for row in &mut self.cells {
            for cell in row.iter_mut() {
                cell.dirty = true;
            }
        }
    }

    /// Clear all dirty flags.
    #[allow(dead_code)]
    pub fn clear_dirty(&mut self) {
        for row in &mut self.cells {
            for cell in row.iter_mut() {
                cell.dirty = false;
            }
        }
    }

    /// Write a character at the current cursor position and advance.
    fn put_char(&mut self, c: char) {
        if self.wrap_pending && self.auto_wrap {
            self.cursor_col = 0;
            self.move_rows_autoscroll(1);
            self.wrap_pending = false;
        }

        if self.insert_mode && self.cursor_row < self.height && self.cursor_col < self.width {
            self.insert_chars(1);
        }

        if self.cursor_row < self.height && self.cursor_col < self.width {
            self.cells[self.cursor_row][self.cursor_col] = Cell {
                character: c,
                fg: self.current_fg,
                bg: self.current_bg,
                attrs: self.current_attrs,
                dirty: true,
            };
        }

        if self.cursor_col + 1 >= self.width {
            self.wrap_pending = true;
        } else {
            self.move_col(1, true, true);
        }
    }

    /// Scroll the scroll region up by n lines.
    fn scroll_up(&mut self, n: usize) {
        for _ in 0..n {
            if self.scroll_top < self.scroll_bottom {
                self.cells.remove(self.scroll_top);
                self.cells.insert(
                    self.scroll_bottom,
                    vec![
                        Cell {
                            bg: self.current_bg,
                            ..Cell::default()
                        };
                        self.width
                    ],
                );
            }
        }
        self.mark_region_dirty(self.scroll_top, self.scroll_bottom);
    }

    /// Scroll the scroll region down by n lines.
    fn scroll_down(&mut self, n: usize) {
        for _ in 0..n {
            if self.scroll_top < self.scroll_bottom {
                self.cells.remove(self.scroll_bottom);
                self.cells.insert(
                    self.scroll_top,
                    vec![
                        Cell {
                            bg: self.current_bg,
                            ..Cell::default()
                        };
                        self.width
                    ],
                );
            }
        }
        self.mark_region_dirty(self.scroll_top, self.scroll_bottom);
    }

    fn mark_region_dirty(&mut self, top: usize, bottom: usize) {
        for row in top..=bottom.min(self.height - 1) {
            for cell in &mut self.cells[row] {
                cell.dirty = true;
            }
        }
    }

    fn limit_top(&self) -> usize {
        if self.origin_mode {
            self.scroll_top
        } else {
            0
        }
    }

    fn limit_bottom(&self) -> usize {
        if self.origin_mode {
            self.scroll_bottom
        } else {
            self.height.saturating_sub(1)
        }
    }

    fn snap_cursor_to_border(&mut self) {
        let top = self.limit_top();
        let bottom = self.limit_bottom();
        self.cursor_row = self.cursor_row.clamp(top, bottom);
        self.cursor_col = self.cursor_col.min(self.width.saturating_sub(1));
    }

    fn move_row(&mut self, n: isize, relative: bool) {
        if relative {
            let target = self.cursor_row as isize + n;
            self.cursor_row = target.max(0) as usize;
        } else {
            let target = self.limit_top() as isize + n;
            self.cursor_row = target.max(0) as usize;
        }
        self.snap_cursor_to_border();
        self.wrap_pending = false;
    }

    fn move_col(&mut self, n: isize, relative: bool, implicit: bool) {
        let target = if relative {
            self.cursor_col as isize + n
        } else {
            n
        };
        self.cursor_col = target.max(0) as usize;
        if implicit {
            self.wrap_pending = self.cursor_col >= self.width;
        }
        self.snap_cursor_to_border();
        if !implicit {
            self.wrap_pending = false;
        }
    }

    fn next_tab_stop(&self, count: i32) -> Option<usize> {
        if count >= 0 {
            let mut remaining = count;
            for i in (self.cursor_col + 1)..self.width {
                if self.tab_stops[i] {
                    remaining -= 1;
                    if remaining == 0 {
                        return Some(i);
                    }
                }
            }
            None
        } else {
            let mut remaining = count;
            for i in (1..self.cursor_col).rev() {
                if self.tab_stops[i] {
                    remaining += 1;
                    if remaining == 0 {
                        return Some(i);
                    }
                }
            }
            Some(0)
        }
    }

    fn move_rows_autoscroll(&mut self, rows: isize) {
        // Outside scrolling region: no autoscroll, just clamp move.
        if self.cursor_row < self.scroll_top || self.cursor_row > self.scroll_bottom {
            self.move_row(rows, true);
            return;
        }

        let target = self.cursor_row as isize + rows;
        if target > self.scroll_bottom as isize {
            let n = (target - self.scroll_bottom as isize) as usize;
            self.scroll_up(n);
            self.move_row(-(n as isize), true);
        } else if target < self.scroll_top as isize {
            let n = (self.scroll_top as isize - target) as usize;
            self.scroll_down(n);
            self.move_row(n as isize, true);
        }
        self.move_row(rows, true);
    }

    /// Erase from cursor to end of line.
    fn erase_to_eol(&mut self) {
        if self.cursor_row < self.height {
            for col in self.cursor_col..self.width {
                self.cells[self.cursor_row][col] = Cell {
                    bg: self.current_bg,
                    dirty: true,
                    ..Cell::default()
                };
            }
        }
    }

    /// Erase from start of line to cursor.
    fn erase_to_bol(&mut self) {
        if self.cursor_row < self.height {
            for col in 0..=self.cursor_col.min(self.width - 1) {
                self.cells[self.cursor_row][col] = Cell {
                    bg: self.current_bg,
                    dirty: true,
                    ..Cell::default()
                };
            }
        }
    }

    /// Erase entire line.
    fn erase_line(&mut self) {
        if self.cursor_row < self.height {
            for col in 0..self.width {
                self.cells[self.cursor_row][col] = Cell {
                    bg: self.current_bg,
                    dirty: true,
                    ..Cell::default()
                };
            }
        }
    }

    /// Erase from cursor to end of screen.
    fn erase_below(&mut self) {
        self.erase_to_eol();
        for row in (self.cursor_row + 1)..self.height {
            for col in 0..self.width {
                self.cells[row][col] = Cell {
                    bg: self.current_bg,
                    dirty: true,
                    ..Cell::default()
                };
            }
        }
    }

    /// Erase from start of screen to cursor.
    fn erase_above(&mut self) {
        self.erase_to_bol();
        for row in 0..self.cursor_row {
            for col in 0..self.width {
                self.cells[row][col] = Cell {
                    bg: self.current_bg,
                    dirty: true,
                    ..Cell::default()
                };
            }
        }
    }

    /// Erase entire screen.
    fn erase_all(&mut self) {
        for row in 0..self.height {
            for col in 0..self.width {
                self.cells[row][col] = Cell {
                    bg: self.current_bg,
                    dirty: true,
                    ..Cell::default()
                };
            }
        }
    }

    /// Insert n blank characters at cursor, shifting existing chars right.
    fn insert_chars(&mut self, n: usize) {
        if self.cursor_row < self.height {
            let row = &mut self.cells[self.cursor_row];
            for _ in 0..n {
                if self.cursor_col < self.width {
                    row.pop();
                    row.insert(
                        self.cursor_col,
                        Cell {
                            bg: self.current_bg,
                            dirty: true,
                            ..Cell::default()
                        },
                    );
                }
            }
            // Mark row dirty
            for cell in row.iter_mut() {
                cell.dirty = true;
            }
        }
    }

    /// Delete n characters at cursor, shifting remaining chars left.
    fn delete_chars(&mut self, n: usize) {
        if self.cursor_row < self.height {
            let row = &mut self.cells[self.cursor_row];
            for _ in 0..n {
                if self.cursor_col < row.len() {
                    row.remove(self.cursor_col);
                    row.push(Cell {
                        bg: self.current_bg,
                        dirty: true,
                        ..Cell::default()
                    });
                }
            }
            for cell in row.iter_mut() {
                cell.dirty = true;
            }
        }
    }

    /// Insert n blank lines at cursor, scrolling down.
    fn insert_lines(&mut self, n: usize) {
        let save = self.cursor_row;
        if save >= self.scroll_top && save <= self.scroll_bottom {
            for _ in 0..n {
                if self.scroll_bottom < self.height {
                    self.cells.remove(self.scroll_bottom);
                    self.cells.insert(
                        save,
                        vec![
                            Cell {
                                bg: self.current_bg,
                                ..Cell::default()
                            };
                            self.width
                        ],
                    );
                }
            }
            self.mark_region_dirty(save, self.scroll_bottom);
        }
    }

    /// Delete n lines at cursor, scrolling up.
    fn delete_lines(&mut self, n: usize) {
        let save = self.cursor_row;
        if save >= self.scroll_top && save <= self.scroll_bottom {
            for _ in 0..n {
                if save < self.cells.len() {
                    self.cells.remove(save);
                    if self.scroll_bottom < self.height {
                        self.cells.insert(
                            self.scroll_bottom,
                            vec![
                                Cell {
                                    bg: self.current_bg,
                                    ..Cell::default()
                                };
                                self.width
                            ],
                        );
                    }
                }
            }
            self.mark_region_dirty(save, self.scroll_bottom);
        }
    }

    /// Apply SGR (Select Graphic Rendition) parameters.
    fn apply_sgr(&mut self, params: &[u16]) {
        let mut i = 0;
        while i < params.len() {
            match params[i] {
                0 => {
                    self.current_attrs = Attributes::default();
                    self.current_fg = Color::Default;
                    self.current_bg = Color::Default;
                }
                1 => self.current_attrs.bold = true,
                3 => self.current_attrs.italic = true,
                4 => self.current_attrs.underline = true,
                5 => self.current_attrs.blink = true,
                7 => self.current_attrs.inverse = true,
                8 => self.current_attrs.invisible = true,
                9 => self.current_attrs.strikethrough = true,
                21 => self.current_attrs.bold = false,    // doubly underlined or bold off
                22 => self.current_attrs.bold = false,
                23 => self.current_attrs.italic = false,
                24 => self.current_attrs.underline = false,
                25 => self.current_attrs.blink = false,
                27 => self.current_attrs.inverse = false,
                28 => self.current_attrs.invisible = false,
                29 => self.current_attrs.strikethrough = false,
                // Standard foreground colors
                30..=37 => self.current_fg = Color::Indexed((params[i] - 30) as u8),
                38 => {
                    // Extended foreground color
                    if i + 1 < params.len() {
                        match params[i + 1] {
                            5 if i + 2 < params.len() => {
                                self.current_fg = Color::Indexed(params[i + 2] as u8);
                                i += 2;
                            }
                            2 if i + 4 < params.len() => {
                                self.current_fg = Color::Rgb(
                                    params[i + 2] as u8,
                                    params[i + 3] as u8,
                                    params[i + 4] as u8,
                                );
                                i += 4;
                            }
                            _ => {}
                        }
                    }
                }
                39 => self.current_fg = Color::Default,
                // Standard background colors
                40..=47 => self.current_bg = Color::Indexed((params[i] - 40) as u8),
                48 => {
                    // Extended background color
                    if i + 1 < params.len() {
                        match params[i + 1] {
                            5 if i + 2 < params.len() => {
                                self.current_bg = Color::Indexed(params[i + 2] as u8);
                                i += 2;
                            }
                            2 if i + 4 < params.len() => {
                                self.current_bg = Color::Rgb(
                                    params[i + 2] as u8,
                                    params[i + 3] as u8,
                                    params[i + 4] as u8,
                                );
                                i += 4;
                            }
                            _ => {}
                        }
                    }
                }
                49 => self.current_bg = Color::Default,
                // Bright foreground colors
                90..=97 => self.current_fg = Color::Indexed((params[i] - 90 + 8) as u8),
                // Bright background colors
                100..=107 => self.current_bg = Color::Indexed((params[i] - 100 + 8) as u8),
                _ => {} // Unknown SGR, ignore
            }
            i += 1;
        }
    }
}

/// VT parser performer: receives parsed escape sequences from the `vte` crate.
pub struct VtPerformer<'a> {
    pub fb: &'a mut Framebuffer,
}

impl<'a> vte::Perform for VtPerformer<'a> {
    fn print(&mut self, c: char) {
        self.fb.put_char(c);
    }

    fn execute(&mut self, byte: u8) {
        match byte {
            // BEL
            0x07 => { /* bell - ignore */ }
            // BS - backspace
            0x08 => {
                self.fb.move_col(-1, true, false);
            }
            // HT - horizontal tab
            0x09 => {
                let wrap_state = self.fb.wrap_pending;
                let col = self.fb.next_tab_stop(1).unwrap_or(self.fb.width.saturating_sub(1));
                self.fb.move_col(col as isize, false, false);
                // HT preserves wrap state.
                self.fb.wrap_pending = wrap_state;
            }
            // LF, VT, FF - line feed
            0x0A | 0x0B | 0x0C => {
                self.fb.move_rows_autoscroll(1);
            }
            // CR - carriage return
            0x0D => {
                self.fb.move_col(0, false, false);
            }
            // SO, SI - shift out/in (charset switching, minimal support)
            0x0E | 0x0F => {}
            // HTS - horizontal tab set
            0x88 => {
                if self.fb.cursor_col < self.fb.tab_stops.len() {
                    self.fb.tab_stops[self.fb.cursor_col] = true;
                }
            }
            _ => {}
        }
    }

    fn hook(&mut self, _params: &vte::Params, _intermediates: &[u8], _ignore: bool, _action: char) {
        // DCS sequences - minimal support
    }

    fn put(&mut self, _byte: u8) {
        // Data within DCS
    }

    fn unhook(&mut self) {
        // End DCS
    }

    fn osc_dispatch(&mut self, params: &[&[u8]], _bell_terminated: bool) {
        // OSC sequences - handle window title (OSC 0 and OSC 2)
        if params.len() >= 2 {
            match params[0] {
                b"0" | b"2" => {
                    if let Ok(title) = std::str::from_utf8(params[1]) {
                        self.fb.title = title.to_string();
                    }
                }
                _ => {}
            }
        }
    }

    fn csi_dispatch(
        &mut self,
        params: &vte::Params,
        intermediates: &[u8],
        _ignore: bool,
        action: char,
    ) {
        let params_vec: Vec<u16> = params.iter().flat_map(|sub| sub.iter().map(|&v| v as u16)).collect();
        let p1 = params_vec.first().copied().unwrap_or(0);
        let p2 = params_vec.get(1).copied().unwrap_or(0);

        let has_question = intermediates.contains(&b'?');

        match action {
            // CUU - Cursor Up
            'A' => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.move_row(-(n as isize), true);
            }
            // CUD - Cursor Down
            'B' => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.move_row(n as isize, true);
            }
            // CUF - Cursor Forward
            'C' => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.move_col(n as isize, true, false);
            }
            // CUB - Cursor Backward
            'D' => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.move_col(-(n as isize), true, false);
            }
            // CNL - Cursor Next Line
            'E' => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.move_col(0, false, false);
                self.fb.move_row(n as isize, true);
            }
            // CPL - Cursor Previous Line
            'F' => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.move_col(0, false, false);
                self.fb.move_row(-(n as isize), true);
            }
            // CHA - Cursor Horizontal Absolute
            'G' => {
                let col = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.move_col((col.saturating_sub(1)) as isize, false, false);
            }
            // CUP - Cursor Position
            'H' | 'f' => {
                let row = if p1 == 0 { 1 } else { p1 as usize };
                let col = if p2 == 0 { 1 } else { p2 as usize };
                self.fb.move_row((row.saturating_sub(1)) as isize, false);
                self.fb.move_col((col.saturating_sub(1)) as isize, false, false);
            }
            // ED - Erase in Display
            'J' => {
                match p1 {
                    0 => self.fb.erase_below(),
                    1 => self.fb.erase_above(),
                    2 | 3 => self.fb.erase_all(),
                    _ => {}
                }
            }
            // EL - Erase in Line
            'K' => {
                match p1 {
                    0 => self.fb.erase_to_eol(),
                    1 => self.fb.erase_to_bol(),
                    2 => self.fb.erase_line(),
                    _ => {}
                }
            }
            // IL - Insert Lines
            'L' => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.insert_lines(n);
            }
            // DL - Delete Lines
            'M' => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.delete_lines(n);
            }
            // DCH - Delete Characters
            'P' => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.delete_chars(n);
            }
            // SU - Scroll Up
            'S' if !has_question => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.scroll_up(n);
            }
            // SD - Scroll Down
            'T' if !has_question => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.scroll_down(n);
            }
            // ECH - Erase Characters
            'X' => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                for i in 0..n {
                    let col = self.fb.cursor_col + i;
                    if col < self.fb.width && self.fb.cursor_row < self.fb.height {
                        self.fb.cells[self.fb.cursor_row][col] = Cell {
                            bg: self.fb.current_bg,
                            dirty: true,
                            ..Cell::default()
                        };
                    }
                }
            }
            // ICH - Insert Characters
            '@' => {
                let n = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.insert_chars(n);
            }
            // CHT/CBT - Cursor forward/back tabulation
            'I' => {
                let count = if p1 == 0 { 1 } else { p1 as i32 };
                let wrap_state = self.fb.wrap_pending;
                let col = self
                    .fb
                    .next_tab_stop(count)
                    .unwrap_or(self.fb.width.saturating_sub(1));
                self.fb.move_col(col as isize, false, false);
                self.fb.wrap_pending = wrap_state;
            }
            'Z' => {
                let count = if p1 == 0 { 1 } else { p1 as i32 };
                let wrap_state = self.fb.wrap_pending;
                let col = self.fb.next_tab_stop(-count).unwrap_or(0);
                self.fb.move_col(col as isize, false, false);
                self.fb.wrap_pending = wrap_state;
            }
            // TBC - Tab clear
            'g' => match p1 {
                0 => {
                    if self.fb.cursor_col < self.fb.tab_stops.len() {
                        self.fb.tab_stops[self.fb.cursor_col] = false;
                    }
                }
                3 => {
                    for tab in &mut self.fb.tab_stops {
                        *tab = false;
                    }
                }
                _ => {}
            },
            // VPA - Vertical Position Absolute
            'd' => {
                let row = if p1 == 0 { 1 } else { p1 as usize };
                self.fb.move_row((row.saturating_sub(1)) as isize, false);
            }
            // SGR - Select Graphic Rendition
            'm' => {
                if params_vec.is_empty() {
                    self.fb.apply_sgr(&[0]);
                } else {
                    self.fb.apply_sgr(&params_vec);
                }
            }
            // DECSET/DECRST - DEC Private Mode Set/Reset
            'h' if has_question => {
                for &p in &params_vec {
                    match p {
                        1 => {} // Application cursor keys mode (frontend concern)
                        3 => self.fb.erase_all(), // 80/132 mode toggle clears screen
                        25 => self.fb.cursor_visible = true,   // Show cursor
                        1049 => {
                            // Alternate screen buffer
                            let alt = vec![vec![Cell::default(); self.fb.width]; self.fb.height];
                            let main = std::mem::replace(&mut self.fb.cells, alt);
                            self.fb.alternate_screen = Some(main);
                            self.fb.move_row(0, false);
                            self.fb.move_col(0, false, false);
                        }
                        7 => self.fb.auto_wrap = true,
                        6 => {
                            self.fb.move_row(0, false);
                            self.fb.move_col(0, false, false);
                            self.fb.origin_mode = true;
                        }
                        _ => {}
                    }
                }
            }
            'l' if has_question => {
                for &p in &params_vec {
                    match p {
                        1 => {} // Application cursor keys mode (frontend concern)
                        3 => self.fb.erase_all(), // 80/132 mode toggle clears screen
                        25 => self.fb.cursor_visible = false,  // Hide cursor
                        1049 => {
                            // Restore main screen buffer
                            if let Some(main) = self.fb.alternate_screen.take() {
                                self.fb.cells = main;
                                self.fb.mark_all_dirty();
                            }
                        }
                        7 => self.fb.auto_wrap = false,
                        6 => {
                            self.fb.move_row(0, false);
                            self.fb.move_col(0, false, false);
                            self.fb.origin_mode = false;
                        }
                        _ => {}
                    }
                }
            }
            // ANSI set/reset mode (IRM only here).
            'h' if !has_question => {
                for &p in &params_vec {
                    if p == 4 {
                        self.fb.insert_mode = true;
                    }
                }
            }
            'l' if !has_question => {
                for &p in &params_vec {
                    if p == 4 {
                        self.fb.insert_mode = false;
                    }
                }
            }
            // DECSTBM - Set Scrolling Region
            'r' if !has_question => {
                let top = if p1 == 0 { 1 } else { p1 as usize };
                let bottom = if p2 == 0 { self.fb.height } else { p2 as usize };
                if top < bottom && bottom <= self.fb.height && !(top == 0 && bottom == 1) {
                    self.fb.scroll_top = top - 1;
                    self.fb.scroll_bottom = bottom - 1;
                    self.fb.move_row(0, false);
                    self.fb.move_col(0, false, false);
                }
            }
            // DECSC - Save Cursor Position
            's' => {
                self.fb.saved_cursor = (self.fb.cursor_row, self.fb.cursor_col);
            }
            // DECRC - Restore Cursor Position
            'u' => {
                let (row, col) = self.fb.saved_cursor;
                self.fb.cursor_row = row.min(self.fb.height - 1);
                self.fb.cursor_col = col.min(self.fb.width - 1);
                self.fb.wrap_pending = false;
            }
            _ => {
                log::trace!("Unhandled CSI: {:?} {:?} {:?}", params_vec, intermediates, action);
            }
        }
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], _ignore: bool, byte: u8) {
        match (intermediates, byte) {
            // DECSC - Save Cursor
            ([], b'7') => {
                self.fb.saved_cursor = (self.fb.cursor_row, self.fb.cursor_col);
            }
            // DECRC - Restore Cursor
            ([], b'8') => {
                let (row, col) = self.fb.saved_cursor;
                self.fb.cursor_row = row.min(self.fb.height - 1);
                self.fb.cursor_col = col.min(self.fb.width - 1);
                self.fb.wrap_pending = false;
            }
            // RI - Reverse Index
            ([], b'M') => {
                self.fb.move_rows_autoscroll(-1);
            }
            // IND - Index (move down)
            ([], b'D') => {
                self.fb.move_rows_autoscroll(1);
            }
            // NEL - Next Line
            ([], b'E') => {
                self.fb.move_col(0, false, false);
                self.fb.move_rows_autoscroll(1);
            }
            // RIS - Full Reset
            ([], b'c') => {
                let w = self.fb.width;
                let h = self.fb.height;
                *self.fb = Framebuffer::new(w, h);
            }
            _ => {
                log::trace!("Unhandled ESC: {:?} {:02x}", intermediates, byte);
            }
        }
    }
}

/// Terminal: wraps the framebuffer and VT parser state.
pub struct Terminal {
    pub fb: Framebuffer,
    parser: vte::Parser,
}

impl Clone for Terminal {
    fn clone(&self) -> Self {
        // Parser state is intentionally reset on clone.
        // Mosh host diffs are complete patches that can be reapplied from
        // framebuffer state without carrying incremental parser state.
        Self {
            fb: self.fb.clone(),
            parser: vte::Parser::new(),
        }
    }
}

impl Terminal {
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            fb: Framebuffer::new(width, height),
            parser: vte::Parser::new(),
        }
    }

    /// Feed raw bytes from the remote host through the VT parser.
    pub fn process(&mut self, data: &[u8]) {
        let mut performer = VtPerformer { fb: &mut self.fb };
        for &byte in data {
            self.parser.advance(&mut performer, byte);
        }
    }

    /// Resize the terminal.
    pub fn resize(&mut self, width: usize, height: usize) {
        self.fb.resize(width, height);
    }
}

impl fmt::Debug for Terminal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Terminal({}x{}, cursor=({},{}))",
            self.fb.width, self.fb.height, self.fb.cursor_row, self.fb.cursor_col
        )
    }
}
