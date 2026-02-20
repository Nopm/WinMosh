//! Windows-native terminal renderer using crossterm.
//!
//! Reads the terminal framebuffer and emits minimal crossterm commands
//! to update the physical display. Uses differential rendering to only
//! update cells that have changed.

use crate::terminal::{Attributes, Cell, Color, Framebuffer};
use crossterm::{
    cursor,
    execute, queue,
    style::{self, Attribute, SetAttribute, SetBackgroundColor, SetForegroundColor},
    terminal::{self, ClearType},
};
use std::io::{self, Write};

/// Convert our Color type to crossterm's Color type.
fn to_crossterm_color(color: Color) -> style::Color {
    match color {
        Color::Default => style::Color::Reset,
        Color::Indexed(idx) => match idx {
            0 => style::Color::Black,
            1 => style::Color::DarkRed,
            2 => style::Color::DarkGreen,
            3 => style::Color::DarkYellow,
            4 => style::Color::DarkBlue,
            5 => style::Color::DarkMagenta,
            6 => style::Color::DarkCyan,
            7 => style::Color::Grey,
            8 => style::Color::DarkGrey,
            9 => style::Color::Red,
            10 => style::Color::Green,
            11 => style::Color::Yellow,
            12 => style::Color::Blue,
            13 => style::Color::Magenta,
            14 => style::Color::Cyan,
            15 => style::Color::White,
            n => style::Color::AnsiValue(n),
        },
        Color::Rgb(r, g, b) => style::Color::Rgb { r, g, b },
    }
}

/// The terminal renderer.
pub struct Renderer {
    /// Previous frame state for differential rendering.
    prev_cells: Vec<Vec<Cell>>,
    prev_cursor: (usize, usize),
    prev_cursor_visible: bool,
    /// Dimensions.
    width: usize,
    height: usize,
    /// Whether we need a full redraw.
    force_redraw: bool,
}

impl Renderer {
    /// Create a new renderer for the given terminal dimensions.
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            prev_cells: vec![vec![Cell::default(); width]; height],
            prev_cursor: (0, 0),
            prev_cursor_visible: true,
            width,
            height,
            force_redraw: true,
        }
    }

    /// Resize the renderer (forces a full redraw).
    pub fn resize(&mut self, width: usize, height: usize) {
        self.width = width;
        self.height = height;
        self.prev_cells = vec![vec![Cell::default(); width]; height];
        self.force_redraw = true;
    }

    /// Force a full redraw on the next render call.
    pub fn force_redraw(&mut self) {
        self.force_redraw = true;
    }

    /// Render the framebuffer to the terminal, only updating changed cells.
    pub fn render(&mut self, fb: &Framebuffer) -> io::Result<()> {
        let mut stdout = io::stdout();

        // Hide cursor during rendering to avoid flicker
        queue!(stdout, cursor::Hide)?;

        let full_redraw = self.force_redraw
            || fb.width != self.width
            || fb.height != self.height;

        if full_redraw {
            // Full redraw
            queue!(
                stdout,
                terminal::Clear(ClearType::All),
                cursor::MoveTo(0, 0)
            )?;

            self.width = fb.width;
            self.height = fb.height;

            let mut last_fg = Color::Default;
            let mut last_bg = Color::Default;
            let mut last_attrs = Attributes::default();

            for row in 0..fb.height {
                queue!(stdout, cursor::MoveTo(0, row as u16))?;
                for col in 0..fb.width {
                    let cell = &fb.cells[row][col];
                    self.emit_cell(&mut stdout, cell, &mut last_fg, &mut last_bg, &mut last_attrs)?;
                }
            }

            // Reset attributes
            queue!(stdout, style::ResetColor, SetAttribute(Attribute::Reset))?;

            // Update prev state
            self.prev_cells = fb.cells.clone();
            self.force_redraw = false;
        } else {
            // Differential rendering: only update dirty cells
            let mut last_fg = Color::Default;
            let mut last_bg = Color::Default;
            let mut last_attrs = Attributes::default();
            let mut last_row: Option<usize> = None;
            let mut last_col: usize = 0;

            for row in 0..fb.height.min(self.prev_cells.len()) {
                for col in 0..fb.width.min(self.prev_cells[row].len()) {
                    let cell = &fb.cells[row][col];
                    let prev = &self.prev_cells[row][col];

                    if cell != prev {
                        // Move cursor if not at expected position
                        let need_move = last_row != Some(row) || last_col != col;
                        if need_move {
                            queue!(stdout, cursor::MoveTo(col as u16, row as u16))?;
                        }

                        self.emit_cell(&mut stdout, cell, &mut last_fg, &mut last_bg, &mut last_attrs)?;

                        last_row = Some(row);
                        last_col = col + 1;

                        // Update prev state for this cell
                        self.prev_cells[row][col] = cell.clone();
                    }
                }
            }

            // Reset attributes after differential update
            if last_row.is_some() {
                queue!(stdout, style::ResetColor, SetAttribute(Attribute::Reset))?;
            }
        }

        // Restore cursor position and visibility
        let cursor_row = fb.cursor_row.min(fb.height.saturating_sub(1));
        let cursor_col = fb.cursor_col.min(fb.width.saturating_sub(1));

        queue!(
            stdout,
            cursor::MoveTo(cursor_col as u16, cursor_row as u16)
        )?;

        if fb.cursor_visible {
            queue!(stdout, cursor::Show)?;
        }

        self.prev_cursor = (cursor_row, cursor_col);
        self.prev_cursor_visible = fb.cursor_visible;

        stdout.flush()?;
        Ok(())
    }

    /// Emit a single cell's content with appropriate styling.
    fn emit_cell(
        &self,
        stdout: &mut io::Stdout,
        cell: &Cell,
        last_fg: &mut Color,
        last_bg: &mut Color,
        last_attrs: &mut Attributes,
    ) -> io::Result<()> {
        // Update foreground color if changed
        if cell.fg != *last_fg {
            queue!(stdout, SetForegroundColor(to_crossterm_color(cell.fg)))?;
            *last_fg = cell.fg;
        }

        // Update background color if changed
        if cell.bg != *last_bg {
            queue!(stdout, SetBackgroundColor(to_crossterm_color(cell.bg)))?;
            *last_bg = cell.bg;
        }

        // Update attributes if changed
        if cell.attrs != *last_attrs {
            // Reset first, then set what's needed
            queue!(stdout, SetAttribute(Attribute::Reset))?;
            *last_fg = Color::Default;
            *last_bg = Color::Default;

            // Re-apply colors
            if cell.fg != Color::Default {
                queue!(stdout, SetForegroundColor(to_crossterm_color(cell.fg)))?;
                *last_fg = cell.fg;
            }
            if cell.bg != Color::Default {
                queue!(stdout, SetBackgroundColor(to_crossterm_color(cell.bg)))?;
                *last_bg = cell.bg;
            }

            if cell.attrs.bold {
                queue!(stdout, SetAttribute(Attribute::Bold))?;
            }
            if cell.attrs.italic {
                queue!(stdout, SetAttribute(Attribute::Italic))?;
            }
            if cell.attrs.underline {
                queue!(stdout, SetAttribute(Attribute::Underlined))?;
            }
            if cell.attrs.blink {
                queue!(stdout, SetAttribute(Attribute::SlowBlink))?;
            }
            if cell.attrs.inverse {
                queue!(stdout, SetAttribute(Attribute::Reverse))?;
            }
            if cell.attrs.invisible {
                queue!(stdout, SetAttribute(Attribute::Hidden))?;
            }
            if cell.attrs.strikethrough {
                queue!(stdout, SetAttribute(Attribute::CrossedOut))?;
            }

            *last_attrs = cell.attrs;
        }

        // Print the character
        queue!(stdout, style::Print(cell.character))?;

        Ok(())
    }

    /// Initialize the terminal for raw mode rendering.
    pub fn init() -> io::Result<()> {
        terminal::enable_raw_mode()?;
        execute!(
            io::stdout(),
            cursor::Show,
        )?;
        Ok(())
    }

    /// Restore the terminal to its original state.
    pub fn cleanup() -> io::Result<()> {
        execute!(
            io::stdout(),
            style::ResetColor,
            cursor::Show,
        )?;
        terminal::disable_raw_mode()?;
        Ok(())
    }
}

/// Notification overlay bar shown at the bottom of the screen.
pub struct NotificationBar {
    message: String,
    visible: bool,
}

impl NotificationBar {
    pub fn new() -> Self {
        Self {
            message: String::new(),
            visible: false,
        }
    }

    pub fn set_message(&mut self, msg: &str) {
        self.message = msg.to_string();
        self.visible = !msg.is_empty();
    }

    pub fn clear(&mut self) {
        self.message.clear();
        self.visible = false;
    }

    /// Render the notification bar at the bottom of the screen.
    pub fn render(&self, width: usize, height: usize) -> io::Result<()> {
        if !self.visible || height == 0 {
            return Ok(());
        }

        let mut stdout = io::stdout();
        let bar_row = (height - 1) as u16;

        queue!(
            stdout,
            cursor::MoveTo(0, bar_row),
            SetBackgroundColor(style::Color::DarkBlue),
            SetForegroundColor(style::Color::White),
            SetAttribute(Attribute::Bold),
        )?;

        // Pad or truncate message to fit width
        let display_msg = if self.message.len() > width {
            &self.message[..width]
        } else {
            &self.message
        };

        queue!(stdout, style::Print(display_msg))?;

        // Fill remaining space
        let padding = width.saturating_sub(display_msg.len());
        if padding > 0 {
            queue!(stdout, style::Print(" ".repeat(padding)))?;
        }

        queue!(
            stdout,
            style::ResetColor,
            SetAttribute(Attribute::Reset),
        )?;

        stdout.flush()?;
        Ok(())
    }
}
