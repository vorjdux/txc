//! A small multi line text editor used by the interactive interface.

/// Editable text with a cursor, stored as lines of characters.
///
/// Positions are counted in characters rather than bytes so that accented
/// letters and other multi byte characters behave like single keystrokes.
#[derive(Debug, Clone)]
pub struct TextArea {
    lines: Vec<String>,
    row: usize,
    column: usize,
    /// Column the cursor tries to return to when moving up and down.
    goal_column: usize,
}

impl Default for TextArea {
    fn default() -> Self {
        Self {
            lines: vec![String::new()],
            row: 0,
            column: 0,
            goal_column: 0,
        }
    }
}

impl TextArea {
    /// Builds an editor holding `text`, with the cursor at the end.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// let area = TextArea::from_text("one\ntwo");
    /// assert_eq!(area.lines(), ["one", "two"]);
    /// assert_eq!(area.cursor(), (1, 3));
    /// ```
    pub fn from_text(text: &str) -> Self {
        let mut area = Self {
            lines: text.split('\n').map(str::to_string).collect(),
            row: 0,
            column: 0,
            goal_column: 0,
        };
        if area.lines.is_empty() {
            area.lines.push(String::new());
        }
        area.row = area.lines.len() - 1;
        area.column = area.line_length(area.row);
        area
    }

    /// The whole text, with lines joined by newlines.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// assert_eq!(TextArea::from_text("one\ntwo").text(), "one\ntwo");
    /// ```
    #[must_use]
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    /// The individual lines, for rendering.
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Cursor position as a zero based row and column.
    ///
    /// The column counts characters, not bytes.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// // Four characters, even though "é" takes two bytes.
    /// assert_eq!(TextArea::from_text("café").cursor(), (0, 4));
    /// ```
    #[must_use]
    pub const fn cursor(&self) -> (usize, usize) {
        (self.row, self.column)
    }

    /// Whether the editor holds no text at all.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// assert!(TextArea::default().is_empty());
    /// assert!(!TextArea::from_text("x").is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lines.len() == 1 && self.lines[0].is_empty()
    }

    /// Removes all the text.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// let mut area = TextArea::from_text("something");
    /// area.clear();
    /// assert!(area.is_empty());
    /// assert_eq!(area.cursor(), (0, 0));
    /// ```
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Inserts one character at the cursor, moving it right.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// let mut area = TextArea::from_text("ab");
    /// area.insert('c');
    /// assert_eq!(area.text(), "abc");
    /// ```
    pub fn insert(&mut self, ch: char) {
        let index = self.byte_index(self.row, self.column);
        self.lines[self.row].insert(index, ch);
        self.column += 1;
        self.goal_column = self.column;
    }

    /// Inserts a run of text at the cursor, splitting lines at newlines.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// let mut area = TextArea::default();
    /// area.insert_str("one\ntwo");
    /// assert_eq!(area.lines(), ["one", "two"]);
    /// ```
    pub fn insert_str(&mut self, text: &str) {
        for ch in text.chars() {
            if ch == '\n' {
                self.newline();
            } else {
                self.insert(ch);
            }
        }
    }

    /// Splits the line at the cursor, which moves to the start of the new one.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// let mut area = TextArea::from_text("ab");
    /// area.move_home();
    /// area.newline();
    /// assert_eq!(area.lines(), ["", "ab"]);
    /// ```
    pub fn newline(&mut self) {
        let index = self.byte_index(self.row, self.column);
        let tail = self.lines[self.row].split_off(index);
        self.lines.insert(self.row + 1, tail);
        self.row += 1;
        self.column = 0;
        self.goal_column = 0;
    }

    /// Deletes the character before the cursor, joining lines at a line start.
    ///
    /// Does nothing at the very beginning of the text.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// let mut area = TextArea::from_text("one\ntwo");
    /// area.move_home();
    /// area.backspace();
    /// assert_eq!(area.text(), "onetwo");
    /// ```
    pub fn backspace(&mut self) {
        if self.column > 0 {
            let start = self.byte_index(self.row, self.column - 1);
            let end = self.byte_index(self.row, self.column);
            self.lines[self.row].replace_range(start..end, "");
            self.column -= 1;
        } else if self.row > 0 {
            // Joining with the line above puts the cursor at the seam.
            let current = self.lines.remove(self.row);
            self.row -= 1;
            self.column = self.line_length(self.row);
            self.lines[self.row].push_str(&current);
        }
        self.goal_column = self.column;
    }

    /// Deletes the character after the cursor, pulling the next line up at a
    /// line end.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// let mut area = TextArea::from_text("abc");
    /// area.move_home();
    /// area.delete();
    /// assert_eq!(area.text(), "bc");
    /// ```
    pub fn delete(&mut self) {
        if self.column < self.line_length(self.row) {
            let start = self.byte_index(self.row, self.column);
            let end = self.byte_index(self.row, self.column + 1);
            self.lines[self.row].replace_range(start..end, "");
        } else if self.row + 1 < self.lines.len() {
            let next = self.lines.remove(self.row + 1);
            self.lines[self.row].push_str(&next);
        }
    }

    /// Moves the cursor one character left, wrapping to the line above.
    pub fn move_left(&mut self) {
        if self.column > 0 {
            self.column -= 1;
        } else if self.row > 0 {
            self.row -= 1;
            self.column = self.line_length(self.row);
        }
        self.goal_column = self.column;
    }

    /// Moves the cursor one character right, wrapping to the line below.
    pub fn move_right(&mut self) {
        if self.column < self.line_length(self.row) {
            self.column += 1;
        } else if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.column = 0;
        }
        self.goal_column = self.column;
    }

    /// Moves the cursor to the line above, keeping the column it is aiming for.
    ///
    /// Moving through a short line and out the other side returns to the
    /// original column rather than staying where the short line ended.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// let mut area = TextArea::from_text("longer line\nx\nlonger line");
    /// area.move_end(); // aiming for column 11
    /// area.move_up();
    /// assert_eq!(area.cursor(), (1, 1)); // clamped by the short line
    /// area.move_up();
    /// assert_eq!(area.cursor(), (0, 11)); // and back out to the goal column
    /// ```
    pub fn move_up(&mut self) {
        if self.row > 0 {
            self.row -= 1;
            self.column = self.goal_column.min(self.line_length(self.row));
        }
    }

    /// Moves the cursor to the line below, keeping the column it is aiming for.
    pub fn move_down(&mut self) {
        if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.column = self.goal_column.min(self.line_length(self.row));
        }
    }

    /// Moves the cursor to the start of the current line.
    pub const fn move_home(&mut self) {
        self.column = 0;
        self.goal_column = 0;
    }

    /// Moves the cursor to the end of the current line.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// let mut area = TextArea::from_text("abc");
    /// area.move_home();
    /// area.move_end();
    /// assert_eq!(area.cursor(), (0, 3));
    /// ```
    pub fn move_end(&mut self) {
        self.column = self.line_length(self.row);
        self.goal_column = self.column;
    }

    /// Removes the word before the cursor, as Ctrl+W does in a shell.
    ///
    /// Whitespace immediately before the cursor goes with it.
    ///
    /// ```
    /// use txc::tui::textarea::TextArea;
    ///
    /// let mut area = TextArea::from_text("one two ");
    /// area.delete_word();
    /// assert_eq!(area.text(), "one ");
    /// ```
    pub fn delete_word(&mut self) {
        while self.column > 0 && self.char_before().is_some_and(char::is_whitespace) {
            self.backspace();
        }
        while self.column > 0 && self.char_before().is_some_and(|c| !c.is_whitespace()) {
            self.backspace();
        }
    }

    fn char_before(&self) -> Option<char> {
        if self.column == 0 {
            return None;
        }
        self.lines[self.row].chars().nth(self.column - 1)
    }

    fn line_length(&self, row: usize) -> usize {
        self.lines[row].chars().count()
    }

    /// Converts a character column into a byte offset for string editing.
    fn byte_index(&self, row: usize, column: usize) -> usize {
        self.lines[row]
            .char_indices()
            .nth(column)
            .map_or(self.lines[row].len(), |(i, _)| i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_and_deleting() {
        let mut area = TextArea::default();
        area.insert_str("hello");
        assert_eq!(area.text(), "hello");
        assert_eq!(area.cursor(), (0, 5));

        area.backspace();
        assert_eq!(area.text(), "hell");

        area.move_home();
        area.delete();
        assert_eq!(area.text(), "ell");
    }

    #[test]
    fn newlines_split_and_join() {
        let mut area = TextArea::from_text("ab");
        area.move_home();
        area.move_right();
        area.newline();
        assert_eq!(area.text(), "a\nb");
        assert_eq!(area.cursor(), (1, 0));

        area.backspace();
        assert_eq!(area.text(), "ab");
        assert_eq!(area.cursor(), (0, 1));
    }

    #[test]
    fn moves_across_multibyte_characters() {
        let mut area = TextArea::from_text("caf\u{e9}s");
        area.move_home();
        for _ in 0..4 {
            area.move_right();
        }
        area.insert('!');
        assert_eq!(area.text(), "caf\u{e9}!s");
    }

    #[test]
    fn vertical_movement_remembers_the_column() {
        let mut area = TextArea::from_text("long line\nx\nanother line");
        area.move_up();
        area.move_up();
        area.move_end();
        assert_eq!(area.cursor(), (0, 9));

        area.move_down();
        // The short line clamps the column.
        assert_eq!(area.cursor(), (1, 1));
        area.move_down();
        // The original column is restored where the line is long enough.
        assert_eq!(area.cursor(), (2, 9));
    }

    #[test]
    fn deletes_a_word_at_a_time() {
        let mut area = TextArea::from_text("one two  three");
        area.delete_word();
        assert_eq!(area.text(), "one two  ");
        area.delete_word();
        assert_eq!(area.text(), "one ");
    }

    #[test]
    fn tracks_emptiness() {
        let mut area = TextArea::default();
        assert!(area.is_empty());
        area.insert('a');
        assert!(!area.is_empty());
        area.clear();
        assert!(area.is_empty());
    }
}
