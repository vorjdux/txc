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
        TextArea {
            lines: vec![String::new()],
            row: 0,
            column: 0,
            goal_column: 0,
        }
    }
}

impl TextArea {
    /// Builds an editor holding `text`, with the cursor at the end.
    pub fn from_text(text: &str) -> TextArea {
        let mut area = TextArea {
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
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    /// The individual lines, for rendering.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Cursor position as a zero based row and column.
    pub fn cursor(&self) -> (usize, usize) {
        (self.row, self.column)
    }

    /// Whether the editor holds no text at all.
    pub fn is_empty(&self) -> bool {
        self.lines.len() == 1 && self.lines[0].is_empty()
    }

    /// Removes all the text.
    pub fn clear(&mut self) {
        *self = TextArea::default();
    }

    pub fn insert(&mut self, ch: char) {
        let index = self.byte_index(self.row, self.column);
        self.lines[self.row].insert(index, ch);
        self.column += 1;
        self.goal_column = self.column;
    }

    pub fn insert_str(&mut self, text: &str) {
        for ch in text.chars() {
            if ch == '\n' {
                self.newline();
            } else {
                self.insert(ch);
            }
        }
    }

    pub fn newline(&mut self) {
        let index = self.byte_index(self.row, self.column);
        let tail = self.lines[self.row].split_off(index);
        self.lines.insert(self.row + 1, tail);
        self.row += 1;
        self.column = 0;
        self.goal_column = 0;
    }

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

    pub fn move_left(&mut self) {
        if self.column > 0 {
            self.column -= 1;
        } else if self.row > 0 {
            self.row -= 1;
            self.column = self.line_length(self.row);
        }
        self.goal_column = self.column;
    }

    pub fn move_right(&mut self) {
        if self.column < self.line_length(self.row) {
            self.column += 1;
        } else if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.column = 0;
        }
        self.goal_column = self.column;
    }

    pub fn move_up(&mut self) {
        if self.row > 0 {
            self.row -= 1;
            self.column = self.goal_column.min(self.line_length(self.row));
        }
    }

    pub fn move_down(&mut self) {
        if self.row + 1 < self.lines.len() {
            self.row += 1;
            self.column = self.goal_column.min(self.line_length(self.row));
        }
    }

    pub fn move_home(&mut self) {
        self.column = 0;
        self.goal_column = 0;
    }

    pub fn move_end(&mut self) {
        self.column = self.line_length(self.row);
        self.goal_column = self.column;
    }

    /// Removes the word before the cursor, as Ctrl+W does in a shell.
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
            .map(|(i, _)| i)
            .unwrap_or(self.lines[row].len())
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
