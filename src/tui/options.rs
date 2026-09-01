//! The options panel: one editable field per parameter of the operation.
//!
//! The fields start from the values the operation would use anyway, so the
//! panel shows what is about to happen rather than an empty box the reader has
//! to guess the syntax for.

use crate::params::Params;
use crate::registry::{Op, Param};

/// One parameter, with the value the reader has chosen for it.
#[derive(Clone, Debug)]
pub struct Field {
    /// The parameter this field stands for.
    pub param: &'static Param,
    /// Current text of a value parameter, unused by switches.
    pub value: String,
    /// Whether a switch is on, unused by value parameters.
    pub enabled: bool,
    /// Cursor position within `value`, counted in characters.
    pub cursor: usize,
}

impl Field {
    fn new(param: &'static Param) -> Field {
        let value = param.starting_value().to_string();
        Field {
            cursor: value.chars().count(),
            param,
            value,
            enabled: false,
        }
    }

    /// How the field reads in the panel.
    pub fn display(&self) -> String {
        if self.param.is_flag() {
            (if self.enabled { "on" } else { "off" }).to_string()
        } else {
            self.value.clone()
        }
    }

    fn byte_index(&self, column: usize) -> usize {
        self.value
            .char_indices()
            .nth(column)
            .map(|(i, _)| i)
            .unwrap_or(self.value.len())
    }
}

/// The whole panel: the fields of one operation, and which is selected.
#[derive(Clone, Debug, Default)]
pub struct OptionsEditor {
    fields: Vec<Field>,
    selected: usize,
}

impl OptionsEditor {
    /// Builds the fields for an operation, pre-filled with its defaults.
    ///
    /// ```
    /// use txc::find;
    /// use txc::tui::options::OptionsEditor;
    ///
    /// let op = find("caesar").expect("caesar is registered");
    /// let editor = OptionsEditor::for_op(op);
    ///
    /// // The panel starts from a working set of values, not an empty box.
    /// assert!(op.apply("abc", &editor.params(op), None).is_ok());
    /// ```
    pub fn for_op(op: &Op) -> OptionsEditor {
        OptionsEditor {
            fields: op.params.iter().map(Field::new).collect(),
            selected: 0,
        }
    }

    /// The fields, in the order the operation declared its parameters.
    ///
    /// ```
    /// use txc::find;
    /// use txc::tui::options::OptionsEditor;
    ///
    /// let op = find("caesar").expect("caesar is registered");
    /// let editor = OptionsEditor::for_op(op);
    /// assert_eq!(editor.fields().len(), op.params.len());
    /// ```
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }

    /// Index of the field the cursor is on.
    pub fn selected(&self) -> usize {
        self.selected
    }

    /// Whether the operation has no parameters, in which case the panel is
    /// not drawn at all.
    ///
    /// ```
    /// use txc::find;
    /// use txc::tui::options::OptionsEditor;
    ///
    /// let op = find("upper").expect("upper is registered");
    /// assert!(OptionsEditor::for_op(op).is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// How many fields the panel holds.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// The parameters as the operation will receive them.
    ///
    /// A value that is still empty is left out, so a parameter with no default
    /// behaves exactly as it would if it had not been mentioned at all.
    ///
    /// ```
    /// use txc::find;
    /// use txc::tui::options::OptionsEditor;
    ///
    /// let op = find("caesar").expect("caesar is registered");
    /// let editor = OptionsEditor::for_op(op);
    /// assert_eq!(op.apply("abc", &editor.params(op), None)?, "def");
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn params(&self, op: &Op) -> Params {
        let mut params = Params::for_op(op);
        for field in &self.fields {
            if field.param.is_flag() {
                if field.enabled {
                    params.enable(field.param.name);
                }
            } else if !field.value.is_empty() || field.param.default_value() == Some("") {
                params.set(field.param.name, field.value.clone());
            }
        }
        params
    }

    /// Moves to the next field, wrapping round at the end.
    ///
    /// ```
    /// use txc::find;
    /// use txc::tui::options::OptionsEditor;
    ///
    /// let op = find("caesar").expect("caesar is registered");
    /// let mut editor = OptionsEditor::for_op(op);
    /// for _ in 0..editor.len() {
    ///     editor.select_next();
    /// }
    /// assert_eq!(editor.selected(), 0); // all the way round
    /// ```
    pub fn select_next(&mut self) {
        if !self.fields.is_empty() {
            self.selected = (self.selected + 1) % self.fields.len();
        }
    }

    /// Moves to the previous field, wrapping round at the start.
    pub fn select_previous(&mut self) {
        if !self.fields.is_empty() {
            self.selected = (self.selected + self.fields.len() - 1) % self.fields.len();
        }
    }

    fn current(&mut self) -> Option<&mut Field> {
        self.fields.get_mut(self.selected)
    }

    /// Whether the selected field is a switch, which changes what the space
    /// and enter keys do.
    pub fn selected_is_flag(&self) -> bool {
        self.fields
            .get(self.selected)
            .is_some_and(|f| f.param.is_flag())
    }

    /// Turns the selected switch on or off. Returns false for value fields.
    pub fn toggle(&mut self) -> bool {
        match self.current() {
            Some(field) if field.param.is_flag() => {
                field.enabled = !field.enabled;
                true
            }
            _ => false,
        }
    }

    /// Types one character into the selected value field. Switches ignore it.
    pub fn insert(&mut self, ch: char) {
        if let Some(field) = self.current()
            && !field.param.is_flag()
        {
            let index = field.byte_index(field.cursor);
            field.value.insert(index, ch);
            field.cursor += 1;
        }
    }

    /// Deletes the character before the cursor in the selected value field.
    pub fn backspace(&mut self) {
        if let Some(field) = self.current()
            && !field.param.is_flag()
            && field.cursor > 0
        {
            let start = field.byte_index(field.cursor - 1);
            let end = field.byte_index(field.cursor);
            field.value.replace_range(start..end, "");
            field.cursor -= 1;
        }
    }

    /// Deletes the character after the cursor in the selected value field.
    pub fn delete(&mut self) {
        if let Some(field) = self.current()
            && !field.param.is_flag()
            && field.cursor < field.value.chars().count()
        {
            let start = field.byte_index(field.cursor);
            let end = field.byte_index(field.cursor + 1);
            field.value.replace_range(start..end, "");
        }
    }

    /// Moves the cursor one character left within the selected value.
    pub fn move_left(&mut self) {
        if let Some(field) = self.current() {
            field.cursor = field.cursor.saturating_sub(1);
        }
    }

    /// Moves the cursor one character right within the selected value.
    pub fn move_right(&mut self) {
        if let Some(field) = self.current() {
            field.cursor = (field.cursor + 1).min(field.value.chars().count());
        }
    }

    /// Moves the cursor to the start of the selected value.
    pub fn move_home(&mut self) {
        if let Some(field) = self.current() {
            field.cursor = 0;
        }
    }

    /// Moves the cursor to the end of the selected value.
    pub fn move_end(&mut self) {
        if let Some(field) = self.current() {
            field.cursor = field.value.chars().count();
        }
    }

    /// Empties the selected value field.
    pub fn clear_selected(&mut self) {
        if let Some(field) = self.current()
            && !field.param.is_flag()
        {
            field.value.clear();
            field.cursor = 0;
        }
    }

    /// Puts every field back to the value the operation starts from.
    pub fn reset(&mut self) {
        for field in &mut self.fields {
            *field = Field::new(field.param);
        }
    }

    /// Cursor position within the selected field, for drawing.
    pub fn cursor(&self) -> usize {
        self.fields
            .get(self.selected)
            .map(|f| f.cursor)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::find;

    #[test]
    fn fields_start_from_the_declared_defaults() {
        let op = find("caesar").unwrap();
        let editor = OptionsEditor::for_op(op);
        assert_eq!(editor.len(), 1);
        assert_eq!(editor.fields()[0].param.name, "shift");
        assert_eq!(editor.fields()[0].value, "3");
        // Running with the panel untouched matches running with no options.
        assert_eq!(op.apply("abc", &editor.params(op), None).unwrap(), "def");
    }

    #[test]
    fn required_parameters_start_from_their_suggestion() {
        let op = find("replace").unwrap();
        let editor = OptionsEditor::for_op(op);
        let find_field = editor
            .fields()
            .iter()
            .find(|f| f.param.name == "find")
            .unwrap();
        assert_eq!(find_field.value, "fox");
        // So the operation produces a result immediately instead of an error.
        let result = op.apply("the fox ran", &editor.params(op), None).unwrap();
        assert_eq!(result, "the cat ran");
    }

    #[test]
    fn editing_a_value_changes_the_result() {
        let op = find("caesar").unwrap();
        let mut editor = OptionsEditor::for_op(op);
        editor.clear_selected();
        editor.insert('1');
        assert_eq!(op.apply("abc", &editor.params(op), None).unwrap(), "bcd");
    }

    #[test]
    fn switches_toggle_rather_than_being_typed() {
        let op = find("sort").unwrap();
        let mut editor = OptionsEditor::for_op(op);
        assert!(editor.selected_is_flag());
        assert_eq!(editor.fields()[0].display(), "off");
        assert!(editor.toggle());
        assert_eq!(editor.fields()[0].display(), "on");
        assert_eq!(editor.fields()[0].param.name, "reverse");
        assert_eq!(op.apply("a\nb", &editor.params(op), None).unwrap(), "b\na");
    }

    #[test]
    fn moves_between_fields_and_wraps_around() {
        let op = find("sort").unwrap();
        let mut editor = OptionsEditor::for_op(op);
        let count = editor.len();
        editor.select_previous();
        assert_eq!(editor.selected(), count - 1);
        editor.select_next();
        assert_eq!(editor.selected(), 0);
    }

    #[test]
    fn edits_multibyte_values_correctly() {
        let op = find("quote").unwrap();
        let mut editor = OptionsEditor::for_op(op);
        editor.clear_selected();
        for ch in "caf\u{e9}".chars() {
            editor.insert(ch);
        }
        editor.move_left();
        editor.backspace();
        assert_eq!(editor.fields()[0].value, "ca\u{e9}");
    }

    #[test]
    fn reset_restores_every_field() {
        let op = find("sort").unwrap();
        let mut editor = OptionsEditor::for_op(op);
        editor.toggle();
        editor.select_next();
        editor.reset();
        assert!(editor.fields().iter().all(|f| !f.enabled));
    }

    #[test]
    fn an_operation_without_parameters_has_no_fields() {
        let op = find("upper").unwrap();
        assert!(OptionsEditor::for_op(op).is_empty());
    }

    #[test]
    fn an_emptied_optional_value_is_treated_as_absent() {
        let op = find("filter").unwrap();
        let mut editor = OptionsEditor::for_op(op);
        // Clearing the suggested value brings back the operation's own error.
        editor.clear_selected();
        assert!(op.apply("a\nb", &editor.params(op), None).is_err());
    }

    #[test]
    fn every_operation_starts_with_a_working_set_of_options() {
        for op in crate::registry::all() {
            let editor = OptionsEditor::for_op(op);
            let result = op.apply(op.sample_input(), &editor.params(op), None);
            assert!(
                result.is_ok(),
                "{} failed on its own sample: {}",
                op.name,
                result.unwrap_err()
            );
        }
    }
}
