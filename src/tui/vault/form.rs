//! The form for adding or editing an entry, built from the fields its kind
//! has.
//!
//! Plain fields are ordinary text. Secret fields show one dot per character,
//! can be shown while typing with ctrl+r, are filled in with ctrl+g where the
//! field can be generated, and live in buffers that are wiped and never
//! reallocated. A note is a real editor over several lines, since notes are
//! there to be read.

use age::secrecy::{ExposeSecret, SecretString};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use crate::tui::textarea::TextArea;
use crate::vault::command::{DEFAULT_GENERATED_LENGTH, PIN_LENGTH, generate, generate_pin};
use crate::vault::model::{
    Entry, Field, FieldSpec, Generator, Kind, MAX_SECRET_BYTES, Sensitivity, check_tag, displayable,
};

/// Room for a typed passphrase or a one line secret, in bytes.
pub const LINE_BYTES: usize = 4096;

const DISCARD: &str = "There are unsaved changes: esc again discards them, ctrl+s saves them.";

/// The characters of pasted text with every line break as `\n`.
///
/// Terminals send a pasted line break as `\r`, `\n` or `\r\n`, depending on
/// the terminal and on what sits in between, such as tmux. Dropping the `\r`
/// alone would run the lines of a private key or a note together.
pub fn line_breaks(text: &str) -> impl Iterator<Item = char> + '_ {
    let mut chars = text.chars().peekable();
    std::iter::from_fn(move || {
        let ch = chars.next()?;
        if ch == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            Some('\n')
        } else {
            Some(ch)
        }
    })
}

/// A field for typing a secret: shown as dots, wiped when cleared or dropped.
///
/// Its buffer is allocated once, at the most it may hold, so typing never
/// moves the text to a larger buffer and leaves a copy in the old one.
pub struct SecretInput {
    text: Zeroizing<String>,
}

impl Default for SecretInput {
    fn default() -> Self {
        Self::with_capacity(LINE_BYTES)
    }
}

impl SecretInput {
    /// An empty field that holds up to `bytes`.
    #[must_use]
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            text: Zeroizing::new(String::with_capacity(bytes)),
        }
    }

    /// Adds a character, unless the field is full.
    // `text.len()` is bounded by its small fixed capacity and `ch.len_utf8()`
    // is at most 4, nowhere near overflowing `usize`.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn insert(&mut self, ch: char) {
        if self.text.len() + ch.len_utf8() <= self.text.capacity() {
            self.text.push(ch);
        }
    }

    /// Adds pasted text. Line breaks are kept only when the field takes
    /// several lines.
    pub fn insert_str(&mut self, text: &str, multiline: bool) {
        for ch in line_breaks(text) {
            match ch {
                '\n' if !multiline => {}
                ch => self.insert(ch),
            }
        }
    }

    /// Removes the last character.
    pub fn backspace(&mut self) {
        self.text.pop();
    }

    /// Wipes the field, keeping its buffer for the next typing.
    pub fn clear(&mut self) {
        let len = self.text.len();
        self.text.clear();
        self.text.extend(std::iter::repeat_n('\0', len));
        self.text.clear();
    }

    /// Whether nothing has been typed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// How many characters have been typed.
    #[must_use]
    pub fn chars(&self) -> usize {
        self.text.chars().count()
    }

    /// How many lines have been typed.
    #[must_use]
    pub fn lines(&self) -> usize {
        self.text.split('\n').count()
    }

    /// The typed text, as a secret.
    #[must_use]
    pub fn secret(&self) -> SecretString {
        SecretString::from(self.text.as_str().to_owned())
    }

    /// Replaces the text with a secret.
    pub fn set(&mut self, secret: &SecretString) {
        self.clear();
        for ch in secret.expose_secret().chars() {
            self.insert(ch);
        }
    }

    /// One dot per character, at most `width` of them.
    #[must_use]
    pub fn masked(&self, width: usize) -> String {
        "•".repeat(self.chars().min(width))
    }

    /// The text itself, on one line and safe to draw, for when it has been
    /// asked to be shown.
    #[must_use]
    pub fn shown(&self) -> String {
        self.text
            .split('\n')
            .map(displayable)
            .collect::<Vec<_>>()
            .join(" ⏎ ")
    }
}

/// How a field of the form is typed into.
pub enum Input {
    /// Ordinary text on one line.
    Text(TextArea),
    /// A secret, shown as dots.
    Secret(SecretInput),
    /// A note, over several lines.
    Note(TextArea),
}

/// One field of the form.
pub struct FormField {
    /// The name it is stored under.
    pub name: String,
    /// What it is called on screen.
    pub label: String,
    /// Whether it may run over several lines.
    pub multiline: bool,
    /// What can fill it in.
    pub generator: Option<Generator>,
    /// An example shown while it is empty.
    pub hint: &'static str,
    /// What has been typed.
    pub input: Input,
    /// Whether the entry being edited already has a value here. A secret left
    /// empty keeps that value.
    pub has_value: bool,
    /// Whether it has been typed into.
    pub touched: bool,
    /// Whether its value was generated.
    pub generated: bool,
}

impl FormField {
    fn blank(spec: &FieldSpec) -> Self {
        let input = match spec.sensitivity {
            Sensitivity::Plain => Input::Text(TextArea::default()),
            Sensitivity::Secret => Input::Secret(SecretInput::with_capacity(if spec.multiline {
                MAX_SECRET_BYTES
            } else {
                LINE_BYTES
            })),
            Sensitivity::Private => Input::Note(TextArea::default()),
        };
        Self {
            name: spec.name.to_string(),
            label: spec.label.to_string(),
            multiline: spec.multiline,
            generator: spec.generator,
            hint: spec.hint,
            input,
            has_value: false,
            touched: false,
            generated: false,
        }
    }

    /// A field the kind does not define, or one stored differently from how
    /// the kind defines it, typed into the way it is stored.
    fn stored(entry: &Entry, field: &Field) -> Self {
        let input = match entry.plain(&field.name) {
            Some(value) => Input::Text(TextArea::from_text(value)),
            None => Input::Secret(SecretInput::with_capacity(MAX_SECRET_BYTES)),
        };
        Self {
            name: field.name.clone(),
            label: entry.label(&field.name).to_string(),
            multiline: false,
            generator: None,
            hint: "",
            input,
            has_value: true,
            touched: false,
            generated: false,
        }
    }

    /// Whether Enter makes a new line here rather than moving on.
    #[must_use]
    pub const fn takes_lines(&self) -> bool {
        match self.input {
            Input::Note(_) => true,
            Input::Secret(_) => self.multiline,
            Input::Text(_) => false,
        }
    }
}

/// A row of the form.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Row {
    /// The entry's name.
    Name,
    /// Which vault it goes in, offered only when adding and there is a choice.
    Vault,
    /// One of the kind's fields.
    Field(usize),
    /// Its tags.
    Tags,
}

/// What a key asks the screen to do with the form.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FormAction {
    /// Keep editing.
    Stay,
    /// Save it.
    Save,
    /// Close it without saving.
    Cancel,
}

/// What the form holds, ready to become an entry or a change.
pub struct Collected {
    /// The name.
    pub name: String,
    /// Plain values given.
    pub plain: Vec<(String, String)>,
    /// Secrets typed.
    pub secrets: Vec<(String, SecretString)>,
    /// Fields emptied, to remove.
    pub cleared: Vec<String>,
    /// Tags.
    pub tags: Vec<String>,
}

/// The form for adding or editing an entry.
pub struct EntryForm {
    /// The name of the entry being edited, or `None` when adding.
    pub editing: Option<String>,
    /// What the entry is.
    pub kind: Kind,
    /// The vaults it can go in: the screen's index for each, and its name.
    pub vaults: Vec<(usize, String)>,
    /// Which of `vaults` is chosen.
    pub vault: usize,
    /// The name typed.
    pub name: TextArea,
    /// The kind's fields, then any others the entry has.
    pub fields: Vec<FormField>,
    /// The tags typed, separated by commas or spaces.
    pub tags: TextArea,
    /// The row being edited.
    pub row: Row,
    /// Whether the secret being typed is shown.
    pub reveal: bool,
    /// Why the last attempt to save failed, or a warning.
    pub error: Option<String>,
    /// Whether anything has changed since the form opened.
    pub dirty: bool,
    discard_armed: bool,
}

impl EntryForm {
    /// An empty form for a new entry of `kind`, in the vault at `vault` of
    /// `vaults`.
    #[must_use]
    pub fn adding(kind: Kind, vaults: Vec<(usize, String)>, vault: usize) -> Self {
        Self {
            editing: None,
            kind,
            vault: vault.min(vaults.len().saturating_sub(1)),
            vaults,
            name: TextArea::default(),
            fields: kind.fields().iter().map(FormField::blank).collect(),
            tags: TextArea::default(),
            row: Row::Name,
            reveal: false,
            error: None,
            dirty: false,
            discard_armed: false,
        }
    }

    /// A form filled in from an entry. Its secrets stay sealed and empty,
    /// meaning unchanged; its notes come already opened in `notes`.
    // `index` is either an existing position in `fields`, or `fields.len() -
    // 1` right after that same field was pushed, so both are always in
    // bounds.
    #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    #[must_use]
    pub fn editing(
        entry: &Entry,
        vault: (usize, String),
        notes: &[(String, SecretString)],
    ) -> Self {
        let mut fields: Vec<FormField> = entry.kind.fields().iter().map(FormField::blank).collect();
        for field in &entry.fields {
            let position = fields.iter().position(|form| form.name == field.name);
            let index = if let Some(index) = position {
                index
            } else {
                fields.push(FormField::stored(entry, field));
                fields.len() - 1
            };
            let form = &mut fields[index];
            let stored_sealed = field.is_sealed();
            let form_sealed = !matches!(form.input, Input::Text(_));
            if stored_sealed != form_sealed {
                *form = FormField::stored(entry, field);
                continue;
            }
            form.has_value = true;
            match &mut form.input {
                Input::Text(text) => {
                    if let Some(value) = entry.plain(&field.name) {
                        *text = TextArea::from_text(value);
                    }
                }
                Input::Note(text) => {
                    if let Some((_, note)) = notes.iter().find(|(name, _)| *name == field.name) {
                        *text = TextArea::from_text(note.expose_secret());
                    }
                }
                Input::Secret(_) => {}
            }
        }

        Self {
            editing: Some(entry.name.clone()),
            kind: entry.kind,
            vaults: vec![vault],
            vault: 0,
            name: TextArea::from_text(&entry.name),
            fields,
            tags: TextArea::from_text(&entry.tags.join(", ")),
            row: Row::Name,
            reveal: false,
            error: None,
            dirty: false,
            discard_armed: false,
        }
    }

    /// The rows, in order.
    #[must_use]
    pub fn rows(&self) -> Vec<Row> {
        let mut rows = vec![Row::Name];
        if self.editing.is_none() && self.vaults.len() > 1 {
            rows.push(Row::Vault);
        }
        rows.extend((0..self.fields.len()).map(Row::Field));
        rows.push(Row::Tags);
        rows
    }

    /// The screen's index of the chosen vault.
    // `vault` is always kept within `0..vaults.len()` by construction and by
    // `edit`'s wrapping arithmetic on `Row::Vault`.
    #[allow(clippy::indexing_slicing)]
    #[must_use]
    pub fn vault_index(&self) -> usize {
        self.vaults[self.vault].0
    }

    /// The chosen vault's name.
    // Same invariant as `vault_index` above.
    #[allow(clippy::indexing_slicing)]
    #[must_use]
    pub fn vault_name(&self) -> &str {
        &self.vaults[self.vault].1
    }

    /// The field being edited, if the row is a field.
    #[must_use]
    pub fn focused(&self) -> Option<&FormField> {
        match self.row {
            Row::Field(index) => self.fields.get(index),
            _ => None,
        }
    }

    // `rows()` always returns at least `Row::Name` and `Row::Tags`, so
    // `rows.len()` is never 0 and `next` is always a valid index into `rows`.
    #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    fn step(&mut self, forward: bool) {
        self.reveal = false;
        let rows = self.rows();
        let index = rows.iter().position(|row| *row == self.row).unwrap_or(0);
        let next = if forward {
            (index + 1) % rows.len()
        } else {
            (index + rows.len() - 1) % rows.len()
        };
        self.row = rows[next];
    }

    fn is_last_row(&self) -> bool {
        self.rows().last() == Some(&self.row)
    }

    /// Whether the cursor is at the top or bottom of what the row holds, so
    /// the arrow keys should leave the row rather than move inside it.
    // A note's row from `text.cursor()` is always within its own line count,
    // and both are tiny compared to `usize::MAX`.
    #[allow(clippy::arithmetic_side_effects)]
    fn at_edge(&self, down: bool) -> bool {
        match self.focused().map(|field| &field.input) {
            Some(Input::Note(text)) => {
                let (row, _) = text.cursor();
                if down {
                    row + 1 >= text.lines().len()
                } else {
                    row == 0
                }
            }
            _ => true,
        }
    }

    /// Answers one key.
    pub fn key(&mut self, key: KeyEvent) -> FormAction {
        let control = key.modifiers.contains(KeyModifiers::CONTROL);
        if key.code == KeyCode::Esc {
            if self.dirty && !self.discard_armed {
                self.discard_armed = true;
                self.error = Some(DISCARD.to_string());
                return FormAction::Stay;
            }
            return FormAction::Cancel;
        }
        if self.discard_armed {
            self.discard_armed = false;
            self.error = None;
        }

        let takes_lines = self.focused().is_some_and(FormField::takes_lines);
        match (key.code, control) {
            (KeyCode::Char('s'), true) => return FormAction::Save,
            (KeyCode::Char('g'), true) => self.generate_here(),
            (KeyCode::Char('r'), true) => {
                if matches!(self.focused().map(|f| &f.input), Some(Input::Secret(_))) {
                    self.reveal = !self.reveal;
                }
            }
            (KeyCode::Tab, _) => self.step(true),
            (KeyCode::BackTab, _) => self.step(false),
            (KeyCode::Enter, _) if !takes_lines => {
                if self.is_last_row() {
                    return FormAction::Save;
                }
                self.step(true);
            }
            (KeyCode::Up, _) if self.at_edge(false) => self.step(false),
            (KeyCode::Down, _) if self.at_edge(true) => self.step(true),
            (code, control) => self.edit(code, control),
        }
        FormAction::Stay
    }

    // `Row::Vault` is only ever the current row when `rows()` included it,
    // which only happens when `vaults.len() > 1`, so `count - 1` and the
    // modulo below cannot underflow or divide by zero.
    #[allow(clippy::arithmetic_side_effects)]
    fn edit(&mut self, code: KeyCode, control: bool) {
        let changed = match self.row {
            Row::Name => edit_line(&mut self.name, code, control),
            Row::Tags => edit_line(&mut self.tags, code, control),
            Row::Vault => {
                let count = self.vaults.len();
                match code {
                    KeyCode::Left => {
                        self.vault = (self.vault + count - 1) % count;
                        true
                    }
                    KeyCode::Right | KeyCode::Char(' ') => {
                        self.vault = (self.vault + 1) % count;
                        true
                    }
                    _ => false,
                }
            }
            Row::Field(index) => {
                let Some(field) = self.fields.get_mut(index) else {
                    return;
                };
                let multiline = field.multiline;
                let changed = match &mut field.input {
                    Input::Text(text) => edit_line(text, code, control),
                    Input::Note(text) => edit_note(text, code, control),
                    Input::Secret(secret) => match (code, control) {
                        (KeyCode::Char('u'), true) => {
                            secret.clear();
                            true
                        }
                        (KeyCode::Char(ch), false) => {
                            secret.insert(ch);
                            true
                        }
                        (KeyCode::Enter, _) if multiline => {
                            secret.insert('\n');
                            true
                        }
                        (KeyCode::Backspace, _) => {
                            secret.backspace();
                            true
                        }
                        _ => false,
                    },
                };
                if changed {
                    field.touched = true;
                    field.generated = false;
                }
                changed
            }
        };
        if changed {
            self.dirty = true;
            self.error = None;
        }
    }

    // `Row::Field(index)` is only ever built from `self.fields`'s own
    // indices (see `rows`), so `index` is always in bounds.
    #[allow(clippy::indexing_slicing)]
    fn generate_here(&mut self) {
        let Row::Field(index) = self.row else {
            self.error = Some("move to a field that can be generated first".to_string());
            return;
        };
        let field = &mut self.fields[index];
        let (Some(generator), Input::Secret(secret)) = (field.generator, &mut field.input) else {
            self.error = Some(format!(
                "the {} cannot be generated",
                field.label.to_lowercase()
            ));
            return;
        };
        let value = match generator {
            Generator::Password => generate(
                usize::try_from(DEFAULT_GENERATED_LENGTH).unwrap_or(24),
                true,
            ),
            Generator::Pin => generate_pin(PIN_LENGTH),
        };
        secret.set(&value);
        field.touched = true;
        field.generated = true;
        self.dirty = true;
        self.reveal = false;
        self.error = None;
    }

    /// Takes pasted text into the row being edited.
    pub fn paste(&mut self, text: &str) {
        match self.row {
            Row::Name => insert_line(&mut self.name, text),
            Row::Tags => insert_line(&mut self.tags, text),
            Row::Vault => return,
            Row::Field(index) => {
                let Some(field) = self.fields.get_mut(index) else {
                    return;
                };
                let multiline = field.multiline;
                match &mut field.input {
                    Input::Text(line) => insert_line(line, text),
                    Input::Secret(secret) => secret.insert_str(text, multiline),
                    Input::Note(note) => {
                        for ch in line_breaks(text) {
                            if ch == '\n' {
                                note.newline();
                            } else {
                                note.insert(ch);
                            }
                        }
                    }
                }
                field.touched = true;
                field.generated = false;
            }
        }
        self.dirty = true;
        self.error = None;
    }

    /// Gathers what was typed, checking what can be checked without the
    /// vault.
    ///
    /// # Errors
    ///
    /// Returns a message when the name or the main secret is missing, or a
    /// tag is malformed.
    pub fn collect(&self) -> Result<Collected, String> {
        let name = self.name.text().trim().to_string();
        if name.is_empty() {
            return Err("give the entry a name".to_string());
        }
        let primary = self.kind.primary();
        let mut collected = Collected {
            name,
            plain: Vec::new(),
            secrets: Vec::new(),
            cleared: Vec::new(),
            tags: Vec::new(),
        };

        for field in &self.fields {
            match &field.input {
                Input::Text(text) => {
                    let value = text.text().trim().to_string();
                    if !value.is_empty() {
                        collected.plain.push((field.name.clone(), value));
                    } else if field.has_value {
                        collected.cleared.push(field.name.clone());
                    }
                }
                Input::Secret(secret) => {
                    if !secret.is_empty() {
                        collected
                            .secrets
                            .push((field.name.clone(), secret.secret()));
                    } else if field.name == primary && !field.has_value {
                        return Err(if field.generator.is_some() {
                            format!(
                                "type or paste the {}, or press ctrl+g to generate one",
                                field.label.to_lowercase()
                            )
                        } else {
                            format!("type or paste the {}", field.label.to_lowercase())
                        });
                    }
                }
                Input::Note(text) => {
                    // An opened note that was not touched is left as it is.
                    if self.editing.is_some() && !field.touched {
                        continue;
                    }
                    let value = Zeroizing::new(text.text());
                    let trimmed = value.trim_end();
                    if !trimmed.is_empty() {
                        collected
                            .secrets
                            .push((field.name.clone(), SecretString::from(trimmed.to_owned())));
                    } else if field.name == primary {
                        return Err(format!(
                            "the {} cannot be empty",
                            field.label.to_lowercase()
                        ));
                    } else if field.has_value {
                        collected.cleared.push(field.name.clone());
                    }
                }
            }
        }

        for tag in self
            .tags
            .text()
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|tag| !tag.is_empty())
        {
            check_tag(tag).map_err(|error| error.to_string())?;
            if !collected.tags.iter().any(|known| known == tag) {
                collected.tags.push(tag.to_string());
            }
        }
        Ok(collected)
    }
}

impl Drop for EntryForm {
    fn drop(&mut self) {
        for field in &mut self.fields {
            if let Input::Text(text) | Input::Note(text) = &mut field.input {
                text.wipe();
            }
        }
    }
}

/// Keys for a single line of text. Returns whether the text changed.
fn edit_line(text: &mut TextArea, code: KeyCode, control: bool) -> bool {
    match (code, control) {
        (KeyCode::Char('u'), true) => text.clear(),
        (KeyCode::Char('w'), true) => text.delete_word(),
        (KeyCode::Char(ch), false) => text.insert(ch),
        (KeyCode::Backspace, _) => text.backspace(),
        (KeyCode::Delete, _) => text.delete(),
        (KeyCode::Left, _) => {
            text.move_left();
            return false;
        }
        (KeyCode::Right, _) => {
            text.move_right();
            return false;
        }
        (KeyCode::Home, _) => {
            text.move_home();
            return false;
        }
        (KeyCode::End, _) => {
            text.move_end();
            return false;
        }
        _ => return false,
    }
    true
}

/// Keys for a note. Returns whether the text changed.
fn edit_note(text: &mut TextArea, code: KeyCode, control: bool) -> bool {
    match (code, control) {
        (KeyCode::Enter, _) => text.newline(),
        (KeyCode::Up, _) => {
            text.move_up();
            return false;
        }
        (KeyCode::Down, _) => {
            text.move_down();
            return false;
        }
        _ => return edit_line(text, code, control),
    }
    true
}

/// Pasted text on one line: line breaks become spaces, other control
/// characters are dropped.
fn insert_line(text: &mut TextArea, pasted: &str) {
    for ch in line_breaks(pasted) {
        match ch {
            '\n' => text.insert(' '),
            ch if ch.is_control() => {}
            ch => text.insert(ch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(form: &mut EntryForm, code: KeyCode) -> FormAction {
        form.key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn ctrl(form: &mut EntryForm, ch: char) -> FormAction {
        form.key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL))
    }

    fn type_text(form: &mut EntryForm, text: &str) {
        for ch in text.chars() {
            press(form, KeyCode::Char(ch));
        }
    }

    fn vaults() -> Vec<(usize, String)> {
        vec![(0, "personal".to_string())]
    }

    /// Why the form cannot be saved. What was collected holds typed secrets,
    /// so it has no Debug output to unwrap an error with.
    fn error_of(form: &EntryForm) -> String {
        match form.collect() {
            Ok(_) => panic!("the form was accepted"),
            Err(error) => error,
        }
    }

    fn field<'a>(form: &'a EntryForm, name: &str) -> &'a FormField {
        form.fields.iter().find(|field| field.name == name).unwrap()
    }

    #[test]
    fn a_card_form_has_a_cards_fields_in_order() {
        let form = EntryForm::adding(Kind::Card, vaults(), 0);
        let names: Vec<&str> = form.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            ["cardholder", "number", "expiry", "cvv", "pin", "notes"]
        );
        assert!(matches!(field(&form, "cvv").input, Input::Secret(_)));
        assert!(matches!(field(&form, "expiry").input, Input::Text(_)));
        assert!(matches!(field(&form, "notes").input, Input::Note(_)));
        // One vault means nothing to choose.
        assert!(!form.rows().contains(&Row::Vault));
    }

    #[test]
    fn tab_and_enter_walk_the_rows_and_enter_on_the_last_saves() {
        let mut form = EntryForm::adding(Kind::Wifi, vaults(), 0);
        let rows = form.rows();
        for expected in &rows[1..] {
            assert_eq!(press(&mut form, KeyCode::Enter), FormAction::Stay);
            if *expected == Row::Field(3) {
                // The notes take Enter for a new line, so Tab leaves them.
                assert_eq!(form.row, *expected);
                press(&mut form, KeyCode::Tab);
                break;
            }
            assert_eq!(form.row, *expected);
        }
        assert_eq!(form.row, Row::Tags);
        assert_eq!(press(&mut form, KeyCode::Enter), FormAction::Save);
    }

    #[test]
    fn a_note_takes_new_lines_and_the_arrows_move_inside_it() {
        let mut form = EntryForm::adding(Kind::Note, vaults(), 0);
        press(&mut form, KeyCode::Tab);
        type_text(&mut form, "first");
        press(&mut form, KeyCode::Enter);
        type_text(&mut form, "second");
        press(&mut form, KeyCode::Up);
        assert_eq!(form.row, Row::Field(0), "up moved inside the note");
        press(&mut form, KeyCode::Up);
        assert_eq!(form.row, Row::Name, "up at the top leaves the note");

        let Input::Note(text) = &field(&form, "text").input else {
            panic!("the note is not a note");
        };
        assert_eq!(text.text(), "first\nsecond");
    }

    #[test]
    fn a_name_and_the_main_secret_are_needed() {
        let mut form = EntryForm::adding(Kind::Login, vaults(), 0);
        assert!(error_of(&form).contains("name"));
        type_text(&mut form, "GitHub");
        let error = error_of(&form);
        assert!(error.contains("ctrl+g"), "{error}");

        let mut card = EntryForm::adding(Kind::Card, vaults(), 0);
        type_text(&mut card, "Visa");
        let error = error_of(&card);
        assert!(
            !error.contains("ctrl+g"),
            "a card number is not generated: {error}"
        );
    }

    #[test]
    fn ctrl_g_generates_a_password_or_a_pin_as_the_field_wants() {
        let mut form = EntryForm::adding(Kind::Card, vaults(), 0);
        form.row = Row::Field(4); // pin
        ctrl(&mut form, 'g');
        let Input::Secret(pin) = &field(&form, "pin").input else {
            panic!("the pin is not secret");
        };
        assert_eq!(pin.chars(), PIN_LENGTH);
        assert!(
            pin.secret()
                .expose_secret()
                .bytes()
                .all(|b| b.is_ascii_digit())
        );

        form.row = Row::Field(1); // card number: nothing to generate
        ctrl(&mut form, 'g');
        assert!(
            form.error
                .as_deref()
                .unwrap()
                .contains("cannot be generated")
        );

        let mut login = EntryForm::adding(Kind::Login, vaults(), 0);
        login.row = Row::Field(1);
        ctrl(&mut login, 'g');
        assert!(field(&login, "password").generated);
    }

    #[test]
    fn escape_asks_before_throwing_changes_away() {
        let mut form = EntryForm::adding(Kind::Login, vaults(), 0);
        assert_eq!(press(&mut form, KeyCode::Esc), FormAction::Cancel);

        let mut form = EntryForm::adding(Kind::Login, vaults(), 0);
        type_text(&mut form, "x");
        assert_eq!(press(&mut form, KeyCode::Esc), FormAction::Stay);
        assert!(form.error.as_deref().unwrap().contains("esc again"));
        assert_eq!(press(&mut form, KeyCode::Esc), FormAction::Cancel);
    }

    #[test]
    fn pasting_a_multiline_value_goes_where_it_belongs() {
        let mut form = EntryForm::adding(Kind::SshKey, vaults(), 0);
        form.row = Row::Field(0); // private key: several lines
        form.paste("-----BEGIN KEY-----\r\nabc\r\n-----END KEY-----");
        let Input::Secret(key) = &field(&form, "private-key").input else {
            panic!("the key is not secret");
        };
        assert_eq!(key.lines(), 3);

        form.row = Row::Field(1); // passphrase: one line
        form.paste("one\ntwo");
        let Input::Secret(passphrase) = &field(&form, "passphrase").input else {
            panic!("the passphrase is not secret");
        };
        assert_eq!(passphrase.secret().expose_secret(), "onetwo");

        form.row = Row::Name;
        form.paste("My\nServer");
        assert_eq!(form.name.text(), "My Server");
    }

    #[test]
    fn a_paste_keeps_its_lines_however_the_terminal_breaks_them() {
        let mut form = EntryForm::adding(Kind::Note, vaults(), 0);
        form.row = Row::Field(0);
        form.paste("one\rtwo\r\nthree\nfour");
        let Input::Note(text) = &field(&form, "text").input else {
            panic!("the note is not a note");
        };
        assert_eq!(text.lines(), ["one", "two", "three", "four"]);

        let mut key = EntryForm::adding(Kind::SshKey, vaults(), 0);
        key.row = Row::Field(0);
        key.paste("-----BEGIN-----\rabc\r-----END-----");
        let Input::Secret(secret) = &field(&key, "private-key").input else {
            panic!("the key is not secret");
        };
        assert_eq!(
            secret.secret().expose_secret(),
            "-----BEGIN-----\nabc\n-----END-----"
        );
    }

    #[test]
    fn editing_leaves_secrets_and_untouched_notes_alone() {
        let entry = Entry {
            name: "site".to_string(),
            kind: Kind::Login,
            fields: vec![
                Field {
                    name: "username".to_string(),
                    value: crate::vault::model::Value::Plain("me".to_string()),
                },
                Field {
                    name: "password".to_string(),
                    value: crate::vault::model::Value::Sealed("YWdl".to_string()),
                },
                Field {
                    name: "notes".to_string(),
                    value: crate::vault::model::Value::Sealed("YWdl".to_string()),
                },
            ],
            tags: vec!["dev".to_string()],
            favourite: false,
            created: String::new(),
            updated: String::new(),
        };
        let notes = vec![("notes".to_string(), SecretString::from("hello".to_string()))];
        let mut form = EntryForm::editing(&entry, (0, "personal".to_string()), &notes);

        let collected = form.collect().unwrap();
        assert!(collected.secrets.is_empty());
        assert!(collected.cleared.is_empty());
        assert_eq!(collected.tags, ["dev"]);

        // Emptying the username removes it; emptying the note does too, once touched.
        form.row = Row::Field(0);
        ctrl(&mut form, 'u');
        form.row = Row::Field(3);
        let Input::Note(text) = &field(&form, "notes").input else {
            panic!("the notes are not a note");
        };
        assert_eq!(text.text(), "hello");
        for _ in 0..5 {
            press(&mut form, KeyCode::Backspace);
        }
        let collected = form.collect().unwrap();
        assert_eq!(collected.cleared, ["username", "notes"]);
    }

    #[test]
    fn a_typed_secret_never_outgrows_its_buffer() {
        let mut input = SecretInput::default();
        let capacity = input.text.capacity();
        for _ in 0..capacity + 10 {
            input.insert('é');
        }
        assert!(input.text.len() <= capacity);
        assert_eq!(input.text.capacity(), capacity);

        input.clear();
        assert!(input.is_empty());
        assert_eq!(input.text.capacity(), capacity);
    }

    #[test]
    fn a_shown_secret_is_safe_to_draw() {
        let mut input = SecretInput::default();
        input.insert_str("a\x1b[2Jb", false);
        assert!(!input.shown().contains('\x1b'));
    }
}
