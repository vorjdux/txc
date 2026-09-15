//! The vault screen of the interactive interface, reached with F3.
//!
//! It keeps the command line's rules. Secrets are typed into fields that show
//! only dots and are wiped when dropped. They are never drawn, and they leave
//! only by the clipboard, which is cleared again after a while. The vault
//! locks itself after a few minutes without a key, and when the interface
//! closes.

use std::time::{Duration, Instant};

use age::secrecy::{ExposeSecret, SecretString};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

use crate::tui::textarea::TextArea;
use crate::vault::clipboard::{DEFAULT_CLEAR_SECONDS, Held};
use crate::vault::command::{DEFAULT_GENERATED_LENGTH, generate};
use crate::vault::model::{DEFAULT_VAULT, Entry, Kind, check_vault_name};
use crate::vault::prompt::check_new_passphrase;
use crate::vault::{Change, Home, Inspection, Keyring, NewEntry, NotTrusted, Opened, harden};

/// How long the vault stays unlocked without a key being pressed.
pub const IDLE_LOCK: Duration = Duration::from_secs(5 * 60);

/// How long a copied secret stays on the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(DEFAULT_CLEAR_SECONDS);

/// The most a typed secret may hold, in bytes. The buffer is allocated at
/// this size once, so typing never reallocates it and leaves a copy behind.
const MAX_TYPED_BYTES: usize = 4096;

/// Which list keystrokes go to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pane {
    /// The vaults down the left.
    Vaults,
    /// The entries of the open vault.
    Entries,
    /// The fields of the selected entry.
    Fields,
}

impl Pane {
    const fn next(self) -> Self {
        match self {
            Self::Vaults => Self::Entries,
            Self::Entries => Self::Fields,
            Self::Fields => Self::Vaults,
        }
    }

    const fn previous(self) -> Self {
        match self {
            Self::Vaults => Self::Fields,
            Self::Entries => Self::Vaults,
            Self::Fields => Self::Entries,
        }
    }
}

/// A field for typing a secret: shown as dots, wiped when cleared or dropped.
pub struct SecretInput {
    text: Zeroizing<String>,
}

impl Default for SecretInput {
    fn default() -> Self {
        Self {
            text: Zeroizing::new(String::with_capacity(MAX_TYPED_BYTES)),
        }
    }
}

impl SecretInput {
    /// Adds a character, unless the field is full.
    pub fn insert(&mut self, ch: char) {
        if self.text.len() + ch.len_utf8() <= MAX_TYPED_BYTES {
            self.text.push(ch);
        }
    }

    /// Removes the last character.
    pub fn backspace(&mut self) {
        self.text.pop();
    }

    /// Wipes the field.
    pub fn clear(&mut self) {
        // Zeroize would also release the buffer; overwriting in place keeps
        // the capacity, so the next typing does not reallocate.
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

    /// One dot per character, which is all that is ever drawn.
    #[must_use]
    pub fn masked(&self) -> String {
        "•".repeat(self.chars())
    }
}

/// A row of the entry form.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FormRow {
    /// The entry's name.
    Name,
    /// Its kind, which can be chosen only when adding.
    Kind,
    /// The username.
    Username,
    /// The address.
    Url,
    /// The main secret.
    Secret,
}

/// The form for adding or editing an entry.
pub struct EntryForm {
    /// The name of the entry being edited, or `None` when adding.
    pub editing: Option<String>,
    /// The name typed.
    pub name: TextArea,
    /// The kind chosen.
    pub kind: Kind,
    /// The username typed.
    pub username: TextArea,
    /// The address typed.
    pub url: TextArea,
    /// The main secret. When editing, empty means unchanged.
    pub secret: SecretInput,
    /// Whether the secret was generated rather than typed.
    pub generated: bool,
    /// The row being edited.
    pub row: FormRow,
    /// Why the last attempt to save failed.
    pub error: Option<String>,
}

impl EntryForm {
    fn adding() -> Self {
        Self {
            editing: None,
            name: TextArea::default(),
            kind: Kind::Login,
            username: TextArea::default(),
            url: TextArea::default(),
            secret: SecretInput::default(),
            generated: false,
            row: FormRow::Name,
            error: None,
        }
    }

    fn editing(entry: &Entry) -> Self {
        Self {
            editing: Some(entry.name.clone()),
            name: TextArea::from_text(&entry.name),
            kind: entry.kind,
            username: TextArea::from_text(entry.plain("username").unwrap_or_default()),
            url: TextArea::from_text(entry.plain("url").unwrap_or_default()),
            secret: SecretInput::default(),
            generated: false,
            row: FormRow::Name,
            error: None,
        }
    }

    /// The rows shown: the kind only when adding, since changing it would
    /// change which field holds the secret.
    #[must_use]
    pub fn rows(&self) -> Vec<FormRow> {
        let mut rows = vec![FormRow::Name];
        if self.editing.is_none() {
            rows.push(FormRow::Kind);
        }
        rows.extend([FormRow::Username, FormRow::Url, FormRow::Secret]);
        rows
    }

    fn step(&mut self, forward: bool) {
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

    fn edit(&mut self, key: KeyEvent, control: bool) {
        let text = match self.row {
            FormRow::Name => &mut self.name,
            FormRow::Username => &mut self.username,
            FormRow::Url => &mut self.url,
            FormRow::Kind => {
                if self.editing.is_none() {
                    let index = Kind::ALL.iter().position(|k| *k == self.kind).unwrap_or(0);
                    match key.code {
                        KeyCode::Right | KeyCode::Char(' ') => {
                            self.kind = Kind::ALL[(index + 1) % Kind::ALL.len()];
                        }
                        KeyCode::Left => {
                            self.kind = Kind::ALL[(index + Kind::ALL.len() - 1) % Kind::ALL.len()];
                        }
                        _ => {}
                    }
                }
                return;
            }
            FormRow::Secret => {
                match (key.code, control) {
                    (KeyCode::Char('u'), true) => self.secret.clear(),
                    (KeyCode::Char(ch), false) => self.secret.insert(ch),
                    (KeyCode::Backspace, _) => self.secret.backspace(),
                    _ => return,
                }
                self.generated = false;
                return;
            }
        };
        match (key.code, control) {
            (KeyCode::Char('u'), true) => text.clear(),
            (KeyCode::Char(ch), false) => text.insert(ch),
            (KeyCode::Backspace, _) => text.backspace(),
            (KeyCode::Delete, _) => text.delete(),
            (KeyCode::Left, _) => text.move_left(),
            (KeyCode::Right, _) => text.move_right(),
            (KeyCode::Home, _) => text.move_home(),
            (KeyCode::End, _) => text.move_end(),
            _ => {}
        }
    }
}

/// A window over the vault screen.
pub enum Dialog {
    /// Asking for the passphrase.
    Unlock {
        /// The passphrase typed.
        passphrase: SecretInput,
        /// Why the last attempt failed.
        error: Option<String>,
    },
    /// Creating the identity, with the passphrase typed twice.
    CreateIdentity {
        /// The passphrase typed.
        passphrase: SecretInput,
        /// The passphrase typed again.
        again: SecretInput,
        /// Whether the second field is the one being typed in.
        on_again: bool,
        /// Why the last attempt failed.
        error: Option<String>,
    },
    /// Naming a new vault.
    NewVault {
        /// The name typed.
        name: TextArea,
        /// Why the last attempt failed.
        error: Option<String>,
    },
    /// Adding or editing an entry.
    Entry(Box<EntryForm>),
    /// Confirming that an entry should be removed.
    Delete {
        /// The entry's name.
        entry: String,
    },
    /// Showing how a vault differs from what was trusted, and asking.
    Trust(Box<Inspection>),
}

/// Everything the vault screen needs to draw itself and answer a key.
pub struct VaultScreen {
    home: Result<Home, String>,
    keyring: Option<Keyring>,
    vaults: Vec<String>,
    vault_index: usize,
    opened: Option<Opened>,
    problem: Option<String>,
    untrusted: bool,
    entry_index: usize,
    field_index: usize,
    /// The text narrowing the entry list.
    pub search: String,
    /// Whether keys are going to the search box.
    pub searching: bool,
    /// Which list keys go to.
    pub pane: Pane,
    /// The window open over the screen, if any.
    pub dialog: Option<Dialog>,
    /// A secret for the event loop to put on the clipboard, and what to call
    /// it. The event loop owns the clipboard, as it does for the output.
    pub pending_copy: Option<(SecretString, String)>,
    held: Option<(Held, Instant)>,
    last_key: Instant,
    /// The message along the bottom.
    pub status: String,
}

impl VaultScreen {
    /// A locked vault screen for the vault directory found, or for the
    /// reason none was.
    #[must_use]
    pub fn new(home: anyhow::Result<Home>) -> Self {
        Self {
            home: home.map_err(|error| format!("{error:#}")),
            keyring: None,
            vaults: Vec::new(),
            vault_index: 0,
            opened: None,
            problem: None,
            untrusted: false,
            entry_index: 0,
            field_index: 0,
            search: String::new(),
            searching: false,
            pane: Pane::Entries,
            dialog: None,
            pending_copy: None,
            held: None,
            last_key: Instant::now(),
            status: String::new(),
        }
    }

    /// Called when the screen is switched to: lists the vaults, and asks for
    /// the passphrase, or offers to create the identity, if locked.
    pub fn enter(&mut self) {
        self.last_key = Instant::now();
        self.refresh_vaults();
        if self.keyring.is_none() && self.dialog.is_none() {
            self.begin_unlock();
        }
    }

    /// Why no vault directory could be found, if none was.
    #[must_use]
    pub fn home_error(&self) -> Option<&str> {
        self.home.as_ref().err().map(String::as_str)
    }

    /// Whether an identity exists to unlock.
    #[must_use]
    pub fn has_identity(&self) -> bool {
        self.home.as_ref().is_ok_and(Home::has_identity)
    }

    /// Whether the identity is unlocked.
    #[must_use]
    pub const fn is_unlocked(&self) -> bool {
        self.keyring.is_some()
    }

    /// This identity's public key, while unlocked.
    #[must_use]
    pub fn public_key(&self) -> Option<String> {
        self.keyring.as_ref().map(Keyring::public_key)
    }

    /// The vault names.
    #[must_use]
    pub fn vaults(&self) -> &[String] {
        &self.vaults
    }

    /// Which vault is selected.
    #[must_use]
    pub const fn vault_index(&self) -> usize {
        self.vault_index
    }

    /// The selected vault's name.
    #[must_use]
    pub fn selected_vault(&self) -> Option<&str> {
        self.vaults.get(self.vault_index).map(String::as_str)
    }

    /// The open vault.
    #[must_use]
    pub const fn opened(&self) -> Option<&Opened> {
        self.opened.as_ref()
    }

    /// Why the selected vault is not open.
    #[must_use]
    pub fn problem(&self) -> Option<&str> {
        self.problem.as_deref()
    }

    /// Whether the selected vault is refused only for want of trust, which
    /// `t` can give.
    #[must_use]
    pub const fn untrusted(&self) -> bool {
        self.untrusted
    }

    /// The entries matching the search.
    #[must_use]
    pub fn entries(&self) -> Vec<&Entry> {
        let Some(opened) = &self.opened else {
            return Vec::new();
        };
        let needle = self.search.trim().to_lowercase();
        opened
            .vault()
            .entries()
            .iter()
            .filter(|entry| {
                needle.is_empty()
                    || entry.name.to_lowercase().contains(&needle)
                    || entry.tags.iter().any(|tag| tag.contains(&needle))
                    || ["username", "url"].iter().any(|field| {
                        entry
                            .plain(field)
                            .is_some_and(|value| value.to_lowercase().contains(&needle))
                    })
            })
            .collect()
    }

    /// Which entry is selected, among those matching the search.
    #[must_use]
    pub const fn entry_index(&self) -> usize {
        self.entry_index
    }

    /// The selected entry.
    #[must_use]
    pub fn selected_entry(&self) -> Option<&Entry> {
        self.entries().get(self.entry_index).copied()
    }

    /// Which field of the entry is selected.
    #[must_use]
    pub const fn field_index(&self) -> usize {
        self.field_index
    }

    /// Seconds until the clipboard is cleared, while a secret is on it.
    #[must_use]
    pub fn clears_in(&self, now: Instant) -> Option<u64> {
        self.held
            .as_ref()
            .map(|(_, at)| at.saturating_duration_since(now).as_secs() + 1)
    }

    fn refresh_vaults(&mut self) {
        let previous = self.selected_vault().map(str::to_string);
        self.vaults = self
            .home
            .as_ref()
            .ok()
            .and_then(|home| home.vault_names().ok())
            .unwrap_or_default();
        let find = |name: &str| self.vaults.iter().position(|vault| vault == name);
        self.vault_index = previous
            .as_deref()
            .and_then(find)
            .or_else(|| find(DEFAULT_VAULT))
            .unwrap_or(0);
    }

    fn open_selected(&mut self) {
        self.opened = None;
        self.problem = None;
        self.untrusted = false;
        self.entry_index = 0;
        self.field_index = 0;
        self.search.clear();
        self.searching = false;

        let (Some(keyring), Some(name)) = (&self.keyring, self.vaults.get(self.vault_index)) else {
            return;
        };
        match keyring.open(name) {
            Ok(opened) => self.opened = Some(opened),
            Err(error) => {
                self.untrusted = error.downcast_ref::<NotTrusted>().is_some();
                self.problem = Some(format!("{error:#}"));
            }
        }
    }

    /// Locks: forgets the key and the open vault, and takes any secret off
    /// the clipboard.
    pub fn lock(&mut self) {
        self.release_clipboard();
        self.pending_copy = None;
        self.opened = None;
        self.keyring = None;
        self.dialog = None;
        self.problem = None;
        self.untrusted = false;
        self.search.clear();
        self.searching = false;
        self.pane = Pane::Entries;
    }

    /// Clears the clipboard when its time is up, and locks after a while
    /// without a key. Called by the event loop on every turn.
    pub fn tick(&mut self, now: Instant) {
        let due = self
            .held
            .as_ref()
            .is_some_and(|(held, at)| now >= *at || held.taken_over());
        if due && let Some((held, _)) = self.held.take() {
            self.status = match held.clear() {
                Ok(true) => "clipboard cleared".to_string(),
                Ok(false) => String::new(),
                Err(error) => error.to_string(),
            };
        }

        if self.keyring.is_some() && now.saturating_duration_since(self.last_key) >= IDLE_LOCK {
            self.lock();
            self.status = "locked after five minutes without a key".to_string();
        }
    }

    /// Takes a secret this screen copied off the clipboard, if it is still
    /// there. The event loop calls this before copying another.
    pub fn release_clipboard(&mut self) {
        if let Some((held, _)) = self.held.take() {
            let _ = held.clear();
        }
    }

    /// Hears back from the event loop about a copy.
    pub fn copied(&mut self, result: anyhow::Result<Held>, label: &str) {
        match result {
            Ok(held) => {
                self.held = Some((held, Instant::now() + CLEAR_AFTER));
                self.status = format!(
                    "copied the {label}; the clipboard clears in {}s",
                    CLEAR_AFTER.as_secs()
                );
            }
            Err(error) => self.status = format!("{error:#}"),
        }
    }

    /// The command that does what the screen is showing.
    #[must_use]
    pub fn command_hint(&self) -> Option<String> {
        if self.home.is_err() {
            return None;
        }
        if !self.has_identity() {
            return Some("txc vault init".to_string());
        }
        let Some(vault) = self.selected_vault() else {
            return Some("txc vault create <name>".to_string());
        };
        if self.untrusted {
            return Some(format!("txc vault trust {vault}"));
        }
        if let Some(entry) = self.selected_entry() {
            let reference = shell_word(&format!("{vault}/{}", entry.name));
            let field = entry
                .fields
                .get(self.field_index)
                .filter(|_| self.pane == Pane::Fields)
                .map(|field| field.name.as_str())
                .filter(|field| *field != entry.kind.primary());
            return Some(match field {
                Some(field) => format!("txc vault copy {reference} --field {field}"),
                None => format!("txc vault copy {reference}"),
            });
        }
        Some(format!("txc vault list {vault}"))
    }

    /// Answers one key.
    pub fn handle_key(&mut self, key: KeyEvent) {
        self.last_key = Instant::now();
        self.status.clear();
        let control = key.modifiers.contains(KeyModifiers::CONTROL);

        if self.dialog.is_some() {
            self.dialog_key(key, control);
            return;
        }
        if self.home.is_err() {
            return;
        }
        if self.keyring.is_none() {
            if key.code == KeyCode::Enter {
                self.begin_unlock();
            }
            return;
        }
        if self.searching {
            self.search_key(key, control);
            return;
        }
        if control {
            if key.code == KeyCode::Char('l') {
                self.lock();
                self.status = "locked".to_string();
            }
            return;
        }

        match key.code {
            KeyCode::Tab => self.pane = self.pane.next(),
            KeyCode::BackTab => self.pane = self.pane.previous(),
            KeyCode::Char('l') => {
                self.lock();
                self.status = "locked".to_string();
            }
            KeyCode::Char('n') => {
                self.dialog = Some(Dialog::NewVault {
                    name: TextArea::default(),
                    error: None,
                });
            }
            KeyCode::Char('t') if self.untrusted => self.begin_trust(),
            KeyCode::Char('/') if self.opened.is_some() => {
                self.searching = true;
                self.pane = Pane::Entries;
            }
            KeyCode::Char('a') if self.opened.is_some() => {
                self.dialog = Some(Dialog::Entry(Box::new(EntryForm::adding())));
            }
            _ => match self.pane {
                Pane::Vaults => self.vaults_key(key),
                Pane::Entries => self.entries_key(key),
                Pane::Fields => self.fields_key(key),
            },
        }
    }

    fn vaults_key(&mut self, key: KeyEvent) {
        let count = self.vaults.len();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') if count > 0 => {
                self.vault_index = (self.vault_index + count - 1) % count;
                self.open_selected();
            }
            KeyCode::Down | KeyCode::Char('j') if count > 0 => {
                self.vault_index = (self.vault_index + 1) % count;
                self.open_selected();
            }
            KeyCode::Enter | KeyCode::Right => self.pane = Pane::Entries,
            _ => {}
        }
    }

    fn entries_key(&mut self, key: KeyEvent) {
        let count = self.entries().len();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.entry_index = self.entry_index.saturating_sub(1);
                self.field_index = 0;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.entry_index = (self.entry_index + 1).min(count.saturating_sub(1));
                self.field_index = 0;
            }
            KeyCode::Home => self.entry_index = 0,
            KeyCode::End => self.entry_index = count.saturating_sub(1),
            KeyCode::Enter | KeyCode::Char('c') => self.copy(None),
            KeyCode::Char('u') => self.copy(Some("username")),
            KeyCode::Char('e') => {
                if let Some(entry) = self.selected_entry() {
                    self.dialog = Some(Dialog::Entry(Box::new(EntryForm::editing(entry))));
                }
            }
            KeyCode::Char('d') => {
                if let Some(entry) = self.selected_entry() {
                    self.dialog = Some(Dialog::Delete {
                        entry: entry.name.clone(),
                    });
                }
            }
            KeyCode::Right => self.pane = Pane::Fields,
            KeyCode::Left => self.pane = Pane::Vaults,
            KeyCode::Esc => {
                self.search.clear();
                self.entry_index = 0;
            }
            _ => {}
        }
    }

    fn fields_key(&mut self, key: KeyEvent) {
        let count = self.selected_entry().map_or(0, |entry| entry.fields.len());
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.field_index = self.field_index.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.field_index = (self.field_index + 1).min(count.saturating_sub(1));
            }
            KeyCode::Enter | KeyCode::Char('c') => {
                let field = self
                    .selected_entry()
                    .and_then(|entry| entry.fields.get(self.field_index))
                    .map(|field| field.name.clone());
                if let Some(field) = field {
                    self.copy(Some(&field));
                }
            }
            KeyCode::Left => self.pane = Pane::Entries,
            _ => {}
        }
    }

    fn search_key(&mut self, key: KeyEvent, control: bool) {
        match (key.code, control) {
            (KeyCode::Enter | KeyCode::Down, _) => self.searching = false,
            (KeyCode::Esc, _) => {
                self.search.clear();
                self.searching = false;
            }
            (KeyCode::Char('u' | 'w'), true) => self.search.clear(),
            (KeyCode::Char(ch), false) => self.search.push(ch),
            (KeyCode::Backspace, _) => {
                self.search.pop();
            }
            _ => return,
        }
        self.entry_index = 0;
        self.field_index = 0;
    }

    /// Decrypts one field and hands it to the event loop for the clipboard.
    fn copy(&mut self, field: Option<&str>) {
        match self.reveal(field) {
            Ok(pending) => {
                self.pending_copy = Some(pending);
                self.status = "copying".to_string();
            }
            Err(message) => self.status = message,
        }
    }

    fn reveal(&self, field: Option<&str>) -> Result<(SecretString, String), String> {
        let (Some(keyring), Some(opened), Some(vault), Some(entry)) = (
            self.keyring.as_ref(),
            self.opened.as_ref(),
            self.selected_vault(),
            self.selected_entry(),
        ) else {
            return Err("there is no entry selected".to_string());
        };
        let field = field.unwrap_or_else(|| entry.kind.primary());
        if entry.field(field).is_none() {
            return Err(format!("{} has no {field}", entry.name));
        }
        let secret = opened
            .reveal(keyring, &entry.name, field)
            .map_err(|error| format!("{error:#}"))?;
        Ok((secret, format!("{field} of {vault}/{}", entry.name)))
    }

    fn begin_unlock(&mut self) {
        if self.home.is_err() {
            return;
        }
        self.dialog = Some(if self.has_identity() {
            Dialog::Unlock {
                passphrase: SecretInput::default(),
                error: None,
            }
        } else {
            Dialog::CreateIdentity {
                passphrase: SecretInput::default(),
                again: SecretInput::default(),
                on_again: false,
                error: None,
            }
        });
    }

    fn begin_trust(&mut self) {
        let (Some(keyring), Some(name)) = (&self.keyring, self.selected_vault()) else {
            return;
        };
        match keyring.inspect(name) {
            Ok(inspection) => self.dialog = Some(Dialog::Trust(Box::new(inspection))),
            Err(error) => self.status = format!("{error:#}"),
        }
    }

    fn dialog_key(&mut self, key: KeyEvent, control: bool) {
        let Some(dialog) = self.dialog.take() else {
            return;
        };
        self.dialog = match dialog {
            Dialog::Unlock {
                mut passphrase,
                error,
            } => match (key.code, control) {
                (KeyCode::Esc, _) => None,
                (KeyCode::Enter, _) => match self.unlock(&passphrase) {
                    Ok(()) => None,
                    Err(error) => {
                        passphrase.clear();
                        Some(Dialog::Unlock {
                            passphrase,
                            error: Some(error),
                        })
                    }
                },
                (KeyCode::Char('u'), true) => {
                    passphrase.clear();
                    Some(Dialog::Unlock { passphrase, error })
                }
                (KeyCode::Char(ch), false) => {
                    passphrase.insert(ch);
                    Some(Dialog::Unlock { passphrase, error })
                }
                (KeyCode::Backspace, _) => {
                    passphrase.backspace();
                    Some(Dialog::Unlock { passphrase, error })
                }
                _ => Some(Dialog::Unlock { passphrase, error }),
            },

            Dialog::CreateIdentity {
                mut passphrase,
                mut again,
                mut on_again,
                error,
            } => {
                let mut error = error;
                match (key.code, control) {
                    (KeyCode::Esc, _) => {
                        return;
                    }
                    (KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down, _) => {
                        on_again = !on_again;
                    }
                    (KeyCode::Enter, _) if !on_again => on_again = true,
                    (KeyCode::Enter, _) => match self.create_identity(&passphrase, &again) {
                        Ok(()) => return,
                        Err(message) => {
                            again.clear();
                            error = Some(message);
                        }
                    },
                    (KeyCode::Char(ch), false) => {
                        if on_again {
                            again.insert(ch);
                        } else {
                            passphrase.insert(ch);
                        }
                    }
                    (KeyCode::Backspace, _) => {
                        if on_again {
                            again.backspace();
                        } else {
                            passphrase.backspace();
                        }
                    }
                    _ => {}
                }
                Some(Dialog::CreateIdentity {
                    passphrase,
                    again,
                    on_again,
                    error,
                })
            }

            Dialog::NewVault { mut name, error } => match (key.code, control) {
                (KeyCode::Esc, _) => None,
                (KeyCode::Enter, _) => {
                    let typed = name.text().trim().to_string();
                    match self.create_vault(&typed) {
                        Ok(()) => None,
                        Err(message) => Some(Dialog::NewVault {
                            name,
                            error: Some(message),
                        }),
                    }
                }
                (code, control) => {
                    match (code, control) {
                        (KeyCode::Char('u'), true) => name.clear(),
                        (KeyCode::Char(ch), false) => name.insert(ch),
                        (KeyCode::Backspace, _) => name.backspace(),
                        (KeyCode::Delete, _) => name.delete(),
                        (KeyCode::Left, _) => name.move_left(),
                        (KeyCode::Right, _) => name.move_right(),
                        (KeyCode::Home, _) => name.move_home(),
                        (KeyCode::End, _) => name.move_end(),
                        _ => {}
                    }
                    Some(Dialog::NewVault { name, error })
                }
            },

            Dialog::Entry(mut form) => match (key.code, control) {
                (KeyCode::Esc, _) => None,
                (KeyCode::Char('s'), true) => self.submit_entry(form),
                (KeyCode::Char('g'), true) => {
                    let length = usize::try_from(DEFAULT_GENERATED_LENGTH).unwrap_or(24);
                    form.secret.set(&generate(length, true));
                    form.generated = true;
                    form.row = FormRow::Secret;
                    Some(Dialog::Entry(form))
                }
                (KeyCode::Enter, _) if form.is_last_row() => self.submit_entry(form),
                (KeyCode::Enter | KeyCode::Tab | KeyCode::Down, _) => {
                    form.step(true);
                    Some(Dialog::Entry(form))
                }
                (KeyCode::BackTab | KeyCode::Up, _) => {
                    form.step(false);
                    Some(Dialog::Entry(form))
                }
                _ => {
                    form.edit(key, control);
                    Some(Dialog::Entry(form))
                }
            },

            Dialog::Delete { entry } => {
                if key.code == KeyCode::Char('y') {
                    self.status = match self.delete(&entry) {
                        Ok(()) => format!("removed {entry}"),
                        Err(message) => message,
                    };
                } else {
                    self.status = "nothing was removed".to_string();
                }
                None
            }

            Dialog::Trust(inspection) => {
                if key.code == KeyCode::Char('y') {
                    self.trust(*inspection);
                } else {
                    self.status = "the vault was not trusted".to_string();
                }
                None
            }
        };
    }

    fn unlock(&mut self, passphrase: &SecretInput) -> Result<(), String> {
        if passphrase.is_empty() {
            return Err("type the passphrase".to_string());
        }
        let home = self.home.clone()?;
        harden::process();
        let keyring =
            Keyring::unlock(&home, &passphrase.secret()).map_err(|error| format!("{error:#}"))?;
        self.keyring = Some(keyring);
        self.refresh_vaults();
        self.open_selected();
        self.pane = Pane::Entries;
        Ok(())
    }

    fn create_identity(
        &mut self,
        passphrase: &SecretInput,
        again: &SecretInput,
    ) -> Result<(), String> {
        let secret = passphrase.secret();
        check_new_passphrase(&secret).map_err(|error| error.to_string())?;
        if secret.expose_secret() != again.secret().expose_secret() {
            return Err("the two passphrases did not match".to_string());
        }
        let home = self.home.clone()?;
        harden::process();
        let keyring = Keyring::create(&home, &secret).map_err(|error| format!("{error:#}"))?;
        let exists = home
            .vault_names()
            .is_ok_and(|names| names.iter().any(|name| name == DEFAULT_VAULT));
        if !exists {
            keyring
                .create_vault(DEFAULT_VAULT, &[])
                .map_err(|error| format!("{error:#}"))?;
        }
        self.keyring = Some(keyring);
        self.refresh_vaults();
        self.open_selected();
        self.status = "created your identity and the personal vault".to_string();
        Ok(())
    }

    fn create_vault(&mut self, name: &str) -> Result<(), String> {
        check_vault_name(name).map_err(|error| error.to_string())?;
        let keyring = self.keyring.as_ref().ok_or("the vault is locked")?;
        keyring
            .create_vault(name, &[])
            .map_err(|error| format!("{error:#}"))?;
        self.refresh_vaults();
        if let Some(index) = self.vaults.iter().position(|vault| vault == name) {
            self.vault_index = index;
        }
        self.open_selected();
        self.status = format!("created the vault {name}");
        Ok(())
    }

    fn submit_entry(&mut self, mut form: Box<EntryForm>) -> Option<Dialog> {
        match self.save_entry(&form) {
            Ok(name) => {
                self.search.clear();
                self.entry_index = self
                    .entries()
                    .iter()
                    .position(|entry| entry.name == name)
                    .unwrap_or(0);
                self.field_index = 0;
                self.status = if form.editing.is_some() {
                    format!("saved {name}")
                } else {
                    format!("added {name}")
                };
                None
            }
            Err(message) => {
                form.error = Some(message);
                Some(Dialog::Entry(form))
            }
        }
    }

    fn save_entry(&mut self, form: &EntryForm) -> Result<String, String> {
        let (Some(keyring), Some(opened)) = (self.keyring.as_ref(), self.opened.as_mut()) else {
            return Err("the vault is not open".to_string());
        };
        let name = form.name.text().trim().to_string();
        let username = form.username.text().trim().to_string();
        let url = form.url.text().trim().to_string();

        let applied = if let Some(original) = &form.editing {
            let entry = opened.entry(original).map_err(|error| error.to_string())?;
            let mut change = Change::default();
            if name != entry.name {
                change.rename = Some(name.clone());
            }
            for (field, value) in [("username", &username), ("url", &url)] {
                match entry.plain(field) {
                    Some(_) if value.is_empty() => change.remove.push(field.to_string()),
                    Some(old) if old == value => {}
                    _ if value.is_empty() => {}
                    _ => change.plain.push((field.to_string(), value.clone())),
                }
            }
            if !form.secret.is_empty() {
                change
                    .secrets
                    .push((entry.kind.primary().to_string(), form.secret.secret()));
            }
            opened.change(original, change)
        } else {
            if form.secret.is_empty() {
                return Err(format!(
                    "type the {} or press ctrl+g to generate one",
                    form.kind.primary()
                ));
            }
            let mut plain = Vec::new();
            for (field, value) in [("username", &username), ("url", &url)] {
                if !value.is_empty() {
                    plain.push((field.to_string(), value.clone()));
                }
            }
            opened.add(NewEntry {
                name: name.clone(),
                kind: form.kind,
                plain,
                secrets: vec![(form.kind.primary().to_string(), form.secret.secret())],
                tags: Vec::new(),
            })
        };
        applied.map_err(|error| format!("{error:#}"))?;

        if let Err(error) = opened.save(keyring) {
            // What is in memory was not saved, so it is thrown away for what
            // is on disk rather than left to look saved.
            let message = format!("{error:#}");
            self.open_selected();
            return Err(message);
        }
        Ok(name)
    }

    fn delete(&mut self, entry: &str) -> Result<(), String> {
        let (Some(keyring), Some(opened)) = (self.keyring.as_ref(), self.opened.as_mut()) else {
            return Err("the vault is not open".to_string());
        };
        opened.remove(entry).map_err(|error| error.to_string())?;
        if let Err(error) = opened.save(keyring) {
            let message = format!("{error:#}");
            self.open_selected();
            return Err(message);
        }
        self.entry_index = self.entry_index.min(self.entries().len().saturating_sub(1));
        self.field_index = 0;
        Ok(())
    }

    fn trust(&mut self, inspection: Inspection) {
        let Some(keyring) = self.keyring.as_ref() else {
            return;
        };
        match keyring.trust_vault(inspection) {
            Ok(opened) => {
                self.status = format!("trusted the vault {}", opened.vault().name());
                self.opened = Some(opened);
                self.problem = None;
                self.untrusted = false;
            }
            Err(error) => self.status = format!("{error:#}"),
        }
    }
}

impl Drop for VaultScreen {
    fn drop(&mut self) {
        self.lock();
    }
}

/// Quotes text for a shell when it needs it.
fn shell_word(text: &str) -> String {
    if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./@:+".contains(c))
    {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::vault::test_support::{PASSPHRASE, Scratch, keyring};

    pub fn press(screen: &mut VaultScreen, code: KeyCode) {
        screen.handle_key(KeyEvent::new(code, KeyModifiers::NONE));
    }

    pub fn press_ctrl(screen: &mut VaultScreen, code: KeyCode) {
        screen.handle_key(KeyEvent::new(code, KeyModifiers::CONTROL));
    }

    pub fn type_text(screen: &mut VaultScreen, text: &str) {
        for ch in text.chars() {
            press(screen, KeyCode::Char(ch));
        }
    }

    /// A screen on a fresh vault directory holding an identity and the
    /// personal vault, not yet unlocked.
    pub fn locked(label: &str) -> (Scratch, VaultScreen) {
        let (scratch, keyring) = keyring(label);
        keyring.create_vault(DEFAULT_VAULT, &[]).unwrap();
        drop(keyring);
        let screen = VaultScreen::new(Ok(Home::at(&scratch.0)));
        (scratch, screen)
    }

    /// The same, unlocked through the passphrase dialog.
    pub fn unlocked(label: &str) -> (Scratch, VaultScreen) {
        let (scratch, mut screen) = locked(label);
        screen.enter();
        type_text(&mut screen, PASSPHRASE);
        press(&mut screen, KeyCode::Enter);
        assert!(screen.is_unlocked(), "{:?}", screen.status);
        (scratch, screen)
    }

    /// Adds a login through the form, the way a person would.
    pub fn add_login(screen: &mut VaultScreen, name: &str, username: &str, password: &str) {
        press(screen, KeyCode::Char('a'));
        type_text(screen, name);
        press(screen, KeyCode::Tab); // kind stays login
        press(screen, KeyCode::Tab);
        type_text(screen, username);
        press(screen, KeyCode::Tab); // no url
        press(screen, KeyCode::Tab);
        type_text(screen, password);
        press(screen, KeyCode::Enter);
    }

    #[test]
    fn entering_asks_for_the_passphrase_and_a_wrong_one_keeps_it_locked() {
        let (_scratch, mut screen) = locked("tui-wrong");
        screen.enter();
        assert!(matches!(screen.dialog, Some(Dialog::Unlock { .. })));

        type_text(&mut screen, "not the passphrase");
        press(&mut screen, KeyCode::Enter);
        assert!(!screen.is_unlocked());
        let Some(Dialog::Unlock { passphrase, error }) = &screen.dialog else {
            panic!("the dialog closed after a wrong passphrase");
        };
        assert!(passphrase.is_empty(), "the wrong passphrase was kept");
        assert!(
            error
                .as_deref()
                .unwrap_or_default()
                .contains("wrong passphrase")
        );
    }

    #[test]
    fn without_an_identity_entering_offers_to_create_one() {
        let scratch = Scratch::new("tui-no-identity");
        let mut screen = VaultScreen::new(Ok(Home::at(&scratch.0)));
        screen.enter();
        assert!(matches!(screen.dialog, Some(Dialog::CreateIdentity { .. })));
        assert_eq!(screen.command_hint().as_deref(), Some("txc vault init"));

        // Too short a passphrase is refused before any key is made.
        type_text(&mut screen, "short");
        press(&mut screen, KeyCode::Enter);
        type_text(&mut screen, "short");
        press(&mut screen, KeyCode::Enter);
        let Some(Dialog::CreateIdentity { error, .. }) = &screen.dialog else {
            panic!("the dialog closed");
        };
        assert!(
            error
                .as_deref()
                .unwrap_or_default()
                .contains("12 characters")
        );
        assert!(!screen.has_identity());
    }

    #[test]
    fn an_entry_added_through_the_form_is_saved_sealed() {
        let (scratch, mut screen) = unlocked("tui-add");
        add_login(&mut screen, "GitHub", "octocat", "hunter2");
        assert!(screen.dialog.is_none(), "{:?}", screen.status);
        assert_eq!(screen.selected_entry().unwrap().name, "GitHub");

        // Read back from disk with a fresh unlock, not from the screen.
        let home = Home::at(&scratch.0);
        let keyring = Keyring::unlock(&home, &SecretString::from(PASSPHRASE.to_string())).unwrap();
        let opened = keyring.open(DEFAULT_VAULT).unwrap();
        let entry = opened.entry("GitHub").unwrap();
        assert_eq!(entry.plain("username"), Some("octocat"));
        assert!(entry.field("password").unwrap().is_sealed());
        assert_eq!(
            opened
                .reveal(&keyring, "GitHub", "password")
                .unwrap()
                .expose_secret(),
            "hunter2"
        );
    }

    #[test]
    fn a_form_without_a_secret_is_not_saved() {
        let (_scratch, mut screen) = unlocked("tui-no-secret");
        press(&mut screen, KeyCode::Char('a'));
        type_text(&mut screen, "site");
        press_ctrl(&mut screen, KeyCode::Char('s'));
        let Some(Dialog::Entry(form)) = &screen.dialog else {
            panic!("the form closed without a secret");
        };
        assert!(form.error.as_deref().unwrap_or_default().contains("ctrl+g"));
    }

    #[test]
    fn ctrl_g_generates_a_secret_that_is_shown_only_as_dots() {
        let (_scratch, mut screen) = unlocked("tui-generate");
        press(&mut screen, KeyCode::Char('a'));
        type_text(&mut screen, "generated");
        press_ctrl(&mut screen, KeyCode::Char('g'));
        let Some(Dialog::Entry(form)) = &screen.dialog else {
            panic!("the form closed");
        };
        assert!(form.generated);
        assert_eq!(form.secret.chars(), 24);
        assert_eq!(form.secret.masked(), "•".repeat(24));
        press_ctrl(&mut screen, KeyCode::Char('s'));
        assert!(screen.dialog.is_none());
    }

    #[test]
    fn copying_hands_one_secret_to_the_event_loop() {
        let (_scratch, mut screen) = unlocked("tui-copy");
        add_login(&mut screen, "site", "octocat", "hunter2");

        press(&mut screen, KeyCode::Char('c'));
        let (secret, label) = screen.pending_copy.take().expect("a copy was queued");
        assert_eq!(secret.expose_secret(), "hunter2");
        assert_eq!(label, "password of personal/site");

        press(&mut screen, KeyCode::Char('u'));
        let (secret, _) = screen.pending_copy.take().unwrap();
        assert_eq!(secret.expose_secret(), "octocat");
    }

    #[test]
    fn editing_keeps_the_secret_unless_a_new_one_is_typed() {
        let (_scratch, mut screen) = unlocked("tui-edit");
        add_login(&mut screen, "site", "old", "keep-me");

        press(&mut screen, KeyCode::Char('e'));
        press(&mut screen, KeyCode::Tab); // to username; kind is not offered
        press_ctrl(&mut screen, KeyCode::Char('u'));
        type_text(&mut screen, "new");
        press_ctrl(&mut screen, KeyCode::Char('s'));
        assert!(screen.dialog.is_none(), "{:?}", screen.status);

        let entry = screen.selected_entry().unwrap();
        assert_eq!(entry.plain("username"), Some("new"));
        press(&mut screen, KeyCode::Char('c'));
        let (secret, _) = screen.pending_copy.take().unwrap();
        assert_eq!(secret.expose_secret(), "keep-me");
    }

    #[test]
    fn removing_asks_first() {
        let (_scratch, mut screen) = unlocked("tui-delete");
        add_login(&mut screen, "site", "u", "p");

        press(&mut screen, KeyCode::Char('d'));
        press(&mut screen, KeyCode::Char('n'));
        assert_eq!(screen.entries().len(), 1);

        press(&mut screen, KeyCode::Char('d'));
        press(&mut screen, KeyCode::Char('y'));
        assert!(screen.entries().is_empty(), "{}", screen.status);
    }

    #[test]
    fn searching_narrows_the_entries() {
        let (_scratch, mut screen) = unlocked("tui-search");
        add_login(&mut screen, "GitHub", "octocat", "1");
        add_login(&mut screen, "Mail", "me", "2");

        press(&mut screen, KeyCode::Char('/'));
        type_text(&mut screen, "octo");
        assert_eq!(screen.entries().len(), 1);
        assert_eq!(screen.selected_entry().unwrap().name, "GitHub");
        press(&mut screen, KeyCode::Esc);
        assert_eq!(screen.entries().len(), 2);
    }

    #[test]
    fn locking_forgets_the_key_the_vault_and_any_pending_copy() {
        let (_scratch, mut screen) = unlocked("tui-lock");
        add_login(&mut screen, "site", "u", "p");
        press(&mut screen, KeyCode::Char('c'));
        assert!(screen.pending_copy.is_some());

        press_ctrl(&mut screen, KeyCode::Char('l'));
        assert!(!screen.is_unlocked());
        assert!(screen.opened().is_none());
        assert!(screen.pending_copy.is_none());
        assert!(screen.entries().is_empty());
    }

    #[test]
    fn it_locks_itself_after_a_while_without_a_key() {
        let (_scratch, mut screen) = unlocked("tui-idle");
        screen.tick(Instant::now() + IDLE_LOCK / 2);
        assert!(screen.is_unlocked());
        screen.tick(Instant::now() + IDLE_LOCK);
        assert!(!screen.is_unlocked());
        assert!(screen.status.contains("five minutes"));
    }

    #[test]
    fn a_vault_without_trust_is_explained_and_can_be_trusted() {
        let (scratch, mut screen) = locked("tui-trust");
        std::fs::remove_file(Home::at(&scratch.0).trust_path()).unwrap();
        screen.enter();
        type_text(&mut screen, PASSPHRASE);
        press(&mut screen, KeyCode::Enter);

        assert!(screen.opened().is_none());
        assert!(screen.untrusted());
        assert!(screen.problem().unwrap().contains("not been trusted"));
        assert_eq!(
            screen.command_hint().as_deref(),
            Some("txc vault trust personal")
        );

        press(&mut screen, KeyCode::Char('t'));
        assert!(matches!(screen.dialog, Some(Dialog::Trust(_))));
        press(&mut screen, KeyCode::Char('y'));
        assert!(screen.opened().is_some(), "{}", screen.status);
    }

    #[test]
    fn a_new_vault_can_be_created_and_is_opened() {
        let (_scratch, mut screen) = unlocked("tui-new-vault");
        press(&mut screen, KeyCode::Char('n'));
        type_text(&mut screen, "Bad Name");
        press(&mut screen, KeyCode::Enter);
        assert!(matches!(
            screen.dialog,
            Some(Dialog::NewVault { error: Some(_), .. })
        ));

        press_ctrl(&mut screen, KeyCode::Char('u'));
        type_text(&mut screen, "work");
        press(&mut screen, KeyCode::Enter);
        assert!(screen.dialog.is_none(), "{}", screen.status);
        assert_eq!(screen.selected_vault(), Some("work"));
        assert!(screen.opened().is_some());
    }

    #[test]
    fn the_command_hint_follows_the_selection() {
        let (_scratch, mut screen) = unlocked("tui-hint");
        assert_eq!(
            screen.command_hint().as_deref(),
            Some("txc vault list personal")
        );
        add_login(&mut screen, "My Bank", "me", "p");
        assert_eq!(
            screen.command_hint().as_deref(),
            Some("txc vault copy 'personal/My Bank'")
        );
        screen.pane = Pane::Fields;
        screen.field_index = 0; // username comes first
        assert_eq!(
            screen.command_hint().as_deref(),
            Some("txc vault copy 'personal/My Bank' --field username")
        );
    }

    #[test]
    fn a_typed_secret_never_outgrows_its_buffer() {
        let mut input = SecretInput::default();
        let capacity = input.text.capacity();
        for _ in 0..MAX_TYPED_BYTES + 10 {
            input.insert('é');
        }
        // Full, and still in the buffer it started with: a reallocation would
        // have left a copy of what was typed in the old one.
        assert!(input.text.len() <= MAX_TYPED_BYTES);
        assert_eq!(input.text.capacity(), capacity);

        input.clear();
        assert!(input.is_empty());
        assert_eq!(input.text.capacity(), capacity);
    }
}
