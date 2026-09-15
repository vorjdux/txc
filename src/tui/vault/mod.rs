//! The vault screen of the interactive interface, reached with F3.
//!
//! Down the left are the ways in: favourites, the entries used most recently
//! on this device, every entry, each kind and each vault. In the middle is the
//! list, and on the right the selected entry.
//!
//! Secrets are masked. One can be revealed for a few seconds on request, and
//! a note is shown in full when it is opened; otherwise a secret leaves only
//! through the clipboard, which is cleared again. The passphrase is checked on
//! a thread of its own, behind a spinner, because that is slow on purpose.
//! The vault locks itself after a few minutes without a key, and when the
//! interface closes.

pub(crate) mod draw;
pub mod form;

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use age::secrecy::{ExposeSecret, SecretString};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::textarea::TextArea;
use crate::vault::clipboard::{DEFAULT_CLEAR_SECONDS, Held};
use crate::vault::model::{DEFAULT_VAULT, Entry, Kind, Sensitivity, check_vault_name};
use crate::vault::prompt::check_new_passphrase;
use crate::vault::{Change, Home, Inspection, Keyring, NewEntry, NotTrusted, Opened, Use, harden};

pub use form::{EntryForm, FormAction, SecretInput};

/// How long the vault stays unlocked without a key being pressed.
pub const IDLE_LOCK: Duration = Duration::from_secs(5 * 60);

/// How long a copied secret stays on the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(DEFAULT_CLEAR_SECONDS);

/// How long a revealed secret stays on screen.
pub const REVEAL_FOR: Duration = Duration::from_secs(15);

/// Which part of the screen keys go to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pane {
    /// The sections down the left.
    Sidebar,
    /// The list of entries.
    Items,
    /// The fields of the selected entry.
    Details,
}

impl Pane {
    const fn next(self) -> Self {
        match self {
            Self::Sidebar => Self::Items,
            Self::Items => Self::Details,
            Self::Details => Self::Sidebar,
        }
    }

    const fn previous(self) -> Self {
        match self {
            Self::Sidebar => Self::Details,
            Self::Items => Self::Sidebar,
            Self::Details => Self::Items,
        }
    }
}

/// What the list in the middle shows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Section {
    /// Starred entries, from every vault.
    Favourites,
    /// The entries used most recently on this device, newest first.
    Recent,
    /// Every entry of every open vault.
    All,
    /// Every entry of one kind.
    Kind(Kind),
    /// The entries of one vault, by its position in the list of vaults.
    Vault(usize),
}

/// A row down the left.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SidebarRow {
    /// A section to choose.
    Section(Section),
    /// A heading over a group of sections.
    Heading(&'static str),
}

/// A vault as the screen holds it: open, or the reason it is not.
pub struct LoadedVault {
    /// Its name.
    pub name: String,
    /// The vault, when it opened.
    pub opened: Option<Opened>,
    /// Why it did not open.
    pub problem: Option<String>,
    /// Whether it is refused only for want of trust, which `t` can give.
    pub untrusted: bool,
}

/// An entry in the list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Item {
    /// The position of its vault.
    pub vault: usize,
    /// Its name.
    pub entry: String,
    /// When it was last used, in the recent list.
    pub used: Option<String>,
}

/// A secret shown on screen for a moment.
pub struct Revealed {
    vault: usize,
    entry: String,
    field: String,
    secret: SecretString,
    until: Instant,
}

/// A note opened to be read.
pub struct NoteView {
    /// The position of its vault.
    pub vault: usize,
    /// The entry it belongs to.
    pub entry: String,
    /// The field holding it.
    pub field: String,
    /// What to call the window.
    pub title: String,
    /// The note itself.
    pub text: SecretString,
    /// How far it is scrolled.
    pub scroll: u16,
}

/// The slow work done off the interface thread.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Job {
    Unlock,
    Create,
}

/// Work running in the background, and when it started.
pub struct Busy {
    /// The window's title.
    pub title: &'static str,
    /// What is happening.
    pub message: &'static str,
    /// When it started.
    pub started: Instant,
    job: Job,
    receiver: Receiver<Result<Keyring, String>>,
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
    /// Choosing what kind of entry to add.
    PickKind {
        /// The kind highlighted.
        index: usize,
    },
    /// Adding or editing an entry.
    Entry(Box<EntryForm>),
    /// Reading a note.
    Note(Box<NoteView>),
    /// Confirming that an entry should be removed.
    Delete {
        /// The position of its vault.
        vault: usize,
        /// Its name.
        entry: String,
    },
    /// Showing how a vault differs from what was trusted, and asking.
    Trust(Box<(usize, Inspection)>),
}

/// Everything the vault screen needs to draw itself and answer a key.
pub struct VaultScreen {
    home: Result<Home, String>,
    keyring: Option<Keyring>,
    vaults: Vec<LoadedVault>,
    locked_names: Vec<String>,
    recent: Vec<Use>,
    /// What the list shows.
    pub section: Section,
    item_index: usize,
    field_index: usize,
    /// Which part keys go to.
    pub pane: Pane,
    /// The text narrowing the list.
    pub search: String,
    /// Whether keys are going to the search box.
    pub searching: bool,
    /// The window open over the screen, if any.
    pub dialog: Option<Dialog>,
    busy: Option<Busy>,
    revealed: Option<Revealed>,
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
            locked_names: Vec::new(),
            recent: Vec::new(),
            section: Section::All,
            item_index: 0,
            field_index: 0,
            pane: Pane::Items,
            search: String::new(),
            searching: false,
            dialog: None,
            busy: None,
            revealed: None,
            pending_copy: None,
            held: None,
            last_key: Instant::now(),
            status: String::new(),
        }
    }

    /// Called when the screen is switched to: while locked, lists the vaults
    /// by name and asks for the passphrase, or offers to create the identity.
    pub fn enter(&mut self) {
        self.last_key = Instant::now();
        if self.keyring.is_none() {
            self.locked_names = self
                .home
                .as_ref()
                .ok()
                .and_then(|home| home.vault_names().ok())
                .unwrap_or_default();
            if self.dialog.is_none() && self.busy.is_none() {
                self.begin_unlock();
            }
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

    /// The slow work in progress, if any.
    #[must_use]
    pub const fn busy(&self) -> Option<&Busy> {
        self.busy.as_ref()
    }

    /// This identity's public key, while unlocked.
    #[must_use]
    pub fn public_key(&self) -> Option<String> {
        self.keyring.as_ref().map(Keyring::public_key)
    }

    /// The vaults, while unlocked.
    #[must_use]
    pub fn vaults(&self) -> &[LoadedVault] {
        &self.vaults
    }

    /// The vault names, as listed while locked.
    #[must_use]
    pub fn locked_names(&self) -> &[String] {
        &self.locked_names
    }

    fn entries(&self) -> impl Iterator<Item = (usize, &Entry)> + '_ {
        self.vaults
            .iter()
            .enumerate()
            .filter_map(|(index, vault)| vault.opened.as_ref().map(|opened| (index, opened)))
            .flat_map(|(index, opened)| {
                opened
                    .vault()
                    .entries()
                    .iter()
                    .map(move |entry| (index, entry))
            })
    }

    /// The rows down the left: the three ways in, the kinds that have
    /// entries, and the vaults.
    #[must_use]
    pub fn sidebar(&self) -> Vec<SidebarRow> {
        let mut rows = vec![
            SidebarRow::Section(Section::Favourites),
            SidebarRow::Section(Section::Recent),
            SidebarRow::Section(Section::All),
        ];
        let kinds: Vec<Kind> = Kind::ALL
            .into_iter()
            .filter(|kind| self.entries().any(|(_, entry)| entry.kind == *kind))
            .collect();
        if !kinds.is_empty() {
            rows.push(SidebarRow::Heading("Kinds"));
            rows.extend(
                kinds
                    .into_iter()
                    .map(|kind| SidebarRow::Section(Section::Kind(kind))),
            );
        }
        rows.push(SidebarRow::Heading("Vaults"));
        rows.extend((0..self.vaults.len()).map(|index| SidebarRow::Section(Section::Vault(index))));
        rows
    }

    /// What a section is called above the list.
    #[must_use]
    pub fn section_title(&self, section: Section) -> String {
        match section {
            Section::Favourites => "Favourites".to_string(),
            Section::Recent => "Recently used".to_string(),
            Section::All => "All items".to_string(),
            Section::Kind(kind) => kind.plural().to_string(),
            Section::Vault(index) => self
                .vaults
                .get(index)
                .map_or_else(String::new, |vault| format!("Vault {}", vault.name)),
        }
    }

    /// How many entries a section holds, ignoring the search.
    #[must_use]
    pub fn count(&self, section: Section) -> usize {
        self.items_in(section, "").len()
    }

    /// The entries the list shows: the section, narrowed by the search.
    #[must_use]
    pub fn items(&self) -> Vec<Item> {
        self.items_in(self.section, &self.search)
    }

    fn items_in(&self, section: Section, search: &str) -> Vec<Item> {
        let mut items: Vec<Item> = if section == Section::Recent {
            self.recent
                .iter()
                .filter_map(|used| {
                    let vault = self.vaults.iter().position(|v| v.name == used.vault)?;
                    let entry = self.vaults[vault]
                        .opened
                        .as_ref()?
                        .vault()
                        .entries()
                        .iter()
                        .find(|entry| entry.name == used.entry)?;
                    Some(Item {
                        vault,
                        entry: entry.name.clone(),
                        used: Some(used.at.clone()),
                    })
                })
                .collect()
        } else {
            let mut items: Vec<Item> = self
                .entries()
                .filter(|(vault, entry)| match section {
                    Section::Favourites => entry.favourite,
                    Section::Kind(kind) => entry.kind == kind,
                    Section::Vault(index) => *vault == index,
                    Section::All | Section::Recent => true,
                })
                .map(|(vault, entry)| Item {
                    vault,
                    entry: entry.name.clone(),
                    used: None,
                })
                .collect();
            items.sort_by_cached_key(|item| (item.entry.to_lowercase(), item.vault));
            items
        };

        let needle = search.trim().to_lowercase();
        if !needle.is_empty() {
            items.retain(|item| {
                self.entry_of(item).is_some_and(|entry| {
                    matches_search(entry, &self.vaults[item.vault].name, &needle)
                })
            });
        }
        items
    }

    /// The entry an item stands for.
    #[must_use]
    pub fn entry_of(&self, item: &Item) -> Option<&Entry> {
        self.vaults
            .get(item.vault)?
            .opened
            .as_ref()?
            .vault()
            .entries()
            .iter()
            .find(|entry| entry.name == item.entry)
    }

    /// Which item is selected.
    #[must_use]
    pub const fn item_index(&self) -> usize {
        self.item_index
    }

    /// The selected item.
    #[must_use]
    pub fn selected_item(&self) -> Option<Item> {
        self.items().into_iter().nth(self.item_index)
    }

    /// The selected entry, and the position of its vault.
    #[must_use]
    pub fn selected(&self) -> Option<(usize, &Entry)> {
        let item = self.selected_item()?;
        Some((item.vault, self.entry_of(&item)?))
    }

    /// Which field of the entry is selected.
    #[must_use]
    pub const fn field_index(&self) -> usize {
        self.field_index
    }

    /// The secret revealed for this field, while it is.
    #[must_use]
    pub fn shown_secret(&self, vault: usize, entry: &str, field: &str) -> Option<&SecretString> {
        self.revealed
            .as_ref()
            .filter(|shown| shown.vault == vault && shown.entry == entry && shown.field == field)
            .map(|shown| &shown.secret)
    }

    /// Seconds until the revealed secret is hidden again.
    #[must_use]
    pub fn reveal_left(&self, now: Instant) -> Option<u64> {
        self.revealed
            .as_ref()
            .map(|shown| shown.until.saturating_duration_since(now).as_secs() + 1)
    }

    /// Seconds until the clipboard is cleared, while a secret is on it.
    #[must_use]
    pub fn clears_in(&self, now: Instant) -> Option<u64> {
        self.held
            .as_ref()
            .map(|(_, at)| at.saturating_duration_since(now).as_secs() + 1)
    }

    /// The vault section on screen, when its vault did not open.
    #[must_use]
    pub fn problem(&self) -> Option<(usize, &LoadedVault)> {
        match self.section {
            Section::Vault(index) => self
                .vaults
                .get(index)
                .filter(|vault| vault.problem.is_some())
                .map(|vault| (index, vault)),
            _ => None,
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
        if !self.is_unlocked() {
            return Some("txc vault list".to_string());
        }
        if let Some((_, vault)) = self.problem() {
            return Some(if vault.untrusted {
                format!("txc vault trust {}", vault.name)
            } else {
                format!("txc vault list {}", vault.name)
            });
        }
        if let Some((vault, entry)) = self.selected() {
            let reference = shell_word(&format!("{}/{}", self.vaults[vault].name, entry.name));
            let field = entry
                .fields
                .get(self.field_index)
                .filter(|_| self.pane == Pane::Details)
                .map(|field| field.name.as_str())
                .filter(|field| *field != entry.kind.primary());
            return Some(match field {
                Some(field) => format!("txc vault copy {reference} --field {field}"),
                None => format!("txc vault copy {reference}"),
            });
        }
        Some(match self.section {
            Section::Favourites => "txc vault list --favourites".to_string(),
            Section::Recent => "txc vault list --recent".to_string(),
            Section::Kind(kind) => format!("txc vault list --kind {}", kind.id()),
            Section::Vault(index) => format!("txc vault list {}", self.vaults[index].name),
            Section::All => "txc vault add <name> --generate".to_string(),
        })
    }

    /// Locks: forgets the key, the vaults and anything revealed, and takes any
    /// secret off the clipboard.
    pub fn lock(&mut self) {
        self.release_clipboard();
        self.pending_copy = None;
        self.revealed = None;
        self.dialog = None;
        self.vaults.clear();
        self.recent.clear();
        self.keyring = None;
        self.search.clear();
        self.searching = false;
        self.section = Section::All;
        self.pane = Pane::Items;
        self.item_index = 0;
        self.field_index = 0;
    }

    /// Picks up finished work, hides a revealed secret and clears the
    /// clipboard when their time is up, and locks after a while without a
    /// key. Called by the event loop on every turn.
    pub fn tick(&mut self, now: Instant) {
        let finished = match self.busy.as_ref().map(|busy| busy.receiver.try_recv()) {
            None | Some(Err(TryRecvError::Empty)) => None,
            Some(Ok(result)) => Some(result),
            Some(Err(TryRecvError::Disconnected)) => {
                Some(Err("the work stopped before it finished".to_string()))
            }
        };
        if let Some(result) = finished
            && let Some(busy) = self.busy.take()
        {
            self.finish_job(busy.job, result);
        }

        if self
            .revealed
            .as_ref()
            .is_some_and(|shown| now >= shown.until)
        {
            self.revealed = None;
        }

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

        if self.keyring.is_some()
            && self.busy.is_none()
            && now.saturating_duration_since(self.last_key) >= IDLE_LOCK
        {
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

    /// Takes pasted text into whatever is being typed.
    pub fn handle_paste(&mut self, text: &str) {
        self.last_key = Instant::now();
        if self.busy.is_some() {
            return;
        }
        match self.dialog.as_mut() {
            Some(Dialog::Unlock { passphrase, .. }) => passphrase.insert_str(text, false),
            Some(Dialog::CreateIdentity {
                passphrase,
                again,
                on_again,
                ..
            }) => {
                if *on_again {
                    again.insert_str(text, false);
                } else {
                    passphrase.insert_str(text, false);
                }
            }
            Some(Dialog::NewVault { name, .. }) => {
                for ch in text.chars().filter(|ch| !ch.is_control()) {
                    name.insert(ch);
                }
            }
            Some(Dialog::Entry(form)) => form.paste(text),
            Some(_) => {}
            None => {
                if self.searching {
                    self.search
                        .extend(text.chars().filter(|ch| !ch.is_control()));
                    self.item_index = 0;
                }
            }
        }
    }

    /// Answers one key.
    pub fn handle_key(&mut self, key: KeyEvent) {
        self.last_key = Instant::now();
        if self.busy.is_some() {
            self.status = "still working, one moment".to_string();
            return;
        }
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
            KeyCode::Char('1') => self.set_section(Section::Favourites),
            KeyCode::Char('2') => self.set_section(Section::Recent),
            KeyCode::Char('3') => self.set_section(Section::All),
            KeyCode::Char('/') => {
                self.searching = true;
                if self.pane == Pane::Sidebar {
                    self.pane = Pane::Items;
                }
            }
            KeyCode::Char('a') => self.begin_add(),
            KeyCode::Char('n') => {
                self.dialog = Some(Dialog::NewVault {
                    name: TextArea::default(),
                    error: None,
                });
            }
            KeyCode::Char('l') => {
                self.lock();
                self.status = "locked".to_string();
            }
            KeyCode::Char('t') => match self.trust_dialog() {
                Ok(dialog) => self.dialog = Some(dialog),
                Err(message) => self.status = message,
            },
            _ => match self.pane {
                Pane::Sidebar => self.sidebar_key(key),
                Pane::Items => self.items_key(key),
                Pane::Details => self.details_key(key),
            },
        }
    }

    fn set_section(&mut self, section: Section) {
        self.section = section;
        self.item_index = 0;
        self.field_index = 0;
        self.revealed = None;
    }

    fn move_section(&mut self, forward: bool) {
        let sections: Vec<Section> = self
            .sidebar()
            .into_iter()
            .filter_map(|row| match row {
                SidebarRow::Section(section) => Some(section),
                SidebarRow::Heading(_) => None,
            })
            .collect();
        let index = sections
            .iter()
            .position(|section| *section == self.section)
            .unwrap_or(0);
        let next = if forward {
            (index + 1).min(sections.len() - 1)
        } else {
            index.saturating_sub(1)
        };
        self.set_section(sections[next]);
    }

    fn move_item(&mut self, to: usize) {
        let count = self.items().len();
        self.item_index = to.min(count.saturating_sub(1));
        self.field_index = 0;
        self.revealed = None;
    }

    /// Selects an entry again after the list changed around it, or keeps the
    /// selection in range when it is gone.
    fn reselect(&mut self, vault: usize, entry: &str) {
        let items = self.items();
        match items
            .iter()
            .position(|item| item.vault == vault && item.entry == entry)
        {
            Some(index) => self.item_index = index,
            None => self.item_index = self.item_index.min(items.len().saturating_sub(1)),
        }
    }

    fn sidebar_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_section(false),
            KeyCode::Down | KeyCode::Char('j') => self.move_section(true),
            KeyCode::Enter | KeyCode::Right => self.pane = Pane::Items,
            _ => {}
        }
    }

    fn items_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_item(self.item_index.saturating_sub(1)),
            KeyCode::Down | KeyCode::Char('j') => self.move_item(self.item_index + 1),
            KeyCode::PageUp => self.move_item(self.item_index.saturating_sub(10)),
            KeyCode::PageDown => self.move_item(self.item_index + 10),
            KeyCode::Home => self.move_item(0),
            KeyCode::End => self.move_item(usize::MAX),
            KeyCode::Enter | KeyCode::Char('c') => self.copy(None),
            KeyCode::Char('u') => self.copy(Some("username".to_string())),
            KeyCode::Char('r') => self.reveal(None),
            KeyCode::Char('f') => self.toggle_favourite(),
            KeyCode::Char('e') => self.begin_edit(),
            KeyCode::Char('d') => self.begin_delete(),
            KeyCode::Right | KeyCode::Char('o') => {
                if self.selected().is_some() {
                    self.pane = Pane::Details;
                }
            }
            KeyCode::Left => self.pane = Pane::Sidebar,
            KeyCode::Esc => {
                self.search.clear();
                self.move_item(0);
            }
            _ => {}
        }
    }

    fn details_key(&mut self, key: KeyEvent) {
        let count = self.selected().map_or(0, |(_, entry)| entry.fields.len());
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.field_index = self.field_index.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.field_index = (self.field_index + 1).min(count.saturating_sub(1));
            }
            KeyCode::Enter => {
                if let Some(field) = self.selected_field() {
                    let private = self.selected().is_some_and(|(_, entry)| {
                        entry.sensitivity(&field) == Sensitivity::Private
                    });
                    if private {
                        self.reveal(Some(field));
                    } else {
                        self.copy(Some(field));
                    }
                }
            }
            KeyCode::Char('c') => {
                if let Some(field) = self.selected_field() {
                    self.copy(Some(field));
                }
            }
            KeyCode::Char('r') => {
                if let Some(field) = self.selected_field() {
                    self.reveal(Some(field));
                }
            }
            KeyCode::Char('f') => self.toggle_favourite(),
            KeyCode::Char('e') => self.begin_edit(),
            KeyCode::Char('d') => self.begin_delete(),
            KeyCode::Left | KeyCode::Esc => self.pane = Pane::Items,
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
        self.move_item(0);
    }

    fn selected_field(&self) -> Option<String> {
        self.selected()
            .and_then(|(_, entry)| entry.fields.get(self.field_index))
            .map(|field| field.name.clone())
    }

    fn decrypt(&self, vault: usize, entry: &str, field: &str) -> Result<SecretString, String> {
        let keyring = self.keyring.as_ref().ok_or("the vault is locked")?;
        let opened = self
            .vaults
            .get(vault)
            .and_then(|loaded| loaded.opened.as_ref())
            .ok_or("the vault is not open")?;
        opened
            .reveal(keyring, entry, field)
            .map_err(|error| format!("{error:#}"))
    }

    /// The selected entry and one of its fields, when the entry has it.
    fn target(
        &self,
        field: Option<String>,
    ) -> Result<(usize, String, String, Sensitivity, String), String> {
        let (vault, entry) = self.selected().ok_or("select an entry first")?;
        let field = field.unwrap_or_else(|| entry.kind.primary().to_string());
        if entry.field(&field).is_none() {
            return Err(format!(
                "{} has no {}",
                entry.name,
                entry.label(&field).to_lowercase()
            ));
        }
        Ok((
            vault,
            entry.name.clone(),
            field.clone(),
            entry.sensitivity(&field),
            entry.label(&field).to_lowercase(),
        ))
    }

    /// Decrypts one field and hands it to the event loop for the clipboard.
    fn copy(&mut self, field: Option<String>) {
        let (vault, entry, field, _, label) = match self.target(field) {
            Ok(target) => target,
            Err(message) => {
                self.status = message;
                return;
            }
        };
        match self.decrypt(vault, &entry, &field) {
            Ok(secret) => {
                self.pending_copy = Some((secret, format!("{label} of {entry}")));
                self.note_use(vault, &entry);
                self.status = "copying".to_string();
            }
            Err(message) => self.status = message,
        }
    }

    /// Shows a secret for a few seconds, or hides it again; opens a note.
    fn reveal(&mut self, field: Option<String>) {
        let (vault, entry, field, sensitivity, label) = match self.target(field) {
            Ok(target) => target,
            Err(message) => {
                self.status = message;
                return;
            }
        };
        match sensitivity {
            Sensitivity::Plain => self.status = format!("the {label} is not hidden"),
            Sensitivity::Private => match self.decrypt(vault, &entry, &field) {
                Ok(text) => {
                    self.dialog = Some(Dialog::Note(Box::new(NoteView {
                        vault,
                        title: format!("{entry}: {label}"),
                        entry: entry.clone(),
                        field,
                        text,
                        scroll: 0,
                    })));
                    self.note_use(vault, &entry);
                }
                Err(message) => self.status = message,
            },
            Sensitivity::Secret => {
                if self.shown_secret(vault, &entry, &field).is_some() {
                    self.revealed = None;
                    self.status = "hidden again".to_string();
                    return;
                }
                match self.decrypt(vault, &entry, &field) {
                    Ok(secret) => {
                        self.revealed = Some(Revealed {
                            vault,
                            entry: entry.clone(),
                            field,
                            secret,
                            until: Instant::now() + REVEAL_FOR,
                        });
                        self.note_use(vault, &entry);
                        self.status = format!(
                            "showing the {label} for {}s; r hides it now",
                            REVEAL_FOR.as_secs()
                        );
                    }
                    Err(message) => self.status = message,
                }
            }
        }
    }

    /// Records a use for the recent list. Failing to is not worth an error.
    fn note_use(&mut self, vault: usize, entry: &str) {
        let (Some(keyring), Some(loaded)) = (self.keyring.as_ref(), self.vaults.get(vault)) else {
            return;
        };
        if keyring.record_use(&loaded.name, entry).is_ok() {
            self.recent = keyring.recent();
        }
        if self.section == Section::Recent {
            self.reselect(vault, entry);
        }
    }

    /// Changes an open vault and saves it. When saving fails, the vault is
    /// read again from disk, so nothing unsaved is left looking saved.
    fn modify(
        &mut self,
        vault: usize,
        change: impl FnOnce(&mut Opened) -> anyhow::Result<()>,
    ) -> Result<(), String> {
        let keyring = self.keyring.as_ref().ok_or("the vault is locked")?;
        let opened = self
            .vaults
            .get_mut(vault)
            .and_then(|loaded| loaded.opened.as_mut())
            .ok_or("the vault is not open")?;
        change(opened).map_err(|error| format!("{error:#}"))?;
        if let Err(error) = opened.save(keyring) {
            let message = format!("{error:#}");
            self.reload(vault);
            return Err(message);
        }
        Ok(())
    }

    fn toggle_favourite(&mut self) {
        let Some((vault, name, favourite)) = self
            .selected()
            .map(|(vault, entry)| (vault, entry.name.clone(), !entry.favourite))
        else {
            return;
        };
        let message = match self.modify(vault, |opened| opened.set_favourite(&name, favourite)) {
            Ok(()) if favourite => format!("starred {name}"),
            Ok(()) => format!("unstarred {name}"),
            Err(message) => message,
        };
        self.status = message;
        self.reselect(vault, &name);
    }

    fn begin_add(&mut self) {
        if self.vaults.iter().all(|vault| vault.opened.is_none()) {
            self.status = "no vault is open to add to".to_string();
        } else {
            self.dialog = Some(Dialog::PickKind { index: 0 });
        }
    }

    fn add_form(&self, kind: Kind) -> Dialog {
        let choices: Vec<(usize, String)> = self
            .vaults
            .iter()
            .enumerate()
            .filter(|(_, vault)| vault.opened.is_some())
            .map(|(index, vault)| (index, vault.name.clone()))
            .collect();
        let preferred = match self.section {
            Section::Vault(index) => Some(index),
            _ => self.selected_item().map(|item| item.vault),
        }
        .or_else(|| {
            self.vaults
                .iter()
                .position(|vault| vault.name == DEFAULT_VAULT)
        });
        let position = preferred
            .and_then(|preferred| choices.iter().position(|(index, _)| *index == preferred))
            .unwrap_or(0);
        Dialog::Entry(Box::new(EntryForm::adding(kind, choices, position)))
    }

    fn edit_form(&self) -> Result<EntryForm, String> {
        let (vault, entry) = self.selected().ok_or("select an entry first")?;
        let keyring = self.keyring.as_ref().ok_or("the vault is locked")?;
        let opened = self.vaults[vault]
            .opened
            .as_ref()
            .ok_or("the vault is not open")?;
        let mut notes = Vec::new();
        for field in &entry.fields {
            if entry.sensitivity(&field.name) == Sensitivity::Private && field.is_sealed() {
                let note = opened
                    .reveal(keyring, &entry.name, &field.name)
                    .map_err(|error| format!("{error:#}"))?;
                notes.push((field.name.clone(), note));
            }
        }
        Ok(EntryForm::editing(
            entry,
            (vault, self.vaults[vault].name.clone()),
            &notes,
        ))
    }

    fn begin_edit(&mut self) {
        match self.edit_form() {
            Ok(form) => self.dialog = Some(Dialog::Entry(Box::new(form))),
            Err(message) => self.status = message,
        }
    }

    fn begin_delete(&mut self) {
        if let Some((vault, entry)) = self.selected() {
            self.dialog = Some(Dialog::Delete {
                vault,
                entry: entry.name.clone(),
            });
        }
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

    fn trust_dialog(&self) -> Result<Dialog, String> {
        let (index, vault) = self
            .problem()
            .ok_or("choose the vault that needs trusting, down the left")?;
        if !vault.untrusted {
            return Err("this vault cannot be opened, so there is nothing to trust".to_string());
        }
        let keyring = self.keyring.as_ref().ok_or("the vault is locked")?;
        let inspection = keyring
            .inspect(&vault.name)
            .map_err(|error| format!("{error:#}"))?;
        Ok(Dialog::Trust(Box::new((index, inspection))))
    }

    /// Starts checking the passphrase, or creating the identity, on a thread
    /// of its own, so the interface keeps drawing while scrypt works.
    fn start_job(&mut self, job: Job, passphrase: SecretString) {
        let Ok(home) = self.home.clone() else {
            return;
        };
        harden::process();
        let (sender, receiver) = mpsc::channel();
        let spawned = std::thread::Builder::new()
            .name("txc-vault-unlock".to_string())
            .spawn(move || {
                let result = match job {
                    Job::Unlock => Keyring::unlock(&home, &passphrase),
                    Job::Create => create_identity(&home, &passphrase),
                };
                drop(passphrase);
                let _ = sender.send(result.map_err(|error| format!("{error:#}")));
            });
        match spawned {
            Ok(_) => {
                let (title, message) = match job {
                    Job::Unlock => ("Unlocking", "Checking your passphrase"),
                    Job::Create => ("Creating your identity", "Protecting your new key"),
                };
                self.busy = Some(Busy {
                    title,
                    message,
                    started: Instant::now(),
                    job,
                    receiver,
                });
            }
            Err(error) => self.status = format!("could not start: {error}"),
        }
    }

    fn finish_job(&mut self, job: Job, result: Result<Keyring, String>) {
        match result {
            Ok(keyring) => {
                self.dialog = None;
                self.recent = keyring.recent();
                self.keyring = Some(keyring);
                self.load_vaults();
                self.section = self.default_section();
                self.item_index = 0;
                self.field_index = 0;
                self.pane = Pane::Items;
                self.last_key = Instant::now();
                if job == Job::Create {
                    self.status = "created your identity and the personal vault".to_string();
                }
            }
            Err(message) => match self.dialog.as_mut() {
                Some(Dialog::Unlock { passphrase, error }) => {
                    passphrase.clear();
                    *error = Some(message);
                }
                Some(Dialog::CreateIdentity { again, error, .. }) => {
                    again.clear();
                    *error = Some(message);
                }
                _ => self.status = message,
            },
        }
    }

    /// Where to start after unlocking: the favourites when there are some,
    /// then what was used recently, then everything.
    fn default_section(&self) -> Section {
        if self.entries().any(|(_, entry)| entry.favourite) {
            Section::Favourites
        } else if !self.items_in(Section::Recent, "").is_empty() {
            Section::Recent
        } else {
            Section::All
        }
    }

    fn load_vault(&self, name: String) -> LoadedVault {
        match self.keyring.as_ref().map(|keyring| keyring.open(&name)) {
            Some(Ok(opened)) => LoadedVault {
                name,
                opened: Some(opened),
                problem: None,
                untrusted: false,
            },
            Some(Err(error)) => LoadedVault {
                untrusted: error.downcast_ref::<NotTrusted>().is_some(),
                problem: Some(format!("{error:#}")),
                name,
                opened: None,
            },
            None => LoadedVault {
                name,
                opened: None,
                problem: Some("the vault is locked".to_string()),
                untrusted: false,
            },
        }
    }

    fn load_vaults(&mut self) {
        let names = self
            .home
            .as_ref()
            .ok()
            .and_then(|home| home.vault_names().ok())
            .unwrap_or_default();
        let vaults = names
            .into_iter()
            .map(|name| self.load_vault(name))
            .collect();
        self.vaults = vaults;
    }

    fn reload(&mut self, vault: usize) {
        if let Some(name) = self.vaults.get(vault).map(|loaded| loaded.name.clone()) {
            let loaded = self.load_vault(name);
            self.vaults[vault] = loaded;
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
                (KeyCode::Enter, _) if passphrase.is_empty() => Some(Dialog::Unlock {
                    passphrase,
                    error: Some("type your passphrase".to_string()),
                }),
                (KeyCode::Enter, _) => {
                    self.start_job(Job::Unlock, passphrase.secret());
                    Some(Dialog::Unlock {
                        passphrase,
                        error: None,
                    })
                }
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
                mut error,
            } => {
                match (key.code, control) {
                    (KeyCode::Esc, _) => return,
                    (KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down, _) => {
                        on_again = !on_again;
                    }
                    (KeyCode::Enter, _) if !on_again => on_again = true,
                    (KeyCode::Enter, _) => {
                        let first = passphrase.secret();
                        if let Err(problem) = check_new_passphrase(&first) {
                            error = Some(problem.to_string());
                            again.clear();
                            on_again = false;
                        } else if first.expose_secret() != again.secret().expose_secret() {
                            error = Some("the two passphrases did not match".to_string());
                            again.clear();
                        } else {
                            error = None;
                            self.start_job(Job::Create, first);
                        }
                    }
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

            Dialog::PickKind { index } => match key.code {
                KeyCode::Esc => None,
                KeyCode::Up | KeyCode::BackTab => Some(Dialog::PickKind {
                    index: index.saturating_sub(1),
                }),
                KeyCode::Down | KeyCode::Tab => Some(Dialog::PickKind {
                    index: (index + 1).min(Kind::ALL.len() - 1),
                }),
                KeyCode::Enter => Some(self.add_form(Kind::ALL[index])),
                KeyCode::Char(ch) => {
                    let ch = ch.to_ascii_lowercase();
                    // The next kind starting with the letter, round from the
                    // one highlighted, so a letter pressed again moves on.
                    let found = (1..=Kind::ALL.len())
                        .map(|step| (index + step) % Kind::ALL.len())
                        .find(|candidate| {
                            Kind::ALL[*candidate]
                                .label()
                                .to_ascii_lowercase()
                                .starts_with(ch)
                        });
                    Some(Dialog::PickKind {
                        index: found.unwrap_or(index),
                    })
                }
                _ => Some(Dialog::PickKind { index }),
            },

            Dialog::Entry(mut form) => match form.key(key) {
                FormAction::Stay => Some(Dialog::Entry(form)),
                FormAction::Cancel => {
                    self.status = "nothing was saved".to_string();
                    None
                }
                FormAction::Save => self.submit_entry(form),
            },

            Dialog::Note(mut view) => match (key.code, control) {
                (KeyCode::Esc | KeyCode::Char('q'), _) => None,
                (KeyCode::Up | KeyCode::Char('k'), _) => {
                    view.scroll = view.scroll.saturating_sub(1);
                    Some(Dialog::Note(view))
                }
                (KeyCode::Down | KeyCode::Char('j'), _) => {
                    view.scroll = view.scroll.saturating_add(1);
                    Some(Dialog::Note(view))
                }
                (KeyCode::PageUp, _) => {
                    view.scroll = view.scroll.saturating_sub(10);
                    Some(Dialog::Note(view))
                }
                (KeyCode::PageDown, _) => {
                    view.scroll = view.scroll.saturating_add(10);
                    Some(Dialog::Note(view))
                }
                (KeyCode::Char('c'), false) => {
                    let copy = SecretString::from(view.text.expose_secret().to_owned());
                    self.pending_copy = Some((copy, view.title.to_lowercase()));
                    self.status = "copying".to_string();
                    Some(Dialog::Note(view))
                }
                (KeyCode::Char('e'), false) => {
                    drop(view);
                    self.begin_edit();
                    return;
                }
                _ => Some(Dialog::Note(view)),
            },

            Dialog::Delete { vault, entry } => {
                let message = if key.code == KeyCode::Char('y') {
                    match self.modify(vault, |opened| opened.remove(&entry)) {
                        Ok(()) => {
                            self.forget(vault, &entry);
                            self.move_item(self.item_index);
                            format!("removed {entry}")
                        }
                        Err(message) => message,
                    }
                } else {
                    "nothing was removed".to_string()
                };
                self.status = message;
                None
            }

            Dialog::Trust(boxed) => {
                if key.code == KeyCode::Char('y') {
                    let (index, inspection) = *boxed;
                    self.trust(index, inspection);
                } else {
                    self.status = "the vault was not trusted".to_string();
                }
                None
            }
        };
    }

    fn forget(&mut self, vault: usize, entry: &str) {
        let (Some(keyring), Some(loaded)) = (self.keyring.as_ref(), self.vaults.get(vault)) else {
            return;
        };
        if keyring.forget_use(&loaded.name, entry).is_ok() {
            self.recent = keyring.recent();
        }
    }

    fn submit_entry(&mut self, mut form: Box<EntryForm>) -> Option<Dialog> {
        match self.save_form(&form) {
            Ok((vault, name)) => {
                self.status = if form.editing.is_some() {
                    format!("saved {name}")
                } else {
                    format!("added {name}")
                };
                self.show_entry(vault, &name);
                None
            }
            Err(message) => {
                form.error = Some(message);
                Some(Dialog::Entry(form))
            }
        }
    }

    fn save_form(&mut self, form: &EntryForm) -> Result<(usize, String), String> {
        let collected = form.collect()?;
        let vault = form.vault_index();
        let name = collected.name.clone();

        if let Some(original) = &form.editing {
            let existing = self
                .vaults
                .get(vault)
                .and_then(|loaded| loaded.opened.as_ref())
                .and_then(|opened| opened.vault().entry(original))
                .cloned()
                .ok_or("the entry is no longer there")?;
            let change = Change {
                rename: (name != existing.name).then(|| name.clone()),
                tag: collected
                    .tags
                    .iter()
                    .filter(|tag| !existing.tags.contains(tag))
                    .cloned()
                    .collect(),
                untag: existing
                    .tags
                    .iter()
                    .filter(|tag| !collected.tags.contains(tag))
                    .cloned()
                    .collect(),
                remove: collected
                    .cleared
                    .into_iter()
                    .filter(|field| existing.field(field).is_some())
                    .collect(),
                plain: collected.plain,
                secrets: collected.secrets,
                favourite: None,
            };
            let renamed = change.rename.is_some();
            self.modify(vault, |opened| opened.change(&existing.name, change))?;
            if renamed
                && let (Some(keyring), Some(loaded)) =
                    (self.keyring.as_ref(), self.vaults.get(vault))
            {
                let _ = keyring.rename_use(&loaded.name, &existing.name, &name);
                self.recent = keyring.recent();
            }
        } else {
            let kind = form.kind;
            self.modify(vault, |opened| {
                opened.add(NewEntry {
                    name: collected.name,
                    kind,
                    plain: collected.plain,
                    secrets: collected.secrets,
                    tags: collected.tags,
                    favourite: false,
                })
            })?;
        }
        Ok((vault, name))
    }

    /// Selects an entry just saved, moving to every entry if the section on
    /// screen does not hold it.
    fn show_entry(&mut self, vault: usize, name: &str) {
        self.search.clear();
        if !self
            .items()
            .iter()
            .any(|item| item.vault == vault && item.entry == name)
        {
            self.section = Section::All;
        }
        self.field_index = 0;
        self.revealed = None;
        self.reselect(vault, name);
    }

    fn create_vault(&mut self, name: &str) -> Result<(), String> {
        check_vault_name(name).map_err(|error| error.to_string())?;
        let keyring = self.keyring.as_ref().ok_or("the vault is locked")?;
        keyring
            .create_vault(name, &[])
            .map_err(|error| format!("{error:#}"))?;
        self.load_vaults();
        if let Some(index) = self.vaults.iter().position(|vault| vault.name == name) {
            self.set_section(Section::Vault(index));
        }
        self.status = format!("created the vault {name}");
        Ok(())
    }

    fn trust(&mut self, index: usize, inspection: Inspection) {
        let Some(keyring) = self.keyring.as_ref() else {
            return;
        };
        match keyring.trust_vault(inspection) {
            Ok(opened) => {
                if let Some(loaded) = self.vaults.get_mut(index) {
                    self.status = format!("trusted the vault {}", loaded.name);
                    loaded.opened = Some(opened);
                    loaded.problem = None;
                    loaded.untrusted = false;
                }
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

/// Creates the identity and, unless there already is one, the personal vault.
fn create_identity(home: &Home, passphrase: &SecretString) -> anyhow::Result<Keyring> {
    let keyring = Keyring::create(home, passphrase)?;
    if !home.vault_names()?.iter().any(|name| name == DEFAULT_VAULT) {
        keyring.create_vault(DEFAULT_VAULT, &[])?;
    }
    Ok(keyring)
}

/// Whether an entry answers the search: its name, kind, vault, tags or any
/// plain value.
fn matches_search(entry: &Entry, vault: &str, needle: &str) -> bool {
    entry.name.to_lowercase().contains(needle)
        || entry.kind.label().to_lowercase().contains(needle)
        || vault.contains(needle)
        || entry.tags.iter().any(|tag| tag.contains(needle))
        || entry.fields.iter().any(|field| {
            entry
                .plain(&field.name)
                .is_some_and(|value| value.to_lowercase().contains(needle))
        })
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

    /// Lets background work finish, as the event loop would.
    pub fn settle(screen: &mut VaultScreen) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while screen.busy().is_some() {
            assert!(Instant::now() < deadline, "the unlock never finished");
            std::thread::sleep(Duration::from_millis(5));
            screen.tick(Instant::now());
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
        settle(&mut screen);
        assert!(screen.is_unlocked(), "{:?}", screen.status);
        (scratch, screen)
    }

    /// Adds a login through the kind picker and the form, the way a person
    /// would.
    pub fn add_login(screen: &mut VaultScreen, name: &str, username: &str, password: &str) {
        press(screen, KeyCode::Char('a'));
        press(screen, KeyCode::Enter); // Login is first
        type_text(screen, name);
        press(screen, KeyCode::Tab);
        type_text(screen, username);
        press(screen, KeyCode::Tab);
        type_text(screen, password);
        press_ctrl(screen, KeyCode::Char('s'));
        assert!(screen.dialog.is_none(), "{:?}", screen.status);
    }

    fn fresh_keyring(scratch: &Scratch) -> Keyring {
        Keyring::unlock(
            &Home::at(&scratch.0),
            &SecretString::from(PASSPHRASE.to_string()),
        )
        .unwrap()
    }

    #[test]
    fn unlocking_runs_in_the_background_and_a_wrong_passphrase_keeps_it_locked() {
        let (_scratch, mut screen) = locked("tui-wrong");
        screen.enter();
        assert!(matches!(screen.dialog, Some(Dialog::Unlock { .. })));

        type_text(&mut screen, "not the passphrase");
        press(&mut screen, KeyCode::Enter);
        assert!(
            screen.busy().is_some(),
            "the check should run in the background"
        );
        // Keys wait while it works.
        press(&mut screen, KeyCode::Char('x'));
        assert!(screen.status.contains("one moment"));

        settle(&mut screen);
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
        assert!(
            screen.busy().is_none(),
            "nothing starts with a short passphrase"
        );
        assert!(!screen.has_identity());
    }

    #[test]
    fn a_login_added_through_the_picker_and_form_is_saved_sealed() {
        let (scratch, mut screen) = unlocked("tui-add");
        add_login(&mut screen, "GitHub", "octocat", "hunter2");
        assert_eq!(screen.selected().unwrap().1.name, "GitHub");

        let keyring = fresh_keyring(&scratch);
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
    fn a_card_is_added_with_its_own_fields() {
        let (scratch, mut screen) = unlocked("tui-card");
        press(&mut screen, KeyCode::Char('a'));
        type_text(&mut screen, "p"); // Payment card
        press(&mut screen, KeyCode::Enter);
        type_text(&mut screen, "Visa");
        press(&mut screen, KeyCode::Tab);
        type_text(&mut screen, "A N Other");
        press(&mut screen, KeyCode::Tab);
        type_text(&mut screen, "4111111111111111");
        press(&mut screen, KeyCode::Tab);
        type_text(&mut screen, "12/30");
        press(&mut screen, KeyCode::Tab);
        type_text(&mut screen, "123");
        press_ctrl(&mut screen, KeyCode::Char('s'));
        assert!(screen.dialog.is_none(), "{:?}", screen.status);

        let keyring = fresh_keyring(&scratch);
        let opened = keyring.open(DEFAULT_VAULT).unwrap();
        let card = opened.entry("Visa").unwrap();
        assert_eq!(card.kind, Kind::Card);
        assert_eq!(card.plain("expiry"), Some("12/30"));
        assert!(card.field("cvv").unwrap().is_sealed());
        assert!(card.field("pin").is_none(), "an empty PIN is left out");
    }

    #[test]
    fn copying_hands_one_secret_to_the_event_loop_and_counts_as_a_use() {
        let (_scratch, mut screen) = unlocked("tui-copy");
        add_login(&mut screen, "first", "one", "p1");
        add_login(&mut screen, "second", "two", "p2");

        screen.set_section(Section::All);
        screen.move_item(0);
        press(&mut screen, KeyCode::Char('c'));
        let (secret, label) = screen.pending_copy.take().expect("a copy was queued");
        assert_eq!(secret.expose_secret(), "p1");
        assert_eq!(label, "password of first");

        press(&mut screen, KeyCode::Char('u'));
        let (secret, _) = screen.pending_copy.take().unwrap();
        assert_eq!(secret.expose_secret(), "one");

        press(&mut screen, KeyCode::Char('2'));
        assert_eq!(screen.section, Section::Recent);
        let items = screen.items();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].entry, "first");
    }

    #[test]
    fn favourites_are_starred_listed_and_opened_first_next_time() {
        let (scratch, mut screen) = unlocked("tui-favourite");
        add_login(&mut screen, "bank", "me", "p");
        add_login(&mut screen, "mail", "me", "p");

        screen.set_section(Section::All);
        screen.move_item(1); // mail
        press(&mut screen, KeyCode::Char('f'));
        assert!(screen.status.contains("starred mail"), "{}", screen.status);
        press(&mut screen, KeyCode::Char('1'));
        let favourites = screen.items();
        assert_eq!(favourites.len(), 1);
        assert_eq!(favourites[0].entry, "mail");

        // The star is saved in the vault, and the next unlock starts there.
        drop(screen);
        let mut again = VaultScreen::new(Ok(Home::at(&scratch.0)));
        again.enter();
        type_text(&mut again, PASSPHRASE);
        press(&mut again, KeyCode::Enter);
        settle(&mut again);
        assert_eq!(again.section, Section::Favourites);
    }

    #[test]
    fn a_revealed_secret_hides_itself_again() {
        let (_scratch, mut screen) = unlocked("tui-reveal");
        add_login(&mut screen, "site", "me", "hunter2");

        press(&mut screen, KeyCode::Char('r'));
        let (vault, entry) = screen.selected().map(|(v, e)| (v, e.name.clone())).unwrap();
        assert_eq!(
            screen
                .shown_secret(vault, &entry, "password")
                .unwrap()
                .expose_secret(),
            "hunter2"
        );
        screen.tick(Instant::now() + REVEAL_FOR);
        assert!(screen.shown_secret(vault, &entry, "password").is_none());

        // Pressing r again hides it at once.
        press(&mut screen, KeyCode::Char('r'));
        press(&mut screen, KeyCode::Char('r'));
        assert!(screen.shown_secret(vault, &entry, "password").is_none());
    }

    #[test]
    fn a_note_is_written_in_an_editor_and_opened_to_read() {
        let (_scratch, mut screen) = unlocked("tui-note");
        press(&mut screen, KeyCode::Char('a'));
        type_text(&mut screen, "s"); // Secure note
        press(&mut screen, KeyCode::Enter);
        type_text(&mut screen, "recovery codes");
        press(&mut screen, KeyCode::Tab);
        type_text(&mut screen, "1111");
        press(&mut screen, KeyCode::Enter);
        type_text(&mut screen, "2222");
        press_ctrl(&mut screen, KeyCode::Char('s'));
        assert!(screen.dialog.is_none(), "{:?}", screen.status);

        press(&mut screen, KeyCode::Enter); // on a note, Enter copies the text
        let (copied, _) = screen.pending_copy.take().unwrap();
        assert_eq!(copied.expose_secret(), "1111\n2222");

        press(&mut screen, KeyCode::Char('r'));
        let Some(Dialog::Note(view)) = &screen.dialog else {
            panic!("the note did not open");
        };
        assert_eq!(view.text.expose_secret(), "1111\n2222");

        // e from the note edits it, with the text already in the editor.
        press(&mut screen, KeyCode::Char('e'));
        assert!(matches!(screen.dialog, Some(Dialog::Entry(_))));
    }

    #[test]
    fn editing_keeps_the_secret_unless_a_new_one_is_typed() {
        let (_scratch, mut screen) = unlocked("tui-edit");
        add_login(&mut screen, "site", "old", "keep-me");

        press(&mut screen, KeyCode::Char('e'));
        press(&mut screen, KeyCode::Tab); // username
        press_ctrl(&mut screen, KeyCode::Char('u'));
        type_text(&mut screen, "new");
        press_ctrl(&mut screen, KeyCode::Char('s'));
        assert!(screen.dialog.is_none(), "{:?}", screen.status);

        assert_eq!(screen.selected().unwrap().1.plain("username"), Some("new"));
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
        assert_eq!(screen.count(Section::All), 1);

        press(&mut screen, KeyCode::Char('d'));
        press(&mut screen, KeyCode::Char('y'));
        assert_eq!(screen.count(Section::All), 0, "{}", screen.status);
    }

    #[test]
    fn searching_narrows_the_list_by_any_plain_value() {
        let (_scratch, mut screen) = unlocked("tui-search");
        add_login(&mut screen, "GitHub", "octocat", "1");
        add_login(&mut screen, "Mail", "me", "2");
        screen.set_section(Section::All);

        press(&mut screen, KeyCode::Char('/'));
        type_text(&mut screen, "octo");
        assert_eq!(screen.items().len(), 1);
        assert_eq!(screen.selected().unwrap().1.name, "GitHub");
        press(&mut screen, KeyCode::Esc);
        assert_eq!(screen.items().len(), 2);
    }

    #[test]
    fn the_sidebar_offers_the_kinds_in_use_and_moves_between_sections() {
        let (_scratch, mut screen) = unlocked("tui-sidebar");
        add_login(&mut screen, "site", "u", "p");
        let rows = screen.sidebar();
        assert!(rows.contains(&SidebarRow::Section(Section::Kind(Kind::Login))));
        assert!(!rows.contains(&SidebarRow::Section(Section::Kind(Kind::Card))));

        screen.pane = Pane::Sidebar;
        screen.set_section(Section::Favourites);
        press(&mut screen, KeyCode::Down);
        assert_eq!(screen.section, Section::Recent);
        press(&mut screen, KeyCode::Down);
        press(&mut screen, KeyCode::Down); // past the heading
        assert_eq!(screen.section, Section::Kind(Kind::Login));
    }

    #[test]
    fn locking_forgets_the_key_the_vaults_and_anything_pending() {
        let (_scratch, mut screen) = unlocked("tui-lock");
        add_login(&mut screen, "site", "u", "p");
        press(&mut screen, KeyCode::Char('c'));
        assert!(screen.pending_copy.is_some());

        press_ctrl(&mut screen, KeyCode::Char('l'));
        assert!(!screen.is_unlocked());
        assert!(screen.vaults().is_empty());
        assert!(screen.pending_copy.is_none());
        assert!(screen.items().is_empty());
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
        settle(&mut screen);

        screen.set_section(Section::Vault(0));
        let (_, vault) = screen.problem().expect("the vault did not open");
        assert!(vault.untrusted);
        assert_eq!(
            screen.command_hint().as_deref(),
            Some("txc vault trust personal")
        );

        press(&mut screen, KeyCode::Char('t'));
        assert!(matches!(screen.dialog, Some(Dialog::Trust(_))));
        press(&mut screen, KeyCode::Char('y'));
        assert!(screen.problem().is_none(), "{}", screen.status);
    }

    #[test]
    fn a_new_vault_can_be_created_and_is_shown() {
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
        let Section::Vault(index) = screen.section else {
            panic!("the new vault is not shown");
        };
        assert_eq!(screen.vaults()[index].name, "work");
    }

    #[test]
    fn with_two_vaults_the_form_asks_which_one() {
        let (scratch, mut screen) = unlocked("tui-two-vaults");
        press(&mut screen, KeyCode::Char('n'));
        type_text(&mut screen, "work");
        press(&mut screen, KeyCode::Enter);

        press(&mut screen, KeyCode::Char('a'));
        press(&mut screen, KeyCode::Enter);
        let Some(Dialog::Entry(form)) = &screen.dialog else {
            panic!("no form");
        };
        assert!(form.rows().contains(&form::Row::Vault));
        assert_eq!(
            form.vault_name(),
            "work",
            "the vault on screen is offered first"
        );
        type_text(&mut screen, "vpn");
        press(&mut screen, KeyCode::Tab); // vault
        press(&mut screen, KeyCode::Left); // personal
        press(&mut screen, KeyCode::Tab);
        press(&mut screen, KeyCode::Tab);
        type_text(&mut screen, "secret");
        press_ctrl(&mut screen, KeyCode::Char('s'));
        assert!(screen.dialog.is_none(), "{:?}", screen.status);

        let keyring = fresh_keyring(&scratch);
        assert!(keyring.open(DEFAULT_VAULT).unwrap().entry("vpn").is_ok());
    }

    #[test]
    fn the_command_hint_follows_the_selection() {
        let (_scratch, mut screen) = unlocked("tui-hint");
        assert_eq!(
            screen.command_hint().as_deref(),
            Some("txc vault add <name> --generate")
        );
        add_login(&mut screen, "My Bank", "me", "p");
        assert_eq!(
            screen.command_hint().as_deref(),
            Some("txc vault copy 'personal/My Bank'")
        );
        screen.pane = Pane::Details;
        screen.field_index = 0; // username comes first
        assert_eq!(
            screen.command_hint().as_deref(),
            Some("txc vault copy 'personal/My Bank' --field username")
        );
    }

    #[test]
    fn a_passphrase_can_be_pasted() {
        let (_scratch, mut screen) = locked("tui-paste");
        screen.enter();
        screen.handle_paste(PASSPHRASE);
        press(&mut screen, KeyCode::Enter);
        settle(&mut screen);
        assert!(screen.is_unlocked(), "{}", screen.status);
    }
}
