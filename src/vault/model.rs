//! What a vault holds, and the rules its names and values follow.
//!
//! Everything here is checked when a vault is opened as well as when it is
//! changed. Text that reaches the terminal from a vault therefore never
//! carries an escape sequence, or an invisible character that disguises what a
//! name really says.

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

/// The vault a reference means when it does not name one.
pub const DEFAULT_VAULT: &str = "personal";

/// The longest entry name, in characters.
pub const MAX_ENTRY_NAME: usize = 128;

/// The longest value stored without its own encryption, in characters.
pub const MAX_PLAIN_VALUE: usize = 2048;

/// The largest secret, in bytes: room for a private key or a page of notes.
pub const MAX_SECRET_BYTES: usize = 64 * 1024;

/// The most entries a vault may hold.
pub const MAX_ENTRIES: usize = 10_000;

/// The most fields an entry may hold.
pub const MAX_FIELDS: usize = 32;

/// The most tags an entry may carry.
pub const MAX_TAGS: usize = 16;

/// The longest sealed value, in base64 characters: the largest secret plus
/// the age header and tag, encoded.
pub(crate) const MAX_SEALED_CHARS: usize = (MAX_SECRET_BYTES + 1024) * 4 / 3 + 4;

/// What an entry is for, which decides the field `copy` takes by default.
///
/// ```
/// use txc::vault::model::Kind;
///
/// assert_eq!(Kind::from_id("api-key"), Some(Kind::ApiKey));
/// assert_eq!(Kind::Login.primary(), "password");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A username and password for a site or a service.
    Login,
    /// A key or token for an API.
    ApiKey,
    /// Any single secret value.
    Secret,
    /// Free text that should stay private.
    Note,
}

impl Kind {
    /// Every kind, in the order they are offered.
    pub const ALL: [Self; 4] = [Self::Login, Self::ApiKey, Self::Secret, Self::Note];

    /// The name used on the command line.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::ApiKey => "api-key",
            Self::Secret => "secret",
            Self::Note => "note",
        }
    }

    /// Looks a kind up by the name used on the command line.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.id() == id)
    }

    /// The field holding the entry's main secret, which is what `copy` takes
    /// unless asked for another.
    #[must_use]
    pub const fn primary(self) -> &'static str {
        match self {
            Self::Login => "password",
            Self::ApiKey => "key",
            Self::Secret => "value",
            Self::Note => "text",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

/// A field's value, either stored as it is or sealed on its own.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum Value {
    /// Kept inside the vault's own encryption, and shown when the entry is:
    /// usernames and addresses.
    Plain(String),
    /// Encrypted a second time, on its own, as base64 age ciphertext. It is
    /// decrypted only at the moment it is copied, so browsing a vault never
    /// puts the secrets themselves in memory.
    Sealed(String),
}

/// One named value of an entry.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    /// The field's name, such as `username` or `password`.
    pub name: String,
    /// What it holds.
    pub value: Value,
}

impl Field {
    /// Whether the value is sealed rather than plain.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        matches!(self.value, Value::Sealed(_))
    }
}

/// One login, key, secret or note.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The entry's name, unique within its vault regardless of case.
    pub name: String,
    /// What the entry is for.
    pub kind: Kind,
    /// The values, plain and sealed, in the order they were added.
    pub fields: Vec<Field>,
    /// Labels for finding entries.
    #[serde(default)]
    pub tags: Vec<String>,
    /// When the entry was added, as RFC 3339.
    pub created: String,
    /// When the entry last changed, as RFC 3339.
    pub updated: String,
}

impl Entry {
    /// The field with this name.
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.name == name)
    }

    /// The value of a plain field, if the entry has one by that name.
    #[must_use]
    pub fn plain(&self, name: &str) -> Option<&str> {
        match self.field(name).map(|field| &field.value) {
            Some(Value::Plain(value)) => Some(value),
            _ => None,
        }
    }

    /// Checks every name and value against the rules in this module.
    ///
    /// # Errors
    ///
    /// Returns an error naming the first rule the entry breaks.
    pub fn validate(&self) -> Result<()> {
        check_entry_name(&self.name)?;
        ensure!(
            self.fields.len() <= MAX_FIELDS,
            "{:?} has more than {MAX_FIELDS} fields",
            self.name
        );
        let mut seen = HashSet::new();
        for field in &self.fields {
            check_field_name(&field.name)?;
            ensure!(
                seen.insert(field.name.as_str()),
                "{:?} has two fields named {:?}",
                self.name,
                field.name
            );
            match &field.value {
                Value::Plain(value) => check_plain_value(&field.name, value)?,
                Value::Sealed(sealed) => ensure!(
                    !sealed.is_empty()
                        && sealed.len() <= MAX_SEALED_CHARS
                        && sealed
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')),
                    "the sealed field {:?} of {:?} is damaged",
                    field.name,
                    self.name
                ),
            }
        }
        ensure!(
            self.tags.len() <= MAX_TAGS,
            "{:?} has more than {MAX_TAGS} tags",
            self.name
        );
        for tag in &self.tags {
            check_tag(tag)?;
        }
        check_plain_value("created", &self.created)?;
        check_plain_value("updated", &self.updated)?;
        Ok(())
    }
}

/// Where an entry lives: `vault/entry`, or a bare `entry` in the default
/// vault.
///
/// Entry names cannot contain `/`, so a reference always splits one way.
///
/// ```
/// use txc::vault::model::Reference;
///
/// let reference: Reference = "work/github".parse()?;
/// assert_eq!((reference.vault.as_str(), reference.entry.as_str()), ("work", "github"));
///
/// let bare: Reference = "email".parse()?;
/// assert_eq!(bare.to_string(), "personal/email");
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reference {
    /// The vault's name.
    pub vault: String,
    /// The entry's name within it.
    pub entry: String,
}

impl FromStr for Reference {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let (vault, entry) = text.split_once('/').unwrap_or((DEFAULT_VAULT, text));
        check_vault_name(vault)?;
        check_entry_name(entry)?;
        Ok(Self {
            vault: vault.to_string(),
            entry: entry.to_string(),
        })
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.vault, self.entry)
    }
}

/// Whether a name is 1 to 32 lowercase letters, digits, `-` or `_`, starting
/// with a letter or a digit.
fn is_slug(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase() | bytes[0].is_ascii_digit()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

/// Checks a vault name, which also becomes a file name.
///
/// # Errors
///
/// Returns an error unless the name is 1 to 32 lowercase letters, digits,
/// `-` or `_`, starting with a letter or digit. Nothing else can reach the
/// file system, so no name can climb out of the vault directory.
///
/// ```
/// use txc::vault::model::check_vault_name;
///
/// assert!(check_vault_name("work").is_ok());
/// assert!(check_vault_name("../etc").is_err());
/// ```
pub fn check_vault_name(name: &str) -> Result<()> {
    ensure!(
        is_slug(name),
        "vault names are 1 to 32 lowercase letters, digits, - or _, starting with a letter or a digit, not {name:?}"
    );
    Ok(())
}

/// Checks a field name.
///
/// # Errors
///
/// Returns an error unless the name follows the same rule as a vault name.
pub fn check_field_name(name: &str) -> Result<()> {
    ensure!(
        is_slug(name),
        "field names are 1 to 32 lowercase letters, digits, - or _, starting with a letter or a digit, not {name:?}"
    );
    Ok(())
}

/// Checks a tag.
///
/// # Errors
///
/// Returns an error unless the tag follows the same rule as a vault name.
pub fn check_tag(tag: &str) -> Result<()> {
    ensure!(
        is_slug(tag),
        "tags are 1 to 32 lowercase letters, digits, - or _, starting with a letter or a digit, not {tag:?}"
    );
    Ok(())
}

/// Checks an entry name.
///
/// # Errors
///
/// Returns an error when the name is empty or too long, contains `/`, starts
/// or ends with a space, or contains a character that is invisible or that a
/// terminal would act on.
///
/// ```
/// use txc::vault::model::check_entry_name;
///
/// assert!(check_entry_name("GitHub (work)").is_ok());
/// // A right-to-left override would make the name read differently on screen.
/// assert!(check_entry_name("bank\u{202e}lanigiro").is_err());
/// ```
pub fn check_entry_name(name: &str) -> Result<()> {
    let count = name.chars().count();
    ensure!(
        (1..=MAX_ENTRY_NAME).contains(&count),
        "entry names are 1 to {MAX_ENTRY_NAME} characters"
    );
    ensure!(
        !name.contains('/'),
        "entry names cannot contain /, which separates the vault from the entry: {name:?}"
    );
    ensure!(
        name.trim() == name,
        "entry names cannot start or end with a space: {name:?}"
    );
    ensure!(
        !name.chars().any(is_unsafe_char),
        "entry names cannot contain control or invisible characters: {name:?}"
    );
    Ok(())
}

/// Checks a value stored in the clear, such as a username or an address.
///
/// # Errors
///
/// Returns an error when the value is too long, or contains a control or
/// invisible character.
pub fn check_plain_value(label: &str, value: &str) -> Result<()> {
    ensure!(
        value.chars().count() <= MAX_PLAIN_VALUE,
        "{label} is longer than {MAX_PLAIN_VALUE} characters"
    );
    ensure!(
        !value.chars().any(is_unsafe_char),
        "{label} cannot contain control or invisible characters; store it as a secret field instead"
    );
    Ok(())
}

/// Whether a character must never be shown from a vault: control characters,
/// which a terminal acts on, and the formatting characters that are invisible
/// or reorder the text around them.
///
/// ```
/// use txc::vault::model::is_unsafe_char;
///
/// assert!(is_unsafe_char('\x1b'));
/// assert!(is_unsafe_char('\u{200b}'));
/// assert!(!is_unsafe_char('é'));
/// ```
#[must_use]
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            name: "github".to_string(),
            kind: Kind::Login,
            fields: vec![
                Field {
                    name: "username".to_string(),
                    value: Value::Plain("octocat".to_string()),
                },
                Field {
                    name: "password".to_string(),
                    value: Value::Sealed("YWdl".to_string()),
                },
            ],
            tags: vec!["dev".to_string()],
            created: "2026-01-01T00:00:00Z".to_string(),
            updated: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn a_well_formed_entry_passes() {
        entry().validate().unwrap();
    }

    #[test]
    fn names_that_could_reach_outside_the_vault_directory_are_refused() {
        for name in ["", "..", "../x", "a/b", "A", "-lead", "with space", "x\0"] {
            assert!(check_vault_name(name).is_err(), "{name:?} was accepted");
        }
        assert!(check_vault_name(&"a".repeat(33)).is_err());
        assert!(check_vault_name(&"a".repeat(32)).is_ok());
    }

    #[test]
    fn terminal_escapes_cannot_hide_in_names_or_values() {
        assert!(check_entry_name("evil\x1b]52;c;x\x07").is_err());
        assert!(check_plain_value("username", "a\nb").is_err());
        assert!(check_plain_value("username", "zero\u{200b}width").is_err());

        let mut bad = entry();
        bad.fields[0].value = Value::Plain("\x1b[2J".to_string());
        assert!(bad.validate().is_err());
    }

    #[test]
    fn duplicate_fields_and_damaged_seals_are_refused() {
        let mut twice = entry();
        twice.fields[1].name = "username".to_string();
        assert!(twice.validate().is_err());

        let mut damaged = entry();
        damaged.fields[1].value = Value::Sealed("not base64!".to_string());
        assert!(damaged.validate().is_err());
    }

    #[test]
    fn references_split_at_the_first_slash_only() {
        let reference: Reference = "work/aws".parse().unwrap();
        assert_eq!(reference.vault, "work");
        assert_eq!(reference.entry, "aws");
        // The entry cannot contain a slash, so there is no second reading.
        assert!("work/aws/prod".parse::<Reference>().is_err());
        assert_eq!("mail".parse::<Reference>().unwrap().vault, DEFAULT_VAULT);
    }

    #[test]
    fn the_serialised_form_rejects_unknown_fields() {
        let json = r#"{"name":"x","kind":"login","fields":[],"created":"","updated":"","extra":1}"#;
        assert!(serde_json::from_str::<Entry>(json).is_err());
    }
}
