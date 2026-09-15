//! What a vault holds, and the rules its names and values follow.
//!
//! Every entry has a [`Kind`], and each kind has the fields that make sense
//! for it: a login has a username, a password and a website; a payment card
//! has a card number, an expiry and a security code. Each field says how it
//! is kept ([`Sensitivity`]), so a card number can never be stored in the
//! clear by mistake.
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

/// How a field is kept, and how the interface shows it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sensitivity {
    /// Kept inside the vault's encryption and shown with the entry: a
    /// username, a website, a card's expiry.
    Plain,
    /// Sealed on its own and always masked. It is copied, or revealed for a
    /// moment when asked: a password, a card number, a private key.
    Secret,
    /// Sealed on its own, and shown in full when it is opened: a note.
    Private,
}

impl Sensitivity {
    /// Whether values of this sensitivity are sealed on their own.
    ///
    /// ```
    /// use txc::vault::model::Sensitivity;
    ///
    /// assert!(Sensitivity::Secret.is_sealed());
    /// assert!(!Sensitivity::Plain.is_sealed());
    /// ```
    #[must_use]
    pub const fn is_sealed(self) -> bool {
        !matches!(self, Self::Plain)
    }
}

/// What can fill a field in for you.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Generator {
    /// A random password of letters, digits and symbols.
    Password,
    /// A random four digit PIN.
    Pin,
}

/// One field a kind of entry has.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FieldSpec {
    /// The name it is stored under, and given on the command line.
    pub name: &'static str,
    /// What the interface calls it.
    pub label: &'static str,
    /// How it is kept and shown.
    pub sensitivity: Sensitivity,
    /// Whether it may run over several lines.
    pub multiline: bool,
    /// What can fill it in, if anything.
    pub generator: Option<Generator>,
    /// An example of what goes in it, shown while it is empty.
    pub hint: &'static str,
}

impl FieldSpec {
    const fn plain(name: &'static str, label: &'static str) -> Self {
        Self {
            name,
            label,
            sensitivity: Sensitivity::Plain,
            multiline: false,
            generator: None,
            hint: "",
        }
    }

    const fn secret(name: &'static str, label: &'static str) -> Self {
        Self {
            sensitivity: Sensitivity::Secret,
            ..Self::plain(name, label)
        }
    }

    const fn password(name: &'static str, label: &'static str) -> Self {
        Self {
            generator: Some(Generator::Password),
            ..Self::secret(name, label)
        }
    }

    const fn pin(name: &'static str, label: &'static str) -> Self {
        Self {
            generator: Some(Generator::Pin),
            ..Self::secret(name, label)
        }
    }

    const fn private(name: &'static str, label: &'static str) -> Self {
        Self {
            sensitivity: Sensitivity::Private,
            multiline: true,
            ..Self::plain(name, label)
        }
    }

    const fn lines(self) -> Self {
        Self {
            multiline: true,
            ..self
        }
    }

    const fn hinted(self, hint: &'static str) -> Self {
        Self { hint, ..self }
    }
}

const NOTES: FieldSpec = FieldSpec::private("notes", "Notes");

static LOGIN: &[FieldSpec] = &[
    FieldSpec::plain("username", "Username"),
    FieldSpec::password("password", "Password"),
    FieldSpec::plain("url", "Website").hinted("https://example.com"),
    NOTES,
];

static CARD: &[FieldSpec] = &[
    FieldSpec::plain("cardholder", "Cardholder"),
    FieldSpec::secret("number", "Card number"),
    FieldSpec::plain("expiry", "Expiry").hinted("MM/YY"),
    FieldSpec::secret("cvv", "Security code"),
    FieldSpec::pin("pin", "PIN"),
    NOTES,
];

static NOTE: &[FieldSpec] = &[FieldSpec::private("text", "Note")];

static API_KEY: &[FieldSpec] = &[
    FieldSpec::secret("key", "Key"),
    FieldSpec::plain("url", "Service").hinted("https://api.example.com"),
    FieldSpec::plain("username", "Account"),
    FieldSpec::plain("expires", "Expires").hinted("2027-01-31"),
    NOTES,
];

static SSH_KEY: &[FieldSpec] = &[
    FieldSpec::secret("private-key", "Private key").lines(),
    FieldSpec::password("passphrase", "Passphrase"),
    FieldSpec::plain("host", "Host").hinted("server.example.com"),
    FieldSpec::plain("username", "Username"),
    FieldSpec::plain("public-key", "Public key").hinted("ssh-ed25519 AAAA…"),
    NOTES,
];

static DATABASE: &[FieldSpec] = &[
    FieldSpec::plain("host", "Host").hinted("db.example.com"),
    FieldSpec::plain("port", "Port").hinted("5432"),
    FieldSpec::plain("database", "Database"),
    FieldSpec::plain("username", "Username"),
    FieldSpec::password("password", "Password"),
    NOTES,
];

static SERVER: &[FieldSpec] = &[
    FieldSpec::plain("host", "Host").hinted("server.example.com"),
    FieldSpec::plain("username", "Username"),
    FieldSpec::password("password", "Password"),
    NOTES,
];

static WIFI: &[FieldSpec] = &[
    FieldSpec::plain("ssid", "Network name"),
    FieldSpec::password("password", "Password"),
    FieldSpec::plain("security", "Security").hinted("WPA2, WPA3"),
    NOTES,
];

static BANK: &[FieldSpec] = &[
    FieldSpec::plain("bank", "Bank"),
    FieldSpec::plain("holder", "Account holder"),
    FieldSpec::secret("account-number", "Account number"),
    FieldSpec::secret("iban", "IBAN"),
    FieldSpec::plain("swift", "SWIFT or BIC"),
    FieldSpec::pin("pin", "PIN"),
    NOTES,
];

static DOCUMENT: &[FieldSpec] = &[
    FieldSpec::plain("full-name", "Full name"),
    FieldSpec::secret("number", "Document number"),
    FieldSpec::plain("issued", "Issued").hinted("2020-05-01"),
    FieldSpec::plain("expires", "Expires").hinted("2030-05-01"),
    FieldSpec::plain("country", "Country"),
    NOTES,
];

static LICENCE: &[FieldSpec] = &[
    FieldSpec::plain("product", "Product"),
    FieldSpec::secret("key", "Licence key"),
    FieldSpec::plain("email", "Registered to"),
    NOTES,
];

static WALLET: &[FieldSpec] = &[
    FieldSpec::plain("address", "Address"),
    FieldSpec::secret("seed-phrase", "Recovery phrase").lines(),
    FieldSpec::password("password", "Wallet password"),
    NOTES,
];

static SECRET: &[FieldSpec] = &[FieldSpec::secret("value", "Secret").lines(), NOTES];

/// What an entry is, which decides the fields it has and the one `copy`
/// takes by default.
///
/// ```
/// use txc::vault::model::{Kind, Sensitivity};
///
/// assert_eq!(Kind::from_id("card"), Some(Kind::Card));
/// assert_eq!(Kind::Card.primary(), "number");
/// assert_eq!(Kind::Card.spec("cvv").unwrap().sensitivity, Sensitivity::Secret);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A username and password for a site or a service.
    Login,
    /// A credit or debit card.
    Card,
    /// Free text that should stay private.
    Note,
    /// A key or token for an API.
    ApiKey,
    /// An SSH private key and where it is used.
    SshKey,
    /// Credentials for a database.
    Database,
    /// Credentials for a server reached over SSH, FTP or similar.
    Server,
    /// A wireless network's password.
    Wifi,
    /// A bank account.
    Bank,
    /// A passport, identity card or driving licence.
    Document,
    /// A software licence key.
    Licence,
    /// A cryptocurrency wallet's recovery phrase.
    Wallet,
    /// Any other secret value.
    Secret,
}

impl Kind {
    /// Every kind, in the order they are offered.
    pub const ALL: [Self; 13] = [
        Self::Login,
        Self::Card,
        Self::Note,
        Self::ApiKey,
        Self::SshKey,
        Self::Database,
        Self::Server,
        Self::Wifi,
        Self::Bank,
        Self::Document,
        Self::Licence,
        Self::Wallet,
        Self::Secret,
    ];

    /// The name used on the command line and in the vault file.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Card => "card",
            Self::Note => "note",
            Self::ApiKey => "api-key",
            Self::SshKey => "ssh-key",
            Self::Database => "database",
            Self::Server => "server",
            Self::Wifi => "wifi",
            Self::Bank => "bank",
            Self::Document => "document",
            Self::Licence => "licence",
            Self::Wallet => "wallet",
            Self::Secret => "secret",
        }
    }

    /// Looks a kind up by its command line name. `license` is accepted for
    /// `licence`.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        if id == "license" {
            return Some(Self::Licence);
        }
        Self::ALL.into_iter().find(|kind| kind.id() == id)
    }

    /// What the interface calls one of this kind.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Login => "Login",
            Self::Card => "Payment card",
            Self::Note => "Secure note",
            Self::ApiKey => "API key",
            Self::SshKey => "SSH key",
            Self::Database => "Database",
            Self::Server => "Server",
            Self::Wifi => "Wi-Fi network",
            Self::Bank => "Bank account",
            Self::Document => "ID document",
            Self::Licence => "Software licence",
            Self::Wallet => "Crypto wallet",
            Self::Secret => "Other secret",
        }
    }

    /// What the interface calls several of this kind.
    #[must_use]
    pub const fn plural(self) -> &'static str {
        match self {
            Self::Login => "Logins",
            Self::Card => "Payment cards",
            Self::Note => "Secure notes",
            Self::ApiKey => "API keys",
            Self::SshKey => "SSH keys",
            Self::Database => "Databases",
            Self::Server => "Servers",
            Self::Wifi => "Wi-Fi networks",
            Self::Bank => "Bank accounts",
            Self::Document => "ID documents",
            Self::Licence => "Software licences",
            Self::Wallet => "Crypto wallets",
            Self::Secret => "Other secrets",
        }
    }

    /// One line on what the kind is for.
    #[must_use]
    pub const fn about(self) -> &'static str {
        match self {
            Self::Login => "a username and password for a website or app",
            Self::Card => "a credit or debit card",
            Self::Note => "private text, such as recovery codes",
            Self::ApiKey => "a key or token for a service's API",
            Self::SshKey => "an SSH private key and where it is used",
            Self::Database => "the credentials for a database",
            Self::Server => "the credentials for a server",
            Self::Wifi => "a wireless network's password",
            Self::Bank => "a bank account's numbers and PIN",
            Self::Document => "a passport, ID card or driving licence",
            Self::Licence => "a software licence key",
            Self::Wallet => "a crypto wallet's recovery phrase",
            Self::Secret => "any other secret value",
        }
    }

    /// The fields an entry of this kind has, in the order they are shown.
    #[must_use]
    pub const fn fields(self) -> &'static [FieldSpec] {
        match self {
            Self::Login => LOGIN,
            Self::Card => CARD,
            Self::Note => NOTE,
            Self::ApiKey => API_KEY,
            Self::SshKey => SSH_KEY,
            Self::Database => DATABASE,
            Self::Server => SERVER,
            Self::Wifi => WIFI,
            Self::Bank => BANK,
            Self::Document => DOCUMENT,
            Self::Licence => LICENCE,
            Self::Wallet => WALLET,
            Self::Secret => SECRET,
        }
    }

    /// The definition of one of this kind's fields.
    #[must_use]
    pub fn spec(self, name: &str) -> Option<&'static FieldSpec> {
        self.fields().iter().find(|spec| spec.name == name)
    }

    /// The field holding the entry's main secret, which is required, and is
    /// what `copy` takes unless asked for another.
    #[must_use]
    pub const fn primary(self) -> &'static str {
        match self {
            Self::Login | Self::Database | Self::Server | Self::Wifi => "password",
            Self::Card | Self::Document => "number",
            Self::Note => "text",
            Self::ApiKey | Self::Licence => "key",
            Self::SshKey => "private-key",
            Self::Bank => "account-number",
            Self::Wallet => "seed-phrase",
            Self::Secret => "value",
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
    /// decrypted only when it is copied, revealed or opened, so browsing a
    /// vault never puts the secrets themselves in memory.
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

/// One login, card, note, key or other secret.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// The entry's name, unique within its vault regardless of case.
    pub name: String,
    /// What the entry is.
    pub kind: Kind,
    /// The values, plain and sealed, in the kind's order and then any others
    /// in the order they were added.
    pub fields: Vec<Field>,
    /// Labels for finding entries.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether it is starred, to find it first. Kept in the vault, so it
    /// follows the entry to other devices.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub favourite: bool,
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

    /// How a field is kept: as its kind defines it, or, for a field the kind
    /// does not have, as it happens to be stored.
    #[must_use]
    pub fn sensitivity(&self, name: &str) -> Sensitivity {
        match (self.kind.spec(name), self.field(name)) {
            (Some(spec), _) => spec.sensitivity,
            (None, Some(field)) if field.is_sealed() => Sensitivity::Secret,
            _ => Sensitivity::Plain,
        }
    }

    /// What a field is called in the interface.
    #[must_use]
    pub fn label<'a>(&self, name: &'a str) -> &'a str {
        self.kind.spec(name).map_or(name, |spec| spec.label)
    }

    /// The plain value that best tells this entry apart in a list: its first
    /// plain field that has a value, such as the username of a login.
    #[must_use]
    pub fn summary(&self) -> Option<&str> {
        self.kind
            .fields()
            .iter()
            .filter(|spec| spec.sensitivity == Sensitivity::Plain)
            .find_map(|spec| self.plain(spec.name).filter(|value| !value.is_empty()))
    }

    /// Puts the fields in the kind's order, followed by any others in the
    /// order they were added.
    pub fn order_fields(&mut self) {
        let fields = self.kind.fields();
        self.fields.sort_by_key(|field| {
            fields
                .iter()
                .position(|spec| spec.name == field.name)
                .unwrap_or(fields.len())
        });
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

/// Makes decrypted text safe to draw: tabs become spaces, and every other
/// character that is unsafe to show becomes a visible replacement.
///
/// Notes and revealed secrets are not checked when they are saved, since any
/// text may be a secret, so this is applied whenever one reaches the screen.
///
/// ```
/// use txc::vault::model::displayable;
///
/// assert_eq!(displayable("a\tb\x1b[2J"), "a    b�[2J");
/// ```
#[must_use]
pub fn displayable(text: &str) -> String {
    let mut shown = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\t' => shown.push_str("    "),
            ch if is_unsafe_char(ch) => shown.push('\u{FFFD}'),
            ch => shown.push(ch),
        }
    }
    shown
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
            favourite: false,
            created: "2026-01-01T00:00:00Z".to_string(),
            updated: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn a_well_formed_entry_passes() {
        entry().validate().unwrap();
    }

    #[test]
    fn every_kind_has_a_sealed_primary_field_and_well_formed_fields() {
        for kind in Kind::ALL {
            let fields = kind.fields();
            let primary = kind
                .spec(kind.primary())
                .unwrap_or_else(|| panic!("{kind} has no {} field", kind.primary()));
            assert!(
                primary.sensitivity.is_sealed(),
                "the main field of {kind} is not sealed"
            );
            let mut names = HashSet::new();
            for spec in fields {
                check_field_name(spec.name).unwrap();
                assert!(names.insert(spec.name), "{kind} repeats {}", spec.name);
                assert!(
                    spec.generator.is_none() || spec.sensitivity == Sensitivity::Secret,
                    "{kind} generates a field that is not secret"
                );
            }
            assert_eq!(Kind::from_id(kind.id()), Some(kind));
            assert!(!kind.label().is_empty() && !kind.plural().is_empty());
        }
        assert_eq!(Kind::from_id("license"), Some(Kind::Licence));
    }

    #[test]
    fn the_kinds_written_before_there_were_more_still_read() {
        for (id, primary) in [
            ("login", "password"),
            ("api-key", "key"),
            ("secret", "value"),
            ("note", "text"),
        ] {
            let kind: Kind = serde_json::from_str(&format!("\"{id}\"")).unwrap();
            assert_eq!(kind.primary(), primary);
        }
    }

    #[test]
    fn favourite_is_left_out_when_false_and_read_as_false_when_missing() {
        let plain = serde_json::to_string(&entry()).unwrap();
        assert!(!plain.contains("favourite"), "{plain}");
        let read: Entry = serde_json::from_str(&plain).unwrap();
        assert!(!read.favourite);

        let mut starred = entry();
        starred.favourite = true;
        let text = serde_json::to_string(&starred).unwrap();
        assert!(serde_json::from_str::<Entry>(&text).unwrap().favourite);
    }

    #[test]
    fn fields_are_put_in_the_kinds_order_with_others_last() {
        let mut entry = entry();
        entry.fields.insert(
            0,
            Field {
                name: "extra".to_string(),
                value: Value::Plain("x".to_string()),
            },
        );
        entry.fields.push(Field {
            name: "url".to_string(),
            value: Value::Plain("https://github.com".to_string()),
        });
        entry.order_fields();
        let names: Vec<&str> = entry.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["username", "password", "url", "extra"]);
        assert_eq!(entry.summary(), Some("octocat"));
        assert_eq!(entry.label("url"), "Website");
        assert_eq!(entry.sensitivity("password"), Sensitivity::Secret);
        assert_eq!(entry.sensitivity("extra"), Sensitivity::Plain);
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
    fn decrypted_text_is_made_safe_to_draw() {
        let shown = displayable("line\x1b]52;c;aGk=\x07\u{202e}end");
        assert!(!shown.chars().any(is_unsafe_char), "{shown:?}");
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
