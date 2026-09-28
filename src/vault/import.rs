//! Reading other password managers' exports into entries.
//!
//! Three shapes cover the common tools:
//!
//! - **Bitwarden JSON** (an unencrypted export): logins, cards, secure notes
//!   and custom fields, with folders as tags.
//! - **Password CSV**, the lingua franca: `1Password`, `KeePassXC`, Bitwarden,
//!   `LastPass`, Chrome and Firefox all export columns for a title, a website,
//!   a username, a password and notes, under slightly different headings,
//!   which are matched by name.
//! - **`.env` files**: each `NAME=value` becomes a secret named `NAME`.
//!
//! Nothing here touches a vault: the caller shows a summary, then adds the
//! entries. Hidden values are kept as secrets; names are cleaned to what the
//! vault accepts, and duplicates are numbered.

use std::collections::BTreeMap;

use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use serde_json::Value as Json;

use crate::vault::model::{Kind, MAX_ENTRY_NAME, check_tag, is_unsafe_char};

/// One entry read from an export, not yet in a vault.
pub struct Imported {
    /// Its name, already cleaned for the vault.
    pub name: String,
    /// Its kind.
    pub kind: Kind,
    /// Plain fields.
    pub plain: Vec<(String, String)>,
    /// Sealed fields; the kind's primary field is always among them.
    pub secrets: Vec<(String, SecretString)>,
    /// Tags, from folders or groups.
    pub tags: Vec<String>,
    /// Whether it was starred in the source.
    pub favourite: bool,
}

/// What was read, and what could not be.
#[derive(Default)]
pub struct Batch {
    /// The entries to add.
    pub entries: Vec<Imported>,
    /// Why some items were left out, with how many of each.
    pub skipped: BTreeMap<&'static str, usize>,
}

impl Batch {
    fn skip(&mut self, reason: &'static str) {
        let count = self.skipped.entry(reason).or_insert(0);
        *count = count.saturating_add(1);
    }
}

/// The formats understood.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// A Bitwarden JSON export.
    Bitwarden,
    /// A CSV with a header row.
    Csv,
    /// A `.env` file.
    Env,
}

impl Format {
    /// Parses a format name as given to `--format`.
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "bitwarden" => Some(Self::Bitwarden),
            "csv" => Some(Self::Csv),
            "env" => Some(Self::Env),
            _ => None,
        }
    }

    /// Guesses the format from the file name and its first bytes.
    #[must_use]
    pub fn detect(path: &str, text: &str) -> Self {
        let file = std::path::Path::new(path);
        let extension = file
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_lowercase);
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_lowercase();
        if extension.as_deref() == Some("json") || text.trim_start().starts_with('{') {
            Self::Bitwarden
        } else if extension.as_deref() == Some("env") || name == ".env" || name.starts_with(".env.")
        {
            Self::Env
        } else {
            Self::Csv
        }
    }
}

/// Reads an export.
///
/// # Errors
///
/// Returns an error when the file is not in the format named.
pub fn read(format: Format, text: &str) -> Result<Batch> {
    let mut batch = match format {
        Format::Bitwarden => bitwarden(text)?,
        Format::Csv => csv(text)?,
        Format::Env => env(text),
    };
    number_duplicates(&mut batch.entries);
    Ok(batch)
}

/// Makes a name the vault accepts: no `/`, no control or invisible
/// characters, no surrounding spaces, not too long.
#[must_use]
pub fn clean_name(raw: &str, fallback: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c == '/' { '-' } else { c })
        .filter(|c| !is_unsafe_char(*c))
        .collect();
    let cleaned: String = cleaned.trim().chars().take(MAX_ENTRY_NAME).collect();
    let cleaned = cleaned.trim().to_string();
    if cleaned.is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

/// Makes a tag or field name: lowercase letters, digits, `-` and `_`.
fn slug(raw: &str) -> Option<String> {
    let mut out = String::new();
    for c in raw.trim().to_lowercase().chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let out: String = out.trim_end_matches('-').chars().take(32).collect();
    check_tag(&out).ok().map(|()| out)
}

fn number_duplicates(entries: &mut [Imported]) {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for entry in entries.iter_mut() {
        let key = entry.name.to_lowercase();
        let count = seen.entry(key).or_insert(0);
        *count = count.saturating_add(1);
        if *count > 1 {
            let suffix = format!(" ({count})");
            let room = MAX_ENTRY_NAME.saturating_sub(suffix.chars().count());
            entry.name = format!(
                "{}{suffix}",
                entry.name.chars().take(room).collect::<String>()
            );
        }
    }
}

fn secret(text: &str) -> SecretString {
    SecretString::from(text.to_string())
}

fn string_at<'a>(item: &'a Json, path: &[&str]) -> Option<&'a str> {
    let mut value = item;
    for key in path {
        value = value.get(key)?;
    }
    value.as_str().filter(|text| !text.is_empty())
}

// ------------------------------------------------------------- Bitwarden --

fn bitwarden(text: &str) -> Result<Batch> {
    let root: Json = serde_json::from_str(text).context("not a JSON export")?;
    if root.get("encrypted").and_then(Json::as_bool) == Some(true) {
        bail!("this Bitwarden export is encrypted; export it again as unencrypted JSON");
    }
    let folders: BTreeMap<String, String> = root
        .get("folders")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
        .filter_map(|folder| {
            Some((
                string_at(folder, &["id"])?.to_string(),
                string_at(folder, &["name"])?.to_string(),
            ))
        })
        .collect();
    let items = root
        .get("items")
        .and_then(Json::as_array)
        .context("no items in this export")?;

    let mut batch = Batch::default();
    for (index, item) in (1_usize..).zip(items) {
        let name = clean_name(
            string_at(item, &["name"]).unwrap_or(""),
            &format!("imported {index}"),
        );
        let tags: Vec<String> = string_at(item, &["folderId"])
            .and_then(|id| folders.get(id))
            .and_then(|folder| slug(folder))
            .into_iter()
            .collect();
        let favourite = item
            .get("favorite")
            .and_then(Json::as_bool)
            .unwrap_or(false);
        let mut plain = Vec::new();
        let mut secrets = Vec::new();
        let notes = string_at(item, &["notes"]);

        let kind = match item.get("type").and_then(Json::as_u64) {
            Some(1) => {
                let Some(password) = string_at(item, &["login", "password"]) else {
                    batch.skip("logins without a password");
                    continue;
                };
                secrets.push(("password".to_string(), secret(password)));
                if let Some(username) = string_at(item, &["login", "username"]) {
                    plain.push(("username".to_string(), username.to_string()));
                }
                if let Some(url) = item
                    .pointer("/login/uris/0/uri")
                    .and_then(Json::as_str)
                    .filter(|url| !url.is_empty())
                {
                    plain.push(("url".to_string(), url.to_string()));
                }
                if let Some(totp) = string_at(item, &["login", "totp"]) {
                    secrets.push(("totp".to_string(), secret(totp)));
                }
                Kind::Login
            }
            Some(2) => {
                let Some(body) = notes else {
                    batch.skip("empty secure notes");
                    continue;
                };
                secrets.push(("text".to_string(), secret(body)));
                Kind::Note
            }
            Some(3) => {
                let Some(number) = string_at(item, &["card", "number"]) else {
                    batch.skip("cards without a number");
                    continue;
                };
                secrets.push(("number".to_string(), secret(number)));
                if let Some(holder) = string_at(item, &["card", "cardholderName"]) {
                    plain.push(("cardholder".to_string(), holder.to_string()));
                }
                if let (Some(month), Some(year)) = (
                    string_at(item, &["card", "expMonth"]),
                    string_at(item, &["card", "expYear"]),
                ) {
                    let year = year.get(year.len().saturating_sub(2)..).unwrap_or(year);
                    plain.push(("expiry".to_string(), format!("{month:0>2}/{year}")));
                }
                if let Some(code) = string_at(item, &["card", "code"]) {
                    secrets.push(("cvv".to_string(), secret(code)));
                }
                Kind::Card
            }
            _ => {
                batch.skip("identities and other item types");
                continue;
            }
        };
        if kind != Kind::Note
            && let Some(notes) = notes
        {
            secrets.push(("notes".to_string(), secret(notes)));
        }
        for field in item
            .get("fields")
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(label), Some(value)) = (
                string_at(field, &["name"]).and_then(slug),
                string_at(field, &["value"]),
            ) else {
                continue;
            };
            let taken = kind.spec(&label).is_some()
                || plain.iter().any(|(name, _)| *name == label)
                || secrets.iter().any(|(name, _)| *name == label);
            if taken {
                continue;
            }
            // Type 0 is text; hidden (1) and anything unknown stay secret.
            if field.get("type").and_then(Json::as_u64) == Some(0) {
                plain.push((label, value.to_string()));
            } else {
                secrets.push((label, secret(value)));
            }
        }
        batch.entries.push(Imported {
            name,
            kind,
            plain,
            secrets,
            tags,
            favourite,
        });
    }
    Ok(batch)
}

// ------------------------------------------------------------------- CSV --

/// The column headings each tool uses, lowercased.
const NAME_COLUMNS: &[&str] = &["title", "name"];
const URL_COLUMNS: &[&str] = &["url", "website", "login_uri", "location"];
const USERNAME_COLUMNS: &[&str] = &["username", "login_username", "user name", "user", "email"];
const PASSWORD_COLUMNS: &[&str] = &["password", "login_password"];
const NOTES_COLUMNS: &[&str] = &["notes", "note", "extra", "comments"];
const TOTP_COLUMNS: &[&str] = &["totp", "otpauth", "login_totp", "one-time password"];
const GROUP_COLUMNS: &[&str] = &["group", "folder", "grouping"];

fn csv(text: &str) -> Result<Batch> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .context("not a CSV file with a header row")?
        .iter()
        .map(|heading| heading.trim().to_lowercase())
        .collect();
    let column = |names: &[&str]| {
        headers
            .iter()
            .position(|heading| names.contains(&heading.as_str()))
    };
    let (name_at, url_at, user_at, password_at, notes_at, totp_at, group_at) = (
        column(NAME_COLUMNS),
        column(URL_COLUMNS),
        column(USERNAME_COLUMNS),
        column(PASSWORD_COLUMNS),
        column(NOTES_COLUMNS),
        column(TOTP_COLUMNS),
        column(GROUP_COLUMNS),
    );
    if password_at.is_none() && notes_at.is_none() {
        bail!(
            "this CSV has no password or notes column; its headings are: {}",
            headers.join(", ")
        );
    }

    let mut batch = Batch::default();
    for (index, record) in (1_usize..).zip(reader.records()) {
        let record = record.with_context(|| format!("row {index} is not valid CSV"))?;
        let cell = |at: Option<usize>| {
            at.and_then(|at| record.get(at))
                .map(str::trim)
                .filter(|cell| !cell.is_empty())
        };
        let url = cell(url_at);
        let fallback = url.map_or_else(
            || format!("imported {index}"),
            |url| host_of(url).to_string(),
        );
        let name = clean_name(cell(name_at).unwrap_or(""), &fallback);
        let tags: Vec<String> = cell(group_at).and_then(slug).into_iter().collect();
        let mut plain = Vec::new();
        let mut secrets = Vec::new();
        let kind = if let Some(password) = cell(password_at) {
            secrets.push(("password".to_string(), secret(password)));
            if let Some(user) = cell(user_at) {
                plain.push(("username".to_string(), user.to_string()));
            }
            if let Some(url) = url {
                plain.push(("url".to_string(), url.to_string()));
            }
            if let Some(totp) = cell(totp_at) {
                secrets.push(("totp".to_string(), secret(totp)));
            }
            if let Some(notes) = cell(notes_at) {
                secrets.push(("notes".to_string(), secret(notes)));
            }
            Kind::Login
        } else if let Some(notes) = cell(notes_at) {
            secrets.push(("text".to_string(), secret(notes)));
            Kind::Note
        } else {
            batch.skip("rows with neither a password nor notes");
            continue;
        };
        batch.entries.push(Imported {
            name,
            kind,
            plain,
            secrets,
            tags,
            favourite: false,
        });
    }
    Ok(batch)
}

fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    rest.split(['/', ':', '?', '#']).next().unwrap_or(rest)
}

// ------------------------------------------------------------------- env --

fn env(text: &str) -> Batch {
    let mut batch = Batch::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let Some((name, value)) = line.split_once('=') else {
            batch.skip("lines that are not NAME=value");
            continue;
        };
        let value = value.trim();
        let value = ['"', '\'']
            .iter()
            .find_map(|quote| {
                value
                    .strip_prefix(*quote)
                    .and_then(|inner| inner.strip_suffix(*quote))
            })
            .unwrap_or(value);
        if value.is_empty() {
            batch.skip("empty values");
            continue;
        }
        batch.entries.push(Imported {
            name: clean_name(name.trim(), "imported"),
            kind: Kind::Secret,
            plain: Vec::new(),
            secrets: vec![("value".to_string(), secret(value))],
            tags: vec!["env".to_string()],
            favourite: false,
        });
    }
    batch
}

#[cfg(test)]
mod tests {
    use age::secrecy::ExposeSecret;

    use super::*;

    fn secret_of<'a>(entry: &'a Imported, field: &str) -> &'a str {
        entry
            .secrets
            .iter()
            .find(|(name, _)| name == field)
            .map(|(_, value)| value.expose_secret())
            .unwrap()
    }

    #[test]
    fn a_bitwarden_export_becomes_logins_cards_and_notes() {
        let export = r#"{
          "encrypted": false,
          "folders": [{"id": "f1", "name": "Work Stuff"}],
          "items": [
            {"type": 1, "name": "GitHub", "folderId": "f1", "favorite": true, "notes": "2fa on",
             "login": {"username": "octocat", "password": "hunter2", "totp": "JBSWY3DP",
                       "uris": [{"uri": "https://github.com"}]},
             "fields": [{"name": "Recovery code", "value": "abc", "type": 1},
                        {"name": "Team", "value": "core", "type": 0}]},
            {"type": 3, "name": "Visa", "card": {"cardholderName": "A N Other", "number": "4111",
             "expMonth": "1", "expYear": "2030", "code": "123"}},
            {"type": 2, "name": "Wifi / home", "notes": "the note"},
            {"type": 4, "name": "Me"},
            {"type": 1, "name": "No password", "login": {"username": "x"}}
          ]
        }"#;
        let batch = read(Format::Bitwarden, export).unwrap();
        assert_eq!(batch.entries.len(), 3);
        let github = &batch.entries[0];
        assert_eq!(
            (github.kind, github.name.as_str(), github.favourite),
            (Kind::Login, "GitHub", true)
        );
        assert_eq!(github.tags, ["work-stuff"]);
        assert_eq!(secret_of(github, "password"), "hunter2");
        assert_eq!(secret_of(github, "totp"), "JBSWY3DP");
        assert_eq!(secret_of(github, "recovery-code"), "abc");
        assert_eq!(secret_of(github, "notes"), "2fa on");
        assert!(
            github
                .plain
                .contains(&("team".to_string(), "core".to_string()))
        );
        let visa = &batch.entries[1];
        assert!(
            visa.plain
                .contains(&("expiry".to_string(), "01/30".to_string()))
        );
        assert_eq!(secret_of(visa, "cvv"), "123");
        assert_eq!(batch.entries[2].name, "Wifi - home");
        assert_eq!(batch.skipped.values().sum::<usize>(), 2);
    }

    #[test]
    fn an_encrypted_bitwarden_export_is_refused() {
        assert!(read(Format::Bitwarden, r#"{"encrypted": true, "items": []}"#).is_err());
    }

    #[test]
    fn csv_columns_are_matched_by_their_heading() {
        // KeePassXC's headings, then Chrome's.
        let keepass = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\
                       \"Root/Mail\",\"Mail\",\"me\",\"pw1\",\"https://mail.example.com\",\"n\",\"\"\n";
        let batch = read(Format::Csv, keepass).unwrap();
        let mail = &batch.entries[0];
        assert_eq!(
            (mail.name.as_str(), secret_of(mail, "password")),
            ("Mail", "pw1")
        );
        assert_eq!(mail.tags, ["root-mail"]);

        let chrome = "name,url,username,password,note\n,https://shop.example.com/login,me,pw2,\n";
        let batch = read(Format::Csv, chrome).unwrap();
        assert_eq!(batch.entries[0].name, "shop.example.com");
    }

    #[test]
    fn duplicate_names_are_numbered() {
        let csv = "title,password\nSame,a\nsame,b\nSame,c\n";
        let names: Vec<String> = read(Format::Csv, csv)
            .unwrap()
            .entries
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["Same", "same (2)", "Same (3)"]);
    }

    #[test]
    fn an_env_file_becomes_secrets_named_after_its_variables() {
        let batch = read(
            Format::Env,
            "# c\nexport API_KEY=\"sk-1\"\nEMPTY=\nnot a line\n",
        )
        .unwrap();
        assert_eq!(batch.entries.len(), 1);
        assert_eq!(
            (
                batch.entries[0].name.as_str(),
                secret_of(&batch.entries[0], "value")
            ),
            ("API_KEY", "sk-1")
        );
        assert_eq!(batch.skipped.values().sum::<usize>(), 2);
    }

    #[test]
    fn names_are_cleaned_for_the_vault() {
        assert_eq!(clean_name("  a/b\u{202e}c  ", "x"), "a-bc");
        assert_eq!(clean_name("   ", "fallback"), "fallback");
        assert_eq!(
            clean_name(&"n".repeat(300), "x").chars().count(),
            MAX_ENTRY_NAME
        );
    }
}
