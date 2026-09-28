//! `.env.txc` templates: references to secrets, never the secrets.
//!
//! A project commits a file like this:
//!
//! ```text
//! # Everything here is safe to commit.
//! DATABASE_URL=txc://work/db
//! DATABASE_PASSWORD=txc://work/db/password
//! TLS_KEY=txc+file://work/tls/key
//! LOG_LEVEL=debug
//! ```
//!
//! `txc vault run -- cmd` resolves each reference and hands the value to `cmd`
//! alone: `txc://` in its environment, `txc+file://` as a file path it can
//! open. Lines without a reference pass through as ordinary settings.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, bail, ensure};

use crate::vault::model::{check_entry_name, check_field_name, check_vault_name};

/// How a value reaches the program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// In the program's environment.
    Environment,
    /// As a file path the program opens.
    File,
}

/// A reference to one secret: `txc://VAULT/ENTRY` for the entry's main
/// secret, `txc://VAULT/ENTRY/FIELD` for a named field. Segments may be
/// percent-encoded, for entry names with spaces or other characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRef {
    /// How it is delivered.
    pub delivery: Delivery,
    /// The vault.
    pub vault: String,
    /// The entry.
    pub entry: String,
    /// The field, or the entry's main secret when absent.
    pub field: Option<String>,
}

impl SecretRef {
    /// Whether a value is a reference at all.
    #[must_use]
    pub fn is_reference(value: &str) -> bool {
        value.starts_with("txc://") || value.starts_with("txc+file://")
    }
}

impl FromStr for SecretRef {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let (delivery, rest) = if let Some(rest) = text.strip_prefix("txc+file://") {
            (Delivery::File, rest)
        } else if let Some(rest) = text.strip_prefix("txc://") {
            (Delivery::Environment, rest)
        } else {
            bail!("{text:?} is not a reference; references start with txc:// or txc+file://");
        };
        let parts: Vec<String> = rest
            .split('/')
            .map(|part| urlencoding::decode(part).map(std::borrow::Cow::into_owned))
            .collect::<Result<_, _>>()
            .with_context(|| format!("{text:?} is not valid percent-encoding"))?;
        let (vault, entry, field) = match parts.as_slice() {
            [vault, entry] => (vault.clone(), entry.clone(), None),
            [vault, entry, field] => (vault.clone(), entry.clone(), Some(field.clone())),
            _ => bail!("{text:?} should be txc://VAULT/ENTRY or txc://VAULT/ENTRY/FIELD"),
        };
        check_vault_name(&vault)?;
        check_entry_name(&entry)?;
        if let Some(field) = &field {
            check_field_name(field)?;
        }
        Ok(Self {
            delivery,
            vault,
            entry,
            field,
        })
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self.delivery {
            Delivery::Environment => "txc",
            Delivery::File => "txc+file",
        };
        write!(
            f,
            "{scheme}://{}/{}",
            self.vault,
            urlencoding::encode(&self.entry)
        )?;
        if let Some(field) = &self.field {
            write!(f, "/{field}")?;
        }
        Ok(())
    }
}

/// One line of a template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// A secret to resolve.
    Secret(SecretRef),
    /// An ordinary setting, passed through as written.
    Plain(String),
}

/// A parsed template: variable names with their values, in file order.
pub type Template = Vec<(String, Value)>;

fn check_variable(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let first = chars.next().unwrap_or('0');
    ensure!(
        (first.is_ascii_alphabetic() || first == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "{name:?} is not a variable name: letters, digits and _, not starting with a digit"
    );
    Ok(())
}

fn unquote(value: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner;
        }
    }
    value
}

/// Parses a template. Blank lines and `#` comments are skipped, and an
/// `export ` prefix is accepted, so the file reads like any `.env` file.
///
/// # Errors
///
/// Returns an error naming the line of the first malformed entry.
pub fn parse(text: &str) -> Result<Template> {
    let mut template = Template::new();
    for (number, line) in (1_usize..).zip(text.lines()) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let (name, value) = line
            .split_once('=')
            .with_context(|| format!("line {number}: expected NAME=VALUE"))?;
        let name = name.trim();
        check_variable(name).with_context(|| format!("line {number}"))?;
        let value = unquote(value.trim());
        let value = if SecretRef::is_reference(value) {
            Value::Secret(value.parse().with_context(|| format!("line {number}"))?)
        } else {
            Value::Plain(value.to_string())
        };
        ensure!(
            !template.iter().any(|(existing, _)| existing == name),
            "line {number}: {name} is set twice"
        );
        template.push((name.to_string(), value));
    }
    Ok(template)
}

/// Parses `NAME=REFERENCE` from the command line. Only references are
/// accepted, so a secret can never arrive as an argument.
///
/// # Errors
///
/// Returns an error when the value is not a reference.
pub fn parse_setting(text: &str) -> Result<(String, SecretRef)> {
    let (name, value) = text
        .split_once('=')
        .context("--set takes NAME=txc://VAULT/ENTRY")?;
    check_variable(name)?;
    ensure!(
        SecretRef::is_reference(value),
        "--set takes only references (txc://VAULT/ENTRY), never a value, which would sit in \
         your shell history and the process list"
    );
    Ok((name.to_string(), value.parse()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_name_a_vault_an_entry_and_perhaps_a_field() {
        let reference: SecretRef = "txc://work/db".parse().unwrap();
        assert_eq!(
            (
                reference.delivery,
                reference.vault.as_str(),
                reference.entry.as_str(),
                reference.field
            ),
            (Delivery::Environment, "work", "db", None)
        );
        let reference: SecretRef = "txc+file://work/tls/key".parse().unwrap();
        assert_eq!(reference.delivery, Delivery::File);
        assert_eq!(reference.field.as_deref(), Some("key"));
        let reference: SecretRef = "txc://personal/GitHub%20(work)".parse().unwrap();
        assert_eq!(reference.entry, "GitHub (work)");
        assert_eq!(reference.to_string(), "txc://personal/GitHub%20%28work%29");
    }

    #[test]
    fn malformed_references_are_refused() {
        for bad in [
            "txc://work",
            "txc://a/b/c/d",
            "txc://Work/db",
            "txc://work/db/Bad Field",
            "http://x/y",
        ] {
            assert!(bad.parse::<SecretRef>().is_err(), "{bad}");
        }
    }

    #[test]
    fn a_template_reads_like_a_dotenv_file() {
        let template = parse(
            "# comment\n\nexport DATABASE_URL=txc://work/db\nLOG_LEVEL=\"debug\"\nKEY='txc+file://work/tls/key'\n",
        )
        .unwrap();
        assert_eq!(template.len(), 3);
        assert!(matches!(&template[0], (name, Value::Secret(_)) if name == "DATABASE_URL"));
        assert_eq!(
            template[1],
            ("LOG_LEVEL".to_string(), Value::Plain("debug".to_string()))
        );
        assert!(matches!(&template[2].1, Value::Secret(r) if r.delivery == Delivery::File));
    }

    #[test]
    fn bad_template_lines_name_their_line() {
        assert!(
            parse("OK=1\nnot a line\n")
                .unwrap_err()
                .to_string()
                .contains("line 2")
        );
        assert!(parse("1BAD=x\n").is_err());
        assert!(
            parse("A=1\nA=2\n")
                .unwrap_err()
                .to_string()
                .contains("twice")
        );
    }

    #[test]
    fn the_command_line_takes_only_references() {
        assert!(parse_setting("DB=txc://work/db").is_ok());
        assert!(parse_setting("DB=hunter2").is_err());
        assert!(parse_setting("=txc://work/db").is_err());
    }
}
