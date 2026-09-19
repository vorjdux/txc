//! Asking for passphrases and secrets.
//!
//! Nothing secret is ever taken from a command line argument, which would end
//! up in shell history and in the process list. Passphrases are typed at the
//! terminal without echo, or read from a file only its owner can read. Secrets
//! are typed the same way, or piped in on standard input.

// A read that fails is reported in the caller's own words rather than by
// forwarding the underlying io error, so map_err discards it on purpose here.
#![allow(clippy::map_err_ignore)]

use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, anyhow, ensure};
use zeroize::Zeroizing;

use crate::vault::model::MAX_SECRET_BYTES;

/// The shortest passphrase accepted for a new identity, in characters.
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// The longest passphrase read from a file, in bytes.
const MAX_PASSPHRASE_BYTES: usize = 4096;

const NO_TERMINAL_FOR_PASSPHRASE: &str =
    "there is no terminal to type the passphrase at; use --passphrase-file";
const NO_TERMINAL_FOR_WRITE: &str =
    "there is no terminal to type the write passphrase at; use --write-passphrase-file";
const NO_TERMINAL_FOR_SECRET: &str =
    "there is no terminal to type the secret at; pipe it in with --secret-from-stdin";

/// Where a passphrase comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Passphrase {
    /// Typed at the terminal, without echo.
    Terminal,
    /// Read from a file, for scripts. On Unix the file must be readable by
    /// its owner alone.
    File(PathBuf),
}

impl Passphrase {
    /// Reads a passphrase to unlock with.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no terminal to ask at, or when the file
    /// cannot be read, is open to other users, or is empty.
    pub fn ask(&self, prompt: &str) -> Result<SecretString> {
        self.ask_hinted(prompt, NO_TERMINAL_FOR_PASSPHRASE)
    }

    /// Reads the write passphrase to unlock the write key. Its no-terminal hint
    /// names `--write-passphrase-file`, never the identity's file, so the two
    /// credentials stay separate.
    ///
    /// # Errors
    ///
    /// As [`ask`](Self::ask).
    pub fn ask_write(&self, prompt: &str) -> Result<SecretString> {
        self.ask_hinted(prompt, NO_TERMINAL_FOR_WRITE)
    }

    fn ask_hinted(&self, prompt: &str, hint: &'static str) -> Result<SecretString> {
        match self {
            Self::Terminal => hidden(prompt, hint),
            Self::File(path) => from_file(path),
        }
    }

    /// Reads a passphrase that is about to protect something: typed twice at
    /// a terminal, and held to the minimum length wherever it came from.
    ///
    /// # Errors
    ///
    /// Returns an error as [`ask`](Self::ask) does, when the two typings
    /// differ, or when the passphrase is too short.
    pub fn ask_new(&self, prompt: &str) -> Result<SecretString> {
        self.ask_new_hinted(prompt, NO_TERMINAL_FOR_PASSPHRASE)
    }

    /// Reads a new write passphrase, as [`ask_new`](Self::ask_new) but hinting
    /// `--write-passphrase-file` when there is no terminal.
    ///
    /// # Errors
    ///
    /// As [`ask_new`](Self::ask_new).
    pub fn ask_new_write(&self, prompt: &str) -> Result<SecretString> {
        self.ask_new_hinted(prompt, NO_TERMINAL_FOR_WRITE)
    }

    fn ask_new_hinted(&self, prompt: &str, hint: &'static str) -> Result<SecretString> {
        let passphrase = self.ask_hinted(prompt, hint)?;
        check_new_passphrase(&passphrase)?;
        if *self == Self::Terminal {
            let again = hidden("Type it again: ", hint)?;
            ensure!(
                passphrase.expose_secret() == again.expose_secret(),
                "the two passphrases did not match"
            );
        }
        Ok(passphrase)
    }
}

/// Holds a new passphrase to the minimum length.
///
/// Length is what makes a passphrase expensive to guess; the key derivation
/// already makes every guess slow. Rules about symbols mostly push people to
/// passphrases that are short and predictable, so there are none.
///
/// # Errors
///
/// Returns an error when the passphrase is shorter than
/// [`MIN_PASSPHRASE_CHARS`].
///
/// ```
/// use txc::vault::prompt::check_new_passphrase;
///
/// assert!(check_new_passphrase(&"short".to_string().into()).is_err());
/// assert!(check_new_passphrase(&"correct horse battery".to_string().into()).is_ok());
/// ```
pub fn check_new_passphrase(passphrase: &SecretString) -> Result<()> {
    ensure!(
        passphrase.expose_secret().chars().count() >= MIN_PASSPHRASE_CHARS,
        "a passphrase needs at least {MIN_PASSPHRASE_CHARS} characters; \
         a few unrelated words are easy to type and hard to guess"
    );
    Ok(())
}

/// Asks for a secret at the terminal, twice, without echo.
///
/// # Errors
///
/// Returns an error when there is no terminal, when the secret is empty or
/// too large, or when the two typings differ.
pub fn secret_from_terminal(label: &str) -> Result<SecretString> {
    let secret = hidden(&format!("{label}: "), NO_TERMINAL_FOR_SECRET)?;
    ensure!(!secret.expose_secret().is_empty(), "the {label} is empty");
    ensure!(
        secret.expose_secret().len() <= MAX_SECRET_BYTES,
        "the {label} is larger than {} KiB",
        MAX_SECRET_BYTES / 1024
    );
    let again = hidden("Type it again: ", NO_TERMINAL_FOR_SECRET)?;
    ensure!(
        secret.expose_secret() == again.expose_secret(),
        "the two entries did not match"
    );
    Ok(secret)
}

/// Reads a secret piped in on standard input.
///
/// One trailing newline is removed, as `echo` adds one.
///
/// # Errors
///
/// Returns an error when standard input is a terminal, or when what arrives
/// is empty, too large or not UTF-8.
pub fn secret_from_stdin() -> Result<SecretString> {
    let stdin = io::stdin();
    ensure!(
        !stdin.is_terminal(),
        "--secret-from-stdin reads a secret piped in, and standard input is a terminal"
    );
    let bytes = read_bounded(stdin.lock(), MAX_SECRET_BYTES + 2)
        .context("cannot read the secret from standard input")?;
    secret_from_bytes(&bytes, MAX_SECRET_BYTES, "the piped secret")
}

/// Asks a yes or no question at the terminal. Anything but yes is no.
///
/// `hint` is appended to the error when there is no terminal, so each caller
/// can name its own way out.
///
/// # Errors
///
/// Returns an error when there is no terminal to ask at.
pub fn confirm(question: &str, hint: &str) -> Result<bool> {
    ensure!(
        io::stdin().is_terminal(),
        "there is no terminal to confirm at; {hint}"
    );
    eprint!("{question} [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// Asks the operator to type an exact value shown on screen, so a decision
/// cannot be made by a reflex keypress. Case, hyphens and spaces are ignored,
/// so the value can be read off a second device.
///
/// This is not a secret comparison: the value is public (a fingerprint), so a
/// plain compare is correct.
///
/// # Errors
///
/// Returns an error when there is no terminal to ask at.
pub fn confirm_value(question: &str, expected: &str, hint: &str) -> Result<bool> {
    ensure!(
        io::stdin().is_terminal(),
        "there is no terminal to confirm at; {hint}"
    );
    eprint!("{question} ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(normalise(&answer) == normalise(expected))
}

/// Whether two fingerprints are the same, ignoring case, hyphens and spaces.
///
/// Not a secret comparison: fingerprints are public.
#[must_use]
pub fn fingerprints_match(a: &str, b: &str) -> bool {
    normalise(a) == normalise(b)
}

/// Lowercases and keeps only letters and digits, so a value can be typed with
/// any grouping or case.
fn normalise(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Reads without echo. rpassword asks the controlling terminal directly, so
/// this works even while standard input is a pipe carrying a secret.
fn hidden(prompt: &str, without_terminal: &'static str) -> Result<SecretString> {
    let typed = rpassword::prompt_password(prompt).map_err(|_| anyhow!(without_terminal))?;
    Ok(SecretString::from(typed))
}

// The mask reads as the permission bits it names, which trailing_zeros would not.
#[allow(clippy::verbose_bit_mask)]
fn from_file(path: &Path) -> Result<SecretString> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("cannot read the passphrase file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        // A pipe such as /dev/fd/3 has no meaningful mode, and nobody else
        // can read from it anyway.
        ensure!(
            !metadata.is_file() || metadata.mode() & 0o077 == 0,
            "{} can be read by other users; fix it with: chmod 600 {}",
            path.display(),
            path.display()
        );
    }
    let bytes = read_bounded(file, MAX_PASSPHRASE_BYTES + 2)
        .with_context(|| format!("cannot read the passphrase file {}", path.display()))?;
    secret_from_bytes(&bytes, MAX_PASSPHRASE_BYTES, "the passphrase file")
}

/// Reads at most `limit` bytes into a buffer that is sized once, so it is
/// never reallocated with an old copy left behind, and wiped when dropped.
fn read_bounded(reader: impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit.saturating_add(1)));
    reader
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "more than {limit} bytes arrived");
    Ok(bytes)
}

fn secret_from_bytes(bytes: &[u8], limit: usize, what: &str) -> Result<SecretString> {
    // Strip one trailing newline, and the carriage return only when it precedes
    // that newline, so a value ending in a lone "\r" is left as it is.
    let trimmed = match bytes.strip_suffix(b"\n") {
        Some(without_newline) => without_newline
            .strip_suffix(b"\r")
            .unwrap_or(without_newline),
        None => bytes,
    };
    let text = std::str::from_utf8(trimmed).map_err(|_| anyhow!("{what} is not UTF-8"))?;
    ensure!(!text.is_empty(), "{what} is empty");
    ensure!(text.len() <= limit, "{what} is larger than {limit} bytes");
    // Built from a slice, so the string is allocated at its final size once.
    Ok(SecretString::from(text.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_trailing_newline_is_removed() {
        let read = |bytes: &[u8]| {
            secret_from_bytes(bytes, 100, "test").map(|secret| secret.expose_secret().to_string())
        };
        assert_eq!(read(b"hunter2\n").unwrap(), "hunter2");
        assert_eq!(read(b"hunter2\r\n").unwrap(), "hunter2");
        assert_eq!(read(b"two\nlines\n").unwrap(), "two\nlines");
        assert_eq!(read(b"kept \n\n").unwrap(), "kept \n");
        assert!(read(b"\n").is_err());
        assert!(read(b"\xff").is_err());
    }

    #[test]
    fn input_past_the_limit_is_refused() {
        assert!(read_bounded(&b"12345"[..], 5).is_ok());
        assert!(read_bounded(&b"123456"[..], 5).is_err());
    }

    #[test]
    fn a_passphrase_file_must_be_private() {
        let path = std::env::temp_dir().join(format!(
            "txc-passphrase-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::write(&path, "correct horse battery staple\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(Passphrase::File(path.clone()).ask("").is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let passphrase = Passphrase::File(path.clone()).ask_new("").unwrap();
        assert_eq!(passphrase.expose_secret(), "correct horse battery staple");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_short_new_passphrase_is_refused_even_from_a_file() {
        let path = std::env::temp_dir().join(format!(
            "txc-passphrase-short-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::write(&path, "short").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(Passphrase::File(path.clone()).ask_new("").is_err());
        assert!(Passphrase::File(path.clone()).ask("").is_ok());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_typed_value_ignores_case_hyphens_and_spaces() {
        assert_eq!(normalise("K7FQ-2mxv 8D3n"), "k7fq2mxv8d3n");
        assert_eq!(normalise("k7fq2mxv8d3n"), "k7fq2mxv8d3n");
        assert_ne!(normalise("k7fq"), normalise("k7fx"));
        assert_eq!(normalise("  "), "");
    }
}
