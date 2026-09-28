//! Hardware keys through age plugins, pinned by path and hash (study
//! sections 5 and 11).
//!
//! A security key, the Secure Enclave or a TPM reaches txc as an age plugin:
//! `age-plugin-yubikey`, `age-plugin-se` and the like hold the private key,
//! and tag recipients (`age1tag1...`, `age1tagpq1...`) are their public side.
//! age plugins receive file keys, so they are never looked up in `PATH`:
//! each is pinned once, by its absolute path and the SHA-256 of the binary,
//! and a plugin whose binary changed or moved is refused.
//!
//! This module speaks the age plugin protocol itself, over `age-core`'s
//! connection, so the pinned binary is the one that runs. Messages, PIN
//! requests and touch confirmations from the plugin go to a [`Prompter`].

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

use age::secrecy::{ExposeSecret, SecretString};
use age_core::format::{FileKey, Stanza};
use age_core::plugin::{Connection, IDENTITY_V1, RECIPIENT_V1, Reply, Response};
use anyhow::{Context as _, Result, anyhow, bail, ensure};
use sha2::{Digest, Sha256};

use crate::vault::wire::{Reader, Writer};

/// Talks to the person on the plugin's behalf.
pub trait Prompter {
    /// Shows a message, such as "touch your security key".
    fn message(&self, text: &str);
    /// Asks for a PIN or other secret.
    fn secret(&self, question: &str) -> Option<SecretString>;
    /// Asks for a public value.
    fn public(&self, question: &str) -> Option<String>;
    /// Asks yes or no.
    fn confirm(&self, question: &str, yes: &str, no: Option<&str>) -> Option<bool>;
}

/// Prompts at the terminal.
pub struct Terminal;

impl Prompter for Terminal {
    fn message(&self, text: &str) {
        eprintln!("{text}");
    }

    fn secret(&self, question: &str) -> Option<SecretString> {
        crate::vault::prompt::secret_from_terminal(question).ok()
    }

    fn public(&self, question: &str) -> Option<String> {
        eprint!("{question} ");
        let mut line = String::new();
        io::stdin().read_line(&mut line).ok()?;
        Some(line.trim().to_owned())
    }

    fn confirm(&self, question: &str, yes: &str, no: Option<&str>) -> Option<bool> {
        let choices = no.map_or_else(|| format!("[{yes}]"), |no| format!("[{yes}/{no}]"));
        let answer = self.public(&format!("{question} {choices}"))?;
        Some(answer.eq_ignore_ascii_case(yes) || answer.eq_ignore_ascii_case("y"))
    }
}

/// A plugin binary, pinned by its absolute path and hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pinned {
    /// The plugin's name: `yubikey` for `age-plugin-yubikey`.
    pub name: String,
    /// The binary's absolute path.
    pub path: PathBuf,
    /// The SHA-256 of the binary.
    pub hash: [u8; 32],
}

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("cannot read the plugin {}", path.display()))?;
    Ok(Sha256::digest(&bytes).into())
}

/// The plugin a recipient or identity string belongs to: `age1<name>1...`
/// or `AGE-PLUGIN-<NAME>-1...`.
///
/// # Errors
///
/// Returns an error when the string names no plugin.
pub fn plugin_name(key: &str) -> Result<String> {
    let lower = key.to_ascii_lowercase();
    let name = if let Some(rest) = lower.strip_prefix("age-plugin-") {
        rest.rsplit_once("-1").map(|(name, _)| name.to_owned())
    } else {
        lower
            .strip_prefix("age1")
            .and_then(|rest| rest.rsplit_once('1'))
            .map(|(name, _)| name.to_owned())
    }
    .filter(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"+-._".contains(&byte))
    })
    .ok_or_else(|| anyhow!("{key:.20}... is not a plugin recipient or identity"))?;
    Ok(name)
}

impl Pinned {
    /// Pins the plugin for `name`: at `path` when given, otherwise the one
    /// `PATH` finds now, once, at setup.
    ///
    /// # Errors
    ///
    /// Returns an error when no such plugin is found or it cannot be read.
    pub fn pin(name: &str, path: Option<&Path>) -> Result<Self> {
        let binary = format!("age-plugin-{name}{}", std::env::consts::EXE_SUFFIX);
        let path = match path {
            Some(path) => path.to_path_buf(),
            None => std::env::var_os("PATH")
                .map(|paths| {
                    std::env::split_paths(&paths)
                        .map(|dir| dir.join(&binary))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
                .into_iter()
                .find(|candidate| candidate.is_file())
                .with_context(|| {
                    format!("{binary} is not installed; give its path with --plugin")
                })?,
        };
        let path = std::fs::canonicalize(&path)
            .with_context(|| format!("cannot find {}", path.display()))?;
        Ok(Self {
            name: name.to_owned(),
            hash: hash_file(&path)?,
            path,
        })
    }

    /// Checks that the binary is still the one pinned.
    ///
    /// # Errors
    ///
    /// Returns an error when it changed, moved or is gone.
    pub fn verify(&self) -> Result<()> {
        ensure!(
            hash_file(&self.path)? == self.hash,
            "the plugin {} changed since it was set up; txc will not run it (set it up again if you \
             updated it on purpose)",
            self.path.display()
        );
        Ok(())
    }

    /// The pin's encoding, for the vault's local files.
    pub fn write(&self, out: &mut Writer) {
        out.str(&self.name);
        out.bytes(self.path.as_os_str().as_encoded_bytes());
        out.fixed(&self.hash);
    }

    /// Reads a pin.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed.
    pub fn read(input: &mut Reader<'_>) -> Result<Self> {
        let name = input.str(256)?;
        let path = std::str::from_utf8(input.bytes()?)
            .map(PathBuf::from)
            .context("a plugin path is not UTF-8")?;
        Ok(Self {
            name,
            path,
            hash: input.fixed()?,
        })
    }

    fn connect(
        &self,
        state_machine: &str,
    ) -> io::Result<
        Connection<
            age_core::io::DebugReader<std::process::ChildStdout>,
            age_core::io::DebugWriter<std::process::ChildStdin>,
        >,
    > {
        self.verify()
            .map_err(|error| io::Error::other(format!("{error:#}")))?;
        Connection::open(&self.path, state_machine)
    }
}

fn plugin_error(errors: &[String]) -> io::Error {
    io::Error::other(errors.join("; "))
}

/// Answers the requests every plugin may make.
fn answer<R: io::Read, W: io::Write>(
    command: &Stanza,
    reply: Reply<R, W>,
    prompter: &dyn Prompter,
    errors: &mut Vec<String>,
) -> Response {
    let body = String::from_utf8_lossy(&command.body);
    match command.tag.as_str() {
        "msg" => {
            prompter.message(&body);
            reply.ok(None)
        }
        "request-public" => match prompter.public(&body) {
            Some(value) => reply.ok(Some(value.as_bytes())),
            None => reply.fail(),
        },
        "request-secret" => match prompter.secret(&body) {
            Some(secret) => reply.ok(Some(secret.expose_secret().as_bytes())),
            None => reply.fail(),
        },
        "confirm" => {
            let decode = |text: &String| {
                data_encoding::BASE64_NOPAD
                    .decode(text.as_bytes())
                    .ok()
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            };
            let (Some(yes), no) = (
                command.args.first().and_then(decode),
                command.args.get(1).and_then(decode),
            ) else {
                errors.push("the plugin asked to confirm without saying what".to_owned());
                return reply.fail();
            };
            match prompter.confirm(&body, &yes, no.as_deref()) {
                Some(value) => reply.ok_with_metadata(&[if value { "yes" } else { "no" }], None),
                None => reply.fail(),
            }
        }
        "error" => {
            errors.push(format!("the plugin said: {body}"));
            reply.ok(None)
        }
        _ => reply.fail(),
    }
}

/// A recipient served by a pinned plugin, such as a hardware tag recipient.
pub struct PluginRecipient<'a> {
    /// The recipient string.
    pub recipient: String,
    /// The plugin that wraps to it.
    pub plugin: Pinned,
    /// Who answers the plugin's questions.
    pub prompter: &'a dyn Prompter,
}

impl age::Recipient for PluginRecipient<'_> {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let mut conn = self.plugin.connect(RECIPIENT_V1)?;
        conn.unidir_send(|mut phase| {
            phase.send("add-recipient", &[self.recipient.as_str()], &[])?;
            phase.send("extension-labels", &[], &[])?;
            phase.send("wrap-file-key", &[], file_key.expose_secret())
        })?;
        let (mut stanzas, mut labels, mut errors) = (Vec::new(), HashSet::new(), Vec::new());
        conn.bidir_receive(
            &[
                "msg",
                "confirm",
                "request-public",
                "request-secret",
                "recipient-stanza",
                "labels",
                "error",
            ],
            |mut command, reply| match command.tag.as_str() {
                "recipient-stanza"
                    if command.args.len() >= 2
                        && command.args.first().is_some_and(|index| index == "0") =>
                {
                    command.args.remove(0);
                    command.tag = command.args.remove(0);
                    stanzas.push(command);
                    reply.ok(None)
                }
                "recipient-stanza" => {
                    errors.push("the plugin sent a stanza it was not asked for".to_owned());
                    reply.ok(None)
                }
                "labels" => {
                    labels.extend(command.args.iter().cloned());
                    reply.ok(None)
                }
                _ => answer(&command, reply, self.prompter, &mut errors),
            },
        )?;
        if !errors.is_empty() || stanzas.is_empty() {
            return Err(plugin_error(&if errors.is_empty() {
                vec!["the plugin wrapped nothing".to_owned()]
            } else {
                errors
            })
            .into());
        }
        Ok((stanzas, labels))
    }
}

/// An identity served by a pinned plugin, such as a key on a security key.
pub struct PluginIdentity<'a> {
    /// The identity string, `AGE-PLUGIN-...`.
    pub identity: SecretString,
    /// The plugin that holds it.
    pub plugin: Pinned,
    /// Who answers the plugin's questions: a touch, a PIN.
    pub prompter: &'a dyn Prompter,
}

impl age::Identity for PluginIdentity<'_> {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        self.unwrap_stanzas(std::slice::from_ref(stanza))
    }

    fn unwrap_stanzas(&self, stanzas: &[Stanza]) -> Option<Result<FileKey, age::DecryptError>> {
        let mut conn = match self.plugin.connect(IDENTITY_V1) {
            Ok(conn) => conn,
            Err(error) => return Some(Err(error.into())),
        };
        let sent = conn.unidir_send(|mut phase| {
            phase.send("add-identity", &[self.identity.expose_secret()], &[])?;
            for stanza in stanzas {
                phase.send_stanza("recipient-stanza", &["0"], stanza)?;
            }
            Ok(())
        });
        if let Err(error) = sent {
            return Some(Err(error.into()));
        }
        let (mut file_key, mut errors) = (None, Vec::new());
        let received = conn.bidir_receive(
            &[
                "msg",
                "confirm",
                "request-public",
                "request-secret",
                "file-key",
                "error",
            ],
            |command, reply| match command.tag.as_str() {
                "file-key"
                    if command.args.first().is_some_and(|index| index == "0")
                        && file_key.is_none() =>
                {
                    file_key = Some(FileKey::try_init_with_mut(|key| {
                        if command.body.len() == key.len() {
                            key.copy_from_slice(&command.body);
                            Ok(())
                        } else {
                            Err(age::DecryptError::DecryptionFailed)
                        }
                    }));
                    reply.ok(None)
                }
                "file-key" => reply.fail(),
                _ => answer(&command, reply, self.prompter, &mut errors),
            },
        );
        if let Err(error) = received {
            return Some(Err(error.into()));
        }
        match file_key {
            Some(key) => Some(key),
            None if errors.is_empty() => None,
            None => Some(Err(plugin_error(&errors).into())),
        }
    }
}

/// A hardware second factor: the recipient a secret is sealed to, the
/// identity that opens it, and the plugins for each, pinned.
#[derive(Clone, Debug)]
pub struct Hardware {
    /// The recipient: the hardware's public side.
    pub recipient: String,
    /// The recipient's plugin.
    pub recipient_plugin: Pinned,
    /// The identity: a handle to the key in the hardware, not the key.
    pub identity: String,
    /// The identity's plugin.
    pub identity_plugin: Pinned,
}

impl Hardware {
    /// Pins the plugins for a recipient and an identity, from `PATH` once
    /// or from the paths given.
    ///
    /// # Errors
    ///
    /// Returns an error when a plugin is not found.
    pub fn set_up(
        recipient: &str,
        identity: &str,
        recipient_path: Option<&Path>,
        identity_path: Option<&Path>,
    ) -> Result<Self> {
        Ok(Self {
            recipient_plugin: Pinned::pin(&plugin_name(recipient)?, recipient_path)?,
            identity_plugin: Pinned::pin(&plugin_name(identity)?, identity_path)?,
            recipient: recipient.to_owned(),
            identity: identity.to_owned(),
        })
    }

    /// Seals a secret to the hardware.
    ///
    /// # Errors
    ///
    /// Returns an error when the plugin fails or was changed.
    pub fn seal(&self, secret: &[u8], prompter: &dyn Prompter) -> Result<Vec<u8>> {
        let recipient = PluginRecipient {
            recipient: self.recipient.clone(),
            plugin: self.recipient_plugin.clone(),
            prompter,
        };
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|error| anyhow!("{error}"))?;
        let mut sealed = Vec::new();
        let mut writer = encryptor.wrap_output(&mut sealed)?;
        std::io::Write::write_all(&mut writer, secret)?;
        writer
            .finish()
            .map_err(|error| anyhow!("the hardware plugin could not seal: {error}"))?;
        Ok(sealed)
    }

    /// Opens a secret with the hardware: a touch or a PIN, as it asks.
    ///
    /// # Errors
    ///
    /// Returns an error when the plugin fails, was changed, or the hardware
    /// is not the one it was sealed to.
    pub fn open(
        &self,
        sealed: &[u8],
        prompter: &dyn Prompter,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        let identity = PluginIdentity {
            identity: SecretString::from(self.identity.clone()),
            plugin: self.identity_plugin.clone(),
            prompter,
        };
        let decryptor = age::Decryptor::new(sealed).map_err(|error| anyhow!("{error}"))?;
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|error| anyhow!("the hardware did not open it: {error}"))?;
        let mut plain = zeroize::Zeroizing::new(Vec::new());
        std::io::Read::read_to_end(&mut reader, &mut plain)?;
        Ok(plain)
    }

    /// The encoding, for the vault's local files.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::default();
        out.str(&self.recipient);
        self.recipient_plugin.write(&mut out);
        out.str(&self.identity);
        self.identity_plugin.write(&mut out);
        out.finish()
    }

    /// Reads the encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        let hardware = Self {
            recipient: input.str(4096)?,
            recipient_plugin: Pinned::read(&mut input)?,
            identity: input.str(4096)?,
            identity_plugin: Pinned::read(&mut input)?,
        };
        input.finish()?;
        if plugin_name(&hardware.recipient)? != hardware.recipient_plugin.name {
            bail!("the recipient's plugin does not match its pin");
        }
        Ok(hardware)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_names_come_from_the_key_strings() {
        assert_eq!(plugin_name("age1yubikey1qwerty").unwrap(), "yubikey");
        assert_eq!(plugin_name("age1tagpq1qqqq").unwrap(), "tagpq");
        assert_eq!(plugin_name("AGE-PLUGIN-YUBIKEY-1QQQQ").unwrap(), "yubikey");
        assert_eq!(plugin_name("AGE-PLUGIN-SE-1ABC").unwrap(), "se");
        assert!(plugin_name("AGE-SECRET-KEY-1ABC").is_err());
        assert!(plugin_name("age1").is_err());
    }

    #[test]
    fn a_changed_plugin_binary_is_refused() {
        let scratch = crate::vault::test_support::Scratch::new("hardware-pin");
        std::fs::create_dir_all(&scratch.0).unwrap();
        let path = scratch.0.join("age-plugin-test");
        std::fs::write(&path, b"one").unwrap();
        let pinned = Pinned::pin("test", Some(&path)).unwrap();
        pinned.verify().unwrap();
        std::fs::write(&path, b"two").unwrap();
        assert!(pinned.verify().is_err());

        let mut out = Writer::default();
        pinned.write(&mut out);
        let bytes = out.finish();
        assert_eq!(Pinned::read(&mut Reader(&bytes)).unwrap(), pinned);
    }
}
