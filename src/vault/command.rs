//! The `txc vault` command line.
//!
//! Secrets never arrive as arguments, where they would be kept in shell
//! history and shown in the process list: they are typed without echo,
//! generated, or piped in. They leave the vault through the clipboard, which
//! is cleared again, or through `--print` into a pipe, never onto a terminal.

use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, anyhow, ensure};
use clap::builder::PossibleValuesParser;
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use rand::RngExt;

use crate::vault::clipboard::{self, Held, MAX_CLEAR_SECONDS};
use crate::vault::model::{
    DEFAULT_VAULT, Entry, Kind, Reference, check_field_name, check_plain_value, check_tag,
    check_vault_name,
};
use crate::vault::prompt::{self, Passphrase};
use crate::vault::{Change, Home, Keyring, NewEntry, Standing, harden};

/// What a sealed value is shown as. Always the same, so it gives away nothing
/// about the length of the secret.
pub const MASK: &str = "••••••••";

/// The length of a generated password unless asked otherwise.
pub const DEFAULT_GENERATED_LENGTH: u64 = 24;

// clap takes defaults as static text; a test keeps these equal to the numbers.
const DEFAULT_GENERATED_LENGTH_TEXT: &str = "24";
const DEFAULT_CLEAR_SECONDS_TEXT: &str = "20";

const PASSPHRASE_PROMPT: &str = "Passphrase: ";

/// Builds the `vault` subcommand.
///
/// ```
/// let vault = txc::vault::command::command();
/// assert_eq!(vault.get_name(), "vault");
/// assert!(vault.find_subcommand("copy").is_some());
/// ```
#[must_use]
pub fn command() -> Command {
    let reference = || {
        Arg::new("ENTRY")
            .required(true)
            .value_name("[VAULT/]ENTRY")
            .help("The entry, in the personal vault unless another is named")
    };
    let many = |name: &'static str, value: &'static str, help: &'static str| {
        Arg::new(name)
            .long(name)
            .value_name(value)
            .action(ArgAction::Append)
            .help(help)
    };

    Command::new("vault")
        .about("Keep passwords, API keys and other secrets in an encrypted local vault")
        .long_about(
            "Keep passwords, API keys and other secrets in an encrypted local vault.\n\n\
             Vaults are age files, encrypted to your identity, which is itself protected by \
             a passphrase. Secrets are never taken as arguments and never shown: they are \
             typed without echo, generated or piped in, and copied to the clipboard, which \
             is cleared again.\n\n\
             Start with: txc vault init",
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .infer_subcommands(false)
        .arg(
            Arg::new("home")
                .long("home")
                .value_name("DIR")
                .global(true)
                .help("Use this vault directory rather than the default, as TXC_VAULT_HOME does"),
        )
        .arg(
            Arg::new("passphrase-file")
                .long("passphrase-file")
                .value_name("PATH")
                .global(true)
                .help("Read the passphrase from a file only you can read, rather than asking"),
        )
        .subcommand(
            Command::new("init")
                .about("Create your identity and the personal vault")
                .long_about(
                    "Create your identity and the personal vault.\n\n\
                     The identity is a private key protected by a passphrase. Without both, \
                     nothing in the vaults can be opened, and neither can be recovered.",
                ),
        )
        .subcommand(
            Command::new("identity")
                .about("Print your public key, for encrypting a vault to you elsewhere"),
        )
        .subcommand(
            Command::new("passwd")
                .about("Change the passphrase protecting your identity")
                .arg(
                    Arg::new("new-passphrase-file")
                        .long("new-passphrase-file")
                        .value_name("PATH")
                        .help("Read the new passphrase from a file rather than asking"),
                ),
        )
        .subcommand(
            Command::new("create")
                .about("Create a new, empty vault")
                .arg(
                    Arg::new("NAME")
                        .required(true)
                        .help("Lowercase letters, digits, - and _"),
                )
                .arg(many(
                    "recipient",
                    "AGE_KEY",
                    "Also encrypt to this public key, such as another device's",
                )),
        )
        .subcommand(
            Command::new("list")
                .about("List the vaults, or the entries of one")
                .arg(Arg::new("VAULT").help("The vault whose entries to list"))
                .arg(
                    Arg::new("tag")
                        .long("tag")
                        .value_name("TAG")
                        .help("Only entries with this tag"),
                ),
        )
        .subcommand(
            secret_source_args(
                Command::new("add")
                    .about("Add an entry; its secret is typed, generated or piped in")
                    .arg(reference())
                    .arg(
                        Arg::new("kind")
                            .long("kind")
                            .value_name("KIND")
                            .default_value("login")
                            .value_parser(PossibleValuesParser::new(Kind::ALL.map(Kind::id)))
                            .help("login, api-key, secret or note"),
                    ),
            )
            .args(plain_args(&many))
            .arg(many(
                "secret-field",
                "NAME",
                "Add another sealed field, asked for at the terminal",
            ))
            .arg(many("tag", "TAG", "Add a tag"))
            .after_help(
                "Examples:\n  \
                 txc vault add github --username octocat --url https://github.com --generate\n  \
                 txc vault add work/openai --kind api-key --secret-from-stdin < key.txt\n  \
                 txc vault add recovery-codes --kind note",
            ),
        )
        .subcommand(
            Command::new("show")
                .about("Show an entry, with its secrets masked")
                .arg(reference()),
        )
        .subcommand(
            Command::new("copy")
                .about("Copy a secret to the clipboard, and clear it again after a while")
                .arg(reference())
                .arg(
                    Arg::new("field")
                        .long("field")
                        .value_name("NAME")
                        .help("The field to copy, rather than the entry's main secret"),
                )
                .arg(
                    Arg::new("clear-after")
                        .long("clear-after")
                        .value_name("SECONDS")
                        .default_value(DEFAULT_CLEAR_SECONDS_TEXT)
                        .value_parser(value_parser!(u64).range(1..=MAX_CLEAR_SECONDS))
                        .help("How long the secret stays on the clipboard"),
                )
                .arg(
                    Arg::new("print")
                        .long("print")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("clear-after")
                        .help("Write the secret to standard output instead, which must be a pipe"),
                )
                .after_help(
                    "Examples:\n  \
                     txc vault copy github\n  \
                     txc vault copy github --field username\n  \
                     export OPENAI_API_KEY=\"$(txc vault copy work/openai --print)\"",
                ),
        )
        .subcommand(
            secret_source_args(
                Command::new("edit")
                    .about("Change an entry")
                    .arg(reference())
                    .arg(
                        Arg::new("rename")
                            .long("rename")
                            .value_name("NAME")
                            .help("Give the entry a new name"),
                    )
                    .arg(
                        Arg::new("set-secret")
                            .long("set-secret")
                            .action(ArgAction::SetTrue)
                            .conflicts_with_all(["generate", "secret-from-stdin"])
                            .help("Replace the main secret, asked for at the terminal"),
                    ),
            )
            .args(plain_args(&many))
            .arg(many(
                "secret-field",
                "NAME",
                "Add or replace a sealed field, asked for at the terminal",
            ))
            .arg(many("remove-field", "NAME", "Remove a field"))
            .arg(many("tag", "TAG", "Add a tag"))
            .arg(many("untag", "TAG", "Remove a tag")),
        )
        .subcommand(
            Command::new("rm")
                .about("Remove an entry")
                .long_about(
                    "Remove an entry.\n\n\
                     The previous version of the vault is kept, still encrypted, in the \
                     .bak file beside it until the next change.",
                )
                .arg(reference())
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .action(ArgAction::SetTrue)
                        .help("Do not ask for confirmation"),
                ),
        )
        .subcommand(
            Command::new("recipients")
                .about("Show or change which public keys a vault is encrypted to")
                .long_about(
                    "Show or change which public keys a vault is encrypted to.\n\n\
                     Every secret is sealed again for the new set of keys. A removed key can \
                     still open any copy of the vault made before, so change the secrets it \
                     could read.",
                )
                .arg(Arg::new("VAULT").required(true))
                .arg(many("add", "AGE_KEY", "Encrypt to this public key too"))
                .arg(many(
                    "remove",
                    "AGE_KEY",
                    "Stop encrypting to this public key",
                )),
        )
        .subcommand(
            Command::new("trust")
                .about("Trust a vault that is new to this device, or that changed")
                .long_about(
                    "Trust a vault that is new to this device, or that changed.\n\n\
                     A vault is refused when this device has not seen it before, when its \
                     key or recipients differ from the ones trusted, or when it is older than \
                     the version last opened. This shows what differs and asks before \
                     trusting it as it is now.",
                )
                .arg(Arg::new("VAULT").required(true))
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .action(ArgAction::SetTrue)
                        .help("Do not ask for confirmation"),
                ),
        )
}

/// The ways a main secret can be given, shared by `add` and `edit`.
fn secret_source_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("generate")
                .long("generate")
                .action(ArgAction::SetTrue)
                .conflicts_with("secret-from-stdin")
                .help("Generate a random password as the main secret"),
        )
        .arg(
            Arg::new("length")
                .long("length")
                .value_name("N")
                .default_value(DEFAULT_GENERATED_LENGTH_TEXT)
                .value_parser(value_parser!(u64).range(12..=128))
                .requires("generate")
                .help("Characters in a generated password"),
        )
        .arg(
            Arg::new("no-symbols")
                .long("no-symbols")
                .action(ArgAction::SetTrue)
                .requires("generate")
                .help("Generate from letters and digits only"),
        )
        .arg(
            Arg::new("secret-from-stdin")
                .long("secret-from-stdin")
                .action(ArgAction::SetTrue)
                .help("Read the main secret from standard input"),
        )
}

/// The fields stored in the clear, shared by `add` and `edit`.
fn plain_args(many: &dyn Fn(&'static str, &'static str, &'static str) -> Arg) -> Vec<Arg> {
    vec![
        Arg::new("username")
            .long("username")
            .value_name("NAME")
            .help("The username, stored in the clear inside the vault"),
        Arg::new("url")
            .long("url")
            .value_name("URL")
            .help("The address, stored in the clear inside the vault"),
        many(
            "field",
            "NAME=VALUE",
            "Set a plain field; never use this for a secret, which arguments expose",
        ),
    ]
}

/// Runs `txc vault`.
///
/// # Errors
///
/// Returns an error when the subcommand fails, with a message saying why.
pub fn run(matches: &ArgMatches) -> Result<()> {
    harden::process();

    let home = Home::locate(matches.get_one::<String>("home").map(Path::new))?;
    let passphrase = matches
        .get_one::<String>("passphrase-file")
        .map_or(Passphrase::Terminal, |path| Passphrase::File(path.into()));
    let context = Session { home, passphrase };

    let Some((name, sub)) = matches.subcommand() else {
        unreachable!("clap requires a subcommand");
    };
    match name {
        "init" => context.init(),
        "identity" => {
            let keyring = context.unlock()?;
            output(&keyring.public_key())
        }
        "passwd" => context.passwd(sub),
        "create" => context.create(sub),
        "list" => context.list(sub),
        "add" => context.add(sub),
        "show" => context.show(sub),
        "copy" => context.copy(sub),
        "edit" => context.edit(sub),
        "rm" => context.remove(sub),
        "recipients" => context.recipients(sub),
        "trust" => context.trust(sub),
        other => unreachable!("clap accepted an unknown subcommand {other}"),
    }
}

/// What every subcommand needs: where the vaults are and how to ask for the
/// passphrase.
struct Session {
    home: Home,
    passphrase: Passphrase,
}

impl Session {
    fn unlock(&self) -> Result<Keyring> {
        Keyring::unlock(&self.home, &self.passphrase.ask(PASSPHRASE_PROMPT)?)
    }

    fn init(&self) -> Result<()> {
        let keyring = if self.home.has_identity() {
            eprintln!(
                "An identity already exists at {}.",
                self.home.identity_path().display()
            );
            self.unlock()?
        } else {
            eprintln!(
                "Creating your identity at {}.\n\
                 Choose a passphrase of at least {} characters. Nothing in the vaults can be \
                 opened without it, and it cannot be recovered.",
                self.home.identity_path().display(),
                prompt::MIN_PASSPHRASE_CHARS
            );
            let passphrase = self.passphrase.ask_new("New passphrase: ")?;
            Keyring::create(&self.home, &passphrase)?
        };

        if self
            .home
            .vault_names()?
            .iter()
            .any(|name| name == DEFAULT_VAULT)
        {
            eprintln!("The vault {DEFAULT_VAULT} already exists.");
        } else {
            keyring.create_vault(DEFAULT_VAULT, &[])?;
            eprintln!("Created the vault {DEFAULT_VAULT}.");
        }
        eprintln!("Your public key, for encrypting a vault to you on another device:");
        output(&keyring.public_key())
    }

    fn passwd(&self, sub: &ArgMatches) -> Result<()> {
        let keyring = self.unlock()?;
        let source = if let Some(path) = sub.get_one::<String>("new-passphrase-file") {
            Passphrase::File(path.into())
        } else {
            ensure!(
                self.passphrase == Passphrase::Terminal,
                "with --passphrase-file, give the new passphrase with --new-passphrase-file"
            );
            Passphrase::Terminal
        };
        let passphrase = source.ask_new("New passphrase: ")?;
        keyring.change_passphrase(&passphrase)?;
        eprintln!("Passphrase changed.");
        Ok(())
    }

    fn create(&self, sub: &ArgMatches) -> Result<()> {
        let name = required(sub, "NAME");
        check_vault_name(name)?;
        let recipients = many(sub, "recipient");
        let keyring = self.unlock()?;
        keyring.create_vault(name, &recipients)?;
        eprintln!("Created the vault {name}.");
        Ok(())
    }

    fn list(&self, sub: &ArgMatches) -> Result<()> {
        let Some(name) = sub.get_one::<String>("VAULT") else {
            let names = self.home.vault_names()?;
            if names.is_empty() {
                eprintln!("There are no vaults yet; start with: txc vault init");
                return Ok(());
            }
            return output(&names.join("\n"));
        };
        check_vault_name(name)?;
        let tag = sub.get_one::<String>("tag");
        if let Some(tag) = tag {
            check_tag(tag)?;
        }

        let keyring = self.unlock()?;
        let vault = keyring.open(name)?;
        let entries: Vec<&Entry> = vault
            .vault()
            .entries()
            .iter()
            .filter(|entry| tag.is_none_or(|tag| entry.tags.contains(tag)))
            .collect();
        if entries.is_empty() {
            eprintln!("No entries.");
            return Ok(());
        }

        let rows: Vec<[String; 3]> = entries
            .iter()
            .map(|entry| {
                [
                    entry.name.clone(),
                    entry.kind.id().to_string(),
                    entry
                        .plain("username")
                        .or_else(|| entry.plain("url"))
                        .unwrap_or_default()
                        .to_string(),
                ]
            })
            .collect();
        output(&table(&rows))
    }

    fn add(&self, sub: &ArgMatches) -> Result<()> {
        let reference: Reference = required(sub, "ENTRY").parse()?;
        let kind = Kind::from_id(required(sub, "kind")).expect("clap checked the kind");
        let plain = plain_fields(sub)?;
        let tags = checked_tags(sub, "tag")?;
        let secret_fields = checked_field_names(sub, "secret-field")?;

        // Everything that can be checked is checked before any secret is typed.
        let keyring = self.unlock()?;
        let mut vault = keyring.open(&reference.vault)?;
        ensure!(
            vault.vault().entry(&reference.entry).is_none(),
            "there is already an entry named {:?} in the vault {}",
            reference.entry,
            reference.vault
        );

        let (primary, generated) = main_secret(sub, kind.primary())?;
        let mut secrets = vec![(kind.primary().to_string(), primary)];
        for name in secret_fields {
            let secret = prompt::secret_from_terminal(&name)?;
            secrets.push((name, secret));
        }

        vault.add(NewEntry {
            name: reference.entry.clone(),
            kind,
            plain,
            secrets,
            tags,
        })?;
        vault.save(&keyring)?;

        eprintln!("Added {reference}.");
        if generated {
            eprintln!(
                "Its {} was generated; copy it with: txc vault copy {reference}",
                kind.primary()
            );
        }
        Ok(())
    }

    fn show(&self, sub: &ArgMatches) -> Result<()> {
        let reference: Reference = required(sub, "ENTRY").parse()?;
        let keyring = self.unlock()?;
        let vault = keyring.open(&reference.vault)?;
        let entry = vault.entry(&reference.entry)?;

        let mut rows = vec![
            ["name".to_string(), entry.name.clone()],
            ["vault".to_string(), reference.vault.clone()],
            ["kind".to_string(), entry.kind.id().to_string()],
        ];
        for field in &entry.fields {
            let shown = match entry.plain(&field.name) {
                Some(value) => value.to_string(),
                None => MASK.to_string(),
            };
            rows.push([field.name.clone(), shown]);
        }
        if !entry.tags.is_empty() {
            rows.push(["tags".to_string(), entry.tags.join(", ")]);
        }
        rows.push(["created".to_string(), entry.created.clone()]);
        rows.push(["updated".to_string(), entry.updated.clone()]);
        output(&table(&rows))
    }

    fn copy(&self, sub: &ArgMatches) -> Result<()> {
        let reference: Reference = required(sub, "ENTRY").parse()?;
        let print = sub.get_flag("print");
        if print {
            ensure!(
                !io::stdout().is_terminal(),
                "--print will not write a secret to the terminal, where it would stay in the \
                 scrollback; pipe it into a program, or leave out --print to use the clipboard"
            );
        }

        let keyring = self.unlock()?;
        let vault = keyring.open(&reference.vault)?;
        let entry = vault.entry(&reference.entry)?;
        let field = sub
            .get_one::<String>("field")
            .cloned()
            .unwrap_or_else(|| entry.kind.primary().to_string());
        let entry_name = entry.name.clone();
        let secret = vault.reveal(&keyring, &entry_name, &field)?;

        // Only the one secret stays in memory while it waits: the key and the
        // vault are wiped now.
        drop(vault);
        drop(keyring);

        if print {
            let mut stdout = io::stdout().lock();
            let written = stdout
                .write_all(secret.expose_secret().as_bytes())
                .and_then(|()| stdout.flush());
            return match written {
                Err(error) if error.kind() != io::ErrorKind::BrokenPipe => Err(error.into()),
                _ => Ok(()),
            };
        }

        let seconds = *sub
            .get_one::<u64>("clear-after")
            .expect("clear-after has a default");
        let held = clipboard::copy(&secret)
            .map_err(|error| anyhow!("{error}; use --print to send it to a pipe instead"))?;
        drop(secret);
        wait_then_clear(held, seconds, &format!("{field} of {reference}"))
    }

    fn edit(&self, sub: &ArgMatches) -> Result<()> {
        let reference: Reference = required(sub, "ENTRY").parse()?;
        let mut change = Change {
            rename: sub.get_one::<String>("rename").cloned(),
            plain: plain_fields(sub)?,
            remove: checked_field_names(sub, "remove-field")?,
            tag: checked_tags(sub, "tag")?,
            untag: checked_tags(sub, "untag")?,
            ..Change::default()
        };
        let secret_fields = checked_field_names(sub, "secret-field")?;
        let new_main = ["set-secret", "generate", "secret-from-stdin"]
            .iter()
            .any(|flag| sub.get_flag(flag));
        ensure!(
            new_main
                || !secret_fields.is_empty()
                || change.rename.is_some()
                || !change.plain.is_empty()
                || !change.remove.is_empty()
                || !change.tag.is_empty()
                || !change.untag.is_empty(),
            "nothing to change; see: txc vault edit --help"
        );

        let keyring = self.unlock()?;
        let mut vault = keyring.open(&reference.vault)?;
        let entry = vault.entry(&reference.entry)?;
        let (name, primary) = (entry.name.clone(), entry.kind.primary());

        if new_main {
            let (secret, _) = main_secret(sub, primary)?;
            change.secrets.push((primary.to_string(), secret));
        }
        for field in secret_fields {
            let secret = prompt::secret_from_terminal(&field)?;
            change.secrets.push((field, secret));
        }

        vault.change(&name, change)?;
        vault.save(&keyring)?;
        eprintln!("Changed {reference}.");
        Ok(())
    }

    fn remove(&self, sub: &ArgMatches) -> Result<()> {
        let reference: Reference = required(sub, "ENTRY").parse()?;
        let keyring = self.unlock()?;
        let mut vault = keyring.open(&reference.vault)?;
        let name = vault.entry(&reference.entry)?.name.clone();

        if !sub.get_flag("yes") {
            ensure!(
                prompt::confirm(&format!("Remove {reference}?"))?,
                "nothing was removed"
            );
        }
        vault.remove(&name)?;
        vault.save(&keyring)?;
        eprintln!("Removed {reference}.");
        Ok(())
    }

    fn recipients(&self, sub: &ArgMatches) -> Result<()> {
        let name = required(sub, "VAULT");
        check_vault_name(name)?;
        let add = many(sub, "add");
        let remove = many(sub, "remove");

        let keyring = self.unlock()?;
        let mut vault = keyring.open(name)?;
        let own = keyring.public_key();
        let current = vault.vault().recipients().to_vec();

        if add.is_empty() && remove.is_empty() {
            let lines: Vec<String> = current
                .iter()
                .map(|key| {
                    if *key == own {
                        format!("{key}  (you)")
                    } else {
                        key.clone()
                    }
                })
                .collect();
            return output(&lines.join("\n"));
        }

        ensure!(
            !remove.contains(&own),
            "your own key cannot be removed, or you could not open the vault any more"
        );
        for key in &remove {
            ensure!(current.contains(key), "the vault is not encrypted to {key}");
        }
        let mut others: Vec<String> = current
            .into_iter()
            .filter(|key| *key != own && !remove.contains(key))
            .collect();
        others.extend(add);

        vault.set_recipients(&keyring, &others)?;
        vault.save(&keyring)?;
        eprintln!(
            "The vault {name} is now encrypted to {} key(s).",
            vault.vault().recipients().len()
        );
        if !remove.is_empty() {
            eprintln!(
                "Copies of the vault made before can still be opened with the removed key(s); \
                 change any secret they could read."
            );
        }
        Ok(())
    }

    fn trust(&self, sub: &ArgMatches) -> Result<()> {
        let name = required(sub, "VAULT");
        check_vault_name(name)?;
        let keyring = self.unlock()?;
        let inspection = keyring.inspect(name)?;

        if *inspection.standing() == Standing::Trusted {
            eprintln!("The vault {name} is already trusted on this device.");
            return Ok(());
        }

        let own = keyring.public_key();
        eprintln!("{}.", capitalise(&inspection.standing().describe(name)));
        eprintln!("  generation  {}", inspection.vault().generation());
        eprintln!("  entries     {}", inspection.vault().entries().len());
        eprintln!("  updated     {}", inspection.vault().updated());
        eprintln!("  encrypted to:");
        for key in inspection.vault().recipients() {
            let marker = if *key == own { "  (you)" } else { "" };
            eprintln!("    {key}{marker}");
        }

        if !sub.get_flag("yes") {
            ensure!(
                prompt::confirm("Trust this vault on this device, as it is now?")?,
                "the vault was not trusted"
            );
        }
        keyring.trust_vault(inspection)?;
        eprintln!("Trusted the vault {name}.");
        Ok(())
    }
}

/// The main secret for `add` or `edit`: generated, piped in, or typed.
fn main_secret(sub: &ArgMatches, label: &str) -> Result<(SecretString, bool)> {
    if sub.get_flag("generate") {
        let length = *sub.get_one::<u64>("length").expect("length has a default");
        let length = usize::try_from(length).expect("the length is at most 128");
        Ok((generate(length, !sub.get_flag("no-symbols")), true))
    } else if sub.get_flag("secret-from-stdin") {
        Ok((prompt::secret_from_stdin()?, false))
    } else {
        Ok((prompt::secret_from_terminal(label)?, false))
    }
}

/// A random password with at least one character of every class it draws
/// from, so sites with composition rules take it.
///
/// It is built in a string allocated once at its final size, so no partial
/// copy is left behind, and a draw missing a class is wiped before the next.
#[must_use]
pub fn generate(length: usize, symbols: bool) -> SecretString {
    const CLASSES: [&str; 4] = [
        "abcdefghijklmnopqrstuvwxyz",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "0123456789",
        "!@#$%^&*()-_=+[]{};:,.<>?",
    ];
    let classes = if symbols { &CLASSES[..] } else { &CLASSES[..3] };
    let alphabet: Vec<u8> = classes.iter().flat_map(|class| class.bytes()).collect();
    let length = length.max(classes.len());
    let mut rng = rand::rng();

    loop {
        let mut password = String::with_capacity(length);
        for _ in 0..length {
            password.push(char::from(alphabet[rng.random_range(0..alphabet.len())]));
        }
        if classes
            .iter()
            .all(|class| password.bytes().any(|b| class.as_bytes().contains(&b)))
        {
            return SecretString::from(password);
        }
        zeroize::Zeroize::zeroize(&mut password);
    }
}

/// Waits for the time to run out, a key, or the clipboard to be taken over,
/// then clears the secret if it is still there.
fn wait_then_clear(held: Held, seconds: u64, what: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let interactive = io::stdin().is_terminal() && io::stderr().is_terminal();

    if interactive {
        eprintln!(
            "Copied the {what}. The clipboard clears in {seconds}s; press any key to clear it now."
        );
        wait_for_key(deadline, &held)?;
    } else {
        eprintln!("Copied the {what}. The clipboard clears in {seconds}s.");
        while Instant::now() < deadline && !held.taken_over() {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    if held.clear()? {
        eprintln!("Clipboard cleared.");
    } else {
        eprintln!("The clipboard holds something else now, so it was left alone.");
    }
    Ok(())
}

/// Waits in raw mode, where ctrl+c arrives as a key rather than killing the
/// process, so even interrupting still clears the clipboard.
fn wait_for_key(deadline: Instant, held: &Held) -> Result<()> {
    use crossterm::event::{self, Event, KeyEventKind};
    use crossterm::terminal;

    struct Raw;
    impl Drop for Raw {
        fn drop(&mut self) {
            let _ = terminal::disable_raw_mode();
        }
    }

    terminal::enable_raw_mode().context("cannot read keys from the terminal")?;
    let _raw = Raw;
    while Instant::now() < deadline && !held.taken_over() {
        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            break;
        }
    }
    Ok(())
}

fn required<'a>(sub: &'a ArgMatches, name: &str) -> &'a str {
    sub.get_one::<String>(name)
        .map(String::as_str)
        .expect("clap enforces required arguments")
}

fn many(sub: &ArgMatches, name: &str) -> Vec<String> {
    sub.get_many::<String>(name)
        .map(|values| values.map(|value| value.trim().to_string()).collect())
        .unwrap_or_default()
}

fn checked_tags(sub: &ArgMatches, name: &str) -> Result<Vec<String>> {
    let tags = many(sub, name);
    for tag in &tags {
        check_tag(tag)?;
    }
    Ok(tags)
}

fn checked_field_names(sub: &ArgMatches, name: &str) -> Result<Vec<String>> {
    let names = many(sub, name);
    for field in &names {
        check_field_name(field)?;
    }
    Ok(names)
}

/// `--username`, `--url` and every `--field NAME=VALUE`.
fn plain_fields(sub: &ArgMatches) -> Result<Vec<(String, String)>> {
    let mut fields = Vec::new();
    for name in ["username", "url"] {
        if let Some(value) = sub.get_one::<String>(name) {
            check_plain_value(name, value)?;
            fields.push((name.to_string(), value.clone()));
        }
    }
    if let Some(pairs) = sub.get_many::<String>("field") {
        for pair in pairs {
            let (name, value) = pair
                .split_once('=')
                .ok_or_else(|| anyhow!("--field takes NAME=VALUE, not {pair:?}"))?;
            check_field_name(name)?;
            check_plain_value(name, value)?;
            fields.push((name.to_string(), value.to_string()));
        }
    }
    Ok(fields)
}

/// Lines up rows in columns, two spaces apart, with the last column ragged.
fn table<const N: usize>(rows: &[[String; N]]) -> String {
    let mut widths = [0; N];
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    rows.iter()
        .map(|row| {
            let mut line = String::new();
            for (index, cell) in row.iter().enumerate() {
                if index + 1 == N {
                    line.push_str(cell);
                } else {
                    let _ = write!(line, "{cell:<width$}  ", width = widths[index]);
                }
            }
            line.trim_end().to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

fn output(text: &str) -> Result<()> {
    crate::input::write(text, None, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::clipboard::DEFAULT_CLEAR_SECONDS;

    #[test]
    fn the_command_tree_is_well_formed() {
        command().debug_assert();
    }

    #[test]
    fn the_default_texts_match_the_numbers() {
        assert_eq!(
            DEFAULT_GENERATED_LENGTH_TEXT,
            DEFAULT_GENERATED_LENGTH.to_string()
        );
        assert_eq!(
            DEFAULT_CLEAR_SECONDS_TEXT,
            DEFAULT_CLEAR_SECONDS.to_string()
        );
    }

    #[test]
    fn generated_passwords_have_the_length_and_every_class() {
        for _ in 0..50 {
            let password = generate(16, true);
            let text = password.expose_secret();
            assert_eq!(text.len(), 16);
            assert!(text.bytes().any(|b| b.is_ascii_lowercase()));
            assert!(text.bytes().any(|b| b.is_ascii_uppercase()));
            assert!(text.bytes().any(|b| b.is_ascii_digit()));
            assert!(text.bytes().any(|b| b.is_ascii_punctuation()));
        }
        let plain = generate(64, false);
        assert!(
            plain
                .expose_secret()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric())
        );
    }

    #[test]
    fn two_generated_passwords_differ() {
        assert_ne!(
            generate(24, true).expose_secret(),
            generate(24, true).expose_secret()
        );
    }

    #[test]
    fn a_secret_is_never_accepted_as_an_argument() {
        fn walk(command: &Command, valued: &[&str]) {
            for arg in command.get_arguments() {
                let name = arg.get_id().as_str();
                if arg.get_long().is_some() && arg.get_action().takes_values() {
                    assert!(
                        valued.contains(&name),
                        "{} --{name} takes a value; secrets must not arrive as arguments",
                        command.get_name()
                    );
                }
            }
            for sub in command.get_subcommands() {
                walk(sub, valued);
            }
        }

        // Only these carry values; none of them is for a secret.
        let valued = [
            "home",
            "passphrase-file",
            "new-passphrase-file",
            "recipient",
            "tag",
            "kind",
            "username",
            "url",
            "field",
            "secret-field",
            "clear-after",
            "rename",
            "remove-field",
            "untag",
            "add",
            "remove",
            "length",
        ];
        walk(&command(), &valued);
    }

    #[test]
    fn tables_line_up() {
        let rows = [
            ["a".to_string(), "login".to_string(), "x".to_string()],
            ["longer".to_string(), "note".to_string(), String::new()],
        ];
        assert_eq!(table(&rows), "a       login  x\nlonger  note");
    }
}
