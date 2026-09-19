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
use clap::builder::{PossibleValue, PossibleValuesParser};
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use rand::RngExt;

use crate::vault::clipboard::{self, Held, MAX_CLEAR_SECONDS};
use crate::vault::crypto::{self, WriteKey};
use crate::vault::grant::{self, Grant};
use crate::vault::home;
use crate::vault::model::{
    DEFAULT_VAULT, Entry, FieldSpec, Generator, Kind, Reference, check_field_name,
    check_plain_value, check_tag, check_vault_name,
};
use crate::vault::prompt::{self, Passphrase};
use crate::vault::recent::ago;
use crate::vault::{Change, Home, Keyring, NewEntry, Opened, Standing, harden};

/// What a sealed value is shown as. Always the same, so it gives away nothing
/// about the length of the secret.
pub const MASK: &str = "••••••••";

/// The length of a generated password unless asked otherwise.
pub const DEFAULT_GENERATED_LENGTH: u64 = 24;

/// The length of a generated PIN.
pub const PIN_LENGTH: usize = 4;

// clap takes defaults as static text; a test keeps these equal to the numbers.
const DEFAULT_GENERATED_LENGTH_TEXT: &str = "24";
const DEFAULT_CLEAR_SECONDS_TEXT: &str = "20";

const PASSPHRASE_PROMPT: &str = "Passphrase: ";

/// Every kind, for `--kind`, with `license` accepted for `licence`.
fn kind_values() -> Vec<PossibleValue> {
    Kind::ALL
        .iter()
        .map(|kind| {
            let value = PossibleValue::new(kind.id()).help(kind.label());
            if *kind == Kind::Licence {
                value.alias("license")
            } else {
                value
            }
        })
        .collect()
}

/// The list of kinds and their fields shown under `add --help`.
fn kinds_help() -> String {
    let width = Kind::ALL
        .iter()
        .map(|kind| kind.id().len())
        .max()
        .unwrap_or(0);
    let mut text = String::from(
        "Examples:\n  \
         txc vault add github --username octocat --url https://github.com --generate\n  \
         txc vault add visa --kind card --field cardholder='A N Other' --field expiry=12/30\n  \
         txc vault add work/openai --kind api-key --secret-from-stdin < key.txt\n  \
         txc vault add recovery-codes --kind note --secret-from-stdin < codes.txt\n\n\
         Kinds and their fields. The main secret comes first and is asked for; fields marked \
         * are also secret and are given with --secret-field, the others with --field:\n",
    );
    for kind in Kind::ALL {
        let primary = kind.primary();
        let mut fields: Vec<&FieldSpec> = kind.fields().iter().collect();
        fields.sort_by_key(|spec| spec.name != primary);
        let names: Vec<String> = fields
            .iter()
            .map(|spec| {
                if spec.sensitivity.is_sealed() {
                    format!("{}*", spec.name)
                } else {
                    spec.name.to_string()
                }
            })
            .collect();
        writeln!(text, "  {:width$}  {}", kind.id(), names.join(", ")).ok();
    }
    text
}

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
        .about("Keep passwords, cards, keys and notes in an encrypted local vault")
        .long_about(
            "Keep passwords, cards, API keys, notes and other secrets in an encrypted local \
             vault.\n\n\
             Vaults are age files, encrypted to your identity, which is itself protected by \
             a passphrase. Secrets are never taken as arguments: they are typed without echo, \
             generated, or piped in. They are shown only when you ask for them, and are copied \
             to the clipboard, which is cleared again.\n\n\
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
        .arg(
            Arg::new("write-passphrase-file")
                .long("write-passphrase-file")
                .value_name("PATH")
                .global(true)
                .help(
                    "Read the write passphrase from a file only you can read. Providing it on a \
                     machine where untrusted code runs as you collapses the read/write split.",
                ),
        )
        .subcommand(
            Command::new("init")
                .about("Create your identity, write key and the personal vault")
                .long_about(
                    "Create your identity, write key and the personal vault.\n\n\
                     The identity is a private key protected by a passphrase, and reads your \
                     vaults. The write key is a second key with its own passphrase, and is what \
                     changes a vault. Keeping them apart means a job given --passphrase-file can \
                     read but not write. Run this on an existing 0.6.0 home to add the write key.",
                )
                .arg(
                    Arg::new("reader-only")
                        .long("reader-only")
                        .action(ArgAction::SetTrue)
                        .help("Create only an identity and an empty writers list, for an unattended reader"),
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
                .about("List the vaults, or entries: of one vault, favourites, or recently used")
                .arg(Arg::new("VAULT").help("The vault whose entries to list; all when left out"))
                .arg(
                    Arg::new("favourites")
                        .long("favourites")
                        .visible_alias("favorites")
                        .action(ArgAction::SetTrue)
                        .help("Only starred entries"),
                )
                .arg(
                    Arg::new("recent")
                        .long("recent")
                        .action(ArgAction::SetTrue)
                        .help("The entries used most recently on this device, newest first"),
                )
                .arg(
                    Arg::new("kind")
                        .long("kind")
                        .value_name("KIND")
                        .value_parser(PossibleValuesParser::new(kind_values()))
                        .hide_possible_values(true)
                        .help("Only entries of this kind"),
                )
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
                            .value_parser(PossibleValuesParser::new(kind_values()))
                            .hide_possible_values(true)
                            .help("What the entry is; the kinds and their fields are listed below"),
                    ),
            )
            .args(plain_args(&many))
            .arg(many(
                "secret-field",
                "NAME",
                "Add another secret field, asked for at the terminal",
            ))
            .arg(many("tag", "TAG", "Add a tag"))
            .arg(
                Arg::new("favourite")
                    .long("favourite")
                    .visible_alias("favorite")
                    .action(ArgAction::SetTrue)
                    .help("Star it straight away"),
            )
            .after_help(kinds_help()),
        )
        .subcommand(
            Command::new("show")
                .about("Show an entry, with its secrets masked")
                .arg(reference()),
        )
        .subcommand(
            Command::new("favourite")
                .visible_alias("favorite")
                .about("Star an entry, so it is easy to find, or unstar it with --remove")
                .arg(reference())
                .arg(
                    Arg::new("remove")
                        .long("remove")
                        .action(ArgAction::SetTrue)
                        .help("Unstar it instead"),
                ),
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
                     txc vault copy visa --field cvv\n  \
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
                "Add or replace a secret field, asked for at the terminal",
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
            Command::new("move")
                .visible_alias("mv")
                .about("Move an entry into another vault, re-sealing its secrets there")
                .long_about(
                    "Move an entry into another vault.\n\n\
                     Its secrets are decrypted and sealed again to the destination vault's \
                     keys, which may differ from the source's. The destination is written \
                     first, so a failure never loses the entry.",
                )
                .arg(reference())
                .arg(
                    Arg::new("TO")
                        .required(true)
                        .value_name("VAULT")
                        .help("The vault to move it into"),
                )
                .after_help(
                    "Examples:\n  \
                     txc vault move github work\n  \
                     txc vault move personal/openai work",
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
                     key or recipients differ from the ones trusted, when it is older than \
                     the version last opened, or when two devices changed it at once. This \
                     shows what differs before trusting it as it is now.\n\n\
                     --yes covers only a vault this device has never seen. A vault that \
                     changed is accepted at a terminal by typing its fingerprint, or without \
                     one by passing --expect the fingerprint read from another device. A \
                     vault that went backwards, changed recipients or diverged cannot be \
                     accepted without a terminal, because its fingerprint settles none of \
                     those; re-provision trust.json from the device that made the change.",
                )
                .arg(Arg::new("VAULT").required(true))
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("expect")
                        .help("Trust without asking, for a vault new to this device only"),
                )
                .arg(
                    Arg::new("expect")
                        .long("expect")
                        .value_name("FINGERPRINT")
                        .help("Trust without a terminal, only if the fingerprint matches this"),
                ),
        )
        .subcommand(
            Command::new("fingerprint")
                .about("Print a vault's fingerprint, to verify it from another device")
                .long_about(
                    "Print a vault's fingerprint.\n\n\
                     The fingerprint is a short public name for the vault's identity, safe \
                     to read out. Compare it on two devices to confirm they hold the same \
                     vault, and pass it to `trust --expect`. It is the same across changes \
                     to the vault, and changes only if the vault is renamed.",
                )
                .arg(Arg::new("VAULT").required(true)),
        )
        .subcommand(
            Command::new("history")
                .about("Show this device's trust decisions for a vault")
                .arg(Arg::new("VAULT").required(true)),
        )
        .subcommand(
            Command::new("writer")
                .about("Print this device's writer public key and fingerprint"),
        )
        .subcommand(
            Command::new("writers")
                .about("List, pin or unpin the writer keys this device trusts")
                .long_about(
                    "List, pin or unpin the writer keys this device trusts.\n\n\
                     A vault opens only when it is signed by a pinned writer. Pin another \
                     device's writer to open vaults it wrote. Pinning and unpinning are \
                     authorization changes, so they need a terminal or --yes.",
                )
                .arg(
                    Arg::new("add")
                        .long("add")
                        .value_name("KEY")
                        .conflicts_with("remove")
                        .help("Pin this writer public key"),
                )
                .arg(
                    Arg::new("remove")
                        .long("remove")
                        .value_name("KEY")
                        .help("Unpin this writer public key"),
                )
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .action(ArgAction::SetTrue)
                        .help("Pin or unpin without asking"),
                ),
        )
        .subcommand(
            Command::new("upgrade")
                .about("Re-sign vaults still in the old format, without other changes")
                .arg(
                    Arg::new("VAULT")
                        .help("Only this vault, rather than every one that needs it"),
                ),
        )
        .subcommand(
            Command::new("delete")
                .about("Delete a whole vault, keeping a recovery copy beside it")
                .long_about(
                    "Delete a whole vault, keeping its last version as a .deleted recovery \
                     file next to it. This removes an entire vault and all its entries, unlike \
                     rm, which removes one entry. The vault must open first, so it must be \
                     trusted and its signature must verify.",
                )
                .arg(Arg::new("VAULT").required(true))
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .action(ArgAction::SetTrue)
                        .help("Delete without asking for the vault's name"),
                ),
        )
        .subcommand(
            Command::new("grant")
                .about("Seal one secret to another key, for a host to redeem")
                .long_about(
                    "Seal one secret to another key, so an automated host can be given exactly \
                     that secret without the identity or a passphrase. Write it to a file or a \
                     pipe.\n\n\
                     A grant is a snapshot and cannot be revoked: it does not follow later edits, \
                     and the only real revocation is rotating the secret. It is a read of the \
                     vault, so it needs no write key.",
                )
                .arg(Arg::new("ENTRY").required(true))
                .arg(
                    Arg::new("field")
                        .long("field")
                        .value_name("NAME")
                        .help("Grant this field rather than the main secret"),
                )
                .arg(
                    Arg::new("to")
                        .long("to")
                        .value_name("RECIPIENT")
                        .conflicts_with("to-file")
                        .help("Seal to this age public key, the host's own key"),
                )
                .arg(
                    Arg::new("to-file")
                        .long("to-file")
                        .action(ArgAction::SetTrue)
                        .help("Bundle a fresh key in the grant; the file then is the secret"),
                )
                .arg(
                    Arg::new("expires")
                        .long("expires")
                        .value_name("DURATION")
                        .help("How long it stays fresh, as 1h, 30m, 7d; hygiene, not enforcement"),
                ),
        )
        .subcommand(
            Command::new("redeem")
                .about("Open a grant, printing its secret to a pipe")
                .arg(Arg::new("FILE").required(true))
                .arg(
                    Arg::new("identity")
                        .long("identity")
                        .value_name("PATH")
                        .help("The host's age secret key file, unless the grant bundles one"),
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
                .help("Generate the main secret: a password, or a PIN where that is what it is"),
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
                .help("Read the main secret from standard input, which may run over several lines"),
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
            "Set a field that is not secret; secret fields are refused here, since arguments \
             are visible to other programs",
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
    let write_passphrase = matches
        .get_one::<String>("write-passphrase-file")
        .map_or(Passphrase::Terminal, |path| Passphrase::File(path.into()));
    let context = Session {
        home,
        passphrase,
        write_passphrase,
    };

    let Some((name, sub)) = matches.subcommand() else {
        unreachable!("clap requires a subcommand");
    };
    match name {
        "init" => context.init(sub),
        "identity" => {
            let keyring = context.unlock()?;
            output(&keyring.public_key())
        }
        "passwd" => context.passwd(sub),
        "create" => context.create(sub),
        "list" => context.list(sub),
        "add" => context.add(sub),
        "show" => context.show(sub),
        "favourite" => context.favourite(sub),
        "copy" => context.copy(sub),
        "edit" => context.edit(sub),
        "rm" => context.remove(sub),
        "move" => context.move_entry(sub),
        "recipients" => context.recipients(sub),
        "trust" => context.trust(sub),
        "fingerprint" => context.fingerprint(sub),
        "history" => context.history(sub),
        "writer" => context.writer(),
        "writers" => context.writers(sub),
        "upgrade" => context.upgrade(sub),
        "delete" => context.delete(sub),
        "grant" => context.grant(sub),
        "redeem" => context.redeem(sub),
        other => unreachable!("clap accepted an unknown subcommand {other}"),
    }
}

/// Runs slow work with a line on the terminal saying what is happening.
///
/// Deriving the key from a passphrase takes a moment on purpose, and a
/// command that sits silently looks like one that has hung.
fn working<T>(message: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
    let shown = io::stderr().is_terminal();
    if shown {
        eprint!("{message}");
        io::stderr().flush().ok();
    }
    let result = work();
    if shown {
        // Back to the start of the line, and clear it. Through crossterm, so
        // that the Windows console, which acts on escape sequences only once
        // it has been put in that mode, is cleared as well.
        crossterm::execute!(
            io::stderr(),
            crossterm::cursor::MoveToColumn(0),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine),
        )
        .ok();
    }
    result
}

/// What every subcommand needs: where the vaults are and how to ask for the
/// passphrase.
struct Session {
    home: Home,
    passphrase: Passphrase,
    write_passphrase: Passphrase,
}

impl Session {
    fn unlock(&self) -> Result<Keyring> {
        let passphrase = self.passphrase.ask(PASSPHRASE_PROMPT)?;
        working("Unlocking...", || Keyring::unlock(&self.home, &passphrase))
    }

    /// Unlocks the write key, asking for its own passphrase. A reader-only home
    /// fails here with the reason and the remedy, before anything is changed.
    ///
    /// The write passphrase is never read from `--passphrase-file`, so an agent
    /// holding the identity credential still cannot write.
    fn write_key(&self) -> Result<WriteKey> {
        ensure!(
            self.home.has_writer(),
            "this device is provisioned to read only: there is no write key at {}, so it \
             cannot change a vault. Copy writer.age from a device that can write, or create one \
             here with: txc vault init",
            self.home.writer_path().display()
        );
        let passphrase = self.write_passphrase.ask_write("Write passphrase: ")?;
        working("Unlocking the write key...", || {
            Keyring::open_writer(&self.home, &passphrase)
        })
    }

    fn init(&self, sub: &ArgMatches) -> Result<()> {
        let reader_only = sub.get_flag("reader-only");
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
            working("Protecting your identity...", || {
                Keyring::create(&self.home, &passphrase)
            })?
        };

        if reader_only {
            // A device that reads but never writes. An empty writers file makes
            // it fail closed on a version 2 vault until a writer is pinned.
            if !home::exists(&self.home.writers_path()) {
                home::write_atomic(&self.home.writers_path(), b"", None)?;
            }
            eprintln!(
                "This device is provisioned to read only: no write key was created. Pin the \
                 writer of the device that writes with: txc vault writers --add <key>"
            );
            eprintln!("Your public key, for encrypting a vault to you:");
            return output(&keyring.public_key());
        }

        let mut keyring = keyring;
        let write_key = if self.home.has_writer() {
            eprintln!(
                "A write key already exists at {}.",
                self.home.writer_path().display()
            );
            self.write_key()?
        } else {
            self.provision_writer(&mut keyring)?
        };

        if self
            .home
            .vault_names()?
            .iter()
            .any(|name| name == DEFAULT_VAULT)
        {
            eprintln!("The vault {DEFAULT_VAULT} already exists.");
        } else {
            keyring.create_vault(DEFAULT_VAULT, &[], &write_key)?;
            eprintln!("Created the vault {DEFAULT_VAULT}.");
        }
        eprintln!("Your public key, for encrypting a vault to you on another device:");
        output(&keyring.public_key())
    }

    /// Creates and pins a write key, protected by its own passphrase.
    fn provision_writer(&self, keyring: &mut Keyring) -> Result<WriteKey> {
        eprintln!(
            "Creating your write key at {}.\n\
             This is a second passphrase, kept apart from the identity's. A job given \
             --passphrase-file can then read your vaults but cannot change them, because the \
             write passphrase is never read from that file.",
            self.home.writer_path().display()
        );
        let passphrase = self.write_passphrase.ask_new_write("Write passphrase: ")?;
        let write_key = crypto::new_write_key();
        let sealed = working("Protecting your write key...", || {
            crypto::seal_write_key(&write_key, &passphrase)
        })?;
        home::write_atomic(&self.home.writer_path(), &sealed, None)?;
        keyring.pin_writer(&crypto::writer_id_string(&crypto::writer_id(&write_key)))?;
        Ok(write_key)
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
        working("Protecting your identity...", || {
            keyring.change_passphrase(&passphrase)
        })?;
        eprintln!("Passphrase changed.");
        Ok(())
    }

    fn create(&self, sub: &ArgMatches) -> Result<()> {
        let name = required(sub, "NAME");
        check_vault_name(name)?;
        let recipients = many(sub, "recipient");
        let keyring = self.unlock()?;
        let write_key = self.write_key()?;
        keyring.create_vault(name, &recipients, &write_key)?;
        eprintln!("Created the vault {name}.");
        Ok(())
    }

    fn list(&self, sub: &ArgMatches) -> Result<()> {
        let vault = sub.get_one::<String>("VAULT");
        let tag = sub.get_one::<String>("tag");
        let kind = sub
            .get_one::<String>("kind")
            .map(|id| Kind::from_id(id).context("clap checked the kind"))
            .transpose()?;
        let favourites = sub.get_flag("favourites");
        let recent = sub.get_flag("recent");

        if vault.is_none() && tag.is_none() && kind.is_none() && !favourites && !recent {
            let names = self.home.vault_names()?;
            if names.is_empty() {
                eprintln!("There are no vaults yet; start with: txc vault init");
                return Ok(());
            }
            return output(&names.join("\n"));
        }
        if let Some(vault) = vault {
            check_vault_name(vault)?;
        }
        if let Some(tag) = tag {
            check_tag(tag)?;
        }

        let keyring = self.unlock()?;
        let names = match vault {
            Some(vault) => vec![vault.clone()],
            None => self.home.vault_names()?,
        };
        let mut opened: Vec<Opened> = Vec::new();
        for name in &names {
            match keyring.open(name) {
                Ok(vault) => opened.push(vault),
                // Across every vault, one that cannot be opened is reported
                // and passed over rather than hiding all the others.
                Err(error) if vault.is_none() => eprintln!("Skipped the vault {name}: {error:#}"),
                Err(error) => return Err(error),
            }
        }

        let wanted = |entry: &Entry| {
            tag.is_none_or(|tag| entry.tags.contains(tag))
                && kind.is_none_or(|kind| entry.kind == kind)
                && (!favourites || entry.favourite)
        };
        // With several vaults listed, each name says which vault it is in.
        let row = |vault: &Opened, entry: &Entry, detail: String| {
            let mut name = if names.len() > 1 {
                format!("{}/{}", vault.vault().name(), entry.name)
            } else {
                entry.name.clone()
            };
            if entry.favourite {
                name.push_str(" ★");
            }
            [name, entry.kind.id().to_string(), detail]
        };

        let rows: Vec<[String; 3]> = if recent {
            keyring
                .recent()
                .iter()
                .filter_map(|used| {
                    let vault = opened
                        .iter()
                        .find(|vault| vault.vault().name() == used.vault)?;
                    let entry = vault
                        .vault()
                        .entries()
                        .iter()
                        .find(|entry| entry.name == used.entry)?;
                    wanted(entry).then(|| row(vault, entry, ago(&used.at)))
                })
                .collect()
        } else {
            opened
                .iter()
                .flat_map(|vault| {
                    vault
                        .vault()
                        .entries()
                        .iter()
                        .filter(|entry| wanted(entry))
                        .map(move |entry| {
                            row(
                                vault,
                                entry,
                                entry.summary().unwrap_or_default().to_string(),
                            )
                        })
                })
                .collect()
        };

        if rows.is_empty() {
            eprintln!("No entries.");
            return Ok(());
        }
        output(&table(&rows))
    }

    fn add(&self, sub: &ArgMatches) -> Result<()> {
        let reference: Reference = required(sub, "ENTRY").parse()?;
        let kind = Kind::from_id(required(sub, "kind")).context("clap checked the kind")?;
        let plain = plain_fields(sub)?;
        let tags = checked_tags(sub, "tag")?;
        let secret_fields = checked_field_names(sub, "secret-field")?;
        check_sensitivities(kind, &plain, &secret_fields)?;
        let primary = main_spec(kind);
        if sub.get_flag("generate") {
            ensure!(
                primary.generator.is_some(),
                "the {} of {} cannot be generated; type it when asked, or pipe it in",
                primary.label.to_lowercase(),
                kind.label().to_lowercase()
            );
        }

        // Everything that can be checked is checked before any secret is typed,
        // and the write key is unlocked first, so a reader-only device stops
        // here rather than after a secret has been entered.
        let keyring = self.unlock()?;
        let write_key = self.write_key()?;
        let mut vault = keyring.open(&reference.vault)?;
        ensure!(
            vault.vault().entry(&reference.entry).is_none(),
            "there is already an entry named {:?} in the vault {}",
            reference.entry,
            reference.vault
        );

        let (secret, generated) = main_secret(sub, primary)?;
        let mut secrets = vec![(primary.name.to_string(), secret)];
        for name in secret_fields {
            let label = kind.spec(&name).map_or(name.as_str(), |spec| spec.label);
            let secret = prompt::secret_from_terminal(label)?;
            secrets.push((name, secret));
        }

        vault.add(NewEntry {
            name: reference.entry.clone(),
            kind,
            plain,
            secrets,
            tags,
            favourite: sub.get_flag("favourite"),
        })?;
        vault.save(&keyring, &write_key)?;

        eprintln!("Added {reference}.");
        if generated {
            eprintln!(
                "Its {} was generated; copy it with: txc vault copy {reference}",
                primary.label.to_lowercase()
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
            ["Name".to_string(), entry.name.clone()],
            ["Vault".to_string(), reference.vault.clone()],
            ["Kind".to_string(), entry.kind.label().to_string()],
        ];
        if entry.favourite {
            rows.push(["Favourite".to_string(), "★".to_string()]);
        }
        for field in &entry.fields {
            let shown = match entry.plain(&field.name) {
                Some(value) => value.to_string(),
                None => MASK.to_string(),
            };
            rows.push([entry.label(&field.name).to_string(), shown]);
        }
        if !entry.tags.is_empty() {
            rows.push(["Tags".to_string(), entry.tags.join(", ")]);
        }
        rows.push(["Created".to_string(), entry.created.clone()]);
        rows.push(["Updated".to_string(), entry.updated.clone()]);
        output(&table(&rows))
    }

    fn favourite(&self, sub: &ArgMatches) -> Result<()> {
        let reference: Reference = required(sub, "ENTRY").parse()?;
        let remove = sub.get_flag("remove");
        let keyring = self.unlock()?;
        let write_key = self.write_key()?;
        let mut vault = keyring.open(&reference.vault)?;
        let name = vault.entry(&reference.entry)?.name.clone();
        vault.set_favourite(&name, !remove)?;
        vault.save(&keyring, &write_key)?;
        if remove {
            eprintln!("Unstarred {reference}.");
        } else {
            eprintln!("Starred {reference}.");
        }
        Ok(())
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
        let label = entry.label(&field).to_lowercase();
        let secret = vault.reveal(&keyring, &entry_name, &field)?;
        if let Err(error) = keyring.record_use(&reference.vault, &entry_name) {
            eprintln!("Could not note this in the recently used list: {error:#}");
        }

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
            .context("clear-after has a default")?;
        let held = clipboard::copy(&secret)
            .map_err(|error| anyhow!("{error}; use --print to send it to a pipe instead"))?;
        drop(secret);
        wait_then_clear(held, seconds, &format!("{label} of {reference}"))
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
        let write_key = self.write_key()?;
        let mut vault = keyring.open(&reference.vault)?;
        let entry = vault.entry(&reference.entry)?;
        let (name, kind) = (entry.name.clone(), entry.kind);
        check_sensitivities(kind, &change.plain, &secret_fields)?;
        let primary = main_spec(kind);

        if new_main {
            if sub.get_flag("generate") {
                ensure!(
                    primary.generator.is_some(),
                    "the {} of {} cannot be generated",
                    primary.label.to_lowercase(),
                    kind.label().to_lowercase()
                );
            }
            let (secret, _) = main_secret(sub, primary)?;
            change.secrets.push((primary.name.to_string(), secret));
        }
        for field in secret_fields {
            let label = kind.spec(&field).map_or(field.as_str(), |spec| spec.label);
            let secret = prompt::secret_from_terminal(label)?;
            change.secrets.push((field, secret));
        }

        let renamed = change.rename.clone();
        vault.change(&name, change)?;
        vault.save(&keyring, &write_key)?;
        if let Some(new_name) = renamed {
            // The recent list is a convenience cache; failing to update it does
            // not undo the change that was already saved.
            keyring.rename_use(&reference.vault, &name, &new_name).ok();
        }
        eprintln!("Changed {reference}.");
        Ok(())
    }

    fn remove(&self, sub: &ArgMatches) -> Result<()> {
        let reference: Reference = required(sub, "ENTRY").parse()?;
        let keyring = self.unlock()?;
        let write_key = self.write_key()?;
        let mut vault = keyring.open(&reference.vault)?;
        let name = vault.entry(&reference.entry)?.name.clone();

        if !sub.get_flag("yes") {
            ensure!(
                prompt::confirm(&format!("Remove {reference}?"), "pass --yes")?,
                "nothing was removed"
            );
        }
        vault.remove(&name)?;
        vault.save(&keyring, &write_key)?;
        // The recent list is a convenience cache; the entry is already removed.
        keyring.forget_use(&reference.vault, &name).ok();
        eprintln!("Removed {reference}.");
        Ok(())
    }

    fn move_entry(&self, sub: &ArgMatches) -> Result<()> {
        let reference: Reference = required(sub, "ENTRY").parse()?;
        let dest = required(sub, "TO");
        check_vault_name(dest)?;

        let keyring = self.unlock()?;
        let write_key = self.write_key()?;
        let mut source = keyring.open(&reference.vault)?;
        let name = source.entry(&reference.entry)?.name.clone();
        keyring.move_entry(&mut source, dest, &name, &write_key)?;
        // The entry took its old reference with it; drop it from this device's
        // recent list, where it now points nowhere. Best effort: the move is done.
        keyring.forget_use(&reference.vault, &name).ok();
        eprintln!("Moved {name} to {dest}.");
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

        // The write key is unlocked only now, on the change path, so a plain
        // `recipients` listing above never asks for the write passphrase.
        let write_key = self.write_key()?;
        vault.set_recipients(&keyring, &others)?;
        vault.save(&keyring, &write_key)?;
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
        const TERMINAL_HINT: &str =
            "trust this vault at a terminal, or pass --expect <fingerprint>";

        let name = required(sub, "VAULT");
        check_vault_name(name)?;
        let keyring = self.unlock()?;
        let inspection = keyring.inspect(name)?;
        // `Standing` is cloned up front because trusting consumes the inspection.
        let standing = inspection.standing().clone();

        if standing == Standing::Trusted {
            eprintln!("The vault {name} is already trusted on this device.");
            return Ok(());
        }

        let fingerprint = inspection.vault().fingerprint();
        let own = keyring.public_key();
        eprintln!("{}.", capitalise(&standing.describe(name)));
        eprintln!("  fingerprint  {fingerprint}");
        eprintln!("  generation   {}", inspection.vault().generation());
        eprintln!("  entries      {}", inspection.vault().entries().len());
        eprintln!("  updated      {}", inspection.vault().updated());
        if matches!(standing, Standing::Diverged { .. }) {
            let mut backup = keyring.home().vault_path(name)?.into_os_string();
            backup.push(".bak");
            eprintln!(
                "  the version this device wrote is kept at {}",
                Path::new(&backup).display()
            );
        }
        eprintln!("  encrypted to:");
        for key in inspection.vault().recipients() {
            let marker = if *key == own { "  (you)" } else { "" };
            eprintln!("    {key}{marker}");
        }

        // A fingerprint answers "is this my vault", nothing more, so it may
        // settle a vault whose identity was in question, but never a rollback,
        // a recipient change or a divergence.
        if let Some(expected) = sub.get_one::<String>("expect") {
            ensure!(
                matches!(
                    standing,
                    Standing::Unknown | Standing::Replaced | Standing::KeyChanged
                ),
                "a fingerprint cannot settle this ({}); trust it at a terminal, or \
                 re-provision trust.json from the device that made the change",
                standing.describe(name)
            );
            ensure!(
                prompt::fingerprints_match(expected, &fingerprint),
                "the vault's fingerprint is {fingerprint}, not what was expected; \
                 nothing was trusted"
            );
            keyring.trust_vault(inspection)?;
            eprintln!("Trusted the vault {name}.");
            return Ok(());
        }

        // No --expect: --yes bootstraps a never-seen vault; anything else is
        // accepted at a terminal, a new vault with y/N and a changed one by
        // typing its fingerprint.
        if standing == Standing::Unknown {
            if !sub.get_flag("yes") {
                ensure!(
                    prompt::confirm(
                        "Trust this vault on this device, as it is now?",
                        TERMINAL_HINT
                    )?,
                    "the vault was not trusted"
                );
            }
        } else {
            ensure!(
                prompt::confirm_value(
                    "Type the fingerprint above to trust it:",
                    &fingerprint,
                    TERMINAL_HINT
                )?,
                "the fingerprint did not match; nothing was trusted"
            );
        }
        keyring.trust_vault(inspection)?;
        eprintln!("Trusted the vault {name}.");
        Ok(())
    }

    fn fingerprint(&self, sub: &ArgMatches) -> Result<()> {
        let name = required(sub, "VAULT");
        check_vault_name(name)?;
        let keyring = self.unlock()?;
        // inspect, not open, so it works on a vault whose standing is bad,
        // which is exactly when the fingerprint is needed.
        let inspection = keyring.inspect(name)?;
        output(&format!("{name}  {}", inspection.vault().fingerprint()))
    }

    fn history(&self, sub: &ArgMatches) -> Result<()> {
        let name = required(sub, "VAULT");
        check_vault_name(name)?;
        let keyring = self.unlock()?;
        let decisions = keyring.trust_history(name)?;
        if decisions.is_empty() {
            eprintln!("No trust decisions recorded for {name} on this device.");
            return Ok(());
        }
        output(&decisions.join("\n"))
    }

    /// Prints this device's writer public key and its fingerprint, for pinning
    /// on another device.
    fn writer(&self) -> Result<()> {
        let write_key = self.write_key()?;
        let id = crypto::writer_id(&write_key);
        output(&format!(
            "{}  {}",
            crypto::writer_id_string(&id),
            crypto::fingerprint(id.as_bytes())
        ))
    }

    /// Lists, pins or unpins the writer keys this device trusts.
    fn writers(&self, sub: &ArgMatches) -> Result<()> {
        let mut keyring = self.unlock()?;
        if let Some(key) = sub.get_one::<String>("add") {
            crypto::parse_writer_id(key)?;
            if !sub.get_flag("yes") {
                ensure!(
                    prompt::confirm(
                        &format!("Pin the writer {key}, so vaults it signs will open here?"),
                        "pass --yes"
                    )?,
                    "nothing was pinned"
                );
            }
            if keyring.pin_writer(key)? {
                eprintln!("Pinned the writer.");
            } else {
                eprintln!("That writer was already pinned.");
            }
            return Ok(());
        }
        if let Some(key) = sub.get_one::<String>("remove") {
            if !sub.get_flag("yes") {
                ensure!(
                    prompt::confirm(
                        &format!(
                            "Unpin the writer {key}? Vaults it signed will no longer open here."
                        ),
                        "pass --yes"
                    )?,
                    "nothing was unpinned"
                );
            }
            if keyring.unpin_writer(key)? {
                eprintln!("Unpinned the writer.");
            } else {
                eprintln!("That writer was not pinned.");
            }
            return Ok(());
        }
        let lines: Vec<String> = keyring
            .writers()
            .iter()
            .map(|id| {
                format!(
                    "{}  {}",
                    crypto::writer_id_string(id),
                    crypto::fingerprint(id.as_bytes())
                )
            })
            .collect();
        if lines.is_empty() {
            eprintln!("No writers are pinned on this device.");
            return Ok(());
        }
        output(&lines.join("\n"))
    }

    /// Re-signs vaults still in the old format as the current one, without any
    /// other change.
    fn upgrade(&self, sub: &ArgMatches) -> Result<()> {
        let keyring = self.unlock()?;
        let write_key = self.write_key()?;
        let names = match sub.get_one::<String>("VAULT") {
            Some(name) => {
                check_vault_name(name)?;
                vec![name.clone()]
            }
            None => keyring.home().vault_names()?,
        };
        let mut upgraded = 0u32;
        for name in names {
            let mut opened = keyring.open(&name)?;
            if opened.vault().needs_upgrade() {
                opened.save(&keyring, &write_key)?;
                upgraded = upgraded.saturating_add(1);
                eprintln!("Upgraded {name}.");
            }
        }
        if upgraded == 0 {
            eprintln!("Every vault is already in the current format.");
        }
        Ok(())
    }

    /// Deletes a vault, keeping its last version as a `.deleted` recovery file.
    fn delete(&self, sub: &ArgMatches) -> Result<()> {
        let name = required(sub, "VAULT");
        check_vault_name(name)?;
        let keyring = self.unlock()?;
        // Require the write key, as every mutation does. Deletion produces no
        // vault file, so the signature check cannot cover it; this is a policy
        // gate that stops accidents and keeps a reader-only device from changing
        // the vault store. It does not stop an attacker, who has `rm`.
        let _write_key = self.write_key()?;
        // Open first, so a vault that is untrusted or fails its signature cannot
        // be deleted through the command; the error names the file to remove by
        // hand, and there is deliberately no --force that deletes by path.
        let opened = keyring.open(name)?;
        let count = opened.vault().entries().len();
        eprintln!(
            "The vault {name} holds {count} {}.",
            if count == 1 { "entry" } else { "entries" }
        );
        if !sub.get_flag("yes") {
            ensure!(
                prompt::confirm_value(
                    &format!("Type the vault's name to delete it: {name}"),
                    name,
                    "pass --yes"
                )?,
                "the vault was not deleted"
            );
        }
        keyring.delete_vault(&opened)?;

        let live = keyring.home().vault_path(name)?;
        let recovery = live.with_extension("age.deleted");
        eprintln!("Deleted {name}. Its last version is kept, still encrypted, at:");
        eprintln!("  {}", recovery.display());
        eprintln!("Restore it with:");
        eprintln!("  mv {} {}", recovery.display(), live.display());
        Ok(())
    }

    /// Seals one secret to another key as a grant, so a host can be given that
    /// one secret without the identity. A read operation: it needs no write key.
    fn grant(&self, sub: &ArgMatches) -> Result<()> {
        ensure!(
            !io::stdout().is_terminal(),
            "a grant is written to a file or a pipe, not the terminal where it would linger in \
             the scrollback; redirect it, as: txc vault grant <entry> --to age1... > deploy.grant"
        );
        let reference: Reference = required(sub, "ENTRY").parse()?;
        let to = sub.get_one::<String>("to");
        let to_file = sub.get_flag("to-file");
        ensure!(
            to.is_some() ^ to_file,
            "give --to <recipient> to seal to a host's own key, or --to-file to bundle a fresh \
             key in the grant (which then is the secret); not both"
        );
        let expires = match sub.get_one::<String>("expires") {
            Some(spec) => Some(grant::expiry_from(spec)?),
            None => None,
        };

        let keyring = self.unlock()?;
        let vault = keyring.open(&reference.vault)?;
        let entry = vault.entry(&reference.entry)?;
        let field = sub
            .get_one::<String>("field")
            .cloned()
            .unwrap_or_else(|| entry.kind.primary().to_string());
        let entry_name = entry.name.clone();
        let label = format!("{}/{entry_name}.{field}", reference.vault);
        let secret = vault.reveal(&keyring, &entry_name, &field)?;

        // For --to, seal to the host's own public key, so the grant file at rest
        // is useless to anyone else. For --to-file, bundle a fresh key.
        let ephemeral = to_file.then(crypto::new_identity);
        let (recipient_text, recipient) = match (&to, &ephemeral) {
            (Some(key), _) => ((*key).clone(), crypto::parse_recipient(key)?),
            (None, Some(id)) => {
                let key = id.to_public().to_string();
                let recipient = crypto::parse_recipient(&key)?;
                (key, recipient)
            }
            (None, None) => unreachable!("checked above"),
        };
        let grant = Grant::issue(
            &label,
            &secret,
            &recipient,
            &recipient_text,
            expires,
            ephemeral.as_ref(),
        )?;
        drop(secret);
        if to_file {
            eprintln!(
                "This grant bundles the key that opens it, so the file is equivalent to the \
                 secret. Keep it as you would the secret, and prefer --to <recipient> when you can."
            );
        }
        eprintln!(
            "A grant is a snapshot and cannot be revoked: it will not follow later edits, and \
             deleting your copy changes nothing. Rotate the secret to revoke access."
        );
        output(&grant.to_json()?)
    }

    /// Opens one grant, printing the secret to a pipe. Needs no identity of its
    /// own beyond the host key that the grant was sealed to, so it uses nothing
    /// from the session; it stays a method for a uniform command dispatch.
    #[allow(clippy::unused_self)]
    fn redeem(&self, sub: &ArgMatches) -> Result<()> {
        ensure!(
            !io::stdout().is_terminal(),
            "redeem writes the secret to a pipe, not the terminal; use it as: \
             export KEY=\"$(txc vault redeem deploy.grant --identity host.key)\""
        );
        let file = required(sub, "FILE");
        let text = std::fs::read_to_string(file)
            .with_context(|| format!("cannot read the grant {file}"))?;
        let grant = Grant::from_json(&text)?;
        let secret = if let Some(path) = sub.get_one::<String>("identity") {
            let key = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read the identity {path}"))?;
            grant.redeem(&crypto::parse_identity(&key)?)?
        } else {
            ensure!(
                grant.is_bundled(),
                "this grant was sealed to a host key; give that key with --identity <path>"
            );
            grant.redeem_bundled()?
        };

        let mut stdout = io::stdout().lock();
        let written = stdout
            .write_all(secret.expose_secret().as_bytes())
            .and_then(|()| stdout.flush());
        match written {
            Err(error) if error.kind() != io::ErrorKind::BrokenPipe => Err(error.into()),
            _ => Ok(()),
        }
    }
}

/// The definition of a kind's main secret field.
fn main_spec(kind: Kind) -> &'static FieldSpec {
    // Every kind's primary field is one of its own defined fields.
    #[allow(clippy::expect_used)]
    kind.spec(kind.primary())
        .expect("every kind defines its main field")
}

/// Refuses a secret field given as a plain value, and a plain one asked for
/// as a secret, before anything is unlocked or typed.
fn check_sensitivities(
    kind: Kind,
    plain: &[(String, String)],
    secret_fields: &[String],
) -> Result<()> {
    for (name, _) in plain {
        if let Some(spec) = kind.spec(name) {
            ensure!(
                !spec.sensitivity.is_sealed(),
                "the {} of {} is secret, so it is not taken as an argument, where other \
                 programs could see it; use --secret-field {name} to be asked for it",
                spec.label.to_lowercase(),
                kind.label().to_lowercase()
            );
        }
    }
    for name in secret_fields {
        if let Some(spec) = kind.spec(name) {
            ensure!(
                spec.sensitivity.is_sealed(),
                "the {} of {} is not secret; give it with --field {name}=VALUE",
                spec.label.to_lowercase(),
                kind.label().to_lowercase()
            );
        }
    }
    Ok(())
}

/// The main secret for `add` or `edit`: generated, piped in, or typed.
fn main_secret(sub: &ArgMatches, spec: &FieldSpec) -> Result<(SecretString, bool)> {
    if sub.get_flag("generate") {
        let secret = if spec.generator == Some(Generator::Pin) {
            generate_pin(PIN_LENGTH)
        } else {
            let length = *sub
                .get_one::<u64>("length")
                .context("length has a default")?;
            let length = usize::try_from(length).context("the length is at most 128")?;
            generate(length, !sub.get_flag("no-symbols"))
        };
        Ok((secret, true))
    } else if sub.get_flag("secret-from-stdin") {
        Ok((prompt::secret_from_stdin()?, false))
    } else {
        if spec.multiline {
            eprintln!(
                "Type the {} on one line, or pipe it in with --secret-from-stdin to keep \
                 several lines.",
                spec.label.to_lowercase()
            );
        }
        Ok((prompt::secret_from_terminal(spec.label)?, false))
    }
}

/// A random password with at least one character of every class it draws
/// from, so sites with composition rules take it.
///
/// It is built in a string allocated once at its final size, so no partial
/// copy is left behind, and a draw missing a class is wiped before the next.
// `random_range(0..alphabet.len())` yields a valid index into `alphabet`.
#[allow(clippy::indexing_slicing)]
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

/// A random PIN of `length` digits.
///
/// ```
/// use age::secrecy::ExposeSecret;
///
/// let pin = txc::vault::command::generate_pin(4);
/// assert_eq!(pin.expose_secret().len(), 4);
/// assert!(pin.expose_secret().bytes().all(|b| b.is_ascii_digit()));
/// ```
// `b'0' + 0..10` stays within a byte, so the addition cannot overflow.
#[allow(clippy::arithmetic_side_effects)]
#[must_use]
pub fn generate_pin(length: usize) -> SecretString {
    let mut rng = rand::rng();
    let mut pin = String::with_capacity(length);
    for _ in 0..length {
        pin.push(char::from(b'0' + rng.random_range(0..10_u8)));
    }
    SecretString::from(pin)
}

/// Waits for the time to run out, a key, or the clipboard to be taken over,
/// then clears the secret if it is still there.
fn wait_then_clear(held: Held, seconds: u64, what: &str) -> Result<()> {
    // A few seconds added to the current instant cannot overflow a real clock.
    #[allow(clippy::arithmetic_side_effects)]
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
            terminal::disable_raw_mode().ok();
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
    // Only ever called for arguments clap marks required, which are always set.
    #[allow(clippy::expect_used)]
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
// `index` runs over a row of exactly N cells, so `index + 1` cannot overflow and
// `widths[index]` is always in range.
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
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
                    write!(line, "{cell:<width$}  ", width = widths[index]).ok();
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
    fn the_help_for_add_names_every_kind_and_marks_secret_fields() {
        let help = kinds_help();
        for kind in Kind::ALL {
            assert!(
                help.contains(kind.id()),
                "{} is missing:\n{help}",
                kind.id()
            );
        }
        assert!(help.contains("number*, cardholder, expiry, cvv*"), "{help}");
    }

    #[test]
    fn a_secret_field_given_as_an_argument_is_refused_before_unlocking() {
        let plain = vec![("cvv".to_string(), "123".to_string())];
        let error = check_sensitivities(Kind::Card, &plain, &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("--secret-field cvv"), "{error}");
        assert!(check_sensitivities(Kind::Card, &[], &["expiry".to_string()]).is_err());
        assert!(check_sensitivities(Kind::Card, &[], &["cvv".to_string()]).is_ok());
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
            "write-passphrase-file",
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
            "expect",
            "to",
            "expires",
            "identity",
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
