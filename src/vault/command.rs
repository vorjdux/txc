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
use crate::vault::synced::{self, Synced};
use crate::vault::synced_command;
use crate::vault::{Change, Home, Keyring, NewEntry, Opened, Standing, harden, session};

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

    let vault = Command::new("vault")
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
            Arg::new("no-session")
                .long("no-session")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Ask for the passphrase even when a session is open (see: txc vault unlock)"),
        )
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
                        .conflicts_with("folder")
                        .help("Create only an identity and an empty writers list, for an unattended reader"),
                )
                .arg(
                    Arg::new("folder")
                        .long("folder")
                        .value_name("DIR")
                        .help("Create a synced vault in this sync folder, to share between your devices"),
                )
                .arg(
                    Arg::new("name")
                        .long("name")
                        .value_name("VAULT")
                        .requires("folder")
                        .help("The synced vault's name (default: personal)"),
                ),
        )
        .subcommand(
            Command::new("unlock")
                .about("Unlock once and keep the vaults open for a while, across commands")
                .long_about(
                    "Unlock once and keep the vaults open for a while, across commands.\n\n\
                     The identity is sealed under a random session key kept where only this \
                     login can reach it: the kernel keyring on Linux, the Keychain on macOS, \
                     DPAPI on Windows. The session ends after it has been idle, at its time \
                     limit, when the computer sleeps, or with: txc vault lock. It never holds \
                     the write key, so changing a vault still asks for the write passphrase.",
                )
                .arg(
                    Arg::new("idle")
                        .long("idle")
                        .value_name("MINUTES")
                        .value_parser(clap::value_parser!(u64).range(1..=1440))
                        .default_value("15")
                        .help("End the session after this many minutes without use"),
                )
                .arg(
                    Arg::new("max")
                        .long("max")
                        .value_name("HOURS")
                        .value_parser(clap::value_parser!(u64).range(1..=24))
                        .default_value("8")
                        .help("End the session after this many hours whatever happens"),
                ),
        )
        .subcommand(Command::new("lock").about("End the session that txc vault unlock opened"))
        .subcommand(
            Command::new("import")
                .about("Bring in entries from another password manager or a .env file")
                .long_about(
                    "Bring in entries from another password manager or a .env file.\n\n\
                     Understood: a Bitwarden JSON export (unencrypted), a CSV with a header row \
                     as 1Password, KeePassXC, Bitwarden, LastPass, Chrome and Firefox write, and \
                     .env files, where each NAME=value becomes a secret named NAME. A summary is \
                     shown first; --dry-run stops there. Hidden values are kept as secrets, \
                     folders become tags, and names that clash are numbered.\n\n\
                     The export file holds every secret in the clear: --remove-source overwrites \
                     it once and deletes it afterwards. On SSDs, in synced folders and in backups \
                     copies can remain, so export to a place that is none of those.",
                )
                .arg(Arg::new("FILE").required(true).help("The export to read"))
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_name("FORMAT")
                        .value_parser(["bitwarden", "csv", "env"])
                        .help("The file's format, when the name does not show it"),
                )
                .arg(
                    Arg::new("into")
                        .long("into")
                        .value_name("VAULT")
                        .default_value(DEFAULT_VAULT)
                        .help("The vault to add the entries to"),
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .help("Show what would be imported, and change nothing"),
                )
                .arg(
                    Arg::new("remove-source")
                        .long("remove-source")
                        .action(ArgAction::SetTrue)
                        .help("Overwrite and delete the export once it is imported"),
                ),
        )
        .subcommand(
            Command::new("export")
                .about("Write a copy of vaults as one age file, readable with age -d")
                .long_about(
                    "Write a copy of vaults as one age file, readable with age -d.\n\n\
                     The file is encrypted to the public keys given with --to, such as a backup \
                     key kept offline, and holds every entry and every secret as JSON. Anyone \
                     with one of those keys can read it with nothing but age: \
                     age -d -i key.txt export.age. Every vault is exported unless some are \
                     named.\n\n\
                     --plaintext writes the JSON unencrypted instead, and asks you to type a \
                     confirmation first; keep such a file off synced folders and delete it \
                     soon.",
                )
                .arg(
                    Arg::new("VAULT")
                        .num_args(0..)
                        .help("The vaults to export (default: all)"),
                )
                .arg(
                    Arg::new("to")
                        .long("to")
                        .value_name("RECIPIENT")
                        .action(ArgAction::Append)
                        .help("An age public key to encrypt the copy to (age1...)"),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .value_name("FILE")
                        .help("Write to this new file rather than to standard output"),
                )
                .arg(
                    Arg::new("plaintext")
                        .long("plaintext")
                        .action(ArgAction::SetTrue)
                        .conflicts_with("to")
                        .help("Write unencrypted JSON, after a typed confirmation"),
                ),
        )
        .subcommand(
            Command::new("run")
                .about("Run a program with secrets in its environment or as files, never in your shell")
                .long_about(
                    "Run a program with secrets in its environment or as files, never in your \
                     shell.\n\n\
                     References come from a template, .env.txc in the current directory unless \
                     --env-file names others, and from --set. A template reads like a .env file \
                     and is safe to commit, because it holds references, not secrets:\n\n  \
                     DATABASE_URL=txc://work/db\n  \
                     DATABASE_PASSWORD=txc://work/db/password\n  \
                     TLS_KEY=txc+file://work/tls/key\n  \
                     LOG_LEVEL=debug\n\n\
                     txc://VAULT/ENTRY puts the entry's main secret, or with /FIELD a named \
                     field, in the program's environment. txc+file:// gives the program a path \
                     to open instead, for programs that read keys and certificates from files: a \
                     sealed in-memory file on Linux, a pipe on macOS, a named pipe only you can \
                     open on Windows. Nothing is written to disk, nothing reaches this shell, and \
                     the program's exit code is passed on.",
                )
                .arg(
                    Arg::new("env-file")
                        .long("env-file")
                        .value_name("FILE")
                        .action(ArgAction::Append)
                        .help("A template of references (default: .env.txc here, if it exists)"),
                )
                .arg(
                    Arg::new("set")
                        .long("set")
                        .value_name("NAME=txc://VAULT/ENTRY")
                        .action(ArgAction::Append)
                        .help("One more variable; only references are accepted, never values"),
                )
                .arg(
                    Arg::new("COMMAND")
                        .required(true)
                        .num_args(1..)
                        .trailing_var_arg(true)
                        .allow_hyphen_values(true)
                        .value_name("COMMAND")
                        .help("The program and its arguments, after --"),
                ),
        )
        .subcommand(
            Command::new("identity")
                .about("Print your public key, for encrypting a vault to you elsewhere"),
        )
        .subcommand(
            Command::new("passwd")
                .about("Change the passphrase of your identity and of the synced vaults it opens")
                .arg(
                    Arg::new("vault")
                        .long("vault")
                        .value_name("VAULT")
                        .help("Change only this synced vault's passphrase"),
                )
                .arg(
                    Arg::new("new-passphrase-file")
                        .long("new-passphrase-file")
                        .value_name("PATH")
                        .help("Read the new passphrase from a file rather than asking"),
                ),
        )
        .subcommand(
            Command::new("create")
                .about("Create a new, empty vault; with --folder, a synced one shared between your devices")
                .arg(
                    Arg::new("NAME")
                        .required(true)
                        .help("Lowercase letters, digits, - and _"),
                )
                .arg(many(
                    "recipient",
                    "AGE_KEY",
                    "Also encrypt to this public key, such as another device's",
                ))
                .arg(
                    Arg::new("folder")
                        .long("folder")
                        .value_name("DIR")
                        .conflicts_with("recipient")
                        .help("Make it a synced vault in this sync folder, shared between your devices"),
                ),
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
                )
                .arg(
                    Arg::new("removed")
                        .long("removed")
                        .action(ArgAction::SetTrue)
                        .requires("VAULT")
                        .conflicts_with_all(["favourites", "recent", "kind", "tag"])
                        .help("Entries of a synced vault removed in the last 30 days, which txc vault restore brings back"),
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
            .arg(
                Arg::new("protect")
                    .long("protect")
                    .action(ArgAction::SetTrue)
                    .help(
                        "Seal it to security keys: each use needs a touch, and it goes only to \
                         programs as a file (synced vaults)",
                    ),
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
            Command::new("join")
                .about("Join a synced vault from another of your devices")
                .long_about(
                    "Join a synced vault from another of your devices.\n\n\
                     On a device that can add devices, run txc vault device add; each side then \
                     shows a line to paste into the other, twice, and a six-digit code. Type the \
                     code the other screen shows. The vault's folder must be synced here first.",
                )
                .arg(Arg::new("folder").long("folder").value_name("DIR").required(true).help("This device's copy of the vault's folder"))
                .arg(Arg::new("name").long("name").value_name("VAULT").help("The name for the vault here (default: personal)")),
        )
        .subcommand(
            Command::new("device")
                .about("Add, list and remove the devices of a synced vault")
                .subcommand_required(true)
                .subcommand(
                    Command::new("add")
                        .about("Pair a new device; it runs txc vault join")
                        .arg(Arg::new("vault").long("vault").value_name("VAULT").help("The synced vault"))
                        .arg(
                            Arg::new("role")
                                .long("role")
                                .value_name("ROLE")
                                .value_parser(["writer", "reader"])
                                .default_value("writer")
                                .help("What the device may do: read and write, or view only"),
                        ),
                )
                .subcommand(
                    Command::new("list")
                        .about("List the devices")
                        .arg(Arg::new("vault").long("vault").value_name("VAULT").help("The synced vault")),
                )
                .subcommand(
                    Command::new("approve")
                        .about("Approve what waits for you: renewals, and security keys other devices added")
                        .arg(Arg::new("vault").long("vault").value_name("VAULT").help("The synced vault"))
                        .arg(Arg::new("yes").long("yes").action(ArgAction::SetTrue).help("Approve all without asking")),
                )
                .subcommand(
                    Command::new("remove")
                        .about("Remove a device; it reads nothing written afterwards")
                        .arg(Arg::new("DEVICE").required(true).help("The device, by the start of its id"))
                        .arg(Arg::new("vault").long("vault").value_name("VAULT").help("The synced vault"))
                        .arg(Arg::new("yes").long("yes").action(ArgAction::SetTrue).help("Do not ask first")),
                ),
        )
        .subcommand(
            Command::new("status")
                .about("Read what other devices wrote, and show what is fine and what needs you")
                .arg(Arg::new("VAULT").help("The synced vault"))
                .arg(
                    Arg::new("all")
                        .long("all")
                        .action(ArgAction::SetTrue)
                        .help("Also show what this system cannot protect, and the lines folded into one"),
                ),
        )
        .subcommand(
            Command::new("ssh-ca")
                .about("Make an SSH certificate authority whose key never leaves txc")
                .arg(reference()),
        )
        .subcommand(
            Command::new("ssh")
                .about("Connect with a fresh key and a certificate that lives for minutes")
                .long_about(
                    "Connect with a fresh key and a certificate that lives for minutes.\n\n\
                     txc signs a new key for this connection with the vault's SSH certificate \
                     authority and hands both to ssh as in-memory files; nothing is written to \
                     disk and no agent runs. Servers trust the authority once; --setup prints \
                     how. Anything after -- goes to ssh.",
                )
                .arg(Arg::new("HOST").help("The host, as ssh takes it"))
                .arg(Arg::new("ARGS").num_args(0..).last(true).help("More arguments for ssh"))
                .arg(Arg::new("vault").long("vault").value_name("VAULT").help("The synced vault"))
                .arg(Arg::new("ca").long("ca").value_name("ENTRY").help("The certificate authority, when there are several"))
                .arg(Arg::new("user").long("user").value_name("LOGIN").help("The login the certificate is for (default: yours)"))
                .arg(
                    Arg::new("minutes")
                        .long("minutes")
                        .value_name("N")
                        .value_parser(value_parser!(u64).range(1..=60))
                        .help("How long the certificate lives (default: 5)"),
                )
                .arg(
                    Arg::new("setup")
                        .long("setup")
                        .action(ArgAction::SetTrue)
                        .help("Print the line servers need, and the authority's public key"),
                ),
        )
        .subcommand(
            Command::new("keyholder")
                .about("Hold one synced vault's keys for the interactive screen")
                .hide(true),
        )
        .subcommand(
            Command::new("breach")
                .about("Check passwords against a breach list, offline")
                .long_about(
                    "Check passwords against a breach list, offline.\n\n\
                     Download the Pwned Passwords SHA-1 list (haveibeenpwned.com/Passwords) \
                     yourself, then import it once: it becomes a filter in the txc home, about \
                     1.2 GB for the whole list, and needs that much memory while importing. \
                     Nothing is ever sent anywhere. A match is probably, not certainly, breached.",
                )
                .subcommand_required(true)
                .subcommand(
                    Command::new("import")
                        .about("Import a Pwned Passwords SHA-1 list, HASH or HASH:COUNT per line")
                        .arg(Arg::new("FILE").required(true)),
                )
                .subcommand(
                    Command::new("check")
                        .about("List the entries whose password is in the imported list")
                        .arg(Arg::new("VAULT").help("The synced vault")),
                ),
        )
        .subcommand(
            Command::new("hardware")
                .about("Keep this device's keys behind a security key, the Secure Enclave or a TPM")
                .long_about(
                    "Keep this device's keys behind a security key, the Secure Enclave or a TPM.\n\n\
                     The hardware reaches txc through its age plugin, such as age-plugin-yubikey or \
                     age-plugin-se. Make an identity with that plugin first; txc then seals this \
                     device's second key factor to it, so unlocking needs the passphrase and the \
                     hardware. Plugins are pinned by path and hash, and never looked up again.",
                )
                .subcommand_required(true)
                .subcommand(
                    Command::new("add")
                        .about("Seal this device's second factor to hardware")
                        .arg(Arg::new("vault").long("vault").value_name("VAULT").help("The synced vault"))
                        .arg(
                            Arg::new("recipient")
                                .long("recipient")
                                .value_name("RECIPIENT")
                                .required(true)
                                .help("The hardware's public side, such as age1yubikey1... or age1tagpq1..."),
                        )
                        .arg(
                            Arg::new("identity-file")
                                .long("identity-file")
                                .value_name("FILE")
                                .required(true)
                                .help("The plugin identity file the hardware's plugin wrote (AGE-PLUGIN-...)"),
                        )
                        .arg(
                            Arg::new("recipient-plugin")
                                .long("recipient-plugin")
                                .value_name("PATH")
                                .help("The plugin for the recipient, rather than the one on PATH now"),
                        )
                        .arg(
                            Arg::new("identity-plugin")
                                .long("identity-plugin")
                                .value_name("PATH")
                                .help("The plugin for the identity, rather than the one on PATH now"),
                        )
                        .arg(
                            Arg::new("name")
                                .long("name")
                                .value_name("NICKNAME")
                                .help("What to call it where other devices show it (default: security key)"),
                        ),
                )
                .subcommand(
                    Command::new("rewrap")
                        .about("Seal protected entries again to every security key registered now")
                        .arg(Arg::new("vault").long("vault").value_name("VAULT").help("The synced vault")),
                )
                .subcommand(
                    Command::new("pin")
                        .about("Pin a plugin, to seal protected entries to other devices' hardware")
                        .arg(Arg::new("NAME").required(true).help("The plugin's name: tagpq for age-plugin-tagpq"))
                        .arg(Arg::new("path").long("path").value_name("PATH").help("Its binary, rather than the one on PATH now"))
                        .arg(Arg::new("vault").long("vault").value_name("VAULT").help("The synced vault")),
                ),
        )
        .subcommand(
            Command::new("compare")
                .about("Show digests to compare with another device, to see you share one history")
                .arg(Arg::new("VAULT").help("The synced vault")),
        )
        .subcommand(
            Command::new("doctor")
                .about("Print a diagnostic report for a bug report; it holds no secret and no entry name")
                .arg(Arg::new("VAULT").help("The synced vault")),
        )
        .subcommand(
            Command::new("recovery")
                .about("Write down the recovery sheets, check one, rehearse or restore")
                .subcommand_required(true)
                .subcommand(
                    Command::new("print")
                        .about("Show the three sheets and the card, one at a time, to write down")
                        .arg(Arg::new("VAULT").help("The synced vault")),
                )
                .subcommand(
                    Command::new("check")
                        .about("Check one sheet and the card against the vault")
                        .arg(Arg::new("VAULT").help("The synced vault")),
                )
                .subcommand(
                    Command::new("drill")
                        .about("Rehearse a full recovery with two sheets and the card, keeping nothing")
                        .arg(Arg::new("VAULT").help("The synced vault")),
                )
                .subcommand(
                    Command::new("reissue")
                        .about("Replace the sheets and the card, after one was lost or seen by someone else")
                        .long_about(
                            "Replace the sheets and the card, after one was lost or seen by \
                             someone else.\n\n\
                             Two of the current sheets and the card sign new ones; from then on \
                             the old ones sign nothing and read nothing written afterwards. At a \
                             terminal they are asked for one at a time; otherwise they are read \
                             from standard input, one per line. Write the new ones down with \
                             txc vault recovery print.",
                        )
                        .arg(Arg::new("VAULT").help("The synced vault")),
                )
                .subcommand(
                    Command::new("restore")
                        .about("Rebuild a vault from its folder with two sheets and the card, after losing every device")
                        .long_about(
                            "Rebuild a vault from its folder with two sheets and the card, after \
                             losing every device.\n\n\
                             The old folder is only read. The entries go into a new vault in a new, \
                             empty folder, with new recovery sheets; protected entries come back \
                             as normal ones until a security key is added. At a terminal the \
                             sheets and card are asked for one at a time; otherwise they are read \
                             from standard input, one per line.",
                        )
                        .arg(Arg::new("VAULT").required(true).help("The name of the restored vault"))
                        .arg(
                            Arg::new("from")
                                .long("from")
                                .value_name("DIR")
                                .required(true)
                                .help("The old vault's sync folder, or a copy of it"),
                        )
                        .arg(
                            Arg::new("folder")
                                .long("folder")
                                .value_name("DIR")
                                .required(true)
                                .help("A new, empty folder for the restored vault"),
                        ),
                ),
        )
        .subcommand(
            Command::new("resolve")
                .about("Show the two versions of an entry edited on two devices at once, and keep one")
                .arg(reference())
                .arg(Arg::new("field").long("field").value_name("NAME").help("The field to settle"))
                .arg(
                    Arg::new("keep")
                        .long("keep")
                        .value_name("NUMBER")
                        .value_parser(value_parser!(usize))
                        .requires("field")
                        .help("The version to keep, as numbered when shown"),
                ),
        )
        .subcommand(
            Command::new("migrate")
                .about("Copy a vault into a synced vault, to share it between devices; the original stays as it is")
                .arg(Arg::new("VAULT").required(true).help("The vault to copy"))
                .arg(Arg::new("folder").long("folder").value_name("DIR").help("The sync folder, when the synced vault is new"))
                .arg(Arg::new("name").long("name").value_name("VAULT").help("The synced vault (default: the same name)")),
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
            Command::new("restore")
                .about("Bring back an entry removed from a synced vault in the last 30 days")
                .long_about(
                    "Bring back an entry removed from a synced vault in the last 30 days.\n\n\
                     The removed entries are listed by: txc vault list VAULT --removed",
                )
                .arg(reference()),
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
                .about("Print this device's writer public key, or rotate the write key")
                .arg(
                    Arg::new("rotate")
                        .long("rotate")
                        .action(ArgAction::SetTrue)
                        .help("Replace the write key with a fresh one and re-sign every vault"),
                ),
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
                .about("Re-sign vaults of txc 0.6 or older in this format; to share vaults between devices see migrate")
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
                )
                .arg(
                    Arg::new("origin")
                        .long("origin")
                        .value_name("TEXT")
                        .help("Where it may be used, signed into a grant from a synced vault"),
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
                )
                .arg(
                    Arg::new("vault-id")
                        .long("vault-id")
                        .value_name("ID")
                        .help("For a grant from a synced vault: the vault id this runner trusts"),
                )
                .arg(
                    Arg::new("min-version")
                        .long("min-version")
                        .value_name("VERSION")
                        .value_parser(value_parser!(u64))
                        .help("For a grant from a synced vault: refuse older versions of the secret"),
                ),
        );
    group_advanced(vault)
}

/// Commands about the details of today's vault format, grouped under
/// `txc vault advanced` so the everyday surface stays small. Their old
/// top-level spellings stay as hidden aliases, so scripts keep working.
const ADVANCED: [&str; 8] = [
    "identity",
    "writer",
    "writers",
    "recipients",
    "trust",
    "fingerprint",
    "history",
    "upgrade",
];

fn group_advanced(vault: Command) -> Command {
    let advanced = Command::new("advanced")
        .about("Keys, trust and format details of vaults that are not synced")
        .subcommand_required(true)
        .subcommands(
            vault
                .get_subcommands()
                .filter(|command| ADVANCED.contains(&command.get_name()))
                .cloned()
                .collect::<Vec<_>>(),
        );
    ADVANCED
        .iter()
        .fold(vault, |vault, name| {
            vault.mut_subcommand(*name, |command| command.hide(true))
        })
        .subcommand(advanced)
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
        resume: !matches.get_flag("no-session"),
    };

    let Some((name, sub)) = matches.subcommand() else {
        unreachable!("clap requires a subcommand");
    };
    // `txc vault advanced X` is `txc vault X`, grouped.
    let (name, sub) = if name == "advanced" {
        sub.subcommand()
            .context("clap requires an advanced subcommand")?
    } else {
        (name, sub)
    };
    match name {
        "init" | "create" if synced_command::folder_of(sub).is_some() => {
            let folder = synced_command::folder_of(sub).cloned().unwrap_or_default();
            synced_command::init(&context.synced(), sub, &folder)
        }
        "join" => synced_command::join(&context.synced(), sub),
        "device" => synced_command::device(&context.synced(), sub),
        "status" => synced_command::status(&context.synced(), sub),
        "compare" => synced_command::compare(&context.synced(), sub),
        "hardware" => synced_command::hardware(&context.synced(), sub),
        "breach" => synced_command::breach(&context.synced(), sub),
        "keyholder" => crate::vault::keyholder::serve(&context.home),
        "ssh-ca" => synced_command::ssh_ca(&context.synced(), sub),
        "ssh" => synced_command::ssh(&context.synced(), sub),
        "doctor" => synced_command::doctor(&context.synced(), sub),
        "recovery" => synced_command::recovery(&context.synced(), sub),
        "resolve" => synced_command::entry(&context.synced(), "resolve", sub),
        "migrate" => {
            let keyring = context.unlock()?;
            synced_command::migrate(&context.synced(), &keyring, sub)
        }
        "list" | "add" | "show" | "copy" | "edit" | "rm" | "restore" | "grant" | "favourite"
            if context.names_synced(name, sub) =>
        {
            synced_command::entry(&context.synced(), name, sub)
        }
        "init" => context.init(sub),
        "unlock" => context.start_session(sub),
        "run" => context.run_program(sub),
        "import" => context.import(sub),
        "export" => context.export(sub),
        "lock" => {
            if session::end(&context.home) {
                eprintln!("The session is closed.");
            } else {
                eprintln!("There was no open session.");
            }
            Ok(())
        }
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
        "restore" => anyhow::bail!(
            "only synced vaults keep removed entries; the previous version of this vault is in \
             the .bak file beside it until its next change"
        ),
        "move" => context.move_entry(sub),
        "recipients" => context.recipients(sub),
        "trust" => context.trust(sub),
        "fingerprint" => context.fingerprint(sub),
        "history" => context.history(sub),
        "writer" => context.writer(sub),
        "writers" => context.writers(sub),
        "upgrade" => context.upgrade(sub),
        "delete" => context.delete(sub),
        "grant" => context.grant(sub),
        "redeem" => context.redeem(sub),
        other => unreachable!("clap accepted an unknown subcommand {other}"),
    }
}

/// Overwrites a file once with zeros, flushes it, and deletes it.
fn remove_source(path: &Path) -> Result<()> {
    let length = std::fs::metadata(path)?.len();
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    let zeros = vec![0_u8; 64 * 1024];
    let mut left = length;
    while left > 0 {
        let chunk = usize::try_from(left.min(zeros.len() as u64)).unwrap_or(zeros.len());
        file.write_all(zeros.get(..chunk).unwrap_or(&zeros))?;
        left = left.saturating_sub(chunk as u64);
    }
    file.sync_all()?;
    drop(file);
    std::fs::remove_file(path).with_context(|| format!("cannot delete {}", path.display()))
}

/// Creates a new file readable by its owner alone, refusing to replace one.
fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {}; it must not exist yet", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// The exit code to pass on: the child's own, or 128 plus the signal that
/// ended it, as a shell reports.
pub(crate) fn exit_code(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128_i32.saturating_add(signal);
        }
    }
    status.code().unwrap_or(1)
}

/// Runs slow work with a line on the terminal saying what is happening.
///
/// Deriving the key from a passphrase takes a moment on purpose, and a
/// command that sits silently looks like one that has hung.
pub(crate) fn working<T>(message: &str, work: impl FnOnce() -> Result<T>) -> Result<T> {
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
    resume: bool,
}

impl Session {
    const fn synced(&self) -> synced_command::Context<'_> {
        synced_command::Context {
            home: &self.home,
            passphrase: &self.passphrase,
            resume: self.resume,
        }
    }

    /// Whether an entry verb names a synced vault: by its `[VAULT/]ENTRY`,
    /// or for `list`, by its vault, or with no vault on a home that has only
    /// synced vaults.
    fn names_synced(&self, verb: &str, sub: &ArgMatches) -> bool {
        if verb == "list" {
            if let Some(vault) = sub.get_one::<String>("VAULT") {
                return synced_command::is_synced(&self.home, vault);
            }
            // Bare, it lists the vault names of both kinds, as the classic
            // path does; with a filter and no identity, only the synced
            // vault can answer.
            let filtered = sub.get_flag("favourites")
                || sub.get_flag("recent")
                || sub.get_one::<String>("tag").is_some()
                || sub.get_one::<String>("kind").is_some();
            return filtered
                && !self.home.has_identity()
                && synced::names(&self.home).is_ok_and(|names| !names.is_empty());
        }
        sub.get_one::<String>("ENTRY")
            .and_then(|entry| entry.parse::<crate::vault::model::Reference>().ok())
            .is_some_and(|reference| synced_command::is_synced(&self.home, &reference.vault))
    }

    /// Unlocks the identity: from the open session when there is one, from the
    /// passphrase otherwise.
    fn unlock(&self) -> Result<Keyring> {
        if self.resume {
            match session::resume(&self.home)? {
                session::Resumed::Open(session::Contents {
                    identity: Some(identity),
                    ..
                }) => {
                    return Keyring::from_session(&self.home, identity);
                }
                session::Resumed::Ended(reason) => {
                    eprintln!("The session has ended: {reason}.");
                }
                session::Resumed::Open(_) | session::Resumed::None => {}
            }
        }
        self.unlock_with_passphrase()
    }

    fn unlock_with_passphrase(&self) -> Result<Keyring> {
        let passphrase = self.passphrase.ask(PASSPHRASE_PROMPT)?;
        working("Unlocking...", || Keyring::unlock(&self.home, &passphrase))
    }

    /// Imports another tool's export into a vault.
    fn import(&self, sub: &ArgMatches) -> Result<()> {
        use crate::vault::import::{self, Format};

        let path = required(sub, "FILE");
        let bytes = std::fs::read(path).with_context(|| format!("cannot read {path}"))?;
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "{path} is larger than any export txc reads"
        );
        let text = zeroize::Zeroizing::new(
            String::from_utf8(bytes).with_context(|| format!("{path} is not UTF-8 text"))?,
        );
        let format = sub
            .get_one::<String>("format")
            .and_then(|id| Format::from_id(id))
            .unwrap_or_else(|| Format::detect(path, &text));
        let batch = import::read(format, &text).with_context(|| format!("cannot read {path}"))?;
        drop(text);

        let vault_name = required(sub, "into");
        check_vault_name(vault_name)?;
        let mut kinds: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for entry in &batch.entries {
            let count = kinds.entry(entry.kind.label()).or_insert(0);
            *count = count.saturating_add(1);
        }
        let summary: Vec<String> = kinds
            .iter()
            .map(|(label, count)| format!("{count} {}", label.to_lowercase()))
            .collect();
        eprintln!(
            "{} entries to import into {vault_name}: {}.",
            batch.entries.len(),
            if summary.is_empty() {
                "none".to_string()
            } else {
                summary.join(", ")
            }
        );
        for (reason, count) in &batch.skipped {
            eprintln!("Left out {count}: {reason}.");
        }
        if sub.get_flag("dry-run") || batch.entries.is_empty() {
            return Ok(());
        }

        if synced_command::is_synced(&self.home, vault_name) {
            let (mut vault, _) = self.synced().open_confined(vault_name)?;
            let new: Vec<NewEntry> = batch
                .entries
                .into_iter()
                .map(|entry| NewEntry {
                    name: entry.name,
                    kind: entry.kind,
                    plain: entry.plain,
                    secrets: entry.secrets,
                    tags: entry.tags,
                    favourite: entry.favourite,
                })
                .collect();
            let count = crate::vault::synced_model::add_all(&mut vault, &new)?;
            eprintln!("Imported {count} entries into {vault_name}, as one change.");
        } else {
            self.import_classic(vault_name, batch)?;
        }
        if sub.get_flag("remove-source") {
            remove_source(Path::new(path))?;
            eprintln!(
                "Overwrote and deleted {path}. Copies may remain on an SSD, in a synced folder or \
                 in a backup."
            );
        }
        Ok(())
    }

    fn import_classic(&self, vault_name: &str, batch: crate::vault::import::Batch) -> Result<()> {
        let keyring = self.unlock()?;
        let write_key = self.write_key()?;
        let mut vault = keyring.open(vault_name)?;
        let count = batch.entries.len();
        for entry in batch.entries {
            // A name already in the vault gets the next free number.
            let mut name = entry.name.clone();
            let mut number = 2_usize;
            while vault.vault().entry(&name).is_some() {
                name = format!("{} ({number})", entry.name);
                number = number.saturating_add(1);
            }
            vault.add(NewEntry {
                name,
                kind: entry.kind,
                plain: entry.plain,
                secrets: entry.secrets,
                tags: entry.tags,
                favourite: entry.favourite,
            })?;
        }
        vault.save(&keyring, &write_key)?;
        eprintln!("Imported {count} entries into {vault_name}.");
        Ok(())
    }

    /// Writes a copy of vaults as one age file, or as JSON after a typed
    /// confirmation.
    fn export(&self, sub: &ArgMatches) -> Result<()> {
        let plaintext = sub.get_flag("plaintext");
        let (mut classic, mut quantum) = (Vec::new(), Vec::new());
        for text in many(sub, "to") {
            if text.starts_with("age1pq1") {
                quantum.push(
                    text.parse::<crate::vault::pq::Recipient>()
                        .map_err(|error| anyhow!("{text}: {error}"))?,
                );
            } else {
                classic.push(crypto::parse_recipient(&text)?);
            }
        }
        let recipients: Vec<&dyn age::Recipient> = classic
            .iter()
            .map(|recipient| recipient as &dyn age::Recipient)
            .chain(
                quantum
                    .iter()
                    .map(|recipient| recipient as &dyn age::Recipient),
            )
            .collect();
        ensure!(
            plaintext || !recipients.is_empty(),
            "name who can read the copy with --to age1..., such as a backup key; or use \
             --plaintext, which asks for a typed confirmation"
        );
        let output = sub.get_one::<String>("output");
        ensure!(
            output.is_some() || !io::stdout().is_terminal(),
            "an export will not be written to the terminal; use --output FILE or a pipe"
        );
        if plaintext {
            ensure!(
                output.is_some(),
                "a plaintext export needs --output FILE, so it never passes through a pipe"
            );
            let confirmed = prompt::confirm_value(
                "Every secret will be written unencrypted. Type 'export plaintext' to go on:",
                "export plaintext",
                "a plaintext export needs a person to confirm it; encrypt it with --to instead",
            )?;
            ensure!(confirmed, "nothing was exported");
        }

        let mut names = many(sub, "VAULT");
        if names.is_empty() {
            names = self.home.vault_names().unwrap_or_default();
            names.extend(synced::names(&self.home)?);
        }
        let needs_identity = names
            .iter()
            .any(|name| !synced_command::is_synced(&self.home, name));
        let keyring = if needs_identity {
            Some(self.unlock()?)
        } else {
            None
        };
        let mut vaults = Vec::new();
        for name in &names {
            if synced_command::is_synced(&self.home, name) {
                vaults.push(synced_command::export_vault(&self.synced(), name)?);
                continue;
            }
            let keyring = keyring
                .as_ref()
                .context("the identity is unlocked for this vault")?;
            let opened = keyring.open(name)?;
            let mut entries = Vec::new();
            for entry in opened.vault().entries() {
                let mut fields = Vec::new();
                for field in &entry.fields {
                    let (value, secret) = match &field.value {
                        crate::vault::model::Value::Plain(text) => (text.clone(), false),
                        crate::vault::model::Value::Sealed(_) => (
                            opened
                                .reveal(keyring, &entry.name, &field.name)?
                                .expose_secret()
                                .to_string(),
                            true,
                        ),
                    };
                    fields.push(serde_json::json!({
                        "name": field.name,
                        "value": value,
                        "secret": secret,
                    }));
                }
                entries.push(serde_json::json!({
                    "name": entry.name,
                    "kind": entry.kind.id(),
                    "fields": fields,
                    "tags": entry.tags,
                    "favourite": entry.favourite,
                    "created": entry.created,
                    "updated": entry.updated,
                }));
            }
            vaults.push(serde_json::json!({ "name": name, "entries": entries }));
        }
        let document = serde_json::json!({
            "format": "txc-export",
            "version": 1,
            "exported": crate::vault::document::now(),
            "vaults": vaults,
        });
        let json = zeroize::Zeroizing::new(serde_json::to_vec_pretty(&document)?);
        drop(document);
        let bytes = if plaintext {
            json.to_vec()
        } else {
            crypto::encrypt_to(&recipients, &json)?
        };

        if let Some(path) = output {
            write_new_private(Path::new(path), &bytes)?;
            eprintln!(
                "Exported {} vaults to {path}.{}",
                names.len(),
                if plaintext {
                    " It is unencrypted: keep it off synced folders and delete it soon."
                } else {
                    " Read it with: age -d -i <key> <file>"
                }
            );
        } else {
            let mut stdout = io::stdout().lock();
            stdout.write_all(&bytes)?;
            stdout.flush()?;
        }
        Ok(())
    }

    /// Runs a program with the secrets its template names.
    fn run_program(&self, sub: &ArgMatches) -> Result<()> {
        use crate::vault::deliver::Delivery;
        use crate::vault::template::{self, Delivery as How, Value};

        let mut files = many(sub, "env-file");
        if files.is_empty() && Path::new(".env.txc").is_file() {
            files.push(".env.txc".to_string());
        }
        let mut variables: template::Template = Vec::new();
        let mut set = |name: String, value: Value| {
            variables.retain(|(existing, _)| *existing != name);
            variables.push((name, value));
        };
        for file in &files {
            let text =
                std::fs::read_to_string(file).with_context(|| format!("cannot read {file}"))?;
            for (name, value) in template::parse(&text).with_context(|| file.clone())? {
                set(name, value);
            }
        }
        for setting in many(sub, "set") {
            let (name, reference) = template::parse_setting(&setting)?;
            set(name, Value::Secret(reference));
        }

        let words: Vec<&String> = sub
            .get_many::<String>("COMMAND")
            .context("a command is required")?
            .collect();
        let (program, args) = words.split_first().context("a command is required")?;
        let mut command = std::process::Command::new(program);
        command.args(args);

        let mut deliveries = Vec::new();
        let needs_secrets = variables.iter().any(|(_, value)| {
            matches!(value, Value::Secret(reference) if !synced_command::is_synced(&self.home, &reference.vault))
        });
        let mut synced_opened: std::collections::BTreeMap<String, Synced> =
            std::collections::BTreeMap::new();
        let keyring = if needs_secrets {
            Some(self.unlock()?)
        } else {
            None
        };
        let mut opened: std::collections::BTreeMap<String, Opened> =
            std::collections::BTreeMap::new();
        for (name, value) in &variables {
            let reference = match value {
                Value::Plain(plain) => {
                    command.env(name, plain);
                    continue;
                }
                Value::Secret(reference) => reference,
            };
            if synced_command::is_synced(&self.home, &reference.vault) {
                let secret = synced_command::resolve_reference(
                    &self.synced(),
                    &mut synced_opened,
                    &reference.vault,
                    &reference.entry,
                    reference.field.as_deref(),
                    match reference.delivery {
                        How::Environment => synced_command::Channel::Environment,
                        How::File => synced_command::Channel::File,
                    },
                )
                .with_context(|| format!("{name}={reference}"))?;
                match reference.delivery {
                    How::Environment => {
                        command.env(name, secret.expose_secret());
                    }
                    How::File => {
                        let delivery = Delivery::prepare(&secret, &mut command)?;
                        command.env(name, &delivery.path);
                        deliveries.push(delivery);
                    }
                }
                continue;
            }
            let keyring = keyring
                .as_ref()
                .context("the vault is unlocked for secrets")?;
            if !opened.contains_key(&reference.vault) {
                opened.insert(reference.vault.clone(), keyring.open(&reference.vault)?);
            }
            let vault = opened
                .get(&reference.vault)
                .context("the vault was just opened")?;
            let entry = vault.entry(&reference.entry)?;
            let field = reference
                .field
                .clone()
                .unwrap_or_else(|| entry.kind.primary().to_string());
            let entry_name = entry.name.clone();
            let secret = vault
                .reveal(keyring, &entry_name, &field)
                .with_context(|| format!("{name}={reference}"))?;
            match reference.delivery {
                How::Environment => {
                    command.env(name, secret.expose_secret());
                }
                How::File => {
                    let delivery = Delivery::prepare(&secret, &mut command)?;
                    command.env(name, &delivery.path);
                    deliveries.push(delivery);
                }
            }
        }
        // Nothing but the child's copies stay in memory while it runs.
        drop(opened);
        drop(synced_opened);
        drop(keyring);

        let mut child = command
            .spawn()
            .with_context(|| format!("cannot run {program}"))?;
        drop(command);
        for delivery in deliveries {
            delivery.after_spawn();
        }
        let status = child.wait()?;
        std::process::exit(exit_code(status));
    }

    /// Unlocks with the passphrase and opens a session.
    fn start_session(&self, sub: &ArgMatches) -> Result<()> {
        let minutes = *sub.get_one::<u64>("idle").unwrap_or(&15);
        let hours = *sub.get_one::<u64>("max").unwrap_or(&8);
        let passphrase = self.passphrase.ask(PASSPHRASE_PROMPT)?;
        let mut contents = session::Contents::default();
        if self.home.has_identity() {
            let keyring = working("Unlocking...", || Keyring::unlock(&self.home, &passphrase))?;
            contents.identity = Some(keyring.identity().clone());
        }
        for name in synced::names(&self.home)? {
            match working(&format!("Unlocking {name}..."), || {
                Synced::unlock(
                    &self.home,
                    &name,
                    &passphrase,
                    &crate::vault::hardware::Terminal,
                )
            }) {
                Ok(kek) => {
                    contents.synced.insert(name, kek);
                }
                Err(error) => eprintln!("The synced vault {name} stays locked: {error:#}"),
            }
        }
        ensure!(
            contents.identity.is_some() || !contents.synced.is_empty(),
            "there is nothing to unlock here; start with: txc vault init"
        );
        let opened = session::start(
            &self.home,
            &contents,
            std::time::Duration::from_secs(minutes.saturating_mul(60)),
            std::time::Duration::from_secs(hours.saturating_mul(3600)),
        )?;
        eprintln!(
            "Unlocked. The session ends after {} minutes without use, after {} hours at most, \
             when the computer sleeps, or with: txc vault lock",
            opened.idle.as_secs() / 60,
            opened.max.as_secs() / 3600
        );
        Ok(())
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
                 writer of the device that writes with: txc vault advanced writers --add <key>"
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
        // The current passphrase, asked once: it opens the identity when
        // this device has one, and every synced vault it opens.
        let current = self.passphrase.ask("Current passphrase: ")?;
        let only = sub.get_one::<String>("vault");
        let keyring = if self.home.has_identity() && only.is_none() {
            Some(working("Unlocking...", || {
                Keyring::unlock(&self.home, &current)
            })?)
        } else {
            None
        };
        let names = match only {
            Some(name) => {
                ensure!(
                    synced::exists(&self.home, name),
                    "there is no synced vault named \"{name}\" on this device"
                );
                vec![name.clone()]
            }
            None => synced::names(&self.home)?,
        };
        let mut vaults = Vec::new();
        for name in names {
            match working(&format!("Unlocking {name}..."), || {
                Synced::open(
                    &self.home,
                    &name,
                    &current,
                    &crate::vault::hardware::Terminal,
                )
            }) {
                Ok(vault) => vaults.push(vault),
                Err(error) if only.is_none() => {
                    eprintln!("The synced vault {name} keeps its own passphrase: {error:#}");
                }
                Err(error) => return Err(error),
            }
        }
        ensure!(
            keyring.is_some() || !vaults.is_empty(),
            "that passphrase opens nothing here"
        );
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
        if let Some(keyring) = &keyring {
            working("Protecting your identity...", || {
                keyring.change_passphrase(&passphrase)
            })?;
        }
        for vault in &mut vaults {
            working(&format!("Protecting {}...", vault.name), || {
                vault.change_passphrase(&current, &passphrase, &crate::vault::hardware::Terminal)
            })?;
        }
        let mut changed: Vec<String> = keyring.iter().map(|_| "your identity".to_owned()).collect();
        changed.extend(
            vaults
                .iter()
                .map(|vault| format!("the synced vault {}", vault.name)),
        );
        // A session holds keys made from the old passphrase.
        let ended = session::end(&self.home);
        eprintln!(
            "Passphrase changed for {}.{}",
            changed.join(", "),
            if ended {
                " The session was ended; unlock again with: txc vault unlock"
            } else {
                ""
            }
        );
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
            let mut names = self.home.vault_names().unwrap_or_default();
            names.extend(
                synced::names(&self.home)?
                    .into_iter()
                    .map(|name| format!("{name} (synced)")),
            );
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

    /// Prints this device's writer public key and its fingerprint, or, with
    /// `--rotate`, replaces the write key and re-signs every vault.
    fn writer(&self, sub: &ArgMatches) -> Result<()> {
        if sub.get_flag("rotate") {
            return self.rotate_writer();
        }
        let write_key = self.write_key()?;
        let id = crypto::writer_id(&write_key);
        output(&format!(
            "{}  {}",
            crypto::writer_id_string(&id),
            crypto::fingerprint(id.as_bytes())
        ))
    }

    /// Replaces the write key with a fresh one and re-signs every vault this
    /// device can open.
    ///
    /// The new key is pinned while the old one stays pinned, and every vault is
    /// re-signed before the old key is removed, so a vault is always signed by a
    /// key still pinned and never stops opening, even if this is interrupted.
    /// Unlocking the current write key first is what stops a holder of the
    /// identity alone from rotating the write key to one they control.
    fn rotate_writer(&self) -> Result<()> {
        let mut keyring = self.unlock()?;
        let old = self.write_key()?;
        let old_id = crypto::writer_id_string(&crypto::writer_id(&old));

        let new_key = crypto::new_write_key();
        let new_id = crypto::writer_id_string(&crypto::writer_id(&new_key));
        let passphrase = self
            .write_passphrase
            .ask_new_write("New write passphrase: ")?;
        let sealed = working("Protecting the new write key...", || {
            crypto::seal_write_key(&new_key, &passphrase)
        })?;
        // Persist and pin the new key first, keeping the old pinned, so every
        // vault stays openable through the re-signing that follows.
        home::write_atomic(&self.home.writer_path(), &sealed, None)?;
        keyring.pin_writer(&new_id)?;

        let mut resigned = 0u32;
        for name in keyring.home().vault_names()? {
            let mut opened = keyring.open(&name)?;
            // Skip vaults already on the new key, so a re-run after an
            // interruption finishes rather than re-signs everything again.
            if opened.vault().writer() == new_id {
                continue;
            }
            opened.save(&keyring, &new_key)?;
            resigned = resigned.saturating_add(1);
            eprintln!("Re-signed {name}.");
        }

        eprintln!("Rotated the write key and re-signed {resigned} vault(s).");
        eprintln!("The old writer stays pinned so vaults still open on devices that have not");
        eprintln!("caught up. Once every device has the new key, remove it with:");
        eprintln!("  txc vault advanced writers --remove {old_id}");
        Ok(())
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
        let bytes = std::fs::read(file).with_context(|| format!("cannot read the grant {file}"))?;
        if bytes.starts_with(b"age-encryption.org/v1") {
            return synced_command::redeem(&bytes, sub);
        }
        let text =
            String::from_utf8(bytes).map_err(|_utf8| anyhow!("the grant {file} is damaged"))?;
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
pub(crate) fn main_spec(kind: Kind) -> &'static FieldSpec {
    // Every kind's primary field is one of its own defined fields.
    #[allow(clippy::expect_used)]
    kind.spec(kind.primary())
        .expect("every kind defines its main field")
}

/// Refuses a secret field given as a plain value, and a plain one asked for
/// as a secret, before anything is unlocked or typed.
pub(crate) fn check_sensitivities(
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
pub(crate) fn main_secret(sub: &ArgMatches, spec: &FieldSpec) -> Result<(SecretString, bool)> {
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
pub(crate) fn wait_then_clear(held: Held, seconds: u64, what: &str) -> Result<()> {
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

pub(crate) fn required<'a>(sub: &'a ArgMatches, name: &str) -> &'a str {
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

pub(crate) fn checked_tags(sub: &ArgMatches, name: &str) -> Result<Vec<String>> {
    let tags = many(sub, name);
    for tag in &tags {
        check_tag(tag)?;
    }
    Ok(tags)
}

pub(crate) fn checked_field_names(sub: &ArgMatches, name: &str) -> Result<Vec<String>> {
    let names = many(sub, name);
    for field in &names {
        check_field_name(field)?;
    }
    Ok(names)
}

/// `--username`, `--url` and every `--field NAME=VALUE`.
pub(crate) fn plain_fields(sub: &ArgMatches) -> Result<Vec<(String, String)>> {
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
pub(crate) fn table<const N: usize>(rows: &[[String; N]]) -> String {
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

pub(crate) fn output(text: &str) -> Result<()> {
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
            "idle",
            "max",
            "env-file",
            "set",
            "format",
            "into",
            "from",
            "output",
            "folder",
            "name",
            "vault",
            "role",
            "keep",
            "origin",
            "vault-id",
            "min-version",
            "ca",
            "user",
            "minutes",
            "recipient",
            "identity-file",
            "recipient-plugin",
            "identity-plugin",
            "path",
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
