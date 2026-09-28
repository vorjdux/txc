//! `txc vault` for synced vaults: vaults kept in a sync folder and shared by
//! several devices (study section 19).
//!
//! Everyday verbs (`add`, `list`, `show`, `copy`, `edit`, `rm`) come here
//! when the vault they name is a synced one; `init --folder`, `join`,
//! `device`, `status`, `sync`, `recovery`, `resolve` and `migrate` are
//! synced-only. Blobs a user moves between devices while pairing go to
//! standard output, one line each; everything meant for people goes to
//! standard error.

// Only small display numbers (sheet, row and version numbers) are added to
// here, never anything near an integer's limit.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::io::{self, BufRead, IsTerminal, Write};
use std::time::{Duration, Instant};

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context as _, Result, anyhow, bail, ensure};
use clap::ArgMatches;
use zeroize::Zeroizing;

use crate::vault::authority::Role;
use crate::vault::clipboard;
use crate::vault::command::{
    MASK, check_sensitivities, checked_field_names, main_secret, main_spec, output, plain_fields,
    required, table, wait_then_clear, working,
};
use crate::vault::confine::{self, Confinement};
use crate::vault::control::Checkpoint;
use crate::vault::device::Alarm;
use crate::vault::entries::{Changes, EntryView, FieldKind, FieldView, NAME, Sensitivity, Slot};
use crate::vault::grant2;
use crate::vault::model::{DEFAULT_VAULT, Kind, Reference, check_vault_name};
use crate::vault::object::Id;
use crate::vault::pairing::Paired;
use crate::vault::prompt::{self, Passphrase};
use crate::vault::synced::{self, Synced, now};
use crate::vault::{Home, Keyring, session};

const PASSPHRASE_PROMPT: &str = "Passphrase: ";
const JOIN_WAIT: Duration = Duration::from_secs(120);

/// What every synced command needs.
pub struct Context<'a> {
    /// The txc home.
    pub home: &'a Home,
    /// Where the passphrase comes from.
    pub passphrase: &'a Passphrase,
    /// Whether an open session may be used.
    pub resume: bool,
}

impl Context<'_> {
    /// Opens a synced vault from the session, or with the passphrase, and
    /// reads what is new in its folder.
    fn open(&self, name: &str) -> Result<Synced> {
        let mut vault = self.open_quiet(name)?;
        working("Syncing...", || vault.sync())?;
        Ok(vault)
    }

    /// Opens and syncs a vault, then confines this process to the txc home
    /// and the vault's objects: no other files, no network, no programs.
    fn open_confined(&self, name: &str) -> Result<(Synced, Confinement)> {
        let vault = self.open(name)?;
        let objects = vault.store().path().to_path_buf();
        let confinement = confine::confine(&[self.home.root(), &objects], &[]);
        Ok((vault, confinement))
    }

    fn open_quiet(&self, name: &str) -> Result<Synced> {
        if self.resume {
            match session::resume(self.home)? {
                session::Resumed::Open(mut contents) => {
                    if let Some(kek) = contents.synced.remove(name) {
                        return Synced::open_with(self.home, name, kek);
                    }
                }
                session::Resumed::Ended(reason) => eprintln!("The session has ended: {reason}."),
                session::Resumed::None => {}
            }
        }
        let passphrase = self.passphrase.ask(PASSPHRASE_PROMPT)?;
        working("Unlocking...", || {
            Synced::open(self.home, name, &passphrase)
        })
    }

    /// The synced vault a command means: the one named, or the only one.
    fn which(&self, given: Option<&String>) -> Result<String> {
        if let Some(name) = given {
            ensure!(
                synced::exists(self.home, name),
                "there is no synced vault named \"{name}\" on this device"
            );
            return Ok(name.clone());
        }
        let names = synced::names(self.home)?;
        match names.as_slice() {
            [only] => Ok(only.clone()),
            [] => bail!(
                "there is no synced vault on this device; create one with: txc vault init --folder DIR"
            ),
            _ => bail!(
                "there are several synced vaults ({}); name one",
                names.join(", ")
            ),
        }
    }
}

/// Whether a `[VAULT/]ENTRY` names an entry in a synced vault.
#[must_use]
pub fn is_synced(home: &Home, vault: &str) -> bool {
    synced::exists(home, vault)
}

fn read_line(what: &str) -> Result<String> {
    if io::stdin().is_terminal() {
        eprintln!("{what}");
    }
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    let line = line.trim().to_owned();
    ensure!(!line.is_empty(), "nothing was pasted");
    Ok(line)
}

fn blob(text: &str) -> Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{text}")?;
    stdout.flush()?;
    Ok(())
}

/// The user types the code the other screen shows; it must equal ours.
fn codes_match(code: &str) -> Result<bool> {
    eprintln!("This screen shows the code: {code}");
    if io::stdin().is_terminal() {
        return prompt::confirm_value("Type the code the other screen shows:", code, "");
    }
    let typed = read_line("")?;
    Ok(prompt::fingerprints_match(&typed, code))
}

// -------------------------------------------------------------------- init --

/// `txc vault init --folder DIR`: a new synced vault with this device as its
/// first admin.
///
/// # Errors
///
/// Returns an error when the name is taken, the folder holds a vault, or no
/// keystore is available.
pub fn init(context: &Context<'_>, sub: &ArgMatches, folder: &str) -> Result<()> {
    let name = sub
        .get_one::<String>("name")
        .map_or(DEFAULT_VAULT, String::as_str);
    check_vault_name(name)?;
    let folder = std::fs::canonicalize(folder)
        .with_context(|| format!("the folder {folder} does not exist"))?;
    eprintln!(
        "Creating the vault \"{name}\" in {}.\n\
         Choose a passphrase of at least {} characters; with this device's keystore it opens the \
         vault here.",
        folder.display(),
        prompt::MIN_PASSPHRASE_CHARS
    );
    let passphrase = context.passphrase.ask_new("New passphrase: ")?;
    let params = working("Measuring this computer...", synced::calibrate)?;
    let mut vault = working("Creating the vault...", || {
        Synced::create(context.home, name, &folder, &passphrase, params)
    })?;
    vault.checkpoint()?;
    eprintln!(
        "Created the vault \"{name}\".\n\
         Next, write down the recovery sheets; adding another device waits for them:\n  \
         txc vault recovery print {name}"
    );
    Ok(())
}

// -------------------------------------------------------------------- join --

/// `txc vault join --folder DIR`: this device joins a vault another device
/// shares, by pairing with one of its admins.
///
/// # Errors
///
/// Returns an error when pairing fails or the codes do not match.
pub fn join(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let name = sub
        .get_one::<String>("name")
        .map_or(DEFAULT_VAULT, String::as_str);
    check_vault_name(name)?;
    ensure!(
        !synced::exists(context.home, name),
        "a vault named \"{name}\" already exists on this device"
    );
    let folder = required(sub, "folder");
    let folder = std::fs::canonicalize(folder)
        .with_context(|| format!("the folder {folder} does not exist"))?;

    let commitment = read_line(
        "On a device that can add devices, run: txc vault device add\nPaste the line it shows:",
    )?;
    let (me, state, reply) = Synced::join_reply(&commitment)?;
    if io::stdin().is_terminal() {
        eprintln!("Paste this line into the other device:");
    }
    blob(&reply)?;
    let reveal = read_line("Paste the line it shows next:")?;
    let paired = state.check(&reveal)?;
    ensure!(
        codes_match(&paired.code)?,
        "the codes differ: pairing is aborted and nothing was saved"
    );

    eprintln!(
        "Choose a passphrase for this device of at least {} characters.",
        prompt::MIN_PASSPHRASE_CHARS
    );
    let passphrase = context.passphrase.ask_new("New passphrase: ")?;
    let params = working("Measuring this computer...", synced::calibrate)?;
    let mut vault = Synced::joined(
        context.home,
        name,
        &folder,
        me,
        &paired,
        &passphrase,
        params,
    )?;
    let started = Instant::now();
    working("Waiting for the other device...", || {
        loop {
            vault.sync()?;
            if vault.device().me().certificate.is_some() {
                return Ok(());
            }
            if started.elapsed() >= JOIN_WAIT {
                bail!(
                    "the other device has not added this one yet; once it has, run: txc vault sync {name}"
                );
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    })?;
    vault.checkpoint()?;
    eprintln!("Joined the vault \"{name}\".");
    Ok(())
}

// ------------------------------------------------------------------ device --

/// `txc vault device add | list | remove`.
///
/// # Errors
///
/// Returns an error when the subcommand fails.
pub fn device(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let (verb, args) = sub
        .subcommand()
        .context("clap requires a device subcommand")?;
    let name = context.which(args.get_one::<String>("vault"))?;
    let (mut vault, _) = context.open_confined(&name)?;
    match verb {
        "add" => {
            let role = match args.get_one::<String>("role").map(String::as_str) {
                Some("reader") => Role::Reader,
                _ => Role::Writer,
            };
            let (start, commitment) = vault.pair()?;
            if io::stdin().is_terminal() {
                eprintln!(
                    "On the new device, run: txc vault join --folder <its copy of the folder>\nPaste this line into it:"
                );
            }
            blob(&commitment)?;
            let reply = read_line("Paste the line the new device shows:")?;
            let (paired, reveal) = start.reveal(&reply)?;
            if io::stdin().is_terminal() {
                eprintln!("Paste this line into the new device:");
            }
            blob(&reveal)?;
            ensure!(
                codes_match(&paired.code)?,
                "the codes differ: pairing is aborted and nothing was added"
            );
            add_paired(&mut vault, &paired, role)?;
            eprintln!("Added the device. It finishes joining on its own within a minute.");
            Ok(())
        }
        "list" => list_devices(&vault),
        "remove" => {
            let prefix = required(args, "DEVICE").to_lowercase();
            let matches: Vec<Id> = vault
                .device()
                .view()
                .keys()
                .filter(|device| {
                    data_encoding::HEXLOWER
                        .encode(&device[..])
                        .starts_with(&prefix)
                })
                .copied()
                .collect();
            let [device] = matches.as_slice() else {
                bail!(
                    "{} devices start with {prefix}; see: txc vault device list",
                    matches.len()
                );
            };
            if !args.get_flag("yes") {
                ensure!(
                    prompt::confirm(
                        &format!("Remove device {prefix}? It will read nothing new."),
                        "pass --yes"
                    )?,
                    "nothing was removed"
                );
            }
            vault.remove_device(*device)?;
            eprintln!("Removed the device. Every device rotates its keys before it writes again.");
            Ok(())
        }
        other => bail!("unknown device subcommand {other}"),
    }
}

fn add_paired(vault: &mut Synced, paired: &Paired, role: Role) -> Result<()> {
    vault.add(paired, role)?;
    vault.checkpoint()
}

fn list_devices(vault: &Synced) -> Result<()> {
    let me = vault.device().me().device;
    let mut rows = vec![[
        "Device".to_owned(),
        "Can".to_owned(),
        "Until".to_owned(),
        String::new(),
    ]];
    for (device, certificate) in vault.device().view() {
        let can = match certificate.role {
            Role::Admin => "add devices",
            Role::Writer => "read and write",
            Role::Reader => "view only",
        };
        rows.push([
            data_encoding::HEXLOWER.encode(&device[..4]),
            can.to_owned(),
            i64::try_from(certificate.not_after)
                .ok()
                .and_then(|at| chrono::DateTime::from_timestamp(at, 0))
                .map_or_else(String::new, |at| at.format("%Y-%m-%d").to_string()),
            if device == me {
                "this device".to_owned()
            } else {
                String::new()
            },
        ]);
    }
    output(&table(&rows))
}

// ------------------------------------------------------------ status, sync --

/// `txc vault status`: one line per item, each with one next action.
///
/// # Errors
///
/// Returns an error when the vault does not open.
pub fn status(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let name = context.which(sub.get_one::<String>("VAULT"))?;
    let (mut vault, confinement) = context.open_confined(&name)?;
    vault.checkpoint()?;
    let mut lines = Vec::new();
    let device = vault.device();
    for alarm in device.alarms() {
        lines.push(match alarm {
            Alarm::Hijack => "● red     Someone changed this device's keys. Stop using it and remove it from another device.".to_owned(),
            Alarm::Removed => "● red     This device was removed from the vault. It reads nothing new.".to_owned(),
            Alarm::Restored => format!("● red     This device was restored from a backup and must be paired again\n          → txc vault join --folder <folder> --name {name}-new"),
            Alarm::Fork(author) => format!(
                "● red     Device {} wrote two different histories\n          → txc vault device remove {}",
                data_encoding::HEXLOWER.encode(&author[..4]),
                data_encoding::HEXLOWER.encode(&author[..4])
            ),
        });
    }
    if vault.kit_pending() {
        lines.push(format!(
            "● yellow  recovery sheets not written down   → txc vault recovery print {name}"
        ));
    }
    let gaps = device.gaps();
    if !gaps.is_empty() {
        lines.push(
            "● yellow  some objects have not arrived yet   → check that the folder is syncing"
                .to_owned(),
        );
    }
    let conflicted: Vec<String> = vault
        .entries()?
        .list()
        .into_iter()
        .filter(|entry| entry.conflict)
        .map(|entry| entry.names.join(" / "))
        .collect();
    for entry in conflicted {
        lines.push(format!(
            "● yellow  {name}/{entry} has two versions      → txc vault resolve {name}/{entry}"
        ));
    }
    // What this platform cannot provide is a permanent condition: shown
    // with --all, not on every status (study section 19).
    if sub.get_flag("all") {
        for missing in confinement.missing() {
            lines.push(format!(
                "● yellow  on this system, {missing}; nothing to do"
            ));
        }
    }
    let members = device.members().len();
    lines.insert(
        0,
        format!(
            "● green   vault \"{name}\", {members} device{}",
            if members == 1 { "" } else { "s" }
        ),
    );
    output(&lines.join("\n"))
}

/// `txc vault sync`: reads what arrived and writes a checkpoint.
///
/// # Errors
///
/// Returns an error when the vault does not open.
pub fn sync(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let name = context.which(sub.get_one::<String>("VAULT"))?;
    let (mut vault, _) = context.open_confined(&name)?;
    vault.checkpoint()?;
    eprintln!("Synced \"{name}\".");
    Ok(())
}

// ---------------------------------------------------------- compare, doctor --

/// A checkpoint's short id and the digest of the head set it commits to.
fn digest_of(checkpoint: &Checkpoint) -> String {
    use sha2::{Digest, Sha384};
    let mut hash = Sha384::new();
    Digest::update(&mut hash, b"txc/v1/compare");
    for (device, (seq, head)) in &checkpoint.heads {
        Digest::update(&mut hash, device);
        Digest::update(&mut hash, seq.to_be_bytes());
        Digest::update(&mut hash, head);
    }
    let digest = hash.finalize();
    digest
        .chunks(2)
        .take(3)
        .map(|pair| data_encoding::HEXLOWER.encode(pair))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `txc vault compare`: for the latest checkpoint of every device, its id
/// and a digest of the heads it saw. Two devices showing the same digest for
/// the same checkpoint id see the same objects; a checkpoint one of them has
/// not received yet is simply missing from its list, never a mismatch
/// (rule 15).
///
/// # Errors
///
/// Returns an error when the vault does not open.
pub fn compare(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let name = context.which(sub.get_one::<String>("VAULT"))?;
    let (mut vault, _) = context.open_confined(&name)?;
    vault.checkpoint()?;
    let me = vault.device().me().device;
    let mut latest: BTreeMap<Id, (u64, Id, Checkpoint)> = BTreeMap::new();
    for content in vault.device().content() {
        if content.payload.kind != crate::vault::object::Kind::Checkpoint {
            continue;
        }
        let Ok(checkpoint) = Checkpoint::decode(&content.payload.body) else {
            continue;
        };
        let id: Id = content
            .hash
            .first_chunk::<16>()
            .copied()
            .unwrap_or_default();
        let newer = latest
            .get(&content.payload.author)
            .is_none_or(|(seq, _, _)| content.payload.seq > *seq);
        if newer {
            latest.insert(
                content.payload.author,
                (content.payload.seq, id, checkpoint),
            );
        }
    }
    let mut rows = vec![[
        "Checkpoint".to_owned(),
        "By".to_owned(),
        "Digest".to_owned(),
    ]];
    for (author, (_, id, checkpoint)) in &latest {
        let by = data_encoding::HEXLOWER.encode(&author[..4]);
        rows.push([
            data_encoding::HEXLOWER.encode(&id[..2]),
            if *author == me {
                format!("{by} (this device)")
            } else {
                by
            },
            digest_of(checkpoint),
        ]);
    }
    output(&table(&rows))?;
    eprintln!(
        "Run this on another device: the same checkpoint must show the same digest there. One it has \
         not received yet is missing from its list, which is not a mismatch."
    );
    Ok(())
}

/// `txc vault doctor`: a diagnostic report with no secret and no entry
/// name in it, for bug reports.
///
/// # Errors
///
/// Returns an error when writing the report fails.
pub fn doctor(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let mut lines = vec![
        format!("txc {}", env!("CARGO_PKG_VERSION")),
        format!(
            "platform: {} {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
        format!("suite: {}", crate::vault::object::SUITE),
        format!("synced vaults: {}", synced::names(context.home)?.len()),
    ];
    let named = sub.get_one::<String>("VAULT");
    if let Ok(name) = context.which(named) {
        match context.open_confined(&name) {
            Ok((vault, confinement)) => {
                let listing = vault.store().list()?;
                lines.push(format!(
                    "folder: {} objects, {} in flight, {} names ignored",
                    listing.names.len(),
                    listing.in_flight,
                    listing.ignored
                ));
                let device = vault.device();
                lines.push(format!("devices: {}", device.members().len()));
                lines.push(format!("alarms: {:?}", device.alarms()));
                lines.push(format!("gaps: {}", device.gaps().len()));
                lines.push(format!(
                    "recovery sheets written down: {}",
                    !vault.kit_pending()
                ));
                let missing = confinement.missing();
                lines.push(format!(
                    "confinement: {}",
                    if missing.is_empty() {
                        "complete".to_owned()
                    } else {
                        missing.join(", ")
                    }
                ));
            }
            Err(error) => lines.push(format!("the vault did not open: {error:#}")),
        }
    }
    output(&lines.join("\n"))
}

// ------------------------------------------------------------------ grants --

/// The certificates a certificate's verification needs, in order, ending
/// with it: its issuing admin, what it renews, and its co-signer.
fn chain_for(
    device: &crate::vault::device::Device,
    id: &Id,
    chain: &mut Vec<crate::vault::authority::IssuedCertificate>,
) -> Result<()> {
    use crate::vault::authority::{Issuance, Issuer};
    if chain.iter().any(|issued| issued.certificate.id == *id) {
        return Ok(());
    }
    let issued = device
        .issued_certificate(id)
        .with_context(|| "a certificate of the chain is missing")?;
    let mut needs = Vec::new();
    if let Issuer::Admin(admin) = issued.certificate.issuer {
        needs.push(admin);
    }
    needs.extend(issued.certificate.renews);
    if let Issuance::SelfRenewal {
        cosigner: Some((cosigner, _)),
        ..
    } = &issued.issuance
    {
        needs.push(*cosigner);
    }
    for need in needs {
        chain_for(device, &need, chain)?;
    }
    chain.push(issued);
    Ok(())
}

/// `txc vault grant VAULT/ENTRY --to age1pq1...` on a synced vault: grant
/// v2, signed by this device and sealed to the runner.
///
/// # Errors
///
/// Returns an error when the entry, the key or the expiry is wrong.
pub fn grant(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    ensure!(
        !io::stdout().is_terminal(),
        "a grant is written to a file or a pipe; redirect it, as: txc vault grant <entry> --to age1pq1... > deploy.grant"
    );
    let reference: Reference = required(sub, "ENTRY").parse()?;
    let runner = sub
        .get_one::<String>("to")
        .context("a grant from a synced vault is sealed to the runner's own key: --to age1pq1... (make one with age-keygen -pq)")?;
    ensure!(
        !sub.get_flag("to-file"),
        "a grant from a synced vault is always sealed to the runner's own key"
    );
    let expires_spec = sub
        .get_one::<String>("expires")
        .map_or("1d", String::as_str);
    let expires =
        chrono::DateTime::parse_from_rfc3339(&crate::vault::grant::expiry_from(expires_spec)?)
            .ok()
            .and_then(|at| u64::try_from(at.timestamp()).ok())
            .context("the expiry does not parse")?;
    let origin = sub.get_one::<String>("origin").cloned().unwrap_or_default();

    let (vault, _) = context.open_confined(&reference.vault)?;
    let entries = vault.entries()?;
    let views = entries.list();
    let view = find(&views, &reference.entry)?;
    let wanted = sub
        .get_one::<String>("field")
        .cloned()
        .or_else(|| kind_of(view).map(|kind| main_spec(kind).name.to_owned()));
    let field = wanted
        .as_deref()
        .and_then(|wanted| field(view, wanted))
        .or_else(|| view.fields.iter().find(|field| field.kind.is_secret()))
        .context("the entry has no such field")?;
    let secret = reveal(&vault, &reference.entry, Some(&field.label))?;
    let device = vault.device();
    let certificate = device
        .me()
        .certificate
        .context("this device has no certificate yet")?;
    let mut chain = Vec::new();
    chain_for(device, &certificate, &mut chain)?;
    let genesis = device
        .signed_genesis()
        .context("this device has not read the vault's genesis")?;
    let statement = grant2::Statement {
        genesis: device.genesis_hash(),
        runner: runner.clone(),
        entry: reference.entry.clone(),
        field: field.label.clone(),
        version: entries.written_at(&view.id, &field.id).unwrap_or(0),
        origin,
        issued: now(),
        expires,
        issuer: certificate,
        secret: Zeroizing::new(secret.expose_secret().as_bytes().to_vec()),
    };
    drop(secret);
    let sealed = grant2::issue(&statement, &device.me().signing, &genesis, &chain)?;
    io::stdout().lock().write_all(&sealed)?;
    eprintln!(
        "A grant is a snapshot and cannot be revoked: rotate the secret to revoke access. It is valid \
         for this runner only, until it expires. The runner redeems it with:\n  \
         txc vault redeem <file> --identity <its key file> --vault-id {}\n\
         and may add --min-version {} to refuse older versions of this secret.",
        grant2::vault_id(&device.genesis_hash()),
        statement.version
    );
    Ok(())
}

/// `txc vault redeem` for a grant v2: checks it against the pinned vault id
/// and prints the secret to a pipe.
///
/// # Errors
///
/// Returns an error when any check fails.
pub fn redeem(sealed: &[u8], sub: &ArgMatches) -> Result<()> {
    let key_path = sub
        .get_one::<String>("identity")
        .context("give the runner's key with --identity <path>")?;
    let vault_id = sub.get_one::<String>("vault-id").context(
        "give the vault id this runner trusts with --vault-id, as the grant's issuer printed it",
    )?;
    let text = Zeroizing::new(
        std::fs::read_to_string(key_path)
            .with_context(|| format!("cannot read the key {key_path}"))?,
    );
    let identity: crate::vault::pq::Identity = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("AGE-SECRET-KEY-PQ-"))
        .context("the key file holds no post-quantum age key")?
        .parse()
        .map_err(|error: &str| anyhow!("the key: {error}"))?;
    let vault = grant2::parse_vault_id(vault_id)?;
    let min_version = sub.get_one::<u64>("min-version").copied().unwrap_or(0);
    let statement = grant2::redeem(
        sealed,
        &identity,
        &grant2::Expect {
            vault: &vault,
            now: now(),
            min_version,
        },
    )?;
    let secret = grant2::secret_text(&statement)?;
    let mut stdout = io::stdout().lock();
    match stdout
        .write_all(secret.expose_secret().as_bytes())
        .and_then(|()| stdout.flush())
    {
        Err(error) if error.kind() != io::ErrorKind::BrokenPipe => Err(error.into()),
        _ => Ok(()),
    }
}

// ------------------------------------------------------------------- ssh --

const SSH_CA_KIND: &str = "ssh-ca";
const SSH_CA_FIELD: &str = "ca-key";

/// `txc vault ssh-ca VAULT/NAME`: makes an SSH certificate authority whose
/// key never leaves txc.
///
/// # Errors
///
/// Returns an error when the name is taken or the write fails.
pub fn ssh_ca(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let reference: Reference = required(sub, "ENTRY").parse()?;
    let (mut vault, _) = context.open_confined(&reference.vault)?;
    let entries = vault.entries()?;
    ensure!(
        !entries
            .list()
            .iter()
            .any(|view| view.names.contains(&reference.entry)),
        "there is already an entry named {:?}",
        reference.entry
    );
    let ca = crate::vault::sshca::new_ca()?;
    let public = crate::vault::sshca::ca_public(&ca)?;
    let mut changes = Changes::new(&entries, now());
    let entry = changes.create(&reference.entry)?;
    changes.set_kind(&entry, SSH_CA_KIND)?;
    changes.classify(&entry, Sensitivity::OperationOnly)?;
    changes.add_field(&entry, FieldKind::SshCa, SSH_CA_FIELD, ca.as_bytes())?;
    vault.write(changes)?;
    eprintln!("Created the SSH certificate authority {reference}. Its key never leaves txc.");
    print_setup(&public)
}

fn print_setup(public: &str) -> Result<()> {
    eprintln!(
        "On each server, save this line as /etc/ssh/txc_user_ca.pub and add to sshd_config:\n  \
         TrustedUserCAKeys /etc/ssh/txc_user_ca.pub"
    );
    output(public)
}

fn find_ca(vault: &Synced, named: Option<&str>) -> Result<(Id, Id)> {
    let entries = vault.entries()?;
    let views = entries.list();
    let view = if let Some(name) = named {
        find(&views, name)?
    } else {
        let cas: Vec<&EntryView> = views
            .iter()
            .filter(|view| view.kinds.iter().any(|kind| kind == SSH_CA_KIND))
            .collect();
        match cas.as_slice() {
            [one] => *one,
            [] => bail!(
                "there is no SSH certificate authority here; make one with: txc vault ssh-ca NAME"
            ),
            _ => bail!("there are several SSH certificate authorities; pick one with --ca"),
        }
    };
    let field = view
        .fields
        .iter()
        .find(|field| field.kind == FieldKind::SshCa)
        .with_context(|| {
            format!(
                "{} is not an SSH certificate authority",
                view.names.join(" / ")
            )
        })?;
    Ok((view.id, field.id))
}

/// `txc vault ssh HOST`: signs a fresh key for this connection and runs
/// `ssh` with it; `--setup` prints what servers need.
///
/// # Errors
///
/// Returns an error when there is no CA or `ssh` does not start.
pub fn ssh(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let vault_name = context.which(sub.get_one::<String>("vault"))?;
    // Not confined: this runs ssh.
    let vault = context.open(&vault_name)?;
    let (entry, field) = find_ca(&vault, sub.get_one::<String>("ca").map(String::as_str))?;
    let entries = vault.entries()?;
    let values = entries.reveal(&entry, &field, Slot::Value)?;
    let [ca] = values.as_slice() else {
        bail!("the CA key has two versions; resolve it first")
    };
    let ca = Zeroizing::new(
        String::from_utf8(ca.to_vec()).map_err(|_utf8| anyhow!("the CA key is damaged"))?,
    );
    drop(values);
    if sub.get_flag("setup") {
        return print_setup(&crate::vault::sshca::ca_public(&ca)?);
    }
    let host = sub
        .get_one::<String>("HOST")
        .context("name the host to connect to, or give --setup")?;
    let principal = match sub.get_one::<String>("user") {
        Some(user) => user.clone(),
        None => std::env::var("USER")
            .or_else(|_unset| std::env::var("USERNAME"))
            .context("give the login with --user")?,
    };
    let minutes = sub
        .get_one::<u64>("minutes")
        .copied()
        .unwrap_or(crate::vault::sshca::DEFAULT_MINUTES);
    let key_id = format!(
        "txc {}",
        data_encoding::HEXLOWER.encode(&vault.device().me().device[..4])
    );
    let issued = crate::vault::sshca::issue(&ca, &principal, minutes, now(), &key_id)?;
    drop(ca);
    drop(vault);

    let program = ssh_program();
    let mut command = std::process::Command::new(&program);
    let key = crate::vault::deliver::Delivery::prepare(
        &SecretString::from(issued.key.to_string()),
        &mut command,
    )?;
    let certificate = crate::vault::deliver::Delivery::prepare(
        &SecretString::from(issued.certificate.clone()),
        &mut command,
    )?;
    command
        .arg("-i")
        .arg(&key.path)
        .arg("-o")
        .arg(format!("CertificateFile={}", certificate.path))
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg(host);
    if let Some(rest) = sub.get_many::<String>("ARGS") {
        command.args(rest);
    }
    drop(issued);
    let mut child = command
        .spawn()
        .with_context(|| format!("cannot run {program}"))?;
    drop(command);
    key.after_spawn();
    certificate.after_spawn();
    let status = child.wait()?;
    std::process::exit(crate::vault::command::exit_code(status));
}

/// `ssh`, or in a debug build a stand-in the tests name.
fn ssh_program() -> String {
    #[cfg(debug_assertions)]
    if let Ok(program) = std::env::var("TXC_VAULT_TEST_SSH") {
        return program;
    }
    "ssh".to_owned()
}

// --------------------------------------------------------------- recovery --

/// `txc vault recovery print | check`.
///
/// # Errors
///
/// Returns an error when the subcommand fails.
pub fn recovery(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let (verb, args) = sub
        .subcommand()
        .context("clap requires a recovery subcommand")?;
    let name = context.which(args.get_one::<String>("VAULT"))?;
    let vault = context.open_quiet(&name)?;
    match verb {
        "print" => {
            ensure!(
                io::stderr().is_terminal() && io::stdin().is_terminal(),
                "the recovery sheets are shown only at a terminal"
            );
            let kit = vault.kit()?;
            eprintln!(
                "You are about to see three recovery sheets and one card: about ten minutes of \
                 writing. Keep the sheets in three places and the card with you; any two sheets \
                 and the card recover everything. Nothing is saved or printed."
            );
            for (number, sheet) in kit.sheets.iter().enumerate() {
                pause(&format!(
                    "Press Enter to show sheet {} of {}.",
                    number + 1,
                    kit.sheets.len()
                ))?;
                eprintln!(
                    "\nSheet {} of {}:\n\n{}\n",
                    number + 1,
                    kit.sheets.len(),
                    words_in_rows(sheet)
                );
                pause("Press Enter once it is written down; the screen is then cleared.")?;
                clear_screen();
            }
            pause("Press Enter to show the card.")?;
            eprintln!("\nThe card:\n\n  {}\n", kit.card.as_str());
            pause("Press Enter once it is written down; the screen is then cleared.")?;
            clear_screen();
            ensure!(
                prompt::confirm_value(
                    "Type \"written\" once all three sheets and the card are written down:",
                    "written",
                    ""
                )?,
                "the sheets stay on this device, sealed; run this again to finish"
            );
            vault.kit_done()?;
            eprintln!("Done. Check a sheet now and then with: txc vault recovery check {name}");
            Ok(())
        }
        "check" => {
            let genesis = vault
                .genesis()
                .context("this device has not read the vault's genesis yet")?
                .clone();
            let sheet = prompt::secret_from_terminal("Sheet words")?;
            let card = prompt::secret_from_terminal("Card words")?;
            let index = synced::check_sheet(&genesis, sheet.expose_secret(), card.expose_secret())?;
            eprintln!(
                "Sheet {} and the card belong to this vault and are intact.",
                index + 1
            );
            Ok(())
        }
        other => bail!("unknown recovery subcommand {other}"),
    }
}

fn pause(message: &str) -> Result<()> {
    eprint!("{message}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(())
}

fn clear_screen() {
    crossterm::execute!(
        io::stderr(),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::Purge),
        crossterm::cursor::MoveTo(0, 0),
    )
    .ok();
}

fn words_in_rows(sheet: &str) -> String {
    let words: Vec<&str> = sheet.split_whitespace().collect();
    words
        .chunks(6)
        .enumerate()
        .map(|(row, chunk)| {
            let cells: Vec<String> = chunk
                .iter()
                .enumerate()
                .map(|(column, word)| format!("{:>2}. {word:<10}", row * 6 + column + 1))
                .collect();
            format!("  {}", cells.join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------- entries --

fn find<'a>(views: &'a [EntryView], name: &str) -> Result<&'a EntryView> {
    let found: Vec<&EntryView> = views
        .iter()
        .filter(|view| view.names.iter().any(|candidate| candidate == name))
        .collect();
    match found.as_slice() {
        [one] => Ok(one),
        [] => bail!("there is no entry named {name:?}"),
        _ => bail!(
            "{} entries are named {name:?}; rename one with txc vault edit",
            found.len()
        ),
    }
}

fn kind_of(view: &EntryView) -> Option<Kind> {
    view.kinds.first().and_then(|kind| Kind::from_id(kind))
}

fn field<'a>(view: &'a EntryView, label: &str) -> Option<&'a FieldView> {
    view.fields.iter().find(|field| field.label == label)
}

/// The everyday verbs on a synced vault.
///
/// # Errors
///
/// Returns an error when the verb fails.
pub fn entry(context: &Context<'_>, verb: &str, sub: &ArgMatches) -> Result<()> {
    match verb {
        "list" => {
            let name = context.which(sub.get_one::<String>("VAULT"))?;
            let (vault, _) = context.open_confined(&name)?;
            let mut rows = vec![["Name".to_owned(), "Kind".to_owned(), String::new()]];
            let mut views = vault.entries()?.list();
            views.sort_by(|a, b| a.names.cmp(&b.names));
            for view in views {
                rows.push([
                    view.names.join(" / "),
                    kind_of(&view).map_or_else(String::new, |kind| kind.label().to_owned()),
                    if view.conflict {
                        "two versions".to_owned()
                    } else {
                        String::new()
                    },
                ]);
            }
            output(&table(&rows))
        }
        "add" => add(context, sub),
        "show" => {
            let reference: Reference = required(sub, "ENTRY").parse()?;
            let (vault, _) = context.open_confined(&reference.vault)?;
            let views = vault.entries()?.list();
            let view = find(&views, &reference.entry)?;
            let mut rows = vec![
                ["Name".to_owned(), view.names.join(" / ")],
                ["Vault".to_owned(), reference.vault.clone()],
            ];
            if let Some(kind) = kind_of(view) {
                rows.push(["Kind".to_owned(), kind.label().to_owned()]);
            }
            for field in &view.fields {
                let shown = field
                    .shown
                    .as_ref()
                    .map_or_else(|| MASK.to_owned(), |values| values.join(" / "));
                let conflict = if field.conflict {
                    "  (two versions)"
                } else {
                    ""
                };
                rows.push([field.label.clone(), format!("{shown}{conflict}")]);
            }
            output(&table(&rows))
        }
        "copy" => copy(context, sub),
        "edit" => edit(context, sub),
        "rm" => {
            let reference: Reference = required(sub, "ENTRY").parse()?;
            let (mut vault, _) = context.open_confined(&reference.vault)?;
            let entries = vault.entries()?;
            let views = entries.list();
            let id = find(&views, &reference.entry)?.id;
            if !sub.get_flag("yes") {
                ensure!(
                    prompt::confirm(&format!("Remove {reference}?"), "pass --yes")?,
                    "nothing was removed"
                );
            }
            let mut changes = Changes::new(&entries, now());
            changes.delete_entry(&id)?;
            vault.write(changes)?;
            eprintln!("Removed {reference}. It can be restored for 30 days.");
            Ok(())
        }
        "resolve" => resolve(context, sub),
        "grant" => grant(context, sub),
        other => bail!("{other} is not available for synced vaults yet"),
    }
}

fn add(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let reference: Reference = required(sub, "ENTRY").parse()?;
    let kind = Kind::from_id(required(sub, "kind")).context("clap checked the kind")?;
    let plain = plain_fields(sub)?;
    let secret_fields = checked_field_names(sub, "secret-field")?;
    check_sensitivities(kind, &plain, &secret_fields)?;
    ensure!(
        sub.get_many::<String>("tag").is_none() && !sub.get_flag("favourite"),
        "tags and favourites are not available for synced vaults yet"
    );
    let primary = main_spec(kind);
    let (mut vault, _) = context.open_confined(&reference.vault)?;
    let entries = vault.entries()?;
    ensure!(
        !entries
            .list()
            .iter()
            .any(|view| view.names.contains(&reference.entry)),
        "there is already an entry named {:?} in the vault {}",
        reference.entry,
        reference.vault
    );
    let (secret, generated) = main_secret(sub, primary)?;
    let mut changes = Changes::new(&entries, now());
    let entry = changes.create(&reference.entry)?;
    changes.set_kind(&entry, kind.id())?;
    changes.add_field(
        &entry,
        FieldKind::Secret,
        primary.name,
        secret.expose_secret().as_bytes(),
    )?;
    for (label, value) in &plain {
        changes.add_field(&entry, plain_kind(label), label, value.as_bytes())?;
    }
    for label in secret_fields {
        let shown = kind.spec(&label).map_or(label.as_str(), |spec| spec.label);
        let value = prompt::secret_from_terminal(shown)?;
        changes.add_field(
            &entry,
            FieldKind::Secret,
            &label,
            value.expose_secret().as_bytes(),
        )?;
    }
    vault.write(changes)?;
    eprintln!("Added {reference}.");
    if generated {
        eprintln!(
            "Its {} was generated; copy it with: txc vault copy {reference}",
            primary.label.to_lowercase()
        );
    }
    Ok(())
}

fn plain_kind(label: &str) -> FieldKind {
    match label {
        "username" => FieldKind::Username,
        "url" => FieldKind::Origin,
        _ => FieldKind::Note,
    }
}

fn copy(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let reference: Reference = required(sub, "ENTRY").parse()?;
    let print = sub.get_flag("print");
    if print {
        ensure!(
            !io::stdout().is_terminal(),
            "--print will not write a secret to the terminal; pipe it into a program, or leave out \
             --print to use the clipboard"
        );
    }
    let (vault, _) = context.open_confined(&reference.vault)?;
    let secret = reveal(
        &vault,
        &reference.entry,
        sub.get_one::<String>("field").map(String::as_str),
    )?;
    drop(vault);
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
    wait_then_clear(held, seconds, &format!("secret of {reference}"))
}

/// One field's single value, decrypted: the named field, or the entry's
/// main secret.
///
/// # Errors
///
/// Returns an error when there is no such field or it has two versions.
pub fn reveal(vault: &Synced, entry: &str, label: Option<&str>) -> Result<SecretString> {
    let entries = vault.entries()?;
    let views = entries.list();
    let view = find(&views, entry)?;
    let wanted = label
        .map(str::to_owned)
        .or_else(|| kind_of(view).map(|kind| main_spec(kind).name.to_owned()));
    let field = wanted
        .as_deref()
        .and_then(|wanted| field(view, wanted))
        .or_else(|| view.fields.iter().find(|field| field.kind.is_secret()))
        .ok_or_else(|| anyhow!("{entry} has no field {}", wanted.unwrap_or_default()))?;
    ensure!(
        field.kind != FieldKind::SshCa && view.sensitivity != Sensitivity::OperationOnly,
        "{entry} is used only inside txc and is never released; for an SSH CA use: txc vault ssh"
    );
    let values = entries.reveal(&view.id, &field.id, Slot::Value)?;
    let [value] = values.as_slice() else {
        bail!(
            "{entry} has two versions of {}; pick one: txc vault resolve {}/{entry}",
            field.label,
            vault.name
        );
    };
    let text =
        String::from_utf8(value.to_vec()).map_err(|_error| anyhow!("the value is not text"))?;
    Ok(SecretString::from(text))
}

fn edit(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let reference: Reference = required(sub, "ENTRY").parse()?;
    let plain = plain_fields(sub)?;
    let secret_fields = checked_field_names(sub, "secret-field")?;
    let removed = checked_field_names(sub, "remove-field")?;
    let rename = sub.get_one::<String>("rename");
    let new_main = ["set-secret", "generate", "secret-from-stdin"]
        .iter()
        .any(|flag| sub.get_flag(flag));
    ensure!(
        sub.get_many::<String>("tag").is_none() && sub.get_many::<String>("untag").is_none(),
        "tags are not available for synced vaults yet"
    );
    ensure!(
        new_main
            || rename.is_some()
            || !plain.is_empty()
            || !secret_fields.is_empty()
            || !removed.is_empty(),
        "nothing to change; see: txc vault edit --help"
    );
    let (mut vault, _) = context.open_confined(&reference.vault)?;
    let entries = vault.entries()?;
    let views = entries.list();
    let view = find(&views, &reference.entry)?;
    let kind = kind_of(view).unwrap_or(Kind::Login);
    check_sensitivities(kind, &plain, &secret_fields)?;
    let mut changes = Changes::new(&entries, now());
    if let Some(name) = rename {
        changes.rename(&view.id, name)?;
    }
    let set = |changes: &mut Changes<'_>,
               label: &str,
               field_kind: FieldKind,
               value: &[u8]|
     -> Result<()> {
        match field(view, label) {
            Some(existing) => changes.set_field(&view.id, &existing.id, existing.kind, value),
            None => changes
                .add_field(&view.id, field_kind, label, value)
                .map(|_| ()),
        }
    };
    if new_main {
        let primary = main_spec(kind);
        let (secret, _) = main_secret(sub, primary)?;
        set(
            &mut changes,
            primary.name,
            FieldKind::Secret,
            secret.expose_secret().as_bytes(),
        )?;
    }
    for (label, value) in &plain {
        set(&mut changes, label, plain_kind(label), value.as_bytes())?;
    }
    for label in secret_fields {
        let value = prompt::secret_from_terminal(&label)?;
        set(
            &mut changes,
            &label,
            FieldKind::Secret,
            value.expose_secret().as_bytes(),
        )?;
    }
    for label in removed {
        let existing = field(view, &label)
            .ok_or_else(|| anyhow!("{} has no field {label}", reference.entry))?;
        changes.delete_field(&view.id, &existing.id)?;
    }
    vault.write(changes)?;
    eprintln!("Changed {reference}.");
    Ok(())
}

/// `txc vault resolve VAULT/ENTRY`: shows the versions of what conflicts,
/// and with `--field` and `--keep` keeps one.
fn resolve(context: &Context<'_>, sub: &ArgMatches) -> Result<()> {
    let reference: Reference = required(sub, "ENTRY").parse()?;
    let (mut vault, _) = context.open_confined(&reference.vault)?;
    let entries = vault.entries()?;
    let views = entries.list();
    let view = find(&views, &reference.entry)?;
    let registers = entries.registers();
    let mut conflicts: BTreeMap<String, (Id, FieldKind)> = BTreeMap::new();
    if registers
        .get(&(view.id, NAME, Slot::Value))
        .is_some_and(|field| field.state.conflict)
    {
        conflicts.insert("name".to_owned(), (NAME, FieldKind::Name));
    }
    for field in view.fields.iter().filter(|field| field.conflict) {
        conflicts.insert(field.label.clone(), (field.id, field.kind));
    }
    ensure!(
        !conflicts.is_empty(),
        "{reference} has only one version of everything"
    );
    let Some(label) = sub.get_one::<String>("field") else {
        for (label, (id, kind)) in &conflicts {
            let values = entries.reveal(&view.id, id, Slot::Value)?;
            eprintln!("{label}:");
            for (number, value) in values.iter().enumerate() {
                let shown = if kind.is_secret() {
                    let digest = crate::vault::crypto::sha256(&[value]);
                    format!(
                        "{MASK} (fingerprint {})",
                        data_encoding::HEXLOWER.encode(&digest[..3])
                    )
                } else {
                    String::from_utf8_lossy(value).into_owned()
                };
                eprintln!("  {}. {shown}", number + 1);
            }
        }
        eprintln!("Keep one with: txc vault resolve {reference} --field NAME --keep NUMBER");
        return Ok(());
    };
    let (id, kind) = conflicts
        .get(label)
        .ok_or_else(|| anyhow!("{label} has only one version"))?;
    let keep = *sub
        .get_one::<usize>("keep")
        .context("--keep NUMBER picks the version to keep")?;
    let values = entries.reveal(&view.id, id, Slot::Value)?;
    let chosen: Zeroizing<Vec<u8>> = values
        .get(keep.saturating_sub(1))
        .cloned()
        .ok_or_else(|| anyhow!("there is no version {keep}"))?;
    let mut changes = Changes::new(&entries, now());
    if *id == NAME {
        changes.rename(&view.id, &String::from_utf8_lossy(&chosen))?;
    } else {
        changes.set_field(&view.id, id, *kind, &chosen)?;
    }
    vault.write(changes)?;
    eprintln!("Kept version {keep} of {label}.");
    Ok(())
}

// ---------------------------------------------------------------- migrate --

/// `txc vault migrate VAULT --folder DIR`: copies a vault of today's format
/// into a new synced vault. The old vault stays as it is, so going back is
/// removing the synced one.
///
/// # Errors
///
/// Returns an error when either vault does not open.
pub fn migrate(context: &Context<'_>, keyring: &Keyring, sub: &ArgMatches) -> Result<()> {
    let old = required(sub, "VAULT");
    let name = sub.get_one::<String>("name").map_or(old, String::as_str);
    let opened = keyring.open(old)?;
    let mut vault = if synced::exists(context.home, name) {
        context.open(name)?
    } else {
        let folder = sub
            .get_one::<String>("folder")
            .context("the synced vault does not exist yet; give --folder DIR")?;
        let folder = std::fs::canonicalize(folder)
            .with_context(|| format!("the folder {folder} does not exist"))?;
        let passphrase = context
            .passphrase
            .ask_new("New passphrase for the synced vault: ")?;
        let params = working("Measuring this computer...", synced::calibrate)?;
        working("Creating the vault...", || {
            Synced::create(context.home, name, &folder, &passphrase, params)
        })?
    };
    let entries = vault.entries()?;
    let existing: Vec<String> = entries
        .list()
        .into_iter()
        .flat_map(|view| view.names)
        .collect();
    let mut changes = Changes::new(&entries, now());
    let mut copied = 0_usize;
    for old_entry in opened.vault().entries() {
        if existing.contains(&old_entry.name) {
            continue;
        }
        let entry = changes.create(&old_entry.name)?;
        changes.set_kind(&entry, old_entry.kind.id())?;
        for old_field in &old_entry.fields {
            if let Some(value) = old_entry.plain(&old_field.name) {
                changes.add_field(
                    &entry,
                    plain_kind(&old_field.name),
                    &old_field.name,
                    value.as_bytes(),
                )?;
            } else {
                let secret = opened.reveal(keyring, &old_entry.name, &old_field.name)?;
                changes.add_field(
                    &entry,
                    FieldKind::Secret,
                    &old_field.name,
                    secret.expose_secret().as_bytes(),
                )?;
            }
        }
        copied = copied.saturating_add(1);
    }
    vault.write(changes)?;
    vault.checkpoint()?;
    eprintln!(
        "Copied {copied} entries from \"{old}\" into the synced vault \"{name}\". The old vault is \
         unchanged; tags and favourites were not copied."
    );
    Ok(())
}

/// Whether an `init` means a synced vault.
#[must_use]
pub fn folder_of(sub: &ArgMatches) -> Option<&String> {
    sub.get_one::<String>("folder")
}

/// Resolves `txc://VAULT/ENTRY[/FIELD]` for a synced vault, for `run`.
///
/// # Errors
///
/// Returns an error when the entry or field does not exist.
pub fn resolve_reference(
    context: &Context<'_>,
    opened: &mut BTreeMap<String, Synced>,
    vault: &str,
    entry: &str,
    field: Option<&str>,
) -> Result<SecretString> {
    if !opened.contains_key(vault) {
        let synced = context.open(vault)?;
        opened.insert(vault.to_owned(), synced);
    }
    let synced = opened
        .get(vault)
        .ok_or_else(|| anyhow!("the vault {vault} did not open"))?;
    reveal(synced, entry, field)
}
