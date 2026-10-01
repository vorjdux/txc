//! A vault kept in a sync folder, as one device holds it (study sections 5,
//! 7 and 12).
//!
//! The shared folder holds only objects. Everything else stays in the txc
//! home, per vault, in `synced/<name>/`:
//!
//! - `folder`: the path of the sync folder;
//! - `device.key`: this device's keys, sealed with the passphrase and a
//!   second factor from the OS keystore (Secret Service, Keychain or
//!   Credential Manager);
//! - `state.age`: the device's view, sealed to itself;
//! - `recovery.age`: the recovery sheets and card, sealed to the device
//!   until they are written down, then erased.

// Protocol code: no unsafe block, and no module-level exception either.
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, anyhow, bail, ensure};
use zeroize::Zeroizing;

use crate::vault::authority::Authenticator;
use crate::vault::authority::{
    Genesis, Lifetime, Policy, Role, RootSet, new_id, normalize_card, recovery_identity, root_key,
    share_commitment,
};
use crate::vault::composite::SigningKey;
use crate::vault::device::{Device, Me};
use crate::vault::entries::{Changes, Entries};
use crate::vault::hardware::{Hardware, Pinned, Prompter};
use crate::vault::home::{self, Home, PRIVATE};
use crate::vault::local::{self, KdfParams};
use crate::vault::object::{Hash, Id};
use crate::vault::pairing::{AdminStart, DeviceReply, Paired};
use crate::vault::slip39;
use crate::vault::store::Store;
use crate::vault::wire::{Reader, Writer};

const DIR: &str = "synced";
const FOLDER: &str = "folder";
const KEYS: &str = "device.key";
const STATE: &str = "state.age";
const KIT: &str = "recovery.age";
const HARDWARE: &str = "hardware";
const SECOND: &str = "second.age";
const PLUGINS: &str = "plugins";
const ACKNOWLEDGED: &str = "acknowledged";
const CHECKS: &str = "checks";
const SNOOZED: &str = "snoozed";
const REMINDED: &str = "reminded";
const KIT_PDF: &str = "kit-pdf";
const KEYSTORE_SERVICE: &str = "txc vault";
const CARD_WORDS: usize = 8;
const SHEETS: u8 = 3;
const SHEET_THRESHOLD: u8 = 2;
const SLIP39_EXPONENT: u8 = 1;
const KEY_LIMIT: usize = 64 * 1024;
const KIT_LIMIT: usize = 64 * 1024;
/// The retention window for tombstones, in seconds (study section 9).
pub const RETENTION: u64 = 30 * 24 * 60 * 60;

/// Seconds since the epoch.
#[must_use]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

fn dir(home: &Home, name: &str) -> PathBuf {
    home.root().join(DIR).join(name)
}

/// The names of the synced vaults on this device.
///
/// # Errors
///
/// Returns an error when the directory exists but cannot be read.
pub fn names(home: &Home) -> Result<Vec<String>> {
    let root = home.root().join(DIR);
    if !home::exists(&root) {
        return Ok(Vec::new());
    }
    let mut names: Vec<String> = fs::read_dir(&root)?
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| home::exists(&dir(home, name).join(KEYS)))
        .collect();
    names.sort();
    Ok(names)
}

/// Whether a vault of this name is a synced vault on this device.
#[must_use]
pub fn exists(home: &Home, name: &str) -> bool {
    home::exists(&dir(home, name).join(KEYS))
}

// ---------------------------------------------------------- second factor --

#[cfg(test)]
static TEST_KEYSTORE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Test builds only: a directory stands in for the OS keystore so tests run
/// where no keyring daemon does. Release builds never read the variable.
fn test_keystore() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(dir) = TEST_KEYSTORE.get() {
        return Some(dir.clone());
    }
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os("TXC_VAULT_TEST_KEYSTORE") {
        return Some(PathBuf::from(dir));
    }
    None
}

/// The second key-at-rest factor for a device, from the OS keystore;
/// created on first use when `create` is set.
fn second_factor(device: &Id, create: bool) -> Result<Zeroizing<[u8; 32]>> {
    let account = hex(device);
    if let Some(dir) = test_keystore() {
        let path = dir.join(&account);
        if create && !home::exists(&path) {
            let mut secret = [0; 32];
            rand::fill(&mut secret[..]);
            home::write_atomic(&path, &secret, None)?;
        }
        let bytes = home::read_private(&path, 32, 0)?;
        return <[u8; 32]>::try_from(bytes.as_slice())
            .map(Zeroizing::new)
            .map_err(|_bytes| anyhow!("the test keystore holds a damaged secret"));
    }
    let entry = keyring::Entry::new(KEYSTORE_SERVICE, &account).map_err(|error| {
        anyhow!("this system offers no keystore for the second factor ({error}); a vault needs one")
    })?;
    match entry.get_secret() {
        Ok(secret) => <[u8; 32]>::try_from(secret.as_slice())
            .map(Zeroizing::new)
            .map_err(|_bytes| {
                anyhow!("the keystore holds a damaged second factor for this device")
            }),
        Err(keyring::Error::NoEntry) if create => {
            let mut secret = Zeroizing::new([0; 32]);
            rand::fill(&mut secret[..]);
            entry
                .set_secret(&secret[..])
                .map_err(|error| anyhow!("cannot store the second factor: {error}"))?;
            Ok(secret)
        }
        Err(keyring::Error::NoEntry) => {
            bail!("this device's second factor is missing from the keystore")
        }
        Err(error) => bail!("cannot read the second factor from the keystore: {error}"),
    }
}

/// Forgets a device's second factor in the OS keystore, once hardware holds
/// it instead. Best effort: an entry left behind opens nothing new.
fn forget_second_factor(device: &Id) {
    let account = hex(device);
    if let Some(dir) = test_keystore() {
        std::fs::remove_file(dir.join(&account)).ok();
        return;
    }
    if let Ok(entry) = keyring::Entry::new(KEYSTORE_SERVICE, &account) {
        entry.delete_credential().ok();
    }
}

/// The second factor candidates for a device, the hardware first when it
/// holds one. The keystore comes second only as a fall-back, for a switch to
/// hardware that did not finish.
fn second_factors(
    dir: &Path,
    device: &Id,
    prompter: &dyn Prompter,
) -> Result<Vec<Zeroizing<[u8; 32]>>> {
    let mut factors = Vec::new();
    if home::exists(&dir.join(HARDWARE)) {
        let hardware = Hardware::decode(&home::read_private(
            &dir.join(HARDWARE),
            KEY_LIMIT,
            PRIVATE,
        )?)?;
        let sealed = home::read_private(&dir.join(SECOND), KEY_LIMIT, PRIVATE)?;
        let opened = hardware.open(&sealed, prompter)?;
        let factor: [u8; 32] = opened
            .as_slice()
            .try_into()
            .map_err(|_len| anyhow!("the hardware returned a damaged factor"))?;
        factors.push(Zeroizing::new(factor));
        if let Ok(fallback) = second_factor(device, false) {
            factors.push(fallback);
        }
    } else {
        factors.push(second_factor(device, false)?);
    }
    Ok(factors)
}

// ------------------------------------------------------------ recovery kit --

/// The recovery kit: three sheets and one card.
pub struct Kit {
    /// One SLIP-39 mnemonic per sheet.
    pub sheets: Vec<Zeroizing<String>>,
    /// The card: the passphrase every sheet needs.
    pub card: Zeroizing<String>,
}

impl Kit {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Writer::default();
        out.str(&self.card);
        out.count(self.sheets.len());
        for sheet in &self.sheets {
            out.str(sheet);
        }
        Zeroizing::new(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        let card = Zeroizing::new(input.str(1024)?);
        let sheets = (0..input.count(16)?)
            .map(|_| Ok(Zeroizing::new(input.str(4096)?)))
            .collect::<Result<_>>()?;
        input.finish()?;
        Ok(Self { sheets, card })
    }
}

/// A card: random words from the SLIP-39 list, already in canonical form.
fn new_card() -> Zeroizing<String> {
    Zeroizing::new(slip39::random_words(CARD_WORDS).join(" "))
}

/// Checks one sheet and the card against genesis, as the offline half of a
/// sheet check does: the root key they derive and the share commitment must
/// be the ones genesis names.
///
/// # Errors
///
/// Returns an error saying which part does not match.
pub fn check_sheet(set: &RootSet, sheet: &str, card: &str) -> Result<u8> {
    check_sheet_key(set, sheet, card).map(|(index, _)| index)
}

/// The same, returning the sheet's root key too, for a root action.
fn check_sheet_key(set: &RootSet, sheet: &str, card: &str) -> Result<(u8, SigningKey)> {
    let index = slip39::share_index(sheet)?;
    let share = slip39::share_value(sheet)?;
    let root = set
        .roots
        .get(usize::from(index))
        .ok_or_else(|| anyhow!("the sheet's number is out of range"))?;
    ensure!(
        set.commitments.get(usize::from(index)) == Some(&share_commitment(&share)),
        "this sheet does not belong to this vault, or was replaced by a reissue"
    );
    let key = root_key(&share, card, usize::from(index))?;
    ensure!(
        key.verifying_key() == *root,
        "the sheet belongs to this vault, but the card does not match it"
    );
    Ok((index, key))
}

/// Two distinct sheets' root keys and the card, checked against the roots
/// in force, for a root action.
///
/// # Errors
///
/// Returns an error when a sheet or the card does not match, or both
/// sheets are the same one.
pub fn root_keys(set: &RootSet, sheets: [&str; 2], card: &str) -> Result<[(SigningKey, u8); 2]> {
    let (a, first) = check_sheet_key(set, sheets[0], card)?;
    let (b, second) = check_sheet_key(set, sheets[1], card)?;
    ensure!(a != b, "two different sheets are needed");
    Ok([(first, a), (second, b)])
}

/// A fresh recovery kit and the roots, recovery recipient and commitments
/// it makes, as at creation or reissue.
fn new_kit() -> Result<(Kit, RootSet, [SigningKey; 3])> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    rand::fill(&mut secret[..]);
    let card = new_card();
    let sheets = slip39::split(&secret[..], &card, SHEET_THRESHOLD, SHEETS, SLIP39_EXPONENT)?;
    let shares: Vec<Zeroizing<Vec<u8>>> = sheets
        .iter()
        .map(|sheet| slip39::share_value(sheet))
        .collect::<Result<_>>()?;
    let key = |index: usize| -> Result<SigningKey> {
        root_key(
            shares.get(index).context("three sheets are needed")?,
            &card,
            index,
        )
    };
    let keys = [key(0)?, key(1)?, key(2)?];
    let commitments = [0, 1, 2].map(|index| {
        shares
            .get(index)
            .map_or([0; 48], |share| share_commitment(share))
    });
    let set = RootSet {
        roots: [
            keys[0].verifying_key(),
            keys[1].verifying_key(),
            keys[2].verifying_key(),
        ],
        recovery: recovery_identity(&secret).to_public(),
        commitments,
    };
    Ok((Kit { sheets, card }, set, keys))
}

/// A vault read back from its folder with two sheets and the card alone
/// (study section 12): the recovery identity is a recipient of every control
/// object, so it holds every sender key and reads every entry.
pub struct Recovered {
    /// The reader, holding what it verified.
    pub device: Device,
}

impl Recovered {
    /// Opens a protected value, which is sealed to the recovery recipient
    /// as well as to every security key.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not sealed to this vault's
    /// recovery recipient.
    pub fn open_protected(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let decryptor = age::Decryptor::new_buffered(sealed)
            .map_err(|_error| anyhow!("a protected value is damaged"))?;
        let mut reader = decryptor
            .decrypt(std::iter::once(
                &self.device.me().identity as &dyn age::Identity,
            ))
            .map_err(|_error| anyhow!("a protected value is not sealed to the recovery key"))?;
        let mut plain = Zeroizing::new(Vec::new());
        std::io::Read::read_to_end(&mut reader, &mut plain)?;
        Ok(plain)
    }
}

/// Reads a vault from its folder with two sheets and the card, on a machine
/// that holds nothing else of it.
///
/// # Errors
///
/// Returns an error when the sheets and card do not combine, or the folder
/// holds no vault they belong to.
pub fn recover(folder: &Path, sheets: &[&str], card: &str) -> Result<Recovered> {
    ensure!(
        sheets.len() >= usize::from(SHEET_THRESHOLD),
        "two sheets are needed"
    );
    let card = normalize_card(card)?;
    let secret = slip39::combine(sheets, &card).context(
        "the sheets and the card do not combine; check each with txc vault recovery check",
    )?;
    let secret: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_length| anyhow!("these sheets do not hold a txc recovery secret"))?;
    let commitments = sheets
        .iter()
        .map(|sheet| {
            Ok((
                slip39::share_index(sheet)?,
                share_commitment(&slip39::share_value(sheet)?),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut device = Device::recovering(recovery_identity(&secret), commitments);
    let store = Store::open(folder, false)?;
    device.sync(&store)?;
    ensure!(
        device.genesis().is_some(),
        "{} holds no vault these sheets belong to",
        folder.display()
    );
    Ok(Recovered { device })
}

/// How often each device writes a checkpoint at least, when it opens a vault.
pub const CHECKPOINT_EVERY: u64 = 60 * 60;
/// How long changes may wait for objects they depend on before this device
/// asks for a snapshot (rule 7).
pub const WAIT_LIMIT: u64 = 3 * 24 * 60 * 60;

/// How often one sheet is checked: twice a year, rotating through the three.
pub const CHECK_EVERY: u64 = 182 * 24 * 60 * 60;
/// How often a full recovery is rehearsed.
pub const DRILL_EVERY: u64 = 365 * 24 * 60 * 60;

/// When this device last saw the sheets written down, checked and drilled.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Checks {
    /// When the sheets were written down.
    pub written: Option<u64>,
    /// When each sheet was last checked.
    pub sheets: [Option<u64>; SHEETS as usize],
    /// When a full recovery was last rehearsed.
    pub drill: Option<u64>,
}

impl Checks {
    fn encode(&self) -> String {
        let written = self.written.map(|at| format!("written {at}"));
        let sheets = self
            .sheets
            .iter()
            .enumerate()
            .filter_map(|(index, at)| at.map(|at| format!("sheet {index} {at}")));
        let drill = self.drill.map(|at| format!("drill {at}"));
        written
            .into_iter()
            .chain(sheets)
            .chain(drill)
            .map(|line| line + "\n")
            .collect()
    }

    fn decode(text: &str) -> Self {
        let mut checks = Self::default();
        for line in text.lines() {
            let words: Vec<&str> = line.split(' ').collect();
            match words.as_slice() {
                ["written", at] => checks.written = at.parse().ok(),
                ["drill", at] => checks.drill = at.parse().ok(),
                ["sheet", index, at] => {
                    if let Some(slot) = index
                        .parse::<usize>()
                        .ok()
                        .and_then(|index| checks.sheets.get_mut(index))
                    {
                        *slot = at.parse().ok();
                    }
                }
                _ => {}
            }
        }
        checks
    }

    /// The sheet to check next, when one is due: the one checked longest
    /// ago, once half a year has passed since any check.
    #[must_use]
    pub fn sheet_due(&self, now: u64) -> Option<u8> {
        let since = self.sheets.iter().flatten().chain(&self.written).max()?;
        if now.saturating_sub(*since) < CHECK_EVERY {
            return None;
        }
        (0..SHEETS).min_by_key(|index| self.sheets.get(usize::from(*index)).copied().flatten())
    }

    /// Whether a recovery drill is due: a year after the last, or after the
    /// sheets were written down.
    #[must_use]
    pub fn drill_due(&self, now: u64) -> bool {
        self.drill
            .or(self.written)
            .is_some_and(|since| now.saturating_sub(since) >= DRILL_EVERY)
    }
}

/// The recovery dates recorded for a synced vault on this device.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be read.
pub fn checks(home: &Home, name: &str) -> Result<Checks> {
    let path = dir(home, name).join(CHECKS);
    if !home::exists(&path) {
        return Ok(Checks::default());
    }
    let bytes = home::read_private(&path, 4096, PRIVATE)?;
    Ok(Checks::decode(&String::from_utf8_lossy(&bytes)))
}

/// Records recovery dates for a synced vault on this device.
///
/// # Errors
///
/// Returns an error when the write fails.
pub fn record_checks(home: &Home, name: &str, update: impl FnOnce(&mut Checks)) -> Result<()> {
    let mut current = checks(home, name)?;
    update(&mut current);
    home::write_atomic(
        &dir(home, name).join(CHECKS),
        current.encode().as_bytes(),
        None,
    )
}

/// What a root action does.
#[derive(Clone, Copy, Debug)]
pub enum RootAction {
    /// Makes a member device an admin, which then adds devices.
    Promote(Id),
    /// Removes an admin device, voiding what it issued afterwards.
    RemoveAdmin(Id),
    /// Lets an admin add this many more devices or security keys.
    Allow(Id, u32),
}

/// Erases a synced vault's local files on this device and its keystore
/// secret. The folder is untouched. Best effort: overwritten, then removed.
fn wipe(dir: &Path, device: &Id) {
    forget_second_factor(device);
    for file in [
        KEYS,
        STATE,
        SECOND,
        HARDWARE,
        KIT,
        CHECKS,
        SNOOZED,
        REMINDED,
        "backup",
        KIT_PDF,
        PLUGINS,
        ACKNOWLEDGED,
        FOLDER,
    ] {
        let path = dir.join(file);
        if let Ok(metadata) = fs::metadata(&path) {
            let zeros = vec![0; usize::try_from(metadata.len()).unwrap_or(0)];
            home::write_atomic(&path, &zeros, None).ok();
            fs::remove_file(&path).ok();
        }
    }
    fs::remove_dir(dir).ok();
}

/// Sync folders found on this computer, with the name of the tool that
/// keeps each (study section 19: setup detects instead of asking).
#[must_use]
pub fn sync_folders() -> Vec<(&'static str, PathBuf)> {
    let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
    else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let mut offer = |tool: &'static str, path: PathBuf| {
        if path.is_dir() && !found.iter().any(|(_, known)| *known == path) {
            found.push((tool, path));
        }
    };
    offer("Dropbox", home.join("Dropbox"));
    offer("Syncthing", home.join("Sync"));
    offer("Nextcloud", home.join("Nextcloud"));
    offer("Google Drive", home.join("Google Drive"));
    offer("OneDrive", home.join("OneDrive"));
    if let Some(one_drive) = std::env::var_os("OneDrive") {
        offer("OneDrive", PathBuf::from(one_drive));
    }
    offer(
        "iCloud Drive",
        home.join("Library/Mobile Documents/com~apple~CloudDocs"),
    );
    if let Ok(entries) = fs::read_dir(home.join("Library/CloudStorage")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let tool = if name.starts_with("Dropbox") {
                "Dropbox"
            } else if name.starts_with("GoogleDrive") {
                "Google Drive"
            } else if name.starts_with("OneDrive") {
                "OneDrive"
            } else {
                continue;
            };
            offer(tool, entry.path());
        }
    }
    found
}

/// How long a yellow status line stays snoozed.
pub const SNOOZE_FOR: u64 = 30 * 24 * 60 * 60;

/// The key a status line is snoozed by: its text, so a line that changes,
/// as a count going up, shows again.
#[must_use]
pub fn line_key(line: &str) -> String {
    hex(&crate::vault::crypto::sha256(&[line.as_bytes()])[..8])
}

/// The status lines snoozed on this device and until when, expired ones
/// left out.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be read.
pub fn snoozed(home: &Home, name: &str) -> Result<std::collections::BTreeMap<String, u64>> {
    let path = dir(home, name).join(SNOOZED);
    if !home::exists(&path) {
        return Ok(std::collections::BTreeMap::new());
    }
    let bytes = home::read_private(&path, 64 * 1024, PRIVATE)?;
    let at = now();
    Ok(String::from_utf8_lossy(&bytes)
        .lines()
        .filter_map(|line| {
            let (key, until) = line.split_once(' ')?;
            let until: u64 = until.parse().ok()?;
            (until > at).then(|| (key.to_owned(), until))
        })
        .collect())
}

/// Snoozes status lines, by their keys, until `until`.
///
/// # Errors
///
/// Returns an error when the write fails.
pub fn snooze(home: &Home, name: &str, keys: &[String], until: u64) -> Result<()> {
    let mut all = snoozed(home, name)?;
    for key in keys {
        all.insert(key.clone(), until);
    }
    let text = all
        .iter()
        .map(|(key, until)| format!("{key} {until}"))
        .collect::<Vec<_>>()
        .join("\n");
    home::write_atomic(&dir(home, name).join(SNOOZED), text.as_bytes(), None)
}

/// Where a PDF of the recovery kit was written, which status asks to delete.
#[must_use]
pub fn kit_pdf(home: &Home, name: &str) -> Option<PathBuf> {
    home::read_private(&dir(home, name).join(KIT_PDF), 4096, PRIVATE)
        .ok()
        .map(|bytes| PathBuf::from(String::from_utf8_lossy(&bytes).trim()))
}

/// Records where a PDF of the recovery kit was written.
///
/// # Errors
///
/// Returns an error when the write fails.
pub fn record_kit_pdf(home: &Home, name: &str, path: &Path) -> Result<()> {
    home::write_atomic(
        &dir(home, name).join(KIT_PDF),
        path.as_os_str().as_encoded_bytes(),
        None,
    )
}

/// When this device last reminded of a vault's yellow lines at unlock.
#[must_use]
pub fn reminded(home: &Home, name: &str) -> Option<u64> {
    home::read_private(&dir(home, name).join(REMINDED), 64, PRIVATE)
        .ok()
        .and_then(|bytes| String::from_utf8_lossy(&bytes).trim().parse().ok())
}

/// Records a reminder at unlock.
///
/// # Errors
///
/// Returns an error when the write fails.
pub fn record_reminded(home: &Home, name: &str, at: u64) -> Result<()> {
    home::write_atomic(
        &dir(home, name).join(REMINDED),
        at.to_string().as_bytes(),
        None,
    )
}

/// The sync folder a synced vault on this device reads.
///
/// # Errors
///
/// Returns an error when there is no such vault here.
pub fn folder(home: &Home, name: &str) -> Result<PathBuf> {
    let dir = dir(home, name);
    ensure!(
        home::exists(&dir.join(KEYS)),
        "no synced vault named \"{name}\" on this device"
    );
    read_folder(&dir)
}

// ------------------------------------------------------------------- vault --

/// An open synced vault.
pub struct Synced {
    /// Its name on this device.
    pub name: String,
    dir: PathBuf,
    file: local::KeyFile,
    kek: Zeroizing<[u8; 32]>,
    store: Store,
    device: Device,
}

fn read_folder(dir: &Path) -> Result<PathBuf> {
    let text =
        fs::read_to_string(dir.join(FOLDER)).context("the vault's folder link is missing")?;
    Ok(PathBuf::from(text.trim_end_matches('\n')))
}

impl Synced {
    /// Creates a synced vault: recovery secret, sheets and card, three root
    /// keys, genesis, and this device as its first admin.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is taken, the folder cannot be used,
    /// or no keystore is available for the second factor.
    pub fn create(
        home: &Home,
        name: &str,
        folder: &Path,
        passphrase: &SecretString,
        params: KdfParams,
    ) -> Result<Self> {
        let dir = dir(home, name);
        ensure!(
            !home::exists(&dir.join(KEYS)),
            "a vault named \"{name}\" already exists on this device"
        );
        let store = Store::open(folder, true)?;
        ensure!(
            store.list()?.names.is_empty(),
            "{} already holds a vault; join it instead",
            folder.display()
        );

        let (kit, set, [r0, r1, r2]) = new_kit()?;
        let genesis = Genesis {
            roots: set.roots,
            recovery: set.recovery,
            commitments: set.commitments,
            policy: Policy::default(),
        };
        drop(r2);

        let me = Me::generate();
        let device = Device::create(
            &store,
            me,
            genesis,
            [(&r0, 0), (&r1, 1)],
            new_id(),
            name,
            now(),
        )?;
        home::private_dir(&dir, PRIVATE)?;
        let second = second_factor(&device.me().device, true)?;
        let (file, kek) = local::new_key_file(
            device.me().device,
            passphrase.expose_secret().as_bytes(),
            &second,
            params,
        )?;
        home::write_atomic(
            &dir.join(FOLDER),
            folder.as_os_str().as_encoded_bytes(),
            None,
        )?;
        let synced = Self {
            name: name.to_owned(),
            dir,
            file,
            kek,
            store,
            device,
        };
        synced.seal_kit(&kit)?;
        synced.save()?;
        Ok(synced)
    }

    /// Opens a synced vault with the passphrase and the second factor.
    ///
    /// # Errors
    ///
    /// Returns an error when the passphrase or second factor is wrong, or a
    /// file is damaged.
    pub fn open(
        home: &Home,
        name: &str,
        passphrase: &SecretString,
        prompter: &dyn Prompter,
    ) -> Result<Self> {
        let kek = Self::unlock(home, name, passphrase, prompter)?;
        Self::open_with(home, name, kek)
    }

    /// The key-encryption key of a synced vault from the passphrase and the
    /// second factor, for a session to hold.
    ///
    /// # Errors
    ///
    /// Returns an error when the passphrase or second factor is wrong.
    pub fn unlock(
        home: &Home,
        name: &str,
        passphrase: &SecretString,
        prompter: &dyn Prompter,
    ) -> Result<Zeroizing<[u8; 32]>> {
        let dir = dir(home, name);
        ensure!(
            home::exists(&dir.join(KEYS)),
            "no synced vault named \"{name}\" on this device"
        );
        let keys = home::read_private(&dir.join(KEYS), KEY_LIMIT, PRIVATE)?;
        let device = local::key_file_device(&keys)?;
        let mut last = None;
        for second in second_factors(&dir, &device, prompter)? {
            let kek = local::key_file_kek(&keys, passphrase.expose_secret().as_bytes(), &second)?;
            match local::unlock_keys_with(&keys, &kek) {
                Ok(_) => return Ok(kek),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| anyhow!("no second factor is available")))
    }

    /// Opens a synced vault with its key-encryption key, from a session.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is wrong or a file is damaged.
    pub fn open_with(home: &Home, name: &str, kek: Zeroizing<[u8; 32]>) -> Result<Self> {
        let dir = dir(home, name);
        let keys = home::read_private(&dir.join(KEYS), KEY_LIMIT, PRIVATE)?;
        let (me, file) = local::unlock_keys_with(&keys, &kek)?;
        let state = home::read_private(&dir.join(STATE), local::MAX_STATE_BYTES, PRIVATE)?;
        let device = local::open_state(&state, me)
            .context("this device's local state does not open; pair it again")?;
        let store = Store::open(&read_folder(&dir)?, false)?;
        Ok(Self {
            name: name.to_owned(),
            dir,
            file,
            kek,
            store,
            device,
        })
    }

    /// Saves the device's keys, which change at pairing and renewal, and its
    /// state.
    ///
    /// # Errors
    ///
    /// Returns an error when the write fails.
    pub fn save(&self) -> Result<()> {
        home::write_atomic(
            &self.dir.join(KEYS),
            &local::seal_keys_with(self.device.me(), &self.file, &self.kek)?,
            None,
        )?;
        home::write_atomic(
            &self.dir.join(STATE),
            &local::seal_state(&self.device)?,
            None,
        )
    }

    /// The device.
    #[must_use]
    pub const fn device(&self) -> &Device {
        &self.device
    }

    /// The device, to change.
    pub const fn device_mut(&mut self) -> &mut Device {
        &mut self.device
    }

    /// The folder store.
    #[must_use]
    pub const fn store(&self) -> &Store {
        &self.store
    }

    /// Reads what is new, keeps entries compact, and saves. Returns how many
    /// objects were accepted.
    ///
    /// # Errors
    ///
    /// Returns an error when the folder cannot be read or a write fails.
    pub fn sync(&mut self) -> Result<usize> {
        let accepted = self.device.sync(&self.store)?;
        if self.device.killed() {
            wipe(&self.dir, &self.device.me().device);
            bail!(
                "a device that can add devices told this one to wipe its keys for the vault \
                 \"{}\", and they are gone; to use the vault here again, pair this device again \
                 with txc vault join",
                self.name
            );
        }
        self.device.expire_due(&self.store, now())?;
        self.device.forward_missing(&self.store)?;
        let entries = Entries::read(&self.device)?;
        if entries.needs_snapshot()
            && self
                .device
                .certificate(&self.device.me().certificate.unwrap_or_default())
                .is_some_and(|cert| cert.role.writes())
        {
            entries.snapshot(&mut self.device, &self.store, now(), RETENTION)?;
        }
        let admin_writer = self
            .device
            .certificate(&self.device.me().certificate.unwrap_or_default())
            .is_some_and(|cert| cert.role == Role::Admin && cert.role.writes());
        if admin_writer && self.device.snapshot_wanted() {
            Entries::read(&self.device)?.snapshot(
                &mut self.device,
                &self.store,
                now(),
                RETENTION,
            )?;
        }
        Entries::read(&self.device)?.collect(&mut self.device, &self.store)?;
        // Every unlock leaves a checkpoint (rule 14), at most one an hour.
        let due = self
            .device
            .last_checkpoint()
            .is_none_or(|last| now().saturating_sub(last) >= CHECKPOINT_EVERY);
        if due && self.device.alarms().is_empty() && self.device.me().certificate.is_some() {
            self.checkpoint()?;
        }
        self.save()?;
        Ok(accepted)
    }

    /// Writes a checkpoint of what this device has seen, as every unlock
    /// does (rule 14).
    ///
    /// # Errors
    ///
    /// Returns an error when the write fails.
    pub fn checkpoint(&mut self) -> Result<()> {
        let entries = Entries::read(&self.device)?;
        let at = now();
        let wants = entries
            .waiting()
            .iter()
            .any(|written| at.saturating_sub(*written) >= WAIT_LIMIT);
        self.device
            .checkpoint(&self.store, build_hash(), entries.verified(), at, wants)?;
        self.save()
    }

    /// How many days this device has heard from none of the others, once
    /// that is past the vault's staleness threshold (rule 17).
    #[must_use]
    pub fn stale_days(&self) -> Option<u64> {
        let limit = self
            .genesis()
            .map_or(7, |genesis| u64::from(genesis.policy.staleness_days))
            .saturating_mul(24 * 60 * 60);
        self.device
            .view_age(now())
            .filter(|age| *age >= limit)
            .map(|age| age / (24 * 60 * 60))
    }

    /// Refuses a change to devices or keys on a stale view: it may miss a
    /// removal another device made. Removing never waits for this.
    fn refuse_if_stale(&self) -> Result<()> {
        if let Some(days) = self.stale_days() {
            bail!(
                "this vault has not heard from your other devices in {days} days; check that the \
                 folder is syncing before adding devices or changing keys"
            );
        }
        Ok(())
    }

    /// Changes that have waited longer than the limit for objects this
    /// device cannot read yet.
    ///
    /// # Errors
    ///
    /// Returns an error when an object is malformed.
    pub fn long_waiting(&self) -> Result<usize> {
        let at = now();
        Ok(Entries::read(&self.device)?
            .waiting()
            .iter()
            .filter(|written| at.saturating_sub(**written) >= WAIT_LIMIT)
            .count())
    }

    /// The entries.
    ///
    /// # Errors
    ///
    /// Returns an error when an object is malformed.
    pub fn entries(&self) -> Result<Entries> {
        Entries::read(&self.device)
    }

    /// Writes a session's changes as one object and saves.
    ///
    /// # Errors
    ///
    /// Returns an error when this device may not write or the write fails.
    pub fn write(&mut self, changes: Changes<'_>) -> Result<Option<Hash>> {
        let written = changes.write(&mut self.device, &self.store)?;
        self.save()?;
        Ok(written)
    }

    // ------------------------------------------------------------ pairing --

    /// Starts pairing a new device: returns the state and the text to give
    /// it.
    ///
    /// # Errors
    ///
    /// Returns an error when the recovery kit has not been written down yet:
    /// adding a second device is refused until it has (study section 12).
    pub fn pair(&self) -> Result<(AdminStart, String)> {
        ensure!(
            !self.kit_pending(),
            "write down the recovery sheets first: txc vault recovery print {}",
            self.name
        );
        Ok(AdminStart::new(
            &self.device.me().keys(),
            self.device.genesis_hash(),
        ))
    }

    /// Adds a paired device once the codes matched.
    ///
    /// # Errors
    ///
    /// Returns an error when this device is not an admin or a write fails.
    pub fn add(&mut self, paired: &Paired, role: Role) -> Result<()> {
        self.device.sync(&self.store)?;
        self.refuse_if_stale()?;
        let principal = self
            .device
            .certificate(&self.device.me().certificate.unwrap_or_default())
            .map_or_else(new_id, |cert| cert.principal);
        self.device.add(
            &self.store,
            &paired.peer,
            principal,
            role,
            Lifetime::Desktop,
            now(),
        )?;
        self.save()
    }

    /// Moves this device's second key-at-rest factor from the OS keystore to
    /// hardware: a fresh factor sealed to it, proven to open, and the key
    /// file sealed again under the new key. The current passphrase is asked
    /// again so it is checked.
    ///
    /// # Errors
    ///
    /// Returns an error when the passphrase is wrong or the hardware cannot
    /// seal and then open the factor.
    pub fn use_hardware(
        &mut self,
        hardware: &Hardware,
        passphrase: &SecretString,
        prompter: &dyn Prompter,
    ) -> Result<()> {
        let keys = home::read_private(&self.dir.join(KEYS), KEY_LIMIT, PRIVATE)?;
        let device = self.device.me().device;
        let current = second_factors(&self.dir, &device, prompter)?;
        ensure!(
            current.iter().any(|second| {
                local::key_file_kek(&keys, passphrase.expose_secret().as_bytes(), second)
                    .is_ok_and(|kek| *kek == *self.kek)
            }),
            "that is not this vault's passphrase"
        );
        let mut factor = Zeroizing::new([0_u8; 32]);
        rand::fill(&mut factor[..]);
        let sealed = hardware.seal(&factor[..], prompter)?;
        ensure!(
            hardware.open(&sealed, prompter)?.as_slice() == &factor[..],
            "the hardware did not give back what was sealed to it"
        );
        let (file, kek) = local::new_key_file(
            device,
            passphrase.expose_secret().as_bytes(),
            &factor,
            self.file.params,
        )?;
        home::write_atomic(&self.dir.join(SECOND), &sealed, None)?;
        home::write_atomic(&self.dir.join(HARDWARE), &hardware.encode(), None)?;
        self.file = file;
        self.kek = kek;
        self.save()?;
        forget_second_factor(&device);
        Ok(())
    }

    /// Registers the hardware this device just proved it holds as an
    /// authenticator in its certificate: at once for an admin alone, or on
    /// approval by another of its owner's devices or, for a member, by an
    /// admin. Returns whether it is done already.
    ///
    /// # Errors
    ///
    /// Returns an error when a write fails.
    pub fn register_authenticator(&mut self, hardware: &Hardware, nickname: &str) -> Result<bool> {
        let authenticator = Authenticator::new(nickname, &hardware.recipient);
        self.acknowledge(&[authenticator.id])?;
        let admin = self
            .device
            .me()
            .certificate
            .and_then(|id| self.device.certificate(&id))
            .is_some_and(|cert| cert.role == Role::Admin);
        let done = if admin {
            self.device
                .request_self_renewal(&self.store, now(), &[authenticator])?
        } else {
            self.device
                .request_renewal(&self.store, vec![authenticator])?;
            false
        };
        self.save()?;
        Ok(done)
    }

    /// Approves an admin renewal of this owner, and saves.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no such request or the write fails.
    pub fn approve(&mut self, certificate: &Id) -> Result<()> {
        self.refuse_if_stale()?;
        self.device.approve(&self.store, certificate)?;
        self.save()
    }

    /// Renews a member from its request, and saves.
    ///
    /// # Errors
    ///
    /// Returns an error when this device is not an admin or the request
    /// does not verify.
    pub fn renew(&mut self, request: &crate::vault::authority::RenewalRequest) -> Result<()> {
        self.refuse_if_stale()?;
        self.device.renew(&self.store, request, now())?;
        self.save()
    }

    /// The plugins pinned on this device, for sealing to authenticators.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is damaged.
    pub fn pins(&self) -> Result<Vec<Pinned>> {
        let path = self.dir.join(PLUGINS);
        if !home::exists(&path) {
            return Ok(Vec::new());
        }
        let bytes = home::read_private(&path, KEY_LIMIT, PRIVATE)?;
        let mut input = Reader(&bytes);
        let pins = (0..input.count(256)?)
            .map(|_| Pinned::read(&mut input))
            .collect::<Result<_>>()?;
        input.finish()?;
        Ok(pins)
    }

    /// Pins plugins, replacing any earlier pin of the same name.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be written.
    pub fn add_pins(&self, new: &[Pinned]) -> Result<()> {
        let mut pins: Vec<Pinned> = self
            .pins()?
            .into_iter()
            .filter(|pin| !new.iter().any(|added| added.name == pin.name))
            .collect();
        pins.extend(new.iter().cloned());
        let mut out = Writer::default();
        out.count(pins.len());
        for pin in &pins {
            pin.write(&mut out);
        }
        home::write_atomic(&self.dir.join(PLUGINS), &out.finish(), None)
    }

    fn acknowledged(&self) -> Result<Vec<Id>> {
        let path = self.dir.join(ACKNOWLEDGED);
        if !home::exists(&path) {
            return Ok(Vec::new());
        }
        let bytes = home::read_private(&path, KEY_LIMIT, PRIVATE)?;
        let mut input = Reader(&bytes);
        let ids = (0..input.count(100_000)?)
            .map(|_| input.fixed())
            .collect::<Result<_>>()?;
        input.finish()?;
        Ok(ids)
    }

    /// Records that the person has seen these authenticators added.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be written.
    pub fn acknowledge(&self, ids: &[Id]) -> Result<()> {
        let mut all = self.acknowledged()?;
        all.extend(
            ids.iter()
                .filter(|id| !all.contains(id))
                .copied()
                .collect::<Vec<_>>(),
        );
        let mut out = Writer::default();
        out.count(all.len());
        for id in &all {
            out.fixed(id);
        }
        home::write_atomic(&self.dir.join(ACKNOWLEDGED), &out.finish(), None)
    }

    /// Authenticators registered to a member that nobody here has
    /// acknowledged yet: each is a red line until then, so none is added
    /// quietly.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is damaged.
    pub fn unacknowledged(&self) -> Result<Vec<(Id, Authenticator)>> {
        let seen = self.acknowledged()?;
        let removed = self.device.removed_authenticators();
        Ok(self
            .device
            .view()
            .into_iter()
            .flat_map(|(device, cert)| {
                cert.authenticators
                    .into_iter()
                    .map(move |authenticator| (device, authenticator))
            })
            .filter(|(_, authenticator)| {
                !seen.contains(&authenticator.id) && !removed.contains(&authenticator.id)
            })
            .collect())
    }

    /// Seals a protected value: an age file to every authenticator in the
    /// vault and the recovery recipient, with a key of its own.
    ///
    /// # Errors
    ///
    /// Returns an error when no authenticator is registered, or the plugin
    /// for one is not pinned here.
    pub fn protect(&self, plain: &[u8], prompter: &dyn Prompter) -> Result<Vec<u8>> {
        let removed = self.device.removed_authenticators();
        let mut recipients: Vec<String> = self
            .authenticators()
            .into_iter()
            .filter(|(_, authenticator)| !removed.contains(&authenticator.id))
            .map(|(_, authenticator)| authenticator.recipient)
            .collect();
        recipients.sort();
        recipients.dedup();
        ensure!(
            !recipients.is_empty(),
            "no security key is registered in this vault yet; add one with: txc vault hardware add"
        );
        let pins = self.pins()?;
        let wrapped = recipients
            .into_iter()
            .map(|recipient| {
                let name = crate::vault::hardware::plugin_name(&recipient)?;
                let plugin = pins
                    .iter()
                    .find(|pin| pin.name == name)
                    .cloned()
                    .with_context(|| {
                        format!(
                            "to seal to a {name} key, pin its plugin: txc vault hardware pin {name}"
                        )
                    })?;
                Ok(crate::vault::hardware::PluginRecipient {
                    recipient,
                    plugin,
                    prompter,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let recovery = self
            .genesis()
            .context("the vault's genesis is not read yet")?
            .recovery
            .clone();
        let all: Vec<&dyn age::Recipient> = wrapped
            .iter()
            .map(|recipient| recipient as &dyn age::Recipient)
            .chain(std::iter::once(&recovery as &dyn age::Recipient))
            .collect();
        crate::vault::crypto::encrypt_to(&all, plain)
    }

    /// Opens a protected value with this device's hardware: a touch.
    ///
    /// # Errors
    ///
    /// Returns an error when this device has no registered hardware or the
    /// hardware does not open it.
    pub fn unprotect(&self, sealed: &[u8], prompter: &dyn Prompter) -> Result<Zeroizing<Vec<u8>>> {
        let hardware = self
            .hardware()?
            .context("only a device with its security key set up opens protected entries: txc vault hardware add")?;
        hardware.open(sealed, prompter)
    }

    /// Checks the passphrase again, as a root-grade release needs: it must
    /// open this device's keys with the second factor, as at unlock.
    ///
    /// # Errors
    ///
    /// Returns an error when it does not.
    pub fn confirm_passphrase(
        &self,
        passphrase: &SecretString,
        prompter: &dyn Prompter,
    ) -> Result<()> {
        let keys = home::read_private(&self.dir.join(KEYS), KEY_LIMIT, PRIVATE)?;
        let device = local::key_file_device(&keys)?;
        for second in second_factors(&self.dir, &device, prompter)? {
            let kek = local::key_file_kek(&keys, passphrase.expose_secret().as_bytes(), &second)?;
            if local::unlock_keys_with(&keys, &kek).is_ok() {
                return Ok(());
            }
        }
        bail!("the passphrase is wrong; nothing was released")
    }

    /// Seals this device's keys again under a new passphrase, with the same
    /// second factor. The current passphrase is checked first.
    ///
    /// # Errors
    ///
    /// Returns an error when the current passphrase is wrong or a write
    /// fails.
    pub fn change_passphrase(
        &mut self,
        current: &SecretString,
        new: &SecretString,
        prompter: &dyn Prompter,
    ) -> Result<()> {
        let keys = home::read_private(&self.dir.join(KEYS), KEY_LIMIT, PRIVATE)?;
        let device = self.device.me().device;
        let second = second_factors(&self.dir, &device, prompter)?
            .into_iter()
            .find(|second| {
                local::key_file_kek(&keys, current.expose_secret().as_bytes(), second)
                    .is_ok_and(|kek| *kek == *self.kek)
            })
            .context("that is not this vault's passphrase")?;
        let (file, kek) = local::new_key_file(
            device,
            new.expose_secret().as_bytes(),
            &second,
            self.file.params,
        )?;
        self.file = file;
        self.kek = kek;
        self.save()
    }

    /// The hardware holding this device's second factor, if any.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is damaged.
    pub fn hardware(&self) -> Result<Option<Hardware>> {
        let path = self.dir.join(HARDWARE);
        if !home::exists(&path) {
            return Ok(None);
        }
        Hardware::decode(&home::read_private(&path, KEY_LIMIT, PRIVATE)?).map(Some)
    }

    /// Removes a device from the vault and saves.
    ///
    /// # Errors
    ///
    /// Returns an error when this device is not an admin or the write fails.
    pub fn remove_device(&mut self, device: Id, wipe: bool, key_lost: bool) -> Result<Vec<String>> {
        let view = self.device.view();
        let theirs = view
            .get(&device)
            .map(|certificate| certificate.authenticators.clone())
            .unwrap_or_default();
        let readable = self.secret_versions()?;
        if wipe {
            self.device.kill(&self.store, device)?;
        } else {
            self.device.remove(&self.store, device)?;
        }
        self.after_removal(device, &view, theirs, readable, key_lost)
    }

    /// Every entry with a secret, and its secrets' versions now.
    fn secret_versions(&self) -> Result<Vec<(Id, Hash)>> {
        let entries = Entries::read(&self.device)?;
        Ok(entries
            .list()
            .into_iter()
            .filter(|view| view.fields.iter().any(|field| field.kind.is_secret()))
            .map(|view| (view.id, entries.secret_version(&view.id)))
            .collect())
    }

    /// What follows taking a device out: its entries flagged for rotation,
    /// and its security keys removed unless another device uses them, or
    /// all of them when it was lost with its key.
    fn after_removal(
        &mut self,
        device: Id,
        view: &std::collections::BTreeMap<Id, crate::vault::authority::Certificate>,
        theirs: Vec<Authenticator>,
        readable: Vec<(Id, Hash)>,
        key_lost: bool,
    ) -> Result<Vec<String>> {
        if !readable.is_empty() {
            self.device
                .require_rotation(&self.store, device, readable, now())?;
        }
        let others: std::collections::BTreeSet<Id> = view
            .iter()
            .filter(|(other, _)| **other != device)
            .flat_map(|(_, certificate)| {
                certificate
                    .authenticators
                    .iter()
                    .map(|authenticator| authenticator.id)
            })
            .collect();
        let mut removed = Vec::new();
        for authenticator in theirs {
            if key_lost || !others.contains(&authenticator.id) {
                self.device
                    .remove_authenticator(&self.store, authenticator.id)?;
                removed.push(authenticator.nickname);
            }
        }
        self.save()?;
        Ok(removed)
    }

    /// Every authenticator in the vault's current certificates, with the
    /// device it belongs to.
    #[must_use]
    pub fn authenticators(&self) -> Vec<(Id, Authenticator)> {
        let removed = self.device.removed_authenticators();
        let mut out: Vec<(Id, Authenticator)> = Vec::new();
        for (device, certificate) in self.device.view() {
            for authenticator in certificate.authenticators {
                if !removed.contains(&authenticator.id)
                    && !out.iter().any(|(_, known)| known.id == authenticator.id)
                {
                    out.push((device, authenticator));
                }
            }
        }
        out
    }

    /// Removes a security key from the vault, by nickname or the start of
    /// its fingerprint. Returns its nickname.
    ///
    /// # Errors
    ///
    /// Returns an error when none or several match, or this device is not
    /// an admin.
    pub fn remove_authenticator(&mut self, which: &str) -> Result<String> {
        let wanted = which.to_lowercase();
        let found: Vec<Authenticator> = self
            .authenticators()
            .into_iter()
            .map(|(_, authenticator)| authenticator)
            .filter(|authenticator| {
                authenticator.nickname == which
                    || hex(&authenticator.fingerprint).starts_with(&wanted)
            })
            .collect();
        let [authenticator] = found.as_slice() else {
            bail!(
                "{} security keys match {which:?}; see: txc vault device list",
                found.len()
            );
        };
        self.device
            .remove_authenticator(&self.store, authenticator.id)?;
        self.save()?;
        Ok(authenticator.nickname.clone())
    }

    /// A root action (study section 5), signed by two sheets' root keys and
    /// the card: making a device an admin, removing an admin, or granting
    /// an admin more additions.
    ///
    /// # Errors
    ///
    /// Returns an error when the sheets or card do not match, or the action
    /// does not apply to the device.
    pub fn root_action(&mut self, sheets: [&str; 2], card: &str, action: RootAction) -> Result<()> {
        use crate::vault::authority::Endorsement;
        let authority = self
            .device
            .authority()
            .context("the vault's genesis is not read yet")?;
        let [(first, a), (second, b)] = root_keys(&authority.set, sheets, card)?;
        let endorse = |message: &[u8]| -> Result<Vec<Endorsement>> {
            Ok(vec![
                Endorsement::sign(&first, a, message)?,
                Endorsement::sign(&second, b, message)?,
            ])
        };
        let view = self.device.view();
        match action {
            RootAction::Promote(device) => {
                self.refuse_if_stale()?;
                let current = view
                    .get(&device)
                    .context("no such device in the vault")?
                    .clone();
                ensure!(
                    current.role != Role::Admin,
                    "that device already adds devices"
                );
                ensure!(
                    !current.authenticators.is_empty(),
                    "a device that adds devices needs a security key first; on it, run: txc \
                     vault hardware add"
                );
                let keys = crate::vault::pairing::Keys {
                    device,
                    signing_key: current.signing_key.clone(),
                    recipient: current.recipient.clone(),
                };
                let mut certificate =
                    self.device
                        .admin_certificate(&keys, current.principal, now())?;
                certificate.authenticators = current.authenticators;
                let endorsements = endorse(&certificate.encode())?;
                self.device
                    .publish_admin(&self.store, certificate, endorsements)?;
            }
            RootAction::RemoveAdmin(device) => {
                let current = view.get(&device).context("no such device in the vault")?;
                ensure!(
                    current.role == Role::Admin,
                    "that device does not add devices"
                );
                ensure!(
                    device != self.device.me().device,
                    "remove this device from another one"
                );
                let theirs = current.authenticators.clone();
                let readable = self.secret_versions()?;
                let mut fact = self.device.admin_revocation(device);
                fact.endorsements = endorse(&fact.statement())?;
                self.device.publish_root_fact(&self.store, fact)?;
                self.after_removal(device, &view, theirs, readable, false)?;
            }
            RootAction::Allow(device, more) => {
                let current = view.get(&device).context("no such device in the vault")?;
                ensure!(
                    current.role == Role::Admin,
                    "that device does not add devices"
                );
                let mut fact = crate::vault::control::Fact {
                    device,
                    kind: crate::vault::control::FactKind::MintAllowance(more),
                    endorsements: Vec::new(),
                };
                fact.endorsements = endorse(&fact.statement())?;
                self.device.publish_root_fact(&self.store, fact)?;
            }
        }
        self.save()
    }

    /// Travel mode (study section 5): removes this vault's keys and state
    /// from this device. Having it back is pairing again.
    pub fn forget(self) {
        wipe(&self.dir, &self.device.me().device);
    }

    /// Joins a vault as a new device: answers the admin's first step.
    ///
    /// # Errors
    ///
    /// Returns an error when the text is not an admin's first step.
    pub fn join_reply(commitment: &str) -> Result<(Me, DeviceReply, String)> {
        let me = Me::generate();
        let (state, reply) = DeviceReply::new(&me.keys(), commitment)?;
        Ok((me, state, reply))
    }

    /// Joins a vault once the codes matched: saves the keys and pins the
    /// admin and genesis from the ceremony.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is taken, the folder is not a vault, or
    /// no keystore is available.
    pub fn joined(
        home: &Home,
        name: &str,
        folder: &Path,
        me: Me,
        paired: &Paired,
        passphrase: &SecretString,
        params: KdfParams,
    ) -> Result<Self> {
        let dir = dir(home, name);
        ensure!(
            !home::exists(&dir.join(KEYS)),
            "a vault named \"{name}\" already exists on this device"
        );
        let store = Store::open(folder, false)?;
        let device = Device::joining(me, paired);
        home::private_dir(&dir, PRIVATE)?;
        let second = second_factor(&device.me().device, true)?;
        let (file, kek) = local::new_key_file(
            device.me().device,
            passphrase.expose_secret().as_bytes(),
            &second,
            params,
        )?;
        home::write_atomic(
            &dir.join(FOLDER),
            folder.as_os_str().as_encoded_bytes(),
            None,
        )?;
        let synced = Self {
            name: name.to_owned(),
            dir,
            file,
            kek,
            store,
            device,
        };
        synced.save()?;
        Ok(synced)
    }

    // ----------------------------------------------------------- recovery --

    fn seal_kit(&self, kit: &Kit) -> Result<()> {
        let recipient = self.device.me().identity.to_public();
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .map_err(|_error| anyhow!("cannot seal the recovery kit"))?;
        let mut sealed = Vec::new();
        let mut writer = encryptor.wrap_output(&mut sealed)?;
        std::io::Write::write_all(&mut writer, &kit.encode())?;
        writer.finish()?;
        home::write_atomic(&self.dir.join(KIT), &sealed, None)
    }

    /// Whether the recovery kit still waits to be written down.
    #[must_use]
    pub fn kit_pending(&self) -> bool {
        home::exists(&self.dir.join(KIT))
    }

    /// The recovery kit, while it has not been written down.
    ///
    /// # Errors
    ///
    /// Returns an error when there is none or it is damaged.
    pub fn kit(&self) -> Result<Kit> {
        let sealed = home::read_private(&self.dir.join(KIT), KIT_LIMIT, PRIVATE)
            .context("the recovery sheets were already written down")?;
        let decryptor = age::Decryptor::new(sealed.as_slice())
            .map_err(|_error| anyhow!("the recovery kit is damaged"))?;
        // Sealed to the identity the device had then, which a renewal since
        // may have retired.
        let me = self.device.me();
        let identities = std::iter::once(&me.identity)
            .chain(&me.retired)
            .map(|identity| identity as &dyn age::Identity);
        let mut reader = decryptor
            .decrypt(identities)
            .map_err(|_error| anyhow!("the recovery kit is not this device's"))?;
        let mut plain = Zeroizing::new(Vec::new());
        std::io::Read::read_to_end(&mut reader, &mut plain)?;
        Kit::decode(&plain)
    }

    /// Erases the recovery kit once it is written down.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be removed.
    pub fn kit_done(&self) -> Result<()> {
        let path = self.dir.join(KIT);
        let length = fs::metadata(&path).map_or(0, |metadata| metadata.len());
        // Overwrite before removing; on copy-on-write or flash storage this
        // is best effort, which is why the kit is sealed in the first place.
        home::write_atomic(&path, &vec![0; usize::try_from(length).unwrap_or(0)], None)?;
        fs::remove_file(&path).context("cannot erase the recovery kit")?;
        let written = now();
        let checks = self.dir.join(CHECKS);
        let mut current = if home::exists(&checks) {
            Checks::decode(&String::from_utf8_lossy(&home::read_private(
                &checks, 4096, PRIVATE,
            )?))
        } else {
            Checks::default()
        };
        current.written = Some(written);
        home::write_atomic(&checks, current.encode().as_bytes(), None)
    }

    /// Reissues the recovery sheets (study section 12): two of the current
    /// sheets and the card sign new root keys, a new recovery recipient and
    /// new share commitments, carrying over what the old roots signed. A
    /// snapshot and a recovery package are then written for the new
    /// recovery recipient, so the new sheets read the whole vault, and the
    /// new kit waits here, sealed, to be written down. The old sheets sign
    /// nothing from then on and read nothing written afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error when the sheets or card do not match, this device
    /// is not an admin, or a write fails.
    pub fn reissue(&mut self, sheets: [&str; 2], card: &str) -> Result<()> {
        ensure!(
            self.device
                .certificate(&self.device.me().certificate.unwrap_or_default())
                .is_some_and(|certificate| certificate.role == Role::Admin),
            "only a device that can add devices reissues the sheets"
        );
        self.refuse_if_stale()?;
        ensure!(
            !self.kit_pending(),
            "the current sheets are not written down yet; write them down first: txc vault \
             recovery print {}",
            self.name
        );
        let authority = self
            .device
            .authority()
            .context("the vault's genesis is not read yet")?;
        let [(first, a), (second, b)] = root_keys(&authority.set, sheets, card)?;
        let (kit, set, _) = new_kit()?;
        let (kept_facts, kept_certificates) = self.device.carried_over();
        let mut fact = crate::vault::control::Fact {
            device: [0; 16],
            kind: crate::vault::control::FactKind::Reissue(Box::new(
                crate::vault::control::Reissue {
                    set,
                    kept_facts,
                    kept_certificates,
                },
            )),
            endorsements: Vec::new(),
        };
        let statement = fact.statement();
        fact.endorsements = vec![
            crate::vault::authority::Endorsement::sign(&first, a, &statement)?,
            crate::vault::authority::Endorsement::sign(&second, b, &statement)?,
        ];
        drop((first, second));
        self.device.publish_root_fact(&self.store, fact)?;
        Entries::read(&self.device)?.snapshot(&mut self.device, &self.store, now(), RETENTION)?;
        self.device.publish_recovery_package(&self.store)?;
        self.seal_kit(&kit)?;
        self.save()
    }

    /// The vault's genesis, once known.
    #[must_use]
    pub const fn genesis(&self) -> Option<&Genesis> {
        self.device.genesis()
    }
}

/// The hash of this txc build, for checkpoints: an honest-client signal
/// only (rule 14).
#[must_use]
pub fn build_hash() -> Hash {
    use sha2::{Digest, Sha384};
    let mut hash = Sha384::new();
    Digest::update(&mut hash, b"txc/v1/build");
    Digest::update(&mut hash, env!("CARGO_PKG_VERSION").as_bytes());
    hash.finalize().into()
}

/// Calibrates Argon2id for this machine, about one second.
///
/// # Errors
///
/// Returns an error when a trial derivation fails.
pub fn calibrate() -> Result<KdfParams> {
    local::calibrate(Duration::from_secs(1))
}

/// Tests use the floor, which is small in test builds.
#[cfg(test)]
pub const TEST_PARAMS: KdfParams = local::FLOOR;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::vault::entries::{FieldKind, Slot};
    use crate::vault::test_support::Scratch;

    fn scratch(label: &str) -> Scratch {
        let scratch = Scratch::new(label);
        fs::create_dir_all(&scratch.0).unwrap();
        scratch
    }

    /// A synced vault made in fresh directories, with its kit written
    /// down, for other modules' tests.
    pub(crate) struct Created {
        pub vault: Synced,
        pub home: Home,
        _dirs: (Scratch, Scratch),
    }

    /// The same, with the recovery kit still waiting to be written down.
    pub(crate) fn created_pending(label: &str) -> Created {
        with_keystore();
        let (home_dir, folder) = (
            scratch(&format!("{label}-home")),
            scratch(&format!("{label}-folder")),
        );
        let home = Home::at(&home_dir.0);
        let passphrase = SecretString::from("correct horse battery staple".to_owned());
        let vault = Synced::create(&home, "personal", &folder.0, &passphrase, TEST_PARAMS).unwrap();
        Created {
            vault,
            home,
            _dirs: (home_dir, folder),
        }
    }

    pub(crate) fn created(label: &str) -> Created {
        with_keystore();
        let (home_dir, folder) = (
            scratch(&format!("{label}-home")),
            scratch(&format!("{label}-folder")),
        );
        let home = Home::at(&home_dir.0);
        let passphrase = SecretString::from("correct horse battery staple".to_owned());
        let vault = Synced::create(&home, "personal", &folder.0, &passphrase, TEST_PARAMS).unwrap();
        vault.kit_done().unwrap();
        Created {
            vault,
            home,
            _dirs: (home_dir, folder),
        }
    }

    fn with_keystore() {
        TEST_KEYSTORE.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("txc-keystore-{}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            dir
        });
    }

    #[test]
    fn a_vault_is_created_opened_joined_and_checked_against_its_sheets() {
        with_keystore();
        let (home_a, home_b, folder) = (scratch("home-a"), scratch("home-b"), scratch("folder"));
        let (home_a, home_b) = (Home::at(&home_a.0), Home::at(&home_b.0));
        let passphrase = SecretString::from("correct horse battery staple".to_owned());

        let mut first =
            Synced::create(&home_a, "work", &folder.0, &passphrase, TEST_PARAMS).unwrap();
        assert_eq!(names(&home_a).unwrap(), vec!["work".to_owned()]);
        assert!(
            Synced::open(
                &home_a,
                "work",
                &SecretString::from("wrong".to_owned()),
                &crate::vault::hardware::Terminal
            )
            .is_err()
        );

        // Pairing is refused until the kit is written down.
        assert!(first.pair().is_err());
        let kit = first.kit().unwrap();
        assert_eq!(kit.sheets.len(), 3);
        let genesis = first.genesis().unwrap().clone();
        for sheet in &kit.sheets {
            check_sheet(&genesis.root_set(), sheet, &kit.card).unwrap();
        }
        assert!(check_sheet(&genesis.root_set(), &kit.sheets[0], "wrong card words").is_err());
        let recovered = slip39::combine(&[&kit.sheets[0], &kit.sheets[2]], &kit.card).unwrap();
        let identity = recovery_identity(&<[u8; 32]>::try_from(&recovered[..]).unwrap());
        assert_eq!(identity.to_public(), genesis.recovery);
        first.kit_done().unwrap();
        assert!(!first.kit_pending());

        let entries = first.entries().unwrap();
        let mut changes = Changes::new(&entries, now());
        let entry = changes.create("github").unwrap();
        let password = changes
            .add_field(&entry, FieldKind::Secret, "password", b"hunter2")
            .unwrap();
        first.write(changes).unwrap();

        let (start, commit) = first.pair().unwrap();
        let (me, reply_state, reply) = Synced::join_reply(&commit).unwrap();
        let (on_admin, reveal) = start.reveal(&reply).unwrap();
        let on_device = reply_state.check(&reveal).unwrap();
        assert_eq!(on_admin.code, on_device.code);
        first.add(&on_admin, Role::Writer).unwrap();
        let mut second = Synced::joined(
            &home_b,
            "work",
            &folder.0,
            me,
            &on_device,
            &passphrase,
            TEST_PARAMS,
        )
        .unwrap();
        second.sync().unwrap();

        let mut reopened = Synced::open(
            &home_b,
            "work",
            &passphrase,
            &crate::vault::hardware::Terminal,
        )
        .unwrap();
        reopened.sync().unwrap();
        let values = reopened
            .entries()
            .unwrap()
            .reveal(&entry, &password, Slot::Value)
            .unwrap();
        assert_eq!(&values[0][..], b"hunter2");
        reopened.checkpoint().unwrap();
        let mut first = Synced::open(
            &home_a,
            "work",
            &passphrase,
            &crate::vault::hardware::Terminal,
        )
        .unwrap();
        first.sync().unwrap();
        assert_eq!(first.device().members().len(), 2);
    }

    #[test]
    fn two_sheets_and_the_card_read_every_entry_back_from_the_folder_alone() {
        let created = created_pending("recover");
        let mut vault = created.vault;
        let kit = vault.kit().unwrap();
        let folder = folder(&created.home, "personal").unwrap();
        let write = |vault: &mut Synced, name: &str, value: &[u8]| {
            let entries = vault.entries().unwrap();
            let mut changes = Changes::new(&entries, now());
            let entry = changes.create(name).unwrap();
            changes
                .add_field(&entry, FieldKind::Secret, "password", value)
                .unwrap();
            vault.write(changes).unwrap();
        };
        write(&mut vault, "before", b"one");
        // A snapshot stands in for what came before it.
        vault
            .entries()
            .unwrap()
            .snapshot(
                vault.device_mut(),
                &Store::open(&folder, false).unwrap(),
                now(),
                RETENTION,
            )
            .unwrap();
        write(&mut vault, "after", b"two");

        let recovered = recover(&folder, &[&kit.sheets[2], &kit.sheets[0]], &kit.card).unwrap();
        let entries = Entries::read(&recovered.device).unwrap();
        let mut found: Vec<(String, Vec<u8>)> = entries
            .list()
            .into_iter()
            .map(|view| {
                let field = &view.fields[0];
                let values = entries.reveal(&view.id, &field.id, Slot::Value).unwrap();
                (view.names[0].clone(), values[0].to_vec())
            })
            .collect();
        found.sort();
        assert_eq!(
            found,
            vec![
                ("after".to_owned(), b"two".to_vec()),
                ("before".to_owned(), b"one".to_vec())
            ]
        );

        assert!(recover(&folder, &[&kit.sheets[0]], &kit.card).is_err());
        assert!(
            recover(
                &folder,
                &[&kit.sheets[0], &kit.sheets[1]],
                "wrong card words"
            )
            .is_err()
        );
        let other = created_pending("recover-other");
        let other_kit = other.vault.kit().unwrap();
        assert!(
            recover(
                &folder,
                &[&other_kit.sheets[0], &other_kit.sheets[1]],
                &other_kit.card
            )
            .is_err(),
            "another vault's sheets read nothing here"
        );
    }

    #[test]
    fn after_a_reissue_every_device_writes_for_the_new_sheets_only() {
        with_keystore();
        let (home_a, home_b, folder) = (
            scratch("reissue-a"),
            scratch("reissue-b"),
            scratch("reissue-folder"),
        );
        let (home_a, home_b) = (Home::at(&home_a.0), Home::at(&home_b.0));
        let passphrase = SecretString::from("correct horse battery staple".to_owned());
        let mut first =
            Synced::create(&home_a, "work", &folder.0, &passphrase, TEST_PARAMS).unwrap();
        let old = first.kit().unwrap();
        first.kit_done().unwrap();
        let (start, commit) = first.pair().unwrap();
        let (me, reply_state, reply) = Synced::join_reply(&commit).unwrap();
        let (on_admin, reveal) = start.reveal(&reply).unwrap();
        let on_device = reply_state.check(&reveal).unwrap();
        first.add(&on_admin, Role::Writer).unwrap();
        let mut second = Synced::joined(
            &home_b,
            "work",
            &folder.0,
            me,
            &on_device,
            &passphrase,
            TEST_PARAMS,
        )
        .unwrap();
        second.sync().unwrap();

        // A writer cannot reissue; the admin can, with two old sheets.
        assert!(
            second
                .reissue([&old.sheets[0], &old.sheets[1]], &old.card)
                .is_err()
        );
        assert!(
            first
                .reissue([&old.sheets[0], &old.sheets[0]], &old.card)
                .is_err(),
            "two different sheets"
        );
        first
            .reissue([&old.sheets[0], &old.sheets[2]], &old.card)
            .unwrap();
        let new = first.kit().unwrap();
        first.kit_done().unwrap();

        second.sync().unwrap();
        assert_eq!(
            second.device().authority().unwrap().set,
            first.device().authority().unwrap().set
        );
        assert_eq!(second.device().members().len(), 2, "the admin stays valid");
        let entries = second.entries().unwrap();
        let mut changes = Changes::new(&entries, now());
        let entry = changes.create("from-second").unwrap();
        changes
            .add_field(&entry, FieldKind::Secret, "password", b"two")
            .unwrap();
        second.write(changes).unwrap();

        let names = |sheets: [&str; 2], card: &str| -> Vec<String> {
            let recovered = recover(&folder.0, &sheets, card).unwrap();
            Entries::read(&recovered.device)
                .unwrap()
                .list()
                .into_iter()
                .flat_map(|view| view.names)
                .collect()
        };
        assert_eq!(
            names([&new.sheets[1], &new.sheets[2]], &new.card),
            vec!["from-second".to_owned()]
        );
        assert!(
            !names([&old.sheets[1], &old.sheets[2]], &old.card).contains(&"from-second".to_owned())
        );
        assert!(
            check_sheet(
                &first.device().authority().unwrap().set,
                &old.sheets[0],
                &old.card
            )
            .is_err()
        );
    }

    /// An admin and a writer sharing a vault, with the admin's kit.
    struct Pair {
        first: Synced,
        second: Synced,
        kit: Kit,
        homes: (Home, Home),
        _dirs: (Scratch, Scratch, Scratch),
    }

    fn pair(label: &str) -> Pair {
        with_keystore();
        let dirs = (
            scratch(&format!("{label}-a")),
            scratch(&format!("{label}-b")),
            scratch(&format!("{label}-folder")),
        );
        let homes = (Home::at(&dirs.0.0), Home::at(&dirs.1.0));
        let passphrase = SecretString::from("correct horse battery staple".to_owned());
        let mut first =
            Synced::create(&homes.0, "work", &dirs.2.0, &passphrase, TEST_PARAMS).unwrap();
        let kit = first.kit().unwrap();
        first.kit_done().unwrap();
        let (start, commit) = first.pair().unwrap();
        let (me, reply_state, reply) = Synced::join_reply(&commit).unwrap();
        let (on_admin, reveal) = start.reveal(&reply).unwrap();
        let on_device = reply_state.check(&reveal).unwrap();
        first.add(&on_admin, Role::Writer).unwrap();
        let mut second = Synced::joined(
            &homes.1,
            "work",
            &dirs.2.0,
            me,
            &on_device,
            &passphrase,
            TEST_PARAMS,
        )
        .unwrap();
        second.sync().unwrap();
        Pair {
            first,
            second,
            kit,
            homes,
            _dirs: dirs,
        }
    }

    #[test]
    fn a_killed_device_wipes_its_keys_and_a_forgotten_vault_leaves_this_one() {
        let Pair {
            mut first,
            mut second,
            homes,
            _dirs,
            ..
        } = pair("kill");
        let entries = first.entries().unwrap();
        let mut changes = Changes::new(&entries, now());
        let entry = changes.create("db").unwrap();
        changes
            .add_field(&entry, FieldKind::Secret, "password", b"one")
            .unwrap();
        first.write(changes).unwrap();
        second.sync().unwrap();

        let target = second.device().me().device;
        first.remove_device(target, true, false).unwrap();
        assert!(first.device().rotation_required().contains_key(&entry));
        let error = second.sync().unwrap_err().to_string();
        assert!(error.contains("wipe its keys"), "{error}");
        assert!(!exists(&homes.1, "work"));
        assert!(names(&homes.1).unwrap().is_empty());

        first.forget();
        assert!(!exists(&homes.0, "work"));
    }

    #[test]
    fn root_actions_need_two_sheets_and_the_card() {
        let Pair {
            mut first,
            mut second,
            kit,
            _dirs,
            ..
        } = pair("root");
        let admin = first.device().me().device;
        let writer = second.device().me().device;
        let sheets = [kit.sheets[0].as_str(), kit.sheets[1].as_str()];
        assert!(
            first
                .root_action(
                    [kit.sheets[0].as_str(), kit.sheets[0].as_str()],
                    &kit.card,
                    RootAction::Allow(admin, 2)
                )
                .is_err()
        );
        first
            .root_action(sheets, &kit.card, RootAction::Allow(admin, 2))
            .unwrap();
        assert!(
            first
                .root_action(sheets, &kit.card, RootAction::Promote(writer))
                .unwrap_err()
                .to_string()
                .contains("security key first")
        );

        // With a security key, the writer becomes an admin, and root can
        // remove it again.
        let store = Store::open(&read_folder(&second.dir).unwrap(), false).unwrap();
        second
            .device_mut()
            .request_renewal(
                &store,
                vec![Authenticator::new("blue", "age1tagpq1example")],
            )
            .unwrap();
        second.save().unwrap();
        first.sync().unwrap();
        let request = first.device().renewal_requests().remove(0);
        first.renew(&request).unwrap();
        first
            .root_action(sheets, &kit.card, RootAction::Promote(writer))
            .unwrap();
        second.sync().unwrap();
        assert_eq!(
            second.device().view()[&writer].role,
            Role::Admin,
            "the writer adds devices now"
        );
        first
            .root_action(sheets, &kit.card, RootAction::RemoveAdmin(writer))
            .unwrap();
        assert!(!first.device().members().contains(&writer));
        assert!(
            first.device().removed_authenticators().len() == 1,
            "its key went with it"
        );
    }

    #[test]
    fn a_root_grade_release_takes_the_passphrase_again() {
        let created = created("confirm");
        let terminal = &crate::vault::hardware::Terminal;
        created
            .vault
            .confirm_passphrase(
                &SecretString::from("correct horse battery staple".to_owned()),
                terminal,
            )
            .unwrap();
        assert!(
            created
                .vault
                .confirm_passphrase(&SecretString::from("wrong".to_owned()), terminal)
                .is_err()
        );
    }

    /// The folder budget of study section 13: a thousand entries after a
    /// synthetic year of edits on two devices stay under 5 MB and a few
    /// hundred files, and a warm open that finds nothing new is quick.
    #[test]
    #[ignore = "a CI gate, slow in debug builds: cargo test --release -- --ignored"]
    fn a_year_of_edits_stays_within_the_folder_budget() {
        let Pair {
            mut first,
            mut second,
            _dirs,
            ..
        } = pair("budget");
        let folder = read_folder(&first.dir).unwrap();
        for batch in 0..50 {
            let entries = first.entries().unwrap();
            let mut changes = Changes::new(&entries, now());
            for index in 0..20 {
                let entry = changes
                    .create(&format!("entry-{}", batch * 20 + index))
                    .unwrap();
                changes
                    .add_field(&entry, FieldKind::Secret, "password", b"correct horse")
                    .unwrap();
                changes
                    .add_field(
                        &entry,
                        FieldKind::Username,
                        "username",
                        b"someone@example.com",
                    )
                    .unwrap();
            }
            first.write(changes).unwrap();
            first.sync().unwrap();
        }
        // A year: two thousand password changes in five hundred sessions,
        // the two devices taking turns, checkpointing now and then.
        for session in 0..500_usize {
            let device = if session % 2 == 0 {
                &mut first
            } else {
                &mut second
            };
            device.sync().unwrap();
            let entries = device.entries().unwrap();
            let views = entries.list();
            let mut changes = Changes::new(&entries, now());
            for step in 0..4 {
                let view = &views[(session * 4 + step) % views.len()];
                let field = view.fields.iter().find(|f| f.kind.is_secret()).unwrap();
                changes
                    .set_field(
                        &view.id,
                        &field.id,
                        FieldKind::Secret,
                        format!("pw-{session}-{step}").as_bytes(),
                    )
                    .unwrap();
            }
            device.write(changes).unwrap();
            if session % 10 == 9 {
                for vault in [&mut first, &mut second] {
                    vault.sync().unwrap();
                    vault.checkpoint().unwrap();
                }
            }
        }
        for _ in 0..2 {
            for vault in [&mut first, &mut second] {
                vault.sync().unwrap();
                vault.checkpoint().unwrap();
            }
        }
        let (mut files, mut bytes) = (0_usize, 0_u64);
        let mut pending = vec![folder.clone()];
        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(&dir).unwrap().flatten() {
                let metadata = entry.metadata().unwrap();
                if metadata.is_dir() {
                    pending.push(entry.path());
                } else {
                    files += 1;
                    bytes += metadata.len();
                }
            }
        }
        let started = std::time::Instant::now();
        first.sync().unwrap();
        let warm = started.elapsed();
        eprintln!("budget: {files} files, {bytes} bytes, warm open {warm:?}");
        assert!(files < 500, "{files} files");
        assert!(bytes < 5 * 1024 * 1024, "{bytes} bytes");
        if !cfg!(debug_assertions) {
            assert!(warm < std::time::Duration::from_millis(500), "{warm:?}");
        }
    }

    #[test]
    fn a_sheet_check_falls_due_twice_a_year_and_a_drill_once() {
        let mut checks = Checks::default();
        assert_eq!(
            checks.sheet_due(CHECK_EVERY * 10),
            None,
            "nothing written down yet"
        );
        checks.written = Some(0);
        assert_eq!(checks.sheet_due(CHECK_EVERY - 1), None);
        assert_eq!(checks.sheet_due(CHECK_EVERY), Some(0));
        checks.sheets[0] = Some(CHECK_EVERY);
        assert_eq!(checks.sheet_due(CHECK_EVERY + 1), None);
        assert_eq!(checks.sheet_due(2 * CHECK_EVERY), Some(1));
        assert!(!checks.drill_due(DRILL_EVERY - 1));
        assert!(checks.drill_due(DRILL_EVERY));
        checks.drill = Some(DRILL_EVERY);
        assert!(!checks.drill_due(DRILL_EVERY + 1));
        assert_eq!(Checks::decode(&checks.encode()), checks);
    }
}
