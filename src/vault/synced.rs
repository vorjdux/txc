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

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, anyhow, bail, ensure};
use zeroize::Zeroizing;

use crate::vault::authority::Authenticator;
use crate::vault::authority::{
    Genesis, Lifetime, Policy, Role, new_id, recovery_identity, root_key, share_commitment,
};
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
pub fn check_sheet(genesis: &Genesis, sheet: &str, card: &str) -> Result<u8> {
    let index = slip39::share_index(sheet)?;
    let share = slip39::share_value(sheet)?;
    let root = genesis
        .roots
        .get(usize::from(index))
        .ok_or_else(|| anyhow!("the sheet's number is out of range"))?;
    ensure!(
        genesis.commitments.get(usize::from(index)) == Some(&share_commitment(&share)),
        "this sheet does not belong to this vault"
    );
    ensure!(
        root_key(&share, card, usize::from(index))?.verifying_key() == *root,
        "the sheet belongs to this vault, but the card does not match it"
    );
    Ok(index)
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

        let mut secret = Zeroizing::new([0_u8; 32]);
        rand::fill(&mut secret[..]);
        let card = new_card();
        let sheets = slip39::split(&secret[..], &card, SHEET_THRESHOLD, SHEETS, SLIP39_EXPONENT)?;
        let shares: Vec<Zeroizing<Vec<u8>>> = sheets
            .iter()
            .map(|sheet| slip39::share_value(sheet))
            .collect::<Result<_>>()?;
        let roots =
            [0, 1, 2].map(|index| shares.get(index).map(|share| root_key(share, &card, index)));
        let [Some(r0), Some(r1), Some(r2)] = roots else {
            bail!("three sheets are needed")
        };
        let (r0, r1, r2) = (r0?, r1?, r2?);
        let commitments = [0, 1, 2].map(|index| {
            shares
                .get(index)
                .map_or([0; 48], |share| share_commitment(share))
        });
        let genesis = Genesis {
            roots: [r0.verifying_key(), r1.verifying_key(), r2.verifying_key()],
            recovery: recovery_identity(&secret).to_public(),
            commitments,
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
        synced.seal_kit(&Kit { sheets, card })?;
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
        Entries::read(&self.device)?.collect(&mut self.device, &self.store)?;
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
        let verified = Entries::read(&self.device)?.verified();
        self.device
            .checkpoint(&self.store, build_hash(), verified)?;
        self.save()
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
        Ok(self
            .device
            .view()
            .into_iter()
            .flat_map(|(device, cert)| {
                cert.authenticators
                    .into_iter()
                    .map(move |authenticator| (device, authenticator))
            })
            .filter(|(_, authenticator)| !seen.contains(&authenticator.id))
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
        let mut recipients: Vec<String> = self
            .device
            .view()
            .values()
            .flat_map(|cert| {
                cert.authenticators
                    .iter()
                    .map(|authenticator| authenticator.recipient.clone())
            })
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
    pub fn remove_device(&mut self, device: Id) -> Result<()> {
        self.device.remove(&self.store, device)?;
        self.save()
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
        let mut reader = decryptor
            .decrypt(std::iter::once(
                &self.device.me().identity as &dyn age::Identity,
            ))
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
        fs::remove_file(&path).context("cannot erase the recovery kit")
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
            check_sheet(&genesis, sheet, &kit.card).unwrap();
        }
        assert!(check_sheet(&genesis, &kit.sheets[0], "wrong card words").is_err());
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
}
