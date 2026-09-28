//! Entries on top of the device engine (study sections 8 and 9).
//!
//! An entry has a random id; its name, its sensitivity class and each of its
//! fields are multi-value registers folded by [`core::fold`]: causally later
//! writes win, concurrent ones are all kept and flagged, and a delete
//! concurrent with a set is a conflict too. An op's dependencies are the
//! live ops of its register when it was written, so the fold needs no clock.
//!
//! Ops are written in batches, one content object per session (rule 18).
//! Each object carries a random field key: every secret-typed value is
//! sealed on its own with XChaCha20-Poly1305 under
//! `HKDF-SHA-384(field key, info = "txc/v1/field" || entry || field ||
//! version)`, the same ids serving as associated data, so listing a vault
//! decrypts no secret and a ciphertext cannot move between fields, entries
//! or versions. Unknown field kinds are kept as they are, so an older client
//! never destroys what a newer one wrote.
//!
//! [`core::fold`]: crate::vault::core::fold

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha384;
use zeroize::Zeroizing;

use crate::vault::authority::new_id;
use crate::vault::core::fold::{self, Kind as OpKind, Op, State};
use crate::vault::device::Device;
use crate::vault::model::displayable;
use crate::vault::object::{Hash, Id, Kind};
use crate::vault::store::Store;
use crate::vault::wire::{Reader, Writer};

const BATCH_TAG: &[u8] = b"txc/v1/ops";
const FIELD_INFO: &[u8] = b"txc/v1/field";
const MAX_OPS: usize = 100_000;
const MAX_DEPS: usize = 1024;
const MAX_VALUES: usize = 64;

/// The register holding an entry's name.
pub const NAME: Id = [0; 16];
/// The register holding an entry's sensitivity class.
pub const SENSITIVITY: Id = {
    let mut id = [0; 16];
    id[15] = 1;
    id
};

/// What a field holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldKind {
    /// The entry's name.
    Name,
    /// The entry's sensitivity class.
    Sensitivity,
    /// A password or other secret.
    Secret,
    /// A user name.
    Username,
    /// A web origin.
    Origin,
    /// A TOTP seed.
    Totp,
    /// A passkey credential.
    Passkey,
    /// An SSH certificate authority key.
    SshCa,
    /// A note.
    Note,
    /// A file's content.
    File,
    /// A kind this version does not know, kept as it is.
    Unknown(u16),
}

impl FieldKind {
    const fn code(self) -> u16 {
        match self {
            Self::Name => 1,
            Self::Sensitivity => 2,
            Self::Secret => 3,
            Self::Username => 4,
            Self::Origin => 5,
            Self::Totp => 6,
            Self::Passkey => 7,
            Self::SshCa => 8,
            Self::Note => 9,
            Self::File => 10,
            Self::Unknown(code) => code,
        }
    }

    const fn from_code(code: u16) -> Self {
        match code {
            1 => Self::Name,
            2 => Self::Sensitivity,
            3 => Self::Secret,
            4 => Self::Username,
            5 => Self::Origin,
            6 => Self::Totp,
            7 => Self::Passkey,
            8 => Self::SshCa,
            9 => Self::Note,
            10 => Self::File,
            other => Self::Unknown(other),
        }
    }

    /// Whether values of this kind are sealed field by field. An unknown
    /// kind is treated as secret, so it is never shown by accident.
    #[must_use]
    pub const fn is_secret(self) -> bool {
        matches!(
            self,
            Self::Secret | Self::Totp | Self::Passkey | Self::SshCa | Self::File | Self::Unknown(_)
        )
    }
}

/// What releasing an entry requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Sensitivity {
    /// A session unlock.
    Normal,
    /// A physical act on presence hardware per release.
    High,
    /// A physical act plus the passphrase per release.
    RootGrade,
    /// Never released; used only inside the keyholder.
    OperationOnly,
}

impl Sensitivity {
    const fn code(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::High => 1,
            Self::RootGrade => 2,
            Self::OperationOnly => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        Ok(match code {
            0 => Self::Normal,
            1 => Self::High,
            2 => Self::RootGrade,
            3 => Self::OperationOnly,
            other => bail!("unknown sensitivity {other}"),
        })
    }
}

/// Which of a field's two registers: its value, or a rotation in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Slot {
    /// The current value.
    Value,
    /// A new value written before a remote change, until commit or abort.
    Pending,
}

/// One register: an entry, a field of it, and a slot.
pub type Register = (Id, Id, Slot);

/// An op's identity: the object it came in and its place there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpId {
    /// The object's hash.
    pub object: Hash,
    /// Its index in the object's batch.
    pub index: u32,
}

/// A value as stored: which object's field key seals it (for secret
/// kinds), and its bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stored {
    /// The object whose field key seals it.
    pub source: Hash,
    /// The plaintext, or for a secret kind the sealed value.
    pub bytes: Vec<u8>,
}

/// One op in a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FieldOp {
    register: Register,
    kind: FieldKind,
    deps: BTreeSet<OpId>,
    time: u64,
    /// `Some` sets a value, `None` deletes; `old` holds what a delete
    /// removed, sealed again under this object's field key.
    value: Option<Vec<u8>>,
    old: Vec<Vec<u8>>,
}

fn field_key(
    key: &[u8; 32],
    entry: &Id,
    field: &Id,
    version: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut info = Vec::with_capacity(FIELD_INFO.len().saturating_add(48));
    info.extend_from_slice(FIELD_INFO);
    info.extend_from_slice(entry);
    info.extend_from_slice(field);
    info.extend_from_slice(version);
    let mut out = Zeroizing::new([0; 32]);
    Hkdf::<Sha384>::new(None, key)
        .expand(&info, &mut out[..])
        .map_err(|_length| anyhow!("cannot derive a field key"))?;
    Ok(out)
}

const fn aad(entry: &Id, field: &Id, version: &[u8; 16]) -> [u8; 48] {
    let mut aad = [0; 48];
    let (head, rest) = aad.split_at_mut(16);
    head.copy_from_slice(entry);
    let (middle, tail) = rest.split_at_mut(16);
    middle.copy_from_slice(field);
    tail.copy_from_slice(version);
    aad
}

/// Seals one secret value: `version || nonce || ciphertext`.
fn seal_value(key: &[u8; 32], entry: &Id, field: &Id, plain: &[u8]) -> Result<Vec<u8>> {
    let mut version = [0; 16];
    rand::fill(&mut version[..]);
    let mut nonce = [0; 24];
    rand::fill(&mut nonce[..]);
    let derived = field_key(key, entry, field, &version)?;
    let sealed = XChaCha20Poly1305::new_from_slice(&derived[..])
        .map_err(|_length| anyhow!("bad field key"))?
        .encrypt(
            XNonce::from_slice(&nonce),
            AeadPayload {
                msg: plain,
                aad: &aad(entry, field, &version),
            },
        )
        .map_err(|_error| anyhow!("cannot seal a field"))?;
    let mut out = Vec::with_capacity(sealed.len().saturating_add(40));
    out.extend_from_slice(&version);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open_value(key: &[u8; 32], entry: &Id, field: &Id, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut input = Reader(sealed);
    let version: [u8; 16] = input.fixed()?;
    let nonce: [u8; 24] = input.fixed()?;
    let derived = field_key(key, entry, field, &version)?;
    let plain = XChaCha20Poly1305::new_from_slice(&derived[..])
        .map_err(|_length| anyhow!("bad field key"))?
        .decrypt(
            XNonce::from_slice(&nonce),
            AeadPayload {
                msg: input.0,
                aad: &aad(entry, field, &version),
            },
        )
        .map_err(|_error| anyhow!("a sealed field is damaged or was moved"))?;
    Ok(Zeroizing::new(plain))
}

const fn slot_code(slot: Slot) -> u8 {
    match slot {
        Slot::Value => 0,
        Slot::Pending => 1,
    }
}

fn write_op(out: &mut Writer, op: &FieldOp) {
    let (entry, field, slot) = &op.register;
    out.fixed(entry);
    out.fixed(field);
    out.u8(slot_code(*slot));
    out.u64(u64::from(op.kind.code()));
    out.count(op.deps.len());
    for dep in &op.deps {
        out.fixed(&dep.object);
        out.u64(u64::from(dep.index));
    }
    out.u64(op.time);
    out.bool(op.value.is_some());
    if let Some(value) = &op.value {
        out.bytes(value);
    }
    out.count(op.old.len());
    for old in &op.old {
        out.bytes(old);
    }
}

fn read_op(input: &mut Reader<'_>) -> Result<FieldOp> {
    let entry = input.fixed()?;
    let field = input.fixed()?;
    let slot = match input.u8()? {
        0 => Slot::Value,
        1 => Slot::Pending,
        other => bail!("unknown slot {other}"),
    };
    let kind = FieldKind::from_code(
        u16::try_from(input.u64()?).map_err(|_code| anyhow!("a field kind is out of range"))?,
    );
    let deps = (0..input.count(MAX_DEPS)?)
        .map(|_| {
            Ok(OpId {
                object: input.fixed()?,
                index: u32::try_from(input.u64()?)
                    .map_err(|_index| anyhow!("an op index is out of range"))?,
            })
        })
        .collect::<Result<_>>()?;
    let time = input.u64()?;
    let value = if input.bool()? {
        Some(input.bytes()?.to_vec())
    } else {
        None
    };
    let old = (0..input.count(MAX_VALUES)?)
        .map(|_| Ok(input.bytes()?.to_vec()))
        .collect::<Result<_>>()?;
    Ok(FieldOp {
        register: (entry, field, slot),
        kind,
        deps,
        time,
        value,
        old,
    })
}

/// A decoded batch: its field key and its ops.
struct Batch {
    key: Zeroizing<[u8; 32]>,
    ops: Vec<FieldOp>,
}

impl Batch {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Writer::default();
        out.fixed(BATCH_TAG);
        out.fixed(&self.key[..]);
        out.count(self.ops.len());
        for op in &self.ops {
            write_op(&mut out, op);
        }
        Zeroizing::new(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        ensure!(
            input.take(BATCH_TAG.len())? == BATCH_TAG,
            "not a batch of ops"
        );
        let key = Zeroizing::new(input.fixed()?);
        let ops = (0..input.count(MAX_OPS)?)
            .map(|_| read_op(&mut input))
            .collect::<Result<_>>()?;
        input.finish()?;
        Ok(Self { key, ops })
    }
}

/// A register's folded state and what its values need.
#[derive(Clone, Debug)]
pub struct Field {
    /// The field's id.
    pub id: Id,
    /// What it holds, as its newest op says.
    pub kind: FieldKind,
    /// The folded state.
    pub state: State<Stored>,
}

/// What listing an entry shows: metadata only, no secret decrypted.
#[derive(Clone, Debug)]
pub struct EntryView {
    /// The entry's id.
    pub id: Id,
    /// Its names, sanitised for display; more than one is a name conflict.
    pub names: Vec<String>,
    /// Its sensitivity class; the highest wins when concurrent.
    pub sensitivity: Sensitivity,
    /// Its fields, without secret values.
    pub fields: Vec<FieldView>,
    /// Whether any register of it is in conflict.
    pub conflict: bool,
}

/// A field in a listing.
#[derive(Clone, Debug)]
pub struct FieldView {
    /// The field's id.
    pub id: Id,
    /// What it holds.
    pub kind: FieldKind,
    /// Its values sanitised for display, or `None` for a secret kind.
    pub shown: Option<Vec<String>>,
    /// Whether it has a rotation in progress.
    pub pending: bool,
    /// Whether concurrent writes left more than one value.
    pub conflict: bool,
}

/// The entries of a vault, folded from the ops a device has accepted.
pub struct Entries {
    ops: BTreeMap<OpId, (FieldOp, Hash)>,
    keys: BTreeMap<Hash, Zeroizing<[u8; 32]>>,
}

impl Entries {
    /// Folds every valid op object the device holds.
    ///
    /// # Errors
    ///
    /// Returns an error when an op object is malformed.
    pub fn read(device: &Device) -> Result<Self> {
        let mut entries = Self {
            ops: BTreeMap::new(),
            keys: BTreeMap::new(),
        };
        for content in device.content() {
            if content.payload.kind != Kind::Op {
                continue;
            }
            let batch = Batch::decode(&content.payload.body)?;
            for (index, op) in (0_u32..).zip(batch.ops) {
                entries.ops.insert(
                    OpId {
                        object: content.hash,
                        index,
                    },
                    (op, content.hash),
                );
            }
            entries.keys.insert(content.hash, batch.key);
        }
        Ok(entries)
    }

    fn register_ops(&self) -> BTreeMap<Register, BTreeMap<OpId, Op<OpId, Stored>>> {
        let mut registers: BTreeMap<Register, BTreeMap<OpId, Op<OpId, Stored>>> = BTreeMap::new();
        for (id, (op, source)) in &self.ops {
            let stored = |bytes: &Vec<u8>| Stored {
                source: *source,
                bytes: bytes.clone(),
            };
            let kind = match &op.value {
                Some(value) => OpKind::Set(stored(value)),
                None => OpKind::Delete {
                    old: op.old.iter().map(stored).collect(),
                },
            };
            registers.entry(op.register).or_default().insert(
                *id,
                Op {
                    kind,
                    deps: op.deps.clone(),
                    time: op.time,
                },
            );
        }
        registers
    }

    /// Every register's folded state, over the ops whose dependencies have
    /// all arrived; the rest wait (rule 7).
    #[must_use]
    pub fn registers(&self) -> BTreeMap<Register, Field> {
        self.register_ops()
            .into_iter()
            .map(|(register, ops)| {
                let known: BTreeSet<OpId> = ops.keys().copied().collect();
                let applied = fold::applicable(&known, &ops);
                let kind = applied
                    .iter()
                    .filter_map(|id| self.ops.get(id))
                    .map(|(op, _)| op.kind)
                    .next_back()
                    .unwrap_or(FieldKind::Unknown(0));
                let state = fold::fold(&applied, &ops);
                (
                    register,
                    Field {
                        id: register.1,
                        kind,
                        state,
                    },
                )
            })
            .collect()
    }

    fn live(&self, register: &Register) -> BTreeSet<OpId> {
        let Some(ops) = self.register_ops().remove(register) else {
            return BTreeSet::new();
        };
        let known: BTreeSet<OpId> = ops.keys().copied().collect();
        let applied = fold::applicable(&known, &ops);
        let dominated: BTreeSet<OpId> = applied
            .iter()
            .filter_map(|id| ops.get(id))
            .flat_map(|op| op.deps.iter().copied())
            .collect();
        applied.difference(&dominated).copied().collect()
    }

    fn plain(
        &self,
        register: &Register,
        kind: FieldKind,
        stored: &Stored,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if !kind.is_secret() {
            return Ok(Zeroizing::new(stored.bytes.clone()));
        }
        let key = self
            .keys
            .get(&stored.source)
            .ok_or_else(|| anyhow!("the field key of a value is missing"))?;
        open_value(key, &register.0, &register.1, &stored.bytes)
    }

    /// Lists every live entry, decrypting no secret.
    #[must_use]
    pub fn list(&self) -> Vec<EntryView> {
        let registers = self.registers();
        let entry_ids: BTreeSet<Id> = registers.keys().map(|(entry, _, _)| *entry).collect();
        let mut views = Vec::new();
        for entry in entry_ids {
            let name = registers.get(&(entry, NAME, Slot::Value));
            if name.is_none_or(|field| field.state.deleted && field.state.values.is_empty()) {
                continue;
            }
            let text = |bytes: &[u8]| displayable(&String::from_utf8_lossy(bytes));
            let names = name.map_or_else(Vec::new, |field| {
                field
                    .state
                    .values
                    .iter()
                    .map(|value| text(&value.bytes))
                    .collect()
            });
            let sensitivity = registers
                .get(&(entry, SENSITIVITY, Slot::Value))
                .and_then(|field| {
                    field
                        .state
                        .values
                        .iter()
                        .filter_map(|value| value.bytes.first().copied())
                        .filter_map(|code| Sensitivity::from_code(code).ok())
                        .max()
                })
                .unwrap_or(Sensitivity::Normal);
            let mut conflict = false;
            let mut fields = Vec::new();
            for ((_, field_id, slot), field) in
                registers.range((entry, [0; 16], Slot::Value)..=(entry, [0xff; 16], Slot::Pending))
            {
                conflict |= field.state.conflict;
                if *slot == Slot::Pending || *field_id == NAME || *field_id == SENSITIVITY {
                    continue;
                }
                if field.state.values.is_empty() {
                    continue;
                }
                let pending = registers
                    .get(&(entry, *field_id, Slot::Pending))
                    .is_some_and(|pending| !pending.state.values.is_empty());
                fields.push(FieldView {
                    id: *field_id,
                    kind: field.kind,
                    shown: (!field.kind.is_secret()).then(|| {
                        field
                            .state
                            .values
                            .iter()
                            .map(|value| text(&value.bytes))
                            .collect()
                    }),
                    pending,
                    conflict: field.state.conflict,
                });
            }
            views.push(EntryView {
                id: entry,
                names,
                sensitivity,
                fields,
                conflict,
            });
        }
        views
    }

    /// Decrypts the live values of one field: exactly one secret field per
    /// release. Several values mean a conflict the user must resolve.
    ///
    /// # Errors
    ///
    /// Returns an error when the field does not exist or a value does not
    /// open.
    pub fn reveal(&self, entry: &Id, field: &Id, slot: Slot) -> Result<Vec<Zeroizing<Vec<u8>>>> {
        let register = (*entry, *field, slot);
        let registers = self.registers();
        let found = registers
            .get(&register)
            .ok_or_else(|| anyhow!("no such field"))?;
        found
            .state
            .values
            .iter()
            .map(|stored| self.plain(&register, found.kind, stored))
            .collect()
    }
}

/// Changes made in one session, written as one object when it ends.
pub struct Changes<'a> {
    entries: &'a Entries,
    key: Zeroizing<[u8; 32]>,
    ops: Vec<FieldOp>,
    time: u64,
}

impl<'a> Changes<'a> {
    /// Starts a batch against the entries as they are now. `time` is for
    /// display and the retention window only.
    #[must_use]
    pub fn new(entries: &'a Entries, time: u64) -> Self {
        let mut key = Zeroizing::new([0; 32]);
        rand::fill(&mut key[..]);
        Self {
            entries,
            key,
            ops: Vec::new(),
            time,
        }
    }

    fn deps(&self, register: &Register) -> Result<BTreeSet<OpId>> {
        ensure!(
            !self.ops.iter().any(|op| op.register == *register),
            "a register changes at most once per batch"
        );
        Ok(self.entries.live(register))
    }

    fn set(&mut self, register: Register, kind: FieldKind, plain: &[u8]) -> Result<()> {
        let deps = self.deps(&register)?;
        let value = if kind.is_secret() {
            seal_value(&self.key, &register.0, &register.1, plain)?
        } else {
            plain.to_vec()
        };
        self.ops.push(FieldOp {
            register,
            kind,
            deps,
            time: self.time,
            value: Some(value),
            old: Vec::new(),
        });
        Ok(())
    }

    fn delete(&mut self, register: Register) -> Result<()> {
        let registers = self.entries.registers();
        let field = registers
            .get(&register)
            .ok_or_else(|| anyhow!("no such field"))?;
        // The tombstone keeps what it removed, sealed again under this
        // object's key, so the value outlives the ops that wrote it.
        let old = field
            .state
            .values
            .iter()
            .map(|stored| {
                let plain = self.entries.plain(&register, field.kind, stored)?;
                if field.kind.is_secret() {
                    seal_value(&self.key, &register.0, &register.1, &plain)
                } else {
                    Ok(plain.to_vec())
                }
            })
            .collect::<Result<_>>()?;
        let deps = self.deps(&register)?;
        self.ops.push(FieldOp {
            register,
            kind: field.kind,
            deps,
            time: self.time,
            value: None,
            old,
        });
        Ok(())
    }

    /// Creates an entry with a name and returns its new random id.
    ///
    /// # Errors
    ///
    /// Returns an error when sealing fails.
    pub fn create(&mut self, name: &str) -> Result<Id> {
        let entry = new_id();
        self.set((entry, NAME, Slot::Value), FieldKind::Name, name.as_bytes())?;
        Ok(entry)
    }

    /// Renames an entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the entry's name already changed in this batch.
    pub fn rename(&mut self, entry: &Id, name: &str) -> Result<()> {
        self.set(
            (*entry, NAME, Slot::Value),
            FieldKind::Name,
            name.as_bytes(),
        )
    }

    /// Sets an entry's sensitivity class.
    ///
    /// # Errors
    ///
    /// As for [`rename`](Self::rename).
    pub fn classify(&mut self, entry: &Id, sensitivity: Sensitivity) -> Result<()> {
        self.set(
            (*entry, SENSITIVITY, Slot::Value),
            FieldKind::Sensitivity,
            &[sensitivity.code()],
        )
    }

    /// Adds a field and returns its new random id.
    ///
    /// # Errors
    ///
    /// Returns an error when sealing fails.
    pub fn add_field(&mut self, entry: &Id, kind: FieldKind, value: &[u8]) -> Result<Id> {
        let field = new_id();
        self.set((*entry, field, Slot::Value), kind, value)?;
        Ok(field)
    }

    /// Sets a field's value.
    ///
    /// # Errors
    ///
    /// Returns an error when the field already changed in this batch.
    pub fn set_field(
        &mut self,
        entry: &Id,
        field: &Id,
        kind: FieldKind,
        value: &[u8],
    ) -> Result<()> {
        self.set((*entry, *field, Slot::Value), kind, value)
    }

    /// Deletes a field; the tombstone keeps its values for the retention
    /// window.
    ///
    /// # Errors
    ///
    /// Returns an error when the field does not exist.
    pub fn delete_field(&mut self, entry: &Id, field: &Id) -> Result<()> {
        self.delete((*entry, *field, Slot::Value))
    }

    /// Deletes an entry: its name, so it leaves every listing, and every
    /// field, each tombstone keeping its values.
    ///
    /// # Errors
    ///
    /// Returns an error when the entry does not exist.
    pub fn delete_entry(&mut self, entry: &Id) -> Result<()> {
        let registers: Vec<Register> = self
            .entries
            .registers()
            .into_iter()
            .filter(|((id, _, _), field)| id == entry && !field.state.values.is_empty())
            .map(|(register, _)| register)
            .collect();
        ensure!(!registers.is_empty(), "no such entry");
        for register in registers {
            self.delete(register)?;
        }
        Ok(())
    }

    /// Two-phase rotation, step 1: writes the new value as pending, before
    /// the remote system changes. Both values stay readable until commit.
    ///
    /// # Errors
    ///
    /// Returns an error when sealing fails.
    pub fn begin_rotation(
        &mut self,
        entry: &Id,
        field: &Id,
        kind: FieldKind,
        value: &[u8],
    ) -> Result<()> {
        self.set((*entry, *field, Slot::Pending), kind, value)
    }

    /// Two-phase rotation, step 3: the remote change is confirmed, so the
    /// pending value becomes current.
    ///
    /// # Errors
    ///
    /// Returns an error when no single rotation is pending.
    pub fn commit_rotation(&mut self, entry: &Id, field: &Id) -> Result<()> {
        let pending = (*entry, *field, Slot::Pending);
        let values = self.entries.reveal(entry, field, Slot::Pending)?;
        let [value] = values.as_slice() else {
            bail!("no single pending value to commit")
        };
        let kind = self
            .entries
            .registers()
            .get(&pending)
            .map_or(FieldKind::Secret, |found| found.kind);
        self.set((*entry, *field, Slot::Value), kind, value)?;
        self.delete(pending)
    }

    /// Two-phase rotation, abort: the old value stays current.
    ///
    /// # Errors
    ///
    /// Returns an error when no rotation is pending.
    pub fn abort_rotation(&mut self, entry: &Id, field: &Id) -> Result<()> {
        self.delete((*entry, *field, Slot::Pending))
    }

    /// Writes the batch as one op object. Returns `None` when there was
    /// nothing to write.
    ///
    /// # Errors
    ///
    /// Returns an error when the device may not write or the write fails.
    pub fn write(self, device: &mut Device, store: &Store) -> Result<Option<Hash>> {
        if self.ops.is_empty() {
            return Ok(None);
        }
        let batch = Batch {
            key: self.key,
            ops: self.ops,
        };
        device
            .write_content(store, Kind::Op, batch.encode().to_vec())
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::authority::{Lifetime, Role, tests::roots};
    use crate::vault::device::Me;
    use crate::vault::pairing::{AdminStart, DeviceReply};
    use crate::vault::test_support::Scratch;

    const NOW: u64 = 1_700_000_000;

    fn setup() -> (Scratch, Store, Device, Device) {
        let scratch = Scratch::new("entries");
        std::fs::create_dir_all(&scratch.0).unwrap();
        let store = Store::open(&scratch.0, true).unwrap();
        let roots = roots();
        let mut admin = Device::create(
            &store,
            Me::generate(),
            roots.genesis,
            [(&roots.keys[0], 0), (&roots.keys[1], 1)],
            [7; 16],
            "personal",
            NOW,
        )
        .unwrap();
        let me = Me::generate();
        let (start, commit) = AdminStart::new(&admin.me().keys(), admin.genesis_hash());
        let (reply_state, reply) = DeviceReply::new(&me.keys(), &commit).unwrap();
        let (on_admin, reveal) = start.reveal(&reply).unwrap();
        admin
            .add(
                &store,
                &on_admin.peer,
                [7; 16],
                Role::Writer,
                Lifetime::Desktop,
                NOW,
            )
            .unwrap();
        let mut laptop = Device::joining(me, &reply_state.check(&reveal).unwrap());
        laptop.sync(&store).unwrap();
        (scratch, store, admin, laptop)
    }

    fn reveal_one(device: &Device, entry: &Id, field: &Id) -> String {
        let entries = Entries::read(device).unwrap();
        let values = entries.reveal(entry, field, Slot::Value).unwrap();
        assert_eq!(values.len(), 1);
        String::from_utf8(values[0].to_vec()).unwrap()
    }

    #[test]
    fn an_entry_written_on_one_device_is_listed_and_revealed_on_another() {
        let (_scratch, store, mut admin, mut laptop) = setup();
        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW);
        let github = changes.create("github").unwrap();
        let user = changes
            .add_field(&github, FieldKind::Username, b"octocat")
            .unwrap();
        let password = changes
            .add_field(&github, FieldKind::Secret, b"hunter2")
            .unwrap();
        changes.write(&mut admin, &store).unwrap();

        laptop.sync(&store).unwrap();
        let entries = Entries::read(&laptop).unwrap();
        let listed = entries.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].names, vec!["github".to_owned()]);
        let fields: BTreeMap<Id, &FieldView> = listed[0]
            .fields
            .iter()
            .map(|field| (field.id, field))
            .collect();
        assert_eq!(fields[&user].shown, Some(vec!["octocat".to_owned()]));
        assert_eq!(fields[&password].shown, None);
        assert_eq!(reveal_one(&laptop, &github, &password), "hunter2");
    }

    #[test]
    fn concurrent_edits_are_kept_and_flagged_and_a_later_edit_resolves_them() {
        let (_scratch, store, mut admin, mut laptop) = setup();
        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW);
        let entry = changes.create("db").unwrap();
        let password = changes
            .add_field(&entry, FieldKind::Secret, b"one")
            .unwrap();
        changes.write(&mut admin, &store).unwrap();
        laptop.sync(&store).unwrap();

        for (device, value) in [(&mut admin, b"admin"), (&mut laptop, b"lapto")] {
            let entries = Entries::read(device).unwrap();
            let mut changes = Changes::new(&entries, NOW + 1);
            changes
                .set_field(&entry, &password, FieldKind::Secret, value)
                .unwrap();
            changes.write(device, &store).unwrap();
        }
        admin.sync(&store).unwrap();
        laptop.sync(&store).unwrap();
        for device in [&admin, &laptop] {
            let entries = Entries::read(device).unwrap();
            assert!(entries.list()[0].conflict);
            let mut values: Vec<Vec<u8>> = entries
                .reveal(&entry, &password, Slot::Value)
                .unwrap()
                .iter()
                .map(|value| value.to_vec())
                .collect();
            values.sort();
            assert_eq!(values, vec![b"admin".to_vec(), b"lapto".to_vec()]);
        }

        let entries = Entries::read(&laptop).unwrap();
        let mut changes = Changes::new(&entries, NOW + 2);
        changes
            .set_field(&entry, &password, FieldKind::Secret, b"chosen")
            .unwrap();
        changes.write(&mut laptop, &store).unwrap();
        admin.sync(&store).unwrap();
        assert!(!Entries::read(&admin).unwrap().list()[0].conflict);
        assert_eq!(reveal_one(&admin, &entry, &password), "chosen");
    }

    #[test]
    fn a_deleted_entry_leaves_listings_and_its_tombstones_keep_the_values() {
        let (_scratch, store, mut admin, _laptop) = setup();
        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW);
        let entry = changes.create("old").unwrap();
        changes
            .add_field(&entry, FieldKind::Secret, b"kept")
            .unwrap();
        changes.write(&mut admin, &store).unwrap();

        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW + 1);
        changes.delete_entry(&entry).unwrap();
        changes.write(&mut admin, &store).unwrap();
        let entries = Entries::read(&admin).unwrap();
        assert!(entries.list().is_empty());

        let tombstone = entries
            .ops
            .values()
            .find(|(op, _)| op.value.is_none() && op.kind == FieldKind::Secret)
            .unwrap();
        let key = &entries.keys[&tombstone.1];
        let old = open_value(
            key,
            &tombstone.0.register.0,
            &tombstone.0.register.1,
            &tombstone.0.old[0],
        )
        .unwrap();
        assert_eq!(&old[..], b"kept");
    }

    #[test]
    fn a_rotation_keeps_both_values_until_commit_or_abort() {
        let (_scratch, store, mut admin, _laptop) = setup();
        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW);
        let entry = changes.create("api").unwrap();
        let token = changes
            .add_field(&entry, FieldKind::Secret, b"old")
            .unwrap();
        changes.write(&mut admin, &store).unwrap();

        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW + 1);
        changes
            .begin_rotation(&entry, &token, FieldKind::Secret, b"new")
            .unwrap();
        changes.write(&mut admin, &store).unwrap();
        let entries = Entries::read(&admin).unwrap();
        assert!(entries.list()[0].fields[0].pending);
        assert_eq!(reveal_one(&admin, &entry, &token), "old");

        let mut changes = Changes::new(&entries, NOW + 2);
        changes.commit_rotation(&entry, &token).unwrap();
        changes.write(&mut admin, &store).unwrap();
        let entries = Entries::read(&admin).unwrap();
        assert!(!entries.list()[0].fields[0].pending);
        assert_eq!(reveal_one(&admin, &entry, &token), "new");

        let mut changes = Changes::new(&entries, NOW + 3);
        changes
            .begin_rotation(&entry, &token, FieldKind::Secret, b"newer")
            .unwrap();
        changes.write(&mut admin, &store).unwrap();
        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW + 4);
        changes.abort_rotation(&entry, &token).unwrap();
        changes.write(&mut admin, &store).unwrap();
        assert_eq!(reveal_one(&admin, &entry, &token), "new");
        assert!(!Entries::read(&admin).unwrap().list()[0].fields[0].pending);
    }

    #[test]
    fn a_sealed_value_cannot_move_between_fields() {
        let key = [4; 32];
        let sealed = seal_value(&key, &[1; 16], &[2; 16], b"secret").unwrap();
        assert_eq!(
            &open_value(&key, &[1; 16], &[2; 16], &sealed).unwrap()[..],
            b"secret"
        );
        assert!(open_value(&key, &[1; 16], &[3; 16], &sealed).is_err());
        assert!(open_value(&key, &[9; 16], &[2; 16], &sealed).is_err());
        let mut changed = sealed;
        changed[0] ^= 1;
        assert!(open_value(&key, &[1; 16], &[2; 16], &changed).is_err());
    }

    #[test]
    fn unknown_kinds_survive_and_are_never_shown() {
        let op = FieldOp {
            register: ([1; 16], [2; 16], Slot::Value),
            kind: FieldKind::Unknown(900),
            deps: [OpId {
                object: [3; 48],
                index: 1,
            }]
            .into_iter()
            .collect(),
            time: 5,
            value: Some(vec![1, 2, 3]),
            old: Vec::new(),
        };
        let batch = Batch {
            key: Zeroizing::new([6; 32]),
            ops: vec![op.clone()],
        };
        let read = Batch::decode(&batch.encode()).unwrap();
        assert_eq!(read.ops, vec![op]);
        assert!(FieldKind::Unknown(900).is_secret());
    }

    #[test]
    fn names_are_sanitised_and_sensitivity_takes_the_highest() {
        let (_scratch, store, mut admin, mut laptop) = setup();
        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW);
        let entry = changes.create("evil\x1b]52;c;x\x07").unwrap();
        changes.write(&mut admin, &store).unwrap();
        laptop.sync(&store).unwrap();
        for (device, class) in [
            (&mut admin, Sensitivity::High),
            (&mut laptop, Sensitivity::RootGrade),
        ] {
            let entries = Entries::read(device).unwrap();
            let mut changes = Changes::new(&entries, NOW + 1);
            changes.classify(&entry, class).unwrap();
            changes.write(device, &store).unwrap();
        }
        admin.sync(&store).unwrap();
        let listed = Entries::read(&admin).unwrap().list();
        assert!(!listed[0].names[0].contains('\x1b'));
        assert_eq!(listed[0].sensitivity, Sensitivity::RootGrade);
    }
}
