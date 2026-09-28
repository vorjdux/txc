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
use crate::vault::device::{Content, Device};
use crate::vault::model::displayable;
use crate::vault::object::{Addressing, Hash, Id, Kind};
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

/// The register holding what an entry is ("login", "card"), which decides
/// its main secret.
pub const KIND: Id = {
    let mut id = [0; 16];
    id[15] = 2;
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

/// Which of a field's registers: its value, a rotation in progress, or its
/// name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Slot {
    /// The current value.
    Value,
    /// A new value written before a remote change, until commit or abort.
    Pending,
    /// The field's name, as people refer to it: "password", "cvv".
    Label,
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
        Slot::Label => 2,
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
        2 => Slot::Label,
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
    /// What it is, when set; more than one is a conflict.
    pub kinds: Vec<String>,
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
    /// Its name, sanitised; concurrent names are joined with " / ".
    pub label: String,
    /// What it holds.
    pub kind: FieldKind,
    /// Its values sanitised for display, or `None` for a secret kind.
    pub shown: Option<Vec<String>>,
    /// Whether it has a rotation in progress.
    pub pending: bool,
    /// Whether concurrent writes left more than one value.
    pub conflict: bool,
}

/// A snapshot: the objects it covers and the folded state of every
/// register, with values sealed again under its own field key.
struct SnapshotBody {
    key: Zeroizing<[u8; 32]>,
    /// The op objects it covers.
    covers: BTreeSet<Hash>,
    /// Per sender key, the highest sequence number it covers.
    keys: BTreeMap<Id, u64>,
    /// Every register's live ops.
    live: Vec<(OpId, FieldOp)>,
    /// Tombstones still inside the retention window that are no longer live.
    tombs: Vec<(OpId, FieldOp)>,
}

const SNAPSHOT_TAG: &[u8] = b"txc/v1/snapshot";

fn write_id_op(out: &mut Writer, id: &OpId, op: &FieldOp) {
    out.fixed(&id.object);
    out.u64(u64::from(id.index));
    write_op(out, op);
}

fn read_id_op(input: &mut Reader<'_>) -> Result<(OpId, FieldOp)> {
    let object = input.fixed()?;
    let index =
        u32::try_from(input.u64()?).map_err(|_index| anyhow!("an op index is out of range"))?;
    Ok((OpId { object, index }, read_op(input)?))
}

impl SnapshotBody {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Writer::default();
        out.fixed(SNAPSHOT_TAG);
        out.fixed(&self.key[..]);
        out.count(self.covers.len());
        for object in &self.covers {
            out.fixed(object);
        }
        out.count(self.keys.len());
        for (key, seq) in &self.keys {
            out.fixed(key);
            out.u64(*seq);
        }
        for list in [&self.live, &self.tombs] {
            out.count(list.len());
            for (id, op) in list {
                write_id_op(&mut out, id, op);
            }
        }
        Zeroizing::new(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        ensure!(
            input.take(SNAPSHOT_TAG.len())? == SNAPSHOT_TAG,
            "not a snapshot"
        );
        let key = Zeroizing::new(input.fixed()?);
        let covers = (0..input.count(MAX_OPS)?)
            .map(|_| input.fixed())
            .collect::<Result<_>>()?;
        let keys = (0..input.count(MAX_OPS)?)
            .map(|_| Ok((input.fixed()?, input.u64()?)))
            .collect::<Result<_>>()?;
        let live = (0..input.count(MAX_OPS)?)
            .map(|_| read_id_op(&mut input))
            .collect::<Result<_>>()?;
        let tombs = (0..input.count(MAX_OPS)?)
            .map(|_| read_id_op(&mut input))
            .collect::<Result<_>>()?;
        input.finish()?;
        Ok(Self {
            key,
            covers,
            keys,
            live,
            tombs,
        })
    }
}

/// How many op objects since the last snapshot trigger a new one (rule 19).
pub const COMPACT_AFTER: usize = 200;

/// The entries of a vault, folded from the ops a device has accepted and
/// the snapshot they start from.
pub struct Entries {
    /// The ops folded: those the base snapshot stands in for, then every
    /// op object it does not cover.
    ops: BTreeMap<OpId, (FieldOp, Hash)>,
    /// Field keys, by the object whose values they seal.
    keys: BTreeMap<Hash, Zeroizing<[u8; 32]>>,
    /// The snapshot the fold starts from, if any.
    base: Option<(Hash, SnapshotBody)>,
    /// Snapshots this device re-folded and found equal (rule 13).
    verified: BTreeSet<Hash>,
    /// Other valid snapshots, by hash, with what they cover.
    snapshots: BTreeMap<Hash, BTreeSet<Hash>>,
    /// Op objects read and not covered by the base, with their sender key
    /// and sequence number.
    objects: BTreeMap<Hash, (Id, u64)>,
}

/// Op objects and snapshots as a device holds them.
struct Raw {
    batches: BTreeMap<Hash, (Batch, (Id, u64))>,
    snapshots: BTreeMap<Hash, (SnapshotBody, Id)>,
}

const fn origin(content: &Content) -> (Id, u64) {
    match content.payload.addressing {
        Addressing::Content { key, seq } => (key, seq),
        Addressing::Control(_) => ([0; 16], 0),
    }
}

/// Whether an op can be applied: every dep, transitively, is present or
/// covered by the base snapshot.
fn applied(ops: &BTreeMap<OpId, (FieldOp, Hash)>, id: &OpId, covered: &BTreeSet<Hash>) -> bool {
    let mut stack = vec![*id];
    let mut seen = BTreeSet::new();
    while let Some(current) = stack.pop() {
        if !seen.insert(current) || covered.contains(&current.object) {
            continue;
        }
        let Some((op, _)) = ops.get(&current) else {
            return false;
        };
        stack.extend(op.deps.iter().copied());
    }
    true
}

/// Folds registers from a set of ops, where deps on objects in `covered`
/// count as present.
fn fold_registers(
    ops: &BTreeMap<OpId, (FieldOp, Hash)>,
    covered: &BTreeSet<Hash>,
) -> BTreeMap<Register, (FieldKind, BTreeSet<OpId>, State<Stored>)> {
    let mut registers: BTreeMap<Register, BTreeMap<OpId, Op<OpId, Stored>>> = BTreeMap::new();
    for (id, (op, source)) in ops {
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
        .into_iter()
        .map(|(register, register_ops)| {
            // Rule 7: an op waits until every dep is here or covered.
            let mut applied: BTreeSet<OpId> = BTreeSet::new();
            loop {
                let before = applied.len();
                for (id, op) in &register_ops {
                    if op
                        .deps
                        .iter()
                        .all(|dep| applied.contains(dep) || covered.contains(&dep.object))
                    {
                        applied.insert(*id);
                    }
                }
                if applied.len() == before {
                    break;
                }
            }
            let dominated: BTreeSet<OpId> = applied
                .iter()
                .filter_map(|id| register_ops.get(id))
                .flat_map(|op| op.deps.iter().copied())
                .collect();
            let live: BTreeSet<OpId> = applied.difference(&dominated).copied().collect();
            let kind = live
                .iter()
                .filter_map(|id| ops.get(id))
                .map(|(op, _)| op.kind)
                .next_back()
                .unwrap_or(FieldKind::Unknown(0));
            let state = fold::fold(&applied, &register_ops);
            (register, (kind, live, state))
        })
        .collect()
}

impl Entries {
    /// Folds every valid op object and snapshot the device holds.
    ///
    /// # Errors
    ///
    /// Returns an error when an op object or snapshot is malformed.
    pub fn read(device: &Device) -> Result<Self> {
        let mut raw = Raw {
            batches: BTreeMap::new(),
            snapshots: BTreeMap::new(),
        };
        for content in device.content() {
            match content.payload.kind {
                Kind::Op => {
                    raw.batches.insert(
                        content.hash,
                        (Batch::decode(&content.payload.body)?, origin(content)),
                    );
                }
                Kind::Snapshot => {
                    raw.snapshots.insert(
                        content.hash,
                        (
                            SnapshotBody::decode(&content.payload.body)?,
                            content.payload.author,
                        ),
                    );
                }
                _ => {}
            }
        }
        // Verify snapshots smallest first, so each can be checked against
        // an already verified one it extends.
        let mut order: Vec<&Hash> = raw.snapshots.keys().collect();
        order.sort_by_key(|hash| {
            (
                raw.snapshots
                    .get(*hash)
                    .map_or(0, |(body, _)| body.covers.len()),
                **hash,
            )
        });
        let mut verified: BTreeSet<Hash> = device.verified().clone();
        for hash in order {
            if verified.contains(hash) {
                continue;
            }
            if Self::check(&raw, &verified, hash) {
                verified.insert(*hash);
            }
        }
        // The base: the verified snapshot covering most, or one from the
        // admin this device paired with that it could not check (trust on
        // join, rule 13).
        let trusted = device.paired_admin();
        let base = raw
            .snapshots
            .iter()
            .filter(|(hash, (_, author))| verified.contains(*hash) || Some(*author) == trusted)
            .max_by_key(|(hash, (body, _))| (body.covers.len(), **hash))
            .map(|(hash, _)| *hash);
        let mut entries = Self {
            ops: BTreeMap::new(),
            keys: BTreeMap::new(),
            base: None,
            verified,
            snapshots: BTreeMap::new(),
            objects: BTreeMap::new(),
        };
        let covered: BTreeSet<Hash> = base
            .and_then(|hash| {
                raw.snapshots
                    .get(&hash)
                    .map(|(body, _)| body.covers.clone())
            })
            .unwrap_or_default();
        for (hash, (batch, at)) in raw.batches {
            if covered.contains(&hash) {
                continue;
            }
            for (index, op) in (0_u32..).zip(batch.ops) {
                entries.ops.insert(
                    OpId {
                        object: hash,
                        index,
                    },
                    (op, hash),
                );
            }
            entries.keys.insert(hash, batch.key);
            entries.objects.insert(hash, at);
        }
        for (hash, (body, _)) in raw.snapshots {
            if Some(hash) == base {
                for (id, op) in &body.live {
                    entries.ops.insert(*id, (op.clone(), hash));
                }
                entries.keys.insert(hash, Zeroizing::new(*body.key));
                entries.base = Some((hash, body));
            } else {
                entries.snapshots.insert(hash, body.covers);
            }
        }
        Ok(entries)
    }

    /// Rule 13: re-folds what a snapshot covers from the ops this device
    /// holds, starting from a verified snapshot it extends, and compares.
    fn check(raw: &Raw, verified: &BTreeSet<Hash>, hash: &Hash) -> bool {
        let Some((body, _)) = raw.snapshots.get(hash) else {
            return false;
        };
        let start = verified
            .iter()
            .filter_map(|other| {
                raw.snapshots
                    .get(other)
                    .map(|(snapshot, _)| (other, snapshot))
            })
            .filter(|(_, snapshot)| snapshot.covers.is_subset(&body.covers))
            .max_by_key(|(other, snapshot)| (snapshot.covers.len(), **other));
        let covered_before: BTreeSet<Hash> = start
            .map(|(_, snapshot)| snapshot.covers.clone())
            .unwrap_or_default();
        let mut ops: BTreeMap<OpId, (FieldOp, Hash)> = BTreeMap::new();
        let mut keys: BTreeMap<Hash, &[u8; 32]> = BTreeMap::new();
        if let Some((start_hash, snapshot)) = start {
            for (id, op) in &snapshot.live {
                ops.insert(*id, (op.clone(), *start_hash));
            }
            keys.insert(*start_hash, &snapshot.key);
        }
        for object in body.covers.difference(&covered_before) {
            let Some((batch, _)) = raw.batches.get(object) else {
                return false;
            };
            for (index, op) in (0_u32..).zip(&batch.ops) {
                ops.insert(
                    OpId {
                        object: *object,
                        index,
                    },
                    (op.clone(), *object),
                );
            }
            keys.insert(*object, &batch.key);
        }
        let expected = fold_registers(&ops, &covered_before);
        let mut claimed: BTreeMap<Register, BTreeSet<OpId>> = BTreeMap::new();
        for (id, op) in &body.live {
            claimed.entry(op.register).or_default().insert(*id);
        }
        let plain = |register: &Register,
                     kind: FieldKind,
                     key: &[u8; 32],
                     bytes: &[u8]|
         -> Option<Vec<u8>> {
            if kind.is_secret() {
                open_value(key, &register.0, &register.1, bytes)
                    .ok()
                    .map(|plain| plain.to_vec())
            } else {
                Some(bytes.to_vec())
            }
        };
        expected
            .iter()
            .filter(|(_, (_, live, _))| !live.is_empty())
            .count()
            == claimed.len()
            && expected.iter().all(|(register, (kind, live, _))| {
                if live.is_empty() {
                    return !claimed.contains_key(register);
                }
                claimed.get(register) == Some(live)
                    && live.iter().all(|id| {
                        let Some((original, source)) = ops.get(id) else {
                            return false;
                        };
                        let Some((_, copy)) = body.live.iter().find(|(other, _)| other == id)
                        else {
                            return false;
                        };
                        let Some(source_key) = keys.get(source) else {
                            return false;
                        };
                        let values = |op: &FieldOp, key: &[u8; 32]| -> Option<Vec<Vec<u8>>> {
                            op.value
                                .iter()
                                .map(|value| plain(register, *kind, key, value))
                                .collect()
                        };
                        copy.deps == original.deps
                            && copy.value.is_some() == original.value.is_some()
                            && values(original, source_key) == values(copy, &body.key)
                    })
            })
    }

    fn covered(&self) -> BTreeSet<Hash> {
        self.base
            .as_ref()
            .map(|(_, body)| body.covers.clone())
            .unwrap_or_default()
    }

    /// Every register's folded state, over the ops whose dependencies have
    /// all arrived or are covered by the base snapshot; the rest wait
    /// (rule 7).
    #[must_use]
    pub fn registers(&self) -> BTreeMap<Register, Field> {
        fold_registers(&self.ops, &self.covered())
            .into_iter()
            .map(|(register, (kind, _, state))| {
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
        let ops: BTreeMap<OpId, (FieldOp, Hash)> = self
            .ops
            .iter()
            .filter(|(_, (op, _))| op.register == *register)
            .map(|(id, op)| (*id, op.clone()))
            .collect();
        fold_registers(&ops, &self.covered())
            .remove(register)
            .map(|(_, live, _)| live)
            .unwrap_or_default()
    }

    /// When a field's current value was written: the latest time among its
    /// live ops. It serves as the entry version a grant carries.
    #[must_use]
    pub fn written_at(&self, entry: &Id, field: &Id) -> Option<u64> {
        let register = (*entry, *field, Slot::Value);
        self.live(&register)
            .iter()
            .filter_map(|id| self.ops.get(id))
            .map(|(op, _)| op.time)
            .max()
    }

    /// The snapshots this device verified, for its checkpoint.
    #[must_use]
    pub fn verified(&self) -> BTreeSet<Hash> {
        self.verified.clone()
    }

    /// Whether enough op objects arrived since the base snapshot that a new
    /// one is due (rule 19).
    #[must_use]
    pub fn needs_snapshot(&self) -> bool {
        self.objects.len() >= COMPACT_AFTER
    }

    /// Writes a snapshot of everything folded so far: the live ops of every
    /// register sealed again under a new field key, and the tombstones still
    /// inside the retention window.
    ///
    /// # Errors
    ///
    /// Returns an error when a value does not open or the write fails.
    pub fn snapshot(
        &self,
        device: &mut Device,
        store: &Store,
        now: u64,
        retention: u64,
    ) -> Result<Hash> {
        let covered = self.covered();
        let folded = fold_registers(&self.ops, &covered);
        let applied_objects: BTreeSet<Hash> = self
            .objects
            .keys()
            .filter(|object| {
                self.ops
                    .keys()
                    .filter(|id| id.object == **object)
                    .all(|id| applied(&self.ops, id, &covered))
            })
            .copied()
            .collect();
        let mut key = Zeroizing::new([0; 32]);
        rand::fill(&mut key[..]);
        let reseal = |op: &FieldOp, source: &Hash| -> Result<FieldOp> {
            let source_key = self
                .keys
                .get(source)
                .ok_or_else(|| anyhow!("a field key is missing"))?;
            let seal = |bytes: &Vec<u8>| -> Result<Vec<u8>> {
                if op.kind.is_secret() {
                    let plain = open_value(source_key, &op.register.0, &op.register.1, bytes)?;
                    seal_value(&key, &op.register.0, &op.register.1, &plain)
                } else {
                    Ok(bytes.clone())
                }
            };
            Ok(FieldOp {
                value: op.value.as_ref().map(seal).transpose()?,
                old: op.old.iter().map(seal).collect::<Result<_>>()?,
                ..op.clone()
            })
        };
        let mut live = Vec::new();
        for (_, ids, _) in folded.values() {
            for id in ids {
                let (op, source) = self
                    .ops
                    .get(id)
                    .ok_or_else(|| anyhow!("a live op is missing"))?;
                live.push((*id, reseal(op, source)?));
            }
        }
        let live_ids: BTreeSet<OpId> = live.iter().map(|(id, _)| *id).collect();
        let mut tombs = Vec::new();
        for (id, (op, source)) in &self.ops {
            let in_window = now.saturating_sub(op.time) < retention;
            if op.value.is_none()
                && in_window
                && !live_ids.contains(id)
                && applied_objects.contains(&id.object)
            {
                tombs.push((*id, reseal(op, source)?));
            }
        }
        if let Some((hash, base)) = &self.base {
            for (id, op) in &base.tombs {
                if now.saturating_sub(op.time) < retention {
                    tombs.push((*id, reseal(op, hash)?));
                }
            }
        }
        let mut keys = self
            .base
            .as_ref()
            .map(|(_, body)| body.keys.clone())
            .unwrap_or_default();
        for object in &applied_objects {
            if let Some((sender, seq)) = self.objects.get(object) {
                let highest = keys.entry(*sender).or_insert(*seq);
                *highest = (*highest).max(*seq);
            }
        }
        let body = SnapshotBody {
            key,
            covers: covered.union(&applied_objects).copied().collect(),
            keys,
            live,
            tombs,
        };
        device.write_content(store, Kind::Snapshot, body.encode().to_vec())
    }

    /// Garbage collection (rule 16): once every current member's checkpoint
    /// says it verified the base snapshot, this device removes its own op
    /// objects and snapshots that the base covers, and its counters record
    /// the coverage so nothing collected looks like a gap.
    ///
    /// # Errors
    ///
    /// Returns an error when a removal fails.
    pub fn collect(&self, device: &mut Device, store: &Store) -> Result<usize> {
        device.mark_verified(&self.verified);
        let Some((base, body)) = &self.base else {
            return Ok(0);
        };
        for (key, seq) in &body.keys {
            device.cover(*key, *seq);
        }
        let me = device.me().device;
        let everyone = device.view().keys().all(|member| {
            if *member == me {
                return self.verified.contains(base);
            }
            device
                .checkpoints()
                .get(member)
                .is_some_and(|(_, checkpoint)| checkpoint.verified.contains(base))
        });
        if !everyone {
            return Ok(0);
        }
        let mut collectible: BTreeSet<Hash> = body.covers.clone();
        collectible.extend(
            self.snapshots
                .iter()
                .filter(|(_, covers)| covers.is_subset(&body.covers))
                .map(|(hash, _)| *hash),
        );
        let removed = device.collect(store, &collectible)?;
        device.forget(&collectible);
        Ok(removed)
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
                registers.range((entry, [0; 16], Slot::Value)..=(entry, [0xff; 16], Slot::Label))
            {
                conflict |= field.state.conflict;
                if *slot != Slot::Value
                    || *field_id == NAME
                    || *field_id == SENSITIVITY
                    || *field_id == KIND
                {
                    continue;
                }
                if field.state.values.is_empty() {
                    continue;
                }
                let pending = registers
                    .get(&(entry, *field_id, Slot::Pending))
                    .is_some_and(|pending| !pending.state.values.is_empty());
                let label = registers
                    .get(&(entry, *field_id, Slot::Label))
                    .map(|label| {
                        label
                            .state
                            .values
                            .iter()
                            .map(|value| text(&value.bytes))
                            .collect::<Vec<_>>()
                            .join(" / ")
                    })
                    .unwrap_or_default();
                fields.push(FieldView {
                    id: *field_id,
                    label,
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
            let kinds = registers
                .get(&(entry, KIND, Slot::Value))
                .map_or_else(Vec::new, |field| {
                    field
                        .state
                        .values
                        .iter()
                        .map(|value| text(&value.bytes))
                        .collect()
                });
            views.push(EntryView {
                id: entry,
                kinds,
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

    /// Sets what an entry is.
    ///
    /// # Errors
    ///
    /// Returns an error when the kind already changed in this batch.
    pub fn set_kind(&mut self, entry: &Id, kind: &str) -> Result<()> {
        self.set(
            (*entry, KIND, Slot::Value),
            FieldKind::Name,
            kind.as_bytes(),
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

    /// Adds a named field and returns its new random id.
    ///
    /// # Errors
    ///
    /// Returns an error when sealing fails.
    pub fn add_field(
        &mut self,
        entry: &Id,
        kind: FieldKind,
        label: &str,
        value: &[u8],
    ) -> Result<Id> {
        let field = new_id();
        self.set(
            (*entry, field, Slot::Label),
            FieldKind::Name,
            label.as_bytes(),
        )?;
        self.set((*entry, field, Slot::Value), kind, value)?;
        Ok(field)
    }

    /// Renames a field.
    ///
    /// # Errors
    ///
    /// Returns an error when the field's name already changed in this batch.
    pub fn rename_field(&mut self, entry: &Id, field: &Id, label: &str) -> Result<()> {
        self.set(
            (*entry, *field, Slot::Label),
            FieldKind::Name,
            label.as_bytes(),
        )
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
        self.delete((*entry, *field, Slot::Value))?;
        if self
            .entries
            .registers()
            .contains_key(&(*entry, *field, Slot::Label))
        {
            self.delete((*entry, *field, Slot::Label))?;
        }
        Ok(())
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
            .add_field(&github, FieldKind::Username, "username", b"octocat")
            .unwrap();
        let password = changes
            .add_field(&github, FieldKind::Secret, "secret", b"hunter2")
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
        assert_eq!(
            (
                fields[&user].label.as_str(),
                fields[&password].label.as_str()
            ),
            ("username", "secret")
        );
        assert_eq!(reveal_one(&laptop, &github, &password), "hunter2");
    }

    #[test]
    fn concurrent_edits_are_kept_and_flagged_and_a_later_edit_resolves_them() {
        let (_scratch, store, mut admin, mut laptop) = setup();
        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW);
        let entry = changes.create("db").unwrap();
        let password = changes
            .add_field(&entry, FieldKind::Secret, "secret", b"one")
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
            .add_field(&entry, FieldKind::Secret, "secret", b"kept")
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
            .add_field(&entry, FieldKind::Secret, "secret", b"old")
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

    fn names(device: &Device) -> Vec<String> {
        let mut names: Vec<String> = Entries::read(device)
            .unwrap()
            .list()
            .into_iter()
            .flat_map(|entry| entry.names)
            .collect();
        names.sort();
        names
    }

    const DAY: u64 = 86_400;

    #[test]
    fn a_verified_snapshot_lets_every_device_collect_its_own_objects() {
        let (_scratch, store, mut admin, mut laptop) = setup();
        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW);
        let entry = changes.create("mail").unwrap();
        let password = changes
            .add_field(&entry, FieldKind::Secret, "secret", b"first")
            .unwrap();
        changes.write(&mut admin, &store).unwrap();
        laptop.sync(&store).unwrap();
        let entries = Entries::read(&laptop).unwrap();
        let mut changes = Changes::new(&entries, NOW + 1);
        changes
            .set_field(&entry, &password, FieldKind::Secret, b"second")
            .unwrap();
        changes.create("bank").unwrap();
        changes.write(&mut laptop, &store).unwrap();
        admin.sync(&store).unwrap();

        let snapshot = Entries::read(&admin)
            .unwrap()
            .snapshot(&mut admin, &store, NOW + 2, 30 * DAY)
            .unwrap();
        laptop.sync(&store).unwrap();
        for device in [&mut admin, &mut laptop] {
            let entries = Entries::read(device).unwrap();
            assert!(entries.verified().contains(&snapshot));
            device
                .checkpoint(&store, [0; 48], entries.verified())
                .unwrap();
        }
        admin.sync(&store).unwrap();
        laptop.sync(&store).unwrap();
        let before = store.list().unwrap().names.len();
        let removed: usize = [&mut admin, &mut laptop]
            .into_iter()
            .map(|device| {
                Entries::read(device)
                    .unwrap()
                    .collect(device, &store)
                    .unwrap()
            })
            .sum();
        assert_eq!(removed, 2);
        assert_eq!(store.list().unwrap().names.len(), before - 2);

        for device in [&admin, &laptop] {
            assert_eq!(names(device), vec!["bank".to_owned(), "mail".to_owned()]);
            let values = Entries::read(device)
                .unwrap()
                .reveal(&entry, &password, Slot::Value)
                .unwrap();
            assert_eq!(
                values
                    .iter()
                    .map(|value| value.to_vec())
                    .collect::<Vec<_>>(),
                vec![b"second".to_vec()]
            );
        }

        // Editing after collection builds on the snapshot's live ops.
        let entries = Entries::read(&laptop).unwrap();
        let mut changes = Changes::new(&entries, NOW + 3);
        changes
            .set_field(&entry, &password, FieldKind::Secret, b"third")
            .unwrap();
        changes.write(&mut laptop, &store).unwrap();
        admin.sync(&store).unwrap();
        let entries = Entries::read(&admin).unwrap();
        assert!(!entries.list().iter().any(|view| view.conflict));
        assert_eq!(
            entries.reveal(&entry, &password, Slot::Value).unwrap()[0].to_vec(),
            b"third"
        );

        // A device paired afterwards starts from the admin's snapshot.
        let me = Me::generate();
        let (start, commit) = AdminStart::new(&admin.me().keys(), admin.genesis_hash());
        let (reply_state, reply) = DeviceReply::new(&me.keys(), &commit).unwrap();
        let (on_admin, reveal) = start.reveal(&reply).unwrap();
        admin
            .add(
                &store,
                &on_admin.peer,
                [7; 16],
                Role::Reader,
                Lifetime::Desktop,
                NOW,
            )
            .unwrap();
        let mut phone = Device::joining(me, &reply_state.check(&reveal).unwrap());
        phone.sync(&store).unwrap();
        assert_eq!(names(&phone), vec!["bank".to_owned(), "mail".to_owned()]);
        Entries::read(&phone)
            .unwrap()
            .collect(&mut phone, &store)
            .unwrap();
        assert!(phone.gaps().is_empty(), "{:?}", phone.gaps());
    }

    #[test]
    fn a_snapshot_that_does_not_refold_is_never_used() {
        let (_scratch, store, mut admin, mut laptop) = setup();
        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW);
        changes.create("real").unwrap();
        changes.write(&mut admin, &store).unwrap();
        laptop.sync(&store).unwrap();

        // The laptop writes a snapshot claiming another name.
        let entries = Entries::read(&laptop).unwrap();
        let mut forged = Changes::new(&entries, NOW);
        forged.create("forged").unwrap();
        let (id, op) = entries
            .ops
            .iter()
            .next()
            .map(|(id, (op, _))| (*id, op.clone()))
            .unwrap();
        let body = SnapshotBody {
            key: Zeroizing::new([1; 32]),
            covers: [id.object].into_iter().collect(),
            keys: BTreeMap::new(),
            live: vec![(
                id,
                FieldOp {
                    value: Some(b"forged".to_vec()),
                    ..op
                },
            )],
            tombs: Vec::new(),
        };
        let hash = laptop
            .write_content(&store, Kind::Snapshot, body.encode().to_vec())
            .unwrap();
        admin.sync(&store).unwrap();
        let entries = Entries::read(&admin).unwrap();
        assert!(!entries.verified().contains(&hash));
        assert_eq!(names(&admin), vec!["real".to_owned()]);
    }

    #[test]
    fn tombstones_outlive_collection_only_inside_the_window() {
        let (_scratch, store, mut admin, _laptop) = setup();
        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW);
        let entry = changes.create("gone").unwrap();
        changes.write(&mut admin, &store).unwrap();
        let entries = Entries::read(&admin).unwrap();
        let mut changes = Changes::new(&entries, NOW + DAY);
        changes.delete_entry(&entry).unwrap();
        changes.write(&mut admin, &store).unwrap();

        let tombstones = |device: &mut Device, now: u64| {
            Entries::read(device)
                .unwrap()
                .snapshot(device, &store, now, 30 * DAY)
                .unwrap();
            let entries = Entries::read(device).unwrap();
            let (_, base) = entries.base.as_ref().unwrap();
            base.live
                .iter()
                .chain(&base.tombs)
                .filter(|(_, op)| op.value.is_none())
                .count()
        };
        assert_eq!(tombstones(&mut admin, NOW + 2 * DAY), 1);
        assert_eq!(
            tombstones(&mut admin, NOW + 40 * DAY),
            1,
            "a live tombstone stays until superseded"
        );
        assert!(names(&admin).is_empty());
    }
}
