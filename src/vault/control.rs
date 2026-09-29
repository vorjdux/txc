//! The bodies of control and bookkeeping objects (study sections 7 and 8):
//! membership facts, sender keys, join packages, fact forwards and
//! checkpoints, with the counters that tell a gap from an object that was
//! never addressed to this device.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail, ensure};
use sha2::{Digest, Sha384};
use zeroize::Zeroizing;

use crate::vault::authority::{Endorsement, RootSet};
use crate::vault::core::membership;
use crate::vault::object::{Hash, Id, SenderKey, Signed};
use crate::vault::wire::{Reader, Writer};

const MAX_ITEMS: usize = 100_000;
const FACT_SET_TAG: &[u8] = b"txc/v1/fact-set";

/// The last object of a device that stays valid: everything it wrote after
/// `(seq, hash)` is rejected, however late it arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cutoff {
    /// The device's last valid sequence number.
    pub seq: u64,
    /// The hash of that object.
    pub hash: Hash,
}

/// What a membership fact says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactKind {
    /// The device joined with this certificate.
    Add {
        /// Its certificate.
        certificate: Id,
    },
    /// An admin removed the device.
    Remove(Cutoff),
    /// The device's certificate expired.
    Expire(Cutoff),
    /// The device was told to wipe its keys.
    Kill(Cutoff),
    /// Root revoked an admin, and every certificate it issued after the
    /// cutoff.
    AdminRevoke(Cutoff),
    /// Entries the removed device could read and that must be rotated:
    /// each with a digest of its secrets' versions then, and flagged while
    /// that digest still holds.
    RotationRequired {
        /// The entries and their secrets' versions.
        entries: Vec<(Id, Hash)>,
        /// When the device was removed, as its admin's clock said.
        at: u64,
    },
    /// Root granted an admin more additions.
    MintAllowance(u32),
    /// An authenticator was removed; rotation excludes it.
    AuthenticatorRemove(Id),
    /// The recovery sheets were reissued: new root keys, recovery recipient
    /// and share commitments replace those in force (study section 12).
    Reissue(Box<Reissue>),
}

/// What a reissue of the recovery sheets states. The roots before it sign
/// it; from then on only the new roots act, and the root-signed facts and
/// certificates it lists stay valid, signed by roots that no longer are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reissue {
    /// The roots, recovery recipient and commitments from now on.
    pub set: RootSet,
    /// Root facts, by object hash, carried over.
    pub kept_facts: BTreeSet<Hash>,
    /// Root-issued certificates, by the hash of their encoding, carried
    /// over.
    pub kept_certificates: BTreeSet<Hash>,
}

/// A membership fact about one device: the body of a fact object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fact {
    /// The device it is about.
    pub device: Id,
    /// What it says.
    pub kind: FactKind,
    /// Root signatures, for the facts only root may state.
    pub endorsements: Vec<Endorsement>,
}

impl Fact {
    /// Whether only root may state this fact.
    #[must_use]
    pub const fn needs_root(&self) -> bool {
        matches!(
            self.kind,
            FactKind::AdminRevoke(_) | FactKind::MintAllowance(_) | FactKind::Reissue(_)
        )
    }

    /// The cutoff of a fact that takes the device out.
    #[must_use]
    pub const fn cutoff(&self) -> Option<Cutoff> {
        match self.kind {
            FactKind::Remove(cutoff)
            | FactKind::Expire(cutoff)
            | FactKind::Kill(cutoff)
            | FactKind::AdminRevoke(cutoff) => Some(cutoff),
            _ => None,
        }
    }

    /// The fact as the membership rules see it, if it changes membership.
    #[must_use]
    pub const fn membership(&self) -> Option<membership::Fact<Id>> {
        match self.kind {
            FactKind::Add { .. } => Some(membership::Fact::Add(self.device)),
            FactKind::Remove(_) | FactKind::AdminRevoke(_) => {
                Some(membership::Fact::Remove(self.device))
            }
            FactKind::Expire(_) => Some(membership::Fact::Expire(self.device)),
            FactKind::Kill(_) => Some(membership::Fact::Kill(self.device)),
            _ => None,
        }
    }

    /// The part root signs, without the signatures.
    #[must_use]
    pub fn statement(&self) -> Vec<u8> {
        let mut out = Writer::default();
        out.fixed(b"txc/v1/fact");
        out.fixed(&self.device);
        let cutoff = |out: &mut Writer, code: u8, cutoff: &Cutoff| {
            out.u8(code);
            out.u64(cutoff.seq);
            out.fixed(&cutoff.hash);
        };
        match &self.kind {
            FactKind::Add { certificate } => {
                out.u8(1);
                out.fixed(certificate);
            }
            FactKind::Remove(c) => cutoff(&mut out, 2, c),
            FactKind::Expire(c) => cutoff(&mut out, 3, c),
            FactKind::Kill(c) => cutoff(&mut out, 4, c),
            FactKind::AdminRevoke(c) => cutoff(&mut out, 5, c),
            FactKind::RotationRequired { entries, at } => {
                out.u8(6);
                out.count(entries.len());
                for (entry, version) in entries {
                    out.fixed(entry);
                    out.fixed(version);
                }
                out.u64(*at);
            }
            FactKind::MintAllowance(count) => {
                out.u8(7);
                out.u64(u64::from(*count));
            }
            FactKind::AuthenticatorRemove(id) => {
                out.u8(8);
                out.fixed(id);
            }
            FactKind::Reissue(reissue) => {
                out.u8(9);
                reissue.set.write(&mut out);
                for kept in [&reissue.kept_facts, &reissue.kept_certificates] {
                    out.count(kept.len());
                    for hash in kept {
                        out.fixed(hash);
                    }
                }
            }
        }
        out.finish()
    }

    /// The object body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::default();
        out.bytes(&self.statement());
        out.count(self.endorsements.len());
        for endorsement in &self.endorsements {
            out.u8(endorsement.root);
            out.bytes(&endorsement.signature);
        }
        out.finish()
    }

    /// Reads the object body.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed or not canonical.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut outer = Reader(bytes);
        let statement = outer.bytes()?;
        let endorsements = (0..outer.count(3)?)
            .map(|_| {
                Ok(Endorsement {
                    root: outer.u8()?,
                    signature: outer.bytes()?.to_vec(),
                })
            })
            .collect::<Result<_>>()?;
        outer.finish()?;
        let mut input = Reader(statement);
        ensure!(input.take(11)? == b"txc/v1/fact", "not a membership fact");
        let device = input.fixed()?;
        let read_cutoff = |input: &mut Reader<'_>| -> Result<Cutoff> {
            Ok(Cutoff {
                seq: input.u64()?,
                hash: input.fixed()?,
            })
        };
        let kind = match input.u8()? {
            1 => FactKind::Add {
                certificate: input.fixed()?,
            },
            2 => FactKind::Remove(read_cutoff(&mut input)?),
            3 => FactKind::Expire(read_cutoff(&mut input)?),
            4 => FactKind::Kill(read_cutoff(&mut input)?),
            5 => FactKind::AdminRevoke(read_cutoff(&mut input)?),
            6 => FactKind::RotationRequired {
                entries: (0..input.count(MAX_ITEMS)?)
                    .map(|_| Ok((input.fixed()?, input.fixed()?)))
                    .collect::<Result<_>>()?,
                at: input.u64()?,
            },
            7 => FactKind::MintAllowance(
                u32::try_from(input.u64()?)
                    .map_err(|_count| anyhow!("a mint allowance is out of range"))?,
            ),
            8 => FactKind::AuthenticatorRemove(input.fixed()?),
            9 => {
                let set = RootSet::read(&mut input)?;
                let mut kept = [BTreeSet::new(), BTreeSet::new()];
                for list in &mut kept {
                    for _ in 0..input.count(MAX_ITEMS)? {
                        list.insert(input.fixed()?);
                    }
                }
                let [kept_facts, kept_certificates] = kept;
                FactKind::Reissue(Box::new(Reissue {
                    set,
                    kept_facts,
                    kept_certificates,
                }))
            }
            other => bail!("unknown membership fact {other}"),
        };
        input.finish()?;
        let fact = Self {
            device,
            kind,
            endorsements,
        };
        ensure!(
            fact.encode() == bytes,
            "the fact is not in its canonical encoding"
        );
        Ok(fact)
    }
}

/// The lowest cutoff among the facts that take a device out: concurrent
/// removals and expiries resolve to it, so every device applies the same.
#[must_use]
pub fn effective_cutoff<'a>(
    facts: impl IntoIterator<Item = &'a Fact>,
    device: &Id,
) -> Option<Cutoff> {
    facts
        .into_iter()
        .filter(|fact| fact.device == *device)
        .filter_map(Fact::cutoff)
        .min()
}

/// The commitment to a set of facts, by their object hashes, that every
/// payload carries as `fact_set`.
#[must_use]
pub fn fact_set_hash(facts: &BTreeSet<Hash>) -> Hash {
    let mut hash = Sha384::new();
    Digest::update(&mut hash, FACT_SET_TAG);
    Digest::update(&mut hash, (facts.len() as u64).to_be_bytes());
    for fact in facts {
        Digest::update(&mut hash, fact);
    }
    hash.finalize().into()
}

/// The body of a sender-key object. Who wrote it and whom it is for are in
/// the signed payload: its author and certificate, and its addressing,
/// which names every recipient with its certificate.
pub struct SenderKeyBody {
    /// The key's id.
    pub id: Id,
    /// The key.
    pub key: Zeroizing<[u8; 32]>,
}

impl SenderKeyBody {
    /// The body carrying a sender key.
    #[must_use]
    pub fn from_key(key: &SenderKey) -> Self {
        Self {
            id: key.id,
            key: key.secret().clone(),
        }
    }

    /// The sender key it carries.
    #[must_use]
    pub fn into_key(self) -> SenderKey {
        SenderKey::from_parts(self.id, self.key)
    }

    /// The object body.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut body = Zeroizing::new(Vec::with_capacity(48));
        body.extend_from_slice(&self.id);
        body.extend_from_slice(&self.key[..]);
        body
    }

    /// Reads the object body.
    ///
    /// # Errors
    ///
    /// Returns an error when it is not 48 bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        let id = input.fixed()?;
        let key = Zeroizing::new(input.fixed()?);
        input.finish()?;
        Ok(Self { id, key })
    }
}

fn write_signed(out: &mut Writer, objects: &[Signed]) {
    out.count(objects.len());
    for object in objects {
        out.bytes(&object.payload);
        out.bytes(&object.signature);
    }
}

fn read_signed(input: &mut Reader<'_>) -> Result<Vec<Signed>> {
    (0..input.count(MAX_ITEMS)?)
        .map(|_| {
            Ok(Signed {
                payload: input.bytes()?.to_vec(),
                signature: input.bytes()?.to_vec(),
            })
        })
        .collect()
}

/// What a newly paired device starts from: the pairing admin's whole view.
/// Every object inside keeps its author's signature, so the device checks
/// each one; the sender keys are accepted on the admin's word, because the
/// pairing ceremony authenticated that admin.
pub struct Join {
    /// Genesis, every certificate and every membership fact the admin holds.
    pub objects: Vec<Signed>,
    /// The sender keys the admin holds: writer device, writer certificate,
    /// and the key.
    pub keys: Vec<(Id, Id, SenderKeyBody)>,
    /// The admin's latest snapshot, sealed as a content object, if any.
    pub snapshot: Option<Vec<u8>>,
}

impl Join {
    /// The object body.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Writer::default();
        write_signed(&mut out, &self.objects);
        out.count(self.keys.len());
        for (device, certificate, key) in &self.keys {
            out.fixed(device);
            out.fixed(certificate);
            out.bytes(&key.encode());
        }
        out.bool(self.snapshot.is_some());
        if let Some(snapshot) = &self.snapshot {
            out.bytes(snapshot);
        }
        Zeroizing::new(out.finish())
    }

    /// Reads the object body.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        let objects = read_signed(&mut input)?;
        let keys = (0..input.count(MAX_ITEMS)?)
            .map(|_| {
                Ok((
                    input.fixed()?,
                    input.fixed()?,
                    SenderKeyBody::decode(input.bytes()?)?,
                ))
            })
            .collect::<Result<_>>()?;
        let snapshot = if input.bool()? {
            Some(input.bytes()?.to_vec())
        } else {
            None
        };
        input.finish()?;
        Ok(Self {
            objects,
            keys,
            snapshot,
        })
    }
}

/// Facts an admin seals again for a member that lacked them: the body of a
/// fact-forward object. Each fact keeps its author's signature.
#[derive(Debug, PartialEq, Eq)]
pub struct Forward(pub Vec<Signed>);

impl Forward {
    /// The object body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::default();
        write_signed(&mut out, &self.0);
        out.finish()
    }

    /// Reads the object body.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        let objects = read_signed(&mut input)?;
        input.finish()?;
        Ok(Self(objects))
    }
}

/// A device's record of what it has seen, written at every unlock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// The head it has seen from every device, its own included.
    pub heads: BTreeMap<Id, (u64, Hash)>,
    /// The membership facts it holds, by object hash, for anti-entropy.
    pub facts: BTreeSet<Hash>,
    /// The snapshots it has verified, for garbage collection.
    pub verified: BTreeSet<Hash>,
    /// The hash of the txc build that wrote it: an honest-client signal.
    pub build: Hash,
    /// When it was written, by its writer's clock: for display and
    /// staleness only, never for the fold.
    pub time: u64,
    /// Whether its writer holds changes that have waited too long for
    /// objects it cannot read, and asks an admin for a snapshot (rule 7).
    pub wants_snapshot: bool,
}

impl Checkpoint {
    /// The object body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::default();
        out.count(self.heads.len());
        for (device, (seq, hash)) in &self.heads {
            out.fixed(device);
            out.u64(*seq);
            out.fixed(hash);
        }
        for set in [&self.facts, &self.verified] {
            out.count(set.len());
            for hash in set {
                out.fixed(hash);
            }
        }
        out.fixed(&self.build);
        out.u64(self.time);
        out.bool(self.wants_snapshot);
        out.finish()
    }

    /// Reads the object body.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed or not canonical.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        let heads = (0..input.count(MAX_ITEMS)?)
            .map(|_| Ok((input.fixed()?, (input.u64()?, input.fixed()?))))
            .collect::<Result<_>>()?;
        let facts = (0..input.count(MAX_ITEMS)?)
            .map(|_| input.fixed())
            .collect::<Result<_>>()?;
        let verified = (0..input.count(MAX_ITEMS)?)
            .map(|_| input.fixed())
            .collect::<Result<_>>()?;
        let build = input.fixed()?;
        let time = input.u64()?;
        let wants_snapshot = input.bool()?;
        input.finish()?;
        let checkpoint = Self {
            heads,
            facts,
            verified,
            build,
            time,
            wants_snapshot,
        };
        ensure!(
            checkpoint.encode() == bytes,
            "the checkpoint is not in its canonical encoding"
        );
        Ok(checkpoint)
    }
}

/// The sequence numbers seen on one counter: a sender key's objects, or the
/// control objects one author sealed to this device. Every holder of a key
/// is a recipient of every object under it, so a number missing below the
/// highest seen is a real gap; objects never addressed here carry no number
/// and are never gaps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counter {
    /// Everything up to and including this is covered (by objects or by a
    /// snapshot); `None` before anything.
    below: Option<u64>,
    /// Numbers seen above the covered prefix.
    seen: BTreeSet<u64>,
}

impl Counter {
    /// Records one number.
    pub fn insert(&mut self, seq: u64) {
        if self.below.is_some_and(|below| seq <= below) {
            return;
        }
        self.seen.insert(seq);
        self.compact();
    }

    /// Records that a snapshot covers every number up to `seq`, so objects
    /// garbage collection removed never look like gaps.
    pub fn cover(&mut self, seq: u64) {
        if self.below.is_none_or(|below| seq > below) {
            self.below = Some(seq);
            self.seen.retain(|seen| *seen > seq);
            self.compact();
        }
    }

    fn compact(&mut self) {
        loop {
            let next = self.below.map_or(0, |below| below.saturating_add(1));
            if !self.seen.remove(&next) {
                break;
            }
            self.below = Some(next);
        }
    }

    /// The highest number seen.
    #[must_use]
    pub fn highest(&self) -> Option<u64> {
        self.seen.last().copied().or(self.below)
    }

    /// The counter's encoding, for sealed local state.
    pub fn write(&self, out: &mut Writer) {
        out.bool(self.below.is_some());
        out.u64(self.below.unwrap_or(0));
        out.count(self.seen.len());
        for seq in &self.seen {
            out.u64(*seq);
        }
    }

    /// Reads what [`write`](Self::write) wrote.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed.
    pub fn read(input: &mut Reader<'_>) -> Result<Self> {
        let present = input.bool()?;
        let below = input.u64()?;
        let seen = (0..input.count(MAX_ITEMS)?)
            .map(|_| input.u64())
            .collect::<Result<_>>()?;
        Ok(Self {
            below: present.then_some(below),
            seen,
        })
    }

    /// The numbers missing below the highest seen.
    #[must_use]
    pub fn gaps(&self) -> Vec<u64> {
        let Some(highest) = self.highest() else {
            return Vec::new();
        };
        let start = self.below.map_or(0, |below| below.saturating_add(1));
        (start..highest)
            .filter(|seq| !self.seen.contains(seq))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn cutoff(seq: u64) -> Cutoff {
        Cutoff {
            seq,
            hash: [u8::try_from(seq % 256).unwrap(); 48],
        }
    }

    #[test]
    fn every_fact_round_trips_canonically() {
        let kinds = [
            FactKind::Add {
                certificate: [1; 16],
            },
            FactKind::Remove(cutoff(3)),
            FactKind::Expire(cutoff(4)),
            FactKind::Kill(cutoff(5)),
            FactKind::AdminRevoke(cutoff(6)),
            FactKind::RotationRequired {
                entries: vec![([2; 16], [5; 48]), ([3; 16], [6; 48])],
                at: 1_700_000_000,
            },
            FactKind::MintAllowance(4),
            FactKind::AuthenticatorRemove([4; 16]),
        ];
        for kind in kinds {
            let fact = Fact {
                device: [9; 16],
                kind,
                endorsements: vec![Endorsement {
                    root: 1,
                    signature: vec![7; 3],
                }],
            };
            let encoded = fact.encode();
            assert_eq!(Fact::decode(&encoded).unwrap(), fact);
            let mut longer = encoded;
            longer.push(0);
            assert!(Fact::decode(&longer).is_err());
        }
    }

    #[test]
    fn concurrent_removals_resolve_to_the_lowest_cutoff() {
        let device = [1; 16];
        let facts = [
            Fact {
                device,
                kind: FactKind::Expire(cutoff(9)),
                endorsements: Vec::new(),
            },
            Fact {
                device,
                kind: FactKind::Remove(cutoff(4)),
                endorsements: Vec::new(),
            },
            Fact {
                device: [2; 16],
                kind: FactKind::Remove(cutoff(1)),
                endorsements: Vec::new(),
            },
            Fact {
                device,
                kind: FactKind::Add {
                    certificate: [0; 16],
                },
                endorsements: Vec::new(),
            },
        ];
        assert_eq!(effective_cutoff(&facts, &device), Some(cutoff(4)));
        assert_eq!(effective_cutoff(&facts, &[3; 16]), None);
    }

    #[test]
    fn the_fact_set_hash_depends_only_on_the_set() {
        let a: BTreeSet<Hash> = [[1; 48], [2; 48]].into_iter().collect();
        let b: BTreeSet<Hash> = [[2; 48], [1; 48]].into_iter().collect();
        assert_eq!(fact_set_hash(&a), fact_set_hash(&b));
        assert_ne!(fact_set_hash(&a), fact_set_hash(&BTreeSet::new()));
    }

    #[test]
    fn bodies_round_trip() {
        let signed = Signed {
            payload: vec![1, 2, 3],
            signature: vec![4; 5],
        };
        let forward = Forward(vec![signed.clone()]);
        assert_eq!(Forward::decode(&forward.encode()).unwrap(), forward);

        let join = Join {
            objects: vec![signed],
            keys: vec![(
                [1; 16],
                [2; 16],
                SenderKeyBody {
                    id: [3; 16],
                    key: Zeroizing::new([4; 32]),
                },
            )],
            snapshot: Some(vec![5; 10]),
        };
        let read = Join::decode(&join.encode()).unwrap();
        assert_eq!(read.objects, join.objects);
        assert_eq!(read.snapshot, join.snapshot);
        assert_eq!(read.keys.len(), 1);
        assert_eq!(*read.keys[0].2.key, [4; 32]);
        let key = SenderKey::generate();
        let body = SenderKeyBody::decode(&SenderKeyBody::from_key(&key).encode()).unwrap();
        assert_eq!((body.id, *body.key), (key.id, **key.secret()));
        assert!(SenderKeyBody::decode(&[0; 47]).is_err());

        let checkpoint = Checkpoint {
            heads: [([1; 16], (3, [2; 48]))].into_iter().collect(),
            facts: [[3; 48]].into_iter().collect(),
            verified: BTreeSet::new(),
            build: [4; 48],
            time: 1_700_000_000,
            wants_snapshot: true,
        };
        assert_eq!(
            Checkpoint::decode(&checkpoint.encode()).unwrap(),
            checkpoint
        );
    }

    #[test]
    fn a_counter_reports_real_gaps_only() {
        let mut counter = Counter::default();
        assert!(counter.gaps().is_empty());
        for seq in [0, 1, 3, 6] {
            counter.insert(seq);
        }
        assert_eq!(counter.gaps(), vec![2, 4, 5]);
        counter.cover(4);
        assert_eq!(counter.gaps(), vec![5]);
        counter.insert(5);
        assert!(counter.gaps().is_empty());
        assert_eq!(counter.highest(), Some(6));
    }

    proptest! {
        /// Whatever order numbers and snapshot coverage arrive in, the gaps
        /// are exactly the numbers below the highest that nothing covered.
        #[test]
        fn counter_gaps_are_exact(seen in proptest::collection::btree_set(0_u64..40, 0..20), cover in proptest::option::of(0_u64..40)) {
            let mut counter = Counter::default();
            for seq in &seen {
                counter.insert(*seq);
            }
            if let Some(cover) = cover {
                counter.cover(cover);
            }
            let highest = seen.iter().copied().chain(cover).max();
            let expected: Vec<u64> = highest.map_or_else(Vec::new, |highest| {
                (0..highest).filter(|seq| !seen.contains(seq) && cover.is_none_or(|cover| *seq > cover)).collect()
            });
            prop_assert_eq!(counter.gaps(), expected);
        }
    }
}
