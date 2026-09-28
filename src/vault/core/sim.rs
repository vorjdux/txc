//! Deterministic simulation harness (study section 13), run against the
//! real core: every step checks the safety invariants, and each run is
//! driven to quiescence and checked for convergence. A run is reproducible
//! from its seed alone.

#![allow(
    clippy::pedantic,
    clippy::use_self,
    clippy::missing_const_for_fn,
    clippy::collapsible_if
)]
//!
//! Devices share a folder that the storage adversary controls: objects
//! arrive in any order, late, duplicated, or never (withheld). Admins add
//! and remove devices, members write entry ops and snapshots under sender
//! keys, admins garbage-collect and forward membership facts. Every step
//! checks the safety invariants; at the end the run is driven to quiescence
//! and the convergence invariants are checked. A run is reproducible from its
//! seed alone.

use std::collections::{BTreeMap, BTreeSet};

use crate::vault::core::fold::{self as entry, Kind, Op, Snapshot};
use crate::vault::core::membership::{self, Fact as GenericFact};

type Device = u8;
type OpId = u32;
type Fact = GenericFact<Device>;
type Op8 = Op<OpId, u8>;
type Snapshot8 = Snapshot<OpId, u8>;

/// Deliberate design violations, used to prove the harness catches them.
#[derive(Clone, Copy, Debug, Default)]
pub struct Mutations {
    /// Writers keep writing under an old key after a membership change.
    pub stale_keys: bool,
    /// GC does not wait for every member to verify the covering snapshot.
    pub gc_without_verify: bool,
    /// Admins never forward facts to members that lack them.
    pub no_forwarding: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub genesis: u8,
    pub admins: u8,
    pub max_devices: u8,
    pub steps: u32,
    pub retention: u32,
    pub max_withheld: usize,
    pub mutations: Mutations,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            genesis: 3,
            admins: 1,
            max_devices: 5,
            steps: 120,
            retention: 3,
            max_withheld: 3,
            mutations: Mutations::default(),
        }
    }
}

type KeyId = (Device, u32);
type ObjId = u32;

#[derive(Clone, Debug)]
enum Obj {
    Fact {
        fact: Fact,
        rcpt: BTreeSet<Device>,
    },
    Forward {
        facts: BTreeSet<Fact>,
        to: Device,
    },
    Join {
        facts: BTreeSet<Fact>,
        keys: BTreeSet<KeyId>,
        to: Device,
    },
    Key {
        key: KeyId,
        rcpt: BTreeSet<Device>,
    },
    Op {
        key: KeyId,
        seq: u32,
        op: OpId,
    },
    Snap {
        key: KeyId,
        seq: u32,
        snap: Snapshot8,
    },
}

#[derive(Clone, Debug, Default)]
struct DeviceState {
    facts: BTreeSet<Fact>,
    got: BTreeSet<ObjId>,
    keys: BTreeSet<KeyId>,
    /// The writer's current key and the member set it was sent to.
    cur_key: Option<(KeyId, BTreeSet<Device>)>,
    next_key: u32,
}

pub struct Sim {
    cfg: Config,
    rng: Rng,
    genesis: BTreeSet<Device>,
    admins: BTreeSet<Device>,
    devices: BTreeMap<Device, DeviceState>,
    objs: BTreeMap<ObjId, Obj>,
    /// Objects currently in the folder (GC removes them).
    store: BTreeSet<ObjId>,
    withheld: BTreeSet<(Device, ObjId)>,
    ops: BTreeMap<OpId, Op8>,
    all_facts: BTreeSet<Fact>,
    key_seq: BTreeMap<KeyId, u32>,
    now: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub objects: usize,
    pub ops: usize,
    pub gc: usize,
    pub withheld: usize,
    pub rotations: usize,
}

impl Sim {
    pub fn new(seed: u64, cfg: Config) -> Self {
        let genesis: BTreeSet<Device> = (0..cfg.genesis).collect();
        let admins: BTreeSet<Device> = (0..cfg.admins).collect();
        let devices = genesis
            .iter()
            .map(|d| (*d, DeviceState::default()))
            .collect();
        Sim {
            cfg,
            rng: Rng::new(seed),
            genesis,
            admins,
            devices,
            objs: BTreeMap::new(),
            store: BTreeSet::new(),
            withheld: BTreeSet::new(),
            ops: BTreeMap::new(),
            all_facts: BTreeSet::new(),
            key_seq: BTreeMap::new(),
            now: 0,
        }
    }

    fn members_of(&self, d: Device) -> BTreeSet<Device> {
        membership::members(&self.genesis, &self.devices[&d].facts)
    }

    fn true_members(&self) -> BTreeSet<Device> {
        membership::members(&self.genesis, &self.all_facts)
    }

    fn publish(&mut self, by: Device, obj: Obj) -> ObjId {
        let id = self.objs.len() as ObjId;
        self.objs.insert(id, obj);
        self.store.insert(id);
        self.receive(by, id);
        id
    }

    /// Ops a device knows: ops and snapshot covers under keys it holds.
    fn known_ops(&self, d: Device) -> BTreeSet<OpId> {
        let st = &self.devices[&d];
        let mut known = BTreeSet::new();
        for id in &st.got {
            match &self.objs[id] {
                Obj::Op { key, op, .. } if st.keys.contains(key) => {
                    known.insert(*op);
                }
                Obj::Snap { key, snap, .. } if st.keys.contains(key) => {
                    known.extend(snap.covers.iter().copied())
                }
                _ => {}
            }
        }
        known
    }

    fn applied(&self, d: Device) -> BTreeSet<OpId> {
        entry::applicable(&self.known_ops(d), &self.ops)
    }

    fn receive(&mut self, d: Device, id: ObjId) {
        let obj = self.objs[&id].clone();
        let st = self.devices.get_mut(&d).expect("device exists");
        if !st.got.insert(id) {
            return; // duplicates are harmless
        }
        match obj {
            Obj::Fact { fact, rcpt } if rcpt.contains(&d) => {
                st.facts.insert(fact);
            }
            Obj::Forward { facts, to } if to == d => st.facts.extend(facts),
            Obj::Join { facts, keys, to } if to == d => {
                st.facts.extend(facts);
                st.keys.extend(keys);
            }
            Obj::Key { key, rcpt } if rcpt.contains(&d) => {
                st.keys.insert(key);
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------ actions --

    fn act_add(&mut self, a: Device) -> Result<(), String> {
        let n = self.devices.len() as Device;
        if n >= self.cfg.max_devices {
            return Ok(());
        }
        self.devices.insert(n, DeviceState::default());
        let fact = Fact::Add(n);
        self.all_facts.insert(fact);
        let mut rcpt = self.members_of(a);
        rcpt.insert(n);
        self.check_rcpt(a, &rcpt, "add fact")?;
        self.publish(a, Obj::Fact { fact, rcpt });
        let mut facts = self.devices[&a].facts.clone();
        facts.insert(fact);
        let keys = self.devices[&a].keys.clone();
        self.publish(a, Obj::Join { facts, keys, to: n });
        Ok(())
    }

    fn act_remove(&mut self, a: Device) -> Result<(), String> {
        let candidates: Vec<Device> = self
            .members_of(a)
            .into_iter()
            .filter(|d| !self.admins.contains(d))
            .collect();
        if candidates.is_empty() {
            return Ok(());
        }
        let x = candidates[self.rng.below(candidates.len())];
        let fact = match self.rng.below(3) {
            0 => Fact::Remove(x),
            1 => Fact::Expire(x),
            _ => Fact::Kill(x),
        };
        self.all_facts.insert(fact);
        let mut rcpt = self.members_of(a);
        rcpt.remove(&x);
        self.devices.get_mut(&a).expect("admin").facts.insert(fact);
        self.check_rcpt(a, &rcpt, "removal fact")?;
        self.publish(a, Obj::Fact { fact, rcpt });
        Ok(())
    }

    /// The rotation rule: a writer creates a new sender key whenever the
    /// members in its view differ from its current key's recipients.
    fn current_key(&mut self, w: Device, stats: &mut Stats) -> Result<KeyId, String> {
        let wanted = self.members_of(w);
        let st = &self.devices[&w];
        let reuse = match &st.cur_key {
            Some((k, rcpt)) if *rcpt == wanted || self.cfg.mutations.stale_keys => Some(*k),
            _ => None,
        };
        if let Some(k) = reuse {
            return Ok(k);
        }
        let st = self.devices.get_mut(&w).expect("writer");
        let key = (w, st.next_key);
        st.next_key += 1;
        st.cur_key = Some((key, wanted.clone()));
        self.check_rcpt(w, &wanted, "sender key")?;
        self.publish(w, Obj::Key { key, rcpt: wanted });
        stats.rotations += 1;
        Ok(key)
    }

    fn act_write(&mut self, w: Device, stats: &mut Stats) -> Result<(), String> {
        let key = self.current_key(w, stats)?;
        let key_rcpt = self.devices[&w]
            .cur_key
            .as_ref()
            .map(|(_, r)| r.clone())
            .unwrap_or_default();
        // Rotation-rule invariant: content never goes under a key reaching a
        // device the writer knows was removed.
        let removed = membership::removed(&self.devices[&w].facts);
        if let Some(x) = key_rcpt.intersection(&removed).next() {
            return Err(format!(
                "device {w} wrote under a key still sent to removed device {x}"
            ));
        }
        let applied = self.applied(w);
        let id = self.ops.len() as OpId;
        let kind = if self.rng.chance(25) && !applied.is_empty() {
            Kind::Delete {
                old: entry::fold(&applied, &self.ops).values,
            }
        } else {
            Kind::Set(self.rng.below(4) as u8)
        };
        self.ops.insert(
            id,
            Op {
                kind,
                deps: applied,
                time: u64::from(self.now),
            },
        );
        let seq = self.bump(key);
        self.publish(w, Obj::Op { key, seq, op: id });
        stats.ops += 1;
        Ok(())
    }

    fn act_snapshot(&mut self, w: Device, stats: &mut Stats) -> Result<(), String> {
        let applied = self.applied(w);
        if applied.is_empty() {
            return Ok(());
        }
        let key = self.current_key(w, stats)?;
        let snap = entry::snapshot(
            &applied,
            &self.ops,
            u64::from(self.now),
            u64::from(self.cfg.retention),
        );
        let seq = self.bump(key);
        self.publish(w, Obj::Snap { key, seq, snap });
        Ok(())
    }

    fn bump(&mut self, key: KeyId) -> u32 {
        let s = self.key_seq.entry(key).or_insert(0);
        *s += 1;
        *s
    }

    /// GC rules 16 and section 9: an op goes once a stored snapshot covering
    /// it has been received by every current member; a tombstone only once
    /// its window passed or a verified stored snapshot carries it.
    fn act_gc(&mut self, stats: &mut Stats) {
        let members = self.true_members();
        let verified: Vec<ObjId> = self
            .store
            .iter()
            .copied()
            .filter(|id| matches!(self.objs[id], Obj::Snap { .. }))
            // Rule 16: every current member has verified the snapshot, which
            // needs both the object and the sender key it is under.
            .filter(|id| {
                let key = match &self.objs[id] {
                    Obj::Snap { key, .. } => *key,
                    _ => unreachable!(),
                };
                self.cfg.mutations.gc_without_verify
                    || members.iter().all(|m| {
                        self.devices[m].got.contains(id) && self.devices[m].keys.contains(&key)
                    })
            })
            .collect();
        let mut drop = Vec::new();
        for id in &self.store {
            if let Obj::Op { op, .. } = &self.objs[id] {
                let covered = verified.iter().any(
                    |s| matches!(&self.objs[s], Obj::Snap { snap, .. } if snap.covers.contains(op)),
                );
                let o = &self.ops[op];
                let tomb_kept = !matches!(o.kind, Kind::Delete { .. })
                    || !entry::in_window(o, u64::from(self.now), u64::from(self.cfg.retention))
                    || verified.iter().any(|s| matches!(&self.objs[s], Obj::Snap { snap, .. } if snap.tombs.contains(op)));
                if covered && tomb_kept {
                    drop.push(*id);
                }
            }
        }
        for id in drop {
            self.store.remove(&id);
            stats.gc += 1;
        }
    }

    /// Anti-entropy: each admin sends each member the facts it lacks.
    fn act_forward(&mut self, a: Device) -> Result<(), String> {
        if self.cfg.mutations.no_forwarding {
            return Ok(());
        }
        for m in self.members_of(a) {
            let lack: BTreeSet<Fact> = self.devices[&a]
                .facts
                .difference(&self.devices[&m].facts)
                .copied()
                .collect();
            if m != a && !lack.is_empty() {
                self.publish(a, Obj::Forward { facts: lack, to: m });
            }
        }
        Ok(())
    }

    fn check_rcpt(&self, by: Device, rcpt: &BTreeSet<Device>, what: &str) -> Result<(), String> {
        let removed = membership::removed(&self.devices[&by].facts);
        match rcpt.intersection(&removed).next() {
            Some(x) => Err(format!(
                "{what} by device {by} sealed to removed device {x}"
            )),
            None => Ok(()),
        }
    }

    fn deliver_random(&mut self) {
        let d = *self
            .devices
            .keys()
            .nth(self.rng.below(self.devices.len()))
            .expect("device");
        let pending: Vec<ObjId> = self
            .store
            .iter()
            .copied()
            .filter(|id| !self.devices[&d].got.contains(id) && !self.withheld.contains(&(d, *id)))
            .collect();
        if !pending.is_empty() {
            let id = pending[self.rng.below(pending.len())];
            self.receive(d, id);
        }
    }

    // --------------------------------------------------------- invariants --

    fn check_step(&self) -> Result<(), String> {
        for (id, obj) in &self.objs {
            if let Obj::Snap { snap, .. } = obj {
                if !entry::snapshot_is_valid(snap, &self.ops) {
                    return Err(format!("snapshot {id} does not re-fold to its state"));
                }
            }
        }
        // Deletes stay recoverable for the whole retention window.
        for (id, op) in &self.ops {
            if matches!(op.kind, Kind::Delete { .. })
                && entry::in_window(op, u64::from(self.now), u64::from(self.cfg.retention))
            {
                let stored = self.store.iter().any(|object| match &self.objs[object] {
                    Obj::Op { op: o, .. } => o == id,
                    Obj::Snap { snap, .. } => snap.tombs.contains(id),
                    _ => false,
                });
                if !stored {
                    return Err(format!("tombstone {} lost inside its retention window", id));
                }
            }
        }
        Ok(())
    }

    /// Drive the run to quiescence: forward facts, deliver everything that
    /// is not withheld, and let each admin answer snapshot requests (rule 7)
    /// with a snapshot under a current key, until nothing changes.
    fn quiesce(&mut self, stats: &mut Stats) -> Result<(), String> {
        for round in 0..20 {
            if round == 2 || round == 4 {
                let admins: Vec<Device> = self
                    .admins
                    .iter()
                    .copied()
                    .filter(|a| self.true_members().contains(a))
                    .collect();
                for a in admins {
                    self.act_snapshot(a, stats)?;
                }
            }
            let admins: Vec<Device> = self
                .admins
                .iter()
                .copied()
                .filter(|a| self.true_members().contains(a))
                .collect();
            for a in admins {
                self.act_forward(a)?;
            }
            let mut changed = false;
            let devs: Vec<Device> = self.devices.keys().copied().collect();
            for d in devs {
                let pending: Vec<ObjId> = self
                    .store
                    .iter()
                    .copied()
                    .filter(|id| {
                        !self.devices[&d].got.contains(id) && !self.withheld.contains(&(d, *id))
                    })
                    .collect();
                for id in pending {
                    self.receive(d, id);
                    changed = true;
                }
            }
            if !changed && round > 4 {
                break;
            }
        }
        Ok(())
    }

    fn check_quiescent(&self) -> Result<(), String> {
        let members = self.true_members();
        // Every current member holds every fact (forwards are never withheld
        // here because they are created after the adversary stopped).
        for m in &members {
            if self.devices[m].facts != self.all_facts {
                return Err(format!("member {m} lacks facts at quiescence"));
            }
        }
        // With nothing withheld, every current member folds the same state.
        // (With withholding, availability is not guaranteed against the
        // storage adversary; what must hold then is gap detection, below.)
        if self.withheld.is_empty() {
            let folds: BTreeSet<_> = members
                .iter()
                .map(|m| format!("{:?}", entry::fold(&self.applied(*m), &self.ops)))
                .collect();
            if folds.len() > 1 {
                return Err(format!("members disagree with nothing withheld: {folds:?}"));
            }
        }
        // Gaps: for every member and every sender key it holds, each missing
        // sequence number below the highest it received must be explained:
        // either storage withheld that object from it (a true, detected gap),
        // or the op is covered by a snapshot it holds (the snapshot records
        // the sequence numbers it covers). Anything else is a false alarm.
        for m in &members {
            let st = &self.devices[m];
            let covered: BTreeSet<OpId> = st
                .got
                .iter()
                .filter_map(|g| match &self.objs[g] {
                    Obj::Snap { key, snap, .. } if st.keys.contains(key) => {
                        Some(snap.covers.clone())
                    }
                    _ => None,
                })
                .flatten()
                .collect();
            for key in &st.keys {
                let seen: BTreeSet<u32> = st
                    .got
                    .iter()
                    .filter_map(|g| match &self.objs[g] {
                        Obj::Op { key: k, seq, .. } | Obj::Snap { key: k, seq, .. } if k == key => {
                            Some(*seq)
                        }
                        _ => None,
                    })
                    .collect();
                let Some(&max) = seen.iter().max() else {
                    continue;
                };
                for s in 1..max {
                    if seen.contains(&s) {
                        continue;
                    }
                    let (id, obj) = self
                        .objs
                        .iter()
                        .find(|(_, o)| matches!(o, Obj::Op { key: k, seq, .. } | Obj::Snap { key: k, seq, .. } if k == key && *seq == s))
                        .expect("every sequence number was issued");
                    let withheld = self.withheld.contains(&(*m, *id));
                    let explained = matches!(obj, Obj::Op { op, .. } if covered.contains(op));
                    if !withheld && !explained {
                        return Err(format!(
                            "member {m} sees an unexplained gap: key {key:?} seq {s}"
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    // ---------------------------------------------------------------- run --

    pub fn run(mut self) -> Result<Stats, String> {
        let mut stats = Stats::default();
        for _ in 0..self.cfg.steps {
            let members: Vec<Device> = self.true_members().into_iter().collect();
            let admins: Vec<Device> = members
                .iter()
                .copied()
                .filter(|d| self.admins.contains(d))
                .collect();
            match self.rng.below(100) {
                0..=5 if !admins.is_empty() => {
                    let a = admins[self.rng.below(admins.len())];
                    self.act_add(a)?;
                }
                6..=11 if !admins.is_empty() => {
                    let a = admins[self.rng.below(admins.len())];
                    self.act_remove(a)?;
                }
                12..=29 => {
                    let w = members[self.rng.below(members.len())];
                    self.act_write(w, &mut stats)?;
                }
                30..=34 => {
                    let w = members[self.rng.below(members.len())];
                    self.act_snapshot(w, &mut stats)?;
                }
                35..=39 => self.act_gc(&mut stats),
                40..=44 if !admins.is_empty() => {
                    let a = admins[self.rng.below(admins.len())];
                    self.act_forward(a)?;
                }
                45..=47 if self.withheld.len() < self.cfg.max_withheld => {
                    let d = *self
                        .devices
                        .keys()
                        .nth(self.rng.below(self.devices.len()))
                        .expect("device");
                    let open: Vec<ObjId> = self
                        .store
                        .iter()
                        .copied()
                        .filter(|id| !self.devices[&d].got.contains(id))
                        .collect();
                    if !open.is_empty() {
                        let id = open[self.rng.below(open.len())];
                        self.withheld.insert((d, id));
                        stats.withheld += 1;
                    }
                }
                48..=51 => self.now += 1,
                _ => self.deliver_random(),
            }
            self.check_step()?;
        }
        self.quiesce(&mut stats)?;
        self.check_step()?;
        self.check_quiescent()?;
        stats.objects = self.objs.len();
        Ok(stats)
    }
}

/// Run one seed.
pub(crate) fn run(seed: u64, cfg: Config) -> Result<Stats, String> {
    Sim::new(seed, cfg).run()
}

#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds() -> u64 {
        std::env::var("DST_SEEDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000)
    }

    fn sweep(cfg: Config) -> Result<(usize, usize, usize), (u64, String)> {
        let (mut ops, mut gc, mut withheld) = (0, 0, 0);
        for seed in 0..seeds() {
            match run(seed, cfg) {
                Ok(s) => {
                    ops += s.ops;
                    gc += s.gc;
                    withheld += s.withheld;
                }
                Err(e) => return Err((seed, e)),
            }
        }
        Ok((ops, gc, withheld))
    }

    #[test]
    fn one_admin_default() {
        let (ops, gc, withheld) =
            sweep(Config::default()).unwrap_or_else(|(s, e)| panic!("seed {s}: {e}"));
        assert!(
            ops > 0 && gc > 0 && withheld > 0,
            "every feature exercised: ops {ops}, gc {gc}, withheld {withheld}"
        );
    }

    #[test]
    fn two_admins() {
        let cfg = Config {
            admins: 2,
            ..Config::default()
        };
        sweep(cfg).unwrap_or_else(|(s, e)| panic!("seed {s}: {e}"));
    }

    /// Each mutation must be caught on some seed, or the harness proves nothing.
    #[test]
    fn mutations_are_caught() {
        for (name, m) in [
            (
                "stale_keys",
                Mutations {
                    stale_keys: true,
                    ..Mutations::default()
                },
            ),
            (
                "gc_without_verify",
                Mutations {
                    gc_without_verify: true,
                    ..Mutations::default()
                },
            ),
            (
                "no_forwarding",
                Mutations {
                    no_forwarding: true,
                    ..Mutations::default()
                },
            ),
        ] {
            let cfg = Config {
                mutations: m,
                ..Config::default()
            };
            assert!(sweep(cfg).is_err(), "mutation {name} was not caught");
        }
    }
}
