//! The entry fold: a field as a multi-value register (study sections 8 and 9).
//!
//! Causality comes only from each op's `deps`, which are the writer's whole
//! applied history. The live ops are those no other op depends on. Concurrent
//! sets keep every value and flag a conflict, and a delete concurrent with a
//! set is a conflict too. A delete is a tombstone holding the values it
//! removed. Snapshots carry the folded state and the tombstones still inside
//! the retention window, and are accepted only when they re-fold (rule 13).

use std::collections::{BTreeMap, BTreeSet};

/// What an op does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind<V> {
    /// Sets the field to a value.
    Set(V),
    /// A tombstone, with the values that were live when it was written.
    Delete {
        /// The values it removed.
        old: BTreeSet<V>,
    },
}

/// One op on a field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op<K, V> {
    /// What it does.
    pub kind: Kind<V>,
    /// Every op its writer had applied.
    pub deps: BTreeSet<K>,
    /// When it was written, for the retention window only; the fold never
    /// reads it.
    pub time: u64,
}

/// A field's folded state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State<V> {
    /// The live values: one, or several when concurrent sets conflict.
    pub values: BTreeSet<V>,
    /// Whether a live delete removed the field.
    pub deleted: bool,
    /// Whether more than one op is live, so a person must choose.
    pub conflict: bool,
}

/// The ops a device can apply: an op whose dependencies have not all arrived
/// is held as pending (rule 7).
#[must_use]
pub fn applicable<K: Ord + Clone, V>(
    known: &BTreeSet<K>,
    ops: &BTreeMap<K, Op<K, V>>,
) -> BTreeSet<K> {
    known
        .iter()
        .filter(|id| {
            ops.get(*id)
                .is_some_and(|op| op.deps.iter().all(|dep| known.contains(dep)))
        })
        .cloned()
        .collect()
}

/// The multi-value register over a causally closed set of ops.
#[must_use]
pub fn fold<K: Ord + Clone, V: Ord + Clone>(
    set: &BTreeSet<K>,
    ops: &BTreeMap<K, Op<K, V>>,
) -> State<V> {
    let dominated: BTreeSet<&K> = set
        .iter()
        .filter_map(|id| ops.get(id))
        .flat_map(|op| op.deps.iter())
        .collect();
    let live: Vec<&Op<K, V>> = set
        .iter()
        .filter(|id| !dominated.contains(id))
        .filter_map(|id| ops.get(id))
        .collect();
    let mut state = State {
        values: BTreeSet::new(),
        deleted: false,
        conflict: live.len() > 1,
    };
    for op in live {
        match &op.kind {
            Kind::Set(value) => {
                state.values.insert(value.clone());
            }
            Kind::Delete { .. } => state.deleted = true,
        }
    }
    state
}

/// A snapshot: what it covers, the folded state, and the tombstones still
/// inside the retention window when it was made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot<K, V> {
    /// The ops it covers, causally closed.
    pub covers: BTreeSet<K>,
    /// The fold of those ops.
    pub state: State<V>,
    /// The tombstones it carries.
    pub tombs: BTreeSet<K>,
}

/// Whether an op is still inside the retention window.
#[must_use]
pub const fn in_window<K, V>(op: &Op<K, V>, now: u64, retention: u64) -> bool {
    now.saturating_sub(op.time) < retention
}

/// Makes a snapshot of what a device has applied.
#[must_use]
pub fn snapshot<K: Ord + Clone, V: Ord + Clone>(
    applied: &BTreeSet<K>,
    ops: &BTreeMap<K, Op<K, V>>,
    now: u64,
    retention: u64,
) -> Snapshot<K, V> {
    Snapshot {
        covers: applied.clone(),
        state: fold(applied, ops),
        tombs: applied
            .iter()
            .filter(|id| {
                ops.get(*id).is_some_and(|op| {
                    matches!(op.kind, Kind::Delete { .. }) && in_window(op, now, retention)
                })
            })
            .cloned()
            .collect(),
    }
}

/// The re-fold check of rule 13: a snapshot is accepted only when what it
/// covers is causally closed and its state is the fold of it.
#[must_use]
pub fn snapshot_is_valid<K: Ord + Clone, V: Ord + Clone>(
    snapshot: &Snapshot<K, V>,
    ops: &BTreeMap<K, Op<K, V>>,
) -> bool {
    snapshot.covers.iter().all(|id| {
        ops.get(id)
            .is_some_and(|op| op.deps.is_subset(&snapshot.covers))
    }) && snapshot.state == fold(&snapshot.covers, ops)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::vault::core::sim::Rng;

    type History = BTreeMap<u32, Op<u32, u8>>;

    /// A causal history: each op depends on an earlier op and all it knew.
    fn history() -> impl Strategy<Value = History> {
        proptest::collection::vec((any::<u8>(), 0_u8..4, any::<bool>()), 1..9).prop_map(|spec| {
            let mut ops = History::new();
            for (id, (pick, value, delete)) in (0_u32..).zip(spec) {
                let deps = if id == 0 || pick % 3 == 0 {
                    BTreeSet::new()
                } else {
                    let base = u32::from(pick) % id;
                    let mut deps = ops[&base].deps.clone();
                    deps.insert(base);
                    deps
                };
                let kind = if delete {
                    Kind::Delete {
                        old: fold(&deps, &ops).values,
                    }
                } else {
                    Kind::Set(value)
                };
                ops.insert(
                    id,
                    Op {
                        kind,
                        deps,
                        time: u64::from(id),
                    },
                );
            }
            ops
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// Delivering ops in any order, holding pending ones, ends in the
        /// fold of the whole history, and what is applied is always closed.
        #[test]
        fn the_fold_ignores_arrival_order(ops in history(), seed in any::<u64>()) {
            let mut order: Vec<u32> = ops.keys().copied().collect();
            let mut rng = Rng::new(seed);
            for i in (1..order.len()).rev() {
                order.swap(i, rng.below(i + 1));
            }
            let mut known = BTreeSet::new();
            for id in order {
                known.insert(id);
                let applied = applicable(&known, &ops);
                for id in &applied {
                    prop_assert!(ops[id].deps.is_subset(&applied));
                }
            }
            let all: BTreeSet<u32> = ops.keys().copied().collect();
            prop_assert_eq!(applicable(&known, &ops), all.clone());
            prop_assert_eq!(fold(&known, &ops), fold(&all, &ops));
        }

        /// A snapshot plus the ops after it fold as the whole history does.
        #[test]
        fn a_snapshot_stands_in_for_the_history_it_covers(ops in history(), cut in any::<u8>()) {
            let all: BTreeSet<u32> = ops.keys().copied().collect();
            let pivot = u32::from(cut) % u32::try_from(all.len()).unwrap();
            let mut covered = ops[&pivot].deps.clone();
            covered.insert(pivot);
            let snap = snapshot(&covered, &ops, 0, 1);
            prop_assert!(snapshot_is_valid(&snap, &ops));
            let rest: BTreeSet<u32> = all.difference(&covered).copied().collect();
            let merged: BTreeSet<u32> = snap.covers.union(&rest).copied().collect();
            prop_assert_eq!(fold(&merged, &ops), fold(&all, &ops));
        }

        /// A tombstone holds exactly the values it removed.
        #[test]
        fn tombstones_hold_the_values_they_removed(ops in history()) {
            for op in ops.values() {
                if let Kind::Delete { old } = &op.kind {
                    prop_assert_eq!(old.clone(), fold(&op.deps, &ops).values);
                }
            }
        }
    }

    /// Writers that record only their frontier, the live ops they saw, as
    /// an op's deps: what txc writes, since the full history would grow
    /// without bound.
    fn frontier_history(spec: &[(u8, u8, bool)]) -> (History, History) {
        let mut full = History::new();
        let mut frontier = History::new();
        for (id, (pick, value, delete)) in (0_u32..).zip(spec) {
            // The writer has seen a causally closed prefix of the history.
            let seen: BTreeSet<u32> = if id == 0 || pick % 3 == 0 {
                BTreeSet::new()
            } else {
                let base = u32::from(*pick) % id;
                let mut seen = full[&base].deps.clone();
                seen.insert(base);
                seen
            };
            let dominated: BTreeSet<u32> = seen
                .iter()
                .flat_map(|op| full[op].deps.iter().copied())
                .collect();
            let live: BTreeSet<u32> = seen.difference(&dominated).copied().collect();
            let kind = |ops: &History| {
                if *delete {
                    Kind::Delete {
                        old: fold(&seen, ops).values,
                    }
                } else {
                    Kind::Set(*value)
                }
            };
            let time = u64::from(id);
            full.insert(
                id,
                Op {
                    kind: kind(&full),
                    deps: seen.clone(),
                    time,
                },
            );
            frontier.insert(
                id,
                Op {
                    kind: kind(&full),
                    deps: live,
                    time,
                },
            );
        }
        (full, frontier)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// Frontier deps fold exactly as full-history deps do, for every
        /// causally closed set a device can hold.
        #[test]
        fn frontier_deps_fold_as_full_history(spec in proptest::collection::vec((any::<u8>(), 0_u8..4, any::<bool>()), 1..12), cut in any::<u8>()) {
            let (full, frontier) = frontier_history(&spec);
            let all: BTreeSet<u32> = full.keys().copied().collect();
            prop_assert_eq!(fold(&all, &full), fold(&all, &frontier));
            let pivot = u32::from(cut) % u32::try_from(all.len()).unwrap();
            let mut closed = full[&pivot].deps.clone();
            closed.insert(pivot);
            prop_assert_eq!(fold(&closed, &full), fold(&closed, &frontier));
        }
    }

    #[test]
    fn a_snapshot_whose_state_was_changed_is_refused() {
        let mut ops = History::new();
        ops.insert(
            0,
            Op {
                kind: Kind::Set(1),
                deps: BTreeSet::new(),
                time: 0,
            },
        );
        let mut snap = snapshot(&[0].into_iter().collect(), &ops, 0, 1);
        assert!(snapshot_is_valid(&snap, &ops));
        snap.state.values.insert(9);
        assert!(!snapshot_is_valid(&snap, &ops));
    }
}
