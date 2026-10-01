//! Membership as a set of monotone facts (study section 7).
//!
//! A device's member set is a pure function of the facts it holds: genesis,
//! plus adds, minus every removal, expiry and kill. A fact is never undone and
//! a device id is never reused, so merging what two devices know is set
//! union: commutative, associative and idempotent. Removals win however the
//! facts arrive, and two admins acting at once need no reconciliation.

use std::collections::BTreeSet;

/// A membership fact about one device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Fact<D> {
    /// The device joined.
    Add(D),
    /// An admin removed the device.
    Remove(D),
    /// The device's certificate expired.
    Expire(D),
    /// The device was told to wipe its keys.
    Kill(D),
}

impl<D: Copy> Fact<D> {
    /// The device the fact is about.
    pub const fn target(self) -> D {
        match self {
            Self::Add(device)
            | Self::Remove(device)
            | Self::Expire(device)
            | Self::Kill(device) => device,
        }
    }

    /// Whether the fact takes the device out.
    pub const fn takes_out(self) -> bool {
        !matches!(self, Self::Add(_))
    }
}

/// The member set a device computes from the facts it holds.
#[must_use]
pub fn members<D: Copy + Ord>(genesis: &BTreeSet<D>, facts: &BTreeSet<Fact<D>>) -> BTreeSet<D> {
    let mut members: BTreeSet<D> = genesis.clone();
    members.extend(
        facts
            .iter()
            .filter(|fact| !fact.takes_out())
            .map(|fact| fact.target()),
    );
    for gone in removed(facts) {
        members.remove(&gone);
    }
    members
}

/// Every device taken out by some fact.
#[must_use]
pub fn removed<D: Copy + Ord>(facts: &BTreeSet<Fact<D>>) -> BTreeSet<D> {
    facts
        .iter()
        .filter(|fact| fact.takes_out())
        .map(|fact| fact.target())
        .collect()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn fact() -> impl Strategy<Value = Fact<u8>> {
        (0_u8..4, 0_u8..6).prop_map(|(kind, device)| match kind {
            0 => Fact::Add(device),
            1 => Fact::Remove(device),
            2 => Fact::Expire(device),
            _ => Fact::Kill(device),
        })
    }

    fn facts() -> impl Strategy<Value = BTreeSet<Fact<u8>>> {
        proptest::collection::btree_set(fact(), 0..10)
    }

    fn genesis() -> BTreeSet<u8> {
        [0, 1, 2].into_iter().collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// Merging knowledge is set union: commutative, associative, idempotent.
        #[test]
        fn merging_is_commutative_associative_and_idempotent(a in facts(), b in facts(), c in facts()) {
            let g = genesis();
            let ab: BTreeSet<_> = a.union(&b).copied().collect();
            let ba: BTreeSet<_> = b.union(&a).copied().collect();
            prop_assert_eq!(members(&g, &ab), members(&g, &ba));
            let ab_c: BTreeSet<_> = ab.union(&c).copied().collect();
            let bc: BTreeSet<_> = b.union(&c).copied().collect();
            let a_bc: BTreeSet<_> = a.union(&bc).copied().collect();
            prop_assert_eq!(members(&g, &ab_c), members(&g, &a_bc));
            let aa: BTreeSet<_> = a.union(&a).copied().collect();
            prop_assert_eq!(members(&g, &aa), members(&g, &a));
        }

        /// Removals win, whatever else is known.
        #[test]
        fn removals_win(a in facts(), extra in facts()) {
            let all: BTreeSet<_> = a.union(&extra).copied().collect();
            let result = members(&genesis(), &all);
            for fact in &all {
                if fact.takes_out() {
                    prop_assert!(!result.contains(&fact.target()));
                }
            }
        }
    }
}
