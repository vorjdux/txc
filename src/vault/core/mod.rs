//! The core of the new vault format, as pure data and rules: no files, no
//! cryptography, no clock.
//!
//! Every device folds the objects it can read into the same state, whatever
//! order they arrived in (study sections 7 to 9):
//!
//! - [`membership`]: who is in a vault is a set of monotone facts; removals
//!   win and merging two devices' knowledge is set union.
//! - [`fold`]: an entry field is a multi-value register over causal
//!   dependencies; snapshots carry the state and the tombstones still inside
//!   the retention window, and garbage collection follows rule 16.
//!
//! These rules were modelled in TLA+ and checked with a deterministic
//! simulation before they were written here; the same simulation runs in the
//! tests below, against this code.

pub mod fold;
pub mod membership;

#[cfg(test)]
mod sim;
