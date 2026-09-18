//! The entries used most recently on this device.
//!
//! The list is kept apart from the vaults, so copying a secret never
//! rewrites a vault or sends it through a sync again, and it stays on this
//! device. What you use is private too, so the list is an age file encrypted
//! to your own key. Nothing in it is trusted: an item is shown only while a
//! vault this device trusts still holds an entry by that name.

// A damaged list is reported as damaged without forwarding the parser's own
// error, so map_err discards the source on purpose here.
#![allow(clippy::map_err_ignore)]

use std::path::PathBuf;

use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::vault::crypto::{self, Identity};
use crate::vault::document::now;
use crate::vault::home::{self, Home, PRIVATE};
use crate::vault::model::{check_entry_name, check_plain_value, check_vault_name};

/// How many recently used entries are remembered.
pub const MAX_RECENT: usize = 20;

const FILE: &str = "recent.age";
const LIMIT: usize = 1024 * 1024;
const FORMAT: &str = "txc-vault-recent";
const VERSION: u32 = 1;

/// One use of an entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Use {
    /// The vault's name.
    pub vault: String,
    /// The entry's name.
    pub entry: String,
    /// When it was used, as RFC 3339.
    pub at: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    format: String,
    version: u32,
    uses: Vec<Use>,
}

fn path(home: &Home) -> PathBuf {
    home.root().join(FILE)
}

/// Reads the list, newest first. A missing file is an empty list.
pub(crate) fn load(home: &Home, identity: &Identity) -> Result<Vec<Use>> {
    let path = path(home);
    if !home::exists(&path) {
        return Ok(Vec::new());
    }
    let damaged = || anyhow!("the list of recently used entries is damaged");
    let ciphertext = home::read_private(&path, LIMIT, PRIVATE)?;
    let plaintext = crypto::decrypt(identity, &ciphertext, LIMIT).map_err(|_| damaged())?;
    let stored: Stored = serde_json::from_slice(&plaintext).map_err(|_| damaged())?;
    ensure!(
        stored.format == FORMAT && stored.version == VERSION,
        damaged()
    );
    Ok(stored
        .uses
        .into_iter()
        .filter(|found| {
            check_vault_name(&found.vault).is_ok()
                && check_entry_name(&found.entry).is_ok()
                && check_plain_value("at", &found.at).is_ok()
        })
        .take(MAX_RECENT)
        .collect())
}

/// Changes the list and writes it back. A list that cannot be read is
/// started again rather than blocking the change.
pub(crate) fn update(
    home: &Home,
    identity: &Identity,
    change: impl FnOnce(&mut Vec<Use>),
) -> Result<()> {
    let mut uses = load(home, identity).unwrap_or_default();
    change(&mut uses);
    uses.truncate(MAX_RECENT);

    let stored = Stored {
        format: FORMAT.to_string(),
        version: VERSION,
        uses,
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&stored)?);
    let ciphertext = crypto::encrypt(&[identity.to_public()], &plaintext)?;
    home.prepare()?;
    home::write_atomic(&path(home), &ciphertext, None)
}

/// How long ago something happened, in words: "just now", "5 min ago",
/// "3 h ago", "yesterday", "12 days ago". Text that is not a time gives an
/// empty string.
#[must_use]
pub fn ago(at: &str) -> String {
    ago_from(at, chrono::Utc::now())
}

fn ago_from(at: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    let Ok(then) = chrono::DateTime::parse_from_rfc3339(at) else {
        return String::new();
    };
    // Both sides are real RFC 3339 timestamps, so the difference is far from
    // the range where chrono's subtraction would overflow.
    #[allow(clippy::arithmetic_side_effects)]
    let seconds = (now - then.with_timezone(&chrono::Utc))
        .num_seconds()
        .max(0);
    match seconds {
        0..=59 => "just now".to_string(),
        60..=3_599 => format!("{} min ago", seconds / 60),
        3_600..=86_399 => format!("{} h ago", seconds / 3_600),
        86_400..=172_799 => "yesterday".to_string(),
        _ => format!("{} days ago", seconds / 86_400),
    }
}

/// Moves an entry to the front of the list.
pub(crate) fn record(uses: &mut Vec<Use>, vault: &str, entry: &str) {
    uses.retain(|found| !(found.vault == vault && found.entry == entry));
    uses.insert(
        0,
        Use {
            vault: vault.to_string(),
            entry: entry.to_string(),
            at: now(),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::home::tests::Scratch;

    #[test]
    fn uses_come_back_newest_first_without_repeats_and_capped() {
        let scratch = Scratch::new("recent");
        let home = Home::at(&scratch.0);
        let identity = Identity::generate();

        for index in 0..MAX_RECENT + 5 {
            update(&home, &identity, |uses| {
                record(uses, "personal", &format!("entry {index}"));
            })
            .unwrap();
        }
        update(&home, &identity, |uses| record(uses, "personal", "entry 3")).unwrap();

        let uses = load(&home, &identity).unwrap();
        assert_eq!(uses.len(), MAX_RECENT);
        assert_eq!(uses[0].entry, "entry 3");
        assert_eq!(
            uses.iter().filter(|found| found.entry == "entry 3").count(),
            1
        );
    }

    #[test]
    fn the_list_is_encrypted_and_only_this_identity_reads_it() {
        let scratch = Scratch::new("recent-private");
        let home = Home::at(&scratch.0);
        let identity = Identity::generate();
        update(&home, &identity, |uses| {
            record(uses, "personal", "my-bank-login");
        })
        .unwrap();

        let bytes = std::fs::read(path(&home)).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("my-bank-login"));
        assert!(load(&home, &Identity::generate()).is_err());
    }

    #[test]
    fn times_are_told_in_words() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-15T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for (at, words) in [
            ("2026-09-15T11:59:30Z", "just now"),
            ("2026-09-15T11:55:00Z", "5 min ago"),
            ("2026-09-15T09:00:00Z", "3 h ago"),
            ("2026-09-14T10:00:00Z", "yesterday"),
            ("2026-09-03T12:00:00Z", "12 days ago"),
            ("2026-09-15T12:05:00Z", "just now"),
            ("not a time", ""),
        ] {
            assert_eq!(ago_from(at, now), words, "{at}");
        }
    }

    #[test]
    fn a_missing_list_is_empty_and_a_damaged_one_is_started_again() {
        let scratch = Scratch::new("recent-damaged");
        let home = Home::at(&scratch.0);
        let identity = Identity::generate();
        assert!(load(&home, &identity).unwrap().is_empty());

        home.prepare().unwrap();
        home::write_atomic(&path(&home), b"not an age file", None).unwrap();
        assert!(load(&home, &identity).is_err());
        update(&home, &identity, |uses| record(uses, "personal", "fresh")).unwrap();
        assert_eq!(load(&home, &identity).unwrap().len(), 1);
    }
}
