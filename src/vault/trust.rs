//! Which vaults this device trusts, and what it last saw of each.
//!
//! Encryption alone does not say who wrote a file. Anyone who knows a public
//! key can encrypt a well formed vault to it, listing their own key as a
//! recipient as well; a device that opened such a vault and saved a new
//! password into it would hand that password over. So each device keeps a
//! record per vault of a tag made with the vault's own secret key, its
//! recipients and its generation, and opens a vault only while all three
//! still agree.
//!
//! The record file carries an HMAC made with a key derived from the identity.
//! Without the identity it cannot be forged either, which matters when the
//! whole vault directory is synchronised through a service.

// A damaged or forged record file is reported as damaged without forwarding the
// parser's own error, so map_err discards the source on purpose here.
#![allow(clippy::map_err_ignore)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Result, anyhow, ensure};
use data_encoding::{BASE64, HEXLOWER};
use serde::{Deserialize, Serialize};

use crate::vault::crypto::{self, Key};
use crate::vault::document::{Vault, now};
use crate::vault::home::{self, Home, PRIVATE, TRUST_LIMIT};

const FORMAT: &str = "txc-vault-trust";
/// The version `save` writes. `load` also reads version 1, treating it as an
/// empty decision log.
const VERSION: u32 = 2;
const TAG_LABEL: &[u8] = b"txc vault trust records v1";
/// The most decisions kept in the log, oldest dropped. Sized to stay well
/// inside `TRUST_LIMIT`.
const LOG_CAP: usize = 256;

/// How a vault compares with what this device trusted.
///
/// Non-exhaustive: more ways a vault can differ may be recognised in future,
/// so match with a wildcard arm.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Standing {
    /// Everything matches the trusted record.
    Trusted,
    /// This device has never trusted the vault.
    Unknown,
    /// A different vault sits under a name this device trusted.
    Replaced,
    /// The vault's secret key or name differ from the ones trusted: it was
    /// rebuilt by someone who could read it, or it is a forgery.
    KeyChanged,
    /// The vault is older than the version this device last opened: an old
    /// copy was put back, by accident or to undo a change.
    RolledBack {
        /// The generation this device last opened.
        seen: u64,
        /// The generation found now.
        found: u64,
    },
    /// The vault is encrypted to a different set of keys than was trusted.
    RecipientsChanged {
        /// Keys the vault is now also encrypted to.
        added: Vec<String>,
        /// Keys the vault is no longer encrypted to.
        removed: Vec<String>,
    },
    /// Another device changed the vault from the same version this device did,
    /// so the two have diverged and one set of changes would be lost.
    Diverged {
        /// The generation both devices reached from the same starting point.
        generation: u64,
    },
}

impl Standing {
    /// Explains the standing in a sentence.
    #[must_use]
    pub fn describe(&self, vault: &str) -> String {
        match self {
            Self::Trusted => format!("the vault {vault} is trusted on this device"),
            Self::Unknown => format!("the vault {vault} has not been trusted on this device yet"),
            Self::Replaced => format!(
                "the vault {vault} is not the vault this device trusted under that name; \
                 it was replaced"
            ),
            Self::KeyChanged => format!(
                "the vault {vault} no longer carries the key this device trusted; \
                 it was rebuilt or forged"
            ),
            Self::RolledBack { seen, found } => format!(
                "the vault {vault} is older than the one this device last opened \
                 (generation {found}, after {seen}); an old copy was put back"
            ),
            Self::RecipientsChanged { added, removed } => {
                let mut text = format!("the vault {vault} changed who can open it");
                if !added.is_empty() {
                    write!(text, "; added {}", added.join(", ")).ok();
                }
                if !removed.is_empty() {
                    write!(text, "; removed {}", removed.join(", ")).ok();
                }
                text
            }
            Self::Diverged { generation } => format!(
                "the vault {vault} was changed to version {generation} by another device, \
                 from the same version this one changed; the two have diverged, and trusting \
                 this copy drops the changes made here"
            ),
        }
    }
}

/// What a device remembers of a vault it trusts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    name: String,
    /// The vault's pin, in hex.
    pin: String,
    /// Sorted.
    recipients: Vec<String>,
    generation: u64,
    /// SHA-256 of the ciphertext this device last accepted, in hex. Absent in
    /// records written before this field existed; backfilled on the next open.
    #[serde(default)]
    digest: Option<String>,
}

/// One entry in the trust decision log: a vault accepted, and what it evicted.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    /// When it was accepted, RFC 3339.
    at: String,
    /// The vault's name at the time.
    vault: String,
    /// A short note on what was accepted.
    note: String,
    /// The vault id now trusted.
    id: String,
    /// The vault's fingerprint.
    fingerprint: String,
    /// The record this decision evicted, if any.
    replaced: Option<Record>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    version: u32,
    /// The records as JSON text, kept as the exact bytes the tag covers.
    records: String,
    /// The decision log as JSON text, empty in a version 1 file.
    #[serde(default)]
    log: String,
    tag: String,
}

/// The trust records and decision log, loaded and verified.
pub(crate) struct Trust {
    records: BTreeMap<String, Record>,
    log: Vec<Decision>,
    key: Key,
}

impl Trust {
    /// Reads and verifies the records, or starts empty when there are none.
    pub(crate) fn load(home: &Home, key: Key) -> Result<Self> {
        let path = home.trust_path();
        if !home::exists(&path) {
            return Ok(Self {
                records: BTreeMap::new(),
                log: Vec::new(),
                key,
            });
        }
        let bytes = home::read_private(&path, TRUST_LIMIT, PRIVATE)?;
        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| damaged(&path))?;
        ensure!(
            envelope.format == FORMAT && (envelope.version == 1 || envelope.version == 2),
            damaged(&path)
        );
        let tag = BASE64
            .decode(envelope.tag.as_bytes())
            .map_err(|_| damaged(&path))?;
        // A version 1 tag covers the records; version 2 also covers the log.
        // `crypto::mac` length-prefixes each part, so the two are unambiguous.
        let parts: &[&[u8]] = &if envelope.version >= 2 {
            vec![
                TAG_LABEL,
                envelope.records.as_bytes(),
                envelope.log.as_bytes(),
            ]
        } else {
            vec![TAG_LABEL, envelope.records.as_bytes()]
        };
        ensure!(crypto::verify(&key[..], parts, &tag), damaged(&path));
        let records = serde_json::from_str(&envelope.records).map_err(|_| damaged(&path))?;
        let log = if envelope.log.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(&envelope.log).map_err(|_| damaged(&path))?
        };
        Ok(Self { records, log, key })
    }

    /// Writes the records and log, always as version 2, with a fresh tag.
    pub(crate) fn save(&self, home: &Home) -> Result<()> {
        let records = serde_json::to_string(&self.records)?;
        let log = if self.log.is_empty() {
            String::new()
        } else {
            serde_json::to_string(&self.log)?
        };
        let tag = crypto::mac(
            &self.key[..],
            &[TAG_LABEL, records.as_bytes(), log.as_bytes()],
        );
        let envelope = Envelope {
            format: FORMAT.to_string(),
            version: VERSION,
            records,
            log,
            tag: BASE64.encode(&tag[..]),
        };
        let mut bytes = serde_json::to_vec_pretty(&envelope)?;
        bytes.push(b'\n');
        home.prepare()?;
        home::write_atomic(&home.trust_path(), &bytes, None)
    }

    /// How the vault compares with its record, given the digest of the
    /// ciphertext being judged.
    pub(crate) fn standing(&self, vault: &Vault, digest: &[u8; 32]) -> Standing {
        let Some(record) = self.records.get(vault.id()) else {
            return if self
                .records
                .values()
                .any(|record| record.name == vault.name())
            {
                Standing::Replaced
            } else {
                Standing::Unknown
            };
        };

        let pinned = HEXLOWER.decode(record.pin.as_bytes()).unwrap_or_default();
        if record.name != vault.name() || !crypto::same(&pinned, &vault.pin()[..]) {
            return Standing::KeyChanged;
        }
        if vault.generation() < record.generation {
            return Standing::RolledBack {
                seen: record.generation,
                found: vault.generation(),
            };
        }
        let recipients = sorted(vault.recipients());
        if recipients != record.recipients {
            return Standing::RecipientsChanged {
                added: recipients
                    .iter()
                    .filter(|key| !record.recipients.contains(key))
                    .cloned()
                    .collect(),
                removed: record
                    .recipients
                    .iter()
                    .filter(|key| !recipients.contains(key))
                    .cloned()
                    .collect(),
            };
        }
        // Same generation but a different ciphertext than this device accepted:
        // another device changed the vault from the same starting point, so the
        // two have diverged. Only checkable once a digest has been recorded; a
        // legacy record without one backfills on this open and is caught next
        // time.
        if let Some(pinned) = &record.digest
            && vault.generation() == record.generation
            && pinned != &HEXLOWER.encode(digest)
        {
            return Standing::Diverged {
                generation: record.generation,
            };
        }
        Standing::Trusted
    }

    /// Trusts the vault as it is now, replacing any record for it and any
    /// record of another vault under the same name, and logging the decision
    /// with whatever record it evicted.
    pub(crate) fn pin(&mut self, vault: &Vault, digest: &[u8; 32]) {
        let hex = HEXLOWER.encode(digest);
        let pin_hex = HEXLOWER.encode(&vault.pin()[..]);

        // What this decision evicts: a record of a different vault under the
        // same name is a replacement; otherwise the prior record of this same
        // vault, if the accepted copy differs from it, is a change.
        let replaced_name = self
            .records
            .iter()
            .find(|(id, record)| id.as_str() != vault.id() && record.name == vault.name())
            .map(|(_, record)| record.clone());
        let previous = self.records.get(vault.id()).cloned();
        let (replaced, note) = match (replaced_name, previous) {
            (Some(other), _) => (Some(other), "replaced another vault of the same name"),
            (None, Some(prev)) if prev.pin != pin_hex || prev.generation != vault.generation() => {
                (Some(prev), "accepted a change")
            }
            (None, Some(prev)) => (Some(prev), "re-trusted"),
            (None, None) => (None, "trusted a vault new to this device"),
        };

        self.records
            .retain(|id, record| id == vault.id() || record.name != vault.name());
        self.records.insert(
            vault.id().to_string(),
            Record {
                name: vault.name().to_string(),
                pin: pin_hex,
                recipients: sorted(vault.recipients()),
                generation: vault.generation(),
                digest: Some(hex),
            },
        );

        self.log.push(Decision {
            at: now(),
            vault: vault.name().to_string(),
            note: note.to_string(),
            id: vault.id().to_string(),
            fingerprint: vault.fingerprint(),
            replaced,
        });
        if self.log.len() > LOG_CAP {
            let excess = self.log.len().saturating_sub(LOG_CAP);
            self.log.drain(0..excess);
        }
    }

    /// Records a newer generation of a trusted vault, or backfills the digest
    /// of a record written before that field existed. Returns whether the
    /// record changed and so needs saving.
    pub(crate) fn advance(&mut self, vault: &Vault, digest: &[u8; 32]) -> bool {
        let hex = HEXLOWER.encode(digest);
        match self.records.get_mut(vault.id()) {
            Some(record)
                if record.generation < vault.generation()
                    || record.digest.as_deref() != Some(&hex) =>
            {
                // The generation guard is defensive: `open` reaches here only
                // after `standing` returned `Trusted`, which refuses a lower
                // generation.
                record.generation = record.generation.max(vault.generation());
                record.digest = Some(hex);
                true
            }
            _ => false,
        }
    }

    /// The trust decisions recorded for a vault of this name, oldest first.
    pub(crate) fn history(&self, vault: &str) -> Vec<String> {
        self.log
            .iter()
            .filter(|decision| decision.vault == vault)
            .map(|decision| {
                let mut line = format!(
                    "{}  {}  fingerprint {}",
                    decision.at, decision.note, decision.fingerprint
                );
                if let Some(prev) = &decision.replaced {
                    write!(line, "; evicted a record at generation {}", prev.generation).ok();
                }
                line
            })
            .collect()
    }

    /// Forgets a vault.
    pub(crate) fn forget(&mut self, vault: &Vault) {
        self.records.remove(vault.id());
    }
}

fn sorted(recipients: &[String]) -> Vec<String> {
    let mut sorted = recipients.to_vec();
    sorted.sort();
    sorted
}

fn damaged(path: &Path) -> anyhow::Error {
    anyhow!(
        "the trust records at {} were changed, or were written by another identity; \
         remove the file, then trust each vault again with: txc vault trust <name>",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::Identity;
    use crate::vault::home::tests::Scratch;

    fn setup() -> (Scratch, Home, Identity, Vault) {
        let scratch = Scratch::new("trust");
        let home = Home::at(&scratch.0);
        let identity = Identity::generate();
        let vault = Vault::new("work", vec![identity.to_public().to_string()]);
        (scratch, home, identity, vault)
    }

    /// A distinct ciphertext digest, standing in for one version of a vault.
    fn dig(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn a_pinned_vault_is_trusted_after_a_round_trip_through_the_file() {
        let (_scratch, home, identity, vault) = setup();
        let key = crypto::derive(&identity, "test");

        let mut trust = Trust::load(&home, key.clone()).unwrap();
        assert_eq!(trust.standing(&vault, &dig(1)), Standing::Unknown);
        trust.pin(&vault, &dig(1));
        trust.save(&home).unwrap();

        let trust = Trust::load(&home, key).unwrap();
        assert_eq!(trust.standing(&vault, &dig(1)), Standing::Trusted);
    }

    #[test]
    fn records_written_by_another_identity_or_edited_are_refused() {
        let (_scratch, home, identity, vault) = setup();
        let mut trust = Trust::load(&home, crypto::derive(&identity, "test")).unwrap();
        trust.pin(&vault, &dig(1));
        trust.save(&home).unwrap();

        let stranger = Identity::generate();
        assert!(Trust::load(&home, crypto::derive(&stranger, "test")).is_err());

        let path = home.trust_path();
        let text = std::fs::read_to_string(&path).unwrap();
        let edited = text.replacen("\\\"generation\\\":1", "\\\"generation\\\":0", 1);
        assert_ne!(text, edited, "the edit should have found its target");
        home::write_atomic(&path, edited.as_bytes(), None).unwrap();
        assert!(Trust::load(&home, crypto::derive(&identity, "test")).is_err());
    }

    #[test]
    fn a_forged_vault_under_a_trusted_name_is_not_trusted() {
        let (_scratch, home, identity, vault) = setup();
        let mut trust = Trust::load(&home, crypto::derive(&identity, "test")).unwrap();
        trust.pin(&vault, &dig(1));

        // Someone with only the public key builds a vault of the same name.
        let forged = Vault::new("work", vault.recipients().to_vec());
        assert_eq!(trust.standing(&forged, &dig(9)), Standing::Replaced);
    }

    #[test]
    fn a_rebuilt_key_an_old_copy_and_new_recipients_are_each_caught() {
        let (_scratch, home, identity, vault) = setup();
        let mut trust = Trust::load(&home, crypto::derive(&identity, "test")).unwrap();

        let mut newer = vault.clone();
        newer.advance();
        trust.pin(&newer, &dig(2));

        assert_eq!(
            trust.standing(&vault, &dig(1)),
            Standing::RolledBack { seen: 2, found: 1 }
        );

        let mut widened = newer.clone();
        let extra = Identity::generate().to_public().to_string();
        widened.set_recipients(vec![identity.to_public().to_string(), extra.clone()]);
        assert_eq!(
            trust.standing(&widened, &dig(2)),
            Standing::RecipientsChanged {
                added: vec![extra],
                removed: Vec::new()
            }
        );

        let json = String::from_utf8(newer.to_plaintext().unwrap().to_vec()).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["key"] = BASE64.encode(&[1; 32]).into();
        let rekeyed = Vault::from_plaintext(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(trust.standing(&rekeyed, &dig(2)), Standing::KeyChanged);
    }

    #[test]
    fn a_newer_generation_moves_the_record_forward() {
        let (_scratch, home, identity, mut vault) = setup();
        let mut trust = Trust::load(&home, crypto::derive(&identity, "test")).unwrap();
        trust.pin(&vault, &dig(1));
        vault.advance();
        assert_eq!(trust.standing(&vault, &dig(2)), Standing::Trusted);
        assert!(trust.advance(&vault, &dig(2)));
        assert!(!trust.advance(&vault, &dig(2)));
        vault.restore((1, String::new()));
        assert!(matches!(
            trust.standing(&vault, &dig(1)),
            Standing::RolledBack { .. }
        ));
    }

    #[test]
    fn an_equal_generation_with_another_digest_is_a_divergence() {
        let (_scratch, home, identity, vault) = setup();
        let mut trust = Trust::load(&home, crypto::derive(&identity, "test")).unwrap();
        // This device accepted one version at generation 1.
        trust.pin(&vault, &dig(1));
        // The same version reads as trusted; a different ciphertext at the same
        // generation is a divergence, not a silent overwrite.
        assert_eq!(trust.standing(&vault, &dig(1)), Standing::Trusted);
        assert_eq!(
            trust.standing(&vault, &dig(2)),
            Standing::Diverged { generation: 1 }
        );
    }

    #[test]
    fn a_record_without_a_digest_is_backfilled() {
        let (_scratch, home, identity, vault) = setup();
        let mut trust = Trust::load(&home, crypto::derive(&identity, "test")).unwrap();
        // A record as an older txc wrote it, with no digest.
        trust.records.insert(
            vault.id().to_string(),
            Record {
                name: "work".to_string(),
                pin: HEXLOWER.encode(&vault.pin()[..]),
                recipients: sorted(vault.recipients()),
                generation: 1,
                digest: None,
            },
        );
        // Without a digest it cannot diverge, so it stays trusted, and the
        // first open backfills the digest.
        assert_eq!(trust.standing(&vault, &dig(5)), Standing::Trusted);
        assert!(trust.advance(&vault, &dig(5)));
        assert!(!trust.advance(&vault, &dig(5)));
        // Now that a digest is recorded, a different one at the same generation
        // is caught.
        assert_eq!(
            trust.standing(&vault, &dig(6)),
            Standing::Diverged { generation: 1 }
        );
    }

    #[test]
    fn records_of_version_one_still_load() {
        let (_scratch, home, identity, vault) = setup();
        let key = crypto::derive(&identity, "test");

        // A version 1 file as older txc wrote it: no log field, and records
        // without the digest field.
        let records = format!(
            r#"{{"{}":{{"name":"work","pin":"{}","recipients":{},"generation":1}}}}"#,
            vault.id(),
            HEXLOWER.encode(&vault.pin()[..]),
            serde_json::to_string(&sorted(vault.recipients())).unwrap()
        );
        let tag = crypto::mac(&key[..], &[TAG_LABEL, records.as_bytes()]);
        let envelope = format!(
            r#"{{"format":"{FORMAT}","version":1,"records":{},"tag":"{}"}}"#,
            serde_json::to_string(&records).unwrap(),
            BASE64.encode(&tag[..])
        );
        home.prepare().unwrap();
        home::write_atomic(&home.trust_path(), envelope.as_bytes(), None).unwrap();

        let trust = Trust::load(&home, key.clone()).unwrap();
        assert_eq!(trust.standing(&vault, &dig(1)), Standing::Trusted);

        // Saving rewrites it as version 2.
        trust.save(&home).unwrap();
        let text = std::fs::read_to_string(home.trust_path()).unwrap();
        assert!(text.contains("\"version\": 2"), "{text}");
        assert!(Trust::load(&home, key).is_ok());
    }

    #[test]
    fn the_tag_still_refuses_a_forged_log() {
        let (_scratch, home, identity, vault) = setup();
        let key = crypto::derive(&identity, "test");
        let mut trust = Trust::load(&home, key.clone()).unwrap();
        trust.pin(&vault, &dig(1));
        trust.save(&home).unwrap();

        let path = home.trust_path();
        let text = std::fs::read_to_string(&path).unwrap();
        let edited = text.replacen(
            "trusted a vault new to this device",
            "quietly rewrote what this device accepted",
            1,
        );
        assert_ne!(text, edited, "the edit should have found the log entry");
        home::write_atomic(&path, edited.as_bytes(), None).unwrap();
        assert!(Trust::load(&home, key).is_err());
    }
}
