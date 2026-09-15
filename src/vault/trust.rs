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

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Result, anyhow, ensure};
use data_encoding::{BASE64, HEXLOWER};
use serde::{Deserialize, Serialize};

use crate::vault::crypto::{self, Key};
use crate::vault::document::Vault;
use crate::vault::home::{self, Home, PRIVATE, TRUST_LIMIT};

const FORMAT: &str = "txc-vault-trust";
const VERSION: u32 = 1;
const TAG_LABEL: &[u8] = b"txc vault trust records v1";

/// How a vault compares with what this device trusted.
#[derive(Clone, Debug, PartialEq, Eq)]
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
                    let _ = write!(text, "; added {}", added.join(", "));
                }
                if !removed.is_empty() {
                    let _ = write!(text, "; removed {}", removed.join(", "));
                }
                text
            }
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
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    version: u32,
    /// The records as JSON text, kept as the exact bytes the tag covers.
    records: String,
    tag: String,
}

/// The trust records, loaded and verified.
pub(crate) struct Trust {
    records: BTreeMap<String, Record>,
    key: Key,
}

impl Trust {
    /// Reads and verifies the records, or starts empty when there are none.
    pub(crate) fn load(home: &Home, key: Key) -> Result<Self> {
        let path = home.trust_path();
        if !home::exists(&path) {
            return Ok(Self {
                records: BTreeMap::new(),
                key,
            });
        }
        let bytes = home::read_private(&path, TRUST_LIMIT, PRIVATE)?;
        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| damaged(&path))?;
        ensure!(
            envelope.format == FORMAT && envelope.version == VERSION,
            damaged(&path)
        );
        let tag = BASE64
            .decode(envelope.tag.as_bytes())
            .map_err(|_| damaged(&path))?;
        ensure!(
            crypto::verify(&key[..], &[TAG_LABEL, envelope.records.as_bytes()], &tag),
            damaged(&path)
        );
        let records = serde_json::from_str(&envelope.records).map_err(|_| damaged(&path))?;
        Ok(Self { records, key })
    }

    /// Writes the records with a fresh tag.
    pub(crate) fn save(&self, home: &Home) -> Result<()> {
        let records = serde_json::to_string(&self.records)?;
        let tag = crypto::mac(&self.key[..], &[TAG_LABEL, records.as_bytes()]);
        let envelope = Envelope {
            format: FORMAT.to_string(),
            version: VERSION,
            records,
            tag: BASE64.encode(&tag[..]),
        };
        let mut bytes = serde_json::to_vec_pretty(&envelope)?;
        bytes.push(b'\n');
        home.prepare()?;
        home::write_atomic(&home.trust_path(), &bytes, None)
    }

    /// How the vault compares with its record.
    pub(crate) fn standing(&self, vault: &Vault) -> Standing {
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
        Standing::Trusted
    }

    /// Trusts the vault as it is now, replacing any record for it and any
    /// record of another vault under the same name.
    pub(crate) fn pin(&mut self, vault: &Vault) {
        self.records
            .retain(|id, record| id == vault.id() || record.name != vault.name());
        self.records.insert(
            vault.id().to_string(),
            Record {
                name: vault.name().to_string(),
                pin: HEXLOWER.encode(&vault.pin()[..]),
                recipients: sorted(vault.recipients()),
                generation: vault.generation(),
            },
        );
    }

    /// Records a newer generation of a trusted vault. Returns whether the
    /// record changed and so needs saving.
    pub(crate) fn advance(&mut self, vault: &Vault) -> bool {
        match self.records.get_mut(vault.id()) {
            Some(record) if record.generation < vault.generation() => {
                record.generation = vault.generation();
                true
            }
            _ => false,
        }
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

    #[test]
    fn a_pinned_vault_is_trusted_after_a_round_trip_through_the_file() {
        let (_scratch, home, identity, vault) = setup();
        let key = crypto::derive(&identity, "test");

        let mut trust = Trust::load(&home, key.clone()).unwrap();
        assert_eq!(trust.standing(&vault), Standing::Unknown);
        trust.pin(&vault);
        trust.save(&home).unwrap();

        let trust = Trust::load(&home, key).unwrap();
        assert_eq!(trust.standing(&vault), Standing::Trusted);
    }

    #[test]
    fn records_written_by_another_identity_or_edited_are_refused() {
        let (_scratch, home, identity, vault) = setup();
        let mut trust = Trust::load(&home, crypto::derive(&identity, "test")).unwrap();
        trust.pin(&vault);
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
        trust.pin(&vault);

        // Someone with only the public key builds a vault of the same name.
        let forged = Vault::new("work", vault.recipients().to_vec());
        assert_eq!(trust.standing(&forged), Standing::Replaced);
    }

    #[test]
    fn a_rebuilt_key_an_old_copy_and_new_recipients_are_each_caught() {
        let (_scratch, home, identity, vault) = setup();
        let mut trust = Trust::load(&home, crypto::derive(&identity, "test")).unwrap();

        let mut newer = vault.clone();
        newer.advance();
        trust.pin(&newer);

        assert_eq!(
            trust.standing(&vault),
            Standing::RolledBack { seen: 2, found: 1 }
        );

        let mut widened = newer.clone();
        let extra = Identity::generate().to_public().to_string();
        widened.set_recipients(vec![identity.to_public().to_string(), extra.clone()]);
        assert_eq!(
            trust.standing(&widened),
            Standing::RecipientsChanged {
                added: vec![extra],
                removed: Vec::new()
            }
        );

        let json = String::from_utf8(newer.to_plaintext().unwrap().to_vec()).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["key"] = BASE64.encode(&[1; 32]).into();
        let rekeyed = Vault::from_plaintext(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(trust.standing(&rekeyed), Standing::KeyChanged);
    }

    #[test]
    fn a_newer_generation_moves_the_record_forward() {
        let (_scratch, home, identity, mut vault) = setup();
        let mut trust = Trust::load(&home, crypto::derive(&identity, "test")).unwrap();
        trust.pin(&vault);
        vault.advance();
        assert_eq!(trust.standing(&vault), Standing::Trusted);
        assert!(trust.advance(&vault));
        assert!(!trust.advance(&vault));
        vault.restore((1, String::new()));
        assert!(matches!(
            trust.standing(&vault),
            Standing::RolledBack { .. }
        ));
    }
}
