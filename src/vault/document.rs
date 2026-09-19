//! What a vault file decrypts to: who can open it, its own key, and its
//! entries.

// A damaged vault is reported as damaged without leaking the parser's own
// error, so map_err discards the source on purpose here.
#![allow(clippy::map_err_ignore)]

use std::collections::HashSet;
use std::fmt;

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Result, anyhow, ensure};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::vault::crypto::{self, Key, Recipient, WriteKey, WriterId};
use crate::vault::model::{
    Entry, MAX_ENTRIES, MAX_SECRET_BYTES, check_plain_value, check_vault_name,
};

const FORMAT: &str = "txc-vault";
/// The current on-disk version. Version 1 (v0.6.0 and earlier) carries no
/// writer or signature; version 2 is signed by a write key. This release reads
/// both and writes only version 2.
const VERSION: u32 = 2;
const PIN_LABEL: &[u8] = b"txc vault pin v1";

/// The most recipients a vault may be encrypted to.
pub const MAX_RECIPIENTS: usize = 64;

/// A decrypted vault.
///
/// Its secrets are still sealed: holding a `Vault` in memory does not mean
/// holding any password, only the names, kinds and plain fields of its
/// entries.
#[derive(Clone)]
pub struct Vault {
    id: String,
    name: String,
    /// The format version this vault was read as. A vault read as version 1
    /// carries no signature and is upgraded to version 2 on the next write.
    version: u32,
    generation: u64,
    /// Known only to those who can decrypt the vault. The trust record pins
    /// a tag made with it, which nobody holding just the public keys can
    /// reproduce, so a vault forged from the public keys alone is told apart.
    key: Key,
    recipients: Vec<String>,
    created: String,
    updated: String,
    pub(crate) entries: Vec<Entry>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("name", &self.name)
            .field("generation", &self.generation)
            .field("recipients", &self.recipients)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// The stored form, as read. The key is wiped when this is dropped.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    format: String,
    version: u32,
    id: String,
    name: String,
    generation: u64,
    key: String,
    recipients: Vec<String>,
    created: String,
    updated: String,
    entries: Vec<Entry>,
    /// The writer's Ed25519 public key, base64. Absent in version 1.
    #[serde(default)]
    writer: String,
    /// Ed25519 over the canonical bytes of this record with `signature` empty.
    /// Absent in version 1.
    #[serde(default)]
    signature: String,
}

impl Drop for Stored {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// The stored form, as written, borrowing rather than copying the entries.
#[derive(Serialize)]
struct StoredRef<'a> {
    format: &'a str,
    version: u32,
    id: &'a str,
    name: &'a str,
    generation: u64,
    key: &'a str,
    recipients: &'a [String],
    created: &'a str,
    updated: &'a str,
    entries: &'a [Entry],
    writer: &'a str,
    signature: &'a str,
}

impl Vault {
    /// A new, empty vault.
    pub(crate) fn new(name: &str, recipients: Vec<String>) -> Self {
        let now = now();
        Self {
            id: uuid::Uuid::new_v4().simple().to_string(),
            name: name.to_string(),
            version: VERSION,
            generation: 1,
            key: crypto::random_key(),
            recipients,
            created: now.clone(),
            updated: now,
            entries: Vec::new(),
        }
    }

    /// Reads a decrypted vault, checking every part of it, and for a version 2
    /// vault verifying its signature against a pinned writer.
    ///
    /// The signature check happens here, where there is no trust record to
    /// consult and no flag to pass: a version 2 vault whose signature does not
    /// verify against a pinned writer is not a vault, and no later decision can
    /// rescue it. `writers` is the set this device has pinned.
    pub(crate) fn from_plaintext(plaintext: &[u8], writers: &[WriterId]) -> Result<Self> {
        let mut stored: Stored = serde_json::from_slice(plaintext).map_err(|_| {
            anyhow!("the vault's contents are not in a form this version of txc reads")
        })?;
        ensure!(stored.format == FORMAT, "this is not a txc vault");
        ensure!(
            stored.version == 1 || stored.version == VERSION,
            "the vault was written in format {}, which this version of txc does not read; upgrade txc",
            stored.version
        );
        ensure!(
            stored.id.len() == 32
                && stored
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "the vault's identifier is damaged"
        );
        check_vault_name(&stored.name)?;
        ensure!(stored.generation >= 1, "the vault's generation is damaged");

        let decoded = Zeroizing::new(
            BASE64
                .decode(stored.key.as_bytes())
                .map_err(|_| anyhow!("the vault's key is damaged"))?,
        );
        ensure!(decoded.len() == 32, "the vault's key is damaged");
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&decoded);

        ensure!(
            (1..=MAX_RECIPIENTS).contains(&stored.recipients.len()),
            "a vault is encrypted to between 1 and {MAX_RECIPIENTS} public keys"
        );
        let mut seen = HashSet::new();
        for recipient in &stored.recipients {
            crypto::parse_recipient(recipient)?;
            ensure!(
                seen.insert(recipient.as_str()),
                "the vault lists {recipient} twice"
            );
        }

        ensure!(
            stored.entries.len() <= MAX_ENTRIES,
            "the vault holds more than {MAX_ENTRIES} entries"
        );
        let mut names = HashSet::new();
        for entry in &stored.entries {
            entry.validate()?;
            ensure!(
                names.insert(entry.name.to_lowercase()),
                "the vault holds two entries named {:?}",
                entry.name
            );
        }
        check_plain_value("created", &stored.created)?;
        check_plain_value("updated", &stored.updated)?;

        // The signature check for a version 2 vault. A version 1 vault carries
        // no signature and falls back to the trust layer alone, until the next
        // write upgrades it; this release still reads it.
        if stored.version == VERSION {
            ensure!(
                !stored.writer.is_empty() && !stored.signature.is_empty(),
                "the vault {} is missing its signature",
                stored.name
            );
            let writer = crypto::parse_writer_id(&stored.writer)?;
            ensure!(
                writers.iter().any(|pinned| pinned == &writer),
                "the vault {} was written by a key this device does not know; \
                 pin it with: txc vault writers --add",
                stored.name
            );
            let signature = decode_signature(&stored.signature)?;
            let canonical = canonical_bytes(&stored)?;
            ensure!(
                crypto::verify_signature(&writer, &canonical, &signature),
                "the vault {} was changed by something that does not hold its write key",
                stored.name
            );
        }

        Ok(Self {
            id: std::mem::take(&mut stored.id),
            name: std::mem::take(&mut stored.name),
            version: stored.version,
            generation: stored.generation,
            key,
            recipients: std::mem::take(&mut stored.recipients),
            created: std::mem::take(&mut stored.created),
            updated: std::mem::take(&mut stored.updated),
            entries: std::mem::take(&mut stored.entries),
        })
    }

    /// Whether this vault was read in an older format and will be upgraded to
    /// the current one on the next write.
    #[must_use]
    pub(crate) const fn needs_upgrade(&self) -> bool {
        self.version < VERSION
    }

    /// Serialises the vault as version 2, signed by `write_key`. The result
    /// holds the vault's key, so it is wiped when dropped.
    ///
    /// The signature covers every field of the record, `writer` and `version`
    /// included, with `signature` itself empty. Verification in
    /// [`from_plaintext`](Self::from_plaintext) reconstructs exactly these
    /// bytes, so the two sides cannot drift within a version.
    pub(crate) fn to_plaintext(&self, write_key: &WriteKey) -> Result<Zeroizing<Vec<u8>>> {
        let key = Zeroizing::new(BASE64.encode(&self.key[..]));
        let writer = crypto::writer_id_string(&crypto::writer_id(write_key));
        let mut stored = StoredRef {
            format: FORMAT,
            version: VERSION,
            id: &self.id,
            name: &self.name,
            generation: self.generation,
            key: &key,
            recipients: &self.recipients,
            created: &self.created,
            updated: &self.updated,
            entries: &self.entries,
            writer: &writer,
            signature: "",
        };
        let canonical = serde_json::to_vec(&stored)?;
        let signature = BASE64.encode(&crypto::sign(write_key, &canonical));
        stored.signature = &signature;
        Ok(Zeroizing::new(serde_json::to_vec(&stored)?))
    }

    /// Encrypts the whole vault to its recipients, signed by `write_key`.
    pub(crate) fn seal(&self, write_key: &WriteKey) -> Result<Vec<u8>> {
        crypto::encrypt(&self.recipient_keys()?, &self.to_plaintext(write_key)?)
    }

    /// Encrypts one secret on its own, to the vault's recipients.
    pub(crate) fn seal_secret(&self, secret: &SecretString) -> Result<String> {
        seal_to(&self.recipient_keys()?, secret)
    }

    /// The recipients, parsed.
    pub(crate) fn recipient_keys(&self) -> Result<Vec<Recipient>> {
        self.recipients
            .iter()
            .map(|recipient| crypto::parse_recipient(recipient))
            .collect()
    }

    /// A tag binding the vault's secret key to its identifier and name, which
    /// is what a device pins when it trusts the vault.
    pub(crate) fn pin(&self) -> Key {
        crypto::mac(
            &self.key[..],
            &[PIN_LABEL, self.id.as_bytes(), self.name.as_bytes()],
        )
    }

    /// A short, stable, public name for the vault's identity, for reading out
    /// to another device to confirm it is the same vault.
    ///
    /// Safe to print anywhere: it is a one way tag of the vault's key (through
    /// its `pin`), so it reveals nothing and cannot be reproduced by anyone who
    /// cannot already decrypt the vault. This is the security property of an
    /// SSH host key fingerprint.
    ///
    /// Two things about it surprise people, so both are said plainly: it is the
    /// **same** across generations, recipient changes and entry edits, and it
    /// **changes** if the vault is renamed, because the name is inside the pin.
    ///
    /// The value is 120 bits of the pin, as six hyphen separated groups of four
    /// lowercase base32 characters, for example `k7fq-2mxv-8d3n-wpls-a4rt-9cez`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        crypto::fingerprint(&self.pin()[..])
    }

    /// Marks the vault as changed: one generation on, at the current time.
    /// Returns what it was, to put back if saving fails.
    pub(crate) fn advance(&mut self) -> (u64, String) {
        let before = (self.generation, self.updated.clone());
        self.generation = self.generation.saturating_add(1);
        self.updated = now();
        before
    }

    /// Undoes [`advance`](Self::advance).
    pub(crate) fn restore(&mut self, (generation, updated): (u64, String)) {
        self.generation = generation;
        self.updated = updated;
    }

    /// Replaces the recipients. The caller re-seals the secrets first.
    pub(crate) fn set_recipients(&mut self, recipients: Vec<String>) {
        self.recipients = recipients;
    }

    /// A random identifier that stays with the vault for its whole life.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The vault's name, which matches its file name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// How many times the vault has been saved. It only ever goes up, which
    /// is how an old copy put back in its place is noticed.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The age public keys the vault is encrypted to.
    #[must_use]
    pub fn recipients(&self) -> &[String] {
        &self.recipients
    }

    /// When the vault was created, as RFC 3339.
    #[must_use]
    pub fn created(&self) -> &str {
        &self.created
    }

    /// When the vault was last saved, as RFC 3339.
    #[must_use]
    pub fn updated(&self) -> &str {
        &self.updated
    }

    /// The entries, sorted by name.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The entry with this name. An exact match wins; failing that, a match
    /// ignoring case, which is unambiguous because names are unique that way.
    #[must_use]
    pub fn entry(&self, name: &str) -> Option<&Entry> {
        self.entry_index(name)
            .and_then(|index| self.entries.get(index))
    }

    pub(crate) fn entry_index(&self, name: &str) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.name == name)
            .or_else(|| {
                let lower = name.to_lowercase();
                self.entries
                    .iter()
                    .position(|entry| entry.name.to_lowercase() == lower)
            })
    }

    /// Whether another entry already has this name, ignoring case.
    pub(crate) fn name_taken(&self, name: &str, except: Option<usize>) -> bool {
        let lower = name.to_lowercase();
        self.entries
            .iter()
            .enumerate()
            .any(|(index, entry)| Some(index) != except && entry.name.to_lowercase() == lower)
    }

    /// Keeps the entries in name order.
    pub(crate) fn sort(&mut self) {
        self.entries.sort_by_key(|entry| entry.name.to_lowercase());
    }
}

/// Encrypts one secret on its own to these recipients, as base64.
pub(crate) fn seal_to(recipients: &[Recipient], secret: &SecretString) -> Result<String> {
    let bytes = secret.expose_secret().as_bytes();
    ensure!(!bytes.is_empty(), "a secret cannot be empty");
    ensure!(
        bytes.len() <= MAX_SECRET_BYTES,
        "a secret cannot be larger than {} KiB",
        MAX_SECRET_BYTES / 1024
    );
    Ok(BASE64.encode(&crypto::encrypt(recipients, bytes)?))
}

/// The bytes a version 2 signature covers: the record serialised with
/// `signature` empty. Built from a parsed [`Stored`] so verification
/// reconstructs exactly what [`Vault::to_plaintext`] signed.
fn canonical_bytes(stored: &Stored) -> Result<Vec<u8>> {
    let stored_ref = StoredRef {
        format: &stored.format,
        version: stored.version,
        id: &stored.id,
        name: &stored.name,
        generation: stored.generation,
        key: &stored.key,
        recipients: &stored.recipients,
        created: &stored.created,
        updated: &stored.updated,
        entries: &stored.entries,
        writer: &stored.writer,
        signature: "",
    };
    Ok(serde_json::to_vec(&stored_ref)?)
}

/// Decodes a base64 Ed25519 signature.
fn decode_signature(text: &str) -> Result<[u8; 64]> {
    let bytes = BASE64
        .decode(text.as_bytes())
        .map_err(|_| anyhow!("the vault's signature is damaged"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("the vault's signature is damaged"))
}

/// The current time, as RFC 3339 to the second.
pub(crate) fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::Identity;

    fn vault() -> (Identity, Vault, WriteKey) {
        let identity = Identity::generate();
        let vault = Vault::new("work", vec![identity.to_public().to_string()]);
        (identity, vault, crypto::new_write_key())
    }

    /// The pinned-writers slice for a write key, for `from_plaintext`.
    fn pinned(write_key: &WriteKey) -> Vec<WriterId> {
        vec![crypto::writer_id(write_key)]
    }

    #[test]
    fn a_vault_survives_being_written_and_read() {
        let (identity, vault, write_key) = vault();
        let ciphertext = vault.seal(&write_key).unwrap();
        let plaintext = crypto::decrypt(&identity, &ciphertext, 1 << 20).unwrap();
        let read = Vault::from_plaintext(&plaintext, &pinned(&write_key)).unwrap();

        assert_eq!(read.id(), vault.id());
        assert_eq!(read.name(), "work");
        assert_eq!(read.generation(), 1);
        assert_eq!(*read.pin(), *vault.pin());
    }

    #[test]
    fn the_plaintext_holds_no_secret_in_the_clear() {
        let (_, vault, write_key) = vault();
        let sealed = vault
            .seal_secret(&"hunter2-very-secret".to_string().into())
            .unwrap();
        let mut with_entry = vault;
        with_entry.entries.push(Entry {
            name: "site".to_string(),
            kind: crate::vault::model::Kind::Login,
            fields: vec![crate::vault::model::Field {
                name: "password".to_string(),
                value: crate::vault::model::Value::Sealed(sealed),
            }],
            tags: Vec::new(),
            favourite: false,
            created: now(),
            updated: now(),
        });
        let plaintext = with_entry.to_plaintext(&write_key).unwrap();
        let text = String::from_utf8_lossy(&plaintext);
        assert!(!text.contains("hunter2"), "{text}");
    }

    #[test]
    fn a_sealed_secret_opens_with_the_identity() {
        let (identity, vault, _) = vault();
        let sealed = vault.seal_secret(&"hunter2".to_string().into()).unwrap();
        let bytes = BASE64.decode(sealed.as_bytes()).unwrap();
        let opened = crypto::decrypt(&identity, &bytes, MAX_SECRET_BYTES).unwrap();
        assert_eq!(opened.as_slice(), b"hunter2");
    }

    #[test]
    fn the_pin_changes_with_the_key_or_the_name() {
        let (_, vault, _) = vault();
        let mut renamed = vault.clone();
        renamed.name = "other".to_string();
        assert_ne!(*renamed.pin(), *vault.pin());

        let mut rekeyed = vault.clone();
        rekeyed.key = crypto::random_key();
        assert_ne!(*rekeyed.pin(), *vault.pin());
    }

    #[test]
    fn a_fingerprint_is_stable_across_changes_and_follows_the_name() {
        let (_, mut vault, _) = vault();
        let original = vault.fingerprint();
        // Shape: six groups of four lowercase base32 characters.
        assert_eq!(original.len(), 29, "{original}");
        assert_eq!(original.split('-').count(), 6);
        assert!(
            original
                .chars()
                .all(|c| c == '-' || c.is_ascii_lowercase() || c.is_ascii_digit())
        );

        // A new generation and new recipients do not change it.
        vault.advance();
        vault.set_recipients(vec![
            crate::vault::crypto::Identity::generate()
                .to_public()
                .to_string(),
        ]);
        assert_eq!(vault.fingerprint(), original);

        // A rename does, because the name is inside the pin.
        let mut renamed = vault.clone();
        renamed.name = "renamed".to_string();
        assert_ne!(renamed.fingerprint(), original);
    }

    #[test]
    fn contents_that_break_the_rules_are_refused() {
        let (_, vault, write_key) = vault();
        let writers = pinned(&write_key);
        let good: serde_json::Value =
            serde_json::from_slice(&vault.to_plaintext(&write_key).unwrap()).unwrap();

        let broken = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value = good.clone();
            change(&mut value);
            Vault::from_plaintext(&serde_json::to_vec(&value).unwrap(), &writers).is_err()
        };

        assert!(broken(&|v| v["format"] = "other".into()));
        assert!(broken(&|v| v["version"] = 99.into()));
        assert!(broken(&|v| v["name"] = "../escape".into()));
        assert!(broken(&|v| v["key"] = "c2hvcnQ=".into()));
        assert!(broken(&|v| v["recipients"] = serde_json::json!([])));
        assert!(broken(&|v| v["recipients"] = serde_json::json!(["age1bad"])));
        assert!(broken(&|v| v["unexpected"] = true.into()));
        assert!(!broken(&|_| {}));
    }

    #[test]
    fn every_field_is_covered_by_the_signature() {
        let (_, vault, write_key) = vault();
        let writers = pinned(&write_key);
        let good: serde_json::Value =
            serde_json::from_slice(&vault.to_plaintext(&write_key).unwrap()).unwrap();

        // Each change keeps the structure valid, so only the signature can
        // catch it. If a field were left out of the signed bytes, one of these
        // would open, and adding a new unsigned field would slip past too.
        let tampered = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value = good.clone();
            change(&mut value);
            Vault::from_plaintext(&serde_json::to_vec(&value).unwrap(), &writers).is_err()
        };
        assert!(tampered(&|v| v["generation"] = 9.into()));
        assert!(tampered(&|v| v["created"] = "2020-01-01T00:00:00Z".into()));
        assert!(tampered(&|v| v["updated"] = "2020-01-01T00:00:00Z".into()));
        assert!(tampered(&|v| v["id"] = "0".repeat(32).into()));
        assert!(tampered(&|v| v["signature"] = "AA".into()));
        // The unchanged vault still opens, so the checks above fail for the
        // right reason.
        assert!(!tampered(&|_| {}));
    }

    #[test]
    fn a_vault_signed_by_an_unpinned_writer_is_refused() {
        let (identity, vault, write_key) = vault();
        let ciphertext = vault.seal(&write_key).unwrap();
        let plaintext = crypto::decrypt(&identity, &ciphertext, 1 << 20).unwrap();
        // A different writer's key is not pinned, so the vault does not open.
        let stranger = pinned(&crypto::new_write_key());
        assert!(Vault::from_plaintext(&plaintext, &stranger).is_err());
        // Nor does an empty pin set: an unprovisioned reader fails closed.
        assert!(Vault::from_plaintext(&plaintext, &[]).is_err());
    }

    #[test]
    fn empty_and_oversized_secrets_are_refused() {
        let (_, vault, _) = vault();
        assert!(vault.seal_secret(&String::new().into()).is_err());
        assert!(
            vault
                .seal_secret(&"x".repeat(MAX_SECRET_BYTES + 1).into())
                .is_err()
        );
    }
}
