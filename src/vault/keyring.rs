//! Unlocking the identity, and opening, changing and saving vaults with it.

// A damaged sealed value is reported as damaged without forwarding the decoder's
// own error, so map_err discards the source on purpose here.
#![allow(clippy::map_err_ignore)]
// Every `entries[index]` below indexes with a value returned by `index()` or
// `entry_index()`, which is a live position into the same list.
#![allow(clippy::indexing_slicing)]

use std::fmt;
use std::path::PathBuf;

use age::secrecy::SecretString;
use anyhow::{Context, Result, anyhow, ensure};
use data_encoding::BASE64;

use crate::vault::crypto::{self, Identity, Key, WriteKey, WriterId};
use crate::vault::document::{self, Vault, now};
use crate::vault::home::{
    self, Home, IDENTITY_LIMIT, PRIVATE, UNCHANGEABLE, VAULT_LIMIT, WRITER_LIMIT, WRITERS_LIMIT,
};
use crate::vault::model::{
    Entry, Field, Kind, MAX_ENTRIES, MAX_SECRET_BYTES, Value, check_entry_name, check_field_name,
};
use crate::vault::prompt::check_new_passphrase;
use crate::vault::recent::{self, Use};
use crate::vault::trust::{Standing, Trust};

const TRUST_KEY_LABEL: &str = "txc vault trust key v1";

/// An unlocked identity.
///
/// It holds the private key, so it lives only as long as it is needed and
/// wipes the key when dropped. It is deliberately not `Clone` and its `Debug`
/// output names nothing secret.
pub struct Keyring {
    home: Home,
    identity: Identity,
    trust_key: Key,
    /// The writer public keys this device has pinned. A vault whose signature
    /// does not verify against one of these does not open. Empty on a device
    /// that has pinned no writer, which fails closed for version 2 vaults.
    writers: Vec<WriterId>,
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring")
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

impl Keyring {
    /// Creates a new identity, protected by the passphrase.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity already exists, when the passphrase
    /// is too short, or when the files cannot be written.
    pub fn create(home: &Home, passphrase: &SecretString) -> Result<Self> {
        check_new_passphrase(passphrase)?;
        home.prepare()?;
        ensure!(
            !home.has_identity(),
            "an identity already exists at {}",
            home.identity_path().display()
        );
        let identity = Identity::generate();
        let sealed = crypto::seal_identity(&identity, passphrase)?;
        home::write_atomic(&home.identity_path(), &sealed, None)?;

        // Trust records belong to the identity that wrote them. Any left from
        // an earlier identity can never be verified again.
        let trust = home.trust_path();
        if home::exists(&trust) {
            std::fs::remove_file(&trust)
                .with_context(|| format!("cannot remove {}", trust.display()))?;
        }
        Self::from_identity(home.clone(), identity)
    }

    /// Unlocks the identity with its passphrase.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no identity, when its files are open to
    /// other users, or when the passphrase is wrong.
    pub fn unlock(home: &Home, passphrase: &SecretString) -> Result<Self> {
        ensure!(
            home.has_identity(),
            "there is no identity at {} yet; create one with: txc vault init",
            home.root().display()
        );
        home.check()?;
        let sealed = home::read_private(&home.identity_path(), IDENTITY_LIMIT, PRIVATE)?;
        let identity = crypto::open_identity(&sealed, passphrase)?;
        Self::from_identity(home.clone(), identity)
    }

    fn from_identity(home: Home, identity: Identity) -> Result<Self> {
        let trust_key = crypto::derive(&identity, TRUST_KEY_LABEL);
        let writers = load_writers(&home)?;
        Ok(Self {
            home,
            identity,
            trust_key,
            writers,
        })
    }

    /// The writer public keys this device has pinned.
    #[must_use]
    pub fn writers(&self) -> &[WriterId] {
        &self.writers
    }

    /// Whether this device can write, i.e. whether a write key is present.
    #[must_use]
    pub fn can_write(&self) -> bool {
        self.home.has_writer()
    }

    /// Unlocks the write key with its own passphrase. Reader-only homes fail
    /// here with the reason and the remedy.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no write key, when its file is open to
    /// other users, or when the passphrase is wrong.
    pub fn open_writer(home: &Home, passphrase: &SecretString) -> Result<WriteKey> {
        ensure!(
            home.has_writer(),
            "this device is provisioned to read only: there is no write key at {}, so it \
             cannot change a vault. Copy writer.age from a device that can write, or create one \
             with: txc vault init",
            home.writer_path().display()
        );
        let sealed = home::read_private(&home.writer_path(), WRITER_LIMIT, PRIVATE)?;
        crypto::open_write_key(&sealed, passphrase, WRITER_LIMIT)
    }

    /// Whether a writer public key is pinned here.
    #[must_use]
    pub fn is_pinned(&self, id: &WriterId) -> bool {
        self.writers.iter().any(|pinned| pinned == id)
    }

    /// Pins a writer public key (base64), so vaults it signs will open here.
    /// Reads the current file, adds the key if new, and writes it back.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is malformed or the file cannot be written.
    pub fn pin_writer(&mut self, id: &str) -> Result<bool> {
        let parsed = crypto::parse_writer_id(id)?;
        let mut ids = read_writer_lines(&self.home)?;
        if ids.iter().any(|pinned| pinned == id.trim()) {
            return Ok(false);
        }
        ids.push(id.trim().to_string());
        write_writer_lines(&self.home, &ids)?;
        self.writers.push(parsed);
        Ok(true)
    }

    /// Unpins a writer public key. Returns whether it was pinned.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be written.
    pub fn unpin_writer(&mut self, id: &str) -> Result<bool> {
        let mut ids = read_writer_lines(&self.home)?;
        let before = ids.len();
        ids.retain(|pinned| pinned != id.trim());
        if ids.len() == before {
            return Ok(false);
        }
        write_writer_lines(&self.home, &ids)?;
        self.writers
            .retain(|pinned| crypto::writer_id_string(pinned) != id.trim());
        Ok(true)
    }

    /// Where the identity and the vaults live.
    #[must_use]
    pub const fn home(&self) -> &Home {
        &self.home
    }

    /// The public key, `age1…`, to give to another device or person so a
    /// vault can be encrypted to it.
    #[must_use]
    pub fn public_key(&self) -> String {
        self.identity.to_public().to_string()
    }

    /// Protects the identity with a new passphrase.
    ///
    /// No copy under the old passphrase is kept: a backup would defeat the
    /// point of changing a passphrase that may have leaked.
    ///
    /// # Errors
    ///
    /// Returns an error when the passphrase is too short or the file cannot
    /// be written.
    pub fn change_passphrase(&self, passphrase: &SecretString) -> Result<()> {
        check_new_passphrase(passphrase)?;
        let sealed = crypto::seal_identity(&self.identity, passphrase)?;
        home::write_atomic(&self.home.identity_path(), &sealed, None)
    }

    fn trust(&self) -> Result<Trust> {
        Trust::load(&self.home, self.trust_key.clone())
    }

    /// This identity's key first, then the others, checked and without
    /// repeats.
    fn recipient_list(&self, others: &[String]) -> Result<Vec<String>> {
        let mut list = vec![self.public_key()];
        for recipient in others {
            let recipient = recipient.trim();
            crypto::parse_recipient(recipient)?;
            if !list.iter().any(|known| known == recipient) {
                list.push(recipient.to_string());
            }
        }
        ensure!(
            list.len() <= document::MAX_RECIPIENTS,
            "a vault can be encrypted to at most {} keys",
            document::MAX_RECIPIENTS
        );
        Ok(list)
    }

    /// Creates an empty vault, encrypted to this identity and to any other
    /// public keys given, and trusts it.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is invalid or taken, when a public key
    /// is malformed, or when the files cannot be written.
    pub fn create_vault(&self, name: &str, others: &[String], write_key: &WriteKey) -> Result<()> {
        let path = self.home.vault_path(name)?;
        self.home.prepare()?;
        ensure!(!home::exists(&path), "a vault named {name} already exists");

        let vault = Vault::new(name, self.recipient_list(others)?);
        let ciphertext = vault.seal(write_key)?;
        home::write_atomic(&path, &ciphertext, None)?;

        let mut trust = self.trust()?;
        trust.pin(&vault, &crypto::sha256(&[&ciphertext]));
        trust.save(&self.home)
    }

    /// Decrypts a vault and compares it with what this device trusts, without
    /// refusing it. This is what `txc vault trust` shows before asking.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault does not exist, cannot be decrypted
    /// with this identity, or breaks the format's rules.
    pub fn inspect(&self, name: &str) -> Result<Inspection> {
        let path = self.home.vault_path(name)?;
        ensure!(home::exists(&path), "there is no vault named {name}");
        self.home.check()?;

        let ciphertext = home::read_private(&path, VAULT_LIMIT, UNCHANGEABLE)?;
        let plaintext = crypto::decrypt(&self.identity, &ciphertext, VAULT_LIMIT)
            .with_context(|| format!("cannot open the vault {name}"))?;
        let vault = Vault::from_plaintext(&plaintext, &self.writers)
            .with_context(|| format!("cannot open the vault {name}"))?;
        ensure!(
            vault.name() == name,
            "the file of the vault {name} holds a vault named {:?}; \
             it was renamed or swapped, so it is not opened",
            vault.name()
        );

        let digest = crypto::sha256(&[&ciphertext]);
        let standing = self.trust()?.standing(&vault, &digest);
        Ok(Inspection {
            opened: Opened {
                vault,
                path,
                digest,
            },
            standing,
        })
    }

    /// Opens a vault this device trusts.
    ///
    /// # Errors
    ///
    /// Returns [`NotTrusted`] when the vault is new to this device or no
    /// longer matches what it trusted, and the errors of
    /// [`inspect`](Self::inspect).
    pub fn open(&self, name: &str) -> Result<Opened> {
        let inspection = self.inspect(name)?;
        if inspection.standing != Standing::Trusted {
            return Err(NotTrusted {
                vault: name.to_string(),
                standing: inspection.standing,
            }
            .into());
        }

        let mut trust = self.trust()?;
        if trust.advance(&inspection.opened.vault, &inspection.opened.digest) {
            trust.save(&self.home)?;
        }
        Ok(inspection.opened)
    }

    /// Trusts a vault as it was inspected, and opens it.
    ///
    /// # Errors
    ///
    /// Returns an error when the trust records cannot be written.
    pub fn trust_vault(&self, inspection: Inspection) -> Result<Opened> {
        let mut trust = self.trust()?;
        trust.pin(&inspection.opened.vault, &inspection.opened.digest);
        trust.save(&self.home)?;
        Ok(inspection.opened)
    }

    /// The trust decisions this device recorded for a vault of this name,
    /// oldest first.
    ///
    /// # Errors
    ///
    /// Returns an error when the trust records cannot be read.
    pub fn trust_history(&self, name: &str) -> Result<Vec<String>> {
        Ok(self.trust()?.history(name))
    }

    /// Deletes a vault and forgets it. A backup of its last version is kept
    /// beside it, still encrypted.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault cannot be opened or removed.
    pub fn delete_vault(&self, opened: &Opened) -> Result<()> {
        home::write_atomic(
            &opened.path.with_extension("age.deleted"),
            &home::read_private(&opened.path, VAULT_LIMIT, UNCHANGEABLE)?,
            None,
        )?;
        std::fs::remove_file(&opened.path)
            .with_context(|| format!("cannot remove {}", opened.path.display()))?;
        let mut trust = self.trust()?;
        trust.forget(&opened.vault);
        trust.save(&self.home)
    }

    /// The entries used most recently on this device, newest first. A list
    /// that cannot be read comes back empty rather than as an error, because
    /// it is a convenience and never holds anything that cannot be rebuilt.
    #[must_use]
    pub fn recent(&self) -> Vec<Use> {
        recent::load(&self.home, &self.identity).unwrap_or_default()
    }

    /// Records that an entry was just used, for the recent list.
    ///
    /// # Errors
    ///
    /// Returns an error when the list cannot be written.
    pub fn record_use(&self, vault: &str, entry: &str) -> Result<()> {
        recent::update(&self.home, &self.identity, |uses| {
            recent::record(uses, vault, entry);
        })
    }

    /// Follows an entry to its new name in the recent list.
    ///
    /// # Errors
    ///
    /// Returns an error when the list cannot be written.
    pub fn rename_use(&self, vault: &str, old: &str, new: &str) -> Result<()> {
        recent::update(&self.home, &self.identity, |uses| {
            for found in uses.iter_mut() {
                if found.vault == vault && found.entry == old {
                    found.entry = new.to_string();
                }
            }
        })
    }

    /// Takes an entry off the recent list.
    ///
    /// # Errors
    ///
    /// Returns an error when the list cannot be written.
    pub fn forget_use(&self, vault: &str, entry: &str) -> Result<()> {
        recent::update(&self.home, &self.identity, |uses| {
            uses.retain(|found| !(found.vault == vault && found.entry == entry));
        })
    }

    /// Moves an entry from an open vault into another vault, re-sealing its
    /// secrets to the destination's recipients.
    ///
    /// The destination is opened here and must be trusted on this device. It
    /// is written first, and the entry is removed from the source only once
    /// that has succeeded, so a failure partway leaves the entry in both
    /// vaults rather than losing it.
    ///
    /// # Errors
    ///
    /// Returns an error when the destination is the source, does not exist or
    /// is not trusted, already holds an entry of that name, or when a secret
    /// cannot be re-sealed or a vault cannot be written.
    pub fn move_entry(
        &self,
        source: &mut Opened,
        dest_vault: &str,
        name: &str,
        write_key: &WriteKey,
    ) -> Result<()> {
        let entry = source.entry(name)?.clone();
        ensure!(
            source.vault.name() != dest_vault,
            "{:?} is already in the vault {dest_vault}",
            entry.name
        );

        let mut dest = self.open(dest_vault)?;
        ensure!(
            !dest.vault.name_taken(&entry.name, None),
            "the vault {dest_vault} already has an entry named {:?}",
            entry.name
        );
        ensure!(
            dest.vault.entries.len() < MAX_ENTRIES,
            "the vault {dest_vault} already holds {MAX_ENTRIES} entries"
        );

        // Every sealed field is opened and sealed again to the destination's
        // recipients, which may differ from the source's; plain fields carry
        // over unchanged. Timestamps, tags and the star come with it.
        let mut moved = entry.clone();
        for field in &mut moved.fields {
            if let Value::Sealed(sealed) = &field.value {
                let secret = self.open_sealed(sealed)?;
                field.value = Value::Sealed(dest.vault.seal_secret(&secret)?);
            }
        }
        moved.validate()?;
        dest.vault.entries.push(moved);
        dest.vault.sort();

        // The destination is written first: if this fails, the source still
        // holds the entry and nothing is lost.
        dest.save(self, write_key)?;

        // Only now is it taken out of the source. Should this fail, the entry
        // is in both vaults, which is safe, and the message says how to
        // finish by hand.
        source.remove(name)?;
        source.save(self, write_key).with_context(|| {
            format!(
                "{:?} was copied to {dest_vault} but could not be removed from {}; \
                 remove it there with: txc vault rm {}/{}",
                entry.name,
                source.vault.name(),
                source.vault.name(),
                entry.name
            )
        })?;
        Ok(())
    }

    fn open_sealed(&self, sealed: &str) -> Result<SecretString> {
        let ciphertext = BASE64
            .decode(sealed.as_bytes())
            .map_err(|_| anyhow!("the sealed value is damaged"))?;
        let plaintext = crypto::decrypt(&self.identity, &ciphertext, MAX_SECRET_BYTES)
            .context("cannot open the sealed value")?;
        let text =
            std::str::from_utf8(&plaintext).map_err(|_| anyhow!("the sealed value is damaged"))?;
        Ok(SecretString::from(text.to_owned()))
    }
}

/// A vault decrypted and compared with the trust records, but not yet
/// accepted.
#[derive(Debug)]
pub struct Inspection {
    opened: Opened,
    standing: Standing,
}

impl Inspection {
    /// How the vault compares with what this device trusts.
    #[must_use]
    pub const fn standing(&self) -> &Standing {
        &self.standing
    }

    /// The vault as it was found.
    #[must_use]
    pub const fn vault(&self) -> &Vault {
        &self.opened.vault
    }
}

/// The error for a vault that does not match what this device trusts.
#[derive(Debug)]
pub struct NotTrusted {
    /// The vault's name.
    pub vault: String,
    /// How it differs.
    pub standing: Standing,
}

impl fmt::Display for NotTrusted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; it is not opened. If you expected this, check it and run: txc vault trust {}",
            self.standing.describe(&self.vault),
            self.vault
        )
    }
}

impl std::error::Error for NotTrusted {}

/// What a new entry holds.
pub struct NewEntry {
    /// Its name.
    pub name: String,
    /// Its kind.
    pub kind: Kind,
    /// Fields stored without their own encryption, such as the username.
    pub plain: Vec<(String, String)>,
    /// Fields sealed on their own. The kind's primary field must be one.
    pub secrets: Vec<(String, SecretString)>,
    /// Tags.
    pub tags: Vec<String>,
    /// Whether it starts out starred.
    pub favourite: bool,
}

/// Changes to an existing entry, all applied or none.
#[derive(Default)]
pub struct Change {
    /// A new name.
    pub rename: Option<String>,
    /// Plain fields to add or replace.
    pub plain: Vec<(String, String)>,
    /// Sealed fields to add or replace.
    pub secrets: Vec<(String, SecretString)>,
    /// Fields to remove. The primary field cannot be.
    pub remove: Vec<String>,
    /// Tags to add.
    pub tag: Vec<String>,
    /// Tags to remove.
    pub untag: Vec<String>,
    /// Star or unstar it.
    pub favourite: Option<bool>,
}

/// An open, trusted vault.
///
/// Changes stay in memory until [`save`](Self::save), which refuses to
/// overwrite a file that changed on disk since it was opened.
pub struct Opened {
    vault: Vault,
    path: PathBuf,
    /// SHA-256 of the file as it was read, to notice a change underneath.
    digest: [u8; 32],
}

impl fmt::Debug for Opened {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opened")
            .field("vault", &self.vault)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Opened {
    /// The vault.
    #[must_use]
    pub const fn vault(&self) -> &Vault {
        &self.vault
    }

    /// The entry with this name.
    ///
    /// # Errors
    ///
    /// Returns an error when there is none.
    pub fn entry(&self, name: &str) -> Result<&Entry> {
        self.vault.entry(name).ok_or_else(|| {
            anyhow!(
                "there is no entry {name:?} in the vault {}",
                self.vault.name()
            )
        })
    }

    fn index(&self, name: &str) -> Result<usize> {
        self.vault.entry_index(name).ok_or_else(|| {
            anyhow!(
                "there is no entry {name:?} in the vault {}",
                self.vault.name()
            )
        })
    }

    /// Adds an entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is taken, the primary secret is
    /// missing, or anything breaks the rules of [`model`](crate::vault::model).
    pub fn add(&mut self, new: NewEntry) -> Result<()> {
        check_entry_name(&new.name)?;
        ensure!(
            self.vault.entries.len() < MAX_ENTRIES,
            "the vault already holds {MAX_ENTRIES} entries"
        );
        ensure!(
            !self.vault.name_taken(&new.name, None),
            "there is already an entry named {:?}",
            new.name
        );
        let primary = new.kind.primary();
        ensure!(
            new.secrets.iter().any(|(name, _)| name == primary),
            "a {} entry needs its {primary}",
            new.kind
        );

        let now = now();
        let mut entry = Entry {
            name: new.name,
            kind: new.kind,
            fields: Vec::new(),
            tags: Vec::new(),
            favourite: new.favourite,
            created: now.clone(),
            updated: now,
        };
        let change = Change {
            plain: new.plain,
            secrets: new.secrets,
            tag: new.tags,
            ..Change::default()
        };
        self.apply(&mut entry, change)?;
        self.vault.entries.push(entry);
        self.vault.sort();
        Ok(())
    }

    /// Changes an entry.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no such entry, when the new name is
    /// taken, when the change would remove the primary field, or when
    /// anything breaks the rules of [`model`](crate::vault::model).
    pub fn change(&mut self, name: &str, change: Change) -> Result<()> {
        let index = self.index(name)?;
        let mut entry = self.vault.entries[index].clone();
        if let Some(new_name) = &change.rename {
            check_entry_name(new_name)?;
            ensure!(
                !self.vault.name_taken(new_name, Some(index)),
                "there is already an entry named {new_name:?}"
            );
            entry.name.clone_from(new_name);
        }
        self.apply(&mut entry, change)?;
        entry.updated = now();
        self.vault.entries[index] = entry;
        self.vault.sort();
        Ok(())
    }

    /// Applies a change to a copy of an entry, checking the result.
    fn apply(&self, entry: &mut Entry, change: Change) -> Result<()> {
        for name in &change.remove {
            ensure!(
                name != entry.kind.primary(),
                "the {name} of a {} entry cannot be removed, only replaced",
                entry.kind
            );
            ensure!(
                entry.field(name).is_some(),
                "{:?} has no field {name:?}",
                entry.name
            );
            entry.fields.retain(|field| &field.name != name);
        }
        for (name, value) in change.plain {
            check_field_name(&name)?;
            // A field the kind keeps secret must never be stored in the
            // clear, however it was asked for.
            if let Some(spec) = entry.kind.spec(&name) {
                ensure!(
                    !spec.sensitivity.is_sealed(),
                    "the {} of {} is kept secret, so it cannot be given as a plain value; \
                     type it when asked, or pipe it in",
                    spec.label.to_lowercase(),
                    article(entry.kind)
                );
            }
            set_field(entry, name, Value::Plain(value));
        }
        for (name, secret) in &change.secrets {
            check_field_name(name)?;
            if let Some(spec) = entry.kind.spec(name) {
                ensure!(
                    spec.sensitivity.is_sealed(),
                    "the {} of {} is not secret; give it as a plain value",
                    spec.label.to_lowercase(),
                    article(entry.kind)
                );
            }
            set_field(
                entry,
                name.clone(),
                Value::Sealed(self.vault.seal_secret(secret)?),
            );
        }
        for tag in change.tag {
            if !entry.tags.contains(&tag) {
                entry.tags.push(tag);
            }
        }
        entry.tags.retain(|tag| !change.untag.contains(tag));
        entry.tags.sort();
        if let Some(favourite) = change.favourite {
            entry.favourite = favourite;
        }
        entry.order_fields();
        entry.validate()
    }

    /// Stars or unstars an entry. Unlike other changes, this leaves the
    /// entry's updated time alone: nothing in it changed.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no such entry.
    pub fn set_favourite(&mut self, name: &str, favourite: bool) -> Result<()> {
        let index = self.index(name)?;
        self.vault.entries[index].favourite = favourite;
        Ok(())
    }

    /// Removes an entry.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no such entry.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        let index = self.index(name)?;
        self.vault.entries.remove(index);
        Ok(())
    }

    /// Decrypts one field. A plain field comes back as it is stored.
    ///
    /// This is the only way a sealed secret leaves the vault, and it opens
    /// exactly one.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no such entry or field, or when the
    /// sealed value cannot be opened with this identity.
    pub fn reveal(&self, keyring: &Keyring, name: &str, field: &str) -> Result<SecretString> {
        let entry = self.entry(name)?;
        let found = entry.field(field).ok_or_else(|| {
            let names: Vec<&str> = entry.fields.iter().map(|f| f.name.as_str()).collect();
            anyhow!(
                "{:?} has no field {field:?}; it has {}",
                entry.name,
                names.join(", ")
            )
        })?;
        match &found.value {
            Value::Plain(value) => Ok(SecretString::from(value.clone())),
            Value::Sealed(sealed) => keyring.open_sealed(sealed),
        }
    }

    /// Replaces who the vault is encrypted to. This identity always stays.
    ///
    /// Every sealed secret is decrypted and sealed again to the new keys.
    /// Taking a key away cannot reach copies of the vault made before, so a
    /// secret that key could read should also be changed.
    ///
    /// # Errors
    ///
    /// Returns an error when a key is malformed or a secret cannot be opened.
    pub fn set_recipients(&mut self, keyring: &Keyring, others: &[String]) -> Result<()> {
        let list = keyring.recipient_list(others)?;
        let keys = list
            .iter()
            .map(|recipient| crypto::parse_recipient(recipient))
            .collect::<Result<Vec<_>>>()?;

        let mut entries = self.vault.entries.clone();
        for entry in &mut entries {
            for field in &mut entry.fields {
                if let Value::Sealed(sealed) = &field.value {
                    let secret = keyring.open_sealed(sealed)?;
                    field.value = Value::Sealed(document::seal_to(&keys, &secret)?);
                }
            }
        }
        self.vault.entries = entries;
        self.vault.set_recipients(list);
        Ok(())
    }

    /// Encrypts the vault and writes it, keeping the previous version as a
    /// backup, and records the new generation as trusted.
    ///
    /// # Errors
    ///
    /// Returns an error when the file changed on disk since the vault was
    /// opened, when this identity is no longer among the recipients, or when
    /// the files cannot be written.
    pub fn save(&mut self, keyring: &Keyring, write_key: &WriteKey) -> Result<()> {
        ensure!(
            self.vault.recipients().contains(&keyring.public_key()),
            "this identity is not among the vault's recipients, so saving would lock it out"
        );
        let current = home::read_private(&self.path, VAULT_LIMIT, UNCHANGEABLE)?;
        ensure!(
            crypto::sha256(&[&current]) == self.digest,
            "the vault {} changed on disk after it was opened; open it again and repeat the change",
            self.vault.name()
        );

        let before = self.vault.advance();
        let written = self.vault.seal(write_key).and_then(|ciphertext| {
            home::write_atomic(&self.path, &ciphertext, Some(UNCHANGEABLE))?;
            Ok(ciphertext)
        });
        let ciphertext = match written {
            Ok(ciphertext) => ciphertext,
            Err(error) => {
                self.vault.restore(before);
                return Err(error);
            }
        };
        self.digest = crypto::sha256(&[&ciphertext]);

        // A write records the new bytes as trusted, but logs a decision only
        // when the recipients or the writer changed (see D3): a routine edit is
        // not a trust decision and must not evict the genuine ones from the log.
        let writer = crypto::writer_id_string(&crypto::writer_id(write_key));
        let mut trust = keyring.trust()?;
        trust.record_write(&self.vault, &self.digest, &writer);
        trust.save(keyring.home())
    }
}

/// Reads the pinned writer keys, one base64 per line. An absent file is an
/// empty set, which fails closed for version 2 vaults.
fn load_writers(home: &Home) -> Result<Vec<WriterId>> {
    let mut writers = Vec::new();
    for line in read_writer_lines(home)? {
        writers.push(crypto::parse_writer_id(&line)?);
    }
    Ok(writers)
}

/// The lines of the writers file, trimmed and without blanks. Absent is empty.
fn read_writer_lines(home: &Home) -> Result<Vec<String>> {
    let path = home.writers_path();
    if !home::exists(&path) {
        return Ok(Vec::new());
    }
    let bytes = home::read_private(&path, WRITERS_LIMIT, PRIVATE)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| anyhow!("the writers file is damaged"))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

/// Writes the writers file, one key per line, owner readable only.
fn write_writer_lines(home: &Home, ids: &[String]) -> Result<()> {
    let mut text = ids.join("\n");
    text.push('\n');
    home::write_atomic(&home.writers_path(), text.as_bytes(), None)
}

/// "a login", "an API key": the kind's label with its article, for messages.
fn article(kind: Kind) -> String {
    let label = kind.label().to_lowercase();
    let vowel = matches!(label.chars().next(), Some('a' | 'e' | 'i' | 'o' | 'u'));
    format!("{} {label}", if vowel { "an" } else { "a" })
}

/// Adds a field, or replaces the value of one with the same name.
fn set_field(entry: &mut Entry, name: String, value: Value) {
    match entry.fields.iter_mut().find(|field| field.name == name) {
        Some(field) => field.value = value,
        None => entry.fields.push(Field { name, value }),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use age::secrecy::ExposeSecret;

    use super::*;
    use crate::vault::home::tests::Scratch;

    pub const PASSPHRASE: &str = "correct horse battery staple";

    pub fn secret(text: &str) -> SecretString {
        SecretString::from(text.to_string())
    }

    /// A keyring on a fresh home, made quickly: the identity and write key are
    /// sealed with a low work factor rather than going through `create`. The
    /// write key is pinned, so vaults it signs open here, and returned so tests
    /// can write with it.
    pub fn keyring(label: &str) -> (Scratch, Keyring, WriteKey) {
        let scratch = Scratch::new(label);
        let home = Home::at(&scratch.0);
        home.prepare().unwrap();
        let identity = Identity::generate();
        home::write_atomic(
            &home.identity_path(),
            &crypto::seal_identity_for_test(&identity, PASSPHRASE),
            None,
        )
        .unwrap();
        let write_key = crypto::new_write_key();
        home::write_atomic(
            &home.writer_path(),
            &crypto::seal_write_key_for_test(&write_key, PASSPHRASE),
            None,
        )
        .unwrap();
        write_writer_lines(
            &home,
            &[crypto::writer_id_string(&crypto::writer_id(&write_key))],
        )
        .unwrap();
        let keyring = Keyring::unlock(&home, &secret(PASSPHRASE)).unwrap();
        (scratch, keyring, write_key)
    }

    fn login(name: &str, password: &str) -> NewEntry {
        NewEntry {
            name: name.to_string(),
            kind: Kind::Login,
            plain: vec![("username".to_string(), "octocat".to_string())],
            secrets: vec![("password".to_string(), secret(password))],
            tags: vec!["dev".to_string()],
            favourite: false,
        }
    }

    #[test]
    fn a_secret_field_cannot_be_stored_in_the_clear_nor_a_plain_one_sealed() {
        let (_scratch, keyring, write_key) = keyring("sensitivity");
        keyring.create_vault("personal", &[], &write_key).unwrap();
        let mut vault = keyring.open("personal").unwrap();

        let card = |plain: Vec<(&str, &str)>, secrets: Vec<(&str, &str)>| NewEntry {
            name: "visa".to_string(),
            kind: Kind::Card,
            plain: plain
                .into_iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            secrets: secrets
                .into_iter()
                .map(|(n, v)| (n.to_string(), secret(v)))
                .collect(),
            tags: Vec::new(),
            favourite: false,
        };

        let error = vault
            .add(card(vec![("cvv", "123")], vec![("number", "4111")]))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("security code of a payment card is kept secret"),
            "{error}"
        );

        let error = vault
            .add(card(
                Vec::new(),
                vec![("number", "4111"), ("expiry", "12/30")],
            ))
            .unwrap_err()
            .to_string();
        assert!(error.contains("not secret"), "{error}");

        vault
            .add(card(
                vec![("expiry", "12/30"), ("cardholder", "A N Other")],
                vec![("cvv", "123"), ("number", "4111")],
            ))
            .unwrap();
        let names: Vec<&str> = vault
            .entry("visa")
            .unwrap()
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect();
        assert_eq!(names, ["cardholder", "number", "expiry", "cvv"]);
    }

    #[test]
    fn a_favourite_is_saved_in_the_vault_without_touching_the_updated_time() {
        let (_scratch, keyring, write_key) = keyring("favourite");
        keyring.create_vault("personal", &[], &write_key).unwrap();
        let mut vault = keyring.open("personal").unwrap();
        vault.add(login("site", "p")).unwrap();
        let updated = vault.entry("site").unwrap().updated.clone();
        vault.set_favourite("site", true).unwrap();
        vault.save(&keyring, &write_key).unwrap();

        let vault = keyring.open("personal").unwrap();
        let entry = vault.entry("site").unwrap();
        assert!(entry.favourite);
        assert_eq!(entry.updated, updated);
    }

    #[test]
    fn the_recent_list_follows_renames_and_removals() {
        let (_scratch, keyring, _write_key) = keyring("recent-uses");
        keyring.record_use("personal", "one").unwrap();
        keyring.record_use("personal", "two").unwrap();
        keyring.rename_use("personal", "one", "uno").unwrap();
        keyring.forget_use("personal", "two").unwrap();
        let uses = keyring.recent();
        assert_eq!(uses.len(), 1);
        assert_eq!(uses[0].entry, "uno");
    }

    #[test]
    fn an_entry_moves_between_vaults_and_its_secret_is_resealed() {
        // The destination is encrypted to a second identity as well, so the
        // move must re-seal the secret to that key, not just copy the bytes.
        let (_scratch, keyring, write_key) = keyring("move");
        let (_other_scratch, mut other, _other_write_key) = self::keyring("move-other");
        // The other device pins this device's writer, so a vault it signed opens.
        other
            .pin_writer(&crypto::writer_id_string(&crypto::writer_id(&write_key)))
            .unwrap();
        keyring.create_vault("personal", &[], &write_key).unwrap();
        keyring
            .create_vault("work", &[other.public_key()], &write_key)
            .unwrap();

        let mut personal = keyring.open("personal").unwrap();
        personal.add(login("GitHub", "hunter2")).unwrap();
        personal.save(&keyring, &write_key).unwrap();

        let mut personal = keyring.open("personal").unwrap();
        keyring
            .move_entry(&mut personal, "work", "GitHub", &write_key)
            .unwrap();

        // Gone from the source, present in the destination, still openable.
        assert!(keyring.open("personal").unwrap().entry("GitHub").is_err());
        let work = keyring.open("work").unwrap();
        assert_eq!(
            work.entry("GitHub").unwrap().plain("username"),
            Some("octocat")
        );
        assert_eq!(
            work.reveal(&keyring, "GitHub", "password")
                .unwrap()
                .expose_secret(),
            "hunter2"
        );

        // And the second identity, a recipient of work only, can read it too:
        // the secret really was re-sealed to that key.
        std::fs::create_dir_all(other.home().vaults_dir()).unwrap();
        std::fs::copy(
            keyring.home().vault_path("work").unwrap(),
            other.home().vault_path("work").unwrap(),
        )
        .unwrap();
        let their_work = other.trust_vault(other.inspect("work").unwrap()).unwrap();
        assert_eq!(
            their_work
                .reveal(&other, "GitHub", "password")
                .unwrap()
                .expose_secret(),
            "hunter2"
        );
    }

    #[test]
    fn a_move_is_refused_when_the_name_is_taken_or_the_vault_is_the_same() {
        let (_scratch, keyring, write_key) = keyring("move-refuse");
        keyring.create_vault("personal", &[], &write_key).unwrap();
        keyring.create_vault("work", &[], &write_key).unwrap();
        let mut personal = keyring.open("personal").unwrap();
        personal.add(login("site", "p")).unwrap();
        personal.save(&keyring, &write_key).unwrap();

        let mut personal = keyring.open("personal").unwrap();
        assert!(
            keyring
                .move_entry(&mut personal, "personal", "site", &write_key)
                .is_err()
        );

        let mut work = keyring.open("work").unwrap();
        work.add(login("site", "other")).unwrap();
        work.save(&keyring, &write_key).unwrap();
        let mut personal = keyring.open("personal").unwrap();
        let error = keyring
            .move_entry(&mut personal, "work", "site", &write_key)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already has an entry"), "{error}");
        // The source still has it: a refused move takes nothing away.
        assert!(keyring.open("personal").unwrap().entry("site").is_ok());
    }

    #[test]
    fn a_secret_saved_in_a_vault_comes_back_after_reopening() {
        let (_scratch, keyring, write_key) = keyring("round-trip");
        keyring.create_vault("personal", &[], &write_key).unwrap();

        let mut vault = keyring.open("personal").unwrap();
        vault.add(login("GitHub", "hunter2")).unwrap();
        vault.save(&keyring, &write_key).unwrap();

        let vault = keyring.open("personal").unwrap();
        assert_eq!(vault.vault().generation(), 2);
        let entry = vault.entry("github").unwrap();
        assert_eq!(entry.plain("username"), Some("octocat"));
        assert!(entry.field("password").unwrap().is_sealed());
        assert_eq!(
            vault
                .reveal(&keyring, "GitHub", "password")
                .unwrap()
                .expose_secret(),
            "hunter2"
        );
    }

    #[test]
    fn the_wrong_passphrase_does_not_unlock() {
        let (scratch, _, _) = keyring("wrong-passphrase");
        let home = Home::at(&scratch.0);
        assert!(Keyring::unlock(&home, &secret("not the passphrase at all")).is_err());
    }

    #[test]
    fn a_vault_from_somewhere_else_must_be_trusted_before_it_opens() {
        let (_scratch, mut keyring, _write_key) = keyring("foreign");
        // Another identity creates a vault encrypted to this one too.
        let (_other_scratch, other, other_write_key) = self::keyring("foreign-other");
        other
            .create_vault("shared", &[keyring.public_key()], &other_write_key)
            .unwrap();
        // Pin the other device's writer, so the signature check passes and the
        // trust layer is what decides, which is the point of this test.
        keyring
            .pin_writer(&crypto::writer_id_string(&crypto::writer_id(
                &other_write_key,
            )))
            .unwrap();
        std::fs::create_dir_all(keyring.home().vaults_dir()).unwrap();
        std::fs::copy(
            other.home().vault_path("shared").unwrap(),
            keyring.home().vault_path("shared").unwrap(),
        )
        .unwrap();

        let error = keyring.open("shared").unwrap_err();
        let not_trusted = error.downcast_ref::<NotTrusted>().expect("a trust error");
        assert_eq!(not_trusted.standing, Standing::Unknown);

        let inspection = keyring.inspect("shared").unwrap();
        keyring.trust_vault(inspection).unwrap();
        assert!(keyring.open("shared").is_ok());
    }

    #[test]
    fn an_old_copy_put_back_is_refused() {
        let (_scratch, keyring, write_key) = keyring("rollback");
        keyring.create_vault("personal", &[], &write_key).unwrap();
        let path = keyring.home().vault_path("personal").unwrap();
        let original = std::fs::read(&path).unwrap();

        let mut vault = keyring.open("personal").unwrap();
        vault.add(login("site", "one")).unwrap();
        vault.save(&keyring, &write_key).unwrap();

        home::write_atomic(&path, &original, None).unwrap();
        let error = keyring.open("personal").unwrap_err();
        assert!(matches!(
            error.downcast_ref::<NotTrusted>().map(|e| &e.standing),
            Some(Standing::RolledBack { seen: 2, found: 1 })
        ));
    }

    #[test]
    fn a_vault_changed_underneath_is_not_overwritten() {
        let (_scratch, keyring, write_key) = keyring("concurrent");
        keyring.create_vault("personal", &[], &write_key).unwrap();

        let mut first = keyring.open("personal").unwrap();
        let mut second = keyring.open("personal").unwrap();
        first.add(login("one", "1")).unwrap();
        first.save(&keyring, &write_key).unwrap();

        second.add(login("two", "2")).unwrap();
        let error = second.save(&keyring, &write_key).unwrap_err().to_string();
        assert!(error.contains("changed on disk"), "{error}");
    }

    #[test]
    fn swapping_one_vault_file_for_another_is_noticed() {
        let (_scratch, keyring, write_key) = keyring("swap");
        keyring.create_vault("personal", &[], &write_key).unwrap();
        keyring.create_vault("work", &[], &write_key).unwrap();
        let home = keyring.home();
        std::fs::copy(
            home.vault_path("work").unwrap(),
            home.vault_path("personal").unwrap(),
        )
        .unwrap();
        let error = format!("{:#}", keyring.open("personal").unwrap_err());
        assert!(error.contains("renamed or swapped"), "{error}");
    }

    #[test]
    fn adding_a_recipient_reseals_every_secret_for_them() {
        let (_scratch, keyring, write_key) = keyring("recipients");
        let (_other_scratch, mut other, _other_write_key) = self::keyring("recipients-other");
        // The other device pins this device's writer, so the shared vault opens.
        other
            .pin_writer(&crypto::writer_id_string(&crypto::writer_id(&write_key)))
            .unwrap();
        keyring.create_vault("personal", &[], &write_key).unwrap();

        let mut vault = keyring.open("personal").unwrap();
        vault.add(login("site", "for both of us")).unwrap();
        vault
            .set_recipients(&keyring, &[other.public_key()])
            .unwrap();
        vault.save(&keyring, &write_key).unwrap();

        std::fs::create_dir_all(other.home().vaults_dir()).unwrap();
        std::fs::copy(
            keyring.home().vault_path("personal").unwrap(),
            other.home().vault_path("personal").unwrap(),
        )
        .unwrap();
        let inspection = other.inspect("personal").unwrap();
        let opened = other.trust_vault(inspection).unwrap();
        assert_eq!(
            opened
                .reveal(&other, "site", "password")
                .unwrap()
                .expose_secret(),
            "for both of us"
        );
    }

    #[test]
    fn entries_keep_their_primary_secret_and_unique_names() {
        let (_scratch, keyring, write_key) = keyring("rules");
        keyring.create_vault("personal", &[], &write_key).unwrap();
        let mut vault = keyring.open("personal").unwrap();

        let mut missing = login("site", "x");
        missing.secrets.clear();
        assert!(vault.add(missing).is_err());

        vault.add(login("Site", "x")).unwrap();
        assert!(vault.add(login("site", "y")).is_err(), "names ignore case");

        let change = Change {
            remove: vec!["password".to_string()],
            ..Change::default()
        };
        assert!(vault.change("site", change).is_err());

        let change = Change {
            rename: Some("renamed".to_string()),
            secrets: vec![("password".to_string(), secret("new"))],
            remove: vec!["username".to_string()],
            ..Change::default()
        };
        vault.change("site", change).unwrap();
        let entry = vault.entry("renamed").unwrap();
        assert!(entry.plain("username").is_none());
        assert_eq!(
            vault
                .reveal(&keyring, "renamed", "password")
                .unwrap()
                .expose_secret(),
            "new"
        );
    }

    #[test]
    fn the_passphrase_can_be_changed() {
        let (scratch, keyring, _write_key) = keyring("passphrase");
        keyring
            .change_passphrase(&secret("a whole new passphrase"))
            .unwrap();
        let home = Home::at(&scratch.0);
        assert!(Keyring::unlock(&home, &secret(PASSPHRASE)).is_err());
        let unlocked = Keyring::unlock(&home, &secret("a whole new passphrase")).unwrap();
        assert_eq!(unlocked.public_key(), keyring.public_key());
        // No backup under the old passphrase was left behind.
        assert!(!home::exists(
            &home.identity_path().with_extension("age.bak")
        ));
    }
}
