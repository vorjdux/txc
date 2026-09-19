//! The cryptography, every primitive of it taken from the age format.
//!
//! Nothing here invents a construction. Files are age files; the identity is
//! an age file protected by a passphrase; secrets are sealed as age files of
//! their own. The only additions are HMAC-SHA256 tags, for proving that a
//! record was written by someone holding a key.

// The age errors are deliberately not shown: a secrets tool reports "wrong
// passphrase, or damaged" rather than leaking which, so map_err discards them
// on purpose here.
#![allow(clippy::map_err_ignore)]
// Every arithmetic here sizes a buffer from a length already bounded by a read
// limit, so none of it can overflow.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::iter;

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, anyhow, ensure};
use data_encoding::{BASE32_NOPAD, BASE64};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::vault::home::IDENTITY_LIMIT;

pub(crate) use age::x25519::{Identity, Recipient};

/// A 32 byte key, wiped from memory when dropped.
pub(crate) type Key = Zeroizing<[u8; 32]>;

/// The vault write key: an Ed25519 signing key. It signs a vault so that a
/// reader can verify who wrote it without being able to write one itself.
pub(crate) type WriteKey = SigningKey;

/// A writer's public identity: the Ed25519 verifying key that a device pins to
/// decide whose vaults it will open.
pub(crate) type WriterId = VerifyingKey;

/// The scrypt work factor for a new identity: N = 2^18, which takes about a
/// second and 256 MiB of memory for each guess at the passphrase.
pub(crate) const WORK_FACTOR: u8 = 18;

/// The largest work factor accepted when opening an identity. Anything above
/// would let a doctored file make txc spend minutes and gigabytes on it.
pub(crate) const MAX_WORK_FACTOR: u8 = 20;

/// Lowers the work factor, in debug builds only, so the test suite does not
/// spend a second on every identity it creates. Release builds never read it.
#[cfg(debug_assertions)]
pub const TEST_WORK_FACTOR_VARIABLE: &str = "TXC_VAULT_TEST_WORK_FACTOR";

const SECRET_KEY_PREFIX: &str = "AGE-SECRET-KEY-1";

fn work_factor() -> u8 {
    #[cfg(debug_assertions)]
    if let Some(factor) = std::env::var(TEST_WORK_FACTOR_VARIABLE)
        .ok()
        .and_then(|value| value.parse::<u8>().ok())
        .filter(|factor| (1..=MAX_WORK_FACTOR).contains(factor))
    {
        return factor;
    }
    WORK_FACTOR
}

/// Encrypts a new identity under a passphrase.
///
/// The result is an ordinary passphrase protected age identity file, so
/// `age -d -i identity.age` can use it too: nothing is locked inside txc.
pub(crate) fn seal_identity(identity: &Identity, passphrase: &SecretString) -> Result<Vec<u8>> {
    let secret = identity.to_string();
    // Sized once, so building the text never leaves a partial copy behind.
    let mut text = Zeroizing::new(String::with_capacity(512));
    text.push_str("# txc vault identity\n# public key: ");
    text.push_str(&identity.to_public().to_string());
    text.push('\n');
    text.push_str(secret.expose_secret());
    text.push('\n');

    seal_secret_bytes(text.as_bytes(), passphrase)
}

/// Encrypts arbitrary bytes under a passphrase as an age scrypt file. This is
/// the one place scrypt is set up, shared by the identity and the write key.
fn seal_secret_bytes(plaintext: &[u8], passphrase: &SecretString) -> Result<Vec<u8>> {
    let mut recipient =
        age::scrypt::Recipient::new(SecretString::from(passphrase.expose_secret().to_owned()));
    recipient.set_work_factor(work_factor());
    encrypt_to(&[&recipient], plaintext)
}

/// Decrypts an age scrypt file with its passphrase, reading at most `limit`
/// bytes. `what` names the file in every error, so the identity and the write
/// key each read in their own words.
fn open_secret_bytes(
    sealed: &[u8],
    passphrase: &SecretString,
    limit: usize,
    what: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let decryptor =
        age::Decryptor::new_buffered(sealed).map_err(|_| anyhow!("the {what} is damaged"))?;
    ensure!(
        decryptor.is_scrypt(),
        "the {what} is not protected by a passphrase, so txc will not use it"
    );

    let mut unlock =
        age::scrypt::Identity::new(SecretString::from(passphrase.expose_secret().to_owned()));
    unlock.set_max_work_factor(MAX_WORK_FACTOR);
    let reader = decryptor
        .decrypt(iter::once(&unlock as &dyn age::Identity))
        .map_err(|error| match error {
            age::DecryptError::ExcessiveWork { .. } => {
                anyhow!("the {what} demands more work to open than txc allows")
            }
            _ => anyhow!("wrong passphrase, or the {what} is damaged"),
        })?;

    let mut plaintext = Zeroizing::new(Vec::with_capacity(limit));
    reader
        .take(limit as u64)
        .read_to_end(&mut plaintext)
        .map_err(|_| anyhow!("the {what} is damaged"))?;
    Ok(plaintext)
}

/// Decrypts an identity file with its passphrase.
pub(crate) fn open_identity(sealed: &[u8], passphrase: &SecretString) -> Result<Identity> {
    let plaintext = open_secret_bytes(sealed, passphrase, IDENTITY_LIMIT, "identity file")?;
    let text =
        std::str::from_utf8(&plaintext).map_err(|_| anyhow!("the identity file is damaged"))?;

    let mut keys = text
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with(SECRET_KEY_PREFIX));
    let key = keys.next().context("the identity file holds no key")?;
    ensure!(
        keys.next().is_none(),
        "the identity file holds more than one key, so txc cannot tell which is yours"
    );
    key.parse::<Identity>()
        .map_err(|_| anyhow!("the identity file holds a damaged key"))
}

/// Reads an age public key, accepting only the X25519 kind the vault uses.
pub(crate) fn parse_recipient(text: &str) -> Result<Recipient> {
    text.parse::<Recipient>()
        .map_err(|_| anyhow!("{text:?} is not an age public key, which starts with age1"))
}

/// Reads a bare age X25519 secret key (`AGE-SECRET-KEY-...`), as a grant host
/// holds one. It protects nothing but the grants issued to it, so it is kept
/// unencrypted like any `age-keygen` key.
pub(crate) fn parse_identity(text: &str) -> Result<Identity> {
    text.trim()
        .parse::<Identity>()
        .map_err(|_| anyhow!("that is not an age secret key, which starts with AGE-SECRET-KEY-"))
}

/// A fresh age identity, for a grant that bundles the key that opens it.
pub(crate) fn new_identity() -> Identity {
    Identity::generate()
}

/// Encrypts to every recipient: any one of their identities can decrypt.
pub(crate) fn encrypt(recipients: &[Recipient], plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipients: Vec<&dyn age::Recipient> = recipients
        .iter()
        .map(|recipient| recipient as &dyn age::Recipient)
        .collect();
    encrypt_to(&recipients, plaintext)
}

fn encrypt_to(recipients: &[&dyn age::Recipient], plaintext: &[u8]) -> Result<Vec<u8>> {
    let encryptor = age::Encryptor::with_recipients(recipients.iter().copied())
        .map_err(|error| anyhow!("cannot encrypt: {error}"))?;
    let mut ciphertext = Vec::with_capacity(plaintext.len() + 1024);
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .context("cannot encrypt")?;
    writer.write_all(plaintext).context("cannot encrypt")?;
    writer.finish().context("cannot encrypt")?;
    Ok(ciphertext)
}

/// Decrypts a file encrypted to this identity, reading at most `limit` bytes
/// of plaintext.
///
/// age authenticates every chunk, so a file that was changed, truncated or
/// extended fails here rather than decrypting to something else.
pub(crate) fn decrypt(
    identity: &Identity,
    ciphertext: &[u8],
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let decryptor = age::Decryptor::new_buffered(ciphertext)
        .map_err(|_| anyhow!("it is not an age file, or it is damaged"))?;
    ensure!(
        !decryptor.is_scrypt(),
        "it is protected by a passphrase rather than encrypted to a key"
    );
    let reader = decryptor
        .decrypt(iter::once(identity as &dyn age::Identity))
        .map_err(|_| anyhow!("it was not encrypted to this identity, or it is damaged"))?;

    // The plaintext is never longer than the ciphertext, so this buffer is
    // never reallocated with a copy left behind.
    let mut plaintext = Zeroizing::new(Vec::with_capacity(ciphertext.len().min(limit) + 1));
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut plaintext)
        .map_err(|_| anyhow!("it is damaged or was changed"))?;
    ensure!(plaintext.len() <= limit, "it is larger than txc allows");
    Ok(plaintext)
}

/// A fresh random key.
pub(crate) fn random_key() -> Key {
    let mut key = Zeroizing::new([0; 32]);
    rand::fill(&mut key[..]);
    key
}

/// Derives a key for one purpose from the identity, so the identity's own
/// secret is used for nothing but decryption.
pub(crate) fn derive(identity: &Identity, label: &str) -> Key {
    let secret = identity.to_string();
    mac(label.as_bytes(), &[secret.expose_secret().as_bytes()])
}

/// Joins the parts into one buffer, each prefixed with its length, so no two
/// different lists of parts can run together into the same bytes. Shared by the
/// MAC and the Ed25519 signature so both frame their input the same way.
fn framed(parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let total: usize = parts.iter().map(|part| part.len() + 8).sum();
    let mut buffer = Zeroizing::new(Vec::with_capacity(total));
    for part in parts {
        buffer.extend_from_slice(&(part.len() as u64).to_be_bytes());
        buffer.extend_from_slice(part);
    }
    buffer
}

fn tagger(key: &[u8], parts: &[&[u8]]) -> Hmac<Sha256> {
    // HMAC accepts a key of any length, so this construction never fails.
    #[allow(clippy::expect_used)]
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(&framed(parts));
    mac
}

/// A new random write key. The seed comes from the same source as every other
/// key here, so there is one place where randomness enters.
pub(crate) fn new_write_key() -> WriteKey {
    let seed = random_key();
    WriteKey::from_bytes(&seed)
}

/// The public identity of a write key, for pinning and for stamping a vault.
pub(crate) fn writer_id(key: &WriteKey) -> WriterId {
    key.verifying_key()
}

/// A writer public key as base64, the shape stored in `writers` and in a vault.
pub(crate) fn writer_id_string(id: &WriterId) -> String {
    BASE64.encode(id.as_bytes())
}

/// Reads a base64 writer public key, rejecting anything that is not a valid
/// Ed25519 point.
pub(crate) fn parse_writer_id(text: &str) -> Result<WriterId> {
    let bytes = BASE64
        .decode(text.trim().as_bytes())
        .map_err(|_| anyhow!("a writer key is not valid base64"))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("a writer key is not 32 bytes"))?;
    WriterId::from_bytes(&array).map_err(|_| anyhow!("a writer key is not a valid Ed25519 key"))
}

/// Seals a write key under its own passphrase, as an age scrypt file.
pub(crate) fn seal_write_key(key: &WriteKey, passphrase: &SecretString) -> Result<Vec<u8>> {
    let seed = Zeroizing::new(key.to_bytes());
    seal_secret_bytes(&seed[..], passphrase)
}

/// Opens a sealed write key with its passphrase.
pub(crate) fn open_write_key(
    sealed: &[u8],
    passphrase: &SecretString,
    limit: usize,
) -> Result<WriteKey> {
    let bytes = open_secret_bytes(sealed, passphrase, limit, "write key file")?;
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("the write key file is damaged"))?;
    Ok(WriteKey::from_bytes(&seed))
}

/// Signs a message with a write key.
pub(crate) fn sign(key: &WriteKey, message: &[u8]) -> [u8; 64] {
    key.sign(message).to_bytes()
}

/// A short, readable fingerprint of some bytes: 120 bits of them as six
/// hyphen-separated groups of four lowercase base32 characters, the same shape
/// the vault fingerprint uses. The input must be at least 15 bytes.
pub(crate) fn fingerprint(bytes: &[u8]) -> String {
    // Callers pass a 32 byte pin or public key, so the first 15 are present.
    #[allow(clippy::indexing_slicing)]
    let encoded = BASE32_NOPAD.encode(&bytes[..15]).to_lowercase();
    encoded
        .as_bytes()
        .chunks(4)
        .map(|group| std::str::from_utf8(group).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

/// Verifies a signature against a writer's public key with `verify_strict`,
/// which rejects the small-order and mixed-order keys that plain `verify`
/// accepts.
pub(crate) fn verify_signature(id: &WriterId, message: &[u8], signature: &[u8; 64]) -> bool {
    let signature = Signature::from_bytes(signature);
    id.verify_strict(message, &signature).is_ok()
}

/// HMAC-SHA256 over the parts, each prefixed with its length.
pub(crate) fn mac(key: &[u8], parts: &[&[u8]]) -> Key {
    let mut tag = Zeroizing::new([0; 32]);
    tag.copy_from_slice(&tagger(key, parts).finalize().into_bytes());
    tag
}

/// Checks an HMAC-SHA256 tag in constant time.
pub(crate) fn verify(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    tagger(key, parts).verify_slice(tag).is_ok()
}

/// Compares two byte strings in time that depends only on their length.
pub(crate) fn same(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}

/// SHA-256 over the parts, joined.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The work factor tests use, low enough to be quick.
#[cfg(test)]
pub(crate) fn seal_identity_for_test(identity: &Identity, passphrase: &str) -> Vec<u8> {
    let mut recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_owned()));
    recipient.set_work_factor(4);
    let text = format!("{}\n", identity.to_string().expose_secret());
    encrypt_to(&[&recipient], text.as_bytes()).unwrap()
}

/// Seals a write key quickly, for tests.
#[cfg(test)]
pub(crate) fn seal_write_key_for_test(key: &WriteKey, passphrase: &str) -> Vec<u8> {
    let mut recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_owned()));
    recipient.set_work_factor(4);
    let seed = Zeroizing::new(key.to_bytes());
    encrypt_to(&[&recipient], &seed[..]).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_opens_with_its_identity_and_no_other() {
        let mine = Identity::generate();
        let theirs = Identity::generate();
        let ciphertext = encrypt(&[mine.to_public()], b"attack at dawn").unwrap();

        assert_eq!(
            decrypt(&mine, &ciphertext, 100).unwrap().as_slice(),
            b"attack at dawn"
        );
        assert!(decrypt(&theirs, &ciphertext, 100).is_err());
    }

    #[test]
    fn every_recipient_can_open_a_shared_file() {
        let laptop = Identity::generate();
        let desktop = Identity::generate();
        let ciphertext = encrypt(&[laptop.to_public(), desktop.to_public()], b"shared").unwrap();
        assert!(decrypt(&laptop, &ciphertext, 100).is_ok());
        assert!(decrypt(&desktop, &ciphertext, 100).is_ok());
    }

    #[test]
    fn any_change_to_a_file_is_detected() {
        let identity = Identity::generate();
        let ciphertext = encrypt(&[identity.to_public()], &[7; 300]).unwrap();

        for index in [0, ciphertext.len() / 2, ciphertext.len() - 1] {
            let mut changed = ciphertext.clone();
            changed[index] ^= 1;
            assert!(
                decrypt(&identity, &changed, 1000).is_err(),
                "flipping byte {index} went unnoticed"
            );
        }
        assert!(decrypt(&identity, &ciphertext[..ciphertext.len() - 1], 1000).is_err());
        let mut extended = ciphertext;
        extended.push(0);
        assert!(decrypt(&identity, &extended, 1000).is_err());
    }

    #[test]
    fn plaintext_past_the_limit_is_refused() {
        let identity = Identity::generate();
        let ciphertext = encrypt(&[identity.to_public()], &[1; 50]).unwrap();
        assert!(decrypt(&identity, &ciphertext, 49).is_err());
        assert!(decrypt(&identity, &ciphertext, 50).is_ok());
    }

    #[test]
    fn the_identity_opens_with_its_passphrase_only() {
        let identity = Identity::generate();
        let sealed = seal_identity_for_test(&identity, "correct horse battery");

        let opened = open_identity(&sealed, &"correct horse battery".to_string().into()).unwrap();
        assert_eq!(
            opened.to_public().to_string(),
            identity.to_public().to_string()
        );
        assert!(open_identity(&sealed, &"wrong horse battery".to_string().into()).is_err());
    }

    #[test]
    fn an_identity_encrypted_to_a_key_instead_of_a_passphrase_is_refused() {
        let identity = Identity::generate();
        let text = format!("{}\n", identity.to_string().expose_secret());
        let unprotected = encrypt(&[identity.to_public()], text.as_bytes()).unwrap();
        // An identity has no Debug output, on purpose, so the error is taken
        // out by hand rather than with unwrap_err.
        let Err(error) = open_identity(&unprotected, &"anything at all".to_string().into()) else {
            panic!("an identity file encrypted to a key was accepted");
        };
        let error = error.to_string();
        assert!(error.contains("not protected by a passphrase"), "{error}");
    }

    #[test]
    fn a_passphrase_file_cannot_stand_in_for_a_vault() {
        let identity = Identity::generate();
        let sealed = seal_identity_for_test(&identity, "correct horse battery");
        assert!(decrypt(&identity, &sealed, 1000).is_err());
    }

    #[test]
    fn tags_verify_and_cannot_be_shifted_between_parts() {
        let key = [9; 32];
        let tag = mac(&key, &[b"ab", b"c"]);
        assert!(verify(&key, &[b"ab", b"c"], &tag[..]));
        assert!(!verify(&key, &[b"a", b"bc"], &tag[..]));
        assert!(!verify(&[8; 32], &[b"ab", b"c"], &tag[..]));
    }

    #[test]
    fn derived_keys_depend_on_the_identity_and_the_purpose() {
        let one = Identity::generate();
        let two = Identity::generate();
        assert_eq!(*derive(&one, "a"), *derive(&one, "a"));
        assert_ne!(*derive(&one, "a"), *derive(&one, "b"));
        assert_ne!(*derive(&one, "a"), *derive(&two, "a"));
    }

    #[test]
    fn only_x25519_public_keys_are_accepted_as_recipients() {
        let identity = Identity::generate();
        assert!(parse_recipient(&identity.to_public().to_string()).is_ok());
        assert!(parse_recipient("age1notakey").is_err());
        assert!(parse_recipient("ssh-ed25519 AAAA").is_err());
    }

    #[test]
    fn comparison_is_exact() {
        assert!(same(b"abc", b"abc"));
        assert!(!same(b"abc", b"abd"));
        assert!(!same(b"abc", b"ab"));
    }
}
