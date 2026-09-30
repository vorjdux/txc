//! Pairing a new device with an admin, never through the folder (study
//! section 7). Both paths bind the new device's keys, the admin's keys and
//! the genesis hash, as the Tamarin model `TxcPairing` proves.
//!
//! - **QR both ways.** The camera channel is authentic. A device's full
//!   public keys are about 3.2 KB, more than one QR code holds, so each QR
//!   code carries a SHA-384 fingerprint of the keys (and, from the admin, of
//!   the genesis hash); the keys travel beside it and are checked against the
//!   fingerprint in full.
//! - **Pasted blobs with a short code.** Commit-then-reveal, so an attacker
//!   on the paste channel gets one guess at a 6-digit code instead of
//!   grinding keys:
//!   1. the admin sends `C = SHA-384("txc/v1/pair-commit" || pk_A || n_A)`;
//!   2. the device sends `pk_B || n_B`;
//!   3. the admin reveals `pk_A || n_A || genesis`, and the device checks it
//!      against `C`;
//!   4. both show a code from
//!      `SHA-384("txc/v1/pair-sas" || pk_A || pk_B || n_A || n_B || genesis)`
//!      and the user confirms they match.
//!
//! Each side's state is consumed by its next step, so a nonce is never used
//! twice: a mismatch means starting again.

// Protocol code: no unsafe block, and no module-level exception either.
#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow, ensure};
use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha384};

use crate::vault::composite::VerifyingKey;
use crate::vault::object::{Hash, Id};
use crate::vault::pq;
use crate::vault::wire::{Reader, Writer};

const KEYS_TAG: &[u8] = b"txc/v1/pair-keys";
const COMMIT_TAG: &[u8] = b"txc/v1/pair-commit";
const SAS_TAG: &[u8] = b"txc/v1/pair-sas";
const QR_ADMIN_TAG: &[u8] = b"txc/v1/pair-qr-admin";
const QR_DEVICE_TAG: &[u8] = b"txc/v1/pair-qr-device";
const MAX_RECIPIENT: usize = 4096;
const PREFIXES: [&str; 3] = ["txc-pair-1:", "txc-pair-2:", "txc-pair-3:"];

type Nonce = [u8; 32];

fn nonce() -> Nonce {
    let mut nonce = [0; 32];
    rand::fill(&mut nonce[..]);
    nonce
}

fn sha384(parts: &[&[u8]]) -> Hash {
    let mut hash = Sha384::new();
    for part in parts {
        Digest::update(&mut hash, part);
    }
    hash.finalize().into()
}

/// The public keys a side presents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keys {
    /// The device's id.
    pub device: Id,
    /// Its signing key.
    pub signing_key: VerifyingKey,
    /// Its age recipient.
    pub recipient: pq::Recipient,
}

impl Keys {
    /// The canonical encoding, `pk` in the protocol.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::default();
        out.fixed(KEYS_TAG);
        out.fixed(&self.device);
        out.bytes(&self.signing_key.to_bytes());
        out.str(&self.recipient.to_string());
        out.finish()
    }

    /// Reads the canonical encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        ensure!(
            input.take(KEYS_TAG.len())? == KEYS_TAG,
            "not a device's keys"
        );
        let device = input.fixed()?;
        let signing_key = VerifyingKey::from_bytes(input.bytes()?)?;
        let recipient = input
            .str(MAX_RECIPIENT)?
            .parse()
            .map_err(|error: &str| anyhow!("recipient: {error}"))?;
        input.finish()?;
        let keys = Self {
            device,
            signing_key,
            recipient,
        };
        ensure!(
            keys.encode() == bytes,
            "the keys are not in their canonical encoding"
        );
        Ok(keys)
    }
}

// --------------------------------------------------------------------- QR --

/// What the admin's QR code shows: a fingerprint of its keys and genesis.
#[must_use]
pub fn qr_admin(keys: &Keys, genesis: &Hash) -> Hash {
    sha384(&[QR_ADMIN_TAG, &keys.encode(), genesis])
}

/// What the device's QR code shows: a fingerprint of its keys.
#[must_use]
pub fn qr_device(keys: &Keys) -> Hash {
    sha384(&[QR_DEVICE_TAG, &keys.encode()])
}

/// The device checks the admin's keys and genesis against the scanned code.
///
/// # Errors
///
/// Returns an error when they do not match what the camera saw.
pub fn check_qr_admin(scanned: &Hash, keys: &Keys, genesis: &Hash) -> Result<()> {
    ensure!(
        qr_admin(keys, genesis) == *scanned,
        "the admin's keys do not match its QR code"
    );
    Ok(())
}

/// The admin checks the device's keys against the scanned code.
///
/// # Errors
///
/// Returns an error when they do not match what the camera saw.
pub fn check_qr_device(scanned: &Hash, keys: &Keys) -> Result<()> {
    ensure!(
        qr_device(keys) == *scanned,
        "the device's keys do not match its QR code"
    );
    Ok(())
}

// -------------------------------------------------------------- the paste --

fn wrap(step: usize, bytes: &[u8]) -> String {
    format!(
        "{}{}",
        PREFIXES.get(step).copied().unwrap_or_default(),
        BASE64URL_NOPAD.encode(bytes)
    )
}

fn unwrap(step: usize, text: &str) -> Result<Vec<u8>> {
    let prefix = PREFIXES.get(step).copied().unwrap_or_default();
    let body = text
        .trim()
        .strip_prefix(prefix)
        .with_context(|| format!("this is not step {} of pairing", step.saturating_add(1)))?;
    BASE64URL_NOPAD
        .decode(body.as_bytes())
        .map_err(|_error| anyhow!("the pasted text is damaged"))
}

/// The six-digit code both screens show, as `123 456`.
fn code(
    admin: &[u8],
    device: &[u8],
    admin_nonce: &Nonce,
    device_nonce: &Nonce,
    genesis: &Hash,
) -> String {
    let mut out = Writer::default();
    out.bytes(admin);
    out.bytes(device);
    out.fixed(admin_nonce);
    out.fixed(device_nonce);
    out.fixed(genesis);
    let hash = sha384(&[SAS_TAG, &out.finish()]);
    let mut word = [0; 8];
    word.copy_from_slice(hash.get(..8).unwrap_or(&[0; 8]));
    let number = u64::from_be_bytes(word) % 1_000_000;
    format!("{:03} {:03}", number / 1000, number % 1000)
}

/// What a finished pairing gives each side, once the user confirms the
/// codes match.
#[derive(Debug, PartialEq, Eq)]
pub struct Paired {
    /// The other side's keys.
    pub peer: Keys,
    /// The genesis both sides bound.
    pub genesis: Hash,
    /// The code to compare with the other screen.
    pub code: String,
}

/// The admin's side, after sending its commitment.
pub struct AdminStart {
    keys: Vec<u8>,
    nonce: Nonce,
    genesis: Hash,
}

impl AdminStart {
    /// Step 1: commits to the admin's keys. Returns the state and the text
    /// to hand to the new device.
    #[must_use]
    pub fn new(keys: &Keys, genesis: Hash) -> (Self, String) {
        let keys = keys.encode();
        let nonce = nonce();
        let commit = sha384(&[COMMIT_TAG, &commit_input(&keys, &nonce)]);
        (
            Self {
                keys,
                nonce,
                genesis,
            },
            wrap(0, &commit),
        )
    }

    /// Step 3: reads the device's reply and reveals the admin's keys.
    /// Returns what to show and the text to hand back.
    ///
    /// # Errors
    ///
    /// Returns an error when the reply is not a device's step 2.
    pub fn reveal(self, reply: &str) -> Result<(Paired, String)> {
        let bytes = unwrap(1, reply)?;
        let mut input = Reader(&bytes);
        let device_keys = input.bytes()?.to_vec();
        let device_nonce: Nonce = input.fixed()?;
        input.finish()?;
        let peer = Keys::decode(&device_keys)?;
        let code = code(
            &self.keys,
            &device_keys,
            &self.nonce,
            &device_nonce,
            &self.genesis,
        );
        let mut out = Writer::default();
        out.bytes(&self.keys);
        out.fixed(&self.nonce);
        out.fixed(&self.genesis);
        Ok((
            Paired {
                peer,
                genesis: self.genesis,
                code,
            },
            wrap(2, &out.finish()),
        ))
    }
}

fn commit_input(keys: &[u8], nonce: &Nonce) -> Vec<u8> {
    let mut out = Writer::default();
    out.bytes(keys);
    out.fixed(nonce);
    out.finish()
}

/// The new device's side, after answering the commitment.
pub struct DeviceReply {
    keys: Vec<u8>,
    nonce: Nonce,
    commit: Hash,
}

impl DeviceReply {
    /// Step 2: reads the admin's commitment and answers with the device's
    /// keys. Returns the state and the text to hand back to the admin.
    ///
    /// # Errors
    ///
    /// Returns an error when the text is not an admin's step 1.
    pub fn new(keys: &Keys, commitment: &str) -> Result<(Self, String)> {
        let commit: Hash = unwrap(0, commitment)?
            .try_into()
            .map_err(|_bytes| anyhow!("the commitment has the wrong length"))?;
        let keys = keys.encode();
        let nonce = nonce();
        let mut out = Writer::default();
        out.bytes(&keys);
        out.fixed(&nonce);
        Ok((
            Self {
                keys,
                nonce,
                commit,
            },
            wrap(1, &out.finish()),
        ))
    }

    /// Step 4: checks the admin's reveal against its commitment. Returns
    /// what to show.
    ///
    /// # Errors
    ///
    /// Returns an error when the reveal does not match the commitment.
    pub fn check(self, reveal: &str) -> Result<Paired> {
        let bytes = unwrap(2, reveal)?;
        let mut input = Reader(&bytes);
        let admin_keys = input.bytes()?.to_vec();
        let admin_nonce: Nonce = input.fixed()?;
        let genesis: Hash = input.fixed()?;
        input.finish()?;
        let expected = sha384(&[COMMIT_TAG, &commit_input(&admin_keys, &admin_nonce)]);
        ensure!(
            expected == self.commit,
            "the admin's keys do not match its commitment: pairing is aborted"
        );
        let peer = Keys::decode(&admin_keys)?;
        let code = code(&admin_keys, &self.keys, &admin_nonce, &self.nonce, &genesis);
        Ok(Paired {
            peer,
            genesis,
            code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::authority::new_id;
    use crate::vault::composite::SigningKey;

    fn keys() -> Keys {
        Keys {
            device: new_id(),
            signing_key: SigningKey::generate().verifying_key(),
            recipient: pq::Identity::generate().to_public(),
        }
    }

    #[test]
    fn both_screens_show_the_same_code_and_each_side_gets_the_other() {
        let (admin, device, genesis) = (keys(), keys(), [4; 48]);
        let (start, commit) = AdminStart::new(&admin, genesis);
        let (reply_state, reply) = DeviceReply::new(&device, &commit).unwrap();
        let (on_admin, reveal) = start.reveal(&reply).unwrap();
        let on_device = reply_state.check(&reveal).unwrap();

        assert_eq!(on_admin.code, on_device.code);
        assert_eq!(on_admin.code.len(), 7);
        assert_eq!((on_admin.peer, on_device.peer), (device, admin));
        assert_eq!(on_device.genesis, genesis);
    }

    #[test]
    fn a_swapped_admin_key_fails_the_commitment() {
        let (admin, device) = (keys(), keys());
        let (_start, commit) = AdminStart::new(&admin, [4; 48]);
        let (reply_state, reply) = DeviceReply::new(&device, &commit).unwrap();
        // An attacker on the paste channel reveals its own keys instead.
        let (attacker, _) = AdminStart::new(&keys(), [4; 48]);
        let (_, forged) = attacker.reveal(&reply).unwrap();
        assert!(reply_state.check(&forged).is_err());
    }

    #[test]
    fn a_swapped_device_key_or_genesis_changes_the_code() {
        let (admin, device) = (keys(), keys());
        let (start, commit) = AdminStart::new(&admin, [4; 48]);
        let (reply_state, _) = DeviceReply::new(&device, &commit).unwrap();
        // An attacker replaces the device's reply with its own keys.
        let (_, forged_reply) = DeviceReply::new(&keys(), &commit).unwrap();
        let (on_admin, reveal) = start.reveal(&forged_reply).unwrap();
        let on_device = reply_state.check(&reveal).unwrap();
        assert_ne!(on_admin.code, on_device.code);

        let (a, b, n, m) = (b"admin".as_slice(), b"device".as_slice(), [1; 32], [2; 32]);
        assert_ne!(code(a, b, &n, &m, &[4; 48]), code(a, b, &n, &m, &[5; 48]));
    }

    #[test]
    fn steps_cannot_be_confused() {
        let (_start, commit) = AdminStart::new(&keys(), [4; 48]);
        assert!(DeviceReply::new(&keys(), "txc-pair-2:AAAA").is_err());
        assert!(DeviceReply::new(&keys(), "garbage").is_err());
        let (reply_state, _) = DeviceReply::new(&keys(), &commit).unwrap();
        assert!(reply_state.check(&commit).is_err());
    }

    #[test]
    fn qr_codes_bind_keys_and_genesis() {
        let (admin, device, genesis) = (keys(), keys(), [4; 48]);
        let shown = qr_admin(&admin, &genesis);
        check_qr_admin(&shown, &admin, &genesis).unwrap();
        assert!(check_qr_admin(&shown, &keys(), &genesis).is_err());
        assert!(check_qr_admin(&shown, &admin, &[5; 48]).is_err());
        let shown = qr_device(&device);
        check_qr_device(&shown, &device).unwrap();
        assert!(check_qr_device(&shown, &admin).is_err());
    }

    #[test]
    fn keys_round_trip_canonically() {
        let keys = keys();
        assert_eq!(Keys::decode(&keys.encode()).unwrap(), keys);
    }
}
