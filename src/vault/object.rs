//! The objects of the new vault format (study sections 6 and 7).
//!
//! Every object carries a [`Payload`] in one canonical encoding, signed with
//! a composite ML-DSA-65 + Ed25519 signature by its author. Objects come in
//! two shapes:
//!
//! - **Control objects** (genesis, certificates, renewal requests,
//!   membership facts, forwards, join packages and sender-key objects) are
//!   age files sealed to explicit post-quantum recipients plus the recovery
//!   recipient, with filler stanzas so the recipient count shows only a class
//!   of 4, 8 or 16.
//! - **Content objects** (ops, snapshots, checkpoints, policy) are
//!   `nonce || tag || ciphertext` under the writer's sender key: an
//!   XChaCha20-Poly1305 key derived per object with HKDF-SHA-384, and a
//!   16-byte tag, an HMAC-SHA-384 of the nonce, that only holders of the key
//!   can compute or recognise. The storage sees no author, no key id and no
//!   link between objects.
//!
//! Every symmetric construction here is a standard AEAD or HMAC under an
//! HKDF-derived key, and nothing is invented.

// Protocol code: no unsafe block, and no module-level exception either.
#![forbid(unsafe_code)]
// Every offset is bounded by a length checked just before it, and every
// slice is of a fixed, checked length.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
// A damaged object is reported as damaged, never with the cipher's own
// error, so map_err discards the source on purpose here.
#![allow(clippy::map_err_ignore)]

use std::io::{Read, Write};

use anyhow::{Result, anyhow, bail, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha384};
use zeroize::Zeroizing;

use crate::vault::composite;
use crate::vault::pq;
use crate::vault::wire::{Reader, Writer};

/// The only cipher suite: age `mlkem768x25519`, composite ML-DSA-65 +
/// Ed25519, SHA-384, HKDF-SHA-384 and XChaCha20-Poly1305.
pub const SUITE: u8 = 1;

/// A SHA-384 digest.
pub type Hash = [u8; 48];
/// A random 16-byte identifier: a device, a certificate or a sender key.
pub type Id = [u8; 16];

const PAYLOAD_TAG: &[u8] = b"txc/v1/payload";
const OBJECT_HASH_TAG: &[u8] = b"txc/v1/object";
const SIGNATURE_CONTEXT: &[u8] = b"txc/v1/object";
const CONTENT_KEY_INFO: &[u8] = b"txc/v1/content";
const TAG_KEY_INFO: &[u8] = b"txc/v1/tag";

const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
/// The largest object txc reads, checked before reading (folder rule 4).
pub const MAX_OBJECT_BYTES: usize = 64 * 1024 * 1024;
const MAX_DEPS: usize = 4096;
const MAX_RECIPIENTS: usize = 256;

/// What an object is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// The vault's first object: root keys, recovery recipient, policy.
    Genesis,
    /// A device certificate.
    Certificate,
    /// A device asking for its certificate to be renewed with new keys.
    RenewalRequest,
    /// A membership fact: add, remove, expire, kill, and the rest.
    Fact,
    /// Facts sealed again for a member that lacked them.
    Forward,
    /// What a newly paired device starts from.
    Join,
    /// A writer's sender key, sealed to its readers.
    SenderKey,
    /// An operation on an entry.
    Op,
    /// A snapshot of entries.
    Snapshot,
    /// A device's record of what it has seen.
    Checkpoint,
    /// Signed vault policy.
    Policy,
}

impl Kind {
    const fn code(self) -> u8 {
        match self {
            Self::Genesis => 1,
            Self::Certificate => 2,
            Self::RenewalRequest => 3,
            Self::Fact => 4,
            Self::Forward => 5,
            Self::Join => 6,
            Self::SenderKey => 7,
            Self::Op => 16,
            Self::Snapshot => 17,
            Self::Checkpoint => 18,
            Self::Policy => 19,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        Ok(match code {
            1 => Self::Genesis,
            2 => Self::Certificate,
            3 => Self::RenewalRequest,
            4 => Self::Fact,
            5 => Self::Forward,
            6 => Self::Join,
            7 => Self::SenderKey,
            16 => Self::Op,
            17 => Self::Snapshot,
            18 => Self::Checkpoint,
            19 => Self::Policy,
            // An unknown kind puts the device in read-only mode (rule 5); the
            // caller decides, so it is an error here.
            other => bail!("unknown object kind {other}"),
        })
    }

    /// Whether the object is a control object (an age file to explicit
    /// recipients) rather than content under a sender key.
    #[must_use]
    pub const fn is_control(self) -> bool {
        self.code() < 16
    }
}

/// Who an object is for, bound into its signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Addressing {
    /// A control object: each recipient device, the certificate it was
    /// sealed to, and how many control objects this author has sealed to it
    /// so far (a per-recipient counter, for gap detection).
    Control(Vec<(Id, Id, u64)>),
    /// A content object: the sender key and its sequence number.
    Content {
        /// The sender key's id.
        key: Id,
        /// The object's number under that key.
        seq: u64,
    },
}

/// The signed content of every object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    /// The genesis this object belongs to, against cross-vault splicing.
    pub genesis: Hash,
    /// What it is.
    pub kind: Kind,
    /// The device that wrote it.
    pub author: Id,
    /// The author's certificate that signed it.
    pub author_cert: Id,
    /// Its place in the author's chain.
    pub seq: u64,
    /// The hash of the author's previous object.
    pub prev: Hash,
    /// The head of every author this object's writer had seen.
    pub deps: Vec<Hash>,
    /// A commitment to the membership facts its writer had read.
    pub fact_set: Hash,
    /// Who it is for.
    pub addressing: Addressing,
    /// The object's own content.
    pub body: Vec<u8>,
}

impl Payload {
    /// The one canonical encoding: a domain tag, then every field at a fixed
    /// size or with its length, in a fixed order.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer(Vec::new());
        out.fixed(PAYLOAD_TAG);
        out.u8(SUITE);
        out.fixed(&self.genesis);
        out.u8(self.kind.code());
        out.fixed(&self.author);
        out.fixed(&self.author_cert);
        out.u64(self.seq);
        out.fixed(&self.prev);
        out.u64(self.deps.len() as u64);
        for dep in &self.deps {
            out.fixed(dep);
        }
        out.fixed(&self.fact_set);
        match &self.addressing {
            Addressing::Control(recipients) => {
                out.u8(0);
                out.u64(recipients.len() as u64);
                for (device, cert, counter) in recipients {
                    out.fixed(device);
                    out.fixed(cert);
                    out.u64(*counter);
                }
            }
            Addressing::Content { key, seq } => {
                out.u8(1);
                out.fixed(key);
                out.u64(*seq);
            }
        }
        out.bytes(&self.body);
        out.0
    }

    /// Reads the canonical encoding, refusing anything that would not
    /// re-encode to the same bytes (study section 6).
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown suite or kind, a malformed field, or
    /// trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        ensure!(
            input.take(PAYLOAD_TAG.len())? == PAYLOAD_TAG,
            "not a txc object"
        );
        let suite = input.u8()?;
        ensure!(suite == SUITE, "object of an unknown suite {suite}");
        let genesis = input.fixed()?;
        let kind = Kind::from_code(input.u8()?)?;
        let author = input.fixed()?;
        let author_cert = input.fixed()?;
        let seq = input.u64()?;
        let prev = input.fixed()?;
        let deps = (0..input.count(MAX_DEPS)?)
            .map(|_| input.fixed())
            .collect::<Result<_>>()?;
        let fact_set = input.fixed()?;
        let addressing = match input.u8()? {
            0 => Addressing::Control(
                (0..input.count(MAX_RECIPIENTS)?)
                    .map(|_| Ok((input.fixed()?, input.fixed()?, input.u64()?)))
                    .collect::<Result<_>>()?,
            ),
            1 => Addressing::Content {
                key: input.fixed()?,
                seq: input.u64()?,
            },
            other => bail!("unknown addressing {other}"),
        };
        ensure!(
            addressing_fits(kind, &addressing),
            "the addressing does not fit the object kind"
        );
        let body = input.bytes()?.to_vec();
        ensure!(input.0.is_empty(), "the object has trailing bytes");
        let payload = Self {
            genesis,
            kind,
            author,
            author_cert,
            seq,
            prev,
            deps,
            fact_set,
            addressing,
            body,
        };
        ensure!(
            payload.encode() == bytes,
            "the object is not in its canonical encoding"
        );
        Ok(payload)
    }

    /// The object's identity: SHA-384 over its canonical encoding, with a
    /// domain tag.
    #[must_use]
    pub fn hash(&self) -> Hash {
        let mut hash = Sha384::new();
        Digest::update(&mut hash, OBJECT_HASH_TAG);
        Digest::update(&mut hash, self.encode());
        hash.finalize().into()
    }
}

const fn addressing_fits(kind: Kind, addressing: &Addressing) -> bool {
    matches!(
        (kind.is_control(), addressing),
        (true, Addressing::Control(_)) | (false, Addressing::Content { .. })
    )
}

/// A payload with its author's signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// The canonical encoding that was signed.
    pub payload: Vec<u8>,
    /// The composite signature over it.
    pub signature: Vec<u8>,
}

impl Signed {
    /// Signs a payload.
    ///
    /// # Errors
    ///
    /// Returns an error when the system has no randomness for the signature.
    pub fn sign(payload: &Payload, key: &composite::SigningKey) -> Result<Self> {
        let encoded = payload.encode();
        let signature = key.sign(&encoded, SIGNATURE_CONTEXT)?;
        Ok(Self {
            payload: encoded,
            signature,
        })
    }

    /// Checks the signature with the author's key, then reads the payload.
    ///
    /// # Errors
    ///
    /// Returns an error when the signature does not verify or the payload is
    /// malformed.
    pub fn verify(&self, author: &composite::VerifyingKey) -> Result<Payload> {
        ensure!(
            author.verify(&self.payload, SIGNATURE_CONTEXT, &self.signature),
            "the object's signature does not verify"
        );
        Payload::decode(&self.payload)
    }

    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Writer(Vec::with_capacity(
            self.payload.len() + self.signature.len() + 16,
        ));
        out.bytes(&self.payload);
        out.bytes(&self.signature);
        Zeroizing::new(out.0)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        let payload = input.bytes()?.to_vec();
        let signature = input.bytes()?.to_vec();
        ensure!(input.0.is_empty(), "the object has trailing bytes");
        ensure!(
            signature.len() == composite::SIGNATURE_BYTES,
            "the object's signature has the wrong length"
        );
        Ok(Self { payload, signature })
    }
}

// --------------------------------------------------------- control objects --

/// The recipient-count class: 4, 8 or 16, or the exact count above that.
fn recipient_class(count: usize) -> usize {
    [4, 8, 16]
        .into_iter()
        .find(|class| count <= *class)
        .unwrap_or(count)
}

/// Seals a signed payload as a control object to the given recipients (the
/// members and the recovery recipient), padded with filler stanzas, real
/// encapsulations to throwaway keys, up to the recipient-count class.
///
/// # Errors
///
/// Returns an error when there is no recipient or encryption fails.
pub fn seal_control(signed: &Signed, recipients: &[pq::Recipient]) -> Result<Vec<u8>> {
    ensure!(!recipients.is_empty(), "a control object needs a recipient");
    let fillers: Vec<pq::Recipient> = (recipients.len()..recipient_class(recipients.len()))
        .map(|_| pq::Identity::generate().to_public())
        .collect();
    let mut all: Vec<&dyn age::Recipient> = recipients
        .iter()
        .chain(&fillers)
        .map(|recipient| recipient as &dyn age::Recipient)
        .collect();
    // Shuffle, so a stanza's position says nothing about who it is for.
    for i in (1..all.len()).rev() {
        let mut pick = [0_u8; 8];
        rand::fill(&mut pick[..]);
        let j = usize::try_from(u64::from_be_bytes(pick) % (i as u64 + 1)).unwrap_or(0);
        all.swap(i, j);
    }
    let encryptor = age::Encryptor::with_recipients(all.into_iter())
        .map_err(|_| anyhow!("cannot seal the object"))?;
    let mut sealed = Vec::new();
    let mut writer = encryptor.wrap_output(&mut sealed)?;
    writer.write_all(&signed.encode())?;
    writer.finish()?;
    Ok(sealed)
}

/// Opens a control object with this device's identity. Returns `None` when
/// the object is not addressed to this identity.
///
/// # Errors
///
/// Returns an error when the object is addressed to this identity but is
/// malformed.
pub fn open_control(bytes: &[u8], identity: &pq::Identity) -> Result<Option<Signed>> {
    ensure!(
        bytes.len() <= MAX_OBJECT_BYTES,
        "the object is larger than any txc writes"
    );
    let decryptor = age::Decryptor::new(bytes)
        .map_err(|_| anyhow!("the object is not a well-formed age file"))?;
    let mut reader = match decryptor.decrypt(std::iter::once(identity as &dyn age::Identity)) {
        Ok(reader) => reader,
        Err(age::DecryptError::NoMatchingKeys) => return Ok(None),
        Err(_) => bail!("the object's header is malformed"),
    };
    let mut plain = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(MAX_OBJECT_BYTES as u64)
        .read_to_end(&mut plain)
        .map_err(|_| anyhow!("the object's content is damaged"))?;
    Signed::decode(&plain).map(Some)
}

// --------------------------------------------------------- content objects --

/// A writer's sender key.
pub struct SenderKey {
    /// Its random id, bound into every object written under it.
    pub id: Id,
    key: Zeroizing<[u8; 32]>,
}

impl SenderKey {
    /// A fresh sender key.
    #[must_use]
    pub fn generate() -> Self {
        let mut id = [0; 16];
        rand::fill(&mut id[..]);
        let mut key = Zeroizing::new([0; 32]);
        rand::fill(&mut key[..]);
        Self { id, key }
    }

    /// A sender key received in a sender-key object.
    #[must_use]
    pub const fn from_parts(id: Id, key: Zeroizing<[u8; 32]>) -> Self {
        Self { id, key }
    }

    /// The key itself, for sealing it into a sender-key object.
    #[must_use]
    pub const fn secret(&self) -> &Zeroizing<[u8; 32]> {
        &self.key
    }

    fn derive(&self, salt: Option<&[u8]>, info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let mut out = Zeroizing::new([0; 32]);
        Hkdf::<Sha384>::new(salt, &self.key[..])
            .expand(info, &mut out[..])
            .map_err(|_| anyhow!("cannot derive a key"))?;
        Ok(out)
    }

    fn tag(&self, nonce: &[u8]) -> Result<[u8; TAG_BYTES]> {
        let tag_key = self.derive(None, TAG_KEY_INFO)?;
        let mut mac = <Hmac<Sha384> as hmac::KeyInit>::new_from_slice(&tag_key[..])
            .map_err(|_| anyhow!("bad tag key"))?;
        mac.update(nonce);
        let full = mac.finalize().into_bytes();
        let mut tag = [0; TAG_BYTES];
        tag.copy_from_slice(&full[..TAG_BYTES]);
        Ok(tag)
    }
}

/// Seals a signed payload as a content object under a sender key.
///
/// # Errors
///
/// Returns an error when encryption fails.
pub fn seal_content(signed: &Signed, key: &SenderKey) -> Result<Vec<u8>> {
    let mut nonce = [0_u8; NONCE_BYTES];
    rand::fill(&mut nonce[..]);
    let tag = key.tag(&nonce)?;
    let object_key = key.derive(Some(&nonce), CONTENT_KEY_INFO)?;
    let mut envelope = Vec::with_capacity(NONCE_BYTES + TAG_BYTES);
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&tag);
    let sealed = XChaCha20Poly1305::new_from_slice(&object_key[..])
        .map_err(|_| anyhow!("bad content key"))?
        .encrypt(
            XNonce::from_slice(&nonce),
            AeadPayload {
                msg: &signed.encode(),
                aad: &envelope,
            },
        )
        .map_err(|_| anyhow!("cannot seal the object"))?;
    envelope.extend_from_slice(&sealed);
    Ok(envelope)
}

/// Finds which of the reader's sender keys a content object is under, by its
/// tag, and opens it. Returns `None` when it is under none of them: not for
/// this reader.
///
/// # Errors
///
/// Returns an error when the tag matches a key but the object does not open,
/// which is damage or tampering, not someone else's object.
pub fn open_content<'k>(
    bytes: &[u8],
    keys: &'k [SenderKey],
) -> Result<Option<(&'k SenderKey, Signed)>> {
    ensure!(
        bytes.len() <= MAX_OBJECT_BYTES,
        "the object is larger than any txc writes"
    );
    ensure!(
        bytes.len() > NONCE_BYTES + TAG_BYTES,
        "the object is too short to be content"
    );
    let (envelope, sealed) = bytes.split_at(NONCE_BYTES + TAG_BYTES);
    let (nonce, tag) = envelope.split_at(NONCE_BYTES);
    for key in keys {
        if !constant_time_eq(&key.tag(nonce)?, tag) {
            continue;
        }
        let object_key = key.derive(Some(nonce), CONTENT_KEY_INFO)?;
        let plain = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(&object_key[..])
                .map_err(|_| anyhow!("bad content key"))?
                .decrypt(
                    XNonce::from_slice(nonce),
                    AeadPayload {
                        msg: sealed,
                        aad: envelope,
                    },
                )
                .map_err(|_| {
                    anyhow!("the object is damaged: its tag matches a key it does not open with")
                })?,
        );
        return Signed::decode(&plain).map(|signed| Some((key, signed)));
    }
    Ok(None)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(kind: Kind) -> Payload {
        Payload {
            genesis: [1; 48],
            kind,
            author: [2; 16],
            author_cert: [3; 16],
            seq: 7,
            prev: [4; 48],
            deps: vec![[5; 48], [6; 48]],
            fact_set: [7; 48],
            addressing: if kind.is_control() {
                Addressing::Control(vec![([8; 16], [9; 16], 1)])
            } else {
                Addressing::Content {
                    key: [10; 16],
                    seq: 3,
                }
            },
            body: b"the body".to_vec(),
        }
    }

    #[test]
    fn a_payload_has_one_canonical_encoding() {
        for kind in [Kind::Fact, Kind::Op] {
            let original = payload(kind);
            let encoded = original.encode();
            assert_eq!(Payload::decode(&encoded).unwrap(), original);
            let mut trailing = encoded.clone();
            trailing.push(0);
            assert!(Payload::decode(&trailing).is_err());
            assert!(Payload::decode(&encoded[..encoded.len() - 1]).is_err());
        }
        // A control kind with content addressing is refused.
        let mut wrong = payload(Kind::Fact);
        wrong.addressing = Addressing::Content {
            key: [0; 16],
            seq: 0,
        };
        assert!(Payload::decode(&wrong.encode()).is_err());
    }

    #[test]
    fn a_signature_binds_the_payload_and_its_author() {
        let key = composite::SigningKey::generate();
        let signed = Signed::sign(&payload(Kind::Op), &key).unwrap();
        assert_eq!(
            signed.verify(&key.verifying_key()).unwrap(),
            payload(Kind::Op)
        );
        let other = composite::SigningKey::generate();
        assert!(signed.verify(&other.verifying_key()).is_err());
        let mut changed = signed.clone();
        changed.payload[20] ^= 1;
        assert!(changed.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn a_control_object_opens_for_its_recipients_only() {
        let key = composite::SigningKey::generate();
        let signed = Signed::sign(&payload(Kind::Fact), &key).unwrap();
        let (alice, bob, eve) = (
            pq::Identity::generate(),
            pq::Identity::generate(),
            pq::Identity::generate(),
        );
        let sealed = seal_control(&signed, &[alice.to_public(), bob.to_public()]).unwrap();

        assert_eq!(open_control(&sealed, &alice).unwrap().unwrap(), signed);
        assert_eq!(open_control(&sealed, &bob).unwrap().unwrap(), signed);
        assert!(open_control(&sealed, &eve).unwrap().is_none());

        // Four stanzas: two real ones and two fillers, the recipient class.
        let header = String::from_utf8_lossy(&sealed);
        assert_eq!(header.matches("-> mlkem768x25519 ").count(), 4);
    }

    #[test]
    fn a_content_object_is_found_by_its_tag_and_opens_under_its_key_only() {
        let author = composite::SigningKey::generate();
        let signed = Signed::sign(&payload(Kind::Op), &author).unwrap();
        let key = SenderKey::generate();
        let other = SenderKey::generate();
        let sealed = seal_content(&signed, &key).unwrap();

        let keys = [other, key];
        let (found, opened) = open_content(&sealed, &keys).unwrap().unwrap();
        assert_eq!(found.id, keys[1].id);
        assert_eq!(opened, signed);
        assert!(open_content(&sealed, &keys[..1]).unwrap().is_none());

        // Tampering with the ciphertext or the envelope is damage, not a miss.
        let mut changed = sealed.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(open_content(&changed, &keys).is_err());
        let mut changed = sealed.clone();
        changed[0] ^= 1;
        // A changed nonce changes the tag, so no key matches it any more.
        assert!(open_content(&changed, &keys).unwrap().is_none());
    }

    #[test]
    fn two_objects_under_one_key_share_nothing_visible() {
        let author = composite::SigningKey::generate();
        let signed = Signed::sign(&payload(Kind::Op), &author).unwrap();
        let key = SenderKey::generate();
        let first = seal_content(&signed, &key).unwrap();
        let second = seal_content(&signed, &key).unwrap();
        assert_ne!(
            first[..NONCE_BYTES + TAG_BYTES],
            second[..NONCE_BYTES + TAG_BYTES]
        );
    }
}
