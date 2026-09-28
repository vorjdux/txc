//! Composite ML-DSA-65 + Ed25519 signatures, `id-MLDSA65-Ed25519-SHA512`,
//! exactly as draft-ietf-lamps-pq-composite-sigs-19 specifies them.
//!
//! A signature is valid only when both halves verify: ML-DSA-65 protects
//! against a future quantum computer, Ed25519 against an undiscovered flaw in
//! the young lattice scheme. Both sign the same message representative
//!
//! ```text
//! M' = "CompositeAlgorithmSignatures2025" || Label || len(ctx) || ctx || SHA-512(M)
//! ```
//!
//! with `Label = "COMPSIG-MLDSA65-Ed25519-SHA512"`, which ML-DSA also takes as
//! its own context. ML-DSA signing is hedged (randomised), which resists fault
//! attacks; Ed25519 verification is strict, refusing non-canonical and
//! small-order encodings. The draft's own test vector is checked in the tests.

// Every slice here is of a fixed, checked length, and every size sum is of
// small constants.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
// The component libraries' errors carry nothing to show a user, and a
// signature that fails is reported only as failing, so map_err discards the
// source on purpose here.
#![allow(clippy::map_err_ignore)]

use anyhow::{Result, anyhow, ensure};
use ed25519_dalek::Signer;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65};
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

const PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";
const LABEL: &[u8] = b"COMPSIG-MLDSA65-Ed25519-SHA512";

const MLDSA_PUBLIC_BYTES: usize = 1952;
const MLDSA_SIGNATURE_BYTES: usize = 3309;
const ED25519_BYTES: usize = 32;
const ED25519_SIGNATURE_BYTES: usize = 64;

/// The size of an encoded composite public key.
pub const PUBLIC_KEY_BYTES: usize = MLDSA_PUBLIC_BYTES + ED25519_BYTES;
/// The size of an encoded composite signature.
pub const SIGNATURE_BYTES: usize = MLDSA_SIGNATURE_BYTES + ED25519_SIGNATURE_BYTES;
/// The size of an encoded composite private key: the two 32-byte seeds.
pub const PRIVATE_KEY_BYTES: usize = 64;

/// The message representative both halves sign.
fn representative(message: &[u8], context: &[u8]) -> Result<Vec<u8>> {
    let length = u8::try_from(context.len())
        .map_err(|_| anyhow!("a signature context is at most 255 bytes"))?;
    let mut out = Vec::with_capacity(PREFIX.len() + LABEL.len() + 1 + context.len() + 64);
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(LABEL);
    out.push(length);
    out.extend_from_slice(context);
    out.extend_from_slice(&Sha512::digest(message));
    Ok(out)
}

/// A composite signing key.
pub struct SigningKey {
    mldsa: ml_dsa::SigningKey<MlDsa65>,
    ed25519: ed25519_dalek::SigningKey,
}

impl SigningKey {
    /// A fresh key: both component keys generated independently.
    #[must_use]
    pub fn generate() -> Self {
        let mut seeds = Zeroizing::new([0_u8; PRIVATE_KEY_BYTES]);
        rand::fill(&mut seeds[..]);
        Self::from_bytes(&seeds)
    }

    /// The key rebuilt from its encoding: the ML-DSA seed, then the Ed25519
    /// secret key.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; PRIVATE_KEY_BYTES]) -> Self {
        let mut mldsa_seed = ml_dsa::Seed::default();
        mldsa_seed.copy_from_slice(&bytes[..32]);
        let mut ed_seed = Zeroizing::new([0_u8; 32]);
        ed_seed.copy_from_slice(&bytes[32..]);
        let key = Self {
            mldsa: ml_dsa::SigningKey::<MlDsa65>::from_seed(&mldsa_seed),
            ed25519: ed25519_dalek::SigningKey::from_bytes(&ed_seed),
        };
        zeroize::Zeroize::zeroize(&mut mldsa_seed[..]);
        key
    }

    /// The encoding: 64 bytes of key material.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; PRIVATE_KEY_BYTES]> {
        let mut out = Zeroizing::new([0_u8; PRIVATE_KEY_BYTES]);
        out[..32].copy_from_slice(&self.mldsa.to_seed());
        out[32..].copy_from_slice(&self.ed25519.to_bytes());
        out
    }

    /// The matching verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            mldsa: self.mldsa.expanded_key().verifying_key(),
            ed25519: self.ed25519.verifying_key(),
        }
    }

    /// Signs a message, bound to an application context of up to 255 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the context is too long or the system has no
    /// randomness to hedge the ML-DSA signature with.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<Vec<u8>> {
        let representative = representative(message, context)?;
        let mldsa = self
            .mldsa
            .expanded_key()
            .sign_randomized(&representative, LABEL, &mut rand::rng())
            .map_err(|_| anyhow!("cannot make the ML-DSA signature"))?;
        let ed25519 = self.ed25519.sign(&representative);
        let mut out = Vec::with_capacity(SIGNATURE_BYTES);
        out.extend_from_slice(&mldsa.encode());
        out.extend_from_slice(&ed25519.to_bytes());
        Ok(out)
    }
}

/// A composite verifying key.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifyingKey {
    mldsa: ml_dsa::VerifyingKey<MlDsa65>,
    ed25519: ed25519_dalek::VerifyingKey,
}

// Equality of the encoded keys is total.
impl Eq for VerifyingKey {}

impl VerifyingKey {
    /// Reads an encoded composite public key.
    ///
    /// # Errors
    ///
    /// Returns an error when the length is wrong or the Ed25519 half is not a
    /// valid point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == PUBLIC_KEY_BYTES,
            "a composite public key is {PUBLIC_KEY_BYTES} bytes"
        );
        let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(&bytes[..MLDSA_PUBLIC_BYTES])
            .map_err(|_| anyhow!("the ML-DSA public key has the wrong length"))?;
        let mut ed = [0_u8; ED25519_BYTES];
        ed.copy_from_slice(&bytes[MLDSA_PUBLIC_BYTES..]);
        Ok(Self {
            mldsa: ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded),
            ed25519: ed25519_dalek::VerifyingKey::from_bytes(&ed)
                .map_err(|_| anyhow!("the Ed25519 public key is not a valid point"))?,
        })
    }

    /// The encoding.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_KEY_BYTES);
        out.extend_from_slice(&self.mldsa.encode());
        out.extend_from_slice(self.ed25519.as_bytes());
        out
    }

    /// Whether `signature` is a valid composite signature over `message` in
    /// `context`: true only when both halves verify.
    #[must_use]
    pub fn verify(&self, message: &[u8], context: &[u8], signature: &[u8]) -> bool {
        if signature.len() != SIGNATURE_BYTES {
            return false;
        }
        let Ok(representative) = representative(message, context) else {
            return false;
        };
        let Ok(encoded) =
            EncodedSignature::<MlDsa65>::try_from(&signature[..MLDSA_SIGNATURE_BYTES])
        else {
            return false;
        };
        let Some(mldsa) = ml_dsa::Signature::<MlDsa65>::decode(&encoded) else {
            return false;
        };
        let Ok(ed_bytes) =
            <[u8; ED25519_SIGNATURE_BYTES]>::try_from(&signature[MLDSA_SIGNATURE_BYTES..])
        else {
            return false;
        };
        let ed25519 = ed25519_dalek::Signature::from_bytes(&ed_bytes);
        self.mldsa
            .verify_with_context(&representative, LABEL, &mldsa)
            && self
                .ed25519
                .verify_strict(&representative, &ed25519)
                .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use data_encoding::BASE64;

    use super::*;

    fn vector() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/composite/mldsa65-ed25519.json");
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn field(vector: &serde_json::Value, name: &str) -> Vec<u8> {
        BASE64
            .decode(vector[name].as_str().unwrap().as_bytes())
            .unwrap()
    }

    #[test]
    fn the_drafts_test_vector_verifies_and_its_key_signs() {
        let vector = vector();
        let message = field(&vector, "m");
        let context = field(&vector, "ctx");
        let public = VerifyingKey::from_bytes(&field(&vector, "pk")).unwrap();

        assert!(public.verify(&message, b"", &field(&vector, "s")));
        assert!(public.verify(&message, &context, &field(&vector, "sWithContext")));
        // The context binds: each signature fails under the other context.
        assert!(!public.verify(&message, &context, &field(&vector, "s")));
        assert!(!public.verify(&message, b"", &field(&vector, "sWithContext")));

        let secret: [u8; PRIVATE_KEY_BYTES] = field(&vector, "sk").try_into().unwrap();
        let key = SigningKey::from_bytes(&secret);
        assert_eq!(
            key.verifying_key(),
            public,
            "the seed format derives the published key"
        );
        let signature = key.sign(&message, &context).unwrap();
        assert!(public.verify(&message, &context, &signature));
    }

    #[test]
    fn both_halves_must_verify() {
        let key = SigningKey::generate();
        let public = key.verifying_key();
        let signature = key.sign(b"message", b"txc").unwrap();
        assert_eq!(signature.len(), SIGNATURE_BYTES);
        assert!(public.verify(b"message", b"txc", &signature));

        // Break the ML-DSA half, then the Ed25519 half.
        let mut broken = signature.clone();
        broken[10] ^= 1;
        assert!(!public.verify(b"message", b"txc", &broken));
        let mut broken = signature.clone();
        broken[SIGNATURE_BYTES - 1] ^= 1;
        assert!(!public.verify(b"message", b"txc", &broken));

        assert!(!public.verify(b"other message", b"txc", &signature));
        assert!(!public.verify(b"message", b"txc", &signature[..SIGNATURE_BYTES - 1]));
    }

    #[test]
    fn signing_is_hedged_and_keys_round_trip() {
        let key = SigningKey::generate();
        let first = key.sign(b"same", b"").unwrap();
        let second = key.sign(b"same", b"").unwrap();
        assert_ne!(first, second, "ML-DSA signing is randomised");

        let again = SigningKey::from_bytes(&key.to_bytes());
        assert_eq!(again.verifying_key(), key.verifying_key());
        let public = VerifyingKey::from_bytes(&key.verifying_key().to_bytes()).unwrap();
        assert_eq!(public, key.verifying_key());
    }

    #[test]
    fn a_context_over_255_bytes_is_refused() {
        let key = SigningKey::generate();
        assert!(key.sign(b"m", &[0; 256]).is_err());
        assert!(
            !key.verifying_key()
                .verify(b"m", &[0; 256], &[0; SIGNATURE_BYTES])
        );
    }
}
