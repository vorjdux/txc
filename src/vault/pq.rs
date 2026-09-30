//! age's post-quantum hybrid recipient type, `mlkem768x25519`, exactly as
//! [c2sp.org/age] specifies it and Go age 1.3 implements it.
//!
//! The Rust `age` crate does not ship this type yet, so it is composed here
//! from the same parts the crate already uses for its other hybrid type
//! (`age-core`'s HPKE and Bech32 helpers, `RustCrypto`'s ML-KEM, X25519 and
//! SHA-3), following the structure of `age`'s own `tagpq` module. Nothing is
//! invented: the KEM is MLKEM768-X25519 (X-Wing) from draft-ietf-hpke-pq-03,
//! used through HPKE `SealBase` with HKDF-SHA256 and `ChaCha20Poly1305`. The
//! test vectors of [C2SP/CCTV], written by Go age 1.3, prove that this code
//! reads what Go age writes and refuses what it refuses; encryption runs the
//! same KEM. When the `age` crate adds the type, this module goes.
//!
//! [c2sp.org/age]: https://c2sp.org/age#the-mlkem768-x25519-ie-x-wing-hybrid-post-quantum-recipient-type
//! [C2SP/CCTV]: https://github.com/C2SP/CCTV/tree/main/age

// Protocol code: no unsafe block, and no module-level exception either.
#![forbid(unsafe_code)]
// Every slice here is of a fixed, checked length; the sizes are type-level
// constants of the KEM.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
// A stanza that does not open is reported as age reports it, never with the
// underlying error, so map_err discards the source on purpose.
#![allow(clippy::map_err_ignore)]

use std::collections::HashSet;
use std::fmt;

use age::{DecryptError, EncryptError};
use age_core::format::{FILE_KEY_BYTES, FileKey, Stanza};
use age_core::primitives::{
    bech32_decode, bech32_encode, bech32_encode_to_fmt, hpke_open, hpke_seal,
};
use age_core::secrecy::{ExposeSecret, SecretString};
use data_encoding::BASE64_NOPAD;
use hpke::generic_array::typenum::{self, U32, Unsigned};
use hpke::kem::SharedSecret;
use hpke::rand_core::{CryptoRng, RngCore};
use hpke::{Deserializable, HpkeError, Serializable};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768};
use sha3_10::digest::{ExtendableOutput, FixedOutput, Update, XofReader};
use sha3_10::{Sha3_256, Shake256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const SECRET_KEY_PREFIX: bech32::Hrp = bech32::Hrp::parse_unchecked("AGE-SECRET-KEY-PQ-");
const PUBLIC_KEY_PREFIX: bech32::Hrp = bech32::Hrp::parse_unchecked("age1pq");

/// The stanza's first argument.
pub const STANZA_TAG: &str = "mlkem768x25519";
const INFO: &[u8] = b"age-encryption.org/mlkem768x25519";
/// X-Wing's label, the six bytes `\.//^\`.
const XWING_LABEL: &[u8] = b"\\.//^\\";
const X25519_BYTES: usize = 32;

type KemNct = <MlKem768 as KemCore>::CiphertextSize;
type KemNek = <<MlKem768 as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
/// The encapsulated key: an ML-KEM-768 ciphertext and an X25519 share.
const ENC_BYTES: usize = 1088 + X25519_BYTES;

// ------------------------------------------------------------------- KEM --

#[derive(Clone)]
struct PrivateKey {
    seed: Zeroizing<[u8; 32]>,
    dk_m: <MlKem768 as KemCore>::DecapsulationKey,
    sk_x: StaticSecret,
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.seed == other.seed
    }
}
impl Eq for PrivateKey {}

impl Deserializable for PrivateKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        let seed: [u8; 32] = encoded
            .try_into()
            .map_err(|_| HpkeError::IncorrectInputLength(32, encoded.len()))?;
        Ok(expand(seed).0)
    }
}

impl Serializable for PrivateKey {
    type OutputSize = U32;

    fn write_exact(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.seed[..]);
    }
}

#[derive(Clone, Debug, PartialEq)]
struct PublicKey {
    ek_m: <MlKem768 as KemCore>::EncapsulationKey,
    pk_x: XPublic,
}

// Equality of the encoded keys is total.
impl Eq for PublicKey {}

impl Deserializable for PublicKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        let expected = <Self as Serializable>::OutputSize::to_usize();
        if encoded.len() != expected {
            return Err(HpkeError::IncorrectInputLength(expected, encoded.len()));
        }
        let (encoded_m, encoded_x) = encoded.split_at(KemNek::to_usize());
        let ek_m = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(
            encoded_m
                .try_into()
                .map_err(|_| HpkeError::ValidationError)?,
        );
        let pk_x: [u8; X25519_BYTES] = encoded_x
            .try_into()
            .map_err(|_| HpkeError::ValidationError)?;
        Ok(Self {
            ek_m,
            pk_x: XPublic::from(pk_x),
        })
    }
}

impl Serializable for PublicKey {
    type OutputSize = typenum::Sum<KemNek, U32>;

    fn write_exact(&self, buf: &mut [u8]) {
        let split = KemNek::to_usize();
        buf[..split].copy_from_slice(&self.ek_m.as_bytes());
        buf[split..].copy_from_slice(self.pk_x.as_bytes());
    }
}

#[derive(Clone)]
struct EncappedKey {
    ct_m: Ciphertext<MlKem768>,
    ct_x: [u8; X25519_BYTES],
}

impl Deserializable for EncappedKey {
    fn from_bytes(encoded: &[u8]) -> Result<Self, HpkeError> {
        if encoded.len() != ENC_BYTES {
            return Err(HpkeError::IncorrectInputLength(ENC_BYTES, encoded.len()));
        }
        let (encoded_m, encoded_x) = encoded.split_at(KemNct::to_usize());
        let ct_m = <[u8; 1088]>::try_from(encoded_m)
            .map_err(|_| HpkeError::ValidationError)?
            .into();
        let ct_x = encoded_x
            .try_into()
            .map_err(|_| HpkeError::ValidationError)?;
        Ok(Self { ct_m, ct_x })
    }
}

impl Serializable for EncappedKey {
    type OutputSize = typenum::Sum<KemNct, U32>;

    fn write_exact(&self, buf: &mut [u8]) {
        let split = KemNct::to_usize();
        buf[..split].copy_from_slice(&self.ct_m);
        buf[split..].copy_from_slice(&self.ct_x);
    }
}

/// MLKEM768-X25519, X-Wing, as an HPKE KEM.
struct XWing;

impl hpke::Kem for XWing {
    type PublicKey = PublicKey;
    type PrivateKey = PrivateKey;
    type EncappedKey = EncappedKey;
    type NSecret = U32;
    const KEM_ID: u16 = 0x647a;

    fn sk_to_pk(sk: &Self::PrivateKey) -> Self::PublicKey {
        PublicKey {
            ek_m: sk.dk_m.encapsulation_key().clone(),
            pk_x: XPublic::from(&sk.sk_x),
        }
    }

    fn derive_keypair(ikm: &[u8]) -> (Self::PrivateKey, Self::PublicKey) {
        let seed = labeled_derive::<32>(ikm, Self::KEM_ID, b"DeriveKeyPair", b"");
        expand(seed)
    }

    fn decap(
        sk_recip: &Self::PrivateKey,
        pk_sender_id: Option<&Self::PublicKey>,
        encapped_key: &Self::EncappedKey,
    ) -> Result<SharedSecret<Self>, HpkeError> {
        if pk_sender_id.is_some() {
            return Err(HpkeError::DecapError);
        }
        let ss_m = sk_recip
            .dk_m
            .decapsulate(&encapped_key.ct_m)
            .map_err(|()| HpkeError::DecapError)?;
        let share = XPublic::from(encapped_key.ct_x);
        let ss_x = sk_recip.sk_x.diffie_hellman(&share);
        // A low-order share gives an all-zero secret: refuse it, as Go's
        // crypto/ecdh does.
        if !ss_x.was_contributory() {
            return Err(HpkeError::DecapError);
        }
        let pk_x = XPublic::from(&sk_recip.sk_x);
        Ok(SharedSecret(combine(
            &ss_m,
            ss_x.as_bytes(),
            &encapped_key.ct_x,
            pk_x.as_bytes(),
        )))
    }

    fn encap<R: CryptoRng + RngCore>(
        pk_recip: &Self::PublicKey,
        sender_id_keypair: Option<(&Self::PrivateKey, &Self::PublicKey)>,
        csprng: &mut R,
    ) -> Result<(SharedSecret<Self>, Self::EncappedKey), HpkeError> {
        if sender_id_keypair.is_some() {
            return Err(HpkeError::EncapError);
        }
        let (ct_m, ss_m) = pk_recip
            .ek_m
            .encapsulate(csprng)
            .map_err(|()| HpkeError::EncapError)?;
        let mut ephemeral = Zeroizing::new([0_u8; X25519_BYTES]);
        csprng.fill_bytes(&mut ephemeral[..]);
        let sk_e = StaticSecret::from(*ephemeral);
        let ct_x = *XPublic::from(&sk_e).as_bytes();
        let ss_x = sk_e.diffie_hellman(&pk_recip.pk_x);
        let ss = combine(&ss_m, ss_x.as_bytes(), &ct_x, pk_recip.pk_x.as_bytes());
        Ok((SharedSecret(ss), EncappedKey { ct_m, ct_x }))
    }
}

/// Expands a 32-byte seed into both key pairs: SHAKE256 gives the 64-byte
/// ML-KEM seed (d, z) and then the X25519 secret.
fn expand(seed: [u8; 32]) -> (PrivateKey, PublicKey) {
    let mut expanded = Zeroizing::new([0_u8; 96]);
    let mut xof = Shake256::default().chain(seed).finalize_xof();
    xof.read(&mut expanded[..]);
    let mut d = [0_u8; 32];
    let mut z = [0_u8; 32];
    d.copy_from_slice(&expanded[..32]);
    z.copy_from_slice(&expanded[32..64]);
    let (dk_m, ek_m) = MlKem768::generate_deterministic(&d.into(), &z.into());
    d.zeroize();
    z.zeroize();
    let mut secret = [0_u8; 32];
    secret.copy_from_slice(&expanded[64..]);
    let sk_x = StaticSecret::from(secret);
    secret.zeroize();
    let pk_x = XPublic::from(&sk_x);
    (
        PrivateKey {
            seed: Zeroizing::new(seed),
            dk_m,
            sk_x,
        },
        PublicKey { ek_m, pk_x },
    )
}

/// X-Wing's combiner: SHA3-256 of both secrets, the X25519 ciphertext and
/// public key, and the label.
fn combine(
    ss_m: &[u8],
    ss_x: &[u8],
    ct_x: &[u8],
    pk_x: &[u8],
) -> hpke::generic_array::GenericArray<u8, U32> {
    let mut hash = Sha3_256::default();
    hash.update(ss_m);
    hash.update(ss_x);
    hash.update(ct_x);
    hash.update(pk_x);
    hash.update(XWING_LABEL);
    let digest = hash.finalize_fixed();
    let mut out = hpke::generic_array::GenericArray::<u8, U32>::default();
    out.copy_from_slice(&digest);
    out
}

fn labeled_derive<const L: usize>(
    ikm: &[u8],
    kem_id: u16,
    label: &[u8],
    context: &[u8],
) -> [u8; L] {
    let mut out = [0; L];
    let label_len = u16::try_from(label.len()).unwrap_or(u16::MAX).to_be_bytes();
    let out_len = u16::try_from(L).unwrap_or(u16::MAX).to_be_bytes();
    Shake256::default()
        .chain(ikm)
        .chain(b"HPKE-v1")
        .chain(b"KEM")
        .chain(kem_id.to_be_bytes())
        .chain(label_len)
        .chain(label)
        .chain(out_len)
        .chain(context)
        .finalize_xof_into(&mut out);
    out
}

// -------------------------------------------------------- age recipient --

/// An `age1pq1...` recipient.
#[derive(Clone, PartialEq, Eq)]
pub struct Recipient(PublicKey);

impl std::str::FromStr for Recipient {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bech32_decode(
            s,
            |_| "invalid Bech32 encoding",
            |hrp| {
                (hrp == PUBLIC_KEY_PREFIX)
                    .then_some(())
                    .ok_or("incorrect HRP")
            },
            |_, bytes| {
                PublicKey::from_bytes(&bytes.collect::<Vec<_>>())
                    .map(Self)
                    .map_err(|_| "invalid recipient")
            },
        )
    }
}

impl fmt::Display for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        bech32_encode_to_fmt(f, PUBLIC_KEY_PREFIX, &self.0.to_bytes())
    }
}

impl fmt::Debug for Recipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl age::Recipient for Recipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let (enc, body) = hpke_seal::<XWing, _>(
            &self.0,
            INFO,
            file_key.expose_secret(),
            &mut rand08::rngs::OsRng,
        );
        Ok((
            vec![Stanza {
                tag: STANZA_TAG.to_owned(),
                args: vec![BASE64_NOPAD.encode(&enc.to_bytes())],
                body,
            }],
            // The same label age gives its own post-quantum types, so age
            // refuses to mix this recipient with classic ones in one file.
            std::iter::once("postquantum".to_owned()).collect(),
        ))
    }
}

/// An `AGE-SECRET-KEY-PQ-1...` identity.
#[derive(Clone)]
pub struct Identity(PrivateKey);

impl Identity {
    /// A new random identity.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = [0_u8; 32];
        rand::fill(&mut seed[..]);
        let identity = Self(expand(seed).0);
        seed.zeroize();
        identity
    }

    /// The identity rebuilt from its 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(expand(seed).0)
    }

    /// The Bech32 encoding, uppercase as age writes secret keys.
    #[must_use]
    pub fn to_string(&self) -> SecretString {
        let mut encoded = bech32_encode(SECRET_KEY_PREFIX, &self.0.seed[..]);
        let upper = SecretString::from(encoded.to_uppercase());
        encoded.zeroize();
        upper
    }

    /// The recipient files for this identity are encrypted to.
    #[must_use]
    pub fn to_public(&self) -> Recipient {
        Recipient(XWing::sk_to_pk(&self.0))
    }
}

impl std::str::FromStr for Identity {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        bech32_decode(
            s,
            |_| "invalid Bech32 encoding",
            |hrp| {
                (hrp == SECRET_KEY_PREFIX)
                    .then_some(())
                    .ok_or("incorrect HRP")
            },
            |_, bytes| {
                let mut buf = bytes.collect::<Vec<_>>();
                let seed: Result<[u8; 32], _> = buf
                    .as_slice()
                    .try_into()
                    .map_err(|_| "incorrect identity length");
                buf.zeroize();
                seed.map(Self::from_seed)
            },
        )
    }
}

use hpke::Kem as _;

impl age::Identity for Identity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        // Exactly one argument, a canonical base64 encoding of 1120 bytes, and
        // a 32-byte body, checked before any decryption.
        let [arg] = stanza.args.as_slice() else {
            return Some(Err(DecryptError::InvalidHeader));
        };
        let Ok(enc) = BASE64_NOPAD.decode(arg.as_bytes()) else {
            return Some(Err(DecryptError::InvalidHeader));
        };
        if enc.len() != ENC_BYTES || stanza.body.len() != FILE_KEY_BYTES + 16 {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let Ok(encapped) = EncappedKey::from_bytes(&enc) else {
            return Some(Err(DecryptError::InvalidHeader));
        };
        match hpke_open::<XWing>(&encapped, &self.0, INFO, &stanza.body) {
            Ok(mut plain) => {
                let key = FileKey::init_with_mut(|file_key| file_key.copy_from_slice(&plain));
                plain.zeroize();
                Some(Ok(key))
            }
            // A low-order share is a malformed header, not someone else's file.
            Err(HpkeError::DecapError) => Some(Err(DecryptError::InvalidHeader)),
            // Anything else is a stanza for another key.
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    #[test]
    fn keys_round_trip_through_their_encodings() {
        let identity = Identity::generate();
        let parsed: Identity = identity.to_string().expose_secret().parse().unwrap();
        assert_eq!(parsed.0.seed, identity.0.seed);
        let recipient = identity.to_public();
        assert!(recipient.to_string().starts_with("age1pq1"));
        assert_eq!(
            recipient.to_string().parse::<Recipient>().unwrap(),
            recipient
        );
    }

    #[test]
    fn a_file_encrypted_to_a_recipient_opens_with_its_identity_only() {
        let identity = Identity::generate();
        let encryptor = age::Encryptor::with_recipients(std::iter::once(
            &identity.to_public() as &dyn age::Recipient
        ))
        .unwrap();
        let mut sealed = Vec::new();
        let mut writer = encryptor.wrap_output(&mut sealed).unwrap();
        writer.write_all(b"hello, quantum world").unwrap();
        writer.finish().unwrap();

        let mut plain = String::new();
        age::Decryptor::new(&sealed[..])
            .unwrap()
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap()
            .read_to_string(&mut plain)
            .unwrap();
        assert_eq!(plain, "hello, quantum world");

        let other = Identity::generate();
        assert!(
            age::Decryptor::new(&sealed[..])
                .unwrap()
                .decrypt(std::iter::once(&other as &dyn age::Identity))
                .is_err()
        );
    }

    /// Runs one C2SP/CCTV vector and returns the outcome in its own terms.
    fn outcome(file: &[u8]) -> (String, String) {
        let split = file
            .windows(2)
            .position(|pair| pair == b"\n\n")
            .expect("a header");
        let header = std::str::from_utf8(&file[..split]).expect("a text header");
        let body = &file[split + 2..];
        let mut expect = String::new();
        let mut payload = String::new();
        let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();
        for line in header.lines() {
            let (key, value) = line.split_once(": ").expect("key: value");
            match key {
                "expect" => expect = value.to_string(),
                "payload" => payload = value.to_string(),
                "identity" if value.starts_with("AGE-SECRET-KEY-PQ-") => {
                    identities.push(Box::new(value.parse::<Identity>().expect("a PQ identity")));
                }
                "identity" => {
                    identities.push(Box::new(
                        value.parse::<age::x25519::Identity>().expect("an identity"),
                    ));
                }
                _ => {}
            }
        }
        let got = match age::Decryptor::new(body) {
            Err(_) => "header failure".to_string(),
            Ok(decryptor) => match decryptor.decrypt(identities.iter().map(Box::as_ref)) {
                Err(DecryptError::NoMatchingKeys) => "no match".to_string(),
                Err(_) => "header failure".to_string(),
                Ok(mut reader) => {
                    let mut plain = Vec::new();
                    if reader.read_to_end(&mut plain).is_err() {
                        "payload failure".to_string()
                    } else {
                        use sha2::Digest;
                        let hash = data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(&plain));
                        if hash == payload {
                            "success".to_string()
                        } else {
                            format!("wrong payload {hash}")
                        }
                    }
                }
            },
        };
        (expect, got)
    }

    #[test]
    fn every_c2sp_vector_behaves_as_go_age_does() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/age-cctv");
        let mut checked = 0;
        for item in std::fs::read_dir(&dir).expect("the vectors are vendored") {
            let path = item.unwrap().path();
            if path.extension().is_some() {
                continue;
            }
            let (expect, got) = outcome(&std::fs::read(&path).unwrap());
            assert_eq!(got, expect, "{}", path.display());
            checked += 1;
        }
        assert!(checked >= 16, "only {checked} vectors found");
    }

    #[test]
    fn a_post_quantum_recipient_is_never_mixed_with_a_classic_one() {
        let pq = Identity::generate().to_public();
        let classic = age::x25519::Identity::generate().to_public();
        let recipients: Vec<&dyn age::Recipient> = vec![&pq, &classic];
        assert!(age::Encryptor::with_recipients(recipients.into_iter()).is_err());
    }
}
