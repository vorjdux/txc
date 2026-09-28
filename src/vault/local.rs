//! A device's secrets and state at rest (study sections 5 and 7).
//!
//! **Keys at rest need both factors.** The device's keys are sealed with
//! XChaCha20-Poly1305 under
//! `KEK = HKDF-SHA-384(salt = device_id, ikm = Argon2id(passphrase) || S,
//! info = "txc/v1/kek")`, where `S` is a random 32-byte secret released by
//! the second factor (a hardware authenticator, or the OS keystore on a
//! device without one). A flaw in either factor alone, or a weak
//! passphrase, does not expose the keys. The Argon2id parameters stored in
//! the file must be at or above the compiled floor, 256 MiB and 3 passes.
//!
//! **Local state is sealed, not just encrypted.** It is age-encrypted to the
//! device's own recipient and signed with its signing key: anyone holding
//! the public recipient could make a valid age file, so encryption alone
//! would not give integrity. A state that fails its signature is discarded
//! and rebuilt from the folder.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use age_core::secrecy::ExposeSecret;
use anyhow::{Result, anyhow, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha384;
use zeroize::Zeroizing;

use crate::vault::composite::SigningKey;
use crate::vault::device::{Device, Me};
use crate::vault::object::{Id, SUITE};
use crate::vault::pq;
use crate::vault::wire::{Reader, Writer};

const KEY_TAG: &[u8] = b"txc/v1/device-key";
const KEY_FORMAT: u8 = 1;
const KEK_INFO: &[u8] = b"txc/v1/kek";
const STATE_CONTEXT: &[u8] = b"txc/v1/local-state";
const MAX_TEXT: usize = 4096;
const MAX_RETIRED: usize = 1024;
/// The largest sealed state txc reads.
pub const MAX_STATE_BYTES: usize = 256 * 1024 * 1024;

/// Argon2id parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Passes over the memory.
    pub passes: u32,
    /// Parallel lanes.
    pub lanes: u32,
}

/// The compiled floor: the memory today's scrypt uses, and three passes.
#[cfg(not(test))]
pub const FLOOR: KdfParams = KdfParams {
    memory_kib: 256 * 1024,
    passes: 3,
    lanes: 1,
};
/// Tests use a small floor so they run quickly; the rules are the same.
#[cfg(test)]
pub const FLOOR: KdfParams = KdfParams {
    memory_kib: 64,
    passes: 3,
    lanes: 1,
};

const CEILING_KIB: u32 = 1024 * 1024;

/// A small floor for the end-to-end tests of debug builds, which run the
/// binary many times; release builds never read the variable.
const TEST_FLOOR: KdfParams = KdfParams {
    memory_kib: 64,
    passes: 3,
    lanes: 1,
};

/// The floor in force: the compiled one, or in a debug build asked for it
/// by the tests' work-factor variable, a small one.
fn floor() -> KdfParams {
    #[cfg(debug_assertions)]
    if std::env::var_os(crate::vault::crypto::TEST_WORK_FACTOR_VARIABLE).is_some() {
        return TEST_FLOOR;
    }
    FLOOR
}

impl KdfParams {
    fn at_floor(self) -> bool {
        let floor = floor();
        self.memory_kib >= floor.memory_kib && self.passes >= floor.passes && self.lanes >= 1
    }

    fn argon2(self) -> Result<Argon2<'static>> {
        let params = Params::new(self.memory_kib, self.passes, self.lanes, Some(32))
            .map_err(|error| anyhow!("Argon2id parameters: {error}"))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Picks parameters for this machine: the floor, with memory doubled while
/// one derivation takes less than half of `target`, up to 1 GiB.
///
/// # Errors
///
/// Returns an error when a trial derivation fails.
pub fn calibrate(target: Duration) -> Result<KdfParams> {
    let mut params = floor();
    if params == TEST_FLOOR {
        return Ok(params);
    }
    loop {
        let started = Instant::now();
        argon2id(b"calibration", &[0; 16], params)?;
        let doubled = params.memory_kib.saturating_mul(2);
        if started.elapsed().saturating_mul(2) >= target || doubled > CEILING_KIB {
            return Ok(params);
        }
        params.memory_kib = doubled;
    }
}

fn argon2id(passphrase: &[u8], salt: &[u8; 16], params: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0; 32]);
    params
        .argon2()?
        .hash_password_into(passphrase, salt, &mut out[..])
        .map_err(|error| anyhow!("Argon2id: {error}"))?;
    Ok(out)
}

/// The key-encryption key from both factors.
///
/// # Errors
///
/// Returns an error when the parameters are below the floor.
pub fn kek(
    device: &Id,
    passphrase: &[u8],
    salt: &[u8; 16],
    params: KdfParams,
    second: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        params.at_floor(),
        "the key file's Argon2id parameters are below the floor"
    );
    let stretched = argon2id(passphrase, salt, params)?;
    let mut ikm = Zeroizing::new([0_u8; 64]);
    let (first, rest) = ikm.split_at_mut(32);
    first.copy_from_slice(&stretched[..]);
    rest.copy_from_slice(second);
    let mut out = Zeroizing::new([0; 32]);
    Hkdf::<Sha384>::new(Some(device), &ikm[..])
        .expand(KEK_INFO, &mut out[..])
        .map_err(|_length| anyhow!("cannot derive the key-encryption key"))?;
    Ok(out)
}

fn write_identity(out: &mut Writer, identity: &pq::Identity) {
    out.bytes(identity.to_string().expose_secret().as_bytes());
}

fn read_identity(input: &mut Reader<'_>) -> Result<pq::Identity> {
    let text = Zeroizing::new(input.str(MAX_TEXT)?);
    text.parse()
        .map_err(|error: &str| anyhow!("identity: {error}"))
}

fn encode_me(me: &Me) -> Zeroizing<Vec<u8>> {
    let mut out = Writer::default();
    out.fixed(&me.signing.to_bytes()[..]);
    write_identity(&mut out, &me.identity);
    out.count(me.retired.len());
    for identity in &me.retired {
        write_identity(&mut out, identity);
    }
    out.bool(me.certificate.is_some());
    out.fixed(&me.certificate.unwrap_or_default());
    Zeroizing::new(out.finish())
}

fn decode_me(device: Id, bytes: &[u8]) -> Result<Me> {
    let mut input = Reader(bytes);
    let signing = SigningKey::from_bytes(&Zeroizing::new(input.fixed()?));
    let identity = read_identity(&mut input)?;
    let retired = (0..input.count(MAX_RETIRED)?)
        .map(|_| read_identity(&mut input))
        .collect::<Result<_>>()?;
    let present = input.bool()?;
    let certificate: Id = input.fixed()?;
    input.finish()?;
    Ok(Me {
        device,
        signing,
        identity,
        retired,
        certificate: present.then_some(certificate),
    })
}

fn key_header(
    device: &Id,
    key_version: u64,
    params: KdfParams,
    salt: &[u8; 16],
    nonce: &[u8; 24],
) -> Vec<u8> {
    let mut out = Writer::default();
    out.fixed(KEY_TAG);
    out.u8(KEY_FORMAT);
    out.u8(SUITE);
    out.fixed(device);
    out.u64(key_version);
    out.u64(u64::from(params.memory_kib));
    out.u64(u64::from(params.passes));
    out.u64(u64::from(params.lanes));
    out.fixed(salt);
    out.fixed(nonce);
    out.finish()
}

/// What a key file's header records, so its keys can be sealed again with
/// the same key-encryption key when they change (at pairing and renewal),
/// without asking for the passphrase again.
#[derive(Clone, Copy, Debug)]
pub struct KeyFile {
    /// The device the file is for, the HKDF salt of the KEK.
    pub device: Id,
    /// Counts re-keyings of the file.
    pub key_version: u64,
    /// The Argon2id parameters.
    pub params: KdfParams,
    /// The Argon2id salt.
    pub salt: [u8; 16],
}

/// Starts a key file for a device: a fresh salt and its KEK from both
/// factors.
///
/// # Errors
///
/// Returns an error when the parameters are below the floor.
pub fn new_key_file(
    device: Id,
    passphrase: &[u8],
    second: &[u8; 32],
    params: KdfParams,
) -> Result<(KeyFile, Zeroizing<[u8; 32]>)> {
    let mut salt = [0; 16];
    rand::fill(&mut salt[..]);
    let kek = kek(&device, passphrase, &salt, params, second)?;
    Ok((
        KeyFile {
            device,
            key_version: 1,
            params,
            salt,
        },
        kek,
    ))
}

/// Seals a device's keys under a key file's KEK. The header, holding the
/// device id, key version and suite, is the associated data.
///
/// # Errors
///
/// Returns an error when the keys are another device's.
pub fn seal_keys_with(me: &Me, file: &KeyFile, kek: &[u8; 32]) -> Result<Vec<u8>> {
    ensure!(me.device == file.device, "the keys are another device's");
    let mut nonce = [0; 24];
    rand::fill(&mut nonce[..]);
    let header = key_header(
        &file.device,
        file.key_version,
        file.params,
        &file.salt,
        &nonce,
    );
    let sealed = XChaCha20Poly1305::new_from_slice(kek)
        .map_err(|_length| anyhow!("bad key-encryption key"))?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &encode_me(me),
                aad: &header,
            },
        )
        .map_err(|_error| anyhow!("cannot seal the device keys"))?;
    let mut out = Writer::default();
    out.bytes(&header);
    out.bytes(&sealed);
    Ok(out.finish())
}

/// Seals a device's keys with both factors.
///
/// # Errors
///
/// Returns an error when the parameters are below the floor.
pub fn seal_keys(
    me: &Me,
    passphrase: &[u8],
    second: &[u8; 32],
    params: KdfParams,
    key_version: u64,
) -> Result<Vec<u8>> {
    let (mut file, kek) = new_key_file(me.device, passphrase, second, params)?;
    file.key_version = key_version;
    seal_keys_with(me, &file, &kek)
}

/// The device a key file is for, from its header, to find its second
/// factor before opening it.
///
/// # Errors
///
/// Returns an error when the file is not a txc key file.
pub fn key_file_device(bytes: &[u8]) -> Result<Id> {
    let mut outer = Reader(bytes);
    let mut input = Reader(outer.bytes()?);
    ensure!(
        input.take(KEY_TAG.len())? == KEY_TAG,
        "not a txc device key file"
    );
    input.u8()?;
    input.u8()?;
    input.fixed()
}

/// A key file split into its parts.
struct Parsed<'a> {
    header: &'a [u8],
    sealed: &'a [u8],
    file: KeyFile,
    nonce: [u8; 24],
}

fn parse_key_file(bytes: &[u8]) -> Result<Parsed<'_>> {
    let mut outer = Reader(bytes);
    let header = outer.bytes()?;
    let sealed = outer.bytes()?;
    outer.finish()?;
    let mut input = Reader(header);
    ensure!(
        input.take(KEY_TAG.len())? == KEY_TAG,
        "not a txc device key file"
    );
    ensure!(
        input.u8()? == KEY_FORMAT,
        "a device key file of an unknown format"
    );
    ensure!(
        input.u8()? == SUITE,
        "a device key file of an unknown suite"
    );
    let device: Id = input.fixed()?;
    let key_version = input.u64()?;
    let small = |value: u64| {
        u32::try_from(value).map_err(|_value| anyhow!("Argon2id parameters out of range"))
    };
    let params = KdfParams {
        memory_kib: small(input.u64()?)?,
        passes: small(input.u64()?)?,
        lanes: small(input.u64()?)?,
    };
    let salt: [u8; 16] = input.fixed()?;
    let nonce: [u8; 24] = input.fixed()?;
    input.finish()?;
    Ok(Parsed {
        header,
        sealed,
        file: KeyFile {
            device,
            key_version,
            params,
            salt,
        },
        nonce,
    })
}

/// The key file's KEK from both factors, for a session to hold.
///
/// # Errors
///
/// Returns an error when the file is malformed or its parameters are below
/// the floor.
pub fn key_file_kek(
    bytes: &[u8],
    passphrase: &[u8],
    second: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let Parsed { file, .. } = parse_key_file(bytes)?;
    kek(&file.device, passphrase, &file.salt, file.params, second)
}

/// Opens a device's keys with a KEK already derived, as a session holds it.
///
/// # Errors
///
/// Returns an error when the KEK is wrong or the file was changed.
pub fn unlock_keys_with(bytes: &[u8], kek: &[u8; 32]) -> Result<(Me, KeyFile)> {
    let Parsed {
        header,
        sealed,
        file,
        nonce,
    } = parse_key_file(bytes)?;
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(kek)
            .map_err(|_length| anyhow!("bad key-encryption key"))?
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: sealed,
                    aad: header,
                },
            )
            .map_err(|_error| {
                anyhow!("wrong passphrase or second factor, or the key file was changed")
            })?,
    );
    Ok((decode_me(file.device, &plain)?, file))
}

/// Opens a device's keys with both factors, returning the key file's
/// header and KEK too, for sealing them again later.
///
/// # Errors
///
/// Returns an error when either factor is wrong, the file was changed, or
/// its parameters are below the floor.
pub fn unlock_keys(
    bytes: &[u8],
    passphrase: &[u8],
    second: &[u8; 32],
) -> Result<(Me, KeyFile, Zeroizing<[u8; 32]>)> {
    let kek = key_file_kek(bytes, passphrase, second)?;
    let (me, file) = unlock_keys_with(bytes, &kek)?;
    Ok((me, file, kek))
}

/// Opens a device's keys with both factors.
///
/// # Errors
///
/// Returns an error when either factor is wrong, the file was changed, or
/// its parameters are below the floor.
pub fn open_keys(bytes: &[u8], passphrase: &[u8], second: &[u8; 32]) -> Result<Me> {
    unlock_keys(bytes, passphrase, second).map(|(me, _, _)| me)
}

/// Seals a device's local state: signed with its key, encrypted to its own
/// recipient.
///
/// # Errors
///
/// Returns an error when signing or encryption fails.
pub fn seal_state(device: &Device) -> Result<Vec<u8>> {
    let state = device.encode_state();
    let signature = device.me().signing.sign(&state, STATE_CONTEXT)?;
    let mut plain = Writer::default();
    plain.bytes(&state);
    plain.bytes(&signature);
    let plain = Zeroizing::new(plain.finish());
    let recipient = device.me().identity.to_public();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|_error| anyhow!("cannot seal the local state"))?;
    let mut sealed = Vec::new();
    let mut writer = encryptor.wrap_output(&mut sealed)?;
    writer.write_all(&plain)?;
    writer.finish()?;
    Ok(sealed)
}

/// Opens a device's local state with its secrets.
///
/// # Errors
///
/// Returns an error when it is not sealed to this device, its signature
/// does not verify, or it is malformed; the caller then rebuilds it from
/// the folder.
pub fn open_state(bytes: &[u8], me: Me) -> Result<Device> {
    ensure!(
        bytes.len() <= MAX_STATE_BYTES,
        "the local state is too large"
    );
    let decryptor =
        age::Decryptor::new(bytes).map_err(|_error| anyhow!("the local state is damaged"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&me.identity as &dyn age::Identity))
        .map_err(|_error| anyhow!("the local state is not this device's"))?;
    let mut plain = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(MAX_STATE_BYTES as u64)
        .read_to_end(&mut plain)
        .map_err(|_error| anyhow!("the local state is damaged"))?;
    let mut input = Reader(&plain);
    let state = input.bytes()?;
    let signature = input.bytes()?;
    input.finish()?;
    ensure!(
        me.signing
            .verifying_key()
            .verify(state, STATE_CONTEXT, signature),
        "the local state's signature does not verify"
    );
    Device::decode_state(me, state)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSPHRASE: &[u8] = b"correct horse battery staple";
    const SECOND: [u8; 32] = [7; 32];

    fn me() -> Me {
        let mut me = Me::generate();
        me.retired.push(pq::Identity::generate());
        me.certificate = Some([3; 16]);
        me
    }

    #[test]
    fn device_keys_open_only_with_both_factors() {
        let me = me();
        let sealed = seal_keys(&me, PASSPHRASE, &SECOND, FLOOR, 1).unwrap();
        let opened = open_keys(&sealed, PASSPHRASE, &SECOND).unwrap();
        assert_eq!(opened.device, me.device);
        assert_eq!(opened.signing.verifying_key(), me.signing.verifying_key());
        assert_eq!(opened.identity.to_public(), me.identity.to_public());
        assert_eq!(opened.retired.len(), 1);
        assert_eq!(opened.certificate, me.certificate);

        assert!(open_keys(&sealed, b"wrong", &SECOND).is_err());
        assert!(open_keys(&sealed, PASSPHRASE, &[8; 32]).is_err());
        let mut changed = sealed.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(open_keys(&changed, PASSPHRASE, &SECOND).is_err());
    }

    #[test]
    fn parameters_below_the_floor_are_refused() {
        let weak = KdfParams {
            memory_kib: FLOOR.memory_kib / 2,
            ..FLOOR
        };
        assert!(seal_keys(&me(), PASSPHRASE, &SECOND, weak, 1).is_err());
        let weak = KdfParams { passes: 2, ..FLOOR };
        assert!(kek(&[0; 16], PASSPHRASE, &[0; 16], weak, &SECOND).is_err());
    }

    #[test]
    fn the_kek_binds_the_device_and_both_factors() {
        let base = kek(&[1; 16], PASSPHRASE, &[2; 16], FLOOR, &SECOND).unwrap();
        assert_eq!(
            base,
            kek(&[1; 16], PASSPHRASE, &[2; 16], FLOOR, &SECOND).unwrap()
        );
        assert_ne!(
            base,
            kek(&[9; 16], PASSPHRASE, &[2; 16], FLOOR, &SECOND).unwrap()
        );
        assert_ne!(
            base,
            kek(&[1; 16], b"other", &[2; 16], FLOOR, &SECOND).unwrap()
        );
        assert_ne!(
            base,
            kek(&[1; 16], PASSPHRASE, &[2; 16], FLOOR, &[0; 32]).unwrap()
        );
    }

    #[test]
    fn the_kek_matches_its_test_vector() {
        // Argon2id(m = 64 KiB, t = 3, p = 1) then HKDF-SHA-384, computed
        // independently with libsodium and Python's hashlib; a change here
        // is a format change.
        let kek = kek(&[1; 16], b"passphrase", &[2; 16], FLOOR, &[3; 32]).unwrap();
        assert_eq!(data_encoding::HEXLOWER.encode(&kek[..]), KEK_VECTOR);
    }

    const KEK_VECTOR: &str = "0b1ff863b55ec9a5e2b1911c8c4387b6c9eaffb898487ea3d9bc4f825dd1ca9f";
}
