//! SLIP-0039: Shamir's secret sharing for mnemonic codes, for the recovery
//! sheets (study section 12).
//!
//! The recovery secret is encrypted with the card as the SLIP-39 passphrase
//! and split 2-of-3, one 33-word mnemonic per sheet, so any standard SLIP-39
//! tool can recombine two sheets. This is the specification as written:
//! GF(256) with the Rijndael polynomial, a digest share at x = 254, a
//! four-round Feistel cipher with PBKDF2-HMAC-SHA256, and an RS1024
//! checksum over 10-bit words. The reference implementation's vectors are
//! the tests.

// Protocol code: no unsafe block, and no module-level exception either.
#![forbid(unsafe_code)]
// Every index is into a fixed-size table with a byte, or into a list of a
// length checked just before.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use anyhow::{Result, anyhow, bail, ensure};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const WORDLIST: &str = include_str!("slip39_wordlist.txt");
const RADIX_BITS: usize = 10;
const ID_BITS: usize = 15;
const CHECKSUM_WORDS: usize = 3;
const DIGEST_INDEX: u8 = 254;
const SECRET_INDEX: u8 = 255;
const DIGEST_BYTES: usize = 4;
const BASE_ITERATIONS: u32 = 10_000;
const ROUNDS: u8 = 4;
const MIN_SECRET_BYTES: usize = 16;
const MAX_SHARES: usize = 16;

static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| WORDLIST.lines().collect());
static INDEX: LazyLock<BTreeMap<&'static str, u16>> = LazyLock::new(|| {
    (0_u16..)
        .zip(WORDS.iter())
        .map(|(index, word)| (*word, index))
        .collect()
});

// ------------------------------------------------------------------ GF(256) --

struct Field {
    exp: [u8; 255],
    log: [u8; 256],
}

static FIELD: LazyLock<Field> = LazyLock::new(|| {
    let mut exp = [0_u8; 255];
    let mut log = [0_u8; 256];
    let mut poly: u16 = 1;
    for i in 0..255_u8 {
        exp[usize::from(i)] = u8::try_from(poly).unwrap_or(0);
        log[usize::from(poly)] = i;
        // Multiply by the generator 3, reducing by x^8 + x^4 + x^3 + x + 1.
        poly = (poly << 1) ^ poly;
        if poly & 0x100 != 0 {
            poly ^= 0x11B;
        }
    }
    Field { exp, log }
});

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let field = &*FIELD;
    let sum =
        (usize::from(field.log[usize::from(a)]) + usize::from(field.log[usize::from(b)])) % 255;
    field.exp[sum]
}

fn div(a: u8, b: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let field = &*FIELD;
    let difference = (usize::from(field.log[usize::from(a)]) + 255
        - usize::from(field.log[usize::from(b)]))
        % 255;
    field.exp[difference]
}

/// Lagrange interpolation at `x` over byte vectors, byte by byte.
fn interpolate(shares: &[(u8, Zeroizing<Vec<u8>>)], x: u8) -> Result<Zeroizing<Vec<u8>>> {
    let xs: BTreeSet<u8> = shares.iter().map(|(index, _)| *index).collect();
    ensure!(xs.len() == shares.len(), "share indices must be distinct");
    let length = shares.first().map_or(0, |(_, value)| value.len());
    ensure!(
        shares.iter().all(|(_, value)| value.len() == length),
        "all share values must have the same length"
    );
    if let Some((_, value)) = shares.iter().find(|(index, _)| *index == x) {
        return Ok(value.clone());
    }
    let mut result = Zeroizing::new(vec![0_u8; length]);
    for (i, (xi, yi)) in shares.iter().enumerate() {
        // The basis polynomial for point i, evaluated at x.
        let mut basis = 1_u8;
        for (j, (xj, _)) in shares.iter().enumerate() {
            if i != j {
                basis = mul(basis, div(x ^ xj, xi ^ xj));
            }
        }
        for (out, byte) in result.iter_mut().zip(yi.iter()) {
            *out ^= mul(basis, *byte);
        }
    }
    Ok(result)
}

fn digest(random: &[u8], secret: &[u8]) -> Result<[u8; DIGEST_BYTES]> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(random)
        .map_err(|_length| anyhow!("bad digest key"))?;
    mac.update(secret);
    let full = mac.finalize().into_bytes();
    let mut out = [0; DIGEST_BYTES];
    out.copy_from_slice(&full[..DIGEST_BYTES]);
    Ok(out)
}

fn random_bytes(count: usize) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0; count]);
    rand::fill(&mut bytes[..]);
    bytes
}

fn split_secret(
    threshold: usize,
    count: usize,
    secret: &[u8],
) -> Result<Vec<(u8, Zeroizing<Vec<u8>>)>> {
    ensure!(
        0 < threshold && threshold <= count && count <= MAX_SHARES,
        "invalid threshold or share count"
    );
    let indices = (0_u8..).take(count);
    if threshold == 1 {
        return Ok(indices
            .map(|index| (index, Zeroizing::new(secret.to_vec())))
            .collect());
    }
    let random = random_bytes(secret.len() - DIGEST_BYTES);
    let mut digest_share = Zeroizing::new(digest(&random, secret)?.to_vec());
    digest_share.extend_from_slice(&random);
    let mut base: Vec<(u8, Zeroizing<Vec<u8>>)> = (0_u8..)
        .take(threshold - 2)
        .map(|index| (index, random_bytes(secret.len())))
        .collect();
    base.push((DIGEST_INDEX, digest_share));
    base.push((SECRET_INDEX, Zeroizing::new(secret.to_vec())));
    let mut shares: Vec<(u8, Zeroizing<Vec<u8>>)> =
        base.iter().take(threshold - 2).cloned().collect();
    for index in (0_u8..).take(count).skip(threshold - 2) {
        shares.push((index, interpolate(&base, index)?));
    }
    Ok(shares)
}

fn recover_secret(
    threshold: usize,
    shares: &[(u8, Zeroizing<Vec<u8>>)],
) -> Result<Zeroizing<Vec<u8>>> {
    if threshold == 1 {
        return shares
            .first()
            .map(|(_, value)| value.clone())
            .ok_or_else(|| anyhow!("no share"));
    }
    let secret = interpolate(shares, SECRET_INDEX)?;
    let digest_share = interpolate(shares, DIGEST_INDEX)?;
    ensure!(digest_share.len() >= DIGEST_BYTES, "a share is too short");
    let (expected, random) = digest_share.split_at(DIGEST_BYTES);
    ensure!(
        digest(random, &secret)? == expected,
        "the shares do not combine: a word or a sheet is wrong"
    );
    Ok(secret)
}

// ------------------------------------------------------------- encryption --

fn round_function(
    round: u8,
    passphrase: &[u8],
    exponent: u8,
    salt: &[u8],
    right: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut password = Zeroizing::new(Vec::with_capacity(passphrase.len() + 1));
    password.push(round);
    password.extend_from_slice(passphrase);
    let mut salted = Vec::with_capacity(salt.len() + right.len());
    salted.extend_from_slice(salt);
    salted.extend_from_slice(right);
    let mut out = Zeroizing::new(vec![0; right.len()]);
    pbkdf2::pbkdf2_hmac::<Sha256>(
        &password,
        &salted,
        (BASE_ITERATIONS / u32::from(ROUNDS)) << exponent,
        &mut out,
    );
    out
}

fn salt(identifier: u16, extendable: bool) -> Vec<u8> {
    if extendable {
        Vec::new()
    } else {
        let mut salt = b"shamir".to_vec();
        salt.extend_from_slice(&identifier.to_be_bytes());
        salt
    }
}

fn feistel(
    input: &[u8],
    passphrase: &[u8],
    exponent: u8,
    identifier: u16,
    extendable: bool,
    rounds: &[u8],
) -> Zeroizing<Vec<u8>> {
    let half = input.len() / 2;
    let mut left = Zeroizing::new(input[..half].to_vec());
    let mut right = Zeroizing::new(input[half..].to_vec());
    let salt = salt(identifier, extendable);
    for round in rounds {
        let f = round_function(*round, passphrase, exponent, &salt, &right);
        let next: Zeroizing<Vec<u8>> =
            Zeroizing::new(left.iter().zip(f.iter()).map(|(a, b)| a ^ b).collect());
        left = right;
        right = next;
    }
    let mut out = Zeroizing::new(right.to_vec());
    out.extend_from_slice(&left);
    out
}

fn encrypt(
    master: &[u8],
    passphrase: &[u8],
    exponent: u8,
    identifier: u16,
    extendable: bool,
) -> Zeroizing<Vec<u8>> {
    feistel(
        master,
        passphrase,
        exponent,
        identifier,
        extendable,
        &[0, 1, 2, 3],
    )
}

fn decrypt(
    encrypted: &[u8],
    passphrase: &[u8],
    exponent: u8,
    identifier: u16,
    extendable: bool,
) -> Zeroizing<Vec<u8>> {
    feistel(
        encrypted,
        passphrase,
        exponent,
        identifier,
        extendable,
        &[3, 2, 1, 0],
    )
}

// ---------------------------------------------------------------- checksum --

fn polymod(values: &[u32]) -> u32 {
    const GEN: [u32; 10] = [
        0xe0_e040,
        0x1c1_c080,
        0x383_8100,
        0x707_0200,
        0xe0e_0009,
        0x1c0c_2412,
        0x3808_6c24,
        0x3090_fc48,
        0x21b1_f890,
        0x3f3_f120,
    ];
    let mut chk: u32 = 1;
    for value in values {
        let top = chk >> 20;
        chk = ((chk & 0xf_ffff) << 10) ^ value;
        for (i, generator) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

const fn customization(extendable: bool) -> &'static [u8] {
    if extendable {
        b"shamir_extendable"
    } else {
        b"shamir"
    }
}

fn checksum(extendable: bool, data: &[u32]) -> [u32; CHECKSUM_WORDS] {
    let mut values: Vec<u32> = customization(extendable)
        .iter()
        .map(|byte| u32::from(*byte))
        .collect();
    values.extend_from_slice(data);
    values.extend_from_slice(&[0; CHECKSUM_WORDS]);
    let value = polymod(&values) ^ 1;
    [(value >> 20) & 1023, (value >> 10) & 1023, value & 1023]
}

fn checksum_ok(extendable: bool, words: &[u32]) -> bool {
    let mut values: Vec<u32> = customization(extendable)
        .iter()
        .map(|byte| u32::from(*byte))
        .collect();
    values.extend_from_slice(words);
    polymod(&values) == 1
}

// ------------------------------------------------------------------ shares --

/// One decoded share.
#[derive(Clone, Debug)]
struct Share {
    identifier: u16,
    extendable: bool,
    exponent: u8,
    group_index: u8,
    group_threshold: u8,
    group_count: u8,
    member_index: u8,
    member_threshold: u8,
    value: Zeroizing<Vec<u8>>,
}

/// A bit writer over 10-bit words.
struct Bits {
    words: Vec<u32>,
    accumulator: u64,
    count: usize,
}

impl Bits {
    const fn new() -> Self {
        Self {
            words: Vec::new(),
            accumulator: 0,
            count: 0,
        }
    }

    fn push(&mut self, value: u64, bits: usize) {
        self.accumulator = (self.accumulator << bits) | value;
        self.count += bits;
        while self.count >= RADIX_BITS {
            self.count -= RADIX_BITS;
            self.words
                .push(u32::try_from((self.accumulator >> self.count) & 1023).unwrap_or(0));
        }
        self.accumulator &= (1 << self.count) - 1;
    }
}

impl Share {
    fn to_words(&self) -> Vec<u32> {
        let mut bits = Bits::new();
        bits.push(u64::from(self.identifier), ID_BITS);
        bits.push(u64::from(self.extendable), 1);
        bits.push(u64::from(self.exponent), 4);
        bits.push(u64::from(self.group_index), 4);
        bits.push(u64::from(self.group_threshold - 1), 4);
        bits.push(u64::from(self.group_count - 1), 4);
        bits.push(u64::from(self.member_index), 4);
        bits.push(u64::from(self.member_threshold - 1), 4);
        let value_bits = self.value.len() * 8;
        let padding = (RADIX_BITS - value_bits % RADIX_BITS) % RADIX_BITS;
        bits.push(0, padding);
        for byte in self.value.iter() {
            bits.push(u64::from(*byte), 8);
        }
        let mut words = bits.words;
        let sum = checksum(self.extendable, &words);
        words.extend_from_slice(&sum);
        words
    }

    fn mnemonic(&self) -> Zeroizing<String> {
        let words: Vec<&str> = self
            .to_words()
            .iter()
            .map(|index| WORDS.get(*index as usize).copied().unwrap_or(""))
            .collect();
        Zeroizing::new(words.join(" "))
    }

    fn parse(mnemonic: &str) -> Result<Self> {
        let words: Vec<u32> = mnemonic
            .split_whitespace()
            .map(|word| {
                INDEX
                    .get(word.to_ascii_lowercase().as_str())
                    .map(|index| u32::from(*index))
                    .ok_or_else(|| anyhow!("\"{word}\" is not a recovery word"))
            })
            .collect::<Result<_>>()?;
        ensure!(words.len() >= 20, "a sheet has at least 20 words");
        let id_and_exponent = (words[0] << 10) | words[1];
        let identifier = u16::try_from(id_and_exponent >> 5).unwrap_or(0);
        let extendable = (id_and_exponent >> 4) & 1 == 1;
        let exponent = u8::try_from(id_and_exponent & 15).unwrap_or(0);
        ensure!(
            checksum_ok(extendable, &words),
            "the sheet's checksum does not match: a word is wrong"
        );
        let fields = (words[2] << 10) | words[3];
        let nibble = |shift: u32| u8::try_from((fields >> shift) & 15).unwrap_or(0);
        let group_index = nibble(16);
        let group_threshold = nibble(12) + 1;
        let group_count = nibble(8) + 1;
        let member_index = nibble(4);
        let member_threshold = nibble(0) + 1;
        ensure!(
            group_count >= group_threshold,
            "a sheet's group threshold is above its group count"
        );
        let value_words = &words[4..words.len() - CHECKSUM_WORDS];
        let padding = value_words.len() * RADIX_BITS % 16;
        ensure!(padding <= 8, "a sheet has the wrong number of words");
        let mut bits: u128 = 0;
        let mut count = 0_usize;
        let mut value = Zeroizing::new(Vec::new());
        let mut skipped = 0_usize;
        for word in value_words {
            bits = (bits << RADIX_BITS) | u128::from(*word);
            count += RADIX_BITS;
            if skipped < padding {
                let take = (padding - skipped).min(count);
                ensure!(bits >> (count - take) == 0, "a sheet's padding is not zero");
                count -= take;
                bits &= (1 << count) - 1;
                skipped += take;
            }
            while count >= 8 {
                count -= 8;
                value.push(u8::try_from((bits >> count) & 0xff).unwrap_or(0));
                bits &= (1 << count) - 1;
            }
        }
        ensure!(
            value.len() >= MIN_SECRET_BYTES,
            "a sheet's secret is too short"
        );
        Ok(Self {
            identifier,
            extendable,
            exponent,
            group_index,
            group_threshold,
            group_count,
            member_index,
            member_threshold,
            value,
        })
    }
}

fn check_passphrase(passphrase: &str) -> Result<()> {
    ensure!(
        passphrase.bytes().all(|byte| (32..=126).contains(&byte)),
        "the passphrase is printable ASCII only"
    );
    Ok(())
}

/// Splits a master secret into mnemonics: one group, `threshold` of `count`,
/// encrypted with `passphrase`. Returns one mnemonic per share.
///
/// # Errors
///
/// Returns an error for an invalid threshold, a secret of the wrong length,
/// or a passphrase that is not printable ASCII.
pub fn split(
    master: &[u8],
    passphrase: &str,
    threshold: u8,
    count: u8,
    exponent: u8,
) -> Result<Vec<Zeroizing<String>>> {
    check_passphrase(passphrase)?;
    ensure!(
        master.len() >= MIN_SECRET_BYTES && master.len().is_multiple_of(2),
        "the secret is at least 16 bytes, an even number"
    );
    ensure!(
        !(threshold == 1 && count > 1),
        "a threshold of 1 with several shares gives nothing"
    );
    ensure!(exponent < 16, "the iteration exponent is at most 15");
    let mut id = [0_u8; 2];
    rand::fill(&mut id[..]);
    let identifier = u16::from_be_bytes(id) & 0x7fff;
    let encrypted = encrypt(master, passphrase.as_bytes(), exponent, identifier, true);
    let groups = split_secret(1, 1, &encrypted)?;
    let mut mnemonics = Vec::new();
    for (group_index, group_value) in groups {
        for (member_index, value) in
            split_secret(usize::from(threshold), usize::from(count), &group_value)?
        {
            let share = Share {
                identifier,
                extendable: true,
                exponent,
                group_index,
                group_threshold: 1,
                group_count: 1,
                member_index,
                member_threshold: threshold,
                value,
            };
            mnemonics.push(share.mnemonic());
        }
    }
    Ok(mnemonics)
}

/// Combines mnemonics back into the master secret with the passphrase.
///
/// # Errors
///
/// Returns an error when a word or checksum is wrong, the sheets do not
/// belong together, or there are too few of them.
pub fn combine(mnemonics: &[&str], passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    check_passphrase(passphrase)?;
    let shares: Vec<Share> = mnemonics
        .iter()
        .map(|mnemonic| Share::parse(mnemonic))
        .collect::<Result<_>>()?;
    let first = shares.first().ok_or_else(|| anyhow!("no sheet given"))?;
    for share in &shares {
        ensure!(
            share.identifier == first.identifier
                && share.extendable == first.extendable
                && share.exponent == first.exponent
                && share.group_threshold == first.group_threshold
                && share.group_count == first.group_count
                && share.value.len() == first.value.len(),
            "these sheets are not from the same set"
        );
    }
    let mut groups: BTreeMap<u8, Vec<&Share>> = BTreeMap::new();
    for share in &shares {
        groups.entry(share.group_index).or_default().push(share);
    }
    ensure!(
        groups.len() == usize::from(first.group_threshold),
        "the wrong number of groups was given"
    );
    let mut group_values = Vec::new();
    for (group_index, members) in groups {
        let threshold = members.first().map_or(0, |share| share.member_threshold);
        ensure!(
            members
                .iter()
                .all(|share| share.member_threshold == threshold),
            "sheets of one group disagree on the threshold"
        );
        let indices: BTreeSet<u8> = members.iter().map(|share| share.member_index).collect();
        ensure!(
            indices.len() == members.len(),
            "the same sheet was given twice"
        );
        if members.len() != usize::from(threshold) {
            bail!("{} of {threshold} needed sheets were given", members.len());
        }
        let points: Vec<(u8, Zeroizing<Vec<u8>>)> = members
            .iter()
            .map(|share| (share.member_index, share.value.clone()))
            .collect();
        group_values.push((
            group_index,
            recover_secret(usize::from(threshold), &points)?,
        ));
    }
    let encrypted = recover_secret(usize::from(first.group_threshold), &group_values)?;
    Ok(decrypt(
        &encrypted,
        passphrase.as_bytes(),
        first.exponent,
        first.identifier,
        first.extendable,
    ))
}

/// Random words from the SLIP-39 list, for the recovery card: lowercase
/// letters only, so the card is already in canonical form. Each word is ten
/// bits.
#[must_use]
pub fn random_words(count: usize) -> Vec<&'static str> {
    (0..count)
        .map(|_| {
            let mut bytes = [0_u8; 2];
            rand::fill(&mut bytes[..]);
            WORDS
                .get(usize::from(u16::from_be_bytes(bytes) & 1023))
                .copied()
                .unwrap_or("academic")
        })
        .collect()
}

/// The share value on one sheet, the input its root key is derived from
/// (study section 5).
///
/// # Errors
///
/// Returns an error when the mnemonic is malformed.
pub fn share_value(mnemonic: &str) -> Result<Zeroizing<Vec<u8>>> {
    Ok(Share::parse(mnemonic)?.value)
}

/// The member index on a sheet: which of the three root keys it derives.
///
/// # Errors
///
/// Returns an error when the mnemonic is malformed.
pub fn share_index(mnemonic: &str) -> Result<u8> {
    Ok(Share::parse(mnemonic)?.member_index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wordlist_is_the_standard_one() {
        assert_eq!(WORDS.len(), 1024);
        assert_eq!(WORDS[0], "academic");
        assert_eq!(WORDS[1023], "zero");
    }

    #[test]
    fn every_reference_vector_behaves_as_the_reference_implementation() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/slip39/vectors.json"
        ))
        .unwrap();
        let vectors: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();
        assert_eq!(vectors.len(), 45);
        for vector in vectors {
            let name = vector[0].as_str().unwrap();
            let mnemonics: Vec<&str> = vector[1]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m.as_str().unwrap())
                .collect();
            let expected = vector[2].as_str().unwrap();
            let result = combine(&mnemonics, "TREZOR");
            if expected.is_empty() {
                assert!(result.is_err(), "{name} should fail");
            } else {
                let secret = result.unwrap_or_else(|error| panic!("{name}: {error}"));
                assert_eq!(data_encoding::HEXLOWER.encode(&secret), expected, "{name}");
            }
        }
    }

    #[test]
    fn two_of_three_sheets_recombine_and_one_does_not() {
        let master = [7_u8; 32];
        let card = "apple river stone cloud maple tiger";
        let sheets = split(&master, card, 2, 3, 1).unwrap();
        assert_eq!(sheets.len(), 3);
        assert!(
            sheets
                .iter()
                .all(|sheet| sheet.split_whitespace().count() == 33)
        );
        for (a, b) in [(0, 1), (0, 2), (2, 1)] {
            let recovered = combine(&[&sheets[a], &sheets[b]], card).unwrap();
            assert_eq!(&recovered[..], &master);
        }
        assert!(combine(&[&sheets[0]], card).is_err());
        assert_ne!(
            &combine(&[&sheets[0], &sheets[1]], "another card").unwrap()[..],
            &master
        );
        assert_eq!(share_index(&sheets[2]).unwrap(), 2);
        // A changed word breaks the checksum.
        let mut words: Vec<&str> = sheets[0].split_whitespace().collect();
        words[10] = if words[10] == "academic" {
            "acid"
        } else {
            "academic"
        };
        assert!(combine(&[&words.join(" "), &sheets[1]], card).is_err());
    }

    /// Writes sheets for a cross-check with the reference implementation:
    /// `TXC_SLIP39_OUT=file cargo test -- --ignored slip39_sheets_for`.
    #[test]
    #[ignore = "writes sheets for an external cross-check"]
    fn slip39_sheets_for_the_reference_implementation() {
        let path = std::env::var("TXC_SLIP39_OUT").unwrap();
        let sheets = split(&[0x42; 32], "apple river stone cloud maple tiger", 2, 3, 1).unwrap();
        let text: Vec<String> = sheets.iter().map(|sheet| sheet.to_string()).collect();
        std::fs::write(path, text.join("\n")).unwrap();
    }
}
