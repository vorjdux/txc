//! Offline breach checks (study phase 8): is a password in the Pwned
//! Passwords list? Nothing leaves the device: the list is imported once
//! into a Bloom filter kept in the txc home, and each password's SHA-1 is
//! looked up in it with a few positioned reads, never loading the file.
//!
//! The filter holds no secret: it is built from a public list. A match is
//! "probably breached" (about one in a hundred false alarms at the default
//! size); a password that does not match is certainly not in the list.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use sha1::{Digest, Sha1};

const MAGIC: &[u8; 20] = b"txc-breach-filter-v1";
/// Bits per hash in the filter: about 1% false positives with 7 probes.
const BITS_PER_ITEM: u64 = 10;
const PROBES: u8 = 7;
const HEADER: u64 = 20 + 8 + 1 + 8;
/// The name of the filter in the txc home.
pub const FILE_NAME: &str = "breach.filter";

/// The positions a hash sets, by double hashing two 64-bit halves of the
/// SHA-1, which is already uniform.
fn positions(hash: &[u8; 20], bits: u64, probes: u8) -> impl Iterator<Item = u64> {
    let mut first = [0; 8];
    first.copy_from_slice(&hash[..8]);
    let mut second = [0; 8];
    second.copy_from_slice(&hash[8..16]);
    let (a, b) = (u64::from_be_bytes(first), u64::from_be_bytes(second) | 1);
    (0..u64::from(probes)).map(move |i| {
        a.wrapping_add(i.wrapping_mul(b))
            .checked_rem(bits)
            .unwrap_or(0)
    })
}

fn parse_hash(line: &str) -> Option<[u8; 20]> {
    let hex = line.split(':').next()?.trim();
    let bytes = data_encoding::HEXUPPER_PERMISSIVE
        .decode(hex.as_bytes())
        .ok()?;
    bytes.try_into().ok()
}

/// What an import found.
#[derive(Debug, PartialEq, Eq)]
pub struct Imported {
    /// Hashes added.
    pub hashes: u64,
    /// Lines that were not a SHA-1 hash.
    pub skipped: u64,
    /// The filter's size in bytes.
    pub bytes: u64,
}

/// Builds a filter from a Pwned Passwords SHA-1 list, one `HASH` or
/// `HASH:COUNT` per line, written to `output` (replacing it). The list is
/// read twice, to size the filter first.
///
/// # Errors
///
/// Returns an error when the list cannot be read, holds no hash, or the
/// filter cannot be written.
pub fn import(list: &Path, output: &Path) -> Result<Imported> {
    let open = || -> Result<BufReader<File>> {
        Ok(BufReader::with_capacity(
            1 << 20,
            File::open(list).with_context(|| format!("cannot read {}", list.display()))?,
        ))
    };
    let mut count = 0_u64;
    for line in open()?.lines() {
        if parse_hash(&line?).is_some() {
            count = count.saturating_add(1);
        }
    }
    ensure!(count > 0, "{} holds no SHA-1 hash", list.display());
    let bits = count.saturating_mul(BITS_PER_ITEM).max(64);
    let length =
        usize::try_from(bits.div_ceil(8)).context("the filter is too large for this computer")?;
    let mut filter = vec![0_u8; length];
    let mut skipped = 0_u64;
    for line in open()?.lines() {
        let Some(hash) = parse_hash(&line?) else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        for position in positions(&hash, bits, PROBES) {
            let byte = usize::try_from(position / 8).unwrap_or(0);
            if let Some(slot) = filter.get_mut(byte) {
                *slot |= 1 << (position % 8);
            }
        }
    }
    let temporary = output.with_extension("filter.tmp");
    {
        let mut file = std::io::BufWriter::new(File::create(&temporary)?);
        file.write_all(MAGIC)?;
        file.write_all(&bits.to_be_bytes())?;
        file.write_all(&[PROBES])?;
        file.write_all(&count.to_be_bytes())?;
        file.write_all(&filter)?;
        file.flush()?;
        file.get_ref().sync_all()?;
    }
    std::fs::rename(&temporary, output)?;
    Ok(Imported {
        hashes: count,
        skipped,
        bytes: HEADER.saturating_add(length as u64),
    })
}

/// An imported filter, opened for lookups.
pub struct Filter {
    file: File,
    bits: u64,
    probes: u8,
    /// How many hashes it was built from.
    pub hashes: u64,
}

impl Filter {
    /// Opens a filter.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is not a txc breach filter.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path).with_context(|| {
            "no breach list imported; see: txc vault breach import --help".to_owned()
        })?;
        let mut header = [0_u8; 37];
        file.read_exact(&mut header)
            .map_err(|_error| anyhow!("the breach filter is damaged"))?;
        ensure!(header.starts_with(MAGIC), "not a txc breach filter");
        let word = |at: usize| -> u64 {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(header.get(at..at.saturating_add(8)).unwrap_or(&[0; 8]));
            u64::from_be_bytes(bytes)
        };
        let (bits, probes, hashes) = (word(20), header[28], word(29));
        ensure!(bits >= 64 && probes > 0, "the breach filter is damaged");
        let expected = HEADER.saturating_add(bits.div_ceil(8));
        ensure!(
            file.metadata()?.len() == expected,
            "the breach filter is damaged"
        );
        Ok(Self {
            file,
            bits,
            probes,
            hashes,
        })
    }

    fn bit(&mut self, position: u64) -> Result<bool> {
        self.file
            .seek(SeekFrom::Start(HEADER.saturating_add(position / 8)))?;
        let mut byte = [0_u8; 1];
        self.file.read_exact(&mut byte)?;
        Ok(byte[0] & (1 << (position % 8)) != 0)
    }

    /// Whether a password is probably in the list.
    ///
    /// # Errors
    ///
    /// Returns an error when the filter cannot be read.
    pub fn contains(&mut self, password: &[u8]) -> Result<bool> {
        let hash: [u8; 20] = Sha1::digest(password).into();
        for position in positions(&hash, self.bits, self.probes).collect::<Vec<_>>() {
            if !self.bit(position)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Refuses a list that is clearly not SHA-1 hashes, before a long import.
///
/// # Errors
///
/// Returns an error naming the problem.
pub fn check_list(list: &Path) -> Result<()> {
    let mut first = String::new();
    BufReader::new(File::open(list)?).read_line(&mut first)?;
    if parse_hash(&first).is_none() {
        bail!(
            "{} does not start with a SHA-1 hash; txc reads the Pwned Passwords SHA-1 list, \
             one HASH or HASH:COUNT per line",
            list.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;
    use crate::vault::test_support::Scratch;

    fn sha1_hex(text: &str) -> String {
        data_encoding::HEXUPPER.encode(&Sha1::digest(text.as_bytes()))
    }

    #[test]
    fn a_listed_password_is_found_and_others_mostly_are_not() {
        let scratch = Scratch::new("breach");
        std::fs::create_dir_all(&scratch.0).unwrap();
        let list = scratch.0.join("pwned.txt");
        let mut text = String::new();
        for index in 0..2_000 {
            writeln!(
                text,
                "{}:{}",
                sha1_hex(&format!("leaked-{index}")),
                index + 1
            )
            .unwrap();
        }
        write!(text, "{}:3861493\nnot a hash\n", sha1_hex("password")).unwrap();
        std::fs::write(&list, text).unwrap();
        check_list(&list).unwrap();

        let output = scratch.0.join(FILE_NAME);
        let imported = import(&list, &output).unwrap();
        assert_eq!((imported.hashes, imported.skipped), (2_001, 1));

        let mut filter = Filter::open(&output).unwrap();
        assert!(filter.contains(b"password").unwrap());
        assert!(filter.contains(b"leaked-1999").unwrap());
        let false_alarms = (0..2_000)
            .filter(|index| {
                filter
                    .contains(format!("fresh-{index}").as_bytes())
                    .unwrap()
            })
            .count();
        assert!(false_alarms < 60, "{false_alarms} false alarms in 2000");
    }

    #[test]
    fn a_damaged_or_foreign_filter_is_refused() {
        let scratch = Scratch::new("breach-bad");
        std::fs::create_dir_all(&scratch.0).unwrap();
        let path = scratch.0.join(FILE_NAME);
        std::fs::write(&path, b"something else entirely, and long enough").unwrap();
        assert!(Filter::open(&path).is_err());
        std::fs::write(scratch.0.join("list.txt"), "hello\n").unwrap();
        assert!(check_list(&scratch.0.join("list.txt")).is_err());
    }
}
