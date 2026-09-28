//! The canonical encoding every vault format shares: fixed-size fields as
//! they are, integers big-endian, and everything of variable size behind a
//! 64-bit length. Readers refuse short input, oversized counts and trailing
//! bytes, so each value has exactly one encoding.

// Every slice is of a length checked just before it.
#![allow(clippy::indexing_slicing)]

use anyhow::{Result, anyhow, ensure};

use crate::vault::object::MAX_OBJECT_BYTES;

/// Builds a canonical encoding.
#[derive(Default)]
pub struct Writer(pub Vec<u8>);

impl Writer {
    /// One byte.
    pub fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    /// A 64-bit integer.
    pub fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    /// Bytes of a size both sides know.
    pub fn fixed(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
    /// Bytes behind their length.
    pub fn bytes(&mut self, bytes: &[u8]) {
        self.u64(bytes.len() as u64);
        self.0.extend_from_slice(bytes);
    }
    /// A count of items that follow.
    pub fn count(&mut self, count: usize) {
        self.u64(count as u64);
    }
    /// A flag.
    pub fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }
    /// Text, as UTF-8 behind its length.
    pub fn str(&mut self, text: &str) {
        self.bytes(text.as_bytes());
    }
    /// The encoding.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

/// Reads a canonical encoding.
pub struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    /// The next `count` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when fewer remain.
    pub fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= count, "the encoding ends early");
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(head)
    }
    /// One byte.
    ///
    /// # Errors
    ///
    /// Returns an error when none remains.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    /// A 64-bit integer.
    ///
    /// # Errors
    ///
    /// Returns an error when too few bytes remain.
    pub fn u64(&mut self) -> Result<u64> {
        let mut word = [0; 8];
        word.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(word))
    }
    /// Bytes of a size both sides know.
    ///
    /// # Errors
    ///
    /// Returns an error when too few bytes remain.
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
    /// A count of items, at most `limit`.
    ///
    /// # Errors
    ///
    /// Returns an error when the count is above the limit.
    pub fn count(&mut self, limit: usize) -> Result<usize> {
        let count =
            usize::try_from(self.u64()?).map_err(|_count| anyhow!("a count is too large"))?;
        ensure!(count <= limit, "a count is larger than any object has");
        Ok(count)
    }
    /// Bytes behind their length.
    ///
    /// # Errors
    ///
    /// Returns an error when the length is too large or too few bytes remain.
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let count = self.count(MAX_OBJECT_BYTES)?;
        self.take(count)
    }
    /// A flag, 0 or 1 only.
    ///
    /// # Errors
    ///
    /// Returns an error for any other byte.
    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(anyhow!("a flag is {other}")),
        }
    }
    /// Text of at most `limit` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when it is longer or not UTF-8.
    pub fn str(&mut self, limit: usize) -> Result<String> {
        let bytes = self.bytes()?;
        ensure!(bytes.len() <= limit, "a text field is too long");
        Ok(std::str::from_utf8(bytes)
            .map_err(|_error| anyhow!("a text field is not UTF-8"))?
            .to_owned())
    }
    /// Checks that nothing is left.
    ///
    /// # Errors
    ///
    /// Returns an error when bytes remain.
    pub fn finish(self) -> Result<()> {
        ensure!(self.0.is_empty(), "the encoding has trailing bytes");
        Ok(())
    }
}
