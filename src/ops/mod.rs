//! The operation implementations, grouped by category.

use crate::registry::Op;

pub mod case;
pub mod convert;
pub mod datetime;
pub mod encoding;
pub mod generate;
pub mod hashing;
pub mod inspect;
pub mod lines;
pub mod numbers;
pub mod text;

/// Collects every operation into the registry.
pub(crate) fn register(out: &mut Vec<Op>) {
    case::register(out);
    encoding::register(out);
    hashing::register(out);
    lines::register(out);
    text::register(out);
    numbers::register(out);
    convert::register(out);
    inspect::register(out);
    generate::register(out);
    datetime::register(out);
}

/// Splits text into words for case conversion.
///
/// Separators are any non alphanumeric character, and boundaries are also
/// recognised inside runs of letters, so `parseHTTPResponse` yields
/// `["parse", "HTTP", "Response"]`.
pub fn split_words(input: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = input.chars().collect();

    for (i, &ch) in chars.iter().enumerate() {
        if !ch.is_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            continue;
        }

        if !current.is_empty() {
            let prev = chars[i - 1];
            let lower_to_upper = (prev.is_lowercase() || prev.is_numeric()) && ch.is_uppercase();
            let acronym_end = prev.is_uppercase()
                && ch.is_uppercase()
                && chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            let letter_to_digit = prev.is_alphabetic() && ch.is_numeric();
            if lower_to_upper || acronym_end || letter_to_digit {
                words.push(std::mem::take(&mut current));
            }
        }
        current.push(ch);
    }

    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Uppercases the first character and leaves the rest untouched.
pub fn capitalize_first(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Uppercases the first character and lowercases the rest.
pub fn capitalize_only(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase(),
        None => String::new(),
    }
}

/// Renders bytes as hexadecimal.
pub fn to_hex(bytes: &[u8], upper: bool) -> String {
    const LOWER_DIGITS: &[u8; 16] = b"0123456789abcdef";
    const UPPER_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let digits = if upper { UPPER_DIGITS } else { LOWER_DIGITS };
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(digits[(byte >> 4) as usize] as char);
        out.push(digits[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Parses hexadecimal, ignoring whitespace and the common `0x` prefix.
pub fn from_hex(input: &str) -> anyhow::Result<Vec<u8>> {
    let cleaned: String = input
        .split_whitespace()
        .collect::<String>()
        .replace("0x", "")
        .replace("0X", "");
    if cleaned.len() % 2 != 0 {
        anyhow::bail!("hex input has an odd number of digits");
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let text = std::str::from_utf8(pair).unwrap_or_default();
        out.push(
            u8::from_str_radix(text, 16)
                .map_err(|_| anyhow::anyhow!("{text:?} is not a hex byte"))?,
        );
    }
    Ok(out)
}

/// Turns decoded bytes into text, with a clear message when they are not text.
pub fn bytes_to_string(bytes: Vec<u8>) -> anyhow::Result<String> {
    String::from_utf8(bytes).map_err(|e| {
        anyhow::anyhow!(
            "decoded bytes are not valid UTF-8 (byte {})",
            e.utf8_error().valid_up_to()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_separators_and_case_changes() {
        assert_eq!(split_words("hello world"), ["hello", "world"]);
        assert_eq!(split_words("helloWorld"), ["hello", "World"]);
        assert_eq!(
            split_words("parseHTTPResponse"),
            ["parse", "HTTP", "Response"]
        );
        assert_eq!(
            split_words("snake_case-kebab.dot"),
            ["snake", "case", "kebab", "dot"]
        );
        assert_eq!(
            split_words("version2Point0"),
            ["version", "2", "Point", "0"]
        );
        assert!(split_words("   ").is_empty());
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00, 0x7f, 0xff, 0x10];
        assert_eq!(to_hex(&bytes, false), "007fff10");
        assert_eq!(to_hex(&bytes, true), "007FFF10");
        assert_eq!(from_hex("00 7f ff 10").unwrap(), bytes);
        assert_eq!(from_hex("0x007fff10").unwrap(), bytes);
        assert!(from_hex("abc").is_err());
        assert!(from_hex("zz").is_err());
    }
}
