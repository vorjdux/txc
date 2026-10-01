//! One-time codes from a stored TOTP seed (RFC 6238 over RFC 4226), so a
//! vault that holds the seed also answers the second factor. The seed stays
//! sealed like any secret; only the code, valid for seconds, is shown.
//!
//! A seed is either the base32 secret sites show, or an `otpauth://` URI,
//! whose `secret`, `digits`, `period` and `algorithm` are honoured.

// Protocol code: no unsafe block, and no module-level exception either.
#![forbid(unsafe_code)]

use anyhow::{Context as _, Result, bail, ensure};
use hmac::{Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

/// The hash a code is computed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed seed.
#[derive(Debug, PartialEq, Eq)]
struct Seed {
    key: Zeroizing<Vec<u8>>,
    digits: u32,
    period: u64,
    algorithm: Algorithm,
}

fn base32(text: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    ensure!(!cleaned.is_empty(), "the TOTP seed is empty");
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
    spec.check_trailing_bits = false;
    let encoding = spec
        .encoding()
        .map_err(|_error| anyhow::anyhow!("cannot build the base32 decoder"))?;
    Ok(Zeroizing::new(
        encoding
            .decode(cleaned.as_bytes())
            .context("the TOTP seed is not base32")?,
    ))
}

fn parse(text: &str) -> Result<Seed> {
    let text = text.trim();
    let mut seed = Seed {
        key: Zeroizing::new(Vec::new()),
        digits: 6,
        period: 30,
        algorithm: Algorithm::Sha1,
    };
    let Some(rest) = text.strip_prefix("otpauth://") else {
        seed.key = base32(text)?;
        return Ok(seed);
    };
    let (kind, query) = rest
        .split_once('?')
        .context("an otpauth URI has parameters after '?'")?;
    ensure!(
        kind.to_ascii_lowercase().starts_with("totp"),
        "only time-based (totp) codes are supported"
    );
    let mut secret = None;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = urlencoding::decode(value)
            .map_or_else(|_| value.to_owned(), std::borrow::Cow::into_owned);
        match name.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(Zeroizing::new(value)),
            "digits" => {
                seed.digits = value.parse().context("digits is not a number")?;
                ensure!((6..=10).contains(&seed.digits), "a code has 6 to 10 digits");
            }
            "period" => {
                seed.period = value.parse().context("period is not a number")?;
                ensure!(seed.period > 0, "the period is at least a second");
            }
            "algorithm" => {
                seed.algorithm = match value.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    other => bail!("unknown TOTP algorithm {other}"),
                }
            }
            _ => {}
        }
    }
    seed.key = base32(&secret.context("the otpauth URI has no secret")?)?;
    Ok(seed)
}

fn hotp(seed: &Seed, counter: u64) -> Result<String> {
    let message = counter.to_be_bytes();
    let digest: Vec<u8> = match seed.algorithm {
        Algorithm::Sha1 => {
            let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&seed.key)?;
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&seed.key)?;
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut mac = Hmac::<sha2::Sha512>::new_from_slice(&seed.key)?;
            mac.update(&message);
            mac.finalize().into_bytes().to_vec()
        }
    };
    let offset = usize::from(digest.last().copied().unwrap_or(0) & 0x0f);
    let window: [u8; 4] = digest
        .get(offset..offset.saturating_add(4))
        .and_then(|bytes| bytes.try_into().ok())
        .context("the digest is too short")?;
    let number = u32::from_be_bytes(window) & 0x7fff_ffff;
    let modulus = 10_u64.pow(seed.digits);
    let code = u64::from(number)
        .checked_rem(modulus)
        .context("a code has 6 to 10 digits")?;
    Ok(format!("{code:0width$}", width = seed.digits as usize))
}

/// The code for `now`, and how many seconds it stays valid.
///
/// # Errors
///
/// Returns an error when the seed is neither base32 nor an otpauth URI.
pub fn code(seed: &str, now: u64) -> Result<(String, u64)> {
    let seed = parse(seed)?;
    let counter = now.checked_div(seed.period).unwrap_or(0);
    let left = seed
        .period
        .saturating_sub(now.checked_rem(seed.period).unwrap_or(0));
    Ok((hotp(&seed, counter)?, left))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238, appendix B: the ASCII seeds "12345678901234567890" and its
    // longer forms, eight digits.
    const SHA1: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const SHA256: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const SHA512: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    fn uri(secret: &str, algorithm: &str) -> String {
        format!(
            "otpauth://totp/Example:alice?secret={secret}&algorithm={algorithm}&digits=8&period=30"
        )
    }

    #[test]
    fn the_rfc_6238_vectors_hold() {
        for (time, sha1, sha256, sha512) in [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ] {
            assert_eq!(code(&uri(SHA1, "SHA1"), time).unwrap().0, sha1);
            assert_eq!(code(&uri(SHA256, "SHA256"), time).unwrap().0, sha256);
            assert_eq!(code(&uri(SHA512, "SHA512"), time).unwrap().0, sha512);
        }
    }

    #[test]
    fn a_bare_seed_gives_six_digits_for_thirty_seconds() {
        let (code_now, left) = code("jbsw y3dp ehpk 3pxp", 45).unwrap();
        assert_eq!(code_now.len(), 6);
        assert_eq!(left, 15);
        assert_eq!(code("JBSWY3DPEHPK3PXP", 31).unwrap().0, code_now);
        assert!(code("not base32 !", 0).is_err());
        assert!(code("otpauth://hotp/x?secret=JBSWY3DP", 0).is_err());
        assert!(code("otpauth://totp/x?digits=6", 0).is_err());
    }
}
