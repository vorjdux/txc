//! Checksums and cryptographic digests.

use digest::Digest;
use hmac::{Hmac, KeyInit, Mac};

use crate::ops::to_hex;
use crate::params::Params;
use crate::registry::{Category, Feed, Op, Param};

const CAT: Category = Category::Hash;

static P_FORMAT: &[Param] = &[
    Param::flag("upper", Some('u'), "Print the digest in uppercase hex"),
    Param::flag(
        "base64",
        Some('b'),
        "Print the digest as base64 instead of hex",
    ),
];

static P_CRC32: &[Param] = &[
    Param::flag("upper", Some('u'), "Print the checksum in uppercase hex"),
    Param::flag(
        "decimal",
        Some('d'),
        "Print the checksum as a decimal number",
    ),
];

static P_HMAC: &[Param] = &[
    Param::value(
        "key",
        Some('k'),
        "SECRET",
        "Secret key for the authentication code",
    )
    .suggest("secret"),
    Param::flag("upper", Some('u'), "Print the digest in uppercase hex"),
    Param::flag(
        "base64",
        Some('b'),
        "Print the digest as base64 instead of hex",
    ),
];

pub(crate) fn register(out: &mut Vec<Op>) {
    out.push(
        Op::new(
            "md5",
            CAT,
            Feed::Buffer,
            "MD5 digest of the input",
            |s, p| Ok(format_digest(&md5::Md5::digest(s.as_bytes()), p)),
        )
        .params(P_FORMAT)
        .examples(&["txc md5 \"hello\"", "txc md5 --file report.pdf"]),
    );

    out.push(
        Op::new(
            "sha1",
            CAT,
            Feed::Buffer,
            "SHA-1 digest of the input",
            |s, p| Ok(format_digest(&sha1::Sha1::digest(s.as_bytes()), p)),
        )
        .params(P_FORMAT),
    );

    out.push(
        Op::new(
            "sha224",
            CAT,
            Feed::Buffer,
            "SHA-224 digest of the input",
            |s, p| Ok(format_digest(&sha2::Sha224::digest(s.as_bytes()), p)),
        )
        .params(P_FORMAT),
    );

    out.push(
        Op::new(
            "sha256",
            CAT,
            Feed::Buffer,
            "SHA-256 digest of the input",
            |s, p| Ok(format_digest(&sha2::Sha256::digest(s.as_bytes()), p)),
        )
        .params(P_FORMAT)
        .examples(&["txc sha256 \"hello\"", "cat file | txc sha256"]),
    );

    out.push(
        Op::new(
            "sha384",
            CAT,
            Feed::Buffer,
            "SHA-384 digest of the input",
            |s, p| Ok(format_digest(&sha2::Sha384::digest(s.as_bytes()), p)),
        )
        .params(P_FORMAT),
    );

    out.push(
        Op::new(
            "sha512",
            CAT,
            Feed::Buffer,
            "SHA-512 digest of the input",
            |s, p| Ok(format_digest(&sha2::Sha512::digest(s.as_bytes()), p)),
        )
        .params(P_FORMAT),
    );

    out.push(
        Op::new(
            "sha3-256",
            CAT,
            Feed::Buffer,
            "SHA3-256 digest of the input",
            |s, p| Ok(format_digest(&sha3::Sha3_256::digest(s.as_bytes()), p)),
        )
        .params(P_FORMAT),
    );

    out.push(
        Op::new(
            "sha3-512",
            CAT,
            Feed::Buffer,
            "SHA3-512 digest of the input",
            |s, p| Ok(format_digest(&sha3::Sha3_512::digest(s.as_bytes()), p)),
        )
        .params(P_FORMAT),
    );

    out.push(
        Op::new(
            "keccak256",
            CAT,
            Feed::Buffer,
            "Keccak-256 digest of the input",
            |s, p| Ok(format_digest(&sha3::Keccak256::digest(s.as_bytes()), p)),
        )
        .params(P_FORMAT),
    );

    out.push(
        Op::new(
            "blake3",
            CAT,
            Feed::Buffer,
            "BLAKE3 digest of the input",
            |s, p| Ok(format_digest(blake3::hash(s.as_bytes()).as_bytes(), p)),
        )
        .params(P_FORMAT),
    );

    out.push(
        Op::new(
            "crc32",
            CAT,
            Feed::Buffer,
            "CRC32 checksum of the input",
            |s, p| {
                let checksum = crc32fast::hash(s.as_bytes());
                Ok(if p.flag("decimal") {
                    checksum.to_string()
                } else if p.flag("upper") {
                    format!("{checksum:08X}")
                } else {
                    format!("{checksum:08x}")
                })
            },
        )
        .params(P_CRC32)
        .examples(&["txc crc32 \"hello\""]),
    );

    out.push(
        Op::new(
            "hmac-sha256",
            CAT,
            Feed::Buffer,
            "HMAC-SHA256 authentication code of the input",
            |s, p| {
                let key = p.require("key")?;
                let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes())?;
                mac.update(s.as_bytes());
                Ok(format_digest(&mac.finalize().into_bytes(), p))
            },
        )
        .aliases(&["hmac"])
        .params(P_HMAC)
        .examples(&["txc hmac-sha256 --key s3cret \"payload\""]),
    );

    out.push(
        Op::new(
            "hmac-sha512",
            CAT,
            Feed::Buffer,
            "HMAC-SHA512 authentication code of the input",
            |s, p| {
                let key = p.require("key")?;
                let mut mac = Hmac::<sha2::Sha512>::new_from_slice(key.as_bytes())?;
                mac.update(s.as_bytes());
                Ok(format_digest(&mac.finalize().into_bytes(), p))
            },
        )
        .params(P_HMAC),
    );

    out.push(
        Op::new(
            "hmac-sha1",
            CAT,
            Feed::Buffer,
            "HMAC-SHA1 authentication code of the input",
            |s, p| {
                let key = p.require("key")?;
                let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key.as_bytes())?;
                mac.update(s.as_bytes());
                Ok(format_digest(&mac.finalize().into_bytes(), p))
            },
        )
        .params(P_HMAC),
    );
}

/// Renders a digest as hex or base64, according to the shared format flags.
fn format_digest(bytes: &[u8], p: &Params) -> String {
    if p.flag("base64") {
        data_encoding::BASE64.encode(bytes)
    } else {
        to_hex(bytes, p.flag("upper"))
    }
}

#[cfg(test)]
mod tests {
    use crate::params::Params;
    use crate::registry::find;

    fn run_with(name: &str, input: &str, options: &str) -> String {
        let op = find(name).expect("operation is registered");
        let params = Params::parse_kv(op, options).expect("options parse");
        op.apply(input, &params, None).expect("runs")
    }

    fn run(name: &str, input: &str) -> String {
        run_with(name, input, "")
    }

    #[test]
    fn known_digests() {
        assert_eq!(run("md5", "hello"), "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(
            run("sha1", "hello"),
            "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        );
        assert_eq!(
            run("sha256", "hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(run("crc32", "hello"), "3610a686");
        assert_eq!(
            run("blake3", "hello"),
            "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
        );
    }

    #[test]
    fn empty_input_still_hashes() {
        assert_eq!(run("md5", ""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn output_formats() {
        assert_eq!(
            run_with("md5", "hello", "upper"),
            "5D41402ABC4B2A76B9719D911017C592"
        );
        assert_eq!(
            run_with("md5", "hello", "base64"),
            "XUFAKrxLKna5cZ2REBfFkg=="
        );
    }

    #[test]
    fn hmac_matches_reference_vector() {
        // RFC 4231 test case 1.
        let op = find("hmac-sha256").unwrap();
        let mut params = Params::for_op(op);
        params.set("key", "\u{b}".repeat(20));
        let digest = op.apply("Hi There", &params, None).unwrap();
        assert_eq!(
            digest,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_requires_a_key() {
        let op = find("hmac-sha256").unwrap();
        let error = op
            .apply("payload", &Params::for_op(op), None)
            .expect_err("key is required")
            .to_string();
        assert!(error.contains("--key"));
    }
}
