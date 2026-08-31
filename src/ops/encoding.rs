//! Encoding, decoding and classic ciphers.

use anyhow::{bail, Context, Result};
use data_encoding::{BASE32, BASE32_NOPAD, BASE64, BASE64URL, BASE64URL_NOPAD, BASE64_NOPAD};

use crate::ops::{bytes_to_string, from_hex, to_hex};
use crate::params::Params;
use crate::registry::{Category, Feed, Op, Param};

const CAT: Category = Category::Encode;

const UPPER: Param = Param::flag("upper", Some('u'), "Use uppercase output");
const SEP: Param = Param::valued("sep", Some('s'), "TEXT", " ", "Separator between values");
const URL_SAFE: Param = Param::flag("url-safe", None, "Use the URL and filename safe alphabet");
const NO_PAD: Param = Param::flag("no-pad", None, "Omit the = padding characters");

// Parameter tables live in statics so the registry can borrow them for the
// whole run of the program.
static P_HTML_QUOTES: &[Param] = &[Param::flag(
    "quotes",
    Some('q'),
    "Also escape single and double quotes",
)];
static P_JSON_QUOTES: &[Param] = &[Param::flag(
    "quotes",
    Some('q'),
    "Keep the surrounding double quotes",
)];
static P_BASE64: &[Param] = &[URL_SAFE, NO_PAD];
static P_NO_PAD: &[Param] = &[NO_PAD];
static P_HEX: &[Param] = &[
    UPPER,
    Param::value("sep", Some('s'), "TEXT", "Separator between bytes"),
];
static P_SEP: &[Param] = &[SEP];
static P_SHIFT: &[Param] = &[Param::valued(
    "shift",
    None,
    "N",
    "3",
    "Number of places to shift",
)];
static P_ESCAPE_ALL: &[Param] = &[Param::flag(
    "all",
    Some('a'),
    "Escape ASCII characters as well",
)];

// The base64 alphabets are exposed as constants by data-encoding; binding them
// to statics lets the selector hand back a borrow instead of a copy.
static B64_STD: data_encoding::Encoding = BASE64;
static B64_STD_NOPAD: data_encoding::Encoding = BASE64_NOPAD;
static B64_URL: data_encoding::Encoding = BASE64URL;
static B64_URL_NOPAD: data_encoding::Encoding = BASE64URL_NOPAD;

pub(crate) fn register(out: &mut Vec<Op>) {
    // ---------------------------------------------------------------- URL
    out.push(
        Op::new(
            "url-encode",
            CAT,
            Feed::Lines,
            "Percent-encode text for URLs",
            |s, _| Ok(urlencoding::encode(s).into_owned()),
        )
        .aliases(&["ue", "urlencode"])
        .examples(&["txc url-encode \"a b&c\"", "echo \"a b&c\" | txc ue"]),
    );

    out.push(
        Op::new(
            "url-decode",
            CAT,
            Feed::Lines,
            "Decode percent-encoded URL text",
            |s, _| {
                Ok(urlencoding::decode(s)
                    .context("input is not valid percent-encoded text")?
                    .into_owned())
            },
        )
        .aliases(&["ud", "urldecode"])
        .examples(&["txc url-decode \"a%20b%26c\""]),
    );

    // --------------------------------------------------------------- HTML
    out.push(
        Op::new(
            "html-encode",
            CAT,
            Feed::Lines,
            "Escape HTML special characters",
            |s, p| {
                Ok(if p.flag("quotes") {
                    html_escape::encode_safe(s).into_owned()
                } else {
                    html_escape::encode_text(s).into_owned()
                })
            },
        )
        .aliases(&["he", "htmlencode", "htmlescape"])
        .params(P_HTML_QUOTES)
        .examples(&["txc html-encode '<b>hi</b>'"]),
    );

    out.push(
        Op::new(
            "html-decode",
            CAT,
            Feed::Lines,
            "Decode HTML entities",
            |s, _| Ok(html_escape::decode_html_entities(s).into_owned()),
        )
        .aliases(&["hd", "htmldecode", "htmlunescape"])
        .examples(&["txc html-decode '&lt;b&gt;hi&lt;/b&gt;'"]),
    );

    // ------------------------------------------------------------- base64
    out.push(
        Op::new(
            "base64-encode",
            CAT,
            Feed::Buffer,
            "Encode text as base64",
            |s, p| Ok(base64_encoding(p).encode(s.as_bytes())),
        )
        .aliases(&["b64", "b64e", "base64"])
        .params(P_BASE64)
        .examples(&[
            "txc base64-encode \"hello\"",
            "txc b64 --url-safe --no-pad \"a?b\"",
        ]),
    );

    out.push(
        Op::new(
            "base64-decode",
            CAT,
            Feed::Buffer,
            "Decode base64 back to text",
            |s, p| {
                let cleaned = strip_whitespace(s);
                let bytes = base64_encoding(p)
                    .decode(cleaned.as_bytes())
                    .or_else(|_| fallback_base64(&cleaned))
                    .context("input is not valid base64")?;
                bytes_to_string(bytes)
            },
        )
        .aliases(&["b64d", "unbase64"])
        .params(P_BASE64)
        .examples(&["txc base64-decode aGVsbG8="]),
    );

    // ------------------------------------------------------------- base32
    out.push(
        Op::new(
            "base32-encode",
            CAT,
            Feed::Buffer,
            "Encode text as base32",
            |s, p| {
                Ok(if p.flag("no-pad") {
                    BASE32_NOPAD.encode(s.as_bytes())
                } else {
                    BASE32.encode(s.as_bytes())
                })
            },
        )
        .aliases(&["b32", "b32e"])
        .params(P_NO_PAD),
    );

    out.push(
        Op::new(
            "base32-decode",
            CAT,
            Feed::Buffer,
            "Decode base32 back to text",
            |s, _| {
                let cleaned = strip_whitespace(s).to_uppercase();
                let bytes = BASE32
                    .decode(cleaned.as_bytes())
                    .or_else(|_| BASE32_NOPAD.decode(cleaned.as_bytes()))
                    .context("input is not valid base32")?;
                bytes_to_string(bytes)
            },
        )
        .aliases(&["b32d"]),
    );

    // ------------------------------------------------------------- base58
    out.push(
        Op::new(
            "base58-encode",
            CAT,
            Feed::Buffer,
            "Encode text as base58 (bitcoin alphabet)",
            |s, _| Ok(bs58::encode(s.as_bytes()).into_string()),
        )
        .aliases(&["b58", "b58e"]),
    );

    out.push(
        Op::new(
            "base58-decode",
            CAT,
            Feed::Buffer,
            "Decode base58 back to text",
            |s, _| {
                let bytes = bs58::decode(strip_whitespace(s))
                    .into_vec()
                    .context("input is not valid base58")?;
                bytes_to_string(bytes)
            },
        )
        .aliases(&["b58d"]),
    );

    // ---------------------------------------------------------------- hex
    out.push(
        Op::new(
            "hex-encode",
            CAT,
            Feed::Buffer,
            "Encode text as hexadecimal",
            |s, p| {
                let hex = to_hex(s.as_bytes(), p.flag("upper"));
                Ok(group(&hex, 2, p.supplied("sep").unwrap_or("")))
            },
        )
        .aliases(&["hex", "tohex"])
        .params(P_HEX)
        .examples(&["txc hex-encode hi", "txc hex --sep ' ' --upper hi"]),
    );

    out.push(
        Op::new(
            "hex-decode",
            CAT,
            Feed::Buffer,
            "Decode hexadecimal back to text",
            |s, _| bytes_to_string(from_hex(s)?),
        )
        .aliases(&["unhex", "fromhex"])
        .examples(&["txc hex-decode 6869"]),
    );

    // ---------------------------------------------------- numeric encodings
    out.push(
        Op::new(
            "binary-encode",
            CAT,
            Feed::Buffer,
            "Encode text as binary bytes",
            |s, p| Ok(radix_encode(s, 2, 8, p.get("sep"))),
        )
        .aliases(&["tobinary", "bin"])
        .params(P_SEP)
        .examples(&["txc binary-encode hi"]),
    );

    out.push(
        Op::new(
            "binary-decode",
            CAT,
            Feed::Buffer,
            "Decode binary bytes back to text",
            |s, _| radix_decode(s, 2, 8),
        )
        .aliases(&["frombinary", "unbin"]),
    );

    out.push(
        Op::new(
            "octal-encode",
            CAT,
            Feed::Buffer,
            "Encode text as octal bytes",
            |s, p| Ok(radix_encode(s, 8, 3, p.get("sep"))),
        )
        .aliases(&["tooctal", "oct"])
        .params(P_SEP),
    );

    out.push(
        Op::new(
            "octal-decode",
            CAT,
            Feed::Buffer,
            "Decode octal bytes back to text",
            |s, _| radix_decode(s, 8, 3),
        )
        .aliases(&["fromoctal", "unoct"]),
    );

    out.push(
        Op::new(
            "decimal-encode",
            CAT,
            Feed::Buffer,
            "Encode text as decimal byte values",
            |s, p| Ok(radix_encode(s, 10, 0, p.get("sep"))),
        )
        .aliases(&["todecimal", "dec"])
        .params(P_SEP),
    );

    out.push(
        Op::new(
            "decimal-decode",
            CAT,
            Feed::Buffer,
            "Decode decimal byte values back to text",
            |s, _| radix_decode(s, 10, 0),
        )
        .aliases(&["fromdecimal", "undec"]),
    );

    // ------------------------------------------------------------- ciphers
    out.push(
        Op::new(
            "rot13",
            CAT,
            Feed::Lines,
            "Apply the ROT13 letter substitution",
            |s, _| Ok(caesar_shift(s, 13)),
        )
        .examples(&["txc rot13 \"hello\"", "txc rot13 \"uryyb\""]),
    );

    out.push(Op::new(
        "rot47",
        CAT,
        Feed::Lines,
        "Apply the ROT47 substitution over printable ASCII",
        |s, _| {
            Ok(s.chars()
                .map(|c| {
                    if ('!'..='~').contains(&c) {
                        let shifted = (c as u8 - b'!' + 47) % 94 + b'!';
                        shifted as char
                    } else {
                        c
                    }
                })
                .collect())
        },
    ));

    out.push(
        Op::new(
            "caesar",
            CAT,
            Feed::Lines,
            "Shift letters by a fixed amount",
            |s, p| {
                let shift: i32 = p.parse("shift")?;
                Ok(caesar_shift(s, shift.rem_euclid(26) as u8))
            },
        )
        .params(P_SHIFT)
        .examples(&["txc caesar --shift 5 \"attack at dawn\""]),
    );

    out.push(Op::new(
        "atbash",
        CAT,
        Feed::Lines,
        "Apply the Atbash mirror cipher",
        |s, _| {
            Ok(s.chars()
                .map(|c| match c {
                    'a'..='z' => (b'z' - (c as u8 - b'a')) as char,
                    'A'..='Z' => (b'Z' - (c as u8 - b'A')) as char,
                    other => other,
                })
                .collect())
        },
    ));

    // --------------------------------------------------------------- morse
    out.push(
        Op::new(
            "morse-encode",
            CAT,
            Feed::Lines,
            "Encode text as Morse code",
            |s, _| {
                let mut parts = Vec::new();
                for ch in s.to_uppercase().chars() {
                    if ch.is_whitespace() {
                        parts.push("/".to_string());
                    } else if let Some(code) = morse_for(ch) {
                        parts.push(code.to_string());
                    } else {
                        bail!("{ch:?} has no Morse representation");
                    }
                }
                Ok(parts.join(" "))
            },
        )
        .aliases(&["morse"])
        .examples(&["txc morse-encode SOS"]),
    );

    out.push(
        Op::new(
            "morse-decode",
            CAT,
            Feed::Lines,
            "Decode Morse code back to text",
            |s, _| {
                let mut out = String::new();
                for token in s.split_whitespace() {
                    if token == "/" || token == "|" {
                        out.push(' ');
                        continue;
                    }
                    match MORSE.iter().find(|(_, code)| *code == token) {
                        Some((ch, _)) => out.push(*ch),
                        None => bail!("{token:?} is not valid Morse code"),
                    }
                }
                Ok(out)
            },
        )
        .aliases(&["unmorse"])
        .examples(&["txc morse-decode \"... --- ...\""]),
    );

    // -------------------------------------------------------- escape forms
    out.push(
        Op::new(
            "json-escape",
            CAT,
            Feed::Buffer,
            "Escape text for a JSON string",
            |s, p| {
                let quoted = serde_json::to_string(s)?;
                Ok(if p.flag("quotes") {
                    quoted
                } else {
                    quoted[1..quoted.len() - 1].to_string()
                })
            },
        )
        .aliases(&["jsonescape"])
        .params(P_JSON_QUOTES)
        .examples(&["txc json-escape 'line\"one\"'"]),
    );

    out.push(
        Op::new(
            "json-unescape",
            CAT,
            Feed::Buffer,
            "Decode a JSON string escape sequence",
            |s, _| {
                let trimmed = s.trim();
                let quoted =
                    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() > 1 {
                        trimmed.to_string()
                    } else {
                        format!("\"{trimmed}\"")
                    };
                serde_json::from_str::<String>(&quoted)
                    .context("input is not a valid JSON string body")
            },
        )
        .aliases(&["jsonunescape"]),
    );

    out.push(
        Op::new(
            "unicode-escape",
            CAT,
            Feed::Buffer,
            "Escape characters as \\uXXXX sequences",
            |s, p| {
                let all = p.flag("all");
                let mut out = String::new();
                for ch in s.chars() {
                    if !all && ch.is_ascii() && !ch.is_ascii_control() {
                        out.push(ch);
                        continue;
                    }
                    let mut buffer = [0u16; 2];
                    for unit in ch.encode_utf16(&mut buffer) {
                        out.push_str(&format!("\\u{unit:04x}"));
                    }
                }
                Ok(out)
            },
        )
        .aliases(&["uescape"])
        .params(P_ESCAPE_ALL)
        .examples(&["txc unicode-escape \"caf\u{e9}\""]),
    );

    out.push(
        Op::new(
            "unicode-unescape",
            CAT,
            Feed::Buffer,
            "Decode \\uXXXX and \\xNN escape sequences",
            |s, _| unicode_unescape(s),
        )
        .aliases(&["uunescape"]),
    );

    out.push(
        Op::new(
            "codepoint-encode",
            CAT,
            Feed::Buffer,
            "Show the Unicode code point of every character",
            |s, p| {
                Ok(s.chars()
                    .map(|c| format!("U+{:04X}", c as u32))
                    .collect::<Vec<_>>()
                    .join(p.get("sep")))
            },
        )
        .aliases(&["codepoints"])
        .params(P_SEP),
    );

    out.push(Op::new(
        "codepoint-decode",
        CAT,
        Feed::Buffer,
        "Turn U+XXXX code points back into characters",
        |s, _| {
            let mut out = String::new();
            for token in s.split_whitespace() {
                let digits = token
                    .trim_start_matches("U+")
                    .trim_start_matches("u+")
                    .trim_start_matches("0x");
                let value = u32::from_str_radix(digits, 16)
                    .map_err(|_| anyhow::anyhow!("{token:?} is not a code point"))?;
                out.push(
                    char::from_u32(value)
                        .with_context(|| format!("{token} is not a valid character"))?,
                );
            }
            Ok(out)
        },
    ));

    out.push(
        Op::new(
            "nato",
            CAT,
            Feed::Lines,
            "Spell text out with the NATO phonetic alphabet",
            |s, _| {
                Ok(s.chars()
                    .filter(|c| c.is_alphanumeric())
                    .map(nato_word)
                    .collect::<Vec<_>>()
                    .join(" "))
            },
        )
        .examples(&["txc nato \"ab12\""]),
    );
}

fn base64_encoding(p: &Params) -> &'static data_encoding::Encoding {
    match (p.flag("url-safe"), p.flag("no-pad")) {
        (true, true) => &B64_URL_NOPAD,
        (true, false) => &B64_URL,
        (false, true) => &B64_STD_NOPAD,
        (false, false) => &B64_STD,
    }
}

/// Accepts base64 written in any of the four common variants.
fn fallback_base64(cleaned: &str) -> Result<Vec<u8>, data_encoding::DecodeError> {
    let bytes = cleaned.as_bytes();
    BASE64
        .decode(bytes)
        .or_else(|_| BASE64_NOPAD.decode(bytes))
        .or_else(|_| BASE64URL.decode(bytes))
        .or_else(|_| BASE64URL_NOPAD.decode(bytes))
}

fn strip_whitespace(input: &str) -> String {
    input.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Inserts `separator` every `size` characters.
fn group(text: &str, size: usize, separator: &str) -> String {
    if separator.is_empty() || size == 0 {
        return text.to_string();
    }
    text.as_bytes()
        .chunks(size)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(separator)
}

fn radix_encode(input: &str, radix: u32, width: usize, separator: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|byte| match radix {
            2 => format!("{byte:0width$b}"),
            8 => format!("{byte:0width$o}"),
            16 => format!("{byte:0width$x}"),
            _ => byte.to_string(),
        })
        .collect::<Vec<_>>()
        .join(separator)
}

/// Parses whitespace separated values, and also handles unseparated runs of
/// fixed width digits such as `0110100001101001`.
fn radix_decode(input: &str, radix: u32, width: usize) -> Result<String> {
    let trimmed = input.trim();
    let tokens: Vec<String> = if trimmed.split_whitespace().count() > 1 || width == 0 {
        trimmed.split_whitespace().map(str::to_string).collect()
    } else {
        let compact = strip_whitespace(trimmed);
        if compact.len() % width != 0 {
            bail!(
                "input length {} is not a multiple of {width}",
                compact.len()
            );
        }
        compact
            .as_bytes()
            .chunks(width)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect()
    };

    let mut bytes = Vec::with_capacity(tokens.len());
    for token in tokens {
        let value = u32::from_str_radix(&token, radix)
            .map_err(|_| anyhow::anyhow!("{token:?} is not a base {radix} number"))?;
        bytes.push(
            u8::try_from(value).map_err(|_| anyhow::anyhow!("{token} does not fit in a byte"))?,
        );
    }
    bytes_to_string(bytes)
}

fn caesar_shift(input: &str, shift: u8) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + shift) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + shift) % 26) + b'A') as char,
            other => other,
        })
        .collect()
}

fn unicode_unescape(input: &str) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut pending_high: Option<u16> = None;

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            flush_pending(&mut pending_high, &mut out);
            out.push(ch);
            continue;
        }

        match chars.next() {
            Some('u') => {
                let digits: String = (0..4).filter_map(|_| chars.next()).collect();
                let unit = u16::from_str_radix(&digits, 16)
                    .map_err(|_| anyhow::anyhow!("\\u{digits} is not a valid escape"))?;
                match pending_high.take() {
                    Some(high) if (0xdc00..=0xdfff).contains(&unit) => {
                        let combined =
                            String::from_utf16(&[high, unit]).context("invalid surrogate pair")?;
                        out.push_str(&combined);
                    }
                    other => {
                        flush_pending(&mut other.clone(), &mut out);
                        if (0xd800..=0xdbff).contains(&unit) {
                            pending_high = Some(unit);
                        } else {
                            out.push(char::from_u32(unit as u32).unwrap_or('\u{fffd}'));
                        }
                    }
                }
            }
            Some('x') => {
                flush_pending(&mut pending_high, &mut out);
                let digits: String = (0..2).filter_map(|_| chars.next()).collect();
                let value = u8::from_str_radix(&digits, 16)
                    .map_err(|_| anyhow::anyhow!("\\x{digits} is not a valid escape"))?;
                out.push(value as char);
            }
            Some(other) => {
                flush_pending(&mut pending_high, &mut out);
                match other {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    '0' => out.push('\0'),
                    '\\' => out.push('\\'),
                    '\'' => out.push('\''),
                    '"' => out.push('"'),
                    // An escape txc does not know is passed through intact.
                    keep => {
                        out.push('\\');
                        out.push(keep);
                    }
                }
            }
            None => out.push('\\'),
        }
    }

    flush_pending(&mut pending_high, &mut out);
    Ok(out)
}

/// An unpaired high surrogate cannot be represented, so it is kept as the
/// replacement character rather than failing the whole decode.
fn flush_pending(pending: &mut Option<u16>, out: &mut String) {
    if pending.take().is_some() {
        out.push('\u{fffd}');
    }
}

const MORSE: &[(char, &str)] = &[
    ('A', ".-"),
    ('B', "-..."),
    ('C', "-.-."),
    ('D', "-.."),
    ('E', "."),
    ('F', "..-."),
    ('G', "--."),
    ('H', "...."),
    ('I', ".."),
    ('J', ".---"),
    ('K', "-.-"),
    ('L', ".-.."),
    ('M', "--"),
    ('N', "-."),
    ('O', "---"),
    ('P', ".--."),
    ('Q', "--.-"),
    ('R', ".-."),
    ('S', "..."),
    ('T', "-"),
    ('U', "..-"),
    ('V', "...-"),
    ('W', ".--"),
    ('X', "-..-"),
    ('Y', "-.--"),
    ('Z', "--.."),
    ('0', "-----"),
    ('1', ".----"),
    ('2', "..---"),
    ('3', "...--"),
    ('4', "....-"),
    ('5', "....."),
    ('6', "-...."),
    ('7', "--..."),
    ('8', "---.."),
    ('9', "----."),
    ('.', ".-.-.-"),
    (',', "--..--"),
    ('?', "..--.."),
    ('\'', ".----."),
    ('!', "-.-.--"),
    ('/', "-..-."),
    ('(', "-.--."),
    (')', "-.--.-"),
    ('&', ".-..."),
    (':', "---..."),
    (';', "-.-.-."),
    ('=', "-...-"),
    ('+', ".-.-."),
    ('-', "-....-"),
    ('_', "..--.-"),
    ('"', ".-..-."),
    ('$', "...-..-"),
    ('@', ".--.-."),
];

fn morse_for(ch: char) -> Option<&'static str> {
    MORSE.iter().find(|(c, _)| *c == ch).map(|(_, code)| *code)
}

fn nato_word(ch: char) -> String {
    const WORDS: [&str; 26] = [
        "Alfa", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf", "Hotel", "India",
        "Juliett", "Kilo", "Lima", "Mike", "November", "Oscar", "Papa", "Quebec", "Romeo",
        "Sierra", "Tango", "Uniform", "Victor", "Whiskey", "Xray", "Yankee", "Zulu",
    ];
    const DIGITS: [&str; 10] = [
        "Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Niner",
    ];
    let upper = ch.to_ascii_uppercase();
    match upper {
        'A'..='Z' => WORDS[(upper as u8 - b'A') as usize].to_string(),
        '0'..='9' => DIGITS[(upper as u8 - b'0') as usize].to_string(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use crate::params::Params;
    use crate::registry::find;

    fn run(name: &str, input: &str) -> String {
        run_with(name, input, "")
    }

    fn run_with(name: &str, input: &str, options: &str) -> String {
        let op = find(name).expect("operation is registered");
        let params = Params::parse_kv(op, options).expect("options parse");
        op.apply(input, &params, None).expect("runs")
    }

    fn fails(name: &str, input: &str) -> String {
        let op = find(name).expect("operation is registered");
        op.apply(input, &Params::for_op(op), None)
            .expect_err("should fail")
            .to_string()
    }

    #[test]
    fn url_round_trips() {
        assert_eq!(run("ue", "a b&c"), "a%20b%26c");
        assert_eq!(run("ud", "a%20b%26c"), "a b&c");
    }

    #[test]
    fn reports_bad_percent_encoding_instead_of_panicking() {
        assert!(fails("ud", "%FF").contains("percent-encoded"));
    }

    #[test]
    fn html_round_trips() {
        assert_eq!(run("he", "<b>&</b>"), "&lt;b&gt;&amp;&lt;/b&gt;");
        assert_eq!(run("hd", "&lt;b&gt;"), "<b>");
    }

    #[test]
    fn base_encodings_round_trip() {
        for (encode, decode) in [
            ("base64-encode", "base64-decode"),
            ("base32-encode", "base32-decode"),
            ("base58-encode", "base58-decode"),
            ("hex-encode", "hex-decode"),
            ("binary-encode", "binary-decode"),
            ("octal-encode", "octal-decode"),
            ("decimal-encode", "decimal-decode"),
        ] {
            let encoded = run(encode, "hello world");
            assert_eq!(run(decode, &encoded), "hello world", "{encode} -> {decode}");
        }
    }

    #[test]
    fn base64_variants() {
        assert_eq!(run("b64", "hello"), "aGVsbG8=");
        assert_eq!(run_with("b64", "hello", "no-pad"), "aGVsbG8");
        // A decoder accepts every variant regardless of the flags given.
        assert_eq!(run("b64d", "aGVsbG8"), "hello");
    }

    #[test]
    fn hex_grouping() {
        assert_eq!(run("hex", "hi"), "6869");
        assert_eq!(run_with("hex", "hi", "upper sep=' '"), "68 69");
    }

    #[test]
    fn binary_accepts_unseparated_input() {
        assert_eq!(run("binary-decode", "0110100001101001"), "hi");
    }

    #[test]
    fn ciphers_are_reversible() {
        assert_eq!(run("rot13", "hello"), "uryyb");
        assert_eq!(run("rot13", "uryyb"), "hello");
        assert_eq!(
            run("rot47", &run("rot47", "Hello, World!")),
            "Hello, World!"
        );
        assert_eq!(run("atbash", &run("atbash", "Attack")), "Attack");
        assert_eq!(run_with("caesar", "abc", "shift=3"), "def");
        assert_eq!(run_with("caesar", "def", "shift=-3"), "abc");
    }

    #[test]
    fn morse_round_trips() {
        assert_eq!(run("morse-encode", "SOS"), "... --- ...");
        assert_eq!(run("morse-decode", "... --- ..."), "SOS");
        assert_eq!(run("morse-decode", ".... .. / - .... . .-. ."), "HI THERE");
        assert!(fails("morse-encode", "\u{e9}").contains("Morse"));
    }

    #[test]
    fn escapes_round_trip() {
        assert_eq!(run("json-escape", "a\"b"), "a\\\"b");
        assert_eq!(run("json-unescape", "a\\\"b"), "a\"b");
        assert_eq!(run("unicode-escape", "caf\u{e9}"), "caf\\u00e9");
        assert_eq!(run("unicode-unescape", "caf\\u00e9"), "caf\u{e9}");
        // Characters outside the basic plane travel as a surrogate pair.
        let rocket = "\u{1f680}";
        assert_eq!(
            run("unicode-unescape", &run("unicode-escape", rocket)),
            rocket
        );
    }

    #[test]
    fn code_points_round_trip() {
        assert_eq!(run("codepoint-encode", "hi"), "U+0068 U+0069");
        assert_eq!(run("codepoint-decode", "U+0068 U+0069"), "hi");
    }

    #[test]
    fn nato_spelling() {
        assert_eq!(run("nato", "ab12"), "Alfa Bravo One Two");
    }
}
