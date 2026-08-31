//! Generators: identifiers, passwords, random data and placeholder text.

use anyhow::{bail, Result};
use rand::seq::IndexedRandom;
use rand::RngExt;
use uuid::Uuid;

use crate::ops::to_hex;
use crate::params::Params;
use crate::registry::{Category, Feed, Op, Param};

const CAT: Category = Category::Generate;

static P_UUID: &[Param] = &[
    Param::valued(
        "version",
        Some('v'),
        "N",
        "4",
        "UUID version: 1, 3, 4, 5, 7 or nil",
    ),
    Param::valued("count", Some('c'), "N", "1", "How many to generate"),
    Param::value(
        "name",
        None,
        "TEXT",
        "Name to hash, required by versions 3 and 5",
    ),
    Param::valued(
        "namespace",
        None,
        "NAME",
        "dns",
        "Namespace for versions 3 and 5: dns, url, oid, x500 or a UUID",
    ),
    Param::flag("upper", Some('u'), "Print in uppercase"),
    Param::flag("compact", None, "Print without the dashes"),
];

static P_PASSWORD: &[Param] = &[
    Param::valued("length", Some('l'), "N", "20", "Characters per password"),
    Param::valued(
        "count",
        Some('c'),
        "N",
        "1",
        "How many passwords to generate",
    ),
    Param::flag("no-symbols", None, "Leave out punctuation"),
    Param::flag("no-digits", None, "Leave out digits"),
    Param::flag("no-upper", None, "Leave out uppercase letters"),
    Param::flag("no-lower", None, "Leave out lowercase letters"),
    Param::flag(
        "no-ambiguous",
        None,
        "Leave out characters that look alike, such as l, 1, O and 0",
    ),
];

static P_RANDOM_STRING: &[Param] = &[
    Param::valued("length", Some('l'), "N", "16", "Characters per string"),
    Param::valued("count", Some('c'), "N", "1", "How many strings to generate"),
    Param::valued("charset", Some('s'), "CHARS", "", "Characters to pick from"),
];

static P_RANDOM_NUMBER: &[Param] = &[
    Param::valued("min", None, "N", "0", "Smallest value, inclusive"),
    Param::valued("max", None, "N", "100", "Largest value, inclusive"),
    Param::valued("count", Some('c'), "N", "1", "How many numbers to generate"),
];

static P_TOKEN: &[Param] = &[
    Param::valued(
        "bytes",
        Some('b'),
        "N",
        "32",
        "How many random bytes to draw",
    ),
    Param::valued("count", Some('c'), "N", "1", "How many tokens to generate"),
    Param::flag("base64", None, "Print as base64 instead of hex"),
];

static P_LOREM: &[Param] = &[
    Param::valued(
        "paragraphs",
        Some('p'),
        "N",
        "3",
        "How many paragraphs to write",
    ),
    Param::valued("sentences", Some('s'), "N", "5", "Sentences per paragraph"),
    Param::value(
        "words",
        Some('w'),
        "N",
        "Produce this many words instead of paragraphs",
    ),
];

static P_SEQUENCE: &[Param] = &[
    Param::valued("start", None, "N", "1", "First value"),
    Param::valued("end", None, "N", "10", "Last value, inclusive"),
    Param::valued("step", None, "N", "1", "Amount to add each time"),
    Param::valued(
        "format",
        Some('t'),
        "TEXT",
        "{}",
        "Template, with {} replaced by the number",
    ),
];

pub(crate) fn register(out: &mut Vec<Op>) {
    out.push(
        Op::new("uuid", CAT, Feed::None, "Generate UUIDs", |_, p| {
            let count: usize = p.parse("count")?;
            let version = p.get("version");
            let mut lines = Vec::with_capacity(count);
            for _ in 0..count {
                let uuid = make_uuid(version, p)?;
                let text = if p.flag("compact") {
                    uuid.simple().to_string()
                } else {
                    uuid.hyphenated().to_string()
                };
                lines.push(if p.flag("upper") {
                    text.to_uppercase()
                } else {
                    text
                });
            }
            Ok(lines.join("\n"))
        })
        .aliases(&["guid"])
        .params(P_UUID)
        .examples(&[
            "txc uuid",
            "txc uuid --count 5",
            "txc uuid --version 5 --name example.com",
            "txc uuid --version 7",
        ]),
    );

    out.push(
        Op::new(
            "password",
            CAT,
            Feed::None,
            "Generate random passwords",
            |_, p| {
                let length: usize = p.parse("length")?;
                let count: usize = p.parse("count")?;
                anyhow::ensure!(length > 0, "--length must be at least 1");

                let mut alphabet = String::new();
                if !p.flag("no-lower") {
                    alphabet.push_str("abcdefghijklmnopqrstuvwxyz");
                }
                if !p.flag("no-upper") {
                    alphabet.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                }
                if !p.flag("no-digits") {
                    alphabet.push_str("0123456789");
                }
                if !p.flag("no-symbols") {
                    alphabet.push_str("!@#$%^&*()-_=+[]{};:,.<>?");
                }
                if p.flag("no-ambiguous") {
                    alphabet.retain(|c| !"lI1O0o|`'\";:.,".contains(c));
                }
                if alphabet.is_empty() {
                    bail!("every character group was excluded, so no password can be made");
                }

                Ok(random_strings(&alphabet, length, count))
            },
        )
        .aliases(&["passwd", "pwgen"])
        .params(P_PASSWORD)
        .examples(&[
            "txc password",
            "txc password --length 32 --count 5",
            "txc password --no-symbols --no-ambiguous",
        ]),
    );

    out.push(
        Op::new(
            "random-string",
            CAT,
            Feed::None,
            "Generate random strings",
            |_, p| {
                let length: usize = p.parse("length")?;
                let count: usize = p.parse("count")?;
                let charset = match p.get("charset") {
                    "" => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                    custom => custom,
                };
                anyhow::ensure!(!charset.is_empty(), "--charset cannot be empty");
                Ok(random_strings(charset, length, count))
            },
        )
        .params(P_RANDOM_STRING)
        .examples(&["txc random-string --length 8 --charset abcdef0123456789"]),
    );

    out.push(
        Op::new(
            "random-number",
            CAT,
            Feed::None,
            "Generate random whole numbers",
            |_, p| {
                let min: i64 = p.parse("min")?;
                let max: i64 = p.parse("max")?;
                let count: usize = p.parse("count")?;
                anyhow::ensure!(min <= max, "--min must not be greater than --max");
                let mut rng = rand::rng();
                Ok((0..count)
                    .map(|_| rng.random_range(min..=max).to_string())
                    .collect::<Vec<_>>()
                    .join("\n"))
            },
        )
        .aliases(&["random-int", "dice"])
        .params(P_RANDOM_NUMBER)
        .examples(&[
            "txc random-number --min 1 --max 6",
            "txc random-number --count 5",
        ]),
    );

    out.push(
        Op::new(
            "token",
            CAT,
            Feed::None,
            "Generate random tokens from raw bytes",
            |_, p| {
                let size: usize = p.parse("bytes")?;
                let count: usize = p.parse("count")?;
                anyhow::ensure!(size > 0, "--bytes must be at least 1");
                let mut rng = rand::rng();
                Ok((0..count)
                    .map(|_| {
                        let bytes: Vec<u8> =
                            (0..size).map(|_| rng.random_range(0..=255u8)).collect();
                        if p.flag("base64") {
                            data_encoding::BASE64.encode(&bytes)
                        } else {
                            to_hex(&bytes, false)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            },
        )
        .aliases(&["random-bytes", "secret"])
        .params(P_TOKEN)
        .examples(&["txc token", "txc token --bytes 16 --base64"]),
    );

    out.push(
        Op::new(
            "lorem",
            CAT,
            Feed::None,
            "Generate placeholder text",
            |_, p| {
                if let Some(words) = p.supplied("words") {
                    let count: usize = words
                        .parse()
                        .map_err(|_| anyhow::anyhow!("--words must be a whole number"))?;
                    return Ok(lorem_words(count));
                }
                let paragraphs: usize = p.parse("paragraphs")?;
                let sentences: usize = p.parse("sentences")?;
                Ok((0..paragraphs)
                    .map(|_| lorem_paragraph(sentences))
                    .collect::<Vec<_>>()
                    .join("\n\n"))
            },
        )
        .aliases(&["lipsum", "placeholder"])
        .params(P_LOREM)
        .examples(&[
            "txc lorem",
            "txc lorem --paragraphs 1 --sentences 2",
            "txc lorem --words 20",
        ]),
    );

    out.push(
        Op::new(
            "sequence",
            CAT,
            Feed::None,
            "Generate a run of numbers",
            |_, p| {
                let start: i64 = p.parse("start")?;
                let end: i64 = p.parse("end")?;
                let step: i64 = p.parse("step")?;
                anyhow::ensure!(step != 0, "--step cannot be zero");
                anyhow::ensure!(
                    (end - start).signum() != -step.signum(),
                    "--step points away from --end, so the sequence would never finish"
                );

                let template = p.get("format");
                let mut lines = Vec::new();
                let mut value = start;
                while (step > 0 && value <= end) || (step < 0 && value >= end) {
                    lines.push(template.replace("{}", &value.to_string()));
                    value += step;
                }
                Ok(lines.join("\n"))
            },
        )
        .aliases(&["seq", "range"])
        .params(P_SEQUENCE)
        .examples(&[
            "txc sequence --start 1 --end 5",
            "txc sequence --end 3 --format 'item-{}'",
        ]),
    );
}

fn make_uuid(version: &str, p: &Params) -> Result<Uuid> {
    match version {
        "4" => Ok(Uuid::new_v4()),
        "7" => Ok(Uuid::now_v7()),
        "1" => {
            // A random node identifier keeps generated values distinct without
            // leaking a real hardware address.
            let mut rng = rand::rng();
            let mut node: [u8; 6] = std::array::from_fn(|_| rng.random_range(0..=255u8));
            node[0] |= 0x01; // Mark it as locally administered.
            Ok(Uuid::now_v1(&node))
        }
        "3" | "5" => {
            let name = p
                .supplied("name")
                .ok_or_else(|| anyhow::anyhow!("--name is required for version {version}"))?;
            let namespace = match p.get("namespace").to_lowercase().as_str() {
                "dns" => Uuid::NAMESPACE_DNS,
                "url" => Uuid::NAMESPACE_URL,
                "oid" => Uuid::NAMESPACE_OID,
                "x500" => Uuid::NAMESPACE_X500,
                custom => Uuid::parse_str(custom).map_err(|_| {
                    anyhow::anyhow!("{custom:?} is not dns, url, oid, x500 or a UUID")
                })?,
            };
            Ok(if version == "3" {
                Uuid::new_v3(&namespace, name.as_bytes())
            } else {
                Uuid::new_v5(&namespace, name.as_bytes())
            })
        }
        "nil" | "0" => Ok(Uuid::nil()),
        other => bail!("unknown UUID version {other:?}, use 1, 3, 4, 5, 7 or nil"),
    }
}

fn random_strings(alphabet: &str, length: usize, count: usize) -> String {
    let pool: Vec<char> = alphabet.chars().collect();
    let mut rng = rand::rng();
    (0..count)
        .map(|_| {
            (0..length)
                .map(|_| *pool.choose(&mut rng).expect("alphabet is not empty"))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

const LOREM: &[&str] = &[
    "lorem",
    "ipsum",
    "dolor",
    "sit",
    "amet",
    "consectetur",
    "adipiscing",
    "elit",
    "sed",
    "do",
    "eiusmod",
    "tempor",
    "incididunt",
    "ut",
    "labore",
    "et",
    "dolore",
    "magna",
    "aliqua",
    "enim",
    "ad",
    "minim",
    "veniam",
    "quis",
    "nostrud",
    "exercitation",
    "ullamco",
    "laboris",
    "nisi",
    "aliquip",
    "ex",
    "ea",
    "commodo",
    "consequat",
    "duis",
    "aute",
    "irure",
    "in",
    "reprehenderit",
    "voluptate",
    "velit",
    "esse",
    "cillum",
    "eu",
    "fugiat",
    "nulla",
    "pariatur",
    "excepteur",
    "sint",
    "occaecat",
    "cupidatat",
    "non",
    "proident",
    "sunt",
    "culpa",
    "qui",
    "officia",
    "deserunt",
    "mollit",
    "anim",
    "id",
    "est",
    "laborum",
];

fn lorem_words(count: usize) -> String {
    let mut rng = rand::rng();
    let words: Vec<&str> = (0..count)
        .map(|i| {
            // The classic opening makes the output recognisable as placeholder text.
            if i < 2 {
                LOREM[i]
            } else {
                *LOREM.choose(&mut rng).expect("word list is not empty")
            }
        })
        .collect();
    crate::ops::capitalize_first(&words.join(" "))
}

fn lorem_paragraph(sentences: usize) -> String {
    let mut rng = rand::rng();
    (0..sentences)
        .map(|_| {
            let length = rng.random_range(6..=14usize);
            let words: Vec<&str> = (0..length)
                .map(|_| *LOREM.choose(&mut rng).expect("word list is not empty"))
                .collect();
            format!("{}.", crate::ops::capitalize_first(&words.join(" ")))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use crate::params::Params;
    use crate::registry::find;

    fn run_with(name: &str, options: &str) -> String {
        let op = find(name).expect("operation is registered");
        let params = Params::parse_kv(op, options).expect("options parse");
        op.apply("", &params, None).expect("runs")
    }

    fn error_from(name: &str, options: &str) -> String {
        let op = find(name).expect("operation is registered");
        let params = Params::parse_kv(op, options).expect("options parse");
        op.apply("", &params, None)
            .expect_err("should fail")
            .to_string()
    }

    #[test]
    fn uuid_versions_all_produce_a_uuid() {
        for version in ["1", "4", "7", "nil"] {
            let value = run_with("uuid", &format!("version={version}"));
            assert_eq!(value.len(), 36, "version {version} gave {value}");
            assert!(uuid::Uuid::parse_str(&value).is_ok(), "version {version}");
        }
    }

    #[test]
    fn name_based_uuids_are_stable() {
        let first = run_with("uuid", "version=5 name=example.com");
        let second = run_with("uuid", "version=5 name=example.com");
        assert_eq!(first, second);
        assert_eq!(first, "cfbff0d1-9375-5685-968c-48ce8b15ae17");

        let v3 = run_with("uuid", "version=3 name=example.com");
        assert_eq!(v3, "9073926b-929f-31c2-abc9-fad77ae3e8eb");
    }

    #[test]
    fn name_based_uuids_need_a_name() {
        assert!(error_from("uuid", "version=5").contains("--name"));
    }

    #[test]
    fn uuid_rejects_an_unknown_version() {
        assert!(error_from("uuid", "version=9").contains("unknown UUID version"));
    }

    #[test]
    fn uuid_count_and_formatting() {
        assert_eq!(run_with("uuid", "count=3").lines().count(), 3);
        assert_eq!(run_with("uuid", "compact").len(), 32);
        let upper = run_with("uuid", "upper");
        assert_eq!(upper, upper.to_uppercase());
    }

    #[test]
    fn passwords_respect_length_and_alphabet() {
        let password = run_with("password", "length=32");
        assert_eq!(password.chars().count(), 32);
        assert_eq!(run_with("password", "count=4").lines().count(), 4);

        let digits_only = run_with("password", "length=64 no-symbols no-upper no-lower");
        assert!(
            digits_only.chars().all(|c| c.is_ascii_digit()),
            "{digits_only}"
        );

        let unambiguous = run_with("password", "length=200 no-ambiguous");
        assert!(!unambiguous.contains('l') && !unambiguous.contains('0'));
    }

    #[test]
    fn passwords_need_at_least_one_group() {
        let error = error_from("password", "no-symbols no-digits no-upper no-lower");
        assert!(error.contains("no password can be made"));
    }

    #[test]
    fn random_numbers_stay_inside_the_range() {
        let numbers = run_with("random-number", "min=5 max=7 count=50");
        for line in numbers.lines() {
            let value: i64 = line.parse().expect("a number");
            assert!((5..=7).contains(&value), "{value} is outside 5..=7");
        }
        assert!(error_from("random-number", "min=10 max=1").contains("--min"));
    }

    #[test]
    fn tokens_have_the_requested_size() {
        assert_eq!(run_with("token", "bytes=16").len(), 32);
        assert!(run_with("token", "bytes=16 base64").len() < 32);
    }

    #[test]
    fn lorem_produces_the_requested_shape() {
        assert_eq!(run_with("lorem", "paragraphs=2").split("\n\n").count(), 2);
        assert_eq!(run_with("lorem", "words=5").split_whitespace().count(), 5);
        assert!(run_with("lorem", "words=3").starts_with("Lorem ipsum"));
    }

    #[test]
    fn sequences_count_up_and_down() {
        assert_eq!(run_with("sequence", "start=1 end=3"), "1\n2\n3");
        assert_eq!(run_with("sequence", "start=3 end=1 step=-1"), "3\n2\n1");
        assert_eq!(run_with("sequence", "start=1 end=2 format='n{}'"), "n1\nn2");
        assert!(error_from("sequence", "start=1 end=5 step=-1").contains("never finish"));
        assert!(error_from("sequence", "step=0").contains("cannot be zero"));
    }
}
