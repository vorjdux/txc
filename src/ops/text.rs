//! Searching, replacing, cleaning and restyling text.

use anyhow::{Context, Result};
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

use crate::registry::{Category, Feed, Op, Param};

const CAT: Category = Category::Text;

static P_REPEAT: &[Param] = &[
    Param::valued("count", Some('c'), "N", "2", "How many copies to produce"),
    Param::valued("sep", Some('s'), "TEXT", "", "Text placed between copies"),
];
static P_TRUNCATE: &[Param] = &[
    Param::valued(
        "length",
        Some('l'),
        "N",
        "80",
        "Maximum length in characters",
    ),
    Param::valued(
        "suffix",
        Some('s'),
        "TEXT",
        "",
        "Text appended when the input is cut",
    ),
];
static P_TRIM: &[Param] = &[
    Param::value(
        "chars",
        Some('c'),
        "CHARS",
        "Characters to strip instead of whitespace",
    ),
    Param::flag("start", None, "Only trim the start"),
    Param::flag("end", None, "Only trim the end"),
];
static P_REPLACE: &[Param] = &[
    Param::value("find", None, "TEXT", "Text or pattern to look for"),
    Param::valued("with", Some('w'), "TEXT", "", "Replacement text"),
    Param::flag("regex", Some('r'), "Treat --find as a regular expression"),
    Param::flag("ignore-case", Some('i'), "Match without regard to case"),
    Param::flag("first", None, "Replace only the first match"),
];
static P_EXTRACT: &[Param] = &[
    Param::value(
        "regex",
        Some('r'),
        "PATTERN",
        "Regular expression to search for",
    ),
    Param::valued(
        "group",
        Some('g'),
        "N",
        "0",
        "Capture group to print, 0 for the whole match",
    ),
    Param::flag("first", None, "Print only the first match"),
];
static P_REMOVE: &[Param] = &[
    Param::value("text", Some('t'), "TEXT", "Exact text to remove"),
    Param::value(
        "regex",
        Some('r'),
        "PATTERN",
        "Regular expression to remove",
    ),
];
static P_TABSTOP: &[Param] = &[Param::valued(
    "width",
    Some('w'),
    "N",
    "4",
    "Number of spaces per tab",
)];
static P_ROTATE: &[Param] = &[Param::valued(
    "count",
    Some('c'),
    "N",
    "1",
    "How many places to rotate",
)];
static P_FANCY: &[Param] = &[Param::valued(
    "style",
    Some('s'),
    "STYLE",
    "bold",
    "bold, italic, bold-italic, script, fraktur, double, mono, circled, fullwidth, smallcaps or flip",
)];
static P_FORM: &[Param] = &[Param::valued(
    "form",
    None,
    "FORM",
    "nfc",
    "Normalisation form: nfc, nfd, nfkc or nfkd",
)];
static P_QUOTE: &[Param] = &[Param::valued(
    "char",
    Some('c'),
    "CHAR",
    "\"",
    "Quote character to wrap each line with",
)];

pub(crate) fn register(out: &mut Vec<Op>) {
    out.push(
        Op::new(
            "reverse",
            CAT,
            Feed::Lines,
            "Reverse the characters of the text",
            |s, _| Ok(s.graphemes(true).rev().collect()),
        )
        .aliases(&["reverse-text"])
        .examples(&["txc reverse \"hello\""]),
    );

    out.push(
        Op::new(
            "reverse-words",
            CAT,
            Feed::Lines,
            "Reverse the order of the words",
            |s, _| Ok(s.split_whitespace().rev().collect::<Vec<_>>().join(" ")),
        )
        .examples(&["txc reverse-words \"one two three\""]),
    );

    out.push(
        Op::new(
            "repeat",
            CAT,
            Feed::Buffer,
            "Repeat the text a number of times",
            |s, p| {
                let count: usize = p.parse("count")?;
                Ok(vec![s; count].join(p.get("sep")))
            },
        )
        .params(P_REPEAT)
        .examples(&["txc repeat --count 3 --sep ' ' ha"]),
    );

    out.push(
        Op::new(
            "truncate",
            CAT,
            Feed::Lines,
            "Shorten text to a maximum length",
            |s, p| {
                let length: usize = p.parse("length")?;
                let suffix = p.get("suffix");
                let graphemes: Vec<&str> = s.graphemes(true).collect();
                if graphemes.len() <= length {
                    return Ok(s.to_string());
                }
                let keep = length.saturating_sub(suffix.graphemes(true).count());
                Ok(format!("{}{suffix}", graphemes[..keep].concat()))
            },
        )
        .aliases(&["shorten"])
        .params(P_TRUNCATE)
        .examples(&["txc truncate --length 10 --suffix ... \"a long sentence\""]),
    );

    out.push(
        Op::new(
            "trim",
            CAT,
            Feed::Lines,
            "Remove whitespace from both ends",
            |s, p| {
                let start = p.flag("start");
                let end = p.flag("end");
                let both = start == end;
                let strip: Vec<char> = p.get("chars").chars().collect();
                let matches = |c: char| {
                    if strip.is_empty() {
                        c.is_whitespace()
                    } else {
                        strip.contains(&c)
                    }
                };
                let mut text = s;
                if both || start {
                    text = text.trim_start_matches(matches);
                }
                if both || end {
                    text = text.trim_end_matches(matches);
                }
                Ok(text.to_string())
            },
        )
        .params(P_TRIM)
        .examples(&["txc trim \"  padded  \"", "txc trim --chars '/' \"/path/\""]),
    );

    out.push(
        Op::new(
            "replace",
            CAT,
            Feed::Buffer,
            "Replace text or a pattern",
            |s, p| {
                let find = p.require("find")?;
                let with = p.get("with");
                let first = p.flag("first");

                if p.flag("regex") || p.flag("ignore-case") {
                    let pattern = if p.flag("regex") {
                        find.to_string()
                    } else {
                        regex::escape(find)
                    };
                    let regex = regex::RegexBuilder::new(&pattern)
                        .case_insensitive(p.flag("ignore-case"))
                        .build()
                        .with_context(|| format!("{find:?} is not a valid regular expression"))?;
                    return Ok(if first {
                        regex.replace(s, with).into_owned()
                    } else {
                        regex.replace_all(s, with).into_owned()
                    });
                }

                Ok(if first {
                    s.replacen(find, with, 1)
                } else {
                    s.replace(find, with)
                })
            },
        )
        .aliases(&["find-replace", "sub"])
        .params(P_REPLACE)
        .examples(&[
            "txc replace --find cat --with dog \"the cat sat\"",
            "txc replace --regex --find '\\s+' --with ' ' --file messy.txt",
        ]),
    );

    out.push(
        Op::new(
            "extract",
            CAT,
            Feed::Buffer,
            "Print the parts of the text matching a pattern",
            |s, p| {
                let pattern = p.require("regex")?;
                let group: usize = p.parse("group")?;
                let regex = regex::Regex::new(pattern)
                    .with_context(|| format!("{pattern:?} is not a valid regular expression"))?;

                let mut found = Vec::new();
                for captures in regex.captures_iter(s) {
                    if let Some(m) = captures.get(group) {
                        found.push(m.as_str().to_string());
                    }
                    if p.flag("first") {
                        break;
                    }
                }
                Ok(found.join("\n"))
            },
        )
        .aliases(&["match"])
        .params(P_EXTRACT)
        .examples(&[
            "txc extract --regex '[\\w.]+@[\\w.]+' --file contacts.txt",
            "txc extract --regex 'v(\\d+)' --group 1 \"v12\"",
        ]),
    );

    out.push(
        Op::new(
            "remove",
            CAT,
            Feed::Buffer,
            "Remove text or a pattern",
            |s, p| match (p.supplied("regex"), p.supplied("text")) {
                (Some(pattern), _) => {
                    let regex = regex::Regex::new(pattern).with_context(|| {
                        format!("{pattern:?} is not a valid regular expression")
                    })?;
                    Ok(regex.replace_all(s, "").into_owned())
                }
                (None, Some(text)) => Ok(s.replace(text, "")),
                (None, None) => anyhow::bail!("give either --text or --regex"),
            },
        )
        .params(P_REMOVE),
    );

    out.push(
        Op::new(
            "squeeze",
            CAT,
            Feed::Lines,
            "Collapse runs of whitespace into single spaces",
            |s, _| Ok(s.split_whitespace().collect::<Vec<_>>().join(" ")),
        )
        .aliases(&["normalize-space", "remove-extra-spaces"])
        .examples(&["txc squeeze \"too    many   spaces\""]),
    );

    out.push(
        Op::new(
            "remove-whitespace",
            CAT,
            Feed::Buffer,
            "Remove every whitespace character",
            |s, _| Ok(s.chars().filter(|c| !c.is_whitespace()).collect()),
        )
        .aliases(&["strip-spaces"]),
    );

    out.push(
        Op::new(
            "remove-punctuation",
            CAT,
            Feed::Lines,
            "Remove punctuation characters",
            |s, _| {
                Ok(s.chars()
                    .filter(|c| c.is_alphanumeric() || c.is_whitespace())
                    .collect())
            },
        )
        .aliases(&["strip-punctuation"]),
    );

    out.push(
        Op::new(
            "remove-accents",
            CAT,
            Feed::Lines,
            "Replace accented letters with their plain form",
            |s, _| Ok(strip_marks(s)),
        )
        .aliases(&["deaccent", "unaccent"])
        .examples(&["txc remove-accents \"cr\u{e8}me br\u{fb}l\u{e9}e\""]),
    );

    out.push(
        Op::new(
            "remove-non-ascii",
            CAT,
            Feed::Lines,
            "Drop every non ASCII character",
            |s, _| Ok(s.chars().filter(char::is_ascii).collect()),
        )
        .aliases(&["ascii-only"]),
    );

    out.push(
        Op::new(
            "slugify",
            CAT,
            Feed::Lines,
            "Turn text into a lowercase URL slug",
            |s, _| {
                let plain = strip_marks(s).to_lowercase();
                let mut slug = String::with_capacity(plain.len());
                let mut pending_dash = false;
                for ch in plain.chars() {
                    if ch.is_ascii_alphanumeric() {
                        if pending_dash && !slug.is_empty() {
                            slug.push('-');
                        }
                        pending_dash = false;
                        slug.push(ch);
                    } else {
                        pending_dash = true;
                    }
                }
                Ok(slug)
            },
        )
        .aliases(&["slug"])
        .examples(&["txc slugify \"Hello, World! 2024\""]),
    );

    out.push(
        Op::new(
            "strip-html",
            CAT,
            Feed::Buffer,
            "Remove HTML tags and decode entities",
            |s, _| {
                let mut out = String::with_capacity(s.len());
                let mut depth = 0usize;
                for ch in s.chars() {
                    match ch {
                        '<' => depth += 1,
                        '>' => depth = depth.saturating_sub(1),
                        _ if depth == 0 => out.push(ch),
                        _ => {}
                    }
                }
                Ok(html_escape::decode_html_entities(&out).into_owned())
            },
        )
        .aliases(&["strip-tags", "html-to-text"])
        .examples(&["txc strip-html '<p>Hi &amp; bye</p>'"]),
    );

    out.push(
        Op::new(
            "tabs-to-spaces",
            CAT,
            Feed::Lines,
            "Replace tabs with spaces",
            |s, p| {
                let width: usize = p.parse("width")?;
                Ok(s.replace('\t', &" ".repeat(width)))
            },
        )
        .aliases(&["untabify", "expand"])
        .params(P_TABSTOP),
    );

    out.push(
        Op::new(
            "spaces-to-tabs",
            CAT,
            Feed::Lines,
            "Replace runs of spaces with tabs",
            |s, p| {
                let width: usize = p.parse("width")?;
                anyhow::ensure!(width > 0, "--width must be at least 1");
                Ok(s.replace(&" ".repeat(width), "\t"))
            },
        )
        .aliases(&["tabify", "unexpand"])
        .params(P_TABSTOP),
    );

    out.push(
        Op::new(
            "newlines-to-spaces",
            CAT,
            Feed::Buffer,
            "Put all the text on one line",
            |s, _| Ok(s.lines().collect::<Vec<_>>().join(" ")),
        )
        .aliases(&["unlines"]),
    );

    out.push(
        Op::new(
            "spaces-to-newlines",
            CAT,
            Feed::Buffer,
            "Put every word on its own line",
            |s, _| Ok(s.split_whitespace().collect::<Vec<_>>().join("\n")),
        )
        .aliases(&["words-to-lines"]),
    );

    out.push(
        Op::new(
            "rotate",
            CAT,
            Feed::Lines,
            "Rotate the characters of the text",
            |s, p| {
                let graphemes: Vec<&str> = s.graphemes(true).collect();
                if graphemes.is_empty() {
                    return Ok(String::new());
                }
                let count: isize = p.parse("count")?;
                let len = graphemes.len() as isize;
                let split = (count.rem_euclid(len)) as usize;
                Ok([&graphemes[split..], &graphemes[..split]].concat().concat())
            },
        )
        .params(P_ROTATE)
        .examples(&["txc rotate --count 1 abcd"]),
    );

    out.push(
        Op::new(
            "quote",
            CAT,
            Feed::Lines,
            "Wrap every line in quotes",
            |s, p| {
                let quote = p.get("char");
                Ok(format!("{quote}{s}{quote}"))
            },
        )
        .params(P_QUOTE),
    );

    out.push(
        Op::new(
            "escape-regex",
            CAT,
            Feed::Buffer,
            "Escape the characters that are special in a regular expression",
            |s, _| Ok(regex::escape(s)),
        )
        .aliases(&["regex-escape"]),
    );

    out.push(
        Op::new(
            "normalize",
            CAT,
            Feed::Buffer,
            "Apply a Unicode normalisation form",
            |s, p| {
                Ok(match p.get("form").to_lowercase().as_str() {
                    "nfc" => s.nfc().collect(),
                    "nfd" => s.nfd().collect(),
                    "nfkc" => s.nfkc().collect(),
                    "nfkd" => s.nfkd().collect(),
                    other => anyhow::bail!("unknown form {other:?}, use nfc, nfd, nfkc or nfkd"),
                })
            },
        )
        .aliases(&["unicode-normalize"])
        .params(P_FORM),
    );

    out.push(Op::new(
        "palindrome",
        CAT,
        Feed::Lines,
        "Make a palindrome by mirroring the text",
        |s, _| {
            let mirrored: String = s.graphemes(true).rev().skip(1).collect();
            Ok(format!("{s}{mirrored}"))
        },
    ));

    out.push(
        Op::new(
            "fancy",
            CAT,
            Feed::Lines,
            "Restyle text with Unicode letterforms",
            |s, p| fancy(s, p.get("style")),
        )
        .aliases(&["fancy-text", "stylize"])
        .params(P_FANCY)
        .examples(&[
            "txc fancy --style bold \"look at this\"",
            "txc fancy --style flip hello",
        ]),
    );
}

/// Decomposes text and drops the combining marks, so `é` becomes `e`.
fn strip_marks(input: &str) -> String {
    input
        .nfd()
        .filter(|c| !matches!(*c as u32, 0x0300..=0x036f))
        .nfc()
        .collect()
}

fn fancy(input: &str, style: &str) -> Result<String> {
    let styled: String = match style.to_lowercase().as_str() {
        "bold" => map_alphabet(input, 0x1D400, 0x1D41A, Some(0x1D7CE), &[]),
        "italic" => map_alphabet(input, 0x1D434, 0x1D44E, None, &[('h', 0x210E)]),
        "bold-italic" | "bolditalic" => map_alphabet(input, 0x1D468, 0x1D482, None, &[]),
        "script" => map_alphabet(
            input,
            0x1D49C,
            0x1D4B6,
            None,
            &[
                ('B', 0x212C),
                ('E', 0x2130),
                ('F', 0x2131),
                ('H', 0x210B),
                ('I', 0x2110),
                ('L', 0x2112),
                ('M', 0x2133),
                ('R', 0x211B),
                ('e', 0x212F),
                ('g', 0x210A),
                ('o', 0x2134),
            ],
        ),
        "fraktur" => map_alphabet(
            input,
            0x1D504,
            0x1D51E,
            None,
            &[
                ('C', 0x212D),
                ('H', 0x210C),
                ('I', 0x2111),
                ('R', 0x211C),
                ('Z', 0x2128),
            ],
        ),
        "double" | "double-struck" => map_alphabet(
            input,
            0x1D538,
            0x1D552,
            Some(0x1D7D8),
            &[
                ('C', 0x2102),
                ('H', 0x210D),
                ('N', 0x2115),
                ('P', 0x2119),
                ('Q', 0x211A),
                ('R', 0x211D),
                ('Z', 0x2124),
            ],
        ),
        "mono" | "monospace" => map_alphabet(input, 0x1D670, 0x1D68A, Some(0x1D7F6), &[]),
        "fullwidth" | "wide" => map_alphabet(input, 0xFF21, 0xFF41, Some(0xFF10), &[(' ', 0x3000)]),
        "circled" => map_alphabet(input, 0x24B6, 0x24D0, None, &circled_digits()),
        "smallcaps" => input.chars().map(small_cap).collect(),
        "flip" | "upside-down" => input.chars().rev().map(flip).collect(),
        other => anyhow::bail!(
            "unknown style {other:?}; try bold, italic, bold-italic, script, fraktur, double, mono, circled, fullwidth, smallcaps or flip"
        ),
    };
    Ok(styled)
}

/// Maps ASCII letters and digits onto a Unicode alphabet.
///
/// Several alphabets have holes where the character already existed elsewhere
/// in Unicode; `exceptions` fills those in.
fn map_alphabet(
    input: &str,
    upper_base: u32,
    lower_base: u32,
    digit_base: Option<u32>,
    exceptions: &[(char, u32)],
) -> String {
    input
        .chars()
        .map(|ch| {
            if let Some((_, code)) = exceptions.iter().find(|(c, _)| *c == ch) {
                return char::from_u32(*code).unwrap_or(ch);
            }
            let mapped = match ch {
                'A'..='Z' => Some(upper_base + (ch as u32 - 'A' as u32)),
                'a'..='z' => Some(lower_base + (ch as u32 - 'a' as u32)),
                '0'..='9' => digit_base.map(|base| base + (ch as u32 - '0' as u32)),
                _ => None,
            };
            mapped.and_then(char::from_u32).unwrap_or(ch)
        })
        .collect()
}

/// Circled digits are not contiguous: 1 to 9 start at U+2460 and zero sits on
/// its own at U+24EA.
fn circled_digits() -> Vec<(char, u32)> {
    let mut table = vec![('0', 0x24EA)];
    for digit in 1..=9u32 {
        let ch = char::from_u32('0' as u32 + digit).expect("ascii digit");
        table.push((ch, 0x2460 + digit - 1));
    }
    table
}

fn small_cap(ch: char) -> char {
    const CAPS: [char; 26] = [
        '\u{1D00}', '\u{0299}', '\u{1D04}', '\u{1D05}', '\u{1D07}', '\u{A730}', '\u{0262}',
        '\u{029C}', '\u{026A}', '\u{1D0A}', '\u{1D0B}', '\u{029F}', '\u{1D0D}', '\u{0274}',
        '\u{1D0F}', '\u{1D18}', 'q', '\u{0280}', '\u{A731}', '\u{1D1B}', '\u{1D1C}', '\u{1D20}',
        '\u{1D21}', 'x', '\u{028F}', '\u{1D22}',
    ];
    match ch.to_ascii_lowercase() {
        c @ 'a'..='z' => CAPS[(c as u8 - b'a') as usize],
        other => other,
    }
}

fn flip(ch: char) -> char {
    const PAIRS: &[(char, char)] = &[
        ('a', '\u{0250}'),
        ('b', 'q'),
        ('c', '\u{0254}'),
        ('d', 'p'),
        ('e', '\u{01DD}'),
        ('f', '\u{025F}'),
        ('g', '\u{0183}'),
        ('h', '\u{0265}'),
        ('i', '\u{0131}'),
        ('j', '\u{027E}'),
        ('k', '\u{029E}'),
        ('l', 'l'),
        ('m', '\u{026F}'),
        ('n', 'u'),
        ('o', 'o'),
        ('p', 'd'),
        ('q', 'b'),
        ('r', '\u{0279}'),
        ('s', 's'),
        ('t', '\u{0287}'),
        ('u', 'n'),
        ('v', '\u{028C}'),
        ('w', '\u{028D}'),
        ('x', 'x'),
        ('y', '\u{028E}'),
        ('z', 'z'),
        ('.', '\u{02D9}'),
        (',', '\''),
        ('?', '\u{00BF}'),
        ('!', '\u{00A1}'),
        ('"', ','),
        ('\'', ','),
        ('(', ')'),
        (')', '('),
        ('[', ']'),
        (']', '['),
        ('{', '}'),
        ('}', '{'),
        ('<', '>'),
        ('>', '<'),
        ('&', '\u{214B}'),
        ('_', '\u{203E}'),
        ('1', '\u{0196}'),
        ('2', '\u{218A}'),
        ('3', '\u{218B}'),
        ('4', '\u{3123}'),
        ('5', '\u{03DB}'),
        ('6', '9'),
        ('7', '\u{3125}'),
        ('9', '6'),
    ];
    let lower = ch.to_ascii_lowercase();
    PAIRS
        .iter()
        .find(|(from, _)| *from == lower)
        .map(|(_, to)| *to)
        .unwrap_or(ch)
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
    fn reverses_by_grapheme_not_by_byte() {
        assert_eq!(run("reverse", "hello"), "olleh");
        assert_eq!(run("reverse", "caf\u{e9}"), "\u{e9}fac");
        assert_eq!(run("reverse-words", "one two three"), "three two one");
    }

    #[test]
    fn repeats_and_truncates() {
        assert_eq!(run_with("repeat", "ab", "count=3"), "ababab");
        assert_eq!(run_with("repeat", "ab", "count=2 sep=-"), "ab-ab");
        assert_eq!(run_with("truncate", "abcdefgh", "length=4"), "abcd");
        assert_eq!(
            run_with("truncate", "abcdefgh", "length=5 suffix=..."),
            "ab..."
        );
        assert_eq!(run_with("truncate", "abc", "length=10"), "abc");
    }

    #[test]
    fn trims_whitespace_and_characters() {
        assert_eq!(run("trim", "  hi  "), "hi");
        assert_eq!(run_with("trim", "  hi  ", "start"), "hi  ");
        assert_eq!(run_with("trim", "  hi  ", "end"), "  hi");
        assert_eq!(run_with("trim", "/path/", "chars=/"), "path");
    }

    #[test]
    fn replaces_literally_and_by_pattern() {
        assert_eq!(
            run_with("replace", "the cat sat", "find=cat with=dog"),
            "the dog sat"
        );
        assert_eq!(
            run_with("replace", "a  b", "regex find='\\s+' with=-"),
            "a-b"
        );
        assert_eq!(run_with("replace", "aa", "find=a with=b first"), "ba");
        assert_eq!(
            run_with("replace", "Cat cat", "find=cat with=dog ignore-case"),
            "dog dog"
        );
    }

    #[test]
    fn extracts_matches_and_groups() {
        assert_eq!(run_with("extract", "a1 b2", "regex='[a-z]\\d'"), "a1\nb2");
        assert_eq!(run_with("extract", "v12", "regex='v(\\d+)' group=1"), "12");
        assert_eq!(run_with("extract", "a1 b2", "regex='[a-z]\\d' first"), "a1");
    }

    #[test]
    fn cleans_up_text() {
        assert_eq!(run("squeeze", "too    many   spaces"), "too many spaces");
        assert_eq!(run("remove-whitespace", " a b "), "ab");
        assert_eq!(run("remove-punctuation", "hi, there!"), "hi there");
        assert_eq!(
            run("remove-accents", "cr\u{e8}me br\u{fb}l\u{e9}e"),
            "creme brulee"
        );
        assert_eq!(run("remove-non-ascii", "caf\u{e9}"), "caf");
        assert_eq!(run("strip-html", "<p>Hi &amp; bye</p>"), "Hi & bye");
        assert_eq!(run_with("remove", "a-b-c", "text=-"), "abc");
    }

    #[test]
    fn slugifies_titles() {
        assert_eq!(run("slugify", "Hello, World! 2024"), "hello-world-2024");
        assert_eq!(run("slugify", "  caf\u{e9} au lait  "), "cafe-au-lait");
        assert_eq!(run("slugify", "--already--slug--"), "already-slug");
    }

    #[test]
    fn converts_whitespace_forms() {
        assert_eq!(run_with("tabs-to-spaces", "a\tb", "width=2"), "a  b");
        assert_eq!(run_with("spaces-to-tabs", "a  b", "width=2"), "a\tb");
        assert_eq!(run("newlines-to-spaces", "a\nb"), "a b");
        assert_eq!(run("spaces-to-newlines", "a b"), "a\nb");
    }

    #[test]
    fn rotates_and_mirrors() {
        assert_eq!(run_with("rotate", "abcd", "count=1"), "bcda");
        assert_eq!(run_with("rotate", "abcd", "count=-1"), "dabc");
        assert_eq!(run("palindrome", "abc"), "abcba");
    }

    #[test]
    fn normalizes_and_escapes() {
        assert_eq!(run_with("normalize", "e\u{301}", "form=nfc"), "\u{e9}");
        assert_eq!(run("escape-regex", "a.b"), "a\\.b");
        assert_eq!(run_with("quote", "hi", "char=\"'\""), "'hi'");
    }

    #[test]
    fn fancy_styles_map_letters() {
        assert_eq!(
            run_with("fancy", "abc", "style=bold"),
            "\u{1D41A}\u{1D41B}\u{1D41C}"
        );
        assert_eq!(
            run_with("fancy", "hi", "style=fullwidth"),
            "\u{FF48}\u{FF49}"
        );
        // The double struck alphabet has holes that must be filled in.
        assert_eq!(run_with("fancy", "CH", "style=double"), "\u{2102}\u{210D}");
        assert_eq!(run_with("fancy", "0", "style=circled"), "\u{24EA}");
        // Flipping reverses the text and swaps each letter for its mirror.
        assert_eq!(
            run_with("fancy", "hello", "style=flip"),
            "oll\u{01DD}\u{0265}"
        );
    }

    #[test]
    fn fancy_rejects_an_unknown_style() {
        let op = find("fancy").unwrap();
        let params = Params::parse_kv(op, "style=sparkles").unwrap();
        let error = op
            .apply("hi", &params, None)
            .expect_err("unknown style")
            .to_string();
        assert!(error.contains("unknown style"));
    }
}
