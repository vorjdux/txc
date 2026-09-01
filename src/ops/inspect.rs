//! Counting, statistics and character inspection.
//!
//! These report on text rather than changing it.
//!
//! ```
//! use txc::{Params, find};
//!
//! let op = find("count-words").expect("count-words is registered");
//! assert_eq!(op.apply("hello world", &Params::for_op(op), None)?, "2");
//!
//! let op = find("count-chars").expect("count-chars is registered");
//! assert_eq!(op.apply("hello", &Params::for_op(op), None)?, "5");
//! # Ok::<(), anyhow::Error>(())
//! ```

use std::collections::HashMap;

use unicode_segmentation::UnicodeSegmentation;

use crate::ops::lines::to_lines;
use crate::registry::{Category, Feed, Op, Param};

const CAT: Category = Category::Inspect;

static P_FREQUENCY: &[Param] = &[
    Param::valued(
        "by",
        Some('b'),
        "UNIT",
        "word",
        "What to count: word, char or line",
    ),
    Param::valued(
        "top",
        Some('t'),
        "N",
        "0",
        "Only show the most frequent entries, 0 for all",
    ),
    Param::flag("ignore-case", Some('i'), "Count without regard to case"),
    Param::flag("percent", Some('p'), "Include the share of the total"),
];

pub(crate) fn register(out: &mut Vec<Op>) {
    out.push(
        Op::new(
            "stats",
            CAT,
            Feed::Buffer,
            "Summarise the text in numbers",
            |s, _| {
                // This is the operation most likely to be pointed at a large
                // file, so the words and the lines are each walked once.
                let mut words = 0usize;
                let mut word_characters = 0usize;
                let mut unique = std::collections::HashSet::new();
                for word in s.unicode_words() {
                    words += 1;
                    word_characters += word.chars().count();
                    unique.insert(word.to_lowercase());
                }

                let all_lines = to_lines(s);
                let lines = all_lines.len();
                let longest = all_lines
                    .iter()
                    .map(|l| l.chars().count())
                    .max()
                    .unwrap_or(0);

                let characters = s.graphemes(true).count();
                let without_spaces = s.chars().filter(|c| !c.is_whitespace()).count();
                let sentences = s
                    .split(['.', '!', '?'])
                    .filter(|part| !part.trim().is_empty())
                    .count();
                let paragraphs = s
                    .split("\n\n")
                    .filter(|part| !part.trim().is_empty())
                    .count();
                let average = if words == 0 {
                    0.0
                } else {
                    word_characters as f64 / words as f64
                };
                // 200 words per minute is the usual figure for silent reading.
                //
                // Rounded to the nearest second in whole numbers. Doing it in
                // f64 read 205 words as 61 seconds rather than 62, because
                // 61.5 is not representable and the value landed just under.
                let reading_seconds = (words as u64 * 60 + 100) / 200;

                Ok(format!(
                    "characters       {characters}\n\
                 without spaces   {without_spaces}\n\
                 bytes            {}\n\
                 words            {words}\n\
                 unique words     {}\n\
                 lines            {lines}\n\
                 longest line     {longest}\n\
                 sentences        {sentences}\n\
                 paragraphs       {paragraphs}\n\
                 average word     {average:.1}\n\
                 reading time     {}",
                    s.len(),
                    unique.len(),
                    format_duration(reading_seconds),
                ))
            },
        )
        .sample(
            "The quick brown fox jumps over the lazy dog.
A second sentence here.

And a new paragraph.",
        )
        .aliases(&["analyze", "info"])
        .examples(&["txc stats --file article.txt"]),
    );

    out.push(
        Op::new(
            "count-chars",
            CAT,
            Feed::Buffer,
            "Count characters",
            |s, _| Ok(s.graphemes(true).count().to_string()),
        )
        .aliases(&["length", "len"])
        .examples(&["txc count-chars \"hello\""]),
    );

    out.push(
        Op::new("count-words", CAT, Feed::Buffer, "Count words", |s, _| {
            Ok(s.unicode_words().count().to_string())
        })
        .aliases(&["wc"]),
    );

    out.push(Op::new(
        "count-lines",
        CAT,
        Feed::Buffer,
        "Count lines",
        |s, _| Ok(to_lines(s).len().to_string()),
    ));

    out.push(Op::new(
        "count-bytes",
        CAT,
        Feed::Buffer,
        "Count bytes",
        |s, _| Ok(s.len().to_string()),
    ));

    out.push(
        Op::new(
            "frequency",
            CAT,
            Feed::Buffer,
            "Count how often each word, character or line appears",
            |s, p| {
                let ignore_case = p.flag("ignore-case");
                let top: usize = p.parse("top")?;
                let text = if ignore_case {
                    s.to_lowercase()
                } else {
                    s.to_string()
                };

                let items: Vec<String> = match p.get("by") {
                    "word" | "words" => text.unicode_words().map(str::to_string).collect(),
                    "char" | "chars" | "character" => text
                        .graphemes(true)
                        .filter(|g| !g.trim().is_empty())
                        .map(str::to_string)
                        .collect(),
                    "line" | "lines" => to_lines(&text)
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect(),
                    other => anyhow::bail!("unknown unit {other:?}, use word, char or line"),
                };

                let total = items.len();
                let mut counts: HashMap<String, usize> = HashMap::new();
                for item in items {
                    *counts.entry(item).or_default() += 1;
                }

                // Ties are broken alphabetically so the output is stable.
                let mut ranked: Vec<(String, usize)> = counts.into_iter().collect();
                ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                if top > 0 {
                    ranked.truncate(top);
                }

                let width = ranked
                    .iter()
                    .map(|(k, _)| k.chars().count())
                    .max()
                    .unwrap_or(0);
                Ok(ranked
                    .iter()
                    .map(|(item, count)| {
                        if p.flag("percent") && total > 0 {
                            let share = *count as f64 / total as f64 * 100.0;
                            format!("{item:width$}  {count}  {share:.1}%")
                        } else {
                            format!("{item:width$}  {count}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            },
        )
        .sample("the cat and the dog and the bird")
        .aliases(&["freq", "histogram"])
        .params(P_FREQUENCY)
        .examples(&[
            "txc frequency --file speech.txt --top 10",
            "txc frequency --by char --percent \"hello\"",
        ]),
    );

    out.push(
        Op::new(
            "is-palindrome",
            CAT,
            Feed::Lines,
            "Report whether the text reads the same backwards",
            |s, _| {
                let cleaned: Vec<char> = s
                    .chars()
                    .filter(|c| c.is_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect();
                let reversed: Vec<char> = cleaned.iter().rev().copied().collect();
                Ok(if cleaned == reversed { "yes" } else { "no" }.to_string())
            },
        )
        .sample("A man, a plan, a canal: Panama")
        .examples(&["txc is-palindrome \"A man, a plan, a canal: Panama\""]),
    );

    out.push(
        Op::new(
            "charinfo",
            CAT,
            Feed::Buffer,
            "Describe every character: code point, bytes and category",
            |s, _| {
                Ok(s.chars()
                    .map(|ch| {
                        let mut buffer = [0u8; 4];
                        let bytes = ch.encode_utf8(&mut buffer).as_bytes();
                        let hex = crate::ops::to_hex(bytes, false);
                        let display = if ch.is_control() {
                            format!("<{:02x}>", ch as u32)
                        } else {
                            ch.to_string()
                        };
                        format!(
                            "{display:<4} U+{:04X}  {:<10} {}",
                            ch as u32,
                            hex,
                            describe(ch)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            },
        )
        .sample("caf\u{e9}")
        .aliases(&["chars", "explain"])
        .examples(&["txc charinfo \"a\u{e9}\""]),
    );
}

fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else {
        format!("{}m {}s", seconds / 60, seconds % 60)
    }
}

fn describe(ch: char) -> &'static str {
    if ch.is_control() {
        "control"
    } else if ch.is_whitespace() {
        "whitespace"
    } else if ch.is_numeric() {
        "digit"
    } else if ch.is_uppercase() {
        "uppercase letter"
    } else if ch.is_lowercase() {
        "lowercase letter"
    } else if ch.is_alphabetic() {
        "letter"
    } else if ch.is_ascii_punctuation() {
        "punctuation"
    } else {
        "symbol"
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
    fn counts_the_obvious_things() {
        assert_eq!(run("count-chars", "hello"), "5");
        assert_eq!(run("count-words", "one two three"), "3");
        assert_eq!(run("count-lines", "a\nb\nc"), "3");
        assert_eq!(run("count-bytes", "caf\u{e9}"), "5");
        // A combining sequence is one character but several code points.
        assert_eq!(run("count-chars", "e\u{301}"), "1");
    }

    #[test]
    fn counts_nothing_in_empty_input() {
        assert_eq!(run("count-chars", ""), "0");
        assert_eq!(run("count-words", ""), "0");
        assert_eq!(run("count-lines", ""), "0");
    }

    #[test]
    fn stats_reports_every_field() {
        let report = run("stats", "One two. Three?\n\nSecond paragraph here.");
        assert!(report.contains("words            6"), "{report}");
        assert!(report.contains("sentences        3"), "{report}");
        assert!(report.contains("paragraphs       2"), "{report}");
        assert!(report.contains("reading time"), "{report}");
    }

    #[test]
    fn frequency_ranks_by_count_then_alphabetically() {
        assert_eq!(run_with("frequency", "b a a", "by=word"), "a  2\nb  1");
        assert_eq!(run_with("frequency", "aab", "by=char top=1"), "a  2");
        assert_eq!(run_with("frequency", "A a", "by=word ignore-case"), "a  2");
        assert!(run_with("frequency", "a a b", "by=word percent").contains("66.7%"));
    }

    #[test]
    fn frequency_rejects_an_unknown_unit() {
        let op = find("frequency").unwrap();
        let params = Params::parse_kv(op, "by=sentence").unwrap();
        assert!(op.apply("a", &params, None).is_err());
    }

    #[test]
    fn detects_palindromes_ignoring_punctuation() {
        assert_eq!(
            run("is-palindrome", "A man, a plan, a canal: Panama"),
            "yes"
        );
        assert_eq!(run("is-palindrome", "hello"), "no");
    }

    #[test]
    fn charinfo_describes_each_character() {
        let report = run("charinfo", "a\u{e9}");
        assert!(report.contains("U+0061"), "{report}");
        assert!(report.contains("U+00E9"), "{report}");
        assert!(report.contains("c3a9"), "{report}");
    }
}
