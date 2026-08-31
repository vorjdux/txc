//! Reordering, filtering and reshaping lines.

use anyhow::{Context, Result};
use rand::seq::SliceRandom;
use unicode_segmentation::UnicodeSegmentation;

use crate::registry::{Category, Feed, Op, Param};

const CAT: Category = Category::Lines;

static P_SORT: &[Param] = &[
    Param::flag("reverse", Some('r'), "Sort in descending order"),
    Param::flag("numeric", None, "Compare the leading number on each line"),
    Param::flag("ignore-case", Some('i'), "Compare without regard to case"),
    Param::flag("unique", Some('u'), "Drop duplicate lines after sorting"),
    Param::flag("length", Some('l'), "Sort by line length"),
];
static P_IGNORE_CASE: &[Param] = &[Param::flag(
    "ignore-case",
    Some('i'),
    "Compare without regard to case",
)];
static P_COUNT: &[Param] = &[Param::valued(
    "count",
    Some('c'),
    "N",
    "10",
    "How many lines to keep",
)];
static P_FILTER: &[Param] = &[
    Param::value(
        "contains",
        Some('c'),
        "TEXT",
        "Keep lines containing this text",
    ),
    Param::value(
        "regex",
        Some('r'),
        "PATTERN",
        "Keep lines matching this regular expression",
    ),
    Param::flag("invert", Some('v'), "Keep the lines that do not match"),
    Param::flag("ignore-case", Some('i'), "Match without regard to case"),
];
static P_NUMBER: &[Param] = &[
    Param::valued("start", Some('s'), "N", "1", "First number to use"),
    Param::valued(
        "sep",
        None,
        "TEXT",
        ". ",
        "Text between the number and the line",
    ),
    Param::valued(
        "width",
        Some('w'),
        "N",
        "0",
        "Pad numbers to this width with spaces",
    ),
    Param::flag(
        "zeros",
        Some('z'),
        "Pad numbers with zeros instead of spaces",
    ),
];
static P_TEXT: &[Param] = &[Param::valued("text", Some('t'), "TEXT", "", "Text to add")];
static P_SEP_JOIN: &[Param] = &[Param::valued(
    "sep",
    Some('s'),
    "TEXT",
    "",
    "Text placed between the joined lines",
)];
static P_SPLIT: &[Param] = &[
    Param::valued("sep", Some('s'), "TEXT", " ", "Separator to split on"),
    Param::flag(
        "regex",
        Some('r'),
        "Treat the separator as a regular expression",
    ),
    Param::flag("keep-empty", None, "Keep empty pieces"),
];
static P_INDENT: &[Param] = &[
    Param::valued(
        "count",
        Some('c'),
        "N",
        "4",
        "How many characters to indent by",
    ),
    Param::flag("tabs", Some('t'), "Indent with tabs instead of spaces"),
];
static P_WIDTH: &[Param] = &[Param::valued(
    "width",
    Some('w'),
    "N",
    "80",
    "Target width in characters",
)];
static P_PAD: &[Param] = &[
    Param::valued("width", Some('w'), "N", "10", "Target width in characters"),
    Param::valued("char", Some('c'), "CHAR", " ", "Character used for padding"),
];
static P_CHUNK: &[Param] = &[Param::valued(
    "size",
    Some('s'),
    "N",
    "80",
    "Characters per output line",
)];
static P_SAMPLE: &[Param] = &[Param::valued(
    "count",
    Some('c'),
    "N",
    "1",
    "How many lines to pick",
)];

pub(crate) fn register(out: &mut Vec<Op>) {
    out.push(
        Op::new(
            "sort",
            CAT,
            Feed::Buffer,
            "Sort lines alphabetically",
            |s, p| {
                let mut lines = to_lines(s);
                if p.flag("numeric") {
                    lines.sort_by(|a, b| {
                        leading_number(a)
                            .partial_cmp(&leading_number(b))
                            .unwrap_or(std::cmp::Ordering::Equal)
                    });
                } else if p.flag("length") {
                    lines.sort_by_key(|l| l.chars().count());
                } else if p.flag("ignore-case") {
                    lines.sort_by_key(|l| l.to_lowercase());
                } else {
                    lines.sort_unstable();
                }
                if p.flag("reverse") {
                    lines.reverse();
                }
                if p.flag("unique") {
                    lines.dedup();
                }
                Ok(lines.join("\n"))
            },
        )
        .params(P_SORT)
        .examples(&["txc sort --file names.txt", "printf 'b\\na\\n' | txc sort"]),
    );

    out.push(
        Op::new(
            "shuffle",
            CAT,
            Feed::Buffer,
            "Put the lines in random order",
            |s, _| {
                let mut lines = to_lines(s);
                lines.shuffle(&mut rand::rng());
                Ok(lines.join("\n"))
            },
        )
        .aliases(&["randomize-lines"]),
    );

    out.push(
        Op::new(
            "unique",
            CAT,
            Feed::Buffer,
            "Remove duplicate lines, keeping the first of each",
            |s, p| {
                let ignore_case = p.flag("ignore-case");
                let mut seen = std::collections::HashSet::new();
                Ok(to_lines(s)
                    .into_iter()
                    .filter(|line| {
                        let key = if ignore_case {
                            line.to_lowercase()
                        } else {
                            (*line).to_string()
                        };
                        seen.insert(key)
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            },
        )
        .aliases(&["dedupe", "remove-duplicates", "uniq"])
        .params(P_IGNORE_CASE)
        .examples(&["txc unique --file log.txt"]),
    );

    out.push(
        Op::new(
            "duplicates",
            CAT,
            Feed::Buffer,
            "Keep only lines that appear more than once",
            |s, p| {
                let ignore_case = p.flag("ignore-case");
                let key_of = |line: &str| {
                    if ignore_case {
                        line.to_lowercase()
                    } else {
                        line.to_string()
                    }
                };
                let lines = to_lines(s);
                let mut counts = std::collections::HashMap::new();
                for line in &lines {
                    *counts.entry(key_of(line)).or_insert(0usize) += 1;
                }
                let mut emitted = std::collections::HashSet::new();
                Ok(lines
                    .iter()
                    .filter(|line| {
                        let key = key_of(line);
                        counts[&key] > 1 && emitted.insert(key)
                    })
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n"))
            },
        )
        .params(P_IGNORE_CASE),
    );

    out.push(
        Op::new(
            "reverse-lines",
            CAT,
            Feed::Buffer,
            "Put the lines in reverse order",
            |s, _| {
                let mut lines = to_lines(s);
                lines.reverse();
                Ok(lines.join("\n"))
            },
        )
        .aliases(&["tac"]),
    );

    out.push(
        Op::new("head", CAT, Feed::Buffer, "Keep the first lines", |s, p| {
            let count: usize = p.parse("count")?;
            Ok(to_lines(s)
                .into_iter()
                .take(count)
                .collect::<Vec<_>>()
                .join("\n"))
        })
        .aliases(&["first"])
        .params(P_COUNT),
    );

    out.push(
        Op::new("tail", CAT, Feed::Buffer, "Keep the last lines", |s, p| {
            let count: usize = p.parse("count")?;
            let lines = to_lines(s);
            let skip = lines.len().saturating_sub(count);
            Ok(lines.into_iter().skip(skip).collect::<Vec<_>>().join("\n"))
        })
        .aliases(&["last"])
        .params(P_COUNT),
    );

    out.push(
        Op::new(
            "filter",
            CAT,
            Feed::Buffer,
            "Keep the lines matching a text or a regular expression",
            |s, p| {
                let invert = p.flag("invert");
                let ignore_case = p.flag("ignore-case");

                let matcher: Box<dyn Fn(&str) -> bool> =
                    match (p.supplied("contains"), p.supplied("regex")) {
                        (_, Some(pattern)) => {
                            let regex = regex::RegexBuilder::new(pattern)
                                .case_insensitive(ignore_case)
                                .build()
                                .with_context(|| {
                                    format!("{pattern:?} is not a valid regular expression")
                                })?;
                            Box::new(move |line: &str| regex.is_match(line))
                        }
                        (Some(needle), None) => {
                            let needle = if ignore_case {
                                needle.to_lowercase()
                            } else {
                                needle.to_string()
                            };
                            Box::new(move |line: &str| {
                                if ignore_case {
                                    line.to_lowercase().contains(&needle)
                                } else {
                                    line.contains(&needle)
                                }
                            })
                        }
                        (None, None) => anyhow::bail!("give either --contains or --regex"),
                    };

                Ok(to_lines(s)
                    .into_iter()
                    .filter(|line| matcher(line) != invert)
                    .collect::<Vec<_>>()
                    .join("\n"))
            },
        )
        .aliases(&["grep"])
        .params(P_FILTER)
        .examples(&[
            "txc filter --contains error --file app.log",
            "txc filter --regex '^\\d+' --invert --file data.txt",
        ]),
    );

    out.push(
        Op::new(
            "remove-empty",
            CAT,
            Feed::Buffer,
            "Remove blank lines",
            |s, _| {
                Ok(to_lines(s)
                    .into_iter()
                    .filter(|line| !line.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join("\n"))
            },
        )
        .aliases(&["compact"]),
    );

    out.push(
        Op::new(
            "number",
            CAT,
            Feed::Buffer,
            "Prefix every line with its number",
            |s, p| {
                let start: usize = p.parse("start")?;
                let width: usize = p.parse("width")?;
                let sep = p.get("sep");
                let zeros = p.flag("zeros");
                Ok(to_lines(s)
                    .into_iter()
                    .enumerate()
                    .map(|(i, line)| {
                        let n = start + i;
                        let label = if zeros {
                            format!("{n:0width$}")
                        } else {
                            format!("{n:width$}")
                        };
                        format!("{label}{sep}{line}")
                    })
                    .collect::<Vec<_>>()
                    .join("\n"))
            },
        )
        .aliases(&["number-lines", "nl"])
        .params(P_NUMBER)
        .examples(&[
            "txc number --file recipe.txt",
            "txc number --width 3 --zeros --file recipe.txt",
        ]),
    );

    out.push(
        Op::new(
            "prefix",
            CAT,
            Feed::Lines,
            "Add text to the start of every line",
            |s, p| Ok(format!("{}{s}", p.get("text"))),
        )
        .aliases(&["add-prefix"])
        .params(P_TEXT)
        .examples(&["txc prefix --text '> ' --file quote.txt"]),
    );

    out.push(
        Op::new(
            "suffix",
            CAT,
            Feed::Lines,
            "Add text to the end of every line",
            |s, p| Ok(format!("{s}{}", p.get("text"))),
        )
        .aliases(&["add-suffix"])
        .params(P_TEXT),
    );

    out.push(Op::new(
        "trim-lines",
        CAT,
        Feed::Lines,
        "Remove leading and trailing spaces from every line",
        |s, _| Ok(s.trim().to_string()),
    ));

    out.push(
        Op::new(
            "join",
            CAT,
            Feed::Buffer,
            "Join all lines into one",
            |s, p| Ok(to_lines(s).join(p.get("sep"))),
        )
        .aliases(&["join-lines"])
        .params(P_SEP_JOIN)
        .examples(&["txc join --sep ', ' --file names.txt"]),
    );

    out.push(
        Op::new(
            "split",
            CAT,
            Feed::Buffer,
            "Split text into one line per piece",
            |s, p| {
                let sep = p.get("sep");
                let keep_empty = p.flag("keep-empty");
                let pieces: Vec<String> = if p.flag("regex") {
                    let regex = regex::Regex::new(sep)
                        .with_context(|| format!("{sep:?} is not a valid regular expression"))?;
                    regex.split(s).map(str::to_string).collect()
                } else if sep.is_empty() {
                    s.graphemes(true).map(str::to_string).collect()
                } else {
                    s.split(sep).map(str::to_string).collect()
                };
                Ok(pieces
                    .into_iter()
                    .filter(|piece| keep_empty || !piece.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n"))
            },
        )
        .aliases(&["split-text"])
        .params(P_SPLIT)
        .examples(&["txc split --sep , \"a,b,c\"", "txc split --sep '' abc"]),
    );

    out.push(
        Op::new("indent", CAT, Feed::Lines, "Indent every line", |s, p| {
            let count: usize = p.parse("count")?;
            let unit = if p.flag("tabs") { '\t' } else { ' ' };
            Ok(format!("{}{s}", unit.to_string().repeat(count)))
        })
        .params(P_INDENT),
    );

    out.push(Op::new(
        "dedent",
        CAT,
        Feed::Buffer,
        "Remove the common leading whitespace",
        |s, _| {
            let lines = to_lines(s);
            let common = lines
                .iter()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.len() - l.trim_start().len())
                .min()
                .unwrap_or(0);
            Ok(lines
                .iter()
                .map(|l| {
                    if l.len() >= common {
                        &l[common..]
                    } else {
                        l.trim_start()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n"))
        },
    ));

    out.push(
        Op::new(
            "wrap",
            CAT,
            Feed::Buffer,
            "Wrap text to a maximum line width",
            |s, p| {
                let width: usize = p.parse("width")?;
                anyhow::ensure!(width > 0, "--width must be at least 1");
                Ok(textwrap::wrap(s, width).join("\n"))
            },
        )
        .aliases(&["fill"])
        .params(P_WIDTH)
        .examples(&["txc wrap --width 60 --file article.txt"]),
    );

    out.push(
        Op::new(
            "center",
            CAT,
            Feed::Lines,
            "Centre every line inside a width",
            |s, p| {
                let width: usize = p.parse("width")?;
                let len = s.chars().count();
                if len >= width {
                    return Ok(s.to_string());
                }
                let left = (width - len) / 2;
                Ok(format!("{}{s}", " ".repeat(left)))
            },
        )
        .params(P_WIDTH),
    );

    out.push(
        Op::new(
            "pad-left",
            CAT,
            Feed::Lines,
            "Pad every line on the left to a width",
            |s, p| pad(s, p.parse("width")?, p.get("char"), true),
        )
        .aliases(&["left-pad", "align-right"])
        .params(P_PAD)
        .examples(&["txc pad-left --width 5 --char 0 --file numbers.txt"]),
    );

    out.push(
        Op::new(
            "pad-right",
            CAT,
            Feed::Lines,
            "Pad every line on the right to a width",
            |s, p| pad(s, p.parse("width")?, p.get("char"), false),
        )
        .aliases(&["right-pad", "align-left"])
        .params(P_PAD),
    );

    out.push(
        Op::new(
            "chunk",
            CAT,
            Feed::Buffer,
            "Break text into fixed width lines",
            |s, p| {
                let size: usize = p.parse("size")?;
                anyhow::ensure!(size > 0, "--size must be at least 1");
                let graphemes: Vec<&str> = s.graphemes(true).collect();
                Ok(graphemes
                    .chunks(size)
                    .map(|chunk| chunk.concat())
                    .collect::<Vec<_>>()
                    .join("\n"))
            },
        )
        .params(P_CHUNK)
        .examples(&["txc chunk --size 4 abcdefgh"]),
    );

    out.push(
        Op::new("sample", CAT, Feed::Buffer, "Pick random lines", |s, p| {
            let count: usize = p.parse("count")?;
            let mut lines = to_lines(s);
            lines.shuffle(&mut rand::rng());
            lines.truncate(count);
            Ok(lines.join("\n"))
        })
        .aliases(&["random-line"])
        .params(P_SAMPLE),
    );
}

/// Splits input into lines, ignoring one trailing newline and normalising
/// Windows line endings.
pub fn to_lines(input: &str) -> Vec<&str> {
    let body = input.strip_suffix('\n').unwrap_or(input);
    if body.is_empty() {
        return Vec::new();
    }
    body.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect()
}

/// The leading number on a line, used by numeric sorting. Lines without one
/// sort before every number.
fn leading_number(line: &str) -> f64 {
    let trimmed = line.trim_start();
    let end = trimmed
        .find(|c: char| !(c.is_ascii_digit() || c == '-' || c == '+' || c == '.'))
        .unwrap_or(trimmed.len());
    trimmed[..end].parse().unwrap_or(f64::NEG_INFINITY)
}

fn pad(line: &str, width: usize, fill: &str, left: bool) -> Result<String> {
    let fill_char = fill.chars().next().unwrap_or(' ');
    let len = line.chars().count();
    if len >= width {
        return Ok(line.to_string());
    }
    let padding: String = std::iter::repeat_n(fill_char, width - len).collect();
    Ok(if left {
        format!("{padding}{line}")
    } else {
        format!("{line}{padding}")
    })
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
    fn sorts_in_several_ways() {
        assert_eq!(run("sort", "b\na\nc"), "a\nb\nc");
        assert_eq!(run_with("sort", "b\na\nc", "reverse"), "c\nb\na");
        assert_eq!(run_with("sort", "10\n9\n100", "numeric"), "9\n10\n100");
        assert_eq!(run_with("sort", "bbb\na\ncc", "length"), "a\ncc\nbbb");
        assert_eq!(run_with("sort", "b\na\nb", "unique"), "a\nb");
    }

    #[test]
    fn keeps_first_of_each_duplicate() {
        assert_eq!(run("unique", "b\na\nb\nc"), "b\na\nc");
        assert_eq!(run_with("unique", "A\na", "ignore-case"), "A");
        assert_eq!(run("duplicates", "a\nb\na\nc\nb"), "a\nb");
    }

    #[test]
    fn trims_and_selects() {
        assert_eq!(run_with("head", "1\n2\n3\n4", "count=2"), "1\n2");
        assert_eq!(run_with("tail", "1\n2\n3\n4", "count=2"), "3\n4");
        assert_eq!(run("reverse-lines", "a\nb\nc"), "c\nb\na");
        assert_eq!(run("remove-empty", "a\n\n  \nb"), "a\nb");
    }

    #[test]
    fn filters_by_text_and_pattern() {
        assert_eq!(
            run_with("filter", "one\ntwo\nthree", "contains=t"),
            "two\nthree"
        );
        assert_eq!(
            run_with("filter", "one\ntwo\nthree", "contains=t invert"),
            "one"
        );
        assert_eq!(run_with("filter", "a1\nb2\ncc", "regex='\\d'"), "a1\nb2");
        assert_eq!(
            run_with("filter", "One\ntwo", "contains=one ignore-case"),
            "One"
        );
    }

    #[test]
    fn filter_reports_a_missing_pattern() {
        let op = find("filter").unwrap();
        let error = op
            .apply("a", &Params::for_op(op), None)
            .expect_err("needs a pattern")
            .to_string();
        assert!(error.contains("--contains"));
    }

    #[test]
    fn numbers_lines() {
        assert_eq!(run("number", "a\nb"), "1. a\n2. b");
        assert_eq!(run_with("number", "a", "start=5 sep=': '"), "5: a");
        assert_eq!(run_with("number", "a", "width=3 zeros"), "001. a");
    }

    #[test]
    fn reshapes_text() {
        assert_eq!(run_with("prefix", "a\nb", "text='> '"), "> a\n> b");
        assert_eq!(run_with("suffix", "a\nb", "text=;"), "a;\nb;");
        assert_eq!(run_with("join", "a\nb", "sep=', '"), "a, b");
        assert_eq!(run_with("split", "a,b,c", "sep=,"), "a\nb\nc");
        assert_eq!(run_with("split", "abc", "sep=''"), "a\nb\nc");
        assert_eq!(run_with("chunk", "abcdef", "size=2"), "ab\ncd\nef");
        assert_eq!(run_with("indent", "a\nb", "count=2"), "  a\n  b");
        assert_eq!(run("dedent", "    a\n      b"), "a\n  b");
        assert_eq!(run_with("wrap", "aa bb cc", "width=5"), "aa bb\ncc");
        assert_eq!(run_with("pad-left", "7", "width=3 char=0"), "007");
        assert_eq!(run_with("pad-right", "7", "width=3 char=."), "7..");
    }

    #[test]
    fn handles_empty_input() {
        for name in [
            "sort",
            "unique",
            "reverse-lines",
            "remove-empty",
            "number",
            "join",
        ] {
            assert_eq!(run(name, ""), "", "{name} on empty input");
        }
    }

    #[test]
    fn shuffle_keeps_every_line() {
        let mut shuffled = run("shuffle", "a\nb\nc\nd")
            .lines()
            .map(str::to_string)
            .collect::<Vec<_>>();
        shuffled.sort();
        assert_eq!(shuffled, ["a", "b", "c", "d"]);
    }
}
