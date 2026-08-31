//! Case conversion.

use rand::RngExt;

use crate::ops::{capitalize_first, capitalize_only, split_words};
use crate::registry::{Category, Feed, Op};

const CAT: Category = Category::Case;

pub(crate) fn register(out: &mut Vec<Op>) {
    out.push(
        Op::new(
            "upper",
            CAT,
            Feed::Lines,
            "Convert text to UPPERCASE",
            |s, _| Ok(s.to_uppercase()),
        )
        .aliases(&["uc", "uppercase"])
        .examples(&["txc upper \"hello world\"", "cat notes.txt | txc upper"]),
    );

    out.push(
        Op::new(
            "lower",
            CAT,
            Feed::Lines,
            "Convert text to lowercase",
            |s, _| Ok(s.to_lowercase()),
        )
        .aliases(&["lc", "lowercase"])
        .examples(&["txc lower \"HELLO WORLD\""]),
    );

    out.push(
        Op::new(
            "title",
            CAT,
            Feed::Lines,
            "Capitalise The First Letter Of Every Word",
            |s, _| {
                Ok(s.split_inclusive(char::is_whitespace)
                    .map(|chunk| {
                        let trimmed = chunk.trim_end();
                        let spacing = &chunk[trimmed.len()..];
                        capitalize_only(trimmed) + spacing
                    })
                    .collect())
            },
        )
        .aliases(&["titlecase"])
        .examples(&["txc title \"the quick brown fox\""]),
    );

    out.push(
        Op::new(
            "sentence",
            CAT,
            Feed::Lines,
            "Capitalise the first letter of every sentence",
            |s, _| {
                let mut out = String::with_capacity(s.len());
                let mut start_of_sentence = true;
                for ch in s.chars() {
                    if start_of_sentence && ch.is_alphabetic() {
                        out.extend(ch.to_uppercase());
                        start_of_sentence = false;
                    } else {
                        out.extend(ch.to_lowercase());
                    }
                    if matches!(ch, '.' | '!' | '?') {
                        start_of_sentence = true;
                    }
                }
                Ok(out)
            },
        )
        .aliases(&["sentencecase"])
        .examples(&["txc sentence \"first one. second one\""]),
    );

    out.push(
        Op::new(
            "capitalize",
            CAT,
            Feed::Lines,
            "Capitalise the first letter of every word, keeping the rest as is",
            |s, _| {
                Ok(s.split_inclusive(char::is_whitespace)
                    .map(|chunk| {
                        let trimmed = chunk.trim_end();
                        let spacing = &chunk[trimmed.len()..];
                        capitalize_first(trimmed) + spacing
                    })
                    .collect())
            },
        )
        .aliases(&["capitalise"]),
    );

    out.push(
        Op::new(
            "camel",
            CAT,
            Feed::Lines,
            "Convert text to camelCase",
            |s, _| {
                let words = split_words(s);
                Ok(words
                    .iter()
                    .enumerate()
                    .map(|(i, w)| {
                        if i == 0 {
                            w.to_lowercase()
                        } else {
                            capitalize_only(w)
                        }
                    })
                    .collect())
            },
        )
        .aliases(&["camelcase"])
        .examples(&["txc camel \"user first name\""]),
    );

    out.push(
        Op::new(
            "pascal",
            CAT,
            Feed::Lines,
            "Convert text to PascalCase",
            |s, _| Ok(split_words(s).iter().map(|w| capitalize_only(w)).collect()),
        )
        .aliases(&["pascalcase"])
        .examples(&["txc pascal \"user first name\""]),
    );

    out.push(
        Op::new(
            "snake",
            CAT,
            Feed::Lines,
            "Convert text to snake_case",
            |s, _| Ok(join_words(s, "_", Casing::Lower)),
        )
        .aliases(&["snakecase"])
        .examples(&["txc snake \"userFirstName\""]),
    );

    out.push(
        Op::new(
            "kebab",
            CAT,
            Feed::Lines,
            "Convert text to kebab-case",
            |s, _| Ok(join_words(s, "-", Casing::Lower)),
        )
        .aliases(&["kebabcase", "dash"])
        .examples(&["txc kebab \"userFirstName\""]),
    );

    out.push(
        Op::new(
            "constant",
            CAT,
            Feed::Lines,
            "Convert text to CONSTANT_CASE",
            |s, _| Ok(join_words(s, "_", Casing::Upper)),
        )
        .aliases(&["screaming", "macro"])
        .examples(&["txc constant \"max retry count\""]),
    );

    out.push(
        Op::new(
            "dot",
            CAT,
            Feed::Lines,
            "Convert text to dot.case",
            |s, _| Ok(join_words(s, ".", Casing::Lower)),
        )
        .aliases(&["dotcase"]),
    );

    out.push(
        Op::new(
            "train",
            CAT,
            Feed::Lines,
            "Convert text to Train-Case",
            |s, _| Ok(join_words(s, "-", Casing::Title)),
        )
        .aliases(&["traincase"]),
    );

    out.push(
        Op::new(
            "swap",
            CAT,
            Feed::Lines,
            "Swap the case of every letter",
            |s, _| {
                Ok(s.chars()
                    .flat_map(|c| {
                        let swapped: Box<dyn Iterator<Item = char>> = if c.is_uppercase() {
                            Box::new(c.to_lowercase())
                        } else {
                            Box::new(c.to_uppercase())
                        };
                        swapped
                    })
                    .collect())
            },
        )
        .aliases(&["invert-case", "swapcase"])
        .examples(&["txc swap \"Hello World\""]),
    );

    out.push(
        Op::new(
            "alternate",
            CAT,
            Feed::Lines,
            "Convert text to aLtErNaTiNg case",
            |s, _| {
                let mut upper = false;
                Ok(s.chars()
                    .map(|c| {
                        if !c.is_alphabetic() {
                            return c;
                        }
                        upper = !upper;
                        if upper {
                            c.to_lowercase().next().unwrap_or(c)
                        } else {
                            c.to_uppercase().next().unwrap_or(c)
                        }
                    })
                    .collect())
            },
        )
        .aliases(&["alternating", "mock"]),
    );

    out.push(
        Op::new(
            "random-case",
            CAT,
            Feed::Lines,
            "Randomise the case of every letter",
            |s, _| {
                let mut rng = rand::rng();
                Ok(s.chars()
                    .map(|c| {
                        if !c.is_alphabetic() {
                            return c;
                        }
                        if rng.random_bool(0.5) {
                            c.to_uppercase().next().unwrap_or(c)
                        } else {
                            c.to_lowercase().next().unwrap_or(c)
                        }
                    })
                    .collect())
            },
        )
        .aliases(&["randomcase"]),
    );
}

enum Casing {
    Lower,
    Upper,
    Title,
}

fn join_words(input: &str, separator: &str, casing: Casing) -> String {
    split_words(input)
        .iter()
        .map(|w| match casing {
            Casing::Lower => w.to_lowercase(),
            Casing::Upper => w.to_uppercase(),
            Casing::Title => capitalize_only(w),
        })
        .collect::<Vec<_>>()
        .join(separator)
}

#[cfg(test)]
mod tests {
    use crate::params::Params;
    use crate::registry::find;

    fn run(name: &str, input: &str) -> String {
        let op = find(name).expect("operation is registered");
        op.apply(input, &Params::for_op(op), None).expect("runs")
    }

    #[test]
    fn converts_between_conventions() {
        assert_eq!(run("upper", "hello"), "HELLO");
        assert_eq!(run("lower", "HeLLo"), "hello");
        assert_eq!(run("title", "the quick brown fox"), "The Quick Brown Fox");
        assert_eq!(run("camel", "user first name"), "userFirstName");
        assert_eq!(run("pascal", "user first name"), "UserFirstName");
        assert_eq!(run("snake", "userFirstName"), "user_first_name");
        assert_eq!(run("kebab", "userFirstName"), "user-first-name");
        assert_eq!(run("constant", "max retry count"), "MAX_RETRY_COUNT");
        assert_eq!(run("dot", "user first name"), "user.first.name");
        assert_eq!(run("train", "user first name"), "User-First-Name");
        assert_eq!(run("swap", "Hello World"), "hELLO wORLD");
        assert_eq!(run("alternate", "hello"), "hElLo");
    }

    #[test]
    fn title_preserves_spacing() {
        assert_eq!(run("title", "a  b"), "A  B");
        assert_eq!(run("capitalize", "iPhone case"), "IPhone Case");
    }

    #[test]
    fn sentence_case_restarts_after_punctuation() {
        assert_eq!(
            run("sentence", "first one. second one"),
            "First one. Second one"
        );
    }

    #[test]
    fn applies_per_line() {
        assert_eq!(run("upper", "a\nb"), "A\nB");
    }
}
