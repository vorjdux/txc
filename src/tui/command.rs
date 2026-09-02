//! The command line behind what the interface is showing.
//!
//! Everything the interactive interface does can be done from a shell, and the
//! footer says how. Reading the two forms back while experimenting is how the
//! interface teaches the command line rather than replacing it.

use crate::params::Params;
use crate::registry::{Feed, Op};

/// The longest input that is quoted into the command rather than stood in for
/// by a file. Beyond this the line stops being something worth reading.
const INLINE_LIMIT: usize = 48;

/// Stand-in used when the input is too long, or has more than one line, to sit
/// on a single line of the footer.
const FILE: &str = "input.txt";

/// The two ways to run an operation from a shell.
///
/// Built by [`invocation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    /// The form that takes the text as an argument, written out in full:
    /// canonical operation name and `--long` parameters.
    pub argument: String,
    /// The form that reads the text from a pipe, written as briefly as the
    /// operation allows: shortest alias and `-s` parameters.
    ///
    /// `None` for a generator, which has no input to pipe into it.
    pub pipe: Option<String>,
}

/// Writes out how to run `op` from a shell, in full and in brief.
///
/// Only parameters that differ from what the operation would do on its own are
/// included, so the line stays as short as the result allows.
///
/// ```
/// use txc::tui::command::invocation;
/// use txc::{Params, find};
///
/// let op = find("slugify").expect("slugify is registered");
/// let shown = invocation(op, &Params::for_op(op), "Hello there");
///
/// assert_eq!(shown.argument, "txc slugify 'Hello there'");
/// assert_eq!(shown.pipe.as_deref(), Some("echo 'Hello there' | txc slug"));
/// ```
///
/// A generator reads nothing, so there is no pipe form:
///
/// ```
/// use txc::tui::command::invocation;
/// use txc::{Params, find};
///
/// let op = find("uuid").expect("uuid is registered");
/// let shown = invocation(op, &Params::for_op(op), "");
///
/// assert_eq!(shown.argument, "txc uuid");
/// assert_eq!(shown.pipe, None);
/// ```
#[must_use]
pub fn invocation(op: &Op, params: &Params, input: &str) -> Invocation {
    let long = arguments(op, params, false);
    let short = arguments(op, params, true);

    let mut argument = format!("txc {}{long}", op.name);
    let mut pipe = format!("txc {}{short}", brief_name(op));

    if op.feed == Feed::None {
        return Invocation {
            argument,
            pipe: None,
        };
    }

    if let Some(text) = inline(input) {
        argument.push(' ');
        argument.push_str(&text);
        pipe = format!("echo {text} | {pipe}");
    } else {
        argument.push_str(" < ");
        argument.push_str(FILE);
        pipe = format!("cat {FILE} | {pipe}");
    }

    Invocation {
        argument,
        pipe: Some(pipe),
    }
}

/// The shortest name that reaches this operation: an alias where one is
/// shorter than the canonical name, and the canonical name otherwise.
///
/// ```
/// use txc::tui::command::brief_name;
/// use txc::find;
///
/// let slugify = find("slugify").expect("slugify is registered");
/// assert_eq!(brief_name(slugify), "slug");
///
/// // Nothing shorter is registered for this one, so it stays as it is.
/// let uuid = find("uuid").expect("uuid is registered");
/// assert_eq!(brief_name(uuid), "uuid");
/// ```
#[must_use]
pub fn brief_name(op: &Op) -> &'static str {
    op.aliases.iter().copied().fold(op.name, |best, alias| {
        if alias.len() < best.len() {
            alias
        } else {
            best
        }
    })
}

/// The parameters worth writing out, each already spaced and prefixed.
///
/// A value left at the operation's own default is left out: repeating it would
/// only make the line longer without changing what runs.
fn arguments(op: &Op, params: &Params, brief: bool) -> String {
    let mut out = String::new();

    for param in op.params {
        if param.is_flag() {
            if params.flag(param.name) {
                out.push(' ');
                out.push_str(&name_of(param, brief));
            }
            continue;
        }

        let Some(value) = params.supplied(param.name) else {
            continue;
        };
        if param.default_value() == Some(value) {
            continue;
        }

        out.push(' ');
        out.push_str(&name_of(param, brief));
        out.push(' ');
        out.push_str(&quote(value));
    }

    out
}

/// `--name`, or `-n` in the brief form where the parameter has a short letter.
fn name_of(param: &crate::registry::Param, brief: bool) -> String {
    match param.short {
        Some(letter) if brief => format!("-{letter}"),
        _ => format!("--{}", param.name),
    }
}

/// The input as a shell word, or `None` when it does not belong on one line.
fn inline(input: &str) -> Option<String> {
    if input.is_empty() || input.len() > INLINE_LIMIT {
        return None;
    }
    if input.chars().any(char::is_control) {
        return None;
    }
    Some(quote(input))
}

/// Quotes a word for a POSIX shell, leaving it bare when nothing needs it.
///
/// ```
/// use txc::tui::command::quote;
///
/// assert_eq!(quote("plain"), "plain");
/// assert_eq!(quote("two words"), "'two words'");
///
/// // A single quote ends the quoted run, escapes itself, and opens a new one.
/// assert_eq!(quote("it's"), r#"'it'\''s'"#);
/// ```
#[must_use]
pub fn quote(word: &str) -> String {
    let safe = !word.is_empty()
        && word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/-=:,+@".contains(c));
    if safe {
        return word.to_string();
    }
    format!("'{}'", word.replace('\'', r"'\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry;

    #[test]
    fn both_forms_are_offered_for_an_ordinary_operation() {
        let op = registry::find("upper").expect("upper is registered");
        let shown = invocation(op, &Params::for_op(op), "hello");

        assert_eq!(shown.argument, "txc upper hello");
        assert_eq!(shown.pipe.as_deref(), Some("echo hello | txc uc"));
    }

    #[test]
    fn a_generator_has_no_pipe_form() {
        for name in ["uuid", "password", "lorem", "token"] {
            let op = registry::find(name).expect("registered");
            assert_eq!(invocation(op, &Params::for_op(op), "text").pipe, None);
        }
    }

    #[test]
    fn the_pipe_form_uses_the_shortest_alias() {
        let op = registry::find("slugify").expect("slugify is registered");
        let shown = invocation(op, &Params::for_op(op), "a b");

        assert!(shown.argument.contains("txc slugify"), "{shown:?}");
        assert!(shown.pipe.unwrap().contains("txc slug"));
    }

    #[test]
    fn a_value_left_at_its_default_is_not_repeated() {
        let op = registry::find("caesar").expect("caesar is registered");
        let mut params = Params::for_op(op);
        params.set("shift", "3");

        // caesar declares 3, so saying it again would only lengthen the line.
        assert_eq!(invocation(op, &params, "abc").argument, "txc caesar abc");

        params.set("shift", "5");
        assert_eq!(
            invocation(op, &params, "abc").argument,
            "txc caesar --shift 5 abc"
        );
    }

    #[test]
    fn a_switch_appears_only_when_it_is_on() {
        let op = registry::all()
            .iter()
            .find(|op| op.params.iter().any(registry::Param::is_flag))
            .expect("some operation has a switch");
        let flag = op
            .params
            .iter()
            .find(|p| p.is_flag())
            .expect("just found one");

        let plain = invocation(op, &Params::for_op(op), "text").argument;
        assert!(!plain.contains(&format!("--{}", flag.name)), "{plain}");

        let mut params = Params::for_op(op);
        params.enable(flag.name);
        let on = invocation(op, &params, "text").argument;
        assert!(on.contains(&format!("--{}", flag.name)), "{on}");
    }

    #[test]
    fn awkward_input_becomes_a_file_rather_than_a_quoted_line() {
        let op = registry::find("upper").expect("upper is registered");
        let params = Params::for_op(op);

        for awkward in ["", "one\ntwo", &"x".repeat(INLINE_LIMIT + 1)] {
            let shown = invocation(op, &params, awkward);
            assert!(shown.argument.ends_with("< input.txt"), "{shown:?}");
            assert_eq!(shown.pipe.as_deref(), Some("cat input.txt | txc uc"));
        }
    }

    #[test]
    fn quoting_survives_a_round_trip_through_a_shell() {
        for word in ["plain", "two words", "it's", "a\"b", "$HOME", "*", ""] {
            let quoted = quote(word);
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf %s {quoted}"))
                .output()
                .expect("sh runs");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                word,
                "{word:?} quoted as {quoted}"
            );
        }
    }

    #[test]
    fn every_operation_produces_a_line_that_names_it() {
        for op in registry::all() {
            let shown = invocation(op, &Params::for_op(op), op.sample_input());
            assert!(shown.argument.starts_with("txc "), "{shown:?}");
            assert!(
                shown.argument.contains(op.name),
                "{} is missing from {shown:?}",
                op.name
            );
            if let Some(pipe) = &shown.pipe {
                assert!(pipe.contains(brief_name(op)), "{}: {pipe}", op.name);
            }
        }
    }
}
