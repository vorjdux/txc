//! The operation registry.
//!
//! Every text operation in `txc` is described by an [`Op`] value. The command
//! line parser, the shell completions, the `txc list` output and the terminal
//! interface are all generated from this one table, so an operation only ever
//! has to be declared once.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::params::Params;

/// What an operation produces, or the reason it could not.
pub type OpResult = anyhow::Result<String>;

/// The signature every operation implements: input text plus parameters in,
/// text out.
pub type OpFn = fn(&str, &Params) -> OpResult;

/// Groups operations for help output, `txc list` and the sidebar of the
/// terminal interface.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Category {
    Case,
    Encode,
    Hash,
    Lines,
    Text,
    Number,
    Convert,
    Inspect,
    Generate,
    Time,
}

impl Category {
    /// Display order, which is also the order used everywhere else.
    pub const ALL: [Category; 10] = [
        Category::Case,
        Category::Encode,
        Category::Hash,
        Category::Lines,
        Category::Text,
        Category::Number,
        Category::Convert,
        Category::Inspect,
        Category::Generate,
        Category::Time,
    ];

    /// Short machine friendly identifier, used by `txc list --category`.
    pub fn id(self) -> &'static str {
        match self {
            Category::Case => "case",
            Category::Encode => "encode",
            Category::Hash => "hash",
            Category::Lines => "lines",
            Category::Text => "text",
            Category::Number => "number",
            Category::Convert => "convert",
            Category::Inspect => "inspect",
            Category::Generate => "generate",
            Category::Time => "time",
        }
    }

    /// Human readable heading.
    pub fn title(self) -> &'static str {
        match self {
            Category::Case => "Case",
            Category::Encode => "Encoding",
            Category::Hash => "Hashing",
            Category::Lines => "Lines",
            Category::Text => "Text",
            Category::Number => "Numbers",
            Category::Convert => "Convert",
            Category::Inspect => "Inspect",
            Category::Generate => "Generate",
            Category::Time => "Time",
        }
    }

    /// One line summary shown above each group.
    pub fn about(self) -> &'static str {
        match self {
            Category::Case => "Upper, lower, title, camel, snake and friends",
            Category::Encode => "URL, HTML, base64, hex, binary and classic ciphers",
            Category::Hash => "Checksums and cryptographic digests",
            Category::Lines => "Sort, filter, number, pad and reshape lines",
            Category::Text => "Search, replace, trim, wrap and clean up text",
            Category::Number => "Bases, roman numerals and number spelling",
            Category::Convert => "JSON, YAML, TOML and CSV in every direction",
            Category::Inspect => "Counts, statistics, frequencies and code points",
            Category::Generate => "UUIDs, passwords, random data and placeholder text",
            Category::Time => "Timestamps and date formatting",
        }
    }

    /// Resolves a category from its identifier or title, case insensitively.
    pub fn from_id(value: &str) -> Option<Category> {
        Category::ALL
            .iter()
            .copied()
            .find(|c| c.id().eq_ignore_ascii_case(value))
    }
}

/// Whether a parameter carries a value or is a simple on/off switch.
#[derive(Clone, Copy)]
pub enum ParamKind {
    Flag,
    Value {
        placeholder: &'static str,
        default: Option<&'static str>,
    },
}

/// A single parameter accepted by an operation.
#[derive(Clone, Copy)]
pub struct Param {
    pub name: &'static str,
    pub short: Option<char>,
    pub help: &'static str,
    pub kind: ParamKind,
}

impl Param {
    /// Declares an on/off switch.
    pub const fn flag(name: &'static str, short: Option<char>, help: &'static str) -> Param {
        Param {
            name,
            short,
            help,
            kind: ParamKind::Flag,
        }
    }

    /// Declares a parameter that takes a value, with no default.
    pub const fn value(
        name: &'static str,
        short: Option<char>,
        placeholder: &'static str,
        help: &'static str,
    ) -> Param {
        Param {
            name,
            short,
            help,
            kind: ParamKind::Value {
                placeholder,
                default: None,
            },
        }
    }

    /// Declares a parameter that takes a value and falls back to `default`.
    pub const fn valued(
        name: &'static str,
        short: Option<char>,
        placeholder: &'static str,
        default: &'static str,
        help: &'static str,
    ) -> Param {
        Param {
            name,
            short,
            help,
            kind: ParamKind::Value {
                placeholder,
                default: Some(default),
            },
        }
    }

    /// The declared default, if any.
    pub fn default_value(&self) -> Option<&'static str> {
        match self.kind {
            ParamKind::Value { default, .. } => default,
            ParamKind::Flag => None,
        }
    }

    /// Whether this parameter is a switch rather than a value.
    pub fn is_flag(&self) -> bool {
        matches!(self.kind, ParamKind::Flag)
    }
}

/// How the input text is handed to an operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Feed {
    /// The whole input is passed in one call.
    Buffer,
    /// The operation is called once per line and the results are rejoined.
    Lines,
    /// The operation generates output and ignores any input.
    None,
}

/// A registered text operation.
#[derive(Clone, Copy)]
pub struct Op {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub category: Category,
    pub about: &'static str,
    pub examples: &'static [&'static str],
    pub params: &'static [Param],
    pub feed: Feed,
    pub run: OpFn,
}

impl Op {
    /// Starts a declaration with the fields every operation must provide.
    pub const fn new(
        name: &'static str,
        category: Category,
        feed: Feed,
        about: &'static str,
        run: OpFn,
    ) -> Op {
        Op {
            name,
            aliases: &[],
            category,
            about,
            examples: &[],
            params: &[],
            feed,
            run,
        }
    }

    /// Adds alternative names. Aliases participate in lookup and completion.
    pub const fn aliases(mut self, aliases: &'static [&'static str]) -> Op {
        self.aliases = aliases;
        self
    }

    /// Adds the parameters the operation reads.
    pub const fn params(mut self, params: &'static [Param]) -> Op {
        self.params = params;
        self
    }

    /// Adds usage examples shown in `--help` and in the terminal interface.
    pub const fn examples(mut self, examples: &'static [&'static str]) -> Op {
        self.examples = examples;
        self
    }

    /// Looks up one of the operation's declared parameters.
    pub fn param(&self, name: &str) -> Option<&'static Param> {
        self.params.iter().find(|p| p.name == name)
    }

    /// Runs the operation, honouring its [`Feed`] mode.
    ///
    /// `line_mode` overrides the declared mode when the caller passed
    /// `--lines` or `--whole`.
    pub fn apply(&self, input: &str, params: &Params, line_mode: Option<bool>) -> OpResult {
        let feed = match (self.feed, line_mode) {
            (Feed::None, _) => Feed::None,
            (_, Some(true)) => Feed::Lines,
            (_, Some(false)) => Feed::Buffer,
            (declared, None) => declared,
        };

        match feed {
            Feed::None => (self.run)("", params),
            Feed::Buffer => (self.run)(input, params),
            Feed::Lines => {
                let body = input.strip_suffix('\n').unwrap_or(input);
                if body.is_empty() {
                    return (self.run)("", params);
                }
                let mut out = String::with_capacity(body.len());
                for (i, line) in body.split('\n').enumerate() {
                    if i > 0 {
                        out.push('\n');
                    }
                    let line = line.strip_suffix('\r').unwrap_or(line);
                    out.push_str(&(self.run)(line, params)?);
                }
                Ok(out)
            }
        }
    }
}

/// Every registered operation, sorted by category and then by name.
pub fn all() -> &'static [Op] {
    static OPS: OnceLock<Vec<Op>> = OnceLock::new();
    OPS.get_or_init(|| {
        let mut ops = Vec::new();
        crate::ops::register(&mut ops);
        ops.sort_by(|a, b| (a.category, a.name).cmp(&(b.category, b.name)));
        ops
    })
}

fn index() -> &'static HashMap<&'static str, usize> {
    static INDEX: OnceLock<HashMap<&'static str, usize>> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut map = HashMap::new();
        for (i, op) in all().iter().enumerate() {
            if map.insert(op.name, i).is_some() {
                panic!("duplicate operation name: {}", op.name);
            }
            for alias in op.aliases {
                if map.insert(*alias, i).is_some() {
                    panic!("duplicate operation alias: {alias}");
                }
            }
        }
        map
    })
}

/// Finds an operation by name or alias.
pub fn find(name: &str) -> Option<&'static Op> {
    index().get(name).map(|i| &all()[*i])
}

/// All operations in a category, in registry order.
pub fn in_category(category: Category) -> Vec<&'static Op> {
    all().iter().filter(|op| op.category == category).collect()
}
