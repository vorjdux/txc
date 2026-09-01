//! The operation registry.
//!
//! Every text operation in `txc` is described by an [`Op`] value. The command
//! line parser, the shell completions, the `txc list` output and the terminal
//! interface are all generated from this one table, so an operation only ever
//! has to be declared once.
//!
//! ```
//! use txc::{Params, find, in_category, Category};
//!
//! // Look an operation up by name or by alias, then run it.
//! let op = find("base64-encode").expect("base64-encode is registered");
//! assert_eq!(op.apply("txc", &Params::for_op(op), None)?, "dHhj");
//!
//! // Aliases resolve to the very same operation.
//! assert_eq!(find("b64e").map(|o| o.name), Some("base64-encode"));
//!
//! // The table can also be walked a category at a time.
//! assert!(!in_category(Category::Hash).is_empty());
//! # Ok::<(), anyhow::Error>(())
//! ```
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::params::Params;

/// What an operation produces, or the reason it could not.
///
/// ```
/// use txc::{OpResult, Params, find};
///
/// let op = find("upper").unwrap();
/// let result: OpResult = op.apply("hello", &Params::for_op(op), None);
/// assert_eq!(result?, "HELLO");
/// # Ok::<(), anyhow::Error>(())
/// ```
pub type OpResult = anyhow::Result<String>;

/// The signature every operation implements: input text plus parameters in,
/// text out.
///
/// ```
/// use txc::{OpFn, Params, find};
///
/// // Every operation's `run` field has this shape.
/// let run: OpFn = find("lower").unwrap().run;
/// assert_eq!(run("SHOUT", &Params::default())?, "shout");
/// # Ok::<(), anyhow::Error>(())
/// ```
pub type OpFn = fn(&str, &Params) -> OpResult;

/// Groups operations for help output, `txc list` and the sidebar of the
/// terminal interface.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Category {
    /// Changing the case or the word convention of text.
    Case,
    /// Encodings and classic ciphers, in both directions.
    Encode,
    /// Checksums and cryptographic digests.
    Hash,
    /// Operations over the lines of the input.
    Lines,
    /// Searching, replacing and tidying text.
    Text,
    /// Number bases, roman numerals and spelling.
    Number,
    /// Translating between structured document formats.
    Convert,
    /// Reporting on text rather than changing it.
    Inspect,
    /// Producing new text from nothing.
    Generate,
    /// Timestamps and date formatting.
    Time,
}

impl Category {
    /// Display order, which is also the order used everywhere else.
    ///
    /// ```
    /// use txc::Category;
    ///
    /// assert_eq!(Category::ALL.len(), 10);
    /// assert_eq!(Category::ALL[0], Category::Case);
    /// ```
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
    ///
    /// ```
    /// use txc::Category;
    ///
    /// assert_eq!(Category::Encode.id(), "encode");
    /// assert_eq!(Category::Number.id(), "number");
    /// ```
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
    ///
    /// This is the display name, which does not always match [`id`]: the
    /// `number` category is headed "Numbers".
    ///
    /// ```
    /// use txc::Category;
    ///
    /// assert_eq!(Category::Number.title(), "Numbers");
    /// ```
    ///
    /// [`id`]: Category::id
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
    ///
    /// ```
    /// use txc::Category;
    ///
    /// assert!(Category::Hash.about().contains("digests"));
    /// ```
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

    /// Resolves a category from its identifier, case insensitively.
    ///
    /// ```
    /// use txc::Category;
    ///
    /// assert_eq!(Category::from_id("hash"), Some(Category::Hash));
    /// assert_eq!(Category::from_id("HASH"), Some(Category::Hash));
    /// assert_eq!(Category::from_id("nonsense"), None);
    /// ```
    pub fn from_id(value: &str) -> Option<Category> {
        Category::ALL
            .iter()
            .copied()
            .find(|c| c.id().eq_ignore_ascii_case(value))
    }
}

/// Whether a parameter carries a value or is a simple on/off switch.
#[derive(Clone, Copy, Debug)]
pub enum ParamKind {
    /// An on/off switch, which is either given or not.
    Flag,
    /// A parameter that takes a value.
    Value {
        /// Name shown for the value in help output, such as `<COUNT>`.
        placeholder: &'static str,
        /// Value used when the caller does not supply one. `None` makes the
        /// parameter required on the command line.
        default: Option<&'static str>,
    },
}

/// A single parameter accepted by an operation.
#[derive(Clone, Copy, Debug)]
pub struct Param {
    /// Long name, used as `--name` on the command line.
    pub name: &'static str,
    /// Optional single letter form, used as `-n`.
    pub short: Option<char>,
    /// One line description shown in help output.
    pub help: &'static str,
    /// Whether the parameter is a switch or takes a value.
    pub kind: ParamKind,
    /// A value the interactive interface pre-fills when the parameter has no
    /// default of its own. It is never applied on the command line, where a
    /// required parameter stays required.
    pub sample: Option<&'static str>,
}

impl Param {
    /// Declares an on/off switch.
    ///
    /// ```
    /// use txc::Param;
    ///
    /// let param = Param::flag("upper", Some('u'), "use upper case");
    /// assert!(param.is_flag());
    /// assert_eq!(param.default_value(), None);
    /// ```
    pub const fn flag(name: &'static str, short: Option<char>, help: &'static str) -> Param {
        Param {
            name,
            short,
            help,
            kind: ParamKind::Flag,
            sample: None,
        }
    }

    /// Declares a parameter that takes a value, with no default.
    ///
    /// With no default the parameter is required: the command line will not
    /// run the operation without it.
    ///
    /// ```
    /// use txc::Param;
    ///
    /// let param = Param::value("key", Some('k'), "<KEY>", "the key to use");
    /// assert!(!param.is_flag());
    /// assert_eq!(param.default_value(), None);
    /// ```
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
            sample: None,
        }
    }

    /// Declares a parameter that takes a value and falls back to `default`.
    ///
    /// ```
    /// use txc::Param;
    ///
    /// let param = Param::valued("count", Some('n'), "<COUNT>", "1", "how many");
    /// assert_eq!(param.default_value(), Some("1"));
    /// assert_eq!(param.starting_value(), "1");
    /// ```
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
            sample: None,
        }
    }

    /// Suggests a starting value for the interactive interface.
    ///
    /// Use this for parameters that are required on the command line: the
    /// interface can then show a working result straight away without the
    /// command line quietly accepting an incomplete invocation.
    ///
    /// ```
    /// use txc::Param;
    ///
    /// let param = Param::value("key", None, "<KEY>", "the key").suggest("secret");
    /// // The suggestion fills the interface, but does not become a default.
    /// assert_eq!(param.starting_value(), "secret");
    /// assert_eq!(param.default_value(), None);
    /// ```
    pub const fn suggest(mut self, sample: &'static str) -> Param {
        self.sample = Some(sample);
        self
    }

    /// The declared default, if any.
    ///
    /// A [`Flag`] never has one.
    ///
    /// ```
    /// use txc::Param;
    ///
    /// assert_eq!(Param::flag("raw", None, "raw output").default_value(), None);
    /// ```
    ///
    /// [`Flag`]: ParamKind::Flag
    pub fn default_value(&self) -> Option<&'static str> {
        match self.kind {
            ParamKind::Value { default, .. } => default,
            ParamKind::Flag => None,
        }
    }

    /// Whether this parameter is a switch rather than a value.
    ///
    /// ```
    /// use txc::Param;
    ///
    /// assert!(Param::flag("raw", None, "raw output").is_flag());
    /// assert!(!Param::value("key", None, "<KEY>", "the key").is_flag());
    /// ```
    pub fn is_flag(&self) -> bool {
        matches!(self.kind, ParamKind::Flag)
    }

    /// The value the interactive interface starts from: the suggestion when
    /// one was given, else the declared default, else nothing.
    ///
    /// The suggestion wins because it is only ever set for parameters whose
    /// default would leave the panel looking empty.
    ///
    /// ```
    /// use txc::Param;
    ///
    /// // Nothing declared at all leaves the field empty.
    /// assert_eq!(Param::value("key", None, "<KEY>", "the key").starting_value(), "");
    /// ```
    pub fn starting_value(&self) -> &'static str {
        self.sample.or(self.default_value()).unwrap_or("")
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
    /// Canonical name, which is what `txc <name>` accepts.
    pub name: &'static str,
    /// Alternative names, which resolve to this same operation.
    pub aliases: &'static [&'static str],
    /// The group this operation is listed under.
    pub category: Category,
    /// One line description shown in help output and in the interface.
    pub about: &'static str,
    /// Example invocations shown in `--help`.
    pub examples: &'static [&'static str],
    /// The parameters this operation reads.
    pub params: &'static [Param],
    /// How the input text is handed to [`run`](Op::run).
    pub feed: Feed,
    /// The function that does the work. Call it through [`apply`] rather than
    /// directly, so the feed mode is honoured.
    ///
    /// [`apply`]: Op::apply
    pub run: OpFn,
    /// Text the interactive interface starts from, when the general purpose
    /// sample would not suit this operation.
    pub sample: Option<&'static str>,
    /// Whether running the operation again on the same input can give a
    /// different answer, as random and clock driven operations do.
    pub varies: bool,
}

impl Op {
    /// Starts a declaration with the fields every operation must provide.
    ///
    /// The remaining fields are added with the builder methods below, each of
    /// which is `const` so the whole table is built at compile time.
    ///
    /// ```
    /// use txc::{Category, Feed, Op, Params};
    ///
    /// const SHOUT: Op = Op::new(
    ///     "shout",
    ///     Category::Case,
    ///     Feed::Buffer,
    ///     "upper case with feeling",
    ///     |input, _params| Ok(format!("{}!", input.to_uppercase())),
    /// )
    /// .aliases(&["yell"])
    /// .examples(&["txc shout hello"]);
    ///
    /// assert_eq!(SHOUT.apply("hello", &Params::default(), None)?, "HELLO!");
    /// # Ok::<(), anyhow::Error>(())
    /// ```
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
            sample: None,
            varies: false,
        }
    }

    /// Adds alternative names. Aliases participate in lookup and completion.
    ///
    /// ```
    /// use txc::find;
    ///
    /// // `b64e` is an alias, and finds the same operation as the full name.
    /// assert_eq!(find("b64e").map(|op| op.name), Some("base64-encode"));
    /// ```
    pub const fn aliases(mut self, aliases: &'static [&'static str]) -> Op {
        self.aliases = aliases;
        self
    }

    /// Adds the parameters the operation reads.
    ///
    /// ```
    /// use txc::find;
    ///
    /// let op = find("caesar").expect("caesar is registered");
    /// assert!(op.param("shift").is_some());
    /// ```
    pub const fn params(mut self, params: &'static [Param]) -> Op {
        self.params = params;
        self
    }

    /// Adds usage examples shown in `--help` and in the terminal interface.
    ///
    /// ```
    /// use txc::find;
    ///
    /// let op = find("slugify").expect("slugify is registered");
    /// assert!(op.examples.iter().all(|example| example.starts_with("txc ")));
    /// ```
    pub const fn examples(mut self, examples: &'static [&'static str]) -> Op {
        self.examples = examples;
        self
    }

    /// Marks an operation whose answer changes from run to run, so the
    /// interface can offer to run it again.
    ///
    /// ```
    /// use txc::find;
    ///
    /// assert!(find("uuid").expect("uuid is registered").varies);
    /// assert!(!find("upper").expect("upper is registered").varies);
    /// ```
    pub const fn varies(mut self) -> Op {
        self.varies = true;
        self
    }

    /// Sets the text the interactive interface starts from.
    ///
    /// Operations that read timestamps, numbers or structured documents need
    /// their own sample; a sentence of prose would only ever produce an error.
    ///
    /// ```
    /// use txc::{Params, find};
    ///
    /// // Whatever the sample is, it has to be something the operation accepts.
    /// let op = find("json-format").expect("json-format is registered");
    /// assert!(op.apply(op.sample_input(), &Params::for_op(op), None).is_ok());
    /// ```
    pub const fn sample(mut self, sample: &'static str) -> Op {
        self.sample = Some(sample);
        self
    }

    /// The text the interactive interface loads when this operation is
    /// selected, falling back to something suitable for the category.
    ///
    /// Generators get an empty sample, because they ignore their input.
    ///
    /// ```
    /// use txc::find;
    ///
    /// assert_eq!(find("uuid").unwrap().sample_input(), "");
    /// assert!(!find("upper").unwrap().sample_input().is_empty());
    /// ```
    pub fn sample_input(&self) -> &'static str {
        if self.feed == Feed::None {
            return "";
        }
        if let Some(sample) = self.sample {
            return sample;
        }
        match self.category {
            Category::Lines => "beta\nalpha\ngamma\nalpha\ndelta",
            Category::Number => "2024",
            Category::Time => "1700000000",
            Category::Convert => "{\"name\": \"txc\", \"offline\": true}",
            _ => "The quick brown fox jumps over the lazy dog",
        }
    }

    /// Looks up one of the operation's declared parameters.
    ///
    /// ```
    /// use txc::find;
    ///
    /// let op = find("caesar").expect("caesar is registered");
    /// assert_eq!(op.param("shift").map(|p| p.name), Some("shift"));
    /// assert!(op.param("no-such-parameter").is_none());
    /// ```
    pub fn param(&self, name: &str) -> Option<&'static Param> {
        self.params.iter().find(|p| p.name == name)
    }

    /// Runs the operation, honouring its [`Feed`] mode.
    ///
    /// `line_mode` overrides the declared mode when the caller passed
    /// `--lines` or `--whole`. Pass `None` to use whatever the operation
    /// declared, which is what you want unless you are implementing those
    /// flags.
    ///
    /// # Errors
    ///
    /// Returns whatever the operation reports: malformed input, a missing
    /// required parameter, or a value it cannot make sense of.
    ///
    /// ```
    /// use txc::{Params, find};
    ///
    /// let op = find("upper").expect("upper is registered");
    /// let params = Params::for_op(op);
    ///
    /// // Declared mode: this operation takes the whole buffer.
    /// assert_eq!(op.apply("one\ntwo", &params, None)?, "ONE\nTWO");
    ///
    /// // Forced line by line, which rejoins with newlines afterwards.
    /// assert_eq!(op.apply("one\ntwo", &params, Some(true))?, "ONE\nTWO");
    ///
    /// // Input that an operation cannot make sense of comes back as an error.
    /// let roman = find("roman-encode").expect("roman-encode is registered");
    /// assert!(roman.apply("not a number", &Params::for_op(roman), None).is_err());
    /// # Ok::<(), anyhow::Error>(())
    /// ```
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
///
/// The table is built once and cached, so calling this repeatedly is cheap.
///
/// ```
/// use txc::all;
///
/// assert!(all().len() > 100);
/// // Sorted by category first, then by name within it.
/// assert!(all().windows(2).all(|w| (w[0].category, w[0].name) <= (w[1].category, w[1].name)));
/// ```
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
///
/// Lookup is exact: this is not a fuzzy search, and it is case sensitive.
///
/// ```
/// use txc::find;
///
/// assert_eq!(find("upper").map(|op| op.name), Some("upper"));
/// assert_eq!(find("b64e").map(|op| op.name), Some("base64-encode"));
/// assert!(find("Upper").is_none());
/// assert!(find("no-such-operation").is_none());
/// ```
pub fn find(name: &str) -> Option<&'static Op> {
    index().get(name).map(|i| &all()[*i])
}

/// All operations in a category, in registry order.
///
/// ```
/// use txc::{Category, in_category};
///
/// let hashes = in_category(Category::Hash);
/// assert!(!hashes.is_empty());
/// assert!(hashes.iter().all(|op| op.category == Category::Hash));
/// ```
pub fn in_category(category: Category) -> Vec<&'static Op> {
    all().iter().filter(|op| op.category == category).collect()
}
