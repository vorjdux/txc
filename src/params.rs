//! Parameter values handed to an operation.
//!
//! The same type is produced from parsed command line arguments and from the
//! options field of the terminal interface, so an operation never needs to
//! know where it is being driven from.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use anyhow::{Context, Result, bail};

use crate::registry::Op;

/// Values and switches for one invocation of an operation.
#[derive(Clone, Debug, Default)]
pub struct Params {
    values: HashMap<String, String>,
    flags: HashSet<String>,
    defaults: HashMap<&'static str, &'static str>,
}

impl Params {
    /// An empty set of parameters carrying `op`'s declared defaults.
    pub fn for_op(op: &Op) -> Params {
        let defaults = op
            .params
            .iter()
            .filter_map(|p| p.default_value().map(|d| (p.name, d)))
            .collect();
        Params {
            values: HashMap::new(),
            flags: HashSet::new(),
            defaults,
        }
    }

    /// Sets a value, replacing any previous one.
    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        self.values.insert(name.to_string(), value.into());
    }

    /// Turns a switch on.
    pub fn enable(&mut self, name: &str) {
        self.flags.insert(name.to_string());
    }

    /// Whether a switch was turned on.
    pub fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }

    /// The value supplied by the caller, ignoring any declared default.
    pub fn supplied(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// The effective value: what the caller supplied, else the declared
    /// default, else the empty string.
    pub fn get(&self, name: &str) -> &str {
        self.values
            .get(name)
            .map(String::as_str)
            .or_else(|| self.defaults.get(name).copied())
            .unwrap_or("")
    }

    /// The effective value, or `None` when neither a value nor a default
    /// exists.
    pub fn opt(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .map(String::as_str)
            .or_else(|| self.defaults.get(name).copied())
    }

    /// The effective value parsed into `T`, with an error naming the option.
    pub fn parse<T>(&self, name: &str) -> Result<T>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        let raw = self.get(name);
        T::from_str(raw).map_err(|e| anyhow::anyhow!("invalid value for --{name}: {raw:?} ({e})"))
    }

    /// A required value, erroring when the caller left it out.
    pub fn require(&self, name: &str) -> Result<&str> {
        match self.opt(name) {
            Some(v) => Ok(v),
            None => bail!("--{name} is required"),
        }
    }

    /// Parses a `key=value key2=value2 flag` string as used by the options
    /// field of the terminal interface.
    ///
    /// Values may be quoted with single or double quotes to include spaces.
    pub fn parse_kv(op: &Op, text: &str) -> Result<Params> {
        let mut params = Params::for_op(op);
        for token in split_tokens(text)? {
            let (key, value) = match token.split_once('=') {
                Some((k, v)) => (k.trim().to_string(), Some(v.to_string())),
                None => (token.trim().to_string(), None),
            };
            if key.is_empty() {
                continue;
            }
            let key = key.trim_start_matches('-').to_string();
            let declared = op
                .param(&key)
                .with_context(|| format!("{} has no option named {key:?}", op.name))?;
            match value {
                Some(v) if !declared.is_flag() => params.set(&key, v),
                Some(v) => {
                    if matches!(v.as_str(), "1" | "true" | "yes" | "on") {
                        params.enable(&key);
                    }
                }
                None if declared.is_flag() => params.enable(&key),
                None => bail!("option {key:?} needs a value, write {key}=..."),
            }
        }
        Ok(params)
    }
}

/// Splits on whitespace while keeping quoted runs together.
fn split_tokens(text: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut has_content = false;

    for ch in text.chars() {
        match quote {
            Some(q) if ch == q => quote = None,
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => {
                quote = Some(ch);
                has_content = true;
            }
            None if ch.is_whitespace() => {
                if has_content {
                    tokens.push(std::mem::take(&mut current));
                    has_content = false;
                }
            }
            None => {
                current.push(ch);
                has_content = true;
            }
        }
    }

    if quote.is_some() {
        bail!("unbalanced quote in options");
    }
    if has_content {
        tokens.push(current);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_tokens() {
        let tokens = split_tokens("a=1 b='two words' c=\"x y\"").unwrap();
        assert_eq!(tokens, vec!["a=1", "b=two words", "c=x y"]);
    }

    #[test]
    fn rejects_unbalanced_quotes() {
        assert!(split_tokens("a='oops").is_err());
    }
}
