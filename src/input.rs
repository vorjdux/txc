//! Reading input and writing output.
//!
//! Every operation accepts its text the same three ways: as trailing
//! arguments, from a file, or over a pipe. Nothing about an operation decides
//! this, so the behaviour is identical across the whole tool.

use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Where the text for an operation comes from.
///
/// ```
/// use txc::input::Source;
///
/// // Positional arguments are joined with a single space.
/// let source = Source {
///     args: vec!["hello".to_string(), "world".to_string()],
///     ..Default::default()
/// };
/// assert_eq!(source.read()?, "hello world");
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Debug, Default, Clone)]
pub struct Source {
    /// Trailing positional arguments, joined with a single space.
    pub args: Vec<String>,
    /// A file to read instead of arguments or standard input.
    pub file: Option<PathBuf>,
    /// Keep the input bytes exactly as read, including a trailing newline.
    pub raw: bool,
}

impl Source {
    /// Reads the input text.
    ///
    /// Precedence is `--file`, then positional arguments, then standard
    /// input. A lone `-` argument also means standard input.
    ///
    /// A shell adds a newline to `echo hello`, so one trailing newline is
    /// removed from piped and file input. That makes `echo hello | txc b64`
    /// agree with `txc b64 hello`. Pass `--raw` to keep the bytes untouched.
    ///
    /// When there is nothing to read and standard input is a terminal this
    /// reports an error rather than blocking forever on a prompt that never
    /// arrives.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, when the bytes are not
    /// valid UTF-8, or when there is nothing to read at all.
    ///
    /// ```
    /// use txc::input::Source;
    ///
    /// let source = Source {
    ///     args: vec!["one".to_string(), "two".to_string()],
    ///     ..Default::default()
    /// };
    /// assert_eq!(source.read()?, "one two");
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn read(&self) -> Result<String> {
        if let Some(path) = &self.file {
            if path.as_os_str() == "-" {
                return Ok(self.tidy(read_stdin()?));
            }
            let bytes =
                fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
            return Ok(self.tidy(decode(bytes, Some(path))?));
        }

        let piped = self.args.is_empty() || (self.args.len() == 1 && self.args[0] == "-");
        if !piped {
            return Ok(self.args.join(" "));
        }

        if io::stdin().is_terminal() {
            bail!(
                "no input: pass the text as an argument, use --file <PATH>, or pipe it in\n\
                 for example: txc upper \"hello\"  |  echo hello | txc upper"
            );
        }
        Ok(self.tidy(read_stdin()?))
    }

    fn tidy(&self, text: String) -> String {
        if self.raw {
            return text;
        }
        match text.strip_suffix('\n') {
            Some(body) => body.strip_suffix('\r').unwrap_or(body).to_string(),
            None => text,
        }
    }
}

fn read_stdin() -> Result<String> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .read_to_end(&mut bytes)
        .context("cannot read standard input")?;
    decode(bytes, None)
}

/// Turns raw bytes into text, reporting where invalid UTF-8 came from instead
/// of panicking on it.
fn decode(bytes: Vec<u8>, path: Option<&Path>) -> Result<String> {
    String::from_utf8(bytes).map_err(|e| {
        let at = e.utf8_error().valid_up_to();
        match path {
            Some(p) => anyhow::anyhow!("{} is not valid UTF-8 (byte {at})", p.display()),
            None => anyhow::anyhow!("input is not valid UTF-8 (byte {at})"),
        }
    })
}

/// Writes the result to a file or to standard output.
///
/// A trailing newline is added unless the text already ends with one or
/// `newline` is false, which keeps `txc` composable in shell substitutions.
///
/// # Errors
///
/// Returns an error when the destination cannot be created or written to.
///
/// ```
/// use txc::input::write;
///
/// let path = std::env::temp_dir().join("txc-doc-write.txt");
///
/// write("hello", Some(&path), true)?;
/// assert_eq!(std::fs::read_to_string(&path)?, "hello\n");
///
/// // Asking for no newline leaves the text exactly as given.
/// write("hello", Some(&path), false)?;
/// assert_eq!(std::fs::read_to_string(&path)?, "hello");
///
/// std::fs::remove_file(&path)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn write(text: &str, destination: Option<&Path>, newline: bool) -> Result<()> {
    let needs_newline = newline && !text.is_empty() && !text.ends_with('\n');

    match destination {
        Some(path) => {
            let mut file = fs::File::create(path)
                .with_context(|| format!("cannot write {}", path.display()))?;
            file.write_all(text.as_bytes())?;
            if needs_newline {
                file.write_all(b"\n")?;
            }
            file.flush()?;
        }
        None => {
            let stdout = io::stdout();
            let mut out = io::BufWriter::new(stdout.lock());
            // A closed pipe is how `txc ... | head` ends; it is not an error.
            let written = out
                .write_all(text.as_bytes())
                .and_then(|()| {
                    if needs_newline {
                        out.write_all(b"\n")
                    } else {
                        Ok(())
                    }
                })
                .and_then(|()| out.flush());
            if let Err(e) = written
                && e.kind() != io::ErrorKind::BrokenPipe
            {
                return Err(e.into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> Source {
        Source::default()
    }

    #[test]
    fn arguments_are_joined_with_a_space() {
        let mut spec = source();
        spec.args = vec!["a".into(), "b".into()];
        assert_eq!(spec.read().unwrap(), "a b");
    }

    #[test]
    fn one_trailing_newline_is_dropped() {
        let spec = source();
        assert_eq!(spec.tidy("hello\n".to_string()), "hello");
        assert_eq!(spec.tidy("hello\r\n".to_string()), "hello");
        // Only one, so deliberate blank lines survive.
        assert_eq!(spec.tidy("hello\n\n".to_string()), "hello\n");
        assert_eq!(spec.tidy("hello".to_string()), "hello");
    }

    #[test]
    fn raw_keeps_the_bytes_untouched() {
        let mut spec = source();
        spec.raw = true;
        assert_eq!(spec.tidy("hello\n".to_string()), "hello\n");
    }

    #[test]
    fn a_file_is_read_and_tidied() {
        let path = std::env::temp_dir().join("txc-input-test.txt");
        fs::write(&path, b"line\n").unwrap();
        let mut spec = source();
        spec.file = Some(path.clone());
        assert_eq!(spec.read().unwrap(), "line");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_missing_file_is_reported_by_name() {
        let mut spec = source();
        spec.file = Some(PathBuf::from("/does/not/exist.txt"));
        let error = spec.read().expect_err("missing file").to_string();
        assert!(error.contains("/does/not/exist.txt"), "{error}");
    }
}
