//! Putting the output on the system clipboard.
//!
//! Two routes, tried in that order.
//!
//! A clipboard program is asked first, because it works whatever the terminal
//! is and whatever it has been configured to allow. Failing that, the terminal
//! itself is asked with the OSC 52 escape sequence, which is what carries a
//! copy back across ssh where no clipboard program can reach the machine in
//! front of the reader.
//!
//! The order matters. OSC 52 alone looks like it works and quietly does
//! nothing: a terminal that does not implement it, or has it turned off, or a
//! multiplexer that will not forward it, all swallow the sequence without a
//! word back.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

/// How the text reached the clipboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// A clipboard program took it.
    Program(String),
    /// The terminal was asked to do it, and did not say whether it worked.
    Terminal,
}

/// A clipboard program and the arguments that make it read standard input.
pub type Program = (&'static str, &'static [&'static str]);

/// The programs to try, in order, for the platform this was built for.
///
/// ```
/// use txc::tui::clipboard::programs;
///
/// // Every platform has at least one, or copying could never work.
/// assert!(!programs().is_empty());
/// ```
#[must_use]
pub const fn programs() -> &'static [Program] {
    #[cfg(target_os = "macos")]
    {
        &[("pbcopy", &[])]
    }

    #[cfg(target_os = "windows")]
    {
        &[
            // Set-Clipboard keeps text outside ASCII intact, which clip.exe
            // mangles unless the console code page happens to be UTF-8.
            (
                "powershell",
                &["-NoProfile", "-Command", "$input | Set-Clipboard"],
            ),
            ("clip", &[]),
        ]
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["--clipboard", "--input"]),
        ]
    }
}

/// Copies `text`, reporting which route carried it.
///
/// # Errors
///
/// Returns an error only when no program took the text *and* the terminal
/// could not be written to.
///
/// ```no_run
/// use txc::tui::clipboard::{Route, copy};
///
/// match copy("text to copy")? {
///     Route::Program(name) => println!("{name} took it"),
///     Route::Terminal => println!("asked the terminal, which does not report back"),
/// }
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn copy(text: &str) -> Result<Route> {
    copy_with(programs(), text)
}

/// The same, against a given list of programs, so the fallback order can be
/// exercised without depending on what this machine happens to have installed.
///
/// The first program that takes the text wins. One that is not installed, or
/// that exits non-zero, is passed over.
///
/// # Errors
///
/// Returns an error only when no program took the text *and* the terminal
/// could not be written to.
pub fn copy_with(programs: &[Program], text: &str) -> Result<Route> {
    for (program, args) in programs {
        if feed(program, args, text).is_ok() {
            return Ok(Route::Program((*program).to_string()));
        }
    }

    send_sequence(text, passthrough())?;
    Ok(Route::Terminal)
}

/// Hands `text` to a program on its standard input.
fn feed(program: &str, args: &[&str], text: &str) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // Taking the handle and dropping it closes the pipe, which is what tells
    // the program the text has ended. wl-copy in particular waits for that.
    let mut stdin = child.stdin.take().context("the program refused a pipe")?;
    stdin.write_all(text.as_bytes())?;
    drop(stdin);

    let status = child.wait()?;
    anyhow::ensure!(status.success(), "{program} exited with {status}");
    Ok(())
}

/// A multiplexer the escape sequence has to travel through.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Passthrough {
    /// Nothing in the way: the sequence goes straight to the terminal.
    None,
    /// Running under tmux, which needs the sequence wrapped and its escapes
    /// doubled.
    Tmux,
    /// Running under GNU screen, which needs the sequence wrapped but not
    /// doubled.
    Screen,
}

/// What this session is running inside.
fn passthrough() -> Passthrough {
    passthrough_for(
        std::env::var("TMUX").ok().as_deref(),
        std::env::var("TERM").ok().as_deref(),
    )
}

/// Decides from the environment, kept separate so it can be tested.
///
/// ```
/// use txc::tui::clipboard::{Passthrough, passthrough_for};
///
/// // TMUX wins, because tmux may run under any TERM.
/// assert_eq!(
///     passthrough_for(Some("/tmp/tmux-1000/default,123,0"), Some("xterm")),
///     Passthrough::Tmux,
/// );
/// assert_eq!(passthrough_for(None, Some("screen-256color")), Passthrough::Screen);
/// assert_eq!(passthrough_for(None, Some("xterm-256color")), Passthrough::None);
/// assert_eq!(passthrough_for(None, None), Passthrough::None);
/// ```
#[must_use]
pub fn passthrough_for(tmux: Option<&str>, term: Option<&str>) -> Passthrough {
    if tmux.is_some_and(|value| !value.is_empty()) {
        return Passthrough::Tmux;
    }
    match term {
        Some(term) if term.starts_with("screen") || term.starts_with("tmux") => Passthrough::Screen,
        _ => Passthrough::None,
    }
}

/// The OSC 52 sequence carrying `text`, wrapped for the multiplexer in the way.
///
/// A bare sequence sent from inside tmux is consumed by tmux rather than
/// reaching the terminal, so it has to be wrapped for passthrough, with the
/// escapes inside doubled.
///
/// ```
/// use txc::tui::clipboard::{Passthrough, sequence};
///
/// // The payload is base64, whatever the wrapping.
/// assert_eq!(sequence("hello", Passthrough::None), "\x1b]52;c;aGVsbG8=\x07");
/// assert_eq!(sequence("hello", Passthrough::Screen), "\x1bP\x1b]52;c;aGVsbG8=\x07\x1b\\");
/// ```
#[must_use]
pub fn sequence(text: &str, passthrough: Passthrough) -> String {
    let payload = format!(
        "\x1b]52;c;{}\x07",
        data_encoding::BASE64.encode(text.as_bytes())
    );
    match passthrough {
        Passthrough::None => payload,
        Passthrough::Tmux => format!("\x1bPtmux;{}\x1b\\", payload.replace('\x1b', "\x1b\x1b")),
        Passthrough::Screen => format!("\x1bP{payload}\x1b\\"),
    }
}

fn send_sequence(text: &str, passthrough: Passthrough) -> Result<()> {
    let mut stdout = std::io::stdout();
    stdout
        .write_all(sequence(text, passthrough).as_bytes())
        .context("cannot reach the terminal")?;
    stdout.flush().context("cannot reach the terminal")?;
    Ok(())
}

/// What to tell the reader once the text has been handed over.
///
/// The terminal route cannot be confirmed, so on a machine that has a display
/// the message says what to install rather than claiming success.
///
/// ```
/// use txc::tui::clipboard::{Route, report};
///
/// assert_eq!(report(&Route::Program("wl-copy".into())), "output copied with wl-copy");
/// ```
#[must_use]
pub fn report(route: &Route) -> String {
    match route {
        Route::Program(program) => format!("output copied with {program}"),
        Route::Terminal => terminal_report(
            std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some(),
            cfg!(target_os = "macos"),
        ),
    }
}

fn terminal_report(has_display: bool, is_macos: bool) -> String {
    if has_display && !is_macos {
        "asked the terminal to copy; if nothing arrived, install wl-clipboard, \
         xclip or xsel"
            .to_string()
    } else {
        "asked the terminal to copy, which needs a terminal that allows it".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Turns owned arguments into the `'static` slice a [`Program`] holds.
    fn leak(args: Vec<String>) -> &'static [&'static str] {
        Box::leak(
            args.into_iter()
                .map(|arg| &*Box::leak(arg.into_boxed_str()))
                .collect::<Vec<&'static str>>()
                .into_boxed_slice(),
        )
    }

    /// A program that writes its standard input, byte for byte, to `path`.
    ///
    /// These tests exercise the pipe itself, and no one program reads standard
    /// input on every platform. The Windows one copies the stream rather than
    /// reading lines, so text outside ASCII is not put through the console code
    /// page on the way.
    fn writes_stdin_to(path: &std::path::Path) -> Program {
        #[cfg(windows)]
        {
            (
                "powershell",
                leak(vec![
                    "-NoProfile".to_string(),
                    "-Command".to_string(),
                    format!(
                        "$out = [IO.File]::Create('{}'); \
                         [Console]::OpenStandardInput().CopyTo($out); \
                         $out.Close()",
                        path.display()
                    ),
                ]),
            )
        }

        #[cfg(not(windows))]
        {
            (
                "sh",
                leak(vec!["-c".to_string(), format!("cat > {}", path.display())]),
            )
        }
    }

    /// A program that runs and reports failure, to stand for a clipboard
    /// program that is installed but cannot take the text.
    fn always_fails() -> Program {
        #[cfg(windows)]
        {
            ("cmd", &["/C", "exit 1"])
        }

        #[cfg(not(windows))]
        {
            ("sh", &["-c", "exit 1"])
        }
    }

    fn decode(sequence: &str) -> String {
        let payload = sequence
            .trim_start_matches("\x1b]52;c;")
            .trim_end_matches('\x07');
        String::from_utf8(data_encoding::BASE64.decode(payload.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn a_plain_sequence_carries_the_encoded_text() {
        let sequence = sequence("hello", Passthrough::None);
        assert_eq!(sequence, "\x1b]52;c;aGVsbG8=\x07");
        assert_eq!(decode(&sequence), "hello");
    }

    #[test]
    fn inside_tmux_the_sequence_is_wrapped_for_passthrough() {
        // Without this tmux eats the sequence and the copy silently does
        // nothing, which is exactly how this went unnoticed.
        // The escapes inside the passthrough are doubled; the terminator that
        // closes it is not.
        assert_eq!(
            sequence("hello", Passthrough::Tmux),
            "\x1bPtmux;\x1b\x1b]52;c;aGVsbG8=\x07\x1b\\"
        );
    }

    #[test]
    fn inside_screen_the_sequence_is_wrapped_without_doubling() {
        let sequence = sequence("hello", Passthrough::Screen);
        assert_eq!(sequence, "\x1bP\x1b]52;c;aGVsbG8=\x07\x1b\\");
    }

    #[test]
    fn the_multiplexer_is_read_from_the_environment() {
        assert_eq!(
            passthrough_for(
                Some("/tmp/tmux-1000/default,123,0"),
                Some("screen-256color")
            ),
            Passthrough::Tmux,
            "TMUX wins, because tmux may run under any TERM"
        );
        assert_eq!(
            passthrough_for(None, Some("screen.xterm-256color")),
            Passthrough::Screen
        );
        assert_eq!(
            passthrough_for(None, Some("xterm-256color")),
            Passthrough::None
        );
        assert_eq!(passthrough_for(Some(""), Some("xterm")), Passthrough::None);
        assert_eq!(passthrough_for(None, None), Passthrough::None);
    }

    #[test]
    fn the_first_program_that_works_takes_the_text() {
        let target = std::env::temp_dir().join("txc-clipboard-first.txt");
        let _ = std::fs::remove_file(&target);
        let writer = writes_stdin_to(&target);

        let programs: Vec<Program> = vec![writer];
        let route = copy_with(&programs, "clipboard text").unwrap();

        assert_eq!(route, Route::Program(writer.0.to_string()));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "clipboard text");
        let _ = std::fs::remove_file(target);
    }

    #[test]
    fn a_program_that_is_not_installed_is_skipped() {
        let target = std::env::temp_dir().join("txc-clipboard-second.txt");
        let _ = std::fs::remove_file(&target);
        let writer = writes_stdin_to(&target);

        let programs: Vec<Program> = vec![("txc-no-such-clipboard-program", &[]), writer];
        let route = copy_with(&programs, "second choice").unwrap();

        assert_eq!(route, Route::Program(writer.0.to_string()));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "second choice");
        let _ = std::fs::remove_file(target);
    }

    #[test]
    fn a_program_that_fails_is_not_treated_as_success() {
        // Falling back to the terminal writes to standard output, which is
        // harmless here and is the documented last resort.
        let programs: Vec<Program> = vec![always_fails()];
        assert_eq!(copy_with(&programs, "text").unwrap(), Route::Terminal);
    }

    #[test]
    fn text_outside_ascii_survives_the_pipe() {
        let target = std::env::temp_dir().join("txc-clipboard-unicode.txt");
        let _ = std::fs::remove_file(&target);
        let programs: Vec<Program> = vec![writes_stdin_to(&target)];

        let text = "caf\u{e9} \u{2014} \u{1f680}\nsecond line";
        copy_with(&programs, text).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), text);
        let _ = std::fs::remove_file(target);
    }

    #[test]
    fn the_platform_list_is_not_empty() {
        assert!(
            !programs().is_empty(),
            "no clipboard program for this platform"
        );
    }

    #[test]
    fn the_report_names_the_program_that_took_it() {
        assert_eq!(
            report(&Route::Program("wl-copy".to_string())),
            "output copied with wl-copy"
        );
    }

    #[test]
    fn the_terminal_report_suggests_what_to_install() {
        // On a machine with a display, a clipboard program would have been the
        // reliable route, so the message says which ones to install.
        assert!(terminal_report(true, false).contains("wl-clipboard"));
        // Over ssh there is nothing to install, so it does not ask.
        assert!(!terminal_report(false, false).contains("install"));
        assert!(!terminal_report(true, true).contains("install"));
    }
}
