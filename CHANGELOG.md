# Changelog

All notable changes to txc are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0]

A documentation release: the library half of txc is now documented in full,
and the whole crate is held to a stricter set of lints.

### Added

- Documentation on every public item. The crate root reads as an
  introduction, covering how to run an operation, pass parameters, chain
  operations, walk the catalogue and read the errors back.
- 100 examples, which run as part of `cargo test`, so they cannot go stale.
- `OpFn` and `ParamKind` are re-exported from the crate root, so declaring an
  operation no longer needs the `registry` module path.
- The dependency audit runs in CI, weekly as well as on every change, since an
  advisory can be published without anything here changing.
- The documentation is built in CI with warnings denied: a broken link would
  otherwise show up only as a mangled page on docs.rs.

### Changed

- The crate is linted with `clippy::pedantic`, plus `use_self` and
  `missing_const_for_fn`. What that fixed is invisible from outside, other
  than more functions being `const` and returning values now being
  `#[must_use]`.
- Reading time in `stats` is worked out in whole numbers. In floating point,
  205 words came out as 61 seconds rather than 62, because 61.5 is not
  representable and the value landed just below it.

## [0.3.0]

Rebuilt around a single registry of text operations, from which the command
line parser, the help text, the shell completions and the interactive interface
are all generated.

### Added

- 143 operations across ten categories: case conversion, encoding, hashing,
  line editing, text cleanup, number formats, format conversion, inspection,
  generators and time.
- An interactive full screen interface, shown when `txc` runs with no
  arguments, with live output, a searchable catalogue, per operation sample
  text and an options panel filled in with the values in force.
- `ctrl+y` copies the output to the system clipboard, asking a clipboard
  program first (`pbcopy`, `Set-Clipboard` or `clip`, `wl-copy`, `xclip`,
  `xsel`) and falling back to the OSC 52 escape sequence, wrapped for
  passthrough when running inside tmux or screen.
- `ctrl+s` saves the output, asking where to put it, and `ctrl+n` runs the
  operations whose answer varies again.
- `txc about` and the `F2` view, naming the version, author and licence.
- Shell completions for bash, zsh, fish, PowerShell and elvish, via
  `txc completions <shell>`.
- Installers for Unix (`install.sh`) and Windows (`install.ps1`), and packaging
  for Debian, RPM, Homebrew, Scoop, the AUR, winget and Alpine, with binaries
  released for Linux, macOS and Windows on both x86_64 and arm64.

### Changed

- Every operation takes its text as arguments, from `--file`, or over a pipe,
  with the same result each way. One trailing newline is dropped from piped
  input so a shell's `echo` agrees with a quoted argument; `--raw` keeps it.
- Text typed in the interface follows you between operations only while the
  new operation can read it, so reaching a decoder no longer shows an error
  about the previous operation's text.
- Moved to the 2024 edition, with a minimum supported Rust version of 1.88.

### Fixed

- `ue` was registered as a second `ud`, so URL encoding was unreachable and
  silently read standard input instead.
- `uuid`, `uuid1` and `uuid5` read an option they did not declare and panicked
  on every run.
- Invalid input reached `unwrap` throughout; it now produces a message and a
  non zero exit status.
- An option written after the text was swallowed as part of it, so
  `txc from-timestamp 1700000000 --utc` ignored `--utc`.
- The key reference along the bottom of the interface was dark text on a dark
  background, and unfocused panel titles were close to invisible.
- `~` in the save prompt read `HOME` alone, so it was taken literally on
  Windows, where the variable is `USERPROFILE`.

## [0.1.0]

- Initial draft.

[Unreleased]: https://github.com/vorjdux/txc/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/vorjdux/txc/releases/tag/v0.3.0
[0.1.0]: https://github.com/vorjdux/txc/releases/tag/v0.1.0
