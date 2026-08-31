# Changelog

All notable changes to txc are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0]

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
- `ctrl+y` copies the output to the system clipboard through the terminal
  (OSC 52), and `ctrl+s` saves it, asking where.
- `txc about` and the `F2` view, naming the version, author and licence.
- Shell completions for bash, zsh, fish, PowerShell and elvish, via
  `txc completions <shell>`.
- Installers for Unix (`install.sh`) and Windows (`install.ps1`), and packages
  for Debian, RPM, Homebrew, Scoop, the AUR, winget and Alpine.

### Changed

- Every operation takes its text as arguments, from `--file`, or over a pipe,
  with the same result each way. One trailing newline is dropped from piped
  input so a shell's `echo` agrees with a quoted argument; `--raw` keeps it.
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

## [0.1.0]

- Initial draft.

[Unreleased]: https://github.com/vorjdux/txc/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/vorjdux/txc/releases/tag/v0.2.0
[0.1.0]: https://github.com/vorjdux/txc/releases/tag/v0.1.0
