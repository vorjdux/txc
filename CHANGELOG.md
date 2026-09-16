# Changelog

All notable changes to txc are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.2] - 2026-09-16

### Fixed

- Each entry in the vault list is now shown over two lines, the name on its own
  and the kind and vault below it, so a name is no longer cropped to share the
  row with them. The list is a narrow column, leaving the wider pane beside it
  for reading the selected entry.

## [0.5.1] - 2026-09-16

### Added

- `txc vault move <entry> <vault>` (also `mv`, and `m` in the interface) moves
  an entry to another vault, decrypting each secret and sealing it again to
  the destination's keys. The destination is written before the entry is taken
  from the source, so an interrupted move never loses it.

### Changed

- The README leads with the project and a one-line install, and the ways to
  install are grouped below rather than spread through it. Only the install
  methods that are published are shown as commands.
- When the key reference along the bottom of the interface is too wide for the
  terminal, it now drops the About key before the vault key, so the vault key
  stays on screen for longer.

## [0.5.0] - 2026-09-16

The vault release: txc now keeps secrets as well as text, in encrypted files
on your own machine.

### Added

- `txc vault`, an encrypted vault for passwords, payment cards, API keys,
  notes and other secrets, kept in local files and built entirely on the age
  format: `init`, `identity`, `passwd`, `create`, `list`, `add`, `show`,
  `favourite`, `copy`, `edit`, `rm`, `recipients` and `trust`.
- Thirteen kinds of entry, each with the fields that suit it: login, payment
  card, secure note, API key, SSH key, database, server, Wi-Fi network, bank
  account, ID document, software licence, crypto wallet and other secret.
  Each field is plain or secret by definition, and a secret field given as a
  plain `--field` is refused.
- Favourites, stored in the vault so they follow it to other devices, and a
  list of what was used recently, kept on the device in its own encrypted
  file. `txc vault list` takes `--favourites`, `--recent`, `--kind` and
  `--tag`, across every vault.
- "Unlocking..." on the terminal while the passphrase is checked, which takes
  a moment on purpose.
- The identity is an age X25519 key encrypted with a passphrase through scrypt
  at N = 2^18. Each vault is one age file, encrypted to one or more public
  keys, and each secret inside it is sealed again on its own, so browsing a
  vault decrypts no secret and copying opens exactly one.
- Trust records per device, authenticated with a key derived from the
  identity. A vault that is new to the device, rebuilt with another key,
  encrypted to different recipients, or older than the version last opened is
  refused until `txc vault trust` shows what differs and it is accepted.
- Secrets are never taken as arguments: they are typed without echo,
  generated with `--generate`, or piped in with `--secret-from-stdin`. `copy`
  keeps them out of clipboard history where the system allows, clears the
  clipboard again after 20 seconds if the secret is still there, and never
  falls back to OSC 52. `--print` writes to a pipe and refuses a terminal.
- Vault files are written atomically and never through a link, and on Unix are
  readable by their owner alone and refused when they are open to other users.
  Keys and secrets are wiped from memory when dropped; on Unix core dumps are
  disabled while the vault is in use, and on Linux the process is also marked
  not dumpable.
- A vault screen in the interactive interface, on `F3`. Favourites, recently
  used, all items, each kind and each vault are down the left; adding an
  entry starts by choosing its kind and opens that kind's form, with
  generated passwords and PINs and a real editor for notes. A secret can be
  revealed for 15 seconds and a note opened to read; otherwise secrets are
  drawn only as dots or a fixed mask. The passphrase is checked in the
  background behind a spinner, and the vault locks after five minutes without
  a key and when the interface closes.
- Pasting into the interactive interface arrives in one piece, so a multi line
  value no longer presses Enter part of the way through. This needs bracketed
  paste, which the Windows console does not have; there a paste still arrives
  as typing.
- A `vault` cargo feature, on by default. `--no-default-features` builds txc
  without the vault and without its dependencies.

### Changed

- Unsafe code is denied across the crate, except in the one module that makes
  system calls to harden the process.
- The release binary is about 1.3 MiB larger with the vault built in.
- The cryptography crates are optimised even in development builds, where
  checking a passphrase otherwise took fifteen seconds rather than half of one.

## [0.4.1]

### Added

- A Command line panel along the bottom, writing the selected operation out in
  two forms: `arg` spells it out in full, `pipe` says the same thing as briefly
  as the operation allows. Both follow the options panel and the input, so they
  reproduce what is on screen rather than a generic example. The panel is
  dropped on a terminal shorter than 20 rows, where the panels above need the
  space more.

### Fixed

- `txc tui` no longer hangs when its input is not a terminal. On Windows
  crossterm reads the console the process is attached to rather than the
  standard streams, so under a pipe the interface started and then waited for
  a key that would never arrive. It now reports the same error there as
  everywhere else. This is what left a CI job running for six hours.

### Changed

- Every CI and release job has a timeout, so a job that blocks rather than
  fails costs minutes instead of the six hour default.
- The end to end tests kill a `txc` that has not finished within a minute and
  fail, rather than waiting on it.

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

[Unreleased]: https://github.com/vorjdux/txc/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/vorjdux/txc/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/vorjdux/txc/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/vorjdux/txc/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/vorjdux/txc/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/vorjdux/txc/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/vorjdux/txc/releases/tag/v0.3.0
[0.1.0]: https://github.com/vorjdux/txc/releases/tag/v0.1.0
