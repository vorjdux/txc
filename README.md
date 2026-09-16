# txc

[![CI](https://github.com/vorjdux/txc/actions/workflows/ci.yml/badge.svg)](https://github.com/vorjdux/txc/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/txc.svg?logo=rust)](https://crates.io/crates/txc)
[![docs.rs](https://img.shields.io/docsrs/txc?logo=docsdotrs)](https://docs.rs/txc)
[![MSRV](https://img.shields.io/crates/msrv/txc?logo=rust)](https://github.com/vorjdux/txc#from-source)
[![Licence](https://img.shields.io/crates/l/txc.svg)](#license)

**Offline text utilities and an encrypted secrets vault for the terminal.**

143 operations across 10 categories: encode, decode, hash, convert, inspect and
generate. Use them as an argument, over a pipe, or from a full-screen interface.
Plus a local, age-encrypted vault for passwords, payment cards, API keys and
notes. Nothing ever leaves your machine: no network call, nothing to paste into
a web form.

## Install

Linux and macOS:

```sh
curl -sSf https://raw.githubusercontent.com/vorjdux/txc/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/vorjdux/txc/main/install.ps1 | iex
```

Or `cargo install txc`, or download a binary or `.deb`/`.rpm` from the
[releases page](https://github.com/vorjdux/txc/releases). More ways, and the
checksums, under [Installing](#installing).

## A quick look

```
$ txc url-encode "This string will be URL encoded"
This%20string%20will%20be%20URL%20encoded

$ echo "This string will be URL encoded" | txc ue
This%20string%20will%20be%20URL%20encoded

$ txc snake "userFirstName" | txc upper
USER_FIRST_NAME
```

The vault, in one line: `txc vault add github --username octocat --generate`,
then `txc vault copy github`. See [the vault](#the-vault).

## The interactive interface

Run `txc` with no arguments and it opens a full screen interface. Pick an
operation on the left, type in the input panel, and the output updates as you
type.

```
 txc  0.5.2 Shift letters by a fixed amount
╭ Categories ──╮╭ Search ──────────────────╮╭ Input (43 characters, sample) ───────────────╮
│All           ││caesar                    ││The quick brown fox jumps over the lazy dog   │
│Case          │╰──────────────────────────╯│                                              │
│Encoding      │┏ Operations (1) ━━━━━━━━━━┓│                                              │
│Hashing       │┃caesar                    ┃│                                              │
│Lines         │┃                          ┃╰──────────────────────────────────────────────╯
│Text          │┃                          ┃╭ Options ─────────────────────────────────────╮
│Numbers       │┃                          ┃│  shift  3                                    │
│Convert       │┃                          ┃╰──────────────────────────────────────────────╯
│Inspect       │┃                          ┃╭ Output (43 characters) ──────────────────────╮
│Generate      │┃                          ┃│Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj   │
│Time          │┃                          ┃│                                              │
│              │┃                          ┃│                                              │
│              │┃                          ┃│                                              │
│              │┃                          ┃│                                              │
│              │┃                          ┃│                                              │
│              │┃                          ┃│                                              │
╰──────────────╯┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛╰──────────────────────────────────────────────╯
╭ Command line ────────────────────────────────────────────────────────────────────────────╮
│arg   txc caesar 'The quick brown fox jumps over the lazy dog'                            │
│pipe  echo 'The quick brown fox jumps over the lazy dog' | txc caesar                     │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
 tab panel   ^up/^down op   ^y copy   ^s save   F3 vault   ? help   F2 about   ^c quit
```

| Key | Action |
| --- | --- |
| `tab` / `shift+tab` | Move between panels |
| `up` / `down` | Move inside a list, or between options |
| `ctrl+up` / `ctrl+down` | Change operation from any panel |
| `ctrl+left` / `ctrl+right` | Change category |
| `/` | Jump to the search box |
| `ctrl+n` | Run the operation again, for the ones that vary |
| `ctrl+y` | Copy the output to the clipboard |
| `ctrl+s` | Save the output, asking where to put it |
| `ctrl+p` | Move the output into the input, to chain operations |
| `ctrl+r` | Bring back the sample text |
| `ctrl+l` | Clear the input, or empty the selected option |
| `ctrl+u` | Put every option back to its default |
| `ctrl+w` | Delete the word before the cursor |
| `page up` / `page down` | Scroll the output |
| `?` or `F1` | Key reference |
| `F2` | About: version, author, licence |
| `F3` | [The vault](#the-vault), and back again |
| `ctrl+c` | Quit |

Each panel earns its place. An operation that generates rather than transforms,
such as `uuid` or `password`, has no input panel at all, and one with nothing to
configure, such as `upper`, has no options panel. The output takes the space
back.

```
 txc  0.5.2 Generate UUIDs
╭ Categories ──╮╭ Search ──────────────────╮╭ Options ─────────────────────────────────────╮
│All           ││uuid                      ││  version    4                                │
│Case          │╰──────────────────────────╯│  count      1                                │
│Encoding      │┏ Operations (1) ━━━━━━━━━━┓│  name       example.com                      │
│Hashing       │┃uuid  gen                 ┃│  namespace  dns                              │
│Lines         │┃                          ┃│  upper      off                              │
│Text          │┃                          ┃│  compact    off                              │
│Numbers       │┃                          ┃╰──────────────────────────────────────────────╯
│Convert       │┃                          ┃╭ Output (36 characters, ^n for another) ──────╮
│Inspect       │┃                          ┃│6733f105-f83e-4002-9996-a53b4ceb6257          │
│Generate      │┃                          ┃│                                              │
│Time          │┃                          ┃│                                              │
│              │┃                          ┃│                                              │
│              │┃                          ┃│                                              │
╰──────────────╯┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛╰──────────────────────────────────────────────╯
╭ Command line ────────────────────────────────────────────────────────────────────────────╮
│arg   txc uuid --name example.com                                                         │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
 tab panel   ^up/^down op   ^n new   ^y copy   ^s save   F3 vault   ? help   ^c quit
```

### Sample text

Selecting an operation loads a sample that suits it: `from-timestamp` starts
from `1700000000`, `roman-decode` from `MMXXIV`, `json-format` from a small JSON
document. So every operation shows itself working the moment you land on it,
rather than an error about the previous operation's text.

Text you type follows you from operation to operation, but only while the new
operation can actually read it. Encode something of your own, then reach for
`base64-decode`, and you get the decoder working on its own sample instead of a
complaint about your sentence. Your text is not thrown away: it returns at the
next operation that accepts it, and `ctrl+r` brings the sample back for good.

### Options

The options panel lists the parameters of the selected operation, one per line,
already filled in with the values the operation would use anyway:

```
╭ Options: Number of places to shift ──────────╮
│> shift  3                                    │
╰──────────────────────────────────────────────╯
```

Type to change a value, and press `space` to turn a switch on or off. The panel
title explains whichever parameter is selected. Parameters that are required on
the command line, such as `replace --find`, start from a worked example so the
output is live straight away.

### The command line, alongside

A panel of its own along the bottom writes out the command that would do what
you are looking at. It follows the panels above as you go, so the options you
change and the text you type are already in it:

```
╭ Command line ────────────────────────────────────────────────────────────────────────────╮
│arg   txc hex-encode --upper --sep ' ' 'The quick brown fox'                              │
│pipe  echo 'The quick brown fox' | txc hex -u -s ' '                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────╯
```

The two lines are the same command written two ways. `arg` spells everything
out: the canonical operation name, every parameter as `--name`, and the text as
an argument. That is the form to read. `pipe` is the same operation as briefly
as it can be said: the shortest alias that reaches it, single letter flags where
a parameter has one, and the text arriving through a pipe. That is the form to
type. Either can be selected out of the terminal and run as it stands.

Only the parameters that matter appear. A value left where the operation would
have put it anyway is left out, so changing `caesar --shift` from 3 to 7 adds
`--shift 7` and changing it back removes it again. Input too long, or with too
many lines, to sit on one line becomes `< input.txt` rather than a wrapped wall
of quoting, and an operation that generates rather than transforms, such as
`uuid`, has no `pipe` line because there is nothing to pipe into it.

The panel is dropped on a terminal shorter than 20 rows, where the panels above
need the space more. The key reference stays: it is how you leave.

### Running again

Operations whose answer changes from run to run say so in the output title, and
`ctrl+n` gives you another one: a different password, a fresh UUID, another
shuffle. `txc uuid --count 5` is still the way to ask for several at once.

### Taking the output with you

`ctrl+y` copies the output to the system clipboard. It asks a clipboard
program first, because that works whatever the terminal is: `pbcopy` on macOS,
`Set-Clipboard` or `clip` on Windows, and `wl-copy`, `xclip` or `xsel` on Linux
and the BSDs. Install one of those three on Linux if none is present.

When no clipboard program answers, which is the normal case over ssh, the
terminal is asked instead with the OSC 52 escape sequence, wrapped for
passthrough when running inside tmux or screen. That route cannot be confirmed,
so the status line says the copy was offered rather than claiming it arrived,
and names what to install when a clipboard program would have been the reliable
choice. A terminal that does not implement OSC 52, or has it switched off,
ignores the request silently: Alacritty needs `terminal.osc52` set to
`OnlyCopy` or `CopyPaste`, and tmux needs `set -g set-clipboard on`.

Output larger than 64 KiB is refused rather than copied in part, because
terminals cap the sequence and half a copy is worse than none.

`ctrl+s` asks where to save, suggesting a name based on the operation, and `~`
means your home directory:

```
┏ Operations (1) ━━━━━━━━━━┓
┃uuid  gen                 ┃
┃                          ┃
┃                          ┃
┏ Save the output as ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃uuid.txt                                                      ┃
┃enter to save, esc to cancel, ~ is your home directory        ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

## The vault

`txc vault` keeps passwords, payment cards, API keys, SSH keys, notes and other
secrets in encrypted files on your own machine. Nothing is sent anywhere. A
secret is shown only when you ask, and leaves the vault only by being copied
to the clipboard, which is cleared again, or by being piped into another
program.

```sh
txc vault init                     # create your identity and the personal vault
txc vault add github --username octocat --url https://github.com --generate --favourite
txc vault add visa --kind card --field cardholder='A N Other' --field expiry=12/30 \
  --secret-field cvv               # the card number and the security code are asked for
txc vault add work/openai --kind api-key --secret-from-stdin < key.txt
txc vault list --favourites        # starred entries, from every vault
txc vault list --recent            # what you used last on this device
txc vault show visa                # secrets are shown masked
txc vault copy github              # the password, cleared from the clipboard after 20s
txc vault copy visa --field cvv
txc vault move github work         # added it to the wrong vault? move it, secrets and all
export OPENAI_API_KEY="$(txc vault copy work/openai --print)"
```

### In the interactive interface

`F3` opens the same vaults. Down the left are the ways in: **Favourites**,
**Recently used** on this device, **All items**, each kind that has entries,
and each vault. The list is in the middle and the selected entry on the right.

```
 txc  0.5.2 Vault unlocked · 3 entries in 1 vault
╭ Browse ────────────────╮╭ Search ──────────────────────────────╮╭ GitHub ──────────────────────────────────╮
│★ Favourites          1 ││/ to search                           ││ Login · personal  ★ favourite            │
│◷ Recently used       0 │╰──────────────────────────────────────╯│                                          │
│▤ All items           3 │┏ All items (3) ━━━━━━━━━━━━━━━━━━━━━━━┓│  Username  octocat                       │
│ Kinds                  │┃★ GitHub                         Login┃│  Password  ••••••••                      │
│  Logins              1 │┃  Home network           Wi-Fi network┃│  Website   https://github.com            │
│  Payment cards       1 │┃  Visa                    Payment card┃│                                          │
│  Wi-Fi networks      1 │┃                                      ┃│  Updated   2026-09-15 17:05              │
│ Vaults                 │┃                                      ┃│                                          │
│  personal            3 │┃                                      ┃│                                          │
╰────────────────────────╯┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛╰──────────────────────────────────────────╯
 c copy   u user   r reveal   f star   a add   e edit   d delete   / search   1 2 3 jump   l lock
```

| Key | Action |
| --- | --- |
| `1` `2` `3` | Favourites, recently used, all items |
| `tab` / `shift+tab` | Move between the three panels |
| `↑` `↓`, or `j` `k` | Move in a list, or between an entry's fields |
| `→` or `o`, `←` or `esc` | Into the entry's fields, and back to the list |
| `/` | Search names, usernames, websites, tags and every other plain field |
| `c` | Copy the main secret; in the fields panel, the selected field |
| `enter` | Copy, or open a note to read |
| `u` | Copy the username |
| `r` | Show the secret for 15 seconds, or open a note to read |
| `f` | Star or unstar the entry |
| `a` | Add an entry: choose its kind, then fill in that kind's form |
| `e`, `d` | Edit or delete the entry |
| `m` | Move the entry to another vault |
| `n` | New vault |
| `t` | Trust a vault that is new to this device or has changed |
| `l` or `ctrl+l` | Lock |

The form for a new entry has the fields that kind has: a payment card asks
for the cardholder, number, expiry, security code and PIN, a Wi-Fi network for
its name, password and security. Secret fields show dots as you type, `ctrl+r`
shows what you typed, and `ctrl+g` generates a password, or a PIN where that is
what the field wants. Notes are written in a real editor where `enter` starts
a new line, and pasting a multi line value such as a private key arrives in
one piece, in terminals that support bracketed paste. The Windows console does
not, so there a paste arrives as typing; it still lands correctly in a note or
another field that takes several lines. `esc` asks before throwing away what
you typed.

Checking the passphrase takes a moment on purpose, so a spinner says so while
it runs. The vault locks itself after five minutes without a key and whenever
the interface closes.

### Entries

An entry is named `vault/entry`, or just `entry` for one in the `personal`
vault. Its kind decides its fields, and which of them is the main secret that
`copy` takes unless given `--field`. Fields marked with * are kept secret:

| Kind | Fields, main secret first |
| --- | --- |
| `login` | password\*, username, url, notes\* |
| `card` | number\*, cardholder, expiry, cvv\*, pin\*, notes\* |
| `note` | text\* |
| `api-key` | key\*, url, username, expires, notes\* |
| `ssh-key` | private-key\*, passphrase\*, host, username, public-key, notes\* |
| `database` | password\*, host, port, database, username, notes\* |
| `server` | password\*, host, username, notes\* |
| `wifi` | password\*, ssid, security, notes\* |
| `bank` | account-number\*, bank, holder, iban\*, swift, pin\*, notes\* |
| `document` | number\*, full-name, issued, expires, country, notes\* |
| `licence` | key\*, product, email, notes\* |
| `wallet` | seed-phrase\*, address, password\*, notes\* |
| `secret` | value\*, notes\* |

The main secret is typed, generated or piped in. Other secret fields are
given with `--secret-field NAME` and asked for at the terminal, and the rest
with `--field NAME=VALUE`, or `--username` and `--url`. Entries can also carry
tags: `--tag` when adding or editing, `--untag` to take one off, and
`txc vault list --tag work` to see them. A secret field given
with `--field` is refused, so a card's security code cannot end up in your
shell history by mistake. `txc vault add --help` prints the same list.

Favourites are stored in the vault, so a starred entry is starred on every
device that opens it. What you used recently stays on this device, in a file
of its own encrypted to your key, so copying a secret never rewrites the vault
or sends it through a sync again.

### Getting secrets in and out

No option takes a secret as its value, because arguments end up in shell
history and in the process list. A secret is typed at the terminal without
echo, twice; generated with `--generate` (24 characters, or `--length N`, with
`--no-symbols` for letters and digits only); or piped in with
`--secret-from-stdin`.

`copy` puts the secret on the clipboard, marked so clipboard managers leave it
out of their history: the KDE password manager hint on Linux, the concealed
type on macOS, and the formats that keep it out of clipboard history and the
cloud clipboard on Windows. It then waits and clears the clipboard after
`--clear-after` seconds (20 by default, at most 300), or at once if you press a
key, but only if the secret is still there. Unlike `ctrl+y` for ordinary
output, it never falls back to the terminal's OSC 52 sequence, which would
send the secret through the terminal and anything recording it; over ssh, use
`--print` into a pipe instead. `--print` refuses to write to a terminal, where
the secret would stay in the scrollback.

For scripts, `--passphrase-file PATH` reads the passphrase from a file, which
on Unix must be readable by you alone. `--home DIR` or `TXC_VAULT_HOME`
chooses a vault directory other than the default; the environment variable
must be an absolute path.

### How it is protected

Everything is built from [age](https://age-encryption.org), a small, openly
specified and widely reviewed format. The design is public, so its safety
rests on keys alone.

- **Your identity** is an age X25519 private key in `identity.age`, encrypted
  with your passphrase through scrypt at N = 2^18, which makes every guess at
  the passphrase cost about a second and 256 MiB. Opening a vault takes both
  the file and the passphrase. Passphrases shorter than 12 characters are
  refused.
- **A vault** is one age file (X25519 and ChaCha20-Poly1305), encrypted to one
  or more public keys. Entry names, usernames and addresses are inside it, so
  the file shows nothing but its size. Any change to the file makes it fail to
  open rather than decrypt to something else.
- **Each secret** is sealed again as an age file of its own inside the vault.
  Opening a vault to browse it decrypts none of them. Copying a secret,
  revealing it or opening a note decrypts exactly that one; a revealed secret
  is hidden again after 15 seconds, and a note is wiped when its window
  closes.
- **Trust.** Encryption does not say who wrote a file: anyone who knows your
  public key can build a vault for it and list their own key beside yours, so
  that a secret you save into it goes to them as well. Each vault therefore
  carries a random key only its recipients can read, and each device keeps a
  record of that key's tag, the vault's recipients and its generation,
  authenticated with a key derived from your identity. A vault that is new to
  the device, rebuilt with another key, encrypted to different recipients, or
  older than the version last opened is refused until `txc vault trust <name>`
  shows you what differs and you accept it.
- **On disk** every file is written to a temporary file and renamed into
  place, readable by you alone, and refused when it is a link, belongs to
  another user, or could have been changed by one. The previous version of a
  vault is kept beside it, still encrypted.
- **In memory** keys and secrets are wiped when they are dropped, buffers for
  them are sized once so no stray copy is left by a reallocation, and on Unix
  the process cannot write a core dump. On Linux it is also marked not
  dumpable, which stops other programs running as you from attaching to it or
  reading its memory.

The files live in `~/.local/share/txc/vault` (or `$XDG_DATA_HOME/txc/vault`)
on Linux, `~/Library/Application Support/txc/vault` on macOS and
`%APPDATA%\txc\vault` on Windows:

```
vault/
├── identity.age              your private key, encrypted with your passphrase
├── trust.json                what this device trusts, authenticated by your key
├── recent.age                what you used recently on this device, encrypted to your key
└── vaults/
    ├── personal.vault.age    one age file per vault
    └── personal.vault.age.bak  the version before the last change
```

### Several devices, and sharing

To use the same vaults on another device, copy `identity.age` and the `vaults/`
directory across, then run `txc vault trust <name>` there once for each vault.
Only `vaults/` needs synchronising afterwards; `trust.json` and `recent.age`
belong to each device.

A vault can also be encrypted to other keys: a second device with its own
identity, a backup key kept offline, or a colleague. `txc vault identity`
prints your public key, and the owner of a vault adds it with
`txc vault create team --recipient age1...` or
`txc vault recipients personal --add age1...`. Every secret is sealed again for
the new set of keys. Removing a key does the same, but it cannot reach copies
of the vault made before, so change any secret that key could read.

### Opening a vault without txc

Nothing is locked inside txc. A vault is an age file, and `identity.age` is an
ordinary passphrase protected age identity, so another age implementation
opens it:

```sh
rage -d -i identity.age vaults/personal.vault.age      # the vault, as JSON
echo '<sealed value>' | base64 -d | rage -d -i identity.age
```

### What it does not protect against

- Malware already running as you while the vault is unlocked, a keylogger
  catching the passphrase, or anyone with administrator rights on the machine.
- Programs reading the clipboard during the seconds a secret is on it, and
  clipboard managers that ignore the request to leave it out of their history.
- Anyone who can see your screen, or record it, while you reveal a secret or
  read a note.
- A forgotten passphrase, or a lost `identity.age`: neither can be recovered,
  and without them the vaults cannot be opened. Keep a copy of `identity.age`
  somewhere safe; it is encrypted.
- What an observer can see without the key: the size of each vault file, when
  it last changed, and how many keys it is encrypted to.
- On Windows the owner and permission checks do not exist, and neither do the
  core dump and debugger protections. The default directory inside your user
  profile is what keeps other users out, so a vault directory set elsewhere
  with `--home` or `TXC_VAULT_HOME` is not protected at all there.

To build txc without the vault, and without its dependencies, use
`cargo install txc --no-default-features`.

## Installing

### Install script

The one-line scripts at the top are the quickest way. Each downloads the archive
for your machine, checks it against the published `SHA256SUMS`, and puts `txc` on
your PATH. Pass `--dry-run` to see what it would do, `VERSION=x.y.z` to pin a
version, and `INSTALL_DIR=...` to choose where it lands.

### With cargo

```sh
cargo install txc
```

Rust 1.88 or newer, 2024 edition. Add `--no-default-features` to build without
the vault and its dependencies.

### Download a binary or package

Every release carries archives for Linux, macOS and Windows on both x86_64 and
arm64, `.deb` and `.rpm` packages, and a `SHA256SUMS` covering all of them, on
[the releases page](https://github.com/vorjdux/txc/releases). The Linux binaries
are linked against musl, so one archive runs on any distribution.

```sh
# a plain binary
tar xzf txc-<version>-linux-x86_64.tar.gz
sudo install -m755 txc-<version>-linux-x86_64/txc /usr/local/bin/txc

# Debian, Ubuntu
sudo dpkg -i txc_<version>_amd64.deb

# Fedora, RHEL, openSUSE
sudo rpm -i txc-<version>.x86_64.rpm
```

### From source

```sh
cargo install --path .
```

Packaging definitions for Homebrew, Scoop, winget, Arch and Alpine live in
[`packaging/`](packaging), and `packaging/render.sh` fills them in with the
version and checksums of a release, ready to submit to each. They are not all
published to their registries yet.

## Shell completion

`txc <tab>` completes operation names, and `txc sort --<tab>` completes that
operation's options. Install the script for your shell:

```
# bash
txc completions bash > ~/.local/share/bash-completion/completions/txc

# zsh, into any directory on your $fpath
txc completions zsh > "${fpath[1]}/_txc"

# fish
txc completions fish > ~/.config/fish/completions/txc.fish

# powershell, appended to your profile
txc completions powershell >> $PROFILE

# elvish
txc completions elvish >> ~/.config/elvish/rc.elv
```

Pre-generated scripts are also in [`completions/`](completions), and the Debian
package installs the bash, zsh and fish ones for you.

## How input works

Every operation takes its text three ways, and they all produce the same
result:

```
txc upper "hello"            # an argument
echo hello | txc upper       # a pipe
txc upper --file notes.txt   # a file
```

Several arguments are joined with a single space, so `txc upper hello world`
gives `HELLO WORLD`. Options may go before or after the text, whichever reads
better:

```
txc from-timestamp 1700000000 --utc
txc from-timestamp --utc 1700000000
```

For text that starts with a dash, put `--` first: `txc upper -- -x-`.

A shell adds a newline to `echo hello`, so one trailing newline is removed from
piped and file input. That is what makes `echo hello | txc b64` agree with
`txc b64 hello`. Pass `--raw` when you need the bytes exactly as they arrived,
for instance to match `sha256sum`:

```
$ txc sha256 hello
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

$ echo hello | txc sha256          # the same, the newline is dropped
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

$ echo hello | txc sha256 --raw    # the newline is hashed, as sha256sum does
5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
```

Running an operation with nothing to read reports the problem instead of
waiting forever at a silent prompt.

## Shared options

These are available on every operation, written after the operation name:

| Option | Meaning |
| --- | --- |
| `-f`, `--file <PATH>` | Read input from a file |
| `-o`, `--out <PATH>` | Write the result to a file |
| `-n`, `--no-newline` | Do not append a trailing newline |
| `--raw` | Keep piped input exactly as read |
| `--lines` | Apply the operation to each line separately |
| `--whole` | Apply the operation to the whole input at once |

Most operations already pick the sensible mode: `upper` works line by line,
`sort` works over the whole input. `--lines` and `--whole` override that when
you need the other one.

```
$ printf 'ab\ncd\n' | txc reverse
ba
dc

$ printf 'ab\ncd\n' | txc reverse --whole
dc
ba
```

## Finding an operation

```
txc list                    # everything, grouped by category
txc list --category hash    # one category
txc list --names            # bare names, one per line
txc sha256 --help           # options and examples for one operation
txc about                   # version, author and licence
```

`txc about` prints the same details the `F2` view shows in the interface, both
read from the package metadata so neither can drift:

```
$ txc about
txc — Offline text utilities for the terminal: encode, hash, convert, inspect
and generate text without sending it anywhere

Version     0.3.0
Operations  143 in 10 categories
Author      Matheus Santos <vorj.dux@gmail.com>
Repository  https://github.com/vorjdux/txc
License     MIT OR Apache-2.0
Copyright   2022 Matheus Santos

Your text never leaves this machine: txc makes no network requests.
Licensed under either of Apache-2.0 or MIT, at your option.
```

## Examples

```
# Encoding
txc base64-encode --url-safe --no-pad "a?b"
txc hex-encode --sep ' ' --upper "hi"
txc morse-encode SOS
txc rot13 "hello"

# Hashing a file
txc sha256 --file report.pdf
txc hmac-sha256 --key s3cret "payload"

# Working with lines
txc sort --numeric --file sizes.txt
txc unique --file log.txt
txc filter --regex '^ERROR' --file app.log
txc number --width 3 --zeros --file recipe.txt

# Cleaning text
txc squeeze "too    many   spaces"
txc slugify "Hello, World! 2024"
txc remove-accents "crème brûlée"
txc strip-html '<p>Hi &amp; bye</p>'

# Converting formats
txc json-to-yaml --file config.json
txc csv-to-json --file people.csv
txc toml-to-json --file Cargo.toml
txc csv-to-markdown --file table.csv

# Inspecting
txc stats --file article.txt
txc frequency --file speech.txt --top 10
txc charinfo "café"

# Generating
txc uuid --count 5
txc uuid --version 5 --name example.com
txc password --length 32 --no-ambiguous
txc lorem --paragraphs 2
```

## Operations

### Case

Upper, lower, title, camel, snake and friends.

| Operation | Also known as | What it does |
| --- | --- | --- |
| `alternate` | `alternating`, `mock` | Convert text to aLtErNaTiNg case |
| `camel` | `camelcase` | Convert text to camelCase |
| `capitalize` | `capitalise` | Capitalise the first letter of every word, keeping the rest as is |
| `constant` | `screaming`, `macro` | Convert text to CONSTANT_CASE |
| `dot` | `dotcase` | Convert text to dot.case |
| `kebab` | `kebabcase`, `dash` | Convert text to kebab-case |
| `lower` | `lc`, `lowercase` | Convert text to lowercase |
| `pascal` | `pascalcase` | Convert text to PascalCase |
| `random-case` | `randomcase` | Randomise the case of every letter |
| `sentence` | `sentencecase` | Capitalise the first letter of every sentence |
| `snake` | `snakecase` | Convert text to snake_case |
| `swap` | `invert-case`, `swapcase` | Swap the case of every letter |
| `title` | `titlecase` | Capitalise The First Letter Of Every Word |
| `train` | `traincase` | Convert text to Train-Case |
| `upper` | `uc`, `uppercase` | Convert text to UPPERCASE |

### Encoding

URL, HTML, base64, hex, binary and classic ciphers.

| Operation | Also known as | What it does |
| --- | --- | --- |
| `atbash` |  | Apply the Atbash mirror cipher |
| `base32-decode` | `b32d` | Decode base32 back to text |
| `base32-encode` | `b32`, `b32e` | Encode text as base32 |
| `base58-decode` | `b58d` | Decode base58 back to text |
| `base58-encode` | `b58`, `b58e` | Encode text as base58 (bitcoin alphabet) |
| `base64-decode` | `b64d`, `unbase64` | Decode base64 back to text |
| `base64-encode` | `b64`, `b64e`, `base64` | Encode text as base64 |
| `binary-decode` | `frombinary`, `unbin` | Decode binary bytes back to text |
| `binary-encode` | `tobinary`, `bin` | Encode text as binary bytes |
| `caesar` |  | Shift letters by a fixed amount |
| `codepoint-decode` |  | Turn U+XXXX code points back into characters |
| `codepoint-encode` | `codepoints` | Show the Unicode code point of every character |
| `decimal-decode` | `fromdecimal`, `undec` | Decode decimal byte values back to text |
| `decimal-encode` | `todecimal`, `dec` | Encode text as decimal byte values |
| `hex-decode` | `unhex`, `fromhex` | Decode hexadecimal back to text |
| `hex-encode` | `hex`, `tohex` | Encode text as hexadecimal |
| `html-decode` | `hd`, `htmldecode`, `htmlunescape` | Decode HTML entities |
| `html-encode` | `he`, `htmlencode`, `htmlescape` | Escape HTML special characters |
| `json-escape` | `jsonescape` | Escape text for a JSON string |
| `json-unescape` | `jsonunescape` | Decode a JSON string escape sequence |
| `morse-decode` | `unmorse` | Decode Morse code back to text |
| `morse-encode` | `morse` | Encode text as Morse code |
| `nato` |  | Spell text out with the NATO phonetic alphabet |
| `octal-decode` | `fromoctal`, `unoct` | Decode octal bytes back to text |
| `octal-encode` | `tooctal`, `oct` | Encode text as octal bytes |
| `rot13` |  | Apply the ROT13 letter substitution |
| `rot47` |  | Apply the ROT47 substitution over printable ASCII |
| `unicode-escape` | `uescape` | Escape characters as \uXXXX sequences |
| `unicode-unescape` | `uunescape` | Decode \uXXXX and \xNN escape sequences |
| `url-decode` | `ud`, `urldecode` | Decode percent-encoded URL text |
| `url-encode` | `ue`, `urlencode` | Percent-encode text for URLs |

### Hashing

Checksums and cryptographic digests.

| Operation | Also known as | What it does |
| --- | --- | --- |
| `blake3` |  | BLAKE3 digest of the input |
| `crc32` |  | CRC32 checksum of the input |
| `hmac-sha1` |  | HMAC-SHA1 authentication code of the input |
| `hmac-sha256` | `hmac` | HMAC-SHA256 authentication code of the input |
| `hmac-sha512` |  | HMAC-SHA512 authentication code of the input |
| `keccak256` |  | Keccak-256 digest of the input |
| `md5` |  | MD5 digest of the input |
| `sha1` |  | SHA-1 digest of the input |
| `sha224` |  | SHA-224 digest of the input |
| `sha256` |  | SHA-256 digest of the input |
| `sha3-256` |  | SHA3-256 digest of the input |
| `sha3-512` |  | SHA3-512 digest of the input |
| `sha384` |  | SHA-384 digest of the input |
| `sha512` |  | SHA-512 digest of the input |

### Lines

Sort, filter, number, pad and reshape lines.

| Operation | Also known as | What it does |
| --- | --- | --- |
| `center` |  | Centre every line inside a width |
| `chunk` |  | Break text into fixed width lines |
| `dedent` |  | Remove the common leading whitespace |
| `duplicates` |  | Keep only lines that appear more than once |
| `filter` | `grep` | Keep the lines matching a text or a regular expression |
| `head` | `first` | Keep the first lines |
| `indent` |  | Indent every line |
| `join` | `join-lines` | Join all lines into one |
| `number` | `number-lines`, `nl` | Prefix every line with its number |
| `pad-left` | `left-pad`, `align-right` | Pad every line on the left to a width |
| `pad-right` | `right-pad`, `align-left` | Pad every line on the right to a width |
| `prefix` | `add-prefix` | Add text to the start of every line |
| `remove-empty` | `compact` | Remove blank lines |
| `reverse-lines` | `tac` | Put the lines in reverse order |
| `sample` | `random-line` | Pick random lines |
| `shuffle` | `randomize-lines` | Put the lines in random order |
| `sort` |  | Sort lines alphabetically |
| `split` | `split-text` | Split text into one line per piece |
| `suffix` | `add-suffix` | Add text to the end of every line |
| `tail` | `last` | Keep the last lines |
| `trim-lines` |  | Remove leading and trailing spaces from every line |
| `unique` | `dedupe`, `remove-duplicates`, `uniq` | Remove duplicate lines, keeping the first of each |
| `wrap` | `fill` | Wrap text to a maximum line width |

### Text

Search, replace, trim, wrap and clean up text.

| Operation | Also known as | What it does |
| --- | --- | --- |
| `escape-regex` | `regex-escape` | Escape the characters that are special in a regular expression |
| `extract` | `match` | Print the parts of the text matching a pattern |
| `fancy` | `fancy-text`, `stylize` | Restyle text with Unicode letterforms |
| `newlines-to-spaces` | `unlines` | Put all the text on one line |
| `normalize` | `unicode-normalize` | Apply a Unicode normalisation form |
| `palindrome` |  | Make a palindrome by mirroring the text |
| `quote` |  | Wrap every line in quotes |
| `remove` |  | Remove text or a pattern |
| `remove-accents` | `deaccent`, `unaccent` | Replace accented letters with their plain form |
| `remove-non-ascii` | `ascii-only` | Drop every non ASCII character |
| `remove-punctuation` | `strip-punctuation` | Remove punctuation characters |
| `remove-whitespace` | `strip-spaces` | Remove every whitespace character |
| `repeat` |  | Repeat the text a number of times |
| `replace` | `find-replace`, `sub` | Replace text or a pattern |
| `reverse` | `reverse-text` | Reverse the characters of the text |
| `reverse-words` |  | Reverse the order of the words |
| `rotate` |  | Rotate the characters of the text |
| `slugify` | `slug` | Turn text into a lowercase URL slug |
| `spaces-to-newlines` | `words-to-lines` | Put every word on its own line |
| `spaces-to-tabs` | `tabify`, `unexpand` | Replace runs of spaces with tabs |
| `squeeze` | `normalize-space`, `remove-extra-spaces` | Collapse runs of whitespace into single spaces |
| `strip-html` | `strip-tags`, `html-to-text` | Remove HTML tags and decode entities |
| `tabs-to-spaces` | `untabify`, `expand` | Replace tabs with spaces |
| `trim` |  | Remove whitespace from both ends |
| `truncate` | `shorten` | Shorten text to a maximum length |

### Numbers

Bases, roman numerals and number spelling.

| Operation | Also known as | What it does |
| --- | --- | --- |
| `base-convert` | `radix` | Convert a number between bases |
| `ordinal` |  | Turn a number into 1st, 2nd, 3rd and so on |
| `roman-decode` | `unroman` | Read a roman numeral as a number |
| `roman-encode` | `roman` | Write a number in roman numerals |
| `spell` | `number-to-words`, `spell-number` | Spell a number out in English words |

### Convert

JSON, YAML, TOML and CSV in every direction.

| Operation | Also known as | What it does |
| --- | --- | --- |
| `csv-to-json` | `csv2json` | Convert CSV rows to JSON |
| `csv-to-markdown` | `csv2md` | Render CSV as a Markdown table |
| `json-format` | `json-pretty`, `json-beautify` | Pretty print JSON |
| `json-minify` | `json-compact` | Remove all whitespace from JSON |
| `json-to-csv` | `json2csv` | Convert an array of JSON objects to CSV |
| `json-to-toml` | `json2toml` | Convert JSON to TOML |
| `json-to-yaml` | `json2yaml` | Convert JSON to YAML |
| `toml-to-json` | `toml2json` | Convert TOML to JSON |
| `toml-to-yaml` | `toml2yaml` | Convert TOML to YAML |
| `yaml-to-json` | `yaml2json` | Convert YAML to JSON |
| `yaml-to-toml` | `yaml2toml` | Convert YAML to TOML |

### Inspect

Counts, statistics, frequencies and code points.

| Operation | Also known as | What it does |
| --- | --- | --- |
| `charinfo` | `chars`, `explain` | Describe every character: code point, bytes and category |
| `count-bytes` |  | Count bytes |
| `count-chars` | `length`, `len` | Count characters |
| `count-lines` |  | Count lines |
| `count-words` | `wc` | Count words |
| `frequency` | `freq`, `histogram` | Count how often each word, character or line appears |
| `is-palindrome` |  | Report whether the text reads the same backwards |
| `stats` | `analyze`, `info` | Summarise the text in numbers |

### Generate

UUIDs, passwords, random data and placeholder text.

| Operation | Also known as | What it does |
| --- | --- | --- |
| `lorem` | `lipsum`, `placeholder` | Generate placeholder text |
| `password` | `passwd`, `pwgen` | Generate random passwords |
| `random-number` | `random-int`, `dice` | Generate random whole numbers |
| `random-string` |  | Generate random strings |
| `sequence` | `seq`, `range` | Generate a run of numbers |
| `token` | `random-bytes`, `secret` | Generate random tokens from raw bytes |
| `uuid` | `guid` | Generate UUIDs |

### Time

Timestamps and date formatting.

| Operation | Also known as | What it does |
| --- | --- | --- |
| `from-timestamp` | `ts2date`, `unix-to-date` | Turn a Unix timestamp into a readable date |
| `now` | `date` | Print the current date and time |
| `timestamp` | `epoch`, `unix` | Print the current Unix timestamp |
| `to-timestamp` | `date2ts`, `date-to-unix` | Turn a date into a Unix timestamp |
## Using it as a library

The operation registry is exposed as a library, so the same catalogue is
available from Rust. The API documentation is on
[docs.rs](https://docs.rs/txc).

```rust
use txc::{Params, find};

let op = find("slugify").expect("slugify is registered");
let text = op.apply("Hello, World!", &Params::for_op(op), None)?;
assert_eq!(text, "hello-world");
```

The vault is there too, as `txc::vault`, with the same checks as the command
line.

## Development

```
cargo test          # unit and end to end tests
cargo clippy        # lints
cargo fmt           # formatting
```

Operations live in [`src/ops/`](src/ops), one module per category. Adding one
means writing a function and registering it; the command line parser, the help
text, the shell completions and the interactive interface are all generated
from that single declaration.

---

## Author

Copyright [2022] Matheus Santos (vorj.dux@gmail.com)

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
