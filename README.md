# txc

Text utilities for the terminal. Everything the online text tool sites do, done
locally: your text never leaves the machine, there is no network call, and
there is nothing to paste into a web form.

143 operations across 10 categories, each usable as an argument, over a pipe,
or from an interactive interface.

```
$ txc url-encode "This string will be URL encoded"
This%20string%20will%20be%20URL%20encoded

$ echo "This string will be URL encoded" | txc ue
This%20string%20will%20be%20URL%20encoded

$ txc snake "userFirstName" | txc upper
USER_FIRST_NAME
```

## The interactive interface

Run `txc` with no arguments and it opens a full screen interface. Pick an
operation on the left, type in the input panel, and the output updates as you
type.

```
 txc  0.2.0 Encode text as base64
╭ Categories ──╮╭ Search ──────────────────╮╭ Input (18 characters) ───────────────────────╮
│All           ││base64                    ││offline text tools                            │
│Case          │╰──────────────────────────╯│                                              │
│Encoding      │┏ Operations (2) ━━━━━━━━━━┓│                                              │
│Hashing       │┃base64-encode             ┃│                                              │
│Lines         │┃base64-decode             ┃│                                              │
│Text          │┃                          ┃╰──────────────────────────────────────────────╯
│Numbers       │┃                          ┃╭ Options ─────────────────────────────────────╮
│Convert       │┃                          ┃│url-safe no-pad                               │
│Inspect       │┃                          ┃╰──────────────────────────────────────────────╯
│Generate      │┃                          ┃╭ Output (24 characters) ──────────────────────╮
│Time          │┃                          ┃│b2ZmbGluZSB0ZXh0IHRvb2xz                      │
│              │┃                          ┃│                                              │
╰──────────────╯┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛╰──────────────────────────────────────────────╯
 tab  panel   ^up/^down  operation   ^p  pipe output to input   ^s  save   ?  help   ^c  quit
```

| Key | Action |
| --- | --- |
| `tab` / `shift+tab` | Move between panels |
| `up` / `down` | Move inside a list |
| `ctrl+up` / `ctrl+down` | Change operation from any panel |
| `ctrl+left` / `ctrl+right` | Change category |
| `/` | Jump to the search box |
| `ctrl+p` | Move the output into the input, to chain operations |
| `ctrl+s` | Save the output to `txc-output.txt` |
| `ctrl+l` | Clear the input |
| `ctrl+w` | Delete the word before the cursor |
| `page up` / `page down` | Scroll the output |
| `?` or `F1` | Key reference |
| `ctrl+c` | Quit |

The Options panel takes the same options the command line does, written as
`key=value` pairs and bare switches, for example `width=40 upper`. The panel
shows the options the selected operation accepts.

## Installing

```
cargo install --path .
```

Or build a Debian package with [`cargo-deb`](https://github.com/kornelski/cargo-deb):

```
cargo deb
```

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
gives `HELLO WORLD`.

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
available from Rust:

```rust
use txc::{find, Params};

let op = find("slugify").expect("slugify is registered");
let text = op.apply("Hello, World!", &Params::for_op(op), None)?;
assert_eq!(text, "hello-world");
```

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
