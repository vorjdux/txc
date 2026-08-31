
use builtin;
use str;

set edit:completion:arg-completer[txc] = {|@words|
    fn spaces {|n|
        builtin:repeat $n ' ' | str:join ''
    }
    fn cand {|text desc|
        edit:complex-candidate $text &display=$text' '(spaces (- 14 (wcswidth $text)))$desc
    }
    var command = 'txc'
    for word $words[1..-1] {
        if (str:has-prefix $word '-') {
            break
        }
        set command = $command';'$word
    }
    var completions = [
        &'txc'= {
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
            cand alternate 'Convert text to aLtErNaTiNg case'
            cand camel 'Convert text to camelCase'
            cand capitalize 'Capitalise the first letter of every word, keeping the rest as is'
            cand constant 'Convert text to CONSTANT_CASE'
            cand dot 'Convert text to dot.case'
            cand kebab 'Convert text to kebab-case'
            cand lower 'Convert text to lowercase'
            cand pascal 'Convert text to PascalCase'
            cand random-case 'Randomise the case of every letter'
            cand sentence 'Capitalise the first letter of every sentence'
            cand snake 'Convert text to snake_case'
            cand swap 'Swap the case of every letter'
            cand title 'Capitalise The First Letter Of Every Word'
            cand train 'Convert text to Train-Case'
            cand upper 'Convert text to UPPERCASE'
            cand atbash 'Apply the Atbash mirror cipher'
            cand base32-decode 'Decode base32 back to text'
            cand base32-encode 'Encode text as base32'
            cand base58-decode 'Decode base58 back to text'
            cand base58-encode 'Encode text as base58 (bitcoin alphabet)'
            cand base64-decode 'Decode base64 back to text'
            cand base64-encode 'Encode text as base64'
            cand binary-decode 'Decode binary bytes back to text'
            cand binary-encode 'Encode text as binary bytes'
            cand caesar 'Shift letters by a fixed amount'
            cand codepoint-decode 'Turn U+XXXX code points back into characters'
            cand codepoint-encode 'Show the Unicode code point of every character'
            cand decimal-decode 'Decode decimal byte values back to text'
            cand decimal-encode 'Encode text as decimal byte values'
            cand hex-decode 'Decode hexadecimal back to text'
            cand hex-encode 'Encode text as hexadecimal'
            cand html-decode 'Decode HTML entities'
            cand html-encode 'Escape HTML special characters'
            cand json-escape 'Escape text for a JSON string'
            cand json-unescape 'Decode a JSON string escape sequence'
            cand morse-decode 'Decode Morse code back to text'
            cand morse-encode 'Encode text as Morse code'
            cand nato 'Spell text out with the NATO phonetic alphabet'
            cand octal-decode 'Decode octal bytes back to text'
            cand octal-encode 'Encode text as octal bytes'
            cand rot13 'Apply the ROT13 letter substitution'
            cand rot47 'Apply the ROT47 substitution over printable ASCII'
            cand unicode-escape 'Escape characters as \uXXXX sequences'
            cand unicode-unescape 'Decode \uXXXX and \xNN escape sequences'
            cand url-decode 'Decode percent-encoded URL text'
            cand url-encode 'Percent-encode text for URLs'
            cand blake3 'BLAKE3 digest of the input'
            cand crc32 'CRC32 checksum of the input'
            cand hmac-sha1 'HMAC-SHA1 authentication code of the input'
            cand hmac-sha256 'HMAC-SHA256 authentication code of the input'
            cand hmac-sha512 'HMAC-SHA512 authentication code of the input'
            cand keccak256 'Keccak-256 digest of the input'
            cand md5 'MD5 digest of the input'
            cand sha1 'SHA-1 digest of the input'
            cand sha224 'SHA-224 digest of the input'
            cand sha256 'SHA-256 digest of the input'
            cand sha3-256 'SHA3-256 digest of the input'
            cand sha3-512 'SHA3-512 digest of the input'
            cand sha384 'SHA-384 digest of the input'
            cand sha512 'SHA-512 digest of the input'
            cand center 'Centre every line inside a width'
            cand chunk 'Break text into fixed width lines'
            cand dedent 'Remove the common leading whitespace'
            cand duplicates 'Keep only lines that appear more than once'
            cand filter 'Keep the lines matching a text or a regular expression'
            cand head 'Keep the first lines'
            cand indent 'Indent every line'
            cand join 'Join all lines into one'
            cand number 'Prefix every line with its number'
            cand pad-left 'Pad every line on the left to a width'
            cand pad-right 'Pad every line on the right to a width'
            cand prefix 'Add text to the start of every line'
            cand remove-empty 'Remove blank lines'
            cand reverse-lines 'Put the lines in reverse order'
            cand sample 'Pick random lines'
            cand shuffle 'Put the lines in random order'
            cand sort 'Sort lines alphabetically'
            cand split 'Split text into one line per piece'
            cand suffix 'Add text to the end of every line'
            cand tail 'Keep the last lines'
            cand trim-lines 'Remove leading and trailing spaces from every line'
            cand unique 'Remove duplicate lines, keeping the first of each'
            cand wrap 'Wrap text to a maximum line width'
            cand escape-regex 'Escape the characters that are special in a regular expression'
            cand extract 'Print the parts of the text matching a pattern'
            cand fancy 'Restyle text with Unicode letterforms'
            cand newlines-to-spaces 'Put all the text on one line'
            cand normalize 'Apply a Unicode normalisation form'
            cand palindrome 'Make a palindrome by mirroring the text'
            cand quote 'Wrap every line in quotes'
            cand remove 'Remove text or a pattern'
            cand remove-accents 'Replace accented letters with their plain form'
            cand remove-non-ascii 'Drop every non ASCII character'
            cand remove-punctuation 'Remove punctuation characters'
            cand remove-whitespace 'Remove every whitespace character'
            cand repeat 'Repeat the text a number of times'
            cand replace 'Replace text or a pattern'
            cand reverse 'Reverse the characters of the text'
            cand reverse-words 'Reverse the order of the words'
            cand rotate 'Rotate the characters of the text'
            cand slugify 'Turn text into a lowercase URL slug'
            cand spaces-to-newlines 'Put every word on its own line'
            cand spaces-to-tabs 'Replace runs of spaces with tabs'
            cand squeeze 'Collapse runs of whitespace into single spaces'
            cand strip-html 'Remove HTML tags and decode entities'
            cand tabs-to-spaces 'Replace tabs with spaces'
            cand trim 'Remove whitespace from both ends'
            cand truncate 'Shorten text to a maximum length'
            cand base-convert 'Convert a number between bases'
            cand ordinal 'Turn a number into 1st, 2nd, 3rd and so on'
            cand roman-decode 'Read a roman numeral as a number'
            cand roman-encode 'Write a number in roman numerals'
            cand spell 'Spell a number out in English words'
            cand csv-to-json 'Convert CSV rows to JSON'
            cand csv-to-markdown 'Render CSV as a Markdown table'
            cand json-format 'Pretty print JSON'
            cand json-minify 'Remove all whitespace from JSON'
            cand json-to-csv 'Convert an array of JSON objects to CSV'
            cand json-to-toml 'Convert JSON to TOML'
            cand json-to-yaml 'Convert JSON to YAML'
            cand toml-to-json 'Convert TOML to JSON'
            cand toml-to-yaml 'Convert TOML to YAML'
            cand yaml-to-json 'Convert YAML to JSON'
            cand yaml-to-toml 'Convert YAML to TOML'
            cand charinfo 'Describe every character: code point, bytes and category'
            cand count-bytes 'Count bytes'
            cand count-chars 'Count characters'
            cand count-lines 'Count lines'
            cand count-words 'Count words'
            cand frequency 'Count how often each word, character or line appears'
            cand is-palindrome 'Report whether the text reads the same backwards'
            cand stats 'Summarise the text in numbers'
            cand lorem 'Generate placeholder text'
            cand password 'Generate random passwords'
            cand random-number 'Generate random whole numbers'
            cand random-string 'Generate random strings'
            cand sequence 'Generate a run of numbers'
            cand token 'Generate random tokens from raw bytes'
            cand uuid 'Generate UUIDs'
            cand from-timestamp 'Turn a Unix timestamp into a readable date'
            cand now 'Print the current date and time'
            cand timestamp 'Print the current Unix timestamp'
            cand to-timestamp 'Turn a date into a Unix timestamp'
            cand list 'List every operation, optionally filtered by category'
            cand completions 'Print a shell completion script'
            cand tui 'Open the interactive interface'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'txc;alternate'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;camel'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;capitalize'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;constant'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;dot'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;kebab'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;lower'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;pascal'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;random-case'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;sentence'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;snake'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;swap'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;title'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;train'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;upper'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;atbash'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;base32-decode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;base32-encode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand --no-pad 'Omit the = padding characters'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;base58-decode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;base58-encode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;base64-decode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand --url-safe 'Use the URL and filename safe alphabet'
            cand --no-pad 'Omit the = padding characters'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;base64-encode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand --url-safe 'Use the URL and filename safe alphabet'
            cand --no-pad 'Omit the = padding characters'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;binary-decode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;binary-encode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -s 'Separator between values'
            cand --sep 'Separator between values'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;caesar'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --shift 'Number of places to shift'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;codepoint-decode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;codepoint-encode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -s 'Separator between values'
            cand --sep 'Separator between values'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;decimal-decode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;decimal-encode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -s 'Separator between values'
            cand --sep 'Separator between values'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;hex-decode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;hex-encode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -s 'Separator between bytes'
            cand --sep 'Separator between bytes'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Use uppercase output'
            cand --upper 'Use uppercase output'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;html-decode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;html-encode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -q 'Also escape single and double quotes'
            cand --quotes 'Also escape single and double quotes'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;json-escape'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -q 'Keep the surrounding double quotes'
            cand --quotes 'Keep the surrounding double quotes'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;json-unescape'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;morse-decode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;morse-encode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;nato'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;octal-decode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;octal-encode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -s 'Separator between values'
            cand --sep 'Separator between values'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;rot13'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;rot47'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;unicode-escape'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -a 'Escape ASCII characters as well'
            cand --all 'Escape ASCII characters as well'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;unicode-unescape'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;url-decode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;url-encode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;blake3'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;crc32'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the checksum in uppercase hex'
            cand --upper 'Print the checksum in uppercase hex'
            cand -d 'Print the checksum as a decimal number'
            cand --decimal 'Print the checksum as a decimal number'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;hmac-sha1'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -k 'Secret key for the authentication code'
            cand --key 'Secret key for the authentication code'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;hmac-sha256'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -k 'Secret key for the authentication code'
            cand --key 'Secret key for the authentication code'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;hmac-sha512'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -k 'Secret key for the authentication code'
            cand --key 'Secret key for the authentication code'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;keccak256'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;md5'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;sha1'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;sha224'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;sha256'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;sha3-256'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;sha3-512'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;sha384'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;sha512'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print the digest in uppercase hex'
            cand --upper 'Print the digest in uppercase hex'
            cand -b 'Print the digest as base64 instead of hex'
            cand --base64 'Print the digest as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;center'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -w 'Target width in characters'
            cand --width 'Target width in characters'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;chunk'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -s 'Characters per output line'
            cand --size 'Characters per output line'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;dedent'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;duplicates'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -i 'Compare without regard to case'
            cand --ignore-case 'Compare without regard to case'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;filter'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -c 'Keep lines containing this text'
            cand --contains 'Keep lines containing this text'
            cand -r 'Keep lines matching this regular expression'
            cand --regex 'Keep lines matching this regular expression'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -v 'Keep the lines that do not match'
            cand --invert 'Keep the lines that do not match'
            cand -i 'Match without regard to case'
            cand --ignore-case 'Match without regard to case'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;head'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -c 'How many lines to keep'
            cand --count 'How many lines to keep'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;indent'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -c 'How many characters to indent by'
            cand --count 'How many characters to indent by'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -t 'Indent with tabs instead of spaces'
            cand --tabs 'Indent with tabs instead of spaces'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;join'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -s 'Text placed between the joined lines'
            cand --sep 'Text placed between the joined lines'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;number'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -s 'First number to use'
            cand --start 'First number to use'
            cand --sep 'Text between the number and the line'
            cand -w 'Pad numbers to this width with spaces'
            cand --width 'Pad numbers to this width with spaces'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -z 'Pad numbers with zeros instead of spaces'
            cand --zeros 'Pad numbers with zeros instead of spaces'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;pad-left'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -w 'Target width in characters'
            cand --width 'Target width in characters'
            cand -c 'Character used for padding'
            cand --char 'Character used for padding'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;pad-right'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -w 'Target width in characters'
            cand --width 'Target width in characters'
            cand -c 'Character used for padding'
            cand --char 'Character used for padding'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;prefix'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -t 'Text to add'
            cand --text 'Text to add'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;remove-empty'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;reverse-lines'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;sample'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -c 'How many lines to pick'
            cand --count 'How many lines to pick'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;shuffle'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;sort'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -r 'Sort in descending order'
            cand --reverse 'Sort in descending order'
            cand --numeric 'Compare the leading number on each line'
            cand -i 'Compare without regard to case'
            cand --ignore-case 'Compare without regard to case'
            cand -u 'Drop duplicate lines after sorting'
            cand --unique 'Drop duplicate lines after sorting'
            cand -l 'Sort by line length'
            cand --length 'Sort by line length'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;split'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -s 'Separator to split on'
            cand --sep 'Separator to split on'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -r 'Treat the separator as a regular expression'
            cand --regex 'Treat the separator as a regular expression'
            cand --keep-empty 'Keep empty pieces'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;suffix'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -t 'Text to add'
            cand --text 'Text to add'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;tail'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -c 'How many lines to keep'
            cand --count 'How many lines to keep'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;trim-lines'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;unique'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -i 'Compare without regard to case'
            cand --ignore-case 'Compare without regard to case'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;wrap'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -w 'Target width in characters'
            cand --width 'Target width in characters'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;escape-regex'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;extract'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -r 'Regular expression to search for'
            cand --regex 'Regular expression to search for'
            cand -g 'Capture group to print, 0 for the whole match'
            cand --group 'Capture group to print, 0 for the whole match'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand --first 'Print only the first match'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;fancy'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -s 'bold, italic, bold-italic, script, fraktur, double, mono, circled, fullwidth, smallcaps or flip'
            cand --style 'bold, italic, bold-italic, script, fraktur, double, mono, circled, fullwidth, smallcaps or flip'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;newlines-to-spaces'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;normalize'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --form 'Normalisation form: nfc, nfd, nfkc or nfkd'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;palindrome'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;quote'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -c 'Quote character to wrap each line with'
            cand --char 'Quote character to wrap each line with'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;remove'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -t 'Exact text to remove'
            cand --text 'Exact text to remove'
            cand -r 'Regular expression to remove'
            cand --regex 'Regular expression to remove'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;remove-accents'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;remove-non-ascii'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;remove-punctuation'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;remove-whitespace'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;repeat'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -c 'How many copies to produce'
            cand --count 'How many copies to produce'
            cand -s 'Text placed between copies'
            cand --sep 'Text placed between copies'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;replace'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --find 'Text or pattern to look for'
            cand -w 'Replacement text'
            cand --with 'Replacement text'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -r 'Treat --find as a regular expression'
            cand --regex 'Treat --find as a regular expression'
            cand -i 'Match without regard to case'
            cand --ignore-case 'Match without regard to case'
            cand --first 'Replace only the first match'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;reverse'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;reverse-words'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;rotate'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -c 'How many places to rotate'
            cand --count 'How many places to rotate'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;slugify'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;spaces-to-newlines'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;spaces-to-tabs'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -w 'Number of spaces per tab'
            cand --width 'Number of spaces per tab'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;squeeze'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;strip-html'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;tabs-to-spaces'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -w 'Number of spaces per tab'
            cand --width 'Number of spaces per tab'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;trim'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -c 'Characters to strip instead of whitespace'
            cand --chars 'Characters to strip instead of whitespace'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand --start 'Only trim the start'
            cand --end 'Only trim the end'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;truncate'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -l 'Maximum length in characters'
            cand --length 'Maximum length in characters'
            cand -s 'Text appended when the input is cut'
            cand --suffix 'Text appended when the input is cut'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;base-convert'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --from 'Base of the input, 2 to 36'
            cand --to 'Base of the output, 2 to 36'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Use uppercase digits'
            cand --upper 'Use uppercase digits'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;ordinal'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;roman-decode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;roman-encode'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;spell'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;csv-to-json'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -d 'Field separator in the input'
            cand --delimiter 'Field separator in the input'
            cand -i 'Spaces of indentation, 0 for one line'
            cand --indent 'Spaces of indentation, 0 for one line'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand --no-header 'Treat the first row as data, not as column names'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;csv-to-markdown'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -d 'Field separator in the output'
            cand --delimiter 'Field separator in the output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;json-format'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -i 'Spaces of indentation'
            cand --indent 'Spaces of indentation'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;json-minify'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;json-to-csv'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -d 'Field separator in the output'
            cand --delimiter 'Field separator in the output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;json-to-toml'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;json-to-yaml'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;toml-to-json'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -i 'Spaces of indentation'
            cand --indent 'Spaces of indentation'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;toml-to-yaml'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;yaml-to-json'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -i 'Spaces of indentation'
            cand --indent 'Spaces of indentation'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;yaml-to-toml'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;charinfo'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;count-bytes'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;count-chars'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;count-lines'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;count-words'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;frequency'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -b 'What to count: word, char or line'
            cand --by 'What to count: word, char or line'
            cand -t 'Only show the most frequent entries, 0 for all'
            cand --top 'Only show the most frequent entries, 0 for all'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -i 'Count without regard to case'
            cand --ignore-case 'Count without regard to case'
            cand -p 'Include the share of the total'
            cand --percent 'Include the share of the total'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;is-palindrome'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;stats'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;lorem'= {
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -p 'How many paragraphs to write'
            cand --paragraphs 'How many paragraphs to write'
            cand -s 'Sentences per paragraph'
            cand --sentences 'Sentences per paragraph'
            cand -w 'Produce this many words instead of paragraphs'
            cand --words 'Produce this many words instead of paragraphs'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;password'= {
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -l 'Characters per password'
            cand --length 'Characters per password'
            cand -c 'How many passwords to generate'
            cand --count 'How many passwords to generate'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand --no-symbols 'Leave out punctuation'
            cand --no-digits 'Leave out digits'
            cand --no-upper 'Leave out uppercase letters'
            cand --no-lower 'Leave out lowercase letters'
            cand --no-ambiguous 'Leave out characters that look alike, such as l, 1, O and 0'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;random-number'= {
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --min 'Smallest value, inclusive'
            cand --max 'Largest value, inclusive'
            cand -c 'How many numbers to generate'
            cand --count 'How many numbers to generate'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;random-string'= {
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -l 'Characters per string'
            cand --length 'Characters per string'
            cand -c 'How many strings to generate'
            cand --count 'How many strings to generate'
            cand -s 'Characters to pick from'
            cand --charset 'Characters to pick from'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;sequence'= {
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand --start 'First value'
            cand --end 'Last value, inclusive'
            cand --step 'Amount to add each time'
            cand -t 'Template, with {} replaced by the number'
            cand --format 'Template, with {} replaced by the number'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;token'= {
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -b 'How many random bytes to draw'
            cand --bytes 'How many random bytes to draw'
            cand -c 'How many tokens to generate'
            cand --count 'How many tokens to generate'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand --base64 'Print as base64 instead of hex'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;uuid'= {
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -v 'UUID version: 1, 3, 4, 5, 7 or nil'
            cand --version 'UUID version: 1, 3, 4, 5, 7 or nil'
            cand -c 'How many to generate'
            cand --count 'How many to generate'
            cand --name 'Name to hash, required by versions 3 and 5'
            cand --namespace 'Namespace for versions 3 and 5: dns, url, oid, x500 or a UUID'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Print in uppercase'
            cand --upper 'Print in uppercase'
            cand --compact 'Print without the dashes'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;from-timestamp'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -t 'strftime style format'
            cand --format 'strftime style format'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Render in UTC instead of the local time zone'
            cand --utc 'Render in UTC instead of the local time zone'
            cand -m 'Read the input as milliseconds'
            cand --millis 'Read the input as milliseconds'
            cand --iso 'Use the RFC 3339 format'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;now'= {
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -t 'strftime style format'
            cand --format 'strftime style format'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Use UTC instead of the local time zone'
            cand --utc 'Use UTC instead of the local time zone'
            cand --iso 'Use the RFC 3339 format'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;timestamp'= {
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -m 'Print milliseconds instead of seconds'
            cand --millis 'Print milliseconds instead of seconds'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;to-timestamp'= {
            cand -f 'Read input from a file instead of arguments or standard input'
            cand --file 'Read input from a file instead of arguments or standard input'
            cand -o 'Write the result to a file instead of standard output'
            cand --out 'Write the result to a file instead of standard output'
            cand -t 'strftime style format of the input'
            cand --format 'strftime style format of the input'
            cand --raw 'Keep piped input exactly as read, including its trailing newline'
            cand --lines 'Apply the operation to each line separately'
            cand --whole 'Apply the operation to the whole input at once'
            cand -n 'Do not append a trailing newline to the result'
            cand --no-newline 'Do not append a trailing newline to the result'
            cand -u 'Read the input as UTC instead of local time'
            cand --utc 'Read the input as UTC instead of local time'
            cand -m 'Print milliseconds instead of seconds'
            cand --millis 'Print milliseconds instead of seconds'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;list'= {
            cand -c 'Show only one category'
            cand --category 'Show only one category'
            cand --names 'Print bare operation names, one per line'
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;completions'= {
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
        }
        &'txc;tui'= {
            cand -h 'Print help'
            cand --help 'Print help'
        }
        &'txc;help'= {
            cand alternate 'Convert text to aLtErNaTiNg case'
            cand camel 'Convert text to camelCase'
            cand capitalize 'Capitalise the first letter of every word, keeping the rest as is'
            cand constant 'Convert text to CONSTANT_CASE'
            cand dot 'Convert text to dot.case'
            cand kebab 'Convert text to kebab-case'
            cand lower 'Convert text to lowercase'
            cand pascal 'Convert text to PascalCase'
            cand random-case 'Randomise the case of every letter'
            cand sentence 'Capitalise the first letter of every sentence'
            cand snake 'Convert text to snake_case'
            cand swap 'Swap the case of every letter'
            cand title 'Capitalise The First Letter Of Every Word'
            cand train 'Convert text to Train-Case'
            cand upper 'Convert text to UPPERCASE'
            cand atbash 'Apply the Atbash mirror cipher'
            cand base32-decode 'Decode base32 back to text'
            cand base32-encode 'Encode text as base32'
            cand base58-decode 'Decode base58 back to text'
            cand base58-encode 'Encode text as base58 (bitcoin alphabet)'
            cand base64-decode 'Decode base64 back to text'
            cand base64-encode 'Encode text as base64'
            cand binary-decode 'Decode binary bytes back to text'
            cand binary-encode 'Encode text as binary bytes'
            cand caesar 'Shift letters by a fixed amount'
            cand codepoint-decode 'Turn U+XXXX code points back into characters'
            cand codepoint-encode 'Show the Unicode code point of every character'
            cand decimal-decode 'Decode decimal byte values back to text'
            cand decimal-encode 'Encode text as decimal byte values'
            cand hex-decode 'Decode hexadecimal back to text'
            cand hex-encode 'Encode text as hexadecimal'
            cand html-decode 'Decode HTML entities'
            cand html-encode 'Escape HTML special characters'
            cand json-escape 'Escape text for a JSON string'
            cand json-unescape 'Decode a JSON string escape sequence'
            cand morse-decode 'Decode Morse code back to text'
            cand morse-encode 'Encode text as Morse code'
            cand nato 'Spell text out with the NATO phonetic alphabet'
            cand octal-decode 'Decode octal bytes back to text'
            cand octal-encode 'Encode text as octal bytes'
            cand rot13 'Apply the ROT13 letter substitution'
            cand rot47 'Apply the ROT47 substitution over printable ASCII'
            cand unicode-escape 'Escape characters as \uXXXX sequences'
            cand unicode-unescape 'Decode \uXXXX and \xNN escape sequences'
            cand url-decode 'Decode percent-encoded URL text'
            cand url-encode 'Percent-encode text for URLs'
            cand blake3 'BLAKE3 digest of the input'
            cand crc32 'CRC32 checksum of the input'
            cand hmac-sha1 'HMAC-SHA1 authentication code of the input'
            cand hmac-sha256 'HMAC-SHA256 authentication code of the input'
            cand hmac-sha512 'HMAC-SHA512 authentication code of the input'
            cand keccak256 'Keccak-256 digest of the input'
            cand md5 'MD5 digest of the input'
            cand sha1 'SHA-1 digest of the input'
            cand sha224 'SHA-224 digest of the input'
            cand sha256 'SHA-256 digest of the input'
            cand sha3-256 'SHA3-256 digest of the input'
            cand sha3-512 'SHA3-512 digest of the input'
            cand sha384 'SHA-384 digest of the input'
            cand sha512 'SHA-512 digest of the input'
            cand center 'Centre every line inside a width'
            cand chunk 'Break text into fixed width lines'
            cand dedent 'Remove the common leading whitespace'
            cand duplicates 'Keep only lines that appear more than once'
            cand filter 'Keep the lines matching a text or a regular expression'
            cand head 'Keep the first lines'
            cand indent 'Indent every line'
            cand join 'Join all lines into one'
            cand number 'Prefix every line with its number'
            cand pad-left 'Pad every line on the left to a width'
            cand pad-right 'Pad every line on the right to a width'
            cand prefix 'Add text to the start of every line'
            cand remove-empty 'Remove blank lines'
            cand reverse-lines 'Put the lines in reverse order'
            cand sample 'Pick random lines'
            cand shuffle 'Put the lines in random order'
            cand sort 'Sort lines alphabetically'
            cand split 'Split text into one line per piece'
            cand suffix 'Add text to the end of every line'
            cand tail 'Keep the last lines'
            cand trim-lines 'Remove leading and trailing spaces from every line'
            cand unique 'Remove duplicate lines, keeping the first of each'
            cand wrap 'Wrap text to a maximum line width'
            cand escape-regex 'Escape the characters that are special in a regular expression'
            cand extract 'Print the parts of the text matching a pattern'
            cand fancy 'Restyle text with Unicode letterforms'
            cand newlines-to-spaces 'Put all the text on one line'
            cand normalize 'Apply a Unicode normalisation form'
            cand palindrome 'Make a palindrome by mirroring the text'
            cand quote 'Wrap every line in quotes'
            cand remove 'Remove text or a pattern'
            cand remove-accents 'Replace accented letters with their plain form'
            cand remove-non-ascii 'Drop every non ASCII character'
            cand remove-punctuation 'Remove punctuation characters'
            cand remove-whitespace 'Remove every whitespace character'
            cand repeat 'Repeat the text a number of times'
            cand replace 'Replace text or a pattern'
            cand reverse 'Reverse the characters of the text'
            cand reverse-words 'Reverse the order of the words'
            cand rotate 'Rotate the characters of the text'
            cand slugify 'Turn text into a lowercase URL slug'
            cand spaces-to-newlines 'Put every word on its own line'
            cand spaces-to-tabs 'Replace runs of spaces with tabs'
            cand squeeze 'Collapse runs of whitespace into single spaces'
            cand strip-html 'Remove HTML tags and decode entities'
            cand tabs-to-spaces 'Replace tabs with spaces'
            cand trim 'Remove whitespace from both ends'
            cand truncate 'Shorten text to a maximum length'
            cand base-convert 'Convert a number between bases'
            cand ordinal 'Turn a number into 1st, 2nd, 3rd and so on'
            cand roman-decode 'Read a roman numeral as a number'
            cand roman-encode 'Write a number in roman numerals'
            cand spell 'Spell a number out in English words'
            cand csv-to-json 'Convert CSV rows to JSON'
            cand csv-to-markdown 'Render CSV as a Markdown table'
            cand json-format 'Pretty print JSON'
            cand json-minify 'Remove all whitespace from JSON'
            cand json-to-csv 'Convert an array of JSON objects to CSV'
            cand json-to-toml 'Convert JSON to TOML'
            cand json-to-yaml 'Convert JSON to YAML'
            cand toml-to-json 'Convert TOML to JSON'
            cand toml-to-yaml 'Convert TOML to YAML'
            cand yaml-to-json 'Convert YAML to JSON'
            cand yaml-to-toml 'Convert YAML to TOML'
            cand charinfo 'Describe every character: code point, bytes and category'
            cand count-bytes 'Count bytes'
            cand count-chars 'Count characters'
            cand count-lines 'Count lines'
            cand count-words 'Count words'
            cand frequency 'Count how often each word, character or line appears'
            cand is-palindrome 'Report whether the text reads the same backwards'
            cand stats 'Summarise the text in numbers'
            cand lorem 'Generate placeholder text'
            cand password 'Generate random passwords'
            cand random-number 'Generate random whole numbers'
            cand random-string 'Generate random strings'
            cand sequence 'Generate a run of numbers'
            cand token 'Generate random tokens from raw bytes'
            cand uuid 'Generate UUIDs'
            cand from-timestamp 'Turn a Unix timestamp into a readable date'
            cand now 'Print the current date and time'
            cand timestamp 'Print the current Unix timestamp'
            cand to-timestamp 'Turn a date into a Unix timestamp'
            cand list 'List every operation, optionally filtered by category'
            cand completions 'Print a shell completion script'
            cand tui 'Open the interactive interface'
            cand help 'Print this message or the help of the given subcommand(s)'
        }
        &'txc;help;alternate'= {
        }
        &'txc;help;camel'= {
        }
        &'txc;help;capitalize'= {
        }
        &'txc;help;constant'= {
        }
        &'txc;help;dot'= {
        }
        &'txc;help;kebab'= {
        }
        &'txc;help;lower'= {
        }
        &'txc;help;pascal'= {
        }
        &'txc;help;random-case'= {
        }
        &'txc;help;sentence'= {
        }
        &'txc;help;snake'= {
        }
        &'txc;help;swap'= {
        }
        &'txc;help;title'= {
        }
        &'txc;help;train'= {
        }
        &'txc;help;upper'= {
        }
        &'txc;help;atbash'= {
        }
        &'txc;help;base32-decode'= {
        }
        &'txc;help;base32-encode'= {
        }
        &'txc;help;base58-decode'= {
        }
        &'txc;help;base58-encode'= {
        }
        &'txc;help;base64-decode'= {
        }
        &'txc;help;base64-encode'= {
        }
        &'txc;help;binary-decode'= {
        }
        &'txc;help;binary-encode'= {
        }
        &'txc;help;caesar'= {
        }
        &'txc;help;codepoint-decode'= {
        }
        &'txc;help;codepoint-encode'= {
        }
        &'txc;help;decimal-decode'= {
        }
        &'txc;help;decimal-encode'= {
        }
        &'txc;help;hex-decode'= {
        }
        &'txc;help;hex-encode'= {
        }
        &'txc;help;html-decode'= {
        }
        &'txc;help;html-encode'= {
        }
        &'txc;help;json-escape'= {
        }
        &'txc;help;json-unescape'= {
        }
        &'txc;help;morse-decode'= {
        }
        &'txc;help;morse-encode'= {
        }
        &'txc;help;nato'= {
        }
        &'txc;help;octal-decode'= {
        }
        &'txc;help;octal-encode'= {
        }
        &'txc;help;rot13'= {
        }
        &'txc;help;rot47'= {
        }
        &'txc;help;unicode-escape'= {
        }
        &'txc;help;unicode-unescape'= {
        }
        &'txc;help;url-decode'= {
        }
        &'txc;help;url-encode'= {
        }
        &'txc;help;blake3'= {
        }
        &'txc;help;crc32'= {
        }
        &'txc;help;hmac-sha1'= {
        }
        &'txc;help;hmac-sha256'= {
        }
        &'txc;help;hmac-sha512'= {
        }
        &'txc;help;keccak256'= {
        }
        &'txc;help;md5'= {
        }
        &'txc;help;sha1'= {
        }
        &'txc;help;sha224'= {
        }
        &'txc;help;sha256'= {
        }
        &'txc;help;sha3-256'= {
        }
        &'txc;help;sha3-512'= {
        }
        &'txc;help;sha384'= {
        }
        &'txc;help;sha512'= {
        }
        &'txc;help;center'= {
        }
        &'txc;help;chunk'= {
        }
        &'txc;help;dedent'= {
        }
        &'txc;help;duplicates'= {
        }
        &'txc;help;filter'= {
        }
        &'txc;help;head'= {
        }
        &'txc;help;indent'= {
        }
        &'txc;help;join'= {
        }
        &'txc;help;number'= {
        }
        &'txc;help;pad-left'= {
        }
        &'txc;help;pad-right'= {
        }
        &'txc;help;prefix'= {
        }
        &'txc;help;remove-empty'= {
        }
        &'txc;help;reverse-lines'= {
        }
        &'txc;help;sample'= {
        }
        &'txc;help;shuffle'= {
        }
        &'txc;help;sort'= {
        }
        &'txc;help;split'= {
        }
        &'txc;help;suffix'= {
        }
        &'txc;help;tail'= {
        }
        &'txc;help;trim-lines'= {
        }
        &'txc;help;unique'= {
        }
        &'txc;help;wrap'= {
        }
        &'txc;help;escape-regex'= {
        }
        &'txc;help;extract'= {
        }
        &'txc;help;fancy'= {
        }
        &'txc;help;newlines-to-spaces'= {
        }
        &'txc;help;normalize'= {
        }
        &'txc;help;palindrome'= {
        }
        &'txc;help;quote'= {
        }
        &'txc;help;remove'= {
        }
        &'txc;help;remove-accents'= {
        }
        &'txc;help;remove-non-ascii'= {
        }
        &'txc;help;remove-punctuation'= {
        }
        &'txc;help;remove-whitespace'= {
        }
        &'txc;help;repeat'= {
        }
        &'txc;help;replace'= {
        }
        &'txc;help;reverse'= {
        }
        &'txc;help;reverse-words'= {
        }
        &'txc;help;rotate'= {
        }
        &'txc;help;slugify'= {
        }
        &'txc;help;spaces-to-newlines'= {
        }
        &'txc;help;spaces-to-tabs'= {
        }
        &'txc;help;squeeze'= {
        }
        &'txc;help;strip-html'= {
        }
        &'txc;help;tabs-to-spaces'= {
        }
        &'txc;help;trim'= {
        }
        &'txc;help;truncate'= {
        }
        &'txc;help;base-convert'= {
        }
        &'txc;help;ordinal'= {
        }
        &'txc;help;roman-decode'= {
        }
        &'txc;help;roman-encode'= {
        }
        &'txc;help;spell'= {
        }
        &'txc;help;csv-to-json'= {
        }
        &'txc;help;csv-to-markdown'= {
        }
        &'txc;help;json-format'= {
        }
        &'txc;help;json-minify'= {
        }
        &'txc;help;json-to-csv'= {
        }
        &'txc;help;json-to-toml'= {
        }
        &'txc;help;json-to-yaml'= {
        }
        &'txc;help;toml-to-json'= {
        }
        &'txc;help;toml-to-yaml'= {
        }
        &'txc;help;yaml-to-json'= {
        }
        &'txc;help;yaml-to-toml'= {
        }
        &'txc;help;charinfo'= {
        }
        &'txc;help;count-bytes'= {
        }
        &'txc;help;count-chars'= {
        }
        &'txc;help;count-lines'= {
        }
        &'txc;help;count-words'= {
        }
        &'txc;help;frequency'= {
        }
        &'txc;help;is-palindrome'= {
        }
        &'txc;help;stats'= {
        }
        &'txc;help;lorem'= {
        }
        &'txc;help;password'= {
        }
        &'txc;help;random-number'= {
        }
        &'txc;help;random-string'= {
        }
        &'txc;help;sequence'= {
        }
        &'txc;help;token'= {
        }
        &'txc;help;uuid'= {
        }
        &'txc;help;from-timestamp'= {
        }
        &'txc;help;now'= {
        }
        &'txc;help;timestamp'= {
        }
        &'txc;help;to-timestamp'= {
        }
        &'txc;help;list'= {
        }
        &'txc;help;completions'= {
        }
        &'txc;help;tui'= {
        }
        &'txc;help;help'= {
        }
    ]
    $completions[$command]
}
