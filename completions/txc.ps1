
using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -Native -CommandName 'txc' -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commandElements = $commandAst.CommandElements
    $command = @(
        'txc'
        for ($i = 1; $i -lt $commandElements.Count; $i++) {
            $element = $commandElements[$i]
            if ($element -isnot [StringConstantExpressionAst] -or
                $element.StringConstantType -ne [StringConstantType]::BareWord -or
                $element.Value.StartsWith('-') -or
                $element.Value -eq $wordToComplete) {
                break
        }
        $element.Value
    }) -join ';'

    $completions = @(switch ($command) {
        'txc' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('-V', '-V ', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'Print version')
            [CompletionResult]::new('alternate', 'alternate', [CompletionResultType]::ParameterValue, 'Convert text to aLtErNaTiNg case')
            [CompletionResult]::new('camel', 'camel', [CompletionResultType]::ParameterValue, 'Convert text to camelCase')
            [CompletionResult]::new('capitalize', 'capitalize', [CompletionResultType]::ParameterValue, 'Capitalise the first letter of every word, keeping the rest as is')
            [CompletionResult]::new('constant', 'constant', [CompletionResultType]::ParameterValue, 'Convert text to CONSTANT_CASE')
            [CompletionResult]::new('dot', 'dot', [CompletionResultType]::ParameterValue, 'Convert text to dot.case')
            [CompletionResult]::new('kebab', 'kebab', [CompletionResultType]::ParameterValue, 'Convert text to kebab-case')
            [CompletionResult]::new('lower', 'lower', [CompletionResultType]::ParameterValue, 'Convert text to lowercase')
            [CompletionResult]::new('pascal', 'pascal', [CompletionResultType]::ParameterValue, 'Convert text to PascalCase')
            [CompletionResult]::new('random-case', 'random-case', [CompletionResultType]::ParameterValue, 'Randomise the case of every letter')
            [CompletionResult]::new('sentence', 'sentence', [CompletionResultType]::ParameterValue, 'Capitalise the first letter of every sentence')
            [CompletionResult]::new('snake', 'snake', [CompletionResultType]::ParameterValue, 'Convert text to snake_case')
            [CompletionResult]::new('swap', 'swap', [CompletionResultType]::ParameterValue, 'Swap the case of every letter')
            [CompletionResult]::new('title', 'title', [CompletionResultType]::ParameterValue, 'Capitalise The First Letter Of Every Word')
            [CompletionResult]::new('train', 'train', [CompletionResultType]::ParameterValue, 'Convert text to Train-Case')
            [CompletionResult]::new('upper', 'upper', [CompletionResultType]::ParameterValue, 'Convert text to UPPERCASE')
            [CompletionResult]::new('atbash', 'atbash', [CompletionResultType]::ParameterValue, 'Apply the Atbash mirror cipher')
            [CompletionResult]::new('base32-decode', 'base32-decode', [CompletionResultType]::ParameterValue, 'Decode base32 back to text')
            [CompletionResult]::new('base32-encode', 'base32-encode', [CompletionResultType]::ParameterValue, 'Encode text as base32')
            [CompletionResult]::new('base58-decode', 'base58-decode', [CompletionResultType]::ParameterValue, 'Decode base58 back to text')
            [CompletionResult]::new('base58-encode', 'base58-encode', [CompletionResultType]::ParameterValue, 'Encode text as base58 (bitcoin alphabet)')
            [CompletionResult]::new('base64-decode', 'base64-decode', [CompletionResultType]::ParameterValue, 'Decode base64 back to text')
            [CompletionResult]::new('base64-encode', 'base64-encode', [CompletionResultType]::ParameterValue, 'Encode text as base64')
            [CompletionResult]::new('binary-decode', 'binary-decode', [CompletionResultType]::ParameterValue, 'Decode binary bytes back to text')
            [CompletionResult]::new('binary-encode', 'binary-encode', [CompletionResultType]::ParameterValue, 'Encode text as binary bytes')
            [CompletionResult]::new('caesar', 'caesar', [CompletionResultType]::ParameterValue, 'Shift letters by a fixed amount')
            [CompletionResult]::new('codepoint-decode', 'codepoint-decode', [CompletionResultType]::ParameterValue, 'Turn U+XXXX code points back into characters')
            [CompletionResult]::new('codepoint-encode', 'codepoint-encode', [CompletionResultType]::ParameterValue, 'Show the Unicode code point of every character')
            [CompletionResult]::new('decimal-decode', 'decimal-decode', [CompletionResultType]::ParameterValue, 'Decode decimal byte values back to text')
            [CompletionResult]::new('decimal-encode', 'decimal-encode', [CompletionResultType]::ParameterValue, 'Encode text as decimal byte values')
            [CompletionResult]::new('hex-decode', 'hex-decode', [CompletionResultType]::ParameterValue, 'Decode hexadecimal back to text')
            [CompletionResult]::new('hex-encode', 'hex-encode', [CompletionResultType]::ParameterValue, 'Encode text as hexadecimal')
            [CompletionResult]::new('html-decode', 'html-decode', [CompletionResultType]::ParameterValue, 'Decode HTML entities')
            [CompletionResult]::new('html-encode', 'html-encode', [CompletionResultType]::ParameterValue, 'Escape HTML special characters')
            [CompletionResult]::new('json-escape', 'json-escape', [CompletionResultType]::ParameterValue, 'Escape text for a JSON string')
            [CompletionResult]::new('json-unescape', 'json-unescape', [CompletionResultType]::ParameterValue, 'Decode a JSON string escape sequence')
            [CompletionResult]::new('morse-decode', 'morse-decode', [CompletionResultType]::ParameterValue, 'Decode Morse code back to text')
            [CompletionResult]::new('morse-encode', 'morse-encode', [CompletionResultType]::ParameterValue, 'Encode text as Morse code')
            [CompletionResult]::new('nato', 'nato', [CompletionResultType]::ParameterValue, 'Spell text out with the NATO phonetic alphabet')
            [CompletionResult]::new('octal-decode', 'octal-decode', [CompletionResultType]::ParameterValue, 'Decode octal bytes back to text')
            [CompletionResult]::new('octal-encode', 'octal-encode', [CompletionResultType]::ParameterValue, 'Encode text as octal bytes')
            [CompletionResult]::new('rot13', 'rot13', [CompletionResultType]::ParameterValue, 'Apply the ROT13 letter substitution')
            [CompletionResult]::new('rot47', 'rot47', [CompletionResultType]::ParameterValue, 'Apply the ROT47 substitution over printable ASCII')
            [CompletionResult]::new('unicode-escape', 'unicode-escape', [CompletionResultType]::ParameterValue, 'Escape characters as \uXXXX sequences')
            [CompletionResult]::new('unicode-unescape', 'unicode-unescape', [CompletionResultType]::ParameterValue, 'Decode \uXXXX and \xNN escape sequences')
            [CompletionResult]::new('url-decode', 'url-decode', [CompletionResultType]::ParameterValue, 'Decode percent-encoded URL text')
            [CompletionResult]::new('url-encode', 'url-encode', [CompletionResultType]::ParameterValue, 'Percent-encode text for URLs')
            [CompletionResult]::new('blake3', 'blake3', [CompletionResultType]::ParameterValue, 'BLAKE3 digest of the input')
            [CompletionResult]::new('crc32', 'crc32', [CompletionResultType]::ParameterValue, 'CRC32 checksum of the input')
            [CompletionResult]::new('hmac-sha1', 'hmac-sha1', [CompletionResultType]::ParameterValue, 'HMAC-SHA1 authentication code of the input')
            [CompletionResult]::new('hmac-sha256', 'hmac-sha256', [CompletionResultType]::ParameterValue, 'HMAC-SHA256 authentication code of the input')
            [CompletionResult]::new('hmac-sha512', 'hmac-sha512', [CompletionResultType]::ParameterValue, 'HMAC-SHA512 authentication code of the input')
            [CompletionResult]::new('keccak256', 'keccak256', [CompletionResultType]::ParameterValue, 'Keccak-256 digest of the input')
            [CompletionResult]::new('md5', 'md5', [CompletionResultType]::ParameterValue, 'MD5 digest of the input')
            [CompletionResult]::new('sha1', 'sha1', [CompletionResultType]::ParameterValue, 'SHA-1 digest of the input')
            [CompletionResult]::new('sha224', 'sha224', [CompletionResultType]::ParameterValue, 'SHA-224 digest of the input')
            [CompletionResult]::new('sha256', 'sha256', [CompletionResultType]::ParameterValue, 'SHA-256 digest of the input')
            [CompletionResult]::new('sha3-256', 'sha3-256', [CompletionResultType]::ParameterValue, 'SHA3-256 digest of the input')
            [CompletionResult]::new('sha3-512', 'sha3-512', [CompletionResultType]::ParameterValue, 'SHA3-512 digest of the input')
            [CompletionResult]::new('sha384', 'sha384', [CompletionResultType]::ParameterValue, 'SHA-384 digest of the input')
            [CompletionResult]::new('sha512', 'sha512', [CompletionResultType]::ParameterValue, 'SHA-512 digest of the input')
            [CompletionResult]::new('center', 'center', [CompletionResultType]::ParameterValue, 'Centre every line inside a width')
            [CompletionResult]::new('chunk', 'chunk', [CompletionResultType]::ParameterValue, 'Break text into fixed width lines')
            [CompletionResult]::new('dedent', 'dedent', [CompletionResultType]::ParameterValue, 'Remove the common leading whitespace')
            [CompletionResult]::new('duplicates', 'duplicates', [CompletionResultType]::ParameterValue, 'Keep only lines that appear more than once')
            [CompletionResult]::new('filter', 'filter', [CompletionResultType]::ParameterValue, 'Keep the lines matching a text or a regular expression')
            [CompletionResult]::new('head', 'head', [CompletionResultType]::ParameterValue, 'Keep the first lines')
            [CompletionResult]::new('indent', 'indent', [CompletionResultType]::ParameterValue, 'Indent every line')
            [CompletionResult]::new('join', 'join', [CompletionResultType]::ParameterValue, 'Join all lines into one')
            [CompletionResult]::new('number', 'number', [CompletionResultType]::ParameterValue, 'Prefix every line with its number')
            [CompletionResult]::new('pad-left', 'pad-left', [CompletionResultType]::ParameterValue, 'Pad every line on the left to a width')
            [CompletionResult]::new('pad-right', 'pad-right', [CompletionResultType]::ParameterValue, 'Pad every line on the right to a width')
            [CompletionResult]::new('prefix', 'prefix', [CompletionResultType]::ParameterValue, 'Add text to the start of every line')
            [CompletionResult]::new('remove-empty', 'remove-empty', [CompletionResultType]::ParameterValue, 'Remove blank lines')
            [CompletionResult]::new('reverse-lines', 'reverse-lines', [CompletionResultType]::ParameterValue, 'Put the lines in reverse order')
            [CompletionResult]::new('sample', 'sample', [CompletionResultType]::ParameterValue, 'Pick random lines')
            [CompletionResult]::new('shuffle', 'shuffle', [CompletionResultType]::ParameterValue, 'Put the lines in random order')
            [CompletionResult]::new('sort', 'sort', [CompletionResultType]::ParameterValue, 'Sort lines alphabetically')
            [CompletionResult]::new('split', 'split', [CompletionResultType]::ParameterValue, 'Split text into one line per piece')
            [CompletionResult]::new('suffix', 'suffix', [CompletionResultType]::ParameterValue, 'Add text to the end of every line')
            [CompletionResult]::new('tail', 'tail', [CompletionResultType]::ParameterValue, 'Keep the last lines')
            [CompletionResult]::new('trim-lines', 'trim-lines', [CompletionResultType]::ParameterValue, 'Remove leading and trailing spaces from every line')
            [CompletionResult]::new('unique', 'unique', [CompletionResultType]::ParameterValue, 'Remove duplicate lines, keeping the first of each')
            [CompletionResult]::new('wrap', 'wrap', [CompletionResultType]::ParameterValue, 'Wrap text to a maximum line width')
            [CompletionResult]::new('escape-regex', 'escape-regex', [CompletionResultType]::ParameterValue, 'Escape the characters that are special in a regular expression')
            [CompletionResult]::new('extract', 'extract', [CompletionResultType]::ParameterValue, 'Print the parts of the text matching a pattern')
            [CompletionResult]::new('fancy', 'fancy', [CompletionResultType]::ParameterValue, 'Restyle text with Unicode letterforms')
            [CompletionResult]::new('newlines-to-spaces', 'newlines-to-spaces', [CompletionResultType]::ParameterValue, 'Put all the text on one line')
            [CompletionResult]::new('normalize', 'normalize', [CompletionResultType]::ParameterValue, 'Apply a Unicode normalisation form')
            [CompletionResult]::new('palindrome', 'palindrome', [CompletionResultType]::ParameterValue, 'Make a palindrome by mirroring the text')
            [CompletionResult]::new('quote', 'quote', [CompletionResultType]::ParameterValue, 'Wrap every line in quotes')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove text or a pattern')
            [CompletionResult]::new('remove-accents', 'remove-accents', [CompletionResultType]::ParameterValue, 'Replace accented letters with their plain form')
            [CompletionResult]::new('remove-non-ascii', 'remove-non-ascii', [CompletionResultType]::ParameterValue, 'Drop every non ASCII character')
            [CompletionResult]::new('remove-punctuation', 'remove-punctuation', [CompletionResultType]::ParameterValue, 'Remove punctuation characters')
            [CompletionResult]::new('remove-whitespace', 'remove-whitespace', [CompletionResultType]::ParameterValue, 'Remove every whitespace character')
            [CompletionResult]::new('repeat', 'repeat', [CompletionResultType]::ParameterValue, 'Repeat the text a number of times')
            [CompletionResult]::new('replace', 'replace', [CompletionResultType]::ParameterValue, 'Replace text or a pattern')
            [CompletionResult]::new('reverse', 'reverse', [CompletionResultType]::ParameterValue, 'Reverse the characters of the text')
            [CompletionResult]::new('reverse-words', 'reverse-words', [CompletionResultType]::ParameterValue, 'Reverse the order of the words')
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate the characters of the text')
            [CompletionResult]::new('slugify', 'slugify', [CompletionResultType]::ParameterValue, 'Turn text into a lowercase URL slug')
            [CompletionResult]::new('spaces-to-newlines', 'spaces-to-newlines', [CompletionResultType]::ParameterValue, 'Put every word on its own line')
            [CompletionResult]::new('spaces-to-tabs', 'spaces-to-tabs', [CompletionResultType]::ParameterValue, 'Replace runs of spaces with tabs')
            [CompletionResult]::new('squeeze', 'squeeze', [CompletionResultType]::ParameterValue, 'Collapse runs of whitespace into single spaces')
            [CompletionResult]::new('strip-html', 'strip-html', [CompletionResultType]::ParameterValue, 'Remove HTML tags and decode entities')
            [CompletionResult]::new('tabs-to-spaces', 'tabs-to-spaces', [CompletionResultType]::ParameterValue, 'Replace tabs with spaces')
            [CompletionResult]::new('trim', 'trim', [CompletionResultType]::ParameterValue, 'Remove whitespace from both ends')
            [CompletionResult]::new('truncate', 'truncate', [CompletionResultType]::ParameterValue, 'Shorten text to a maximum length')
            [CompletionResult]::new('base-convert', 'base-convert', [CompletionResultType]::ParameterValue, 'Convert a number between bases')
            [CompletionResult]::new('ordinal', 'ordinal', [CompletionResultType]::ParameterValue, 'Turn a number into 1st, 2nd, 3rd and so on')
            [CompletionResult]::new('roman-decode', 'roman-decode', [CompletionResultType]::ParameterValue, 'Read a roman numeral as a number')
            [CompletionResult]::new('roman-encode', 'roman-encode', [CompletionResultType]::ParameterValue, 'Write a number in roman numerals')
            [CompletionResult]::new('spell', 'spell', [CompletionResultType]::ParameterValue, 'Spell a number out in English words')
            [CompletionResult]::new('csv-to-json', 'csv-to-json', [CompletionResultType]::ParameterValue, 'Convert CSV rows to JSON')
            [CompletionResult]::new('csv-to-markdown', 'csv-to-markdown', [CompletionResultType]::ParameterValue, 'Render CSV as a Markdown table')
            [CompletionResult]::new('json-format', 'json-format', [CompletionResultType]::ParameterValue, 'Pretty print JSON')
            [CompletionResult]::new('json-minify', 'json-minify', [CompletionResultType]::ParameterValue, 'Remove all whitespace from JSON')
            [CompletionResult]::new('json-to-csv', 'json-to-csv', [CompletionResultType]::ParameterValue, 'Convert an array of JSON objects to CSV')
            [CompletionResult]::new('json-to-toml', 'json-to-toml', [CompletionResultType]::ParameterValue, 'Convert JSON to TOML')
            [CompletionResult]::new('json-to-yaml', 'json-to-yaml', [CompletionResultType]::ParameterValue, 'Convert JSON to YAML')
            [CompletionResult]::new('toml-to-json', 'toml-to-json', [CompletionResultType]::ParameterValue, 'Convert TOML to JSON')
            [CompletionResult]::new('toml-to-yaml', 'toml-to-yaml', [CompletionResultType]::ParameterValue, 'Convert TOML to YAML')
            [CompletionResult]::new('yaml-to-json', 'yaml-to-json', [CompletionResultType]::ParameterValue, 'Convert YAML to JSON')
            [CompletionResult]::new('yaml-to-toml', 'yaml-to-toml', [CompletionResultType]::ParameterValue, 'Convert YAML to TOML')
            [CompletionResult]::new('charinfo', 'charinfo', [CompletionResultType]::ParameterValue, 'Describe every character: code point, bytes and category')
            [CompletionResult]::new('count-bytes', 'count-bytes', [CompletionResultType]::ParameterValue, 'Count bytes')
            [CompletionResult]::new('count-chars', 'count-chars', [CompletionResultType]::ParameterValue, 'Count characters')
            [CompletionResult]::new('count-lines', 'count-lines', [CompletionResultType]::ParameterValue, 'Count lines')
            [CompletionResult]::new('count-words', 'count-words', [CompletionResultType]::ParameterValue, 'Count words')
            [CompletionResult]::new('frequency', 'frequency', [CompletionResultType]::ParameterValue, 'Count how often each word, character or line appears')
            [CompletionResult]::new('is-palindrome', 'is-palindrome', [CompletionResultType]::ParameterValue, 'Report whether the text reads the same backwards')
            [CompletionResult]::new('stats', 'stats', [CompletionResultType]::ParameterValue, 'Summarise the text in numbers')
            [CompletionResult]::new('lorem', 'lorem', [CompletionResultType]::ParameterValue, 'Generate placeholder text')
            [CompletionResult]::new('password', 'password', [CompletionResultType]::ParameterValue, 'Generate random passwords')
            [CompletionResult]::new('random-number', 'random-number', [CompletionResultType]::ParameterValue, 'Generate random whole numbers')
            [CompletionResult]::new('random-string', 'random-string', [CompletionResultType]::ParameterValue, 'Generate random strings')
            [CompletionResult]::new('sequence', 'sequence', [CompletionResultType]::ParameterValue, 'Generate a run of numbers')
            [CompletionResult]::new('token', 'token', [CompletionResultType]::ParameterValue, 'Generate random tokens from raw bytes')
            [CompletionResult]::new('uuid', 'uuid', [CompletionResultType]::ParameterValue, 'Generate UUIDs')
            [CompletionResult]::new('from-timestamp', 'from-timestamp', [CompletionResultType]::ParameterValue, 'Turn a Unix timestamp into a readable date')
            [CompletionResult]::new('now', 'now', [CompletionResultType]::ParameterValue, 'Print the current date and time')
            [CompletionResult]::new('timestamp', 'timestamp', [CompletionResultType]::ParameterValue, 'Print the current Unix timestamp')
            [CompletionResult]::new('to-timestamp', 'to-timestamp', [CompletionResultType]::ParameterValue, 'Turn a date into a Unix timestamp')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List every operation, optionally filtered by category')
            [CompletionResult]::new('completions', 'completions', [CompletionResultType]::ParameterValue, 'Print a shell completion script')
            [CompletionResult]::new('tui', 'tui', [CompletionResultType]::ParameterValue, 'Open the interactive interface')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'txc;alternate' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;camel' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;capitalize' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;constant' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;dot' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;kebab' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;lower' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;pascal' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;random-case' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;sentence' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;snake' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;swap' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;title' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;train' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;upper' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;atbash' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;base32-decode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;base32-encode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-pad', '--no-pad', [CompletionResultType]::ParameterName, 'Omit the = padding characters')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;base58-decode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;base58-encode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;base64-decode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--url-safe', '--url-safe', [CompletionResultType]::ParameterName, 'Use the URL and filename safe alphabet')
            [CompletionResult]::new('--no-pad', '--no-pad', [CompletionResultType]::ParameterName, 'Omit the = padding characters')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;base64-encode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--url-safe', '--url-safe', [CompletionResultType]::ParameterName, 'Use the URL and filename safe alphabet')
            [CompletionResult]::new('--no-pad', '--no-pad', [CompletionResultType]::ParameterName, 'Omit the = padding characters')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;binary-decode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;binary-encode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Separator between values')
            [CompletionResult]::new('--sep', '--sep', [CompletionResultType]::ParameterName, 'Separator between values')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;caesar' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--shift', '--shift', [CompletionResultType]::ParameterName, 'Number of places to shift')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;codepoint-decode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;codepoint-encode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Separator between values')
            [CompletionResult]::new('--sep', '--sep', [CompletionResultType]::ParameterName, 'Separator between values')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;decimal-decode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;decimal-encode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Separator between values')
            [CompletionResult]::new('--sep', '--sep', [CompletionResultType]::ParameterName, 'Separator between values')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;hex-decode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;hex-encode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Separator between bytes')
            [CompletionResult]::new('--sep', '--sep', [CompletionResultType]::ParameterName, 'Separator between bytes')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Use uppercase output')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Use uppercase output')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;html-decode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;html-encode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Also escape single and double quotes')
            [CompletionResult]::new('--quotes', '--quotes', [CompletionResultType]::ParameterName, 'Also escape single and double quotes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;json-escape' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-q', '-q', [CompletionResultType]::ParameterName, 'Keep the surrounding double quotes')
            [CompletionResult]::new('--quotes', '--quotes', [CompletionResultType]::ParameterName, 'Keep the surrounding double quotes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;json-unescape' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;morse-decode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;morse-encode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;nato' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;octal-decode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;octal-encode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Separator between values')
            [CompletionResult]::new('--sep', '--sep', [CompletionResultType]::ParameterName, 'Separator between values')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;rot13' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;rot47' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;unicode-escape' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-a', '-a', [CompletionResultType]::ParameterName, 'Escape ASCII characters as well')
            [CompletionResult]::new('--all', '--all', [CompletionResultType]::ParameterName, 'Escape ASCII characters as well')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;unicode-unescape' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;url-decode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;url-encode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;blake3' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;crc32' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the checksum in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the checksum in uppercase hex')
            [CompletionResult]::new('-d', '-d', [CompletionResultType]::ParameterName, 'Print the checksum as a decimal number')
            [CompletionResult]::new('--decimal', '--decimal', [CompletionResultType]::ParameterName, 'Print the checksum as a decimal number')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;hmac-sha1' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'Secret key for the authentication code')
            [CompletionResult]::new('--key', '--key', [CompletionResultType]::ParameterName, 'Secret key for the authentication code')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;hmac-sha256' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'Secret key for the authentication code')
            [CompletionResult]::new('--key', '--key', [CompletionResultType]::ParameterName, 'Secret key for the authentication code')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;hmac-sha512' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-k', '-k', [CompletionResultType]::ParameterName, 'Secret key for the authentication code')
            [CompletionResult]::new('--key', '--key', [CompletionResultType]::ParameterName, 'Secret key for the authentication code')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;keccak256' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;md5' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;sha1' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;sha224' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;sha256' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;sha3-256' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;sha3-512' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;sha384' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;sha512' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print the digest in uppercase hex')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print the digest as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;center' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-w', '-w', [CompletionResultType]::ParameterName, 'Target width in characters')
            [CompletionResult]::new('--width', '--width', [CompletionResultType]::ParameterName, 'Target width in characters')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;chunk' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Characters per output line')
            [CompletionResult]::new('--size', '--size', [CompletionResultType]::ParameterName, 'Characters per output line')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;dedent' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;duplicates' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Compare without regard to case')
            [CompletionResult]::new('--ignore-case', '--ignore-case', [CompletionResultType]::ParameterName, 'Compare without regard to case')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;filter' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'Keep lines containing this text')
            [CompletionResult]::new('--contains', '--contains', [CompletionResultType]::ParameterName, 'Keep lines containing this text')
            [CompletionResult]::new('-r', '-r', [CompletionResultType]::ParameterName, 'Keep lines matching this regular expression')
            [CompletionResult]::new('--regex', '--regex', [CompletionResultType]::ParameterName, 'Keep lines matching this regular expression')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'Keep the lines that do not match')
            [CompletionResult]::new('--invert', '--invert', [CompletionResultType]::ParameterName, 'Keep the lines that do not match')
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Match without regard to case')
            [CompletionResult]::new('--ignore-case', '--ignore-case', [CompletionResultType]::ParameterName, 'Match without regard to case')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;head' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'How many lines to keep')
            [CompletionResult]::new('--count', '--count', [CompletionResultType]::ParameterName, 'How many lines to keep')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;indent' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'How many characters to indent by')
            [CompletionResult]::new('--count', '--count', [CompletionResultType]::ParameterName, 'How many characters to indent by')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-t', '-t', [CompletionResultType]::ParameterName, 'Indent with tabs instead of spaces')
            [CompletionResult]::new('--tabs', '--tabs', [CompletionResultType]::ParameterName, 'Indent with tabs instead of spaces')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;join' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Text placed between the joined lines')
            [CompletionResult]::new('--sep', '--sep', [CompletionResultType]::ParameterName, 'Text placed between the joined lines')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;number' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'First number to use')
            [CompletionResult]::new('--start', '--start', [CompletionResultType]::ParameterName, 'First number to use')
            [CompletionResult]::new('--sep', '--sep', [CompletionResultType]::ParameterName, 'Text between the number and the line')
            [CompletionResult]::new('-w', '-w', [CompletionResultType]::ParameterName, 'Pad numbers to this width with spaces')
            [CompletionResult]::new('--width', '--width', [CompletionResultType]::ParameterName, 'Pad numbers to this width with spaces')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-z', '-z', [CompletionResultType]::ParameterName, 'Pad numbers with zeros instead of spaces')
            [CompletionResult]::new('--zeros', '--zeros', [CompletionResultType]::ParameterName, 'Pad numbers with zeros instead of spaces')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;pad-left' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-w', '-w', [CompletionResultType]::ParameterName, 'Target width in characters')
            [CompletionResult]::new('--width', '--width', [CompletionResultType]::ParameterName, 'Target width in characters')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'Character used for padding')
            [CompletionResult]::new('--char', '--char', [CompletionResultType]::ParameterName, 'Character used for padding')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;pad-right' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-w', '-w', [CompletionResultType]::ParameterName, 'Target width in characters')
            [CompletionResult]::new('--width', '--width', [CompletionResultType]::ParameterName, 'Target width in characters')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'Character used for padding')
            [CompletionResult]::new('--char', '--char', [CompletionResultType]::ParameterName, 'Character used for padding')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;prefix' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-t', '-t', [CompletionResultType]::ParameterName, 'Text to add')
            [CompletionResult]::new('--text', '--text', [CompletionResultType]::ParameterName, 'Text to add')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;remove-empty' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;reverse-lines' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;sample' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'How many lines to pick')
            [CompletionResult]::new('--count', '--count', [CompletionResultType]::ParameterName, 'How many lines to pick')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;shuffle' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;sort' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-r', '-r', [CompletionResultType]::ParameterName, 'Sort in descending order')
            [CompletionResult]::new('--reverse', '--reverse', [CompletionResultType]::ParameterName, 'Sort in descending order')
            [CompletionResult]::new('--numeric', '--numeric', [CompletionResultType]::ParameterName, 'Compare the leading number on each line')
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Compare without regard to case')
            [CompletionResult]::new('--ignore-case', '--ignore-case', [CompletionResultType]::ParameterName, 'Compare without regard to case')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Drop duplicate lines after sorting')
            [CompletionResult]::new('--unique', '--unique', [CompletionResultType]::ParameterName, 'Drop duplicate lines after sorting')
            [CompletionResult]::new('-l', '-l', [CompletionResultType]::ParameterName, 'Sort by line length')
            [CompletionResult]::new('--length', '--length', [CompletionResultType]::ParameterName, 'Sort by line length')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;split' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Separator to split on')
            [CompletionResult]::new('--sep', '--sep', [CompletionResultType]::ParameterName, 'Separator to split on')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-r', '-r', [CompletionResultType]::ParameterName, 'Treat the separator as a regular expression')
            [CompletionResult]::new('--regex', '--regex', [CompletionResultType]::ParameterName, 'Treat the separator as a regular expression')
            [CompletionResult]::new('--keep-empty', '--keep-empty', [CompletionResultType]::ParameterName, 'Keep empty pieces')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;suffix' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-t', '-t', [CompletionResultType]::ParameterName, 'Text to add')
            [CompletionResult]::new('--text', '--text', [CompletionResultType]::ParameterName, 'Text to add')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;tail' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'How many lines to keep')
            [CompletionResult]::new('--count', '--count', [CompletionResultType]::ParameterName, 'How many lines to keep')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;trim-lines' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;unique' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Compare without regard to case')
            [CompletionResult]::new('--ignore-case', '--ignore-case', [CompletionResultType]::ParameterName, 'Compare without regard to case')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;wrap' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-w', '-w', [CompletionResultType]::ParameterName, 'Target width in characters')
            [CompletionResult]::new('--width', '--width', [CompletionResultType]::ParameterName, 'Target width in characters')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;escape-regex' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;extract' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-r', '-r', [CompletionResultType]::ParameterName, 'Regular expression to search for')
            [CompletionResult]::new('--regex', '--regex', [CompletionResultType]::ParameterName, 'Regular expression to search for')
            [CompletionResult]::new('-g', '-g', [CompletionResultType]::ParameterName, 'Capture group to print, 0 for the whole match')
            [CompletionResult]::new('--group', '--group', [CompletionResultType]::ParameterName, 'Capture group to print, 0 for the whole match')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--first', '--first', [CompletionResultType]::ParameterName, 'Print only the first match')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;fancy' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'bold, italic, bold-italic, script, fraktur, double, mono, circled, fullwidth, smallcaps or flip')
            [CompletionResult]::new('--style', '--style', [CompletionResultType]::ParameterName, 'bold, italic, bold-italic, script, fraktur, double, mono, circled, fullwidth, smallcaps or flip')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;newlines-to-spaces' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;normalize' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--form', '--form', [CompletionResultType]::ParameterName, 'Normalisation form: nfc, nfd, nfkc or nfkd')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;palindrome' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;quote' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'Quote character to wrap each line with')
            [CompletionResult]::new('--char', '--char', [CompletionResultType]::ParameterName, 'Quote character to wrap each line with')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;remove' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-t', '-t', [CompletionResultType]::ParameterName, 'Exact text to remove')
            [CompletionResult]::new('--text', '--text', [CompletionResultType]::ParameterName, 'Exact text to remove')
            [CompletionResult]::new('-r', '-r', [CompletionResultType]::ParameterName, 'Regular expression to remove')
            [CompletionResult]::new('--regex', '--regex', [CompletionResultType]::ParameterName, 'Regular expression to remove')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;remove-accents' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;remove-non-ascii' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;remove-punctuation' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;remove-whitespace' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;repeat' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'How many copies to produce')
            [CompletionResult]::new('--count', '--count', [CompletionResultType]::ParameterName, 'How many copies to produce')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Text placed between copies')
            [CompletionResult]::new('--sep', '--sep', [CompletionResultType]::ParameterName, 'Text placed between copies')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;replace' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--find', '--find', [CompletionResultType]::ParameterName, 'Text or pattern to look for')
            [CompletionResult]::new('-w', '-w', [CompletionResultType]::ParameterName, 'Replacement text')
            [CompletionResult]::new('--with', '--with', [CompletionResultType]::ParameterName, 'Replacement text')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-r', '-r', [CompletionResultType]::ParameterName, 'Treat --find as a regular expression')
            [CompletionResult]::new('--regex', '--regex', [CompletionResultType]::ParameterName, 'Treat --find as a regular expression')
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Match without regard to case')
            [CompletionResult]::new('--ignore-case', '--ignore-case', [CompletionResultType]::ParameterName, 'Match without regard to case')
            [CompletionResult]::new('--first', '--first', [CompletionResultType]::ParameterName, 'Replace only the first match')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;reverse' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;reverse-words' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;rotate' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'How many places to rotate')
            [CompletionResult]::new('--count', '--count', [CompletionResultType]::ParameterName, 'How many places to rotate')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;slugify' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;spaces-to-newlines' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;spaces-to-tabs' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-w', '-w', [CompletionResultType]::ParameterName, 'Number of spaces per tab')
            [CompletionResult]::new('--width', '--width', [CompletionResultType]::ParameterName, 'Number of spaces per tab')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;squeeze' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;strip-html' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;tabs-to-spaces' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-w', '-w', [CompletionResultType]::ParameterName, 'Number of spaces per tab')
            [CompletionResult]::new('--width', '--width', [CompletionResultType]::ParameterName, 'Number of spaces per tab')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;trim' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'Characters to strip instead of whitespace')
            [CompletionResult]::new('--chars', '--chars', [CompletionResultType]::ParameterName, 'Characters to strip instead of whitespace')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--start', '--start', [CompletionResultType]::ParameterName, 'Only trim the start')
            [CompletionResult]::new('--end', '--end', [CompletionResultType]::ParameterName, 'Only trim the end')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;truncate' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-l', '-l', [CompletionResultType]::ParameterName, 'Maximum length in characters')
            [CompletionResult]::new('--length', '--length', [CompletionResultType]::ParameterName, 'Maximum length in characters')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Text appended when the input is cut')
            [CompletionResult]::new('--suffix', '--suffix', [CompletionResultType]::ParameterName, 'Text appended when the input is cut')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;base-convert' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--from', '--from', [CompletionResultType]::ParameterName, 'Base of the input, 2 to 36')
            [CompletionResult]::new('--to', '--to', [CompletionResultType]::ParameterName, 'Base of the output, 2 to 36')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Use uppercase digits')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Use uppercase digits')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;ordinal' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;roman-decode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;roman-encode' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;spell' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;csv-to-json' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-d', '-d', [CompletionResultType]::ParameterName, 'Field separator in the input')
            [CompletionResult]::new('--delimiter', '--delimiter', [CompletionResultType]::ParameterName, 'Field separator in the input')
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Spaces of indentation, 0 for one line')
            [CompletionResult]::new('--indent', '--indent', [CompletionResultType]::ParameterName, 'Spaces of indentation, 0 for one line')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-header', '--no-header', [CompletionResultType]::ParameterName, 'Treat the first row as data, not as column names')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;csv-to-markdown' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-d', '-d', [CompletionResultType]::ParameterName, 'Field separator in the output')
            [CompletionResult]::new('--delimiter', '--delimiter', [CompletionResultType]::ParameterName, 'Field separator in the output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;json-format' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Spaces of indentation')
            [CompletionResult]::new('--indent', '--indent', [CompletionResultType]::ParameterName, 'Spaces of indentation')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;json-minify' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;json-to-csv' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-d', '-d', [CompletionResultType]::ParameterName, 'Field separator in the output')
            [CompletionResult]::new('--delimiter', '--delimiter', [CompletionResultType]::ParameterName, 'Field separator in the output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;json-to-toml' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;json-to-yaml' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;toml-to-json' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Spaces of indentation')
            [CompletionResult]::new('--indent', '--indent', [CompletionResultType]::ParameterName, 'Spaces of indentation')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;toml-to-yaml' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;yaml-to-json' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Spaces of indentation')
            [CompletionResult]::new('--indent', '--indent', [CompletionResultType]::ParameterName, 'Spaces of indentation')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;yaml-to-toml' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;charinfo' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;count-bytes' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;count-chars' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;count-lines' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;count-words' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;frequency' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'What to count: word, char or line')
            [CompletionResult]::new('--by', '--by', [CompletionResultType]::ParameterName, 'What to count: word, char or line')
            [CompletionResult]::new('-t', '-t', [CompletionResultType]::ParameterName, 'Only show the most frequent entries, 0 for all')
            [CompletionResult]::new('--top', '--top', [CompletionResultType]::ParameterName, 'Only show the most frequent entries, 0 for all')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-i', '-i', [CompletionResultType]::ParameterName, 'Count without regard to case')
            [CompletionResult]::new('--ignore-case', '--ignore-case', [CompletionResultType]::ParameterName, 'Count without regard to case')
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'Include the share of the total')
            [CompletionResult]::new('--percent', '--percent', [CompletionResultType]::ParameterName, 'Include the share of the total')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;is-palindrome' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;stats' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;lorem' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-p', '-p', [CompletionResultType]::ParameterName, 'How many paragraphs to write')
            [CompletionResult]::new('--paragraphs', '--paragraphs', [CompletionResultType]::ParameterName, 'How many paragraphs to write')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Sentences per paragraph')
            [CompletionResult]::new('--sentences', '--sentences', [CompletionResultType]::ParameterName, 'Sentences per paragraph')
            [CompletionResult]::new('-w', '-w', [CompletionResultType]::ParameterName, 'Produce this many words instead of paragraphs')
            [CompletionResult]::new('--words', '--words', [CompletionResultType]::ParameterName, 'Produce this many words instead of paragraphs')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;password' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-l', '-l', [CompletionResultType]::ParameterName, 'Characters per password')
            [CompletionResult]::new('--length', '--length', [CompletionResultType]::ParameterName, 'Characters per password')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'How many passwords to generate')
            [CompletionResult]::new('--count', '--count', [CompletionResultType]::ParameterName, 'How many passwords to generate')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-symbols', '--no-symbols', [CompletionResultType]::ParameterName, 'Leave out punctuation')
            [CompletionResult]::new('--no-digits', '--no-digits', [CompletionResultType]::ParameterName, 'Leave out digits')
            [CompletionResult]::new('--no-upper', '--no-upper', [CompletionResultType]::ParameterName, 'Leave out uppercase letters')
            [CompletionResult]::new('--no-lower', '--no-lower', [CompletionResultType]::ParameterName, 'Leave out lowercase letters')
            [CompletionResult]::new('--no-ambiguous', '--no-ambiguous', [CompletionResultType]::ParameterName, 'Leave out characters that look alike, such as l, 1, O and 0')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;random-number' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--min', '--min', [CompletionResultType]::ParameterName, 'Smallest value, inclusive')
            [CompletionResult]::new('--max', '--max', [CompletionResultType]::ParameterName, 'Largest value, inclusive')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'How many numbers to generate')
            [CompletionResult]::new('--count', '--count', [CompletionResultType]::ParameterName, 'How many numbers to generate')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;random-string' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-l', '-l', [CompletionResultType]::ParameterName, 'Characters per string')
            [CompletionResult]::new('--length', '--length', [CompletionResultType]::ParameterName, 'Characters per string')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'How many strings to generate')
            [CompletionResult]::new('--count', '--count', [CompletionResultType]::ParameterName, 'How many strings to generate')
            [CompletionResult]::new('-s', '-s', [CompletionResultType]::ParameterName, 'Characters to pick from')
            [CompletionResult]::new('--charset', '--charset', [CompletionResultType]::ParameterName, 'Characters to pick from')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;sequence' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--start', '--start', [CompletionResultType]::ParameterName, 'First value')
            [CompletionResult]::new('--end', '--end', [CompletionResultType]::ParameterName, 'Last value, inclusive')
            [CompletionResult]::new('--step', '--step', [CompletionResultType]::ParameterName, 'Amount to add each time')
            [CompletionResult]::new('-t', '-t', [CompletionResultType]::ParameterName, 'Template, with {} replaced by the number')
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'Template, with {} replaced by the number')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;token' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-b', '-b', [CompletionResultType]::ParameterName, 'How many random bytes to draw')
            [CompletionResult]::new('--bytes', '--bytes', [CompletionResultType]::ParameterName, 'How many random bytes to draw')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'How many tokens to generate')
            [CompletionResult]::new('--count', '--count', [CompletionResultType]::ParameterName, 'How many tokens to generate')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--base64', '--base64', [CompletionResultType]::ParameterName, 'Print as base64 instead of hex')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;uuid' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-v', '-v', [CompletionResultType]::ParameterName, 'UUID version: 1, 3, 4, 5, 7 or nil')
            [CompletionResult]::new('--version', '--version', [CompletionResultType]::ParameterName, 'UUID version: 1, 3, 4, 5, 7 or nil')
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'How many to generate')
            [CompletionResult]::new('--count', '--count', [CompletionResultType]::ParameterName, 'How many to generate')
            [CompletionResult]::new('--name', '--name', [CompletionResultType]::ParameterName, 'Name to hash, required by versions 3 and 5')
            [CompletionResult]::new('--namespace', '--namespace', [CompletionResultType]::ParameterName, 'Namespace for versions 3 and 5: dns, url, oid, x500 or a UUID')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Print in uppercase')
            [CompletionResult]::new('--upper', '--upper', [CompletionResultType]::ParameterName, 'Print in uppercase')
            [CompletionResult]::new('--compact', '--compact', [CompletionResultType]::ParameterName, 'Print without the dashes')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;from-timestamp' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-t', '-t', [CompletionResultType]::ParameterName, 'strftime style format')
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'strftime style format')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Render in UTC instead of the local time zone')
            [CompletionResult]::new('--utc', '--utc', [CompletionResultType]::ParameterName, 'Render in UTC instead of the local time zone')
            [CompletionResult]::new('-m', '-m', [CompletionResultType]::ParameterName, 'Read the input as milliseconds')
            [CompletionResult]::new('--millis', '--millis', [CompletionResultType]::ParameterName, 'Read the input as milliseconds')
            [CompletionResult]::new('--iso', '--iso', [CompletionResultType]::ParameterName, 'Use the RFC 3339 format')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;now' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-t', '-t', [CompletionResultType]::ParameterName, 'strftime style format')
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'strftime style format')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Use UTC instead of the local time zone')
            [CompletionResult]::new('--utc', '--utc', [CompletionResultType]::ParameterName, 'Use UTC instead of the local time zone')
            [CompletionResult]::new('--iso', '--iso', [CompletionResultType]::ParameterName, 'Use the RFC 3339 format')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;timestamp' {
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-m', '-m', [CompletionResultType]::ParameterName, 'Print milliseconds instead of seconds')
            [CompletionResult]::new('--millis', '--millis', [CompletionResultType]::ParameterName, 'Print milliseconds instead of seconds')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;to-timestamp' {
            [CompletionResult]::new('-f', '-f', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('--file', '--file', [CompletionResultType]::ParameterName, 'Read input from a file instead of arguments or standard input')
            [CompletionResult]::new('-o', '-o', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('--out', '--out', [CompletionResultType]::ParameterName, 'Write the result to a file instead of standard output')
            [CompletionResult]::new('-t', '-t', [CompletionResultType]::ParameterName, 'strftime style format of the input')
            [CompletionResult]::new('--format', '--format', [CompletionResultType]::ParameterName, 'strftime style format of the input')
            [CompletionResult]::new('--raw', '--raw', [CompletionResultType]::ParameterName, 'Keep piped input exactly as read, including its trailing newline')
            [CompletionResult]::new('--lines', '--lines', [CompletionResultType]::ParameterName, 'Apply the operation to each line separately')
            [CompletionResult]::new('--whole', '--whole', [CompletionResultType]::ParameterName, 'Apply the operation to the whole input at once')
            [CompletionResult]::new('-n', '-n', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('--no-newline', '--no-newline', [CompletionResultType]::ParameterName, 'Do not append a trailing newline to the result')
            [CompletionResult]::new('-u', '-u', [CompletionResultType]::ParameterName, 'Read the input as UTC instead of local time')
            [CompletionResult]::new('--utc', '--utc', [CompletionResultType]::ParameterName, 'Read the input as UTC instead of local time')
            [CompletionResult]::new('-m', '-m', [CompletionResultType]::ParameterName, 'Print milliseconds instead of seconds')
            [CompletionResult]::new('--millis', '--millis', [CompletionResultType]::ParameterName, 'Print milliseconds instead of seconds')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;list' {
            [CompletionResult]::new('-c', '-c', [CompletionResultType]::ParameterName, 'Show only one category')
            [CompletionResult]::new('--category', '--category', [CompletionResultType]::ParameterName, 'Show only one category')
            [CompletionResult]::new('--names', '--names', [CompletionResultType]::ParameterName, 'Print bare operation names, one per line')
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;completions' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help (see more with ''--help'')')
            break
        }
        'txc;tui' {
            [CompletionResult]::new('-h', '-h', [CompletionResultType]::ParameterName, 'Print help')
            [CompletionResult]::new('--help', '--help', [CompletionResultType]::ParameterName, 'Print help')
            break
        }
        'txc;help' {
            [CompletionResult]::new('alternate', 'alternate', [CompletionResultType]::ParameterValue, 'Convert text to aLtErNaTiNg case')
            [CompletionResult]::new('camel', 'camel', [CompletionResultType]::ParameterValue, 'Convert text to camelCase')
            [CompletionResult]::new('capitalize', 'capitalize', [CompletionResultType]::ParameterValue, 'Capitalise the first letter of every word, keeping the rest as is')
            [CompletionResult]::new('constant', 'constant', [CompletionResultType]::ParameterValue, 'Convert text to CONSTANT_CASE')
            [CompletionResult]::new('dot', 'dot', [CompletionResultType]::ParameterValue, 'Convert text to dot.case')
            [CompletionResult]::new('kebab', 'kebab', [CompletionResultType]::ParameterValue, 'Convert text to kebab-case')
            [CompletionResult]::new('lower', 'lower', [CompletionResultType]::ParameterValue, 'Convert text to lowercase')
            [CompletionResult]::new('pascal', 'pascal', [CompletionResultType]::ParameterValue, 'Convert text to PascalCase')
            [CompletionResult]::new('random-case', 'random-case', [CompletionResultType]::ParameterValue, 'Randomise the case of every letter')
            [CompletionResult]::new('sentence', 'sentence', [CompletionResultType]::ParameterValue, 'Capitalise the first letter of every sentence')
            [CompletionResult]::new('snake', 'snake', [CompletionResultType]::ParameterValue, 'Convert text to snake_case')
            [CompletionResult]::new('swap', 'swap', [CompletionResultType]::ParameterValue, 'Swap the case of every letter')
            [CompletionResult]::new('title', 'title', [CompletionResultType]::ParameterValue, 'Capitalise The First Letter Of Every Word')
            [CompletionResult]::new('train', 'train', [CompletionResultType]::ParameterValue, 'Convert text to Train-Case')
            [CompletionResult]::new('upper', 'upper', [CompletionResultType]::ParameterValue, 'Convert text to UPPERCASE')
            [CompletionResult]::new('atbash', 'atbash', [CompletionResultType]::ParameterValue, 'Apply the Atbash mirror cipher')
            [CompletionResult]::new('base32-decode', 'base32-decode', [CompletionResultType]::ParameterValue, 'Decode base32 back to text')
            [CompletionResult]::new('base32-encode', 'base32-encode', [CompletionResultType]::ParameterValue, 'Encode text as base32')
            [CompletionResult]::new('base58-decode', 'base58-decode', [CompletionResultType]::ParameterValue, 'Decode base58 back to text')
            [CompletionResult]::new('base58-encode', 'base58-encode', [CompletionResultType]::ParameterValue, 'Encode text as base58 (bitcoin alphabet)')
            [CompletionResult]::new('base64-decode', 'base64-decode', [CompletionResultType]::ParameterValue, 'Decode base64 back to text')
            [CompletionResult]::new('base64-encode', 'base64-encode', [CompletionResultType]::ParameterValue, 'Encode text as base64')
            [CompletionResult]::new('binary-decode', 'binary-decode', [CompletionResultType]::ParameterValue, 'Decode binary bytes back to text')
            [CompletionResult]::new('binary-encode', 'binary-encode', [CompletionResultType]::ParameterValue, 'Encode text as binary bytes')
            [CompletionResult]::new('caesar', 'caesar', [CompletionResultType]::ParameterValue, 'Shift letters by a fixed amount')
            [CompletionResult]::new('codepoint-decode', 'codepoint-decode', [CompletionResultType]::ParameterValue, 'Turn U+XXXX code points back into characters')
            [CompletionResult]::new('codepoint-encode', 'codepoint-encode', [CompletionResultType]::ParameterValue, 'Show the Unicode code point of every character')
            [CompletionResult]::new('decimal-decode', 'decimal-decode', [CompletionResultType]::ParameterValue, 'Decode decimal byte values back to text')
            [CompletionResult]::new('decimal-encode', 'decimal-encode', [CompletionResultType]::ParameterValue, 'Encode text as decimal byte values')
            [CompletionResult]::new('hex-decode', 'hex-decode', [CompletionResultType]::ParameterValue, 'Decode hexadecimal back to text')
            [CompletionResult]::new('hex-encode', 'hex-encode', [CompletionResultType]::ParameterValue, 'Encode text as hexadecimal')
            [CompletionResult]::new('html-decode', 'html-decode', [CompletionResultType]::ParameterValue, 'Decode HTML entities')
            [CompletionResult]::new('html-encode', 'html-encode', [CompletionResultType]::ParameterValue, 'Escape HTML special characters')
            [CompletionResult]::new('json-escape', 'json-escape', [CompletionResultType]::ParameterValue, 'Escape text for a JSON string')
            [CompletionResult]::new('json-unescape', 'json-unescape', [CompletionResultType]::ParameterValue, 'Decode a JSON string escape sequence')
            [CompletionResult]::new('morse-decode', 'morse-decode', [CompletionResultType]::ParameterValue, 'Decode Morse code back to text')
            [CompletionResult]::new('morse-encode', 'morse-encode', [CompletionResultType]::ParameterValue, 'Encode text as Morse code')
            [CompletionResult]::new('nato', 'nato', [CompletionResultType]::ParameterValue, 'Spell text out with the NATO phonetic alphabet')
            [CompletionResult]::new('octal-decode', 'octal-decode', [CompletionResultType]::ParameterValue, 'Decode octal bytes back to text')
            [CompletionResult]::new('octal-encode', 'octal-encode', [CompletionResultType]::ParameterValue, 'Encode text as octal bytes')
            [CompletionResult]::new('rot13', 'rot13', [CompletionResultType]::ParameterValue, 'Apply the ROT13 letter substitution')
            [CompletionResult]::new('rot47', 'rot47', [CompletionResultType]::ParameterValue, 'Apply the ROT47 substitution over printable ASCII')
            [CompletionResult]::new('unicode-escape', 'unicode-escape', [CompletionResultType]::ParameterValue, 'Escape characters as \uXXXX sequences')
            [CompletionResult]::new('unicode-unescape', 'unicode-unescape', [CompletionResultType]::ParameterValue, 'Decode \uXXXX and \xNN escape sequences')
            [CompletionResult]::new('url-decode', 'url-decode', [CompletionResultType]::ParameterValue, 'Decode percent-encoded URL text')
            [CompletionResult]::new('url-encode', 'url-encode', [CompletionResultType]::ParameterValue, 'Percent-encode text for URLs')
            [CompletionResult]::new('blake3', 'blake3', [CompletionResultType]::ParameterValue, 'BLAKE3 digest of the input')
            [CompletionResult]::new('crc32', 'crc32', [CompletionResultType]::ParameterValue, 'CRC32 checksum of the input')
            [CompletionResult]::new('hmac-sha1', 'hmac-sha1', [CompletionResultType]::ParameterValue, 'HMAC-SHA1 authentication code of the input')
            [CompletionResult]::new('hmac-sha256', 'hmac-sha256', [CompletionResultType]::ParameterValue, 'HMAC-SHA256 authentication code of the input')
            [CompletionResult]::new('hmac-sha512', 'hmac-sha512', [CompletionResultType]::ParameterValue, 'HMAC-SHA512 authentication code of the input')
            [CompletionResult]::new('keccak256', 'keccak256', [CompletionResultType]::ParameterValue, 'Keccak-256 digest of the input')
            [CompletionResult]::new('md5', 'md5', [CompletionResultType]::ParameterValue, 'MD5 digest of the input')
            [CompletionResult]::new('sha1', 'sha1', [CompletionResultType]::ParameterValue, 'SHA-1 digest of the input')
            [CompletionResult]::new('sha224', 'sha224', [CompletionResultType]::ParameterValue, 'SHA-224 digest of the input')
            [CompletionResult]::new('sha256', 'sha256', [CompletionResultType]::ParameterValue, 'SHA-256 digest of the input')
            [CompletionResult]::new('sha3-256', 'sha3-256', [CompletionResultType]::ParameterValue, 'SHA3-256 digest of the input')
            [CompletionResult]::new('sha3-512', 'sha3-512', [CompletionResultType]::ParameterValue, 'SHA3-512 digest of the input')
            [CompletionResult]::new('sha384', 'sha384', [CompletionResultType]::ParameterValue, 'SHA-384 digest of the input')
            [CompletionResult]::new('sha512', 'sha512', [CompletionResultType]::ParameterValue, 'SHA-512 digest of the input')
            [CompletionResult]::new('center', 'center', [CompletionResultType]::ParameterValue, 'Centre every line inside a width')
            [CompletionResult]::new('chunk', 'chunk', [CompletionResultType]::ParameterValue, 'Break text into fixed width lines')
            [CompletionResult]::new('dedent', 'dedent', [CompletionResultType]::ParameterValue, 'Remove the common leading whitespace')
            [CompletionResult]::new('duplicates', 'duplicates', [CompletionResultType]::ParameterValue, 'Keep only lines that appear more than once')
            [CompletionResult]::new('filter', 'filter', [CompletionResultType]::ParameterValue, 'Keep the lines matching a text or a regular expression')
            [CompletionResult]::new('head', 'head', [CompletionResultType]::ParameterValue, 'Keep the first lines')
            [CompletionResult]::new('indent', 'indent', [CompletionResultType]::ParameterValue, 'Indent every line')
            [CompletionResult]::new('join', 'join', [CompletionResultType]::ParameterValue, 'Join all lines into one')
            [CompletionResult]::new('number', 'number', [CompletionResultType]::ParameterValue, 'Prefix every line with its number')
            [CompletionResult]::new('pad-left', 'pad-left', [CompletionResultType]::ParameterValue, 'Pad every line on the left to a width')
            [CompletionResult]::new('pad-right', 'pad-right', [CompletionResultType]::ParameterValue, 'Pad every line on the right to a width')
            [CompletionResult]::new('prefix', 'prefix', [CompletionResultType]::ParameterValue, 'Add text to the start of every line')
            [CompletionResult]::new('remove-empty', 'remove-empty', [CompletionResultType]::ParameterValue, 'Remove blank lines')
            [CompletionResult]::new('reverse-lines', 'reverse-lines', [CompletionResultType]::ParameterValue, 'Put the lines in reverse order')
            [CompletionResult]::new('sample', 'sample', [CompletionResultType]::ParameterValue, 'Pick random lines')
            [CompletionResult]::new('shuffle', 'shuffle', [CompletionResultType]::ParameterValue, 'Put the lines in random order')
            [CompletionResult]::new('sort', 'sort', [CompletionResultType]::ParameterValue, 'Sort lines alphabetically')
            [CompletionResult]::new('split', 'split', [CompletionResultType]::ParameterValue, 'Split text into one line per piece')
            [CompletionResult]::new('suffix', 'suffix', [CompletionResultType]::ParameterValue, 'Add text to the end of every line')
            [CompletionResult]::new('tail', 'tail', [CompletionResultType]::ParameterValue, 'Keep the last lines')
            [CompletionResult]::new('trim-lines', 'trim-lines', [CompletionResultType]::ParameterValue, 'Remove leading and trailing spaces from every line')
            [CompletionResult]::new('unique', 'unique', [CompletionResultType]::ParameterValue, 'Remove duplicate lines, keeping the first of each')
            [CompletionResult]::new('wrap', 'wrap', [CompletionResultType]::ParameterValue, 'Wrap text to a maximum line width')
            [CompletionResult]::new('escape-regex', 'escape-regex', [CompletionResultType]::ParameterValue, 'Escape the characters that are special in a regular expression')
            [CompletionResult]::new('extract', 'extract', [CompletionResultType]::ParameterValue, 'Print the parts of the text matching a pattern')
            [CompletionResult]::new('fancy', 'fancy', [CompletionResultType]::ParameterValue, 'Restyle text with Unicode letterforms')
            [CompletionResult]::new('newlines-to-spaces', 'newlines-to-spaces', [CompletionResultType]::ParameterValue, 'Put all the text on one line')
            [CompletionResult]::new('normalize', 'normalize', [CompletionResultType]::ParameterValue, 'Apply a Unicode normalisation form')
            [CompletionResult]::new('palindrome', 'palindrome', [CompletionResultType]::ParameterValue, 'Make a palindrome by mirroring the text')
            [CompletionResult]::new('quote', 'quote', [CompletionResultType]::ParameterValue, 'Wrap every line in quotes')
            [CompletionResult]::new('remove', 'remove', [CompletionResultType]::ParameterValue, 'Remove text or a pattern')
            [CompletionResult]::new('remove-accents', 'remove-accents', [CompletionResultType]::ParameterValue, 'Replace accented letters with their plain form')
            [CompletionResult]::new('remove-non-ascii', 'remove-non-ascii', [CompletionResultType]::ParameterValue, 'Drop every non ASCII character')
            [CompletionResult]::new('remove-punctuation', 'remove-punctuation', [CompletionResultType]::ParameterValue, 'Remove punctuation characters')
            [CompletionResult]::new('remove-whitespace', 'remove-whitespace', [CompletionResultType]::ParameterValue, 'Remove every whitespace character')
            [CompletionResult]::new('repeat', 'repeat', [CompletionResultType]::ParameterValue, 'Repeat the text a number of times')
            [CompletionResult]::new('replace', 'replace', [CompletionResultType]::ParameterValue, 'Replace text or a pattern')
            [CompletionResult]::new('reverse', 'reverse', [CompletionResultType]::ParameterValue, 'Reverse the characters of the text')
            [CompletionResult]::new('reverse-words', 'reverse-words', [CompletionResultType]::ParameterValue, 'Reverse the order of the words')
            [CompletionResult]::new('rotate', 'rotate', [CompletionResultType]::ParameterValue, 'Rotate the characters of the text')
            [CompletionResult]::new('slugify', 'slugify', [CompletionResultType]::ParameterValue, 'Turn text into a lowercase URL slug')
            [CompletionResult]::new('spaces-to-newlines', 'spaces-to-newlines', [CompletionResultType]::ParameterValue, 'Put every word on its own line')
            [CompletionResult]::new('spaces-to-tabs', 'spaces-to-tabs', [CompletionResultType]::ParameterValue, 'Replace runs of spaces with tabs')
            [CompletionResult]::new('squeeze', 'squeeze', [CompletionResultType]::ParameterValue, 'Collapse runs of whitespace into single spaces')
            [CompletionResult]::new('strip-html', 'strip-html', [CompletionResultType]::ParameterValue, 'Remove HTML tags and decode entities')
            [CompletionResult]::new('tabs-to-spaces', 'tabs-to-spaces', [CompletionResultType]::ParameterValue, 'Replace tabs with spaces')
            [CompletionResult]::new('trim', 'trim', [CompletionResultType]::ParameterValue, 'Remove whitespace from both ends')
            [CompletionResult]::new('truncate', 'truncate', [CompletionResultType]::ParameterValue, 'Shorten text to a maximum length')
            [CompletionResult]::new('base-convert', 'base-convert', [CompletionResultType]::ParameterValue, 'Convert a number between bases')
            [CompletionResult]::new('ordinal', 'ordinal', [CompletionResultType]::ParameterValue, 'Turn a number into 1st, 2nd, 3rd and so on')
            [CompletionResult]::new('roman-decode', 'roman-decode', [CompletionResultType]::ParameterValue, 'Read a roman numeral as a number')
            [CompletionResult]::new('roman-encode', 'roman-encode', [CompletionResultType]::ParameterValue, 'Write a number in roman numerals')
            [CompletionResult]::new('spell', 'spell', [CompletionResultType]::ParameterValue, 'Spell a number out in English words')
            [CompletionResult]::new('csv-to-json', 'csv-to-json', [CompletionResultType]::ParameterValue, 'Convert CSV rows to JSON')
            [CompletionResult]::new('csv-to-markdown', 'csv-to-markdown', [CompletionResultType]::ParameterValue, 'Render CSV as a Markdown table')
            [CompletionResult]::new('json-format', 'json-format', [CompletionResultType]::ParameterValue, 'Pretty print JSON')
            [CompletionResult]::new('json-minify', 'json-minify', [CompletionResultType]::ParameterValue, 'Remove all whitespace from JSON')
            [CompletionResult]::new('json-to-csv', 'json-to-csv', [CompletionResultType]::ParameterValue, 'Convert an array of JSON objects to CSV')
            [CompletionResult]::new('json-to-toml', 'json-to-toml', [CompletionResultType]::ParameterValue, 'Convert JSON to TOML')
            [CompletionResult]::new('json-to-yaml', 'json-to-yaml', [CompletionResultType]::ParameterValue, 'Convert JSON to YAML')
            [CompletionResult]::new('toml-to-json', 'toml-to-json', [CompletionResultType]::ParameterValue, 'Convert TOML to JSON')
            [CompletionResult]::new('toml-to-yaml', 'toml-to-yaml', [CompletionResultType]::ParameterValue, 'Convert TOML to YAML')
            [CompletionResult]::new('yaml-to-json', 'yaml-to-json', [CompletionResultType]::ParameterValue, 'Convert YAML to JSON')
            [CompletionResult]::new('yaml-to-toml', 'yaml-to-toml', [CompletionResultType]::ParameterValue, 'Convert YAML to TOML')
            [CompletionResult]::new('charinfo', 'charinfo', [CompletionResultType]::ParameterValue, 'Describe every character: code point, bytes and category')
            [CompletionResult]::new('count-bytes', 'count-bytes', [CompletionResultType]::ParameterValue, 'Count bytes')
            [CompletionResult]::new('count-chars', 'count-chars', [CompletionResultType]::ParameterValue, 'Count characters')
            [CompletionResult]::new('count-lines', 'count-lines', [CompletionResultType]::ParameterValue, 'Count lines')
            [CompletionResult]::new('count-words', 'count-words', [CompletionResultType]::ParameterValue, 'Count words')
            [CompletionResult]::new('frequency', 'frequency', [CompletionResultType]::ParameterValue, 'Count how often each word, character or line appears')
            [CompletionResult]::new('is-palindrome', 'is-palindrome', [CompletionResultType]::ParameterValue, 'Report whether the text reads the same backwards')
            [CompletionResult]::new('stats', 'stats', [CompletionResultType]::ParameterValue, 'Summarise the text in numbers')
            [CompletionResult]::new('lorem', 'lorem', [CompletionResultType]::ParameterValue, 'Generate placeholder text')
            [CompletionResult]::new('password', 'password', [CompletionResultType]::ParameterValue, 'Generate random passwords')
            [CompletionResult]::new('random-number', 'random-number', [CompletionResultType]::ParameterValue, 'Generate random whole numbers')
            [CompletionResult]::new('random-string', 'random-string', [CompletionResultType]::ParameterValue, 'Generate random strings')
            [CompletionResult]::new('sequence', 'sequence', [CompletionResultType]::ParameterValue, 'Generate a run of numbers')
            [CompletionResult]::new('token', 'token', [CompletionResultType]::ParameterValue, 'Generate random tokens from raw bytes')
            [CompletionResult]::new('uuid', 'uuid', [CompletionResultType]::ParameterValue, 'Generate UUIDs')
            [CompletionResult]::new('from-timestamp', 'from-timestamp', [CompletionResultType]::ParameterValue, 'Turn a Unix timestamp into a readable date')
            [CompletionResult]::new('now', 'now', [CompletionResultType]::ParameterValue, 'Print the current date and time')
            [CompletionResult]::new('timestamp', 'timestamp', [CompletionResultType]::ParameterValue, 'Print the current Unix timestamp')
            [CompletionResult]::new('to-timestamp', 'to-timestamp', [CompletionResultType]::ParameterValue, 'Turn a date into a Unix timestamp')
            [CompletionResult]::new('list', 'list', [CompletionResultType]::ParameterValue, 'List every operation, optionally filtered by category')
            [CompletionResult]::new('completions', 'completions', [CompletionResultType]::ParameterValue, 'Print a shell completion script')
            [CompletionResult]::new('tui', 'tui', [CompletionResultType]::ParameterValue, 'Open the interactive interface')
            [CompletionResult]::new('help', 'help', [CompletionResultType]::ParameterValue, 'Print this message or the help of the given subcommand(s)')
            break
        }
        'txc;help;alternate' {
            break
        }
        'txc;help;camel' {
            break
        }
        'txc;help;capitalize' {
            break
        }
        'txc;help;constant' {
            break
        }
        'txc;help;dot' {
            break
        }
        'txc;help;kebab' {
            break
        }
        'txc;help;lower' {
            break
        }
        'txc;help;pascal' {
            break
        }
        'txc;help;random-case' {
            break
        }
        'txc;help;sentence' {
            break
        }
        'txc;help;snake' {
            break
        }
        'txc;help;swap' {
            break
        }
        'txc;help;title' {
            break
        }
        'txc;help;train' {
            break
        }
        'txc;help;upper' {
            break
        }
        'txc;help;atbash' {
            break
        }
        'txc;help;base32-decode' {
            break
        }
        'txc;help;base32-encode' {
            break
        }
        'txc;help;base58-decode' {
            break
        }
        'txc;help;base58-encode' {
            break
        }
        'txc;help;base64-decode' {
            break
        }
        'txc;help;base64-encode' {
            break
        }
        'txc;help;binary-decode' {
            break
        }
        'txc;help;binary-encode' {
            break
        }
        'txc;help;caesar' {
            break
        }
        'txc;help;codepoint-decode' {
            break
        }
        'txc;help;codepoint-encode' {
            break
        }
        'txc;help;decimal-decode' {
            break
        }
        'txc;help;decimal-encode' {
            break
        }
        'txc;help;hex-decode' {
            break
        }
        'txc;help;hex-encode' {
            break
        }
        'txc;help;html-decode' {
            break
        }
        'txc;help;html-encode' {
            break
        }
        'txc;help;json-escape' {
            break
        }
        'txc;help;json-unescape' {
            break
        }
        'txc;help;morse-decode' {
            break
        }
        'txc;help;morse-encode' {
            break
        }
        'txc;help;nato' {
            break
        }
        'txc;help;octal-decode' {
            break
        }
        'txc;help;octal-encode' {
            break
        }
        'txc;help;rot13' {
            break
        }
        'txc;help;rot47' {
            break
        }
        'txc;help;unicode-escape' {
            break
        }
        'txc;help;unicode-unescape' {
            break
        }
        'txc;help;url-decode' {
            break
        }
        'txc;help;url-encode' {
            break
        }
        'txc;help;blake3' {
            break
        }
        'txc;help;crc32' {
            break
        }
        'txc;help;hmac-sha1' {
            break
        }
        'txc;help;hmac-sha256' {
            break
        }
        'txc;help;hmac-sha512' {
            break
        }
        'txc;help;keccak256' {
            break
        }
        'txc;help;md5' {
            break
        }
        'txc;help;sha1' {
            break
        }
        'txc;help;sha224' {
            break
        }
        'txc;help;sha256' {
            break
        }
        'txc;help;sha3-256' {
            break
        }
        'txc;help;sha3-512' {
            break
        }
        'txc;help;sha384' {
            break
        }
        'txc;help;sha512' {
            break
        }
        'txc;help;center' {
            break
        }
        'txc;help;chunk' {
            break
        }
        'txc;help;dedent' {
            break
        }
        'txc;help;duplicates' {
            break
        }
        'txc;help;filter' {
            break
        }
        'txc;help;head' {
            break
        }
        'txc;help;indent' {
            break
        }
        'txc;help;join' {
            break
        }
        'txc;help;number' {
            break
        }
        'txc;help;pad-left' {
            break
        }
        'txc;help;pad-right' {
            break
        }
        'txc;help;prefix' {
            break
        }
        'txc;help;remove-empty' {
            break
        }
        'txc;help;reverse-lines' {
            break
        }
        'txc;help;sample' {
            break
        }
        'txc;help;shuffle' {
            break
        }
        'txc;help;sort' {
            break
        }
        'txc;help;split' {
            break
        }
        'txc;help;suffix' {
            break
        }
        'txc;help;tail' {
            break
        }
        'txc;help;trim-lines' {
            break
        }
        'txc;help;unique' {
            break
        }
        'txc;help;wrap' {
            break
        }
        'txc;help;escape-regex' {
            break
        }
        'txc;help;extract' {
            break
        }
        'txc;help;fancy' {
            break
        }
        'txc;help;newlines-to-spaces' {
            break
        }
        'txc;help;normalize' {
            break
        }
        'txc;help;palindrome' {
            break
        }
        'txc;help;quote' {
            break
        }
        'txc;help;remove' {
            break
        }
        'txc;help;remove-accents' {
            break
        }
        'txc;help;remove-non-ascii' {
            break
        }
        'txc;help;remove-punctuation' {
            break
        }
        'txc;help;remove-whitespace' {
            break
        }
        'txc;help;repeat' {
            break
        }
        'txc;help;replace' {
            break
        }
        'txc;help;reverse' {
            break
        }
        'txc;help;reverse-words' {
            break
        }
        'txc;help;rotate' {
            break
        }
        'txc;help;slugify' {
            break
        }
        'txc;help;spaces-to-newlines' {
            break
        }
        'txc;help;spaces-to-tabs' {
            break
        }
        'txc;help;squeeze' {
            break
        }
        'txc;help;strip-html' {
            break
        }
        'txc;help;tabs-to-spaces' {
            break
        }
        'txc;help;trim' {
            break
        }
        'txc;help;truncate' {
            break
        }
        'txc;help;base-convert' {
            break
        }
        'txc;help;ordinal' {
            break
        }
        'txc;help;roman-decode' {
            break
        }
        'txc;help;roman-encode' {
            break
        }
        'txc;help;spell' {
            break
        }
        'txc;help;csv-to-json' {
            break
        }
        'txc;help;csv-to-markdown' {
            break
        }
        'txc;help;json-format' {
            break
        }
        'txc;help;json-minify' {
            break
        }
        'txc;help;json-to-csv' {
            break
        }
        'txc;help;json-to-toml' {
            break
        }
        'txc;help;json-to-yaml' {
            break
        }
        'txc;help;toml-to-json' {
            break
        }
        'txc;help;toml-to-yaml' {
            break
        }
        'txc;help;yaml-to-json' {
            break
        }
        'txc;help;yaml-to-toml' {
            break
        }
        'txc;help;charinfo' {
            break
        }
        'txc;help;count-bytes' {
            break
        }
        'txc;help;count-chars' {
            break
        }
        'txc;help;count-lines' {
            break
        }
        'txc;help;count-words' {
            break
        }
        'txc;help;frequency' {
            break
        }
        'txc;help;is-palindrome' {
            break
        }
        'txc;help;stats' {
            break
        }
        'txc;help;lorem' {
            break
        }
        'txc;help;password' {
            break
        }
        'txc;help;random-number' {
            break
        }
        'txc;help;random-string' {
            break
        }
        'txc;help;sequence' {
            break
        }
        'txc;help;token' {
            break
        }
        'txc;help;uuid' {
            break
        }
        'txc;help;from-timestamp' {
            break
        }
        'txc;help;now' {
            break
        }
        'txc;help;timestamp' {
            break
        }
        'txc;help;to-timestamp' {
            break
        }
        'txc;help;list' {
            break
        }
        'txc;help;completions' {
            break
        }
        'txc;help;tui' {
            break
        }
        'txc;help;help' {
            break
        }
    })

    $completions.Where{ $_.CompletionText -like "$wordToComplete*" } |
        Sort-Object -Property ListItemText
}
