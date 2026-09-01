//! Number bases, roman numerals and number spelling.
//!
//! ```
//! use txc::{Params, find};
//!
//! let op = find("roman-encode").expect("roman-encode is registered");
//! assert_eq!(op.apply("2024", &Params::for_op(op), None)?, "MMXXIV");
//!
//! let op = find("spell").expect("spell is registered");
//! assert_eq!(op.apply("42", &Params::for_op(op), None)?, "forty-two");
//!
//! let op = find("base-convert").expect("base-convert is registered");
//! let mut params = Params::for_op(op);
//! params.set("from", "10");
//! params.set("to", "16");
//! assert_eq!(op.apply("255", &params, None)?, "ff");
//! # Ok::<(), anyhow::Error>(())
//! ```

use anyhow::bail;

use crate::registry::{Category, Feed, Op, Param};

const CAT: Category = Category::Number;

static P_BASE: &[Param] = &[
    Param::valued("from", None, "N", "10", "Base of the input, 2 to 36"),
    Param::valued("to", None, "N", "16", "Base of the output, 2 to 36"),
    Param::flag("upper", Some('u'), "Use uppercase digits"),
];

pub(crate) fn register(out: &mut Vec<Op>) {
    out.push(
        Op::new(
            "base-convert",
            CAT,
            Feed::Lines,
            "Convert a number between bases",
            |s, p| {
                let from: u32 = p.parse("from")?;
                let to: u32 = p.parse("to")?;
                for (name, base) in [("from", from), ("to", to)] {
                    if !(2..=36).contains(&base) {
                        bail!("--{name} must be between 2 and 36");
                    }
                }

                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Ok(String::new());
                }
                let (negative, digits) = match trimmed.strip_prefix('-') {
                    Some(rest) => (true, rest),
                    None => (false, trimmed),
                };
                let digits = strip_base_prefix(digits, from);
                let value = i128::from_str_radix(digits, from)
                    .map_err(|_| anyhow::anyhow!("{trimmed:?} is not a base {from} number"))?;

                let rendered = to_radix(value.unsigned_abs(), to, p.flag("upper"));
                Ok(if negative {
                    format!("-{rendered}")
                } else {
                    rendered
                })
            },
        )
        .aliases(&["radix"])
        .params(P_BASE)
        .examples(&[
            "txc base-convert --from 10 --to 2 42",
            "txc base-convert --from 16 --to 10 ff",
        ]),
    );

    out.push(
        Op::new(
            "roman-encode",
            CAT,
            Feed::Lines,
            "Write a number in roman numerals",
            |s, _| {
                const TABLE: [(u32, &str); 13] = [
                    (1000, "M"),
                    (900, "CM"),
                    (500, "D"),
                    (400, "CD"),
                    (100, "C"),
                    (90, "XC"),
                    (50, "L"),
                    (40, "XL"),
                    (10, "X"),
                    (9, "IX"),
                    (5, "V"),
                    (4, "IV"),
                    (1, "I"),
                ];

                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Ok(String::new());
                }
                let value: u32 = trimmed
                    .parse()
                    .map_err(|_| anyhow::anyhow!("{trimmed:?} is not a whole number"))?;
                if !(1..=3999).contains(&value) {
                    bail!("roman numerals cover 1 to 3999, got {value}");
                }

                let mut left = value;
                let mut roman = String::new();
                for (amount, symbol) in TABLE {
                    while left >= amount {
                        roman.push_str(symbol);
                        left -= amount;
                    }
                }
                Ok(roman)
            },
        )
        .aliases(&["roman"])
        .examples(&["txc roman-encode 2024"]),
    );

    out.push(
        Op::new(
            "roman-decode",
            CAT,
            Feed::Lines,
            "Read a roman numeral as a number",
            |s, _| {
                let trimmed = s.trim().to_uppercase();
                if trimmed.is_empty() {
                    return Ok(String::new());
                }
                let mut total = 0u32;
                let mut previous = 0u32;
                for ch in trimmed.chars().rev() {
                    let value = match ch {
                        'I' => 1,
                        'V' => 5,
                        'X' => 10,
                        'L' => 50,
                        'C' => 100,
                        'D' => 500,
                        'M' => 1000,
                        other => bail!("{other:?} is not a roman numeral"),
                    };
                    if value < previous {
                        total -= value;
                    } else {
                        total += value;
                        previous = value;
                    }
                }
                Ok(total.to_string())
            },
        )
        .sample("MMXXIV")
        .aliases(&["unroman"])
        .examples(&["txc roman-decode MMXXIV"]),
    );

    out.push(
        Op::new(
            "spell",
            CAT,
            Feed::Lines,
            "Spell a number out in English words",
            |s, _| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Ok(String::new());
                }
                let value: i64 = trimmed
                    .parse()
                    .map_err(|_| anyhow::anyhow!("{trimmed:?} is not a whole number"))?;
                Ok(spell_number(value))
            },
        )
        .aliases(&["number-to-words", "spell-number"])
        .examples(&["txc spell 1234"]),
    );

    out.push(
        Op::new(
            "ordinal",
            CAT,
            Feed::Lines,
            "Turn a number into 1st, 2nd, 3rd and so on",
            |s, _| {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Ok(String::new());
                }
                let value: i64 = trimmed
                    .parse()
                    .map_err(|_| anyhow::anyhow!("{trimmed:?} is not a whole number"))?;
                let suffix = match (value.abs() % 100, value.abs() % 10) {
                    (11..=13, _) => "th",
                    (_, 1) => "st",
                    (_, 2) => "nd",
                    (_, 3) => "rd",
                    _ => "th",
                };
                Ok(format!("{value}{suffix}"))
            },
        )
        .examples(&["txc ordinal 22"]),
    );
}

/// Removes a `0x`, `0b` or `0o` prefix when it matches the stated base.
fn strip_base_prefix(digits: &str, base: u32) -> &str {
    let prefix = match base {
        16 => "0x",
        8 => "0o",
        2 => "0b",
        _ => return digits,
    };
    digits
        .strip_prefix(prefix)
        .or_else(|| digits.strip_prefix(&prefix.to_uppercase()))
        .unwrap_or(digits)
}

fn to_radix(mut value: u128, base: u32, upper: bool) -> String {
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if value == 0 {
        return "0".to_string();
    }
    let base = u128::from(base);
    let mut out = Vec::new();
    while value > 0 {
        let digit = DIGITS[(value % base) as usize] as char;
        out.push(if upper {
            digit.to_ascii_uppercase()
        } else {
            digit
        });
        value /= base;
    }
    out.iter().rev().collect()
}

const ONES: [&str; 20] = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    "eighteen",
    "nineteen",
];
const TENS: [&str; 10] = [
    "", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety",
];
const SCALES: [&str; 7] = [
    "",
    " thousand",
    " million",
    " billion",
    " trillion",
    " quadrillion",
    " quintillion",
];

fn spell_number(value: i64) -> String {
    // unsigned_abs rather than negation, so i64::MIN spells out too.
    if value < 0 {
        return format!("minus {}", spell_magnitude(value.unsigned_abs()));
    }
    spell_magnitude(value.unsigned_abs())
}

fn spell_magnitude(value: u64) -> String {
    if value < 20 {
        return ONES[value as usize].to_string();
    }

    // Break the number into groups of three digits, spelling each in turn.
    let mut groups = Vec::new();
    let mut left = value;
    while left > 0 {
        groups.push((left % 1000) as u16);
        left /= 1000;
    }

    let mut parts = Vec::new();
    for (index, group) in groups.iter().enumerate().rev() {
        if *group == 0 {
            continue;
        }
        parts.push(format!("{}{}", spell_group(*group), SCALES[index]));
    }
    parts.join(" ")
}

fn spell_group(group: u16) -> String {
    let mut parts = Vec::new();
    let hundreds = group / 100;
    let rest = group % 100;

    if hundreds > 0 {
        parts.push(format!("{} hundred", ONES[hundreds as usize]));
    }
    if rest > 0 {
        parts.push(if rest < 20 {
            ONES[rest as usize].to_string()
        } else if rest.is_multiple_of(10) {
            TENS[(rest / 10) as usize].to_string()
        } else {
            format!(
                "{}-{}",
                TENS[(rest / 10) as usize],
                ONES[(rest % 10) as usize]
            )
        });
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use crate::params::Params;
    use crate::registry::find;

    fn run_with(name: &str, input: &str, options: &str) -> String {
        let op = find(name).expect("operation is registered");
        let params = Params::parse_kv(op, options).expect("options parse");
        op.apply(input, &params, None).expect("runs")
    }

    fn run(name: &str, input: &str) -> String {
        run_with(name, input, "")
    }

    #[test]
    fn converts_between_bases() {
        assert_eq!(run_with("base-convert", "42", "from=10 to=2"), "101010");
        assert_eq!(run_with("base-convert", "ff", "from=16 to=10"), "255");
        assert_eq!(run_with("base-convert", "0xff", "from=16 to=10"), "255");
        assert_eq!(run_with("base-convert", "255", "from=10 to=16 upper"), "FF");
        assert_eq!(run_with("base-convert", "-10", "from=10 to=2"), "-1010");
        assert_eq!(run_with("base-convert", "0", "from=10 to=2"), "0");
    }

    #[test]
    fn rejects_impossible_bases_and_digits() {
        let op = find("base-convert").unwrap();
        let params = Params::parse_kv(op, "from=1 to=10").unwrap();
        assert!(op.apply("10", &params, None).is_err());

        let params = Params::parse_kv(op, "from=2 to=10").unwrap();
        assert!(op.apply("9", &params, None).is_err());
    }

    #[test]
    fn roman_numerals_round_trip() {
        assert_eq!(run("roman-encode", "2024"), "MMXXIV");
        assert_eq!(run("roman-decode", "MMXXIV"), "2024");
        assert_eq!(run("roman-encode", "4"), "IV");
        assert_eq!(run("roman-decode", "MCMXCIX"), "1999");
        for n in [1u32, 9, 40, 90, 400, 900, 1987, 3999] {
            let roman = run("roman-encode", &n.to_string());
            assert_eq!(run("roman-decode", &roman), n.to_string(), "{n} -> {roman}");
        }
    }

    #[test]
    fn roman_range_is_enforced() {
        let op = find("roman-encode").unwrap();
        assert!(op.apply("0", &Params::for_op(op), None).is_err());
        assert!(op.apply("4000", &Params::for_op(op), None).is_err());
    }

    #[test]
    fn spells_numbers() {
        assert_eq!(run("spell", "0"), "zero");
        assert_eq!(run("spell", "7"), "seven");
        assert_eq!(run("spell", "21"), "twenty-one");
        assert_eq!(run("spell", "100"), "one hundred");
        assert_eq!(run("spell", "1234"), "one thousand two hundred thirty-four");
        assert_eq!(run("spell", "1000000"), "one million");
        assert_eq!(run("spell", "-5"), "minus five");
        assert_eq!(run("spell", "1000000000"), "one billion");
    }

    #[test]
    fn writes_ordinals() {
        assert_eq!(run("ordinal", "1"), "1st");
        assert_eq!(run("ordinal", "2"), "2nd");
        assert_eq!(run("ordinal", "3"), "3rd");
        assert_eq!(run("ordinal", "4"), "4th");
        assert_eq!(run("ordinal", "11"), "11th");
        assert_eq!(run("ordinal", "22"), "22nd");
        assert_eq!(run("ordinal", "101"), "101st");
    }

    #[test]
    fn works_line_by_line() {
        assert_eq!(run("ordinal", "1\n2"), "1st\n2nd");
    }
}
