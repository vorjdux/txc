//! Checks that the behaviour the README promises is the behaviour that ships.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_txc");

fn run(args: &[&str]) -> String {
    let output = Command::new(BIN).args(args).output().expect("txc runs");
    assert!(
        output.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_string()
}

#[test]
fn the_headline_examples_produce_the_documented_output() {
    assert_eq!(
        run(&["url-encode", "This string will be URL encoded"]),
        "This%20string%20will%20be%20URL%20encoded"
    );
    assert_eq!(
        run(&["base64-encode", "--url-safe", "--no-pad", "a?b"]),
        "YT9i"
    );
    assert_eq!(run(&["hex-encode", "--sep", " ", "--upper", "hi"]), "68 69");
    assert_eq!(run(&["morse-encode", "SOS"]), "... --- ...");
    assert_eq!(run(&["rot13", "hello"]), "uryyb");
    assert_eq!(run(&["squeeze", "too    many   spaces"]), "too many spaces");
    assert_eq!(run(&["slugify", "Hello, World! 2024"]), "hello-world-2024");
    assert_eq!(run(&["strip-html", "<p>Hi &amp; bye</p>"]), "Hi & bye");
    assert_eq!(
        run(&["remove-accents", "cr\u{e8}me br\u{fb}l\u{e9}e"]),
        "creme brulee"
    );
}

#[test]
fn several_arguments_are_joined_with_a_space() {
    assert_eq!(run(&["upper", "hello", "world"]), "HELLO WORLD");
}

#[test]
fn the_documented_hash_values_are_right() {
    assert_eq!(
        run(&["sha256", "hello"]),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[test]
fn the_readme_reports_the_real_number_of_operations() {
    let readme = include_str!("../README.md");
    let count = run(&["list", "--names"]).lines().count();
    let categories = run(&["list"])
        .lines()
        .filter(|line| line.contains(" — "))
        .count();
    assert!(
        readme.contains(&format!("{count} operations")),
        "the README does not mention {count} operations",
    );
    assert!(
        readme.contains(&format!("{categories} categories")),
        "the README does not mention {categories} categories",
    );
}

#[test]
fn every_operation_named_in_the_readme_exists() {
    let readme = include_str!("../README.md");
    let known: Vec<String> = run(&["list", "--names"])
        .lines()
        .map(str::to_string)
        .collect();

    // Only the catalogue section names operations; the tables before it list
    // keys and shared options.
    let catalogue = readme
        .split_once("## Operations")
        .expect("the README has a catalogue")
        .1
        .split_once("## Using it as a library")
        .expect("the catalogue ends")
        .0;

    // Each row of the catalogue starts with `| \`name\` |`.
    for line in catalogue.lines().filter(|l| l.starts_with("| `")) {
        let name = line
            .trim_start_matches("| `")
            .split('`')
            .next()
            .unwrap_or_default();
        assert!(
            known.iter().any(|op| op == name),
            "the README documents {name:?}, which is not a registered operation",
        );
    }
}

#[test]
fn the_library_example_compiles_and_runs() {
    use txc::{find, Params};

    let op = find("slugify").expect("slugify is registered");
    let text = op
        .apply("Hello, World!", &Params::for_op(op), None)
        .expect("slugify runs");
    assert_eq!(text, "hello-world");
}
