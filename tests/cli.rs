//! End to end tests that run the built `txc` binary.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_txc");

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("txc runs")
}

fn pipe(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("txc starts");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(input.as_bytes())
        .expect("input is written");
    child.wait_with_output().expect("txc finishes")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout)
        .trim_end_matches('\n')
        .to_string()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn an_argument_and_a_pipe_give_the_same_answer() {
    for (args, input) in [
        (vec!["url-encode"], "a b&c"),
        (vec!["base64-encode"], "hello world"),
        (vec!["sha256"], "hello"),
        (vec!["snake"], "userFirstName"),
        (vec!["count-chars"], "hello"),
    ] {
        let mut with_argument = args.clone();
        with_argument.push(input);
        assert_eq!(
            stdout_of(&run(&with_argument)),
            stdout_of(&pipe(&args, &format!("{input}\n"))),
            "{args:?} disagreed between an argument and a pipe",
        );
    }
}

#[test]
fn raw_keeps_the_newline_a_shell_adds() {
    assert_eq!(stdout_of(&pipe(&["base64-encode"], "hello\n")), "aGVsbG8=");
    assert_eq!(
        stdout_of(&pipe(&["base64-encode", "--raw"], "hello\n")),
        "aGVsbG8K"
    );
}

#[test]
fn options_belong_after_the_operation() {
    // Options are declared per operation, in the style of git and cargo, so a
    // flag placed before the operation is a usage error rather than a silent
    // no-op.
    let misplaced = run(&["--raw", "base64-encode", "hello"]);
    assert_eq!(misplaced.status.code(), Some(2));
    assert!(stderr_of(&misplaced).contains("unexpected argument"));
}

#[test]
fn options_are_accepted_on_either_side_of_the_text() {
    // Writing the text first is the natural way to reach for an option after
    // seeing the result, so both orders have to work.
    assert_eq!(
        stdout_of(&run(&["from-timestamp", "1700000000", "--utc"])),
        "2023-11-14 22:13:20"
    );
    assert_eq!(
        stdout_of(&run(&["from-timestamp", "--utc", "1700000000"])),
        "2023-11-14 22:13:20"
    );
    assert_eq!(
        stdout_of(&run(&["hex-encode", "hi", "--upper", "--sep", " "])),
        "68 69"
    );
    assert_eq!(
        stdout_of(&run(&[
            "replace",
            "the fox ran",
            "--find",
            "fox",
            "--with",
            "cat"
        ])),
        "the cat ran"
    );
}

#[test]
fn a_double_dash_protects_text_that_starts_with_a_dash() {
    assert_eq!(stdout_of(&run(&["upper", "--", "-x-"])), "-X-");
}

#[test]
fn operations_can_be_chained_through_pipes() {
    let first = pipe(&["snake"], "Hello World\n");
    let second = pipe(&["upper"], &String::from_utf8_lossy(&first.stdout));
    assert_eq!(stdout_of(&second), "HELLO_WORLD");
}

#[test]
fn aliases_reach_the_same_operation() {
    for (name, alias) in [
        ("url-encode", "ue"),
        ("base64-encode", "b64"),
        ("html-decode", "hd"),
        ("unique", "dedupe"),
    ] {
        assert_eq!(
            stdout_of(&run(&[name, "a b"])),
            stdout_of(&run(&[alias, "a b"])),
            "{name} and {alias} disagreed",
        );
    }
}

#[test]
fn reads_a_file_and_writes_a_file() {
    let directory = std::env::temp_dir().join("txc-cli-test");
    std::fs::create_dir_all(&directory).expect("temp directory");
    let input = directory.join("in.txt");
    let output = directory.join("out.txt");
    std::fs::write(&input, "b\na\nc\n").expect("write input");

    let result = run(&[
        "sort",
        "--file",
        input.to_str().unwrap(),
        "--out",
        output.to_str().unwrap(),
    ]);
    assert!(result.status.success(), "{}", stderr_of(&result));
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "a\nb\nc\n");

    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn line_and_whole_modes_can_be_forced() {
    // reverse works per line by default.
    assert_eq!(stdout_of(&pipe(&["reverse"], "ab\ncd")), "ba\ndc");
    // and over the whole buffer when asked.
    assert_eq!(
        stdout_of(&pipe(&["reverse", "--whole"], "ab\ncd")),
        "dc\nba"
    );
    // sort works on the whole buffer by default, and per line when asked.
    assert_eq!(stdout_of(&pipe(&["sort"], "b\na")), "a\nb");
    assert_eq!(stdout_of(&pipe(&["sort", "--lines"], "b\na")), "b\na");
}

#[test]
fn no_newline_suppresses_the_trailing_newline() {
    let padded = run(&["upper", "hi"]);
    assert_eq!(padded.stdout, b"HI\n");
    let bare = run(&["upper", "--no-newline", "hi"]);
    assert_eq!(bare.stdout, b"HI");
}

#[test]
fn a_terminal_with_no_input_explains_itself_instead_of_hanging() {
    // With stdin closed there is nothing to read and nothing to wait for.
    let output = pipe(&["upper"], "");
    assert!(output.status.success(), "{}", stderr_of(&output));
    assert_eq!(stdout_of(&output), "");
}

#[test]
fn failures_report_a_message_and_a_non_zero_status() {
    for args in [
        vec!["url-decode", "%FF"],
        vec!["uuid", "--version", "9"],
        vec!["hmac-sha256", "payload"],
        vec!["json-format", "not json"],
        vec!["roman-encode", "0"],
        vec!["filter", "text"],
    ] {
        let output = run(&args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{args:?} should fail cleanly"
        );
        let error = stderr_of(&output);
        assert!(error.starts_with("txc: "), "{args:?} gave {error:?}");
        assert!(!error.contains("panicked"), "{args:?} panicked: {error}");
    }
}

#[test]
fn an_unknown_operation_is_a_usage_error() {
    let output = run(&["definitely-not-an-operation", "x"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr_of(&output).contains("unrecognized subcommand"));
}

#[test]
fn every_operation_runs_through_the_command_line_without_panicking() {
    let names = stdout_of(&run(&["list", "--names"]));
    let names: Vec<&str> = names.lines().collect();
    assert!(
        names.len() > 100,
        "expected a large catalogue, found {}",
        names.len()
    );

    for name in names {
        let output = pipe(&[name], "Sample Text 42\nsecond line\n");
        let error = stderr_of(&output);
        assert!(!error.contains("panicked"), "{name} panicked:\n{error}",);
        // Either it worked, or it explained what it needed.
        let code = output.status.code();
        assert!(
            code == Some(0) || code == Some(1),
            "{name} exited with {code:?}: {error}",
        );
        if code == Some(1) {
            assert!(error.starts_with("txc: "), "{name} gave {error:?}");
        }
    }
}

#[test]
fn every_operation_offers_help() {
    let names = stdout_of(&run(&["list", "--names"]));
    for name in names.lines() {
        let output = run(&[name, "--help"]);
        assert!(output.status.success(), "{name} --help failed");
        assert!(!stdout_of(&output).is_empty(), "{name} --help was empty");
    }
}

#[test]
fn listing_covers_every_category() {
    let full = stdout_of(&run(&["list"]));
    for category in [
        "CASE", "ENCODING", "HASHING", "LINES", "TEXT", "NUMBERS", "CONVERT", "INSPECT",
        "GENERATE", "TIME",
    ] {
        assert!(
            full.contains(category),
            "{category} missing from the listing"
        );
    }
    assert!(full.contains("operations in"), "{full}");

    let one = stdout_of(&run(&["list", "--category", "hash"]));
    assert!(one.contains("sha256"));
    assert!(!one.contains("url-encode"));

    let unknown = run(&["list", "--category", "nonsense"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(stderr_of(&unknown).contains("unknown category"));
}

#[test]
fn completion_scripts_are_generated_for_every_shell() {
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let output = run(&["completions", shell]);
        assert!(output.status.success(), "{shell}: {}", stderr_of(&output));
        let script = stdout_of(&output);
        assert!(
            script.len() > 500,
            "{shell} produced a suspiciously short script"
        );
        assert!(
            script.contains("txc"),
            "{shell} script does not mention txc"
        );
        // The catalogue must be present, or tab completion would be useless.
        assert!(
            script.contains("base64-encode"),
            "{shell} script lists no operations"
        );
    }
}

#[test]
fn about_reports_the_author_and_the_licence() {
    let output = run(&["about"]);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let report = stdout_of(&output);
    for expected in [
        "Matheus Santos",
        "vorj.dux@gmail.com",
        "MIT OR Apache-2.0",
        "https://github.com/vorjdux/txc",
        env!("CARGO_PKG_VERSION"),
        "never leaves this machine",
    ] {
        assert!(
            report.contains(expected),
            "{expected:?} missing from:\n{report}"
        );
    }

    // The catalogue size it quotes has to be the real one.
    let operations = stdout_of(&run(&["list", "--names"])).lines().count();
    assert!(report.contains(&format!("{operations} in ")), "{report}");

    assert_eq!(stdout_of(&run(&["credits"])), report);
}

#[test]
fn the_version_and_help_flags_work() {
    let version = run(&["--version"]);
    assert!(version.status.success());
    assert!(stdout_of(&version).contains(env!("CARGO_PKG_VERSION")));

    let help = run(&["--help"]);
    assert!(help.status.success());
    assert!(stdout_of(&help).contains("Offline text utilities"));
}

#[test]
fn without_a_terminal_and_without_arguments_it_prints_help() {
    let output = pipe(&[], "");
    assert!(output.status.success());
    assert!(stdout_of(&output).contains("Usage"));
}

#[test]
fn the_interface_explains_itself_when_there_is_no_terminal() {
    let output = pipe(&["tui"], "");
    assert_eq!(output.status.code(), Some(1));
    let error = stderr_of(&output);
    assert!(error.contains("needs a terminal"), "{error}");
    assert!(!error.contains("panicked"), "{error}");
}

#[test]
fn generators_do_not_wait_for_input() {
    for args in [
        vec!["uuid"],
        vec!["password", "--length", "8"],
        vec!["lorem", "--words", "3"],
        vec!["token", "--bytes", "4"],
        vec!["timestamp"],
        vec!["sequence", "--end", "3"],
    ] {
        let output = run(&args);
        assert!(output.status.success(), "{args:?}: {}", stderr_of(&output));
        assert!(!stdout_of(&output).is_empty(), "{args:?} produced nothing");
    }
}
