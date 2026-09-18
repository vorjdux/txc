//! End to end tests of `txc vault`, run against the built binary.
//!
//! Every test works in a directory of its own, with the passphrase in a file,
//! so nothing ever waits at a terminal. The clipboard is not exercised here:
//! CI runners have none, and `--print` reaches the same secret.

#![cfg(feature = "vault")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_txc");
const PASSPHRASE: &str = "correct horse battery staple";
const PATIENCE: Duration = Duration::from_secs(60);

/// A vault directory and passphrase file for one test, removed when dropped.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "txc-vault-e2e-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let sandbox = Self { root };
        sandbox.passphrase_file("pass", PASSPHRASE);
        sandbox
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn passphrase_file(&self, name: &str, passphrase: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::write(&path, format!("{passphrase}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    /// Runs `txc vault --home <home> --passphrase-file <pass> <args>`.
    fn vault(&self, args: &[&str]) -> Output {
        self.vault_with(&self.home(), &self.root.join("pass"), args, None)
    }

    fn vault_piped(&self, args: &[&str], input: &str) -> Output {
        self.vault_with(&self.home(), &self.root.join("pass"), args, Some(input))
    }

    fn vault_with(&self, home: &Path, pass: &Path, args: &[&str], input: Option<&str>) -> Output {
        let mut command = Command::new(BIN);
        command
            .arg("vault")
            .arg("--home")
            .arg(home)
            .arg("--passphrase-file")
            .arg(pass)
            .args(args)
            // Debug builds read this, so identities are made in milliseconds.
            .env("TXC_VAULT_TEST_WORK_FACTOR", "10")
            .env_remove("TXC_VAULT_HOME")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("txc starts");
        if let Some(input) = input {
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        finish(child, args)
    }

    fn init(&self) {
        succeeds(&self.vault(&["init"]));
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Waits for the child, killing it rather than waiting for ever.
fn finish(mut child: Child, args: &[&str]) -> Output {
    drop(child.stdin.take());
    let (finished, waiting) = mpsc::channel::<()>();
    let id = child.id();
    let watchdog = std::thread::spawn(move || match waiting.recv_timeout(PATIENCE) {
        Err(mpsc::RecvTimeoutError::Timeout) => {
            kill(id);
            true
        }
        _ => false,
    });
    let output = child.wait_with_output().expect("txc finishes");
    drop(finished);
    assert!(
        !watchdog.join().unwrap(),
        "txc vault {args:?} did not finish within {PATIENCE:?}"
    );
    output
}

#[cfg(unix)]
fn kill(pid: u32) {
    let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
}

#[cfg(windows)]
fn kill(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .status();
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn succeeds(output: &Output) -> String {
    assert!(
        output.status.success(),
        "failed: {}\n{}",
        stderr(output),
        stdout(output)
    );
    stdout(output)
}

fn fails(output: &Output) -> String {
    assert!(
        !output.status.success(),
        "succeeded when it should not have: {}",
        stdout(output)
    );
    stderr(output)
}

/// Every file under a directory, as bytes, for searching for leaks.
fn every_file(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    for item in std::fs::read_dir(dir).unwrap() {
        let path = item.unwrap().path();
        if path.is_dir() {
            files.extend(every_file(&path));
        } else {
            files.push((path.clone(), std::fs::read(&path).unwrap()));
        }
    }
    files
}

/// The fingerprint a vault prints, for reading onto another device.
fn fingerprint(sandbox: &Sandbox, vault: &str) -> String {
    let out = succeeds(&sandbox.vault(&["fingerprint", vault]));
    out.split_whitespace().last().unwrap().to_string()
}

/// Copies a whole vault home, as syncing the directory across would, keeping
/// the owner-only permissions txc insists on.
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for item in std::fs::read_dir(from).unwrap() {
        let entry = item.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
}

#[test]
fn init_prints_the_public_key_and_creates_the_personal_vault() {
    let sandbox = Sandbox::new("init");
    let output = sandbox.vault(&["init"]);
    let key = succeeds(&output);
    assert!(key.trim().starts_with("age1"), "{key}");
    assert_eq!(succeeds(&sandbox.vault(&["list"])).trim(), "personal");
    assert_eq!(succeeds(&sandbox.vault(&["identity"])), key);

    // Running it again changes nothing.
    assert_eq!(succeeds(&sandbox.vault(&["init"])), key);
}

#[cfg(unix)]
#[test]
fn every_file_and_directory_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new("modes");
    sandbox.init();
    let mode = |path: PathBuf| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let home = sandbox.home();
    assert_eq!(mode(home.clone()), 0o700);
    assert_eq!(mode(home.join("vaults")), 0o700);
    assert_eq!(mode(home.join("identity.age")), 0o600);
    assert_eq!(mode(home.join("trust.json")), 0o600);
    assert_eq!(mode(home.join("vaults/personal.vault.age")), 0o600);
}

#[test]
fn a_secret_goes_in_through_a_pipe_and_comes_out_only_when_asked() {
    let sandbox = Sandbox::new("round-trip");
    sandbox.init();
    succeeds(&sandbox.vault_piped(
        &[
            "add",
            "GitHub",
            "--username",
            "octocat",
            "--url",
            "https://github.com",
            "--tag",
            "dev",
            "--secret-from-stdin",
        ],
        "hunter2-the-secret\n",
    ));

    let list = succeeds(&sandbox.vault(&["list", "personal"]));
    assert!(
        list.contains("GitHub") && list.contains("octocat"),
        "{list}"
    );
    assert!(!list.contains("hunter2"), "{list}");

    let show = succeeds(&sandbox.vault(&["show", "github"]));
    assert!(show.contains("https://github.com"), "{show}");
    assert!(show.contains("••••••••"), "{show}");
    assert!(!show.contains("hunter2"), "{show}");

    // The trailing newline from the pipe is not part of the secret, and none
    // is added on the way out.
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "personal/GitHub", "--print"])),
        "hunter2-the-secret"
    );
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "github", "--field", "username", "--print"])),
        "octocat"
    );
}

#[test]
fn no_secret_and_no_name_is_readable_in_any_file() {
    let sandbox = Sandbox::new("leaks");
    sandbox.init();
    succeeds(&sandbox.vault_piped(
        &[
            "add",
            "bank-of-examples",
            "--username",
            "account-holder-name",
            "--secret-from-stdin",
        ],
        "correct-battery-horse-staple-secret",
    ));

    for (path, bytes) in every_file(&sandbox.home()) {
        let text = String::from_utf8_lossy(&bytes);
        for needle in [
            "correct-battery-horse-staple-secret",
            "bank-of-examples",
            "account-holder-name",
            "AGE-SECRET-KEY",
        ] {
            assert!(
                !text.contains(needle),
                "{} holds {needle:?} in the clear",
                path.display()
            );
        }
    }
}

#[test]
fn a_generated_password_has_the_length_asked_for() {
    let sandbox = Sandbox::new("generate");
    sandbox.init();
    succeeds(&sandbox.vault(&["add", "site", "--generate", "--length", "40"]));
    let password = succeeds(&sandbox.vault(&["copy", "site", "--print"]));
    assert_eq!(password.chars().count(), 40, "{password}");

    succeeds(&sandbox.vault(&["add", "other", "--generate"]));
    let other = succeeds(&sandbox.vault(&["copy", "other", "--print"]));
    assert_eq!(other.chars().count(), 24);
    assert_ne!(password, other);
}

#[test]
fn the_wrong_passphrase_reveals_nothing() {
    let sandbox = Sandbox::new("wrong");
    sandbox.init();
    succeeds(&sandbox.vault_piped(&["add", "site", "--secret-from-stdin"], "s3cret"));

    let wrong = sandbox.passphrase_file("wrong", "not the right passphrase");
    let output = sandbox.vault_with(&sandbox.home(), &wrong, &["copy", "site", "--print"], None);
    let error = fails(&output);
    assert!(error.contains("wrong passphrase"), "{error}");
    assert!(stdout(&output).is_empty());
}

#[cfg(unix)]
#[test]
fn a_passphrase_file_other_users_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new("open-passphrase");
    let pass = sandbox.root.join("pass");
    std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = fails(&sandbox.vault(&["init"]));
    assert!(error.contains("other users"), "{error}");
}

#[test]
fn a_short_passphrase_is_refused_for_a_new_identity() {
    let sandbox = Sandbox::new("short");
    let short = sandbox.passphrase_file("short", "too short");
    let error = fails(&sandbox.vault_with(&sandbox.home(), &short, &["init"], None));
    assert!(error.contains("at least 12 characters"), "{error}");
}

#[test]
fn entries_can_be_changed_and_removed() {
    let sandbox = Sandbox::new("edit");
    sandbox.init();
    succeeds(&sandbox.vault_piped(
        &["add", "site", "--username", "old", "--secret-from-stdin"],
        "first",
    ));
    succeeds(&sandbox.vault_piped(
        &[
            "edit",
            "site",
            "--rename",
            "renamed",
            "--username",
            "new",
            "--field",
            "note-to-self=plain",
            "--secret-from-stdin",
        ],
        "second",
    ));
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "renamed", "--print"])),
        "second"
    );
    let show = succeeds(&sandbox.vault(&["show", "renamed"]));
    assert!(
        show.contains("new") && show.contains("note-to-self"),
        "{show}"
    );

    fails(&sandbox.vault(&["rm", "renamed"]));
    succeeds(&sandbox.vault(&["rm", "renamed", "--yes"]));
    let error = fails(&sandbox.vault(&["show", "renamed"]));
    assert!(error.contains("no entry"), "{error}");
}

#[test]
fn a_changed_vault_file_is_refused() {
    let sandbox = Sandbox::new("tamper");
    sandbox.init();
    let path = sandbox.home().join("vaults/personal.vault.age");
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 3;
    bytes[last] ^= 1;
    std::fs::write(&path, bytes).unwrap();

    let error = fails(&sandbox.vault(&["list", "personal"]));
    assert!(error.contains("cannot open the vault"), "{error}");
}

#[test]
fn an_old_copy_put_back_stays_refused_without_a_terminal() {
    let sandbox = Sandbox::new("rollback");
    sandbox.init();
    let path = sandbox.home().join("vaults/personal.vault.age");
    let original = std::fs::read(&path).unwrap();
    succeeds(&sandbox.vault_piped(&["add", "site", "--secret-from-stdin"], "x"));

    std::fs::write(&path, original).unwrap();
    let error = fails(&sandbox.vault(&["list", "personal"]));
    assert!(error.contains("older"), "{error}");

    // A rollback is a policy change: --yes does not cover it, and there is no
    // terminal here, so it stays refused. Its fingerprint would settle nothing.
    let no_terminal = fails(&sandbox.vault(&["trust", "personal"]));
    assert!(no_terminal.contains("terminal"), "{no_terminal}");
    let yes = fails(&sandbox.vault(&["trust", "personal", "--yes"]));
    assert!(yes.contains("terminal"), "{yes}");

    let fp = fingerprint(&sandbox, "personal");
    let expect = fails(&sandbox.vault(&["trust", "personal", "--expect", &fp]));
    assert!(expect.contains("cannot settle this"), "{expect}");

    // The vault is still not openable; that is the correct end state here.
    fails(&sandbox.vault(&["list", "personal"]));
}

#[test]
fn a_vault_copied_to_another_device_needs_trusting_there() {
    let laptop = Sandbox::new("laptop");
    laptop.init();
    succeeds(&laptop.vault_piped(&["add", "site", "--secret-from-stdin"], "travels"));

    // The same identity and vault on a second device, without its trust
    // records: exactly what copying the vault directory across looks like.
    let desktop = Sandbox::new("desktop");
    std::fs::create_dir_all(desktop.home().join("vaults")).unwrap();
    for name in ["identity.age", "vaults/personal.vault.age"] {
        std::fs::copy(laptop.home().join(name), desktop.home().join(name)).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [desktop.home(), desktop.home().join("vaults")] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    let error = fails(&desktop.vault(&["copy", "site", "--print"]));
    assert!(error.contains("not been trusted"), "{error}");
    succeeds(&desktop.vault(&["trust", "personal", "--yes"]));
    assert_eq!(
        succeeds(&desktop.vault(&["copy", "site", "--print"])),
        "travels"
    );
}

#[test]
fn a_vault_can_be_shared_with_another_identity() {
    let alice = Sandbox::new("alice");
    let bob = Sandbox::new("bob");
    alice.init();
    let bob_key = succeeds(&bob.vault(&["init"])).trim().to_string();

    succeeds(&alice.vault(&["create", "team", "--recipient", &bob_key]));
    succeeds(&alice.vault_piped(
        &[
            "add",
            "team/deploy",
            "--kind",
            "api-key",
            "--secret-from-stdin",
        ],
        "shared-key",
    ));
    let recipients = succeeds(&alice.vault(&["recipients", "team"]));
    assert_eq!(recipients.lines().count(), 2, "{recipients}");
    assert!(recipients.contains(&bob_key));

    std::fs::copy(
        alice.home().join("vaults/team.vault.age"),
        bob.home().join("vaults/team.vault.age"),
    )
    .unwrap();
    succeeds(&bob.vault(&["trust", "team", "--yes"]));
    assert_eq!(
        succeeds(&bob.vault(&["copy", "team/deploy", "--print"])),
        "shared-key"
    );

    // Taking Bob off seals everything again without his key.
    succeeds(&alice.vault(&["recipients", "team", "--remove", &bob_key]));
    std::fs::copy(
        alice.home().join("vaults/team.vault.age"),
        bob.home().join("vaults/team.vault.age"),
    )
    .unwrap();
    fails(&bob.vault(&["copy", "team/deploy", "--print"]));
}

#[test]
fn a_secret_cannot_be_passed_as_an_argument() {
    let sandbox = Sandbox::new("argument");
    sandbox.init();
    // There is no --password or --secret option to put one on the command line.
    for flag in ["--password", "--secret", "--value"] {
        let output = sandbox.vault(&["add", "site", flag, "hunter2"]);
        let error = fails(&output);
        assert!(error.contains("unexpected argument"), "{flag}: {error}");
    }
}

#[test]
fn names_that_could_escape_the_vault_directory_are_refused() {
    let sandbox = Sandbox::new("names");
    sandbox.init();
    for name in ["../outside", "Upper", "a b"] {
        fails(&sandbox.vault(&["create", name]));
    }
    fails(&sandbox.vault_piped(&["add", "bad\u{1b}[2Jname", "--secret-from-stdin"], "x"));
}

#[test]
fn each_kind_keeps_its_secret_fields_secret() {
    let sandbox = Sandbox::new("kinds");
    sandbox.init();

    // A card's security code is secret, so it is refused as an argument.
    let error = fails(&sandbox.vault_piped(
        &[
            "add",
            "visa",
            "--kind",
            "card",
            "--field",
            "cvv=123",
            "--secret-from-stdin",
        ],
        "4111111111111111",
    ));
    assert!(error.contains("--secret-field cvv"), "{error}");

    succeeds(&sandbox.vault_piped(
        &[
            "add",
            "visa",
            "--kind",
            "card",
            "--field",
            "cardholder=A N Other",
            "--field",
            "expiry=12/30",
            "--secret-from-stdin",
        ],
        "4111111111111111",
    ));
    let show = succeeds(&sandbox.vault(&["show", "visa"]));
    assert!(show.contains("Payment card"), "{show}");
    assert!(show.contains("Card number"), "{show}");
    assert!(show.contains("A N Other"), "{show}");
    assert!(!show.contains("4111"), "{show}");
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "visa", "--print"])),
        "4111111111111111"
    );

    // A card number is not something to make up.
    let error = fails(&sandbox.vault(&["add", "other", "--kind", "card", "--generate"]));
    assert!(error.contains("cannot be generated"), "{error}");
}

#[test]
fn favourites_and_recently_used_entries_can_be_listed() {
    let sandbox = Sandbox::new("favourites");
    sandbox.init();
    for name in ["alpha", "beta", "gamma"] {
        succeeds(&sandbox.vault_piped(&["add", name, "--secret-from-stdin"], "x"));
    }

    succeeds(&sandbox.vault(&["favourite", "beta"]));
    let favourites = succeeds(&sandbox.vault(&["list", "--favourites"]));
    assert!(favourites.contains("beta ★"), "{favourites}");
    assert!(!favourites.contains("alpha"), "{favourites}");

    succeeds(&sandbox.vault(&["copy", "gamma", "--print"]));
    succeeds(&sandbox.vault(&["copy", "alpha", "--print"]));
    let recent = succeeds(&sandbox.vault(&["list", "--recent"]));
    let lines: Vec<&str> = recent.lines().collect();
    assert_eq!(lines.len(), 2, "{recent}");
    assert!(lines[0].contains("alpha"), "{recent}");
    assert!(lines[1].contains("gamma"), "{recent}");
    assert!(recent.contains("just now"), "{recent}");

    succeeds(&sandbox.vault(&["favourite", "beta", "--remove"]));
    let output = sandbox.vault(&["list", "--favourites"]);
    assert!(stdout(&output).trim().is_empty(), "{}", stdout(&output));
}

#[test]
fn the_help_for_add_lists_the_kinds_and_their_fields() {
    let sandbox = Sandbox::new("kinds-help");
    let help = succeeds(&sandbox.vault(&["add", "--help"]));
    for kind in ["login", "card", "ssh-key", "wifi", "wallet", "licence"] {
        assert!(help.contains(kind), "{kind} is missing:\n{help}");
    }
    assert!(help.contains("cvv*"), "{help}");
}

#[test]
fn an_entry_moves_to_another_vault_and_keeps_its_secret() {
    let sandbox = Sandbox::new("move");
    sandbox.init();
    succeeds(&sandbox.vault(&["create", "work"]));
    succeeds(&sandbox.vault_piped(
        &["add", "openai", "--kind", "api-key", "--secret-from-stdin"],
        "sk-secret-key",
    ));

    // Moves from personal (the default) into work.
    succeeds(&sandbox.vault(&["move", "openai", "work"]));

    // Gone from personal, present in work, still readable.
    let error = fails(&sandbox.vault(&["show", "personal/openai"]));
    assert!(error.contains("no entry"), "{error}");
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "work/openai", "--print"])),
        "sk-secret-key"
    );

    // The alias works, and moving onto a taken name is refused.
    succeeds(&sandbox.vault_piped(
        &["add", "note", "--kind", "note", "--secret-from-stdin"],
        "n",
    ));
    succeeds(&sandbox.vault_piped(
        &["add", "work/note", "--kind", "note", "--secret-from-stdin"],
        "n2",
    ));
    let clash = fails(&sandbox.vault(&["mv", "note", "work"]));
    assert!(clash.contains("already has an entry"), "{clash}");
    // Refused move left the source untouched.
    succeeds(&sandbox.vault(&["show", "personal/note"]));
}

#[test]
fn an_unattended_job_cannot_trust_a_replaced_vault() {
    // Alice has a vault. An attacker holds only Alice's public key.
    let alice = Sandbox::new("attack-alice");
    alice.init();
    let alice_key = succeeds(&alice.vault(&["identity"])).trim().to_string();

    // The attacker builds a vault of the same name, encrypted to Alice and to
    // themselves, and drops it into Alice's synced vaults directory.
    let attacker = Sandbox::new("attack-eve");
    attacker.init();
    std::fs::remove_file(attacker.home().join("vaults/personal.vault.age")).unwrap();
    let _ = std::fs::remove_file(attacker.home().join("vaults/personal.vault.age.bak"));
    succeeds(&attacker.vault(&["create", "personal", "--recipient", &alice_key]));
    std::fs::copy(
        attacker.home().join("vaults/personal.vault.age"),
        alice.home().join("vaults/personal.vault.age"),
    )
    .unwrap();

    // An unattended job cannot pin the replacement, and nothing on disk changes.
    let before = std::fs::read(alice.home().join("trust.json")).unwrap();
    let error = fails(&alice.vault(&["trust", "personal", "--yes"]));
    assert!(error.contains("terminal"), "{error}");
    let after = std::fs::read(alice.home().join("trust.json")).unwrap();
    assert_eq!(before, after, "trust.json changed under an unattended job");
}

#[test]
fn a_fingerprint_lets_a_script_accept_a_replaced_vault() {
    let alice = Sandbox::new("fp-alice");
    let bob = Sandbox::new("fp-bob");
    alice.init();
    bob.init();
    let bob_key = succeeds(&bob.vault(&["identity"])).trim().to_string();

    succeeds(&alice.vault(&["create", "team", "--recipient", &bob_key]));
    succeeds(&alice.vault_piped(
        &[
            "add",
            "team/deploy",
            "--kind",
            "api-key",
            "--secret-from-stdin",
        ],
        "k",
    ));
    let fp = fingerprint(&alice, "team");

    // Bob receives the vault; it is new to him.
    std::fs::copy(
        alice.home().join("vaults/team.vault.age"),
        bob.home().join("vaults/team.vault.age"),
    )
    .unwrap();

    // A wrong fingerprint pins nothing and leaves it untrusted.
    let wrong = fails(&bob.vault(&["trust", "team", "--expect", "aaaa-bbbb-cccc-dddd-eeee-ffff"]));
    assert!(wrong.contains("fingerprint is"), "{wrong}");
    fails(&bob.vault(&["list", "team"]));

    // The right fingerprint accepts it with no terminal.
    succeeds(&bob.vault(&["trust", "team", "--expect", &fp]));
    assert_eq!(
        succeeds(&bob.vault(&["copy", "team/deploy", "--print"])),
        "k"
    );

    // A matching fingerprint still does not settle a rollback.
    let path = alice.home().join("vaults/team.vault.age");
    let gen_one = std::fs::read(&path).unwrap();
    succeeds(&alice.vault_piped(
        &[
            "add",
            "team/another",
            "--kind",
            "secret",
            "--secret-from-stdin",
        ],
        "y",
    ));
    std::fs::write(&path, gen_one).unwrap();
    let team_fp = fingerprint(&alice, "team");
    let rolled = fails(&alice.vault(&["trust", "team", "--expect", &team_fp]));
    assert!(rolled.contains("cannot settle this"), "{rolled}");
}

#[test]
fn two_devices_changing_a_vault_at_once_is_refused() {
    let a = Sandbox::new("diverge-a");
    a.init();
    // Device B is a full copy of A: same identity, same vault, same trust.
    let b = Sandbox::new("diverge-b");
    copy_dir(&a.home(), &b.home());

    // Each adds a different entry offline, both reaching the next generation.
    succeeds(&a.vault_piped(&["add", "from-a", "--secret-from-stdin"], "a"));
    succeeds(&b.vault_piped(&["add", "from-b", "--secret-from-stdin"], "b"));

    // A's version is synced over B's.
    std::fs::copy(
        a.home().join("vaults/personal.vault.age"),
        b.home().join("vaults/personal.vault.age"),
    )
    .unwrap();

    // On B this is a divergence, not a silent overwrite of B's entry.
    let error = fails(&b.vault(&["list", "personal"]));
    assert!(error.contains("diverged"), "{error}");
}

#[test]
fn trusting_records_what_it_replaced() {
    let alice = Sandbox::new("hist-alice");
    alice.init();
    let alice_key = succeeds(&alice.vault(&["identity"])).trim().to_string();

    // A vault of the same name is rebuilt elsewhere and copied over Alice's.
    let other = Sandbox::new("hist-other");
    other.init();
    std::fs::remove_file(other.home().join("vaults/personal.vault.age")).unwrap();
    let _ = std::fs::remove_file(other.home().join("vaults/personal.vault.age.bak"));
    succeeds(&other.vault(&["create", "personal", "--recipient", &alice_key]));
    let fp = fingerprint(&other, "personal");
    std::fs::copy(
        other.home().join("vaults/personal.vault.age"),
        alice.home().join("vaults/personal.vault.age"),
    )
    .unwrap();

    // Alice accepts it with the fingerprint she verified, and the log records
    // that it replaced the vault she had.
    succeeds(&alice.vault(&["trust", "personal", "--expect", &fp]));
    let history = succeeds(&alice.vault(&["history", "personal"]));
    assert!(
        history.contains("replaced another vault of the same name"),
        "{history}"
    );
}
