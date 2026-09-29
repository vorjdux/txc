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
/// The write key's passphrase, kept different from the identity's, as the two
/// are meant to be.
const WRITE_PASSPHRASE: &str = "a quite separate write passphrase";
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
        sandbox.passphrase_file("write-pass", WRITE_PASSPHRASE);
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
            .arg("--write-passphrase-file")
            .arg(self.root.join("write-pass"))
            .args(args)
            // Debug builds read this, so identities are made in milliseconds.
            .env("TXC_VAULT_TEST_WORK_FACTOR", "10")
            // Where each platform keeps session files: private to this test.
            .env("XDG_RUNTIME_DIR", self.private("run"))
            .env("TMPDIR", self.private("tmp"))
            .env("LOCALAPPDATA", self.private("local"))
            // Debug builds keep the synced vaults' second factor here rather
            // than in the OS keystore, which CI runners do not have.
            .env("TXC_VAULT_TEST_KEYSTORE", self.private("keystore"))
            .env("TXC_VAULT_TEST_SSH", self.root.join("fake-ssh"))
            // Debug builds print the recovery kit here instead of showing it
            // one sheet at a time at a terminal.
            .env("TXC_VAULT_TEST_KIT", "1")
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

    /// A directory only this user can open, created on first use.
    fn private(&self, name: &str) -> PathBuf {
        let dir = self.root.join(name);
        if !dir.exists() {
            std::fs::create_dir_all(&dir).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        dir
    }

    /// Opens a session, or returns false when this machine cannot keep one
    /// (a container without a kernel keyring, for instance).
    fn unlock(&self, args: &[&str]) -> bool {
        let mut all = vec!["unlock"];
        all.extend_from_slice(args);
        let output = self.vault(&all);
        if output.status.success() {
            return true;
        }
        let error = stderr(&output);
        assert!(
            error.contains("keyring") || error.contains("Keychain") || error.contains("DPAPI"),
            "unlock failed for another reason: {error}"
        );
        eprintln!("skipping: this machine cannot keep a session ({error})");
        false
    }

    /// Runs a command with a wrong passphrase, so it can only succeed through
    /// an open session.
    fn vault_without_passphrase(&self, args: &[&str]) -> Output {
        let wrong = self.passphrase_file("wrong", "not the passphrase at all");
        self.vault_with(&self.home(), &wrong, args, None)
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

/// This device's writer public key (the first field of `vault writer`).
fn writer_key(sandbox: &Sandbox) -> String {
    let out = succeeds(&sandbox.vault(&["writer"]));
    out.split_whitespace().next().unwrap().to_string()
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
    // The write key and the pinned writers travel with the identity to another
    // of your own devices, so a vault it signed opens there.
    for name in [
        "identity.age",
        "writer.age",
        "writers",
        "vaults/personal.vault.age",
    ] {
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
    // Bob pins Alice's writer, so the vault she signed opens for him.
    succeeds(&bob.vault(&["writers", "--add", &writer_key(&alice), "--yes"]));
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

    // The attacker does not hold Alice's write key, so the forgery is signed by
    // a writer Alice never pinned and is refused outright, before trust even
    // enters into it. Nothing on disk changes.
    let before = std::fs::read(alice.home().join("trust.json")).unwrap();
    let error = fails(&alice.vault(&["trust", "personal", "--yes"]));
    assert!(error.contains("does not know"), "{error}");
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

    // Bob receives the vault; it is new to him. He pins Alice's writer, so the
    // signature verifies and the fingerprint is what settles trust.
    std::fs::copy(
        alice.home().join("vaults/team.vault.age"),
        bob.home().join("vaults/team.vault.age"),
    )
    .unwrap();
    succeeds(&bob.vault(&["writers", "--add", &writer_key(&alice), "--yes"]));

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

    // Alice pins the other device's writer, so its vault reaches the trust
    // layer, then accepts it with the fingerprint she verified. The log records
    // that it replaced the vault she had.
    succeeds(&alice.vault(&["writers", "--add", &writer_key(&other), "--yes"]));
    succeeds(&alice.vault(&["trust", "personal", "--expect", &fp]));
    let history = succeeds(&alice.vault(&["history", "personal"]));
    assert!(
        history.contains("replaced another vault of the same name"),
        "{history}"
    );
}

#[test]
fn a_reader_only_device_can_read_but_not_write() {
    let writer = Sandbox::new("ro-writer");
    writer.init();
    succeeds(&writer.vault_piped(&["add", "site", "--secret-from-stdin"], "the-secret"));

    // Provision a reader: the identity, the pinned writers and the trust
    // record, but NOT writer.age. This is the automation-host row of the
    // provisioning matrix.
    let reader = Sandbox::new("ro-reader");
    std::fs::create_dir_all(reader.home().join("vaults")).unwrap();
    for name in [
        "identity.age",
        "writers",
        "trust.json",
        "vaults/personal.vault.age",
    ] {
        std::fs::copy(writer.home().join(name), reader.home().join(name)).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [reader.home(), reader.home().join("vaults")] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    // It can read the secret.
    assert_eq!(
        succeeds(&reader.vault(&["copy", "site", "--print"])),
        "the-secret"
    );

    // It cannot write, on any path, and every refusal names the reason.
    let alice_key = succeeds(&reader.vault(&["identity"])).trim().to_string();
    for args in [
        vec!["rm", "site", "--yes"],
        vec!["recipients", "personal", "--add", alice_key.as_str()],
        vec!["create", "another"],
    ] {
        let error = fails(&reader.vault(&args));
        assert!(error.contains("read only"), "{:?}: {error}", args);
    }
    // The secret is still there, unchanged.
    assert_eq!(
        succeeds(&reader.vault(&["copy", "site", "--print"])),
        "the-secret"
    );
}

#[test]
fn the_identity_passphrase_does_not_unlock_the_write_key() {
    // A full device, but the write passphrase given is the identity's, not the
    // write key's. The write key does not open, so the change is refused: an
    // agent holding only the identity credential cannot write. (I5.)
    let alice = Sandbox::new("i5");
    alice.init();

    let mut command = Command::new(BIN);
    command
        .arg("vault")
        .arg("--home")
        .arg(alice.home())
        .arg("--passphrase-file")
        .arg(alice.root.join("pass"))
        // The identity's passphrase file, not the write key's.
        .arg("--write-passphrase-file")
        .arg(alice.root.join("pass"))
        .args(["add", "site", "--secret-from-stdin"])
        .env("TXC_VAULT_TEST_WORK_FACTOR", "10")
        .env_remove("TXC_VAULT_HOME")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("txc starts");
    child.stdin.as_mut().unwrap().write_all(b"secret").unwrap();
    let error = fails(&child.wait_with_output().unwrap());
    assert!(
        error.contains("wrong passphrase") || error.contains("write key"),
        "{error}"
    );
}

#[test]
fn a_deleted_vault_can_be_restored_and_reopened() {
    let s = Sandbox::new("del-restore");
    s.init();
    succeeds(&s.vault_piped(&["add", "keep", "--secret-from-stdin"], "value"));

    let output = s.vault(&["delete", "personal", "--yes"]);
    assert!(output.status.success(), "delete failed");
    let told = String::from_utf8_lossy(&output.stderr);
    assert!(
        told.contains("mv "),
        "the output should show how to restore: {told}"
    );

    let live = s.home().join("vaults/personal.vault.age");
    let recovery = s.home().join("vaults/personal.vault.age.deleted");
    assert!(!live.exists(), "the vault file is still there after delete");
    assert!(recovery.exists(), "no recovery file was kept");
    assert!(
        !s.home().join("vaults/personal.vault.age.bak").exists(),
        "the .bak should have been removed, leaving one recovery file"
    );
    fails(&s.vault(&["list", "personal"]));

    // Restore by hand, as the output instructs, then trust it again.
    std::fs::rename(&recovery, &live).unwrap();
    succeeds(&s.vault(&["trust", "personal", "--yes"]));
    assert_eq!(succeeds(&s.vault(&["copy", "keep", "--print"])), "value");
}

#[test]
fn deleting_forgets_the_trust_record_and_the_recent_entries() {
    let s = Sandbox::new("del-forget");
    s.init();
    succeeds(&s.vault_piped(&["add", "used", "--secret-from-stdin"], "value"));
    succeeds(&s.vault(&["copy", "used", "--print"]));
    assert!(
        succeeds(&s.vault(&["list", "--recent"])).contains("used"),
        "the entry was not recorded as recently used"
    );

    succeeds(&s.vault(&["delete", "personal", "--yes"]));

    // Restore the vault, but the recent entry stays forgotten: deletion cleaned
    // recent.age, and bringing the vault back does not bring the recent use back.
    let live = s.home().join("vaults/personal.vault.age");
    std::fs::rename(s.home().join("vaults/personal.vault.age.deleted"), &live).unwrap();
    succeeds(&s.vault(&["trust", "personal", "--yes"]));
    assert!(
        !succeeds(&s.vault(&["list", "--recent"])).contains("used"),
        "the recent entry survived the delete"
    );
    assert_eq!(succeeds(&s.vault(&["copy", "used", "--print"])), "value");
}

#[test]
fn deleting_a_second_vault_of_the_same_name_refuses_rather_than_overwriting() {
    let s = Sandbox::new("del-twice");
    s.init();
    succeeds(&s.vault(&["delete", "personal", "--yes"]));
    succeeds(&s.vault(&["create", "personal"]));
    let error = fails(&s.vault(&["delete", "personal", "--yes"]));
    assert!(error.contains("already"), "{error}");
    // The second vault is untouched, since deleting it would overwrite the first
    // one's recovery file.
    assert!(s.home().join("vaults/personal.vault.age").exists());
}

#[test]
fn a_reader_only_device_cannot_delete_a_vault() {
    let writer = Sandbox::new("del-ro-writer");
    writer.init();
    let reader = Sandbox::new("del-ro-reader");
    std::fs::create_dir_all(reader.home().join("vaults")).unwrap();
    for name in [
        "identity.age",
        "writers",
        "trust.json",
        "vaults/personal.vault.age",
    ] {
        std::fs::copy(writer.home().join(name), reader.home().join(name)).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [reader.home(), reader.home().join("vaults")] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let error = fails(&reader.vault(&["delete", "personal", "--yes"]));
    assert!(error.contains("read only"), "{error}");
    assert!(reader.home().join("vaults/personal.vault.age").exists());
}

#[test]
fn deleting_without_a_terminal_or_yes_fails() {
    let s = Sandbox::new("del-noyes");
    s.init();
    let error = fails(&s.vault(&["delete", "personal"]));
    assert!(error.contains("terminal"), "{error}");
    assert!(s.home().join("vaults/personal.vault.age").exists());
}

#[test]
fn rm_still_removes_an_entry_not_a_vault() {
    let s = Sandbox::new("del-rm-entry");
    s.init();
    succeeds(&s.vault_piped(&["add", "one", "--secret-from-stdin"], "value"));
    succeeds(&s.vault(&["rm", "one", "--yes"]));
    // The vault is still there; only the entry is gone.
    assert!(s.home().join("vaults/personal.vault.age").exists());
    fails(&s.vault(&["show", "personal/one"]));
}

#[test]
fn a_grant_lets_a_host_open_one_secret_and_no_other() {
    let s = Sandbox::new("grant-roundtrip");
    s.init();
    succeeds(&s.vault_piped(&["add", "site", "--secret-from-stdin"], "the-secret"));
    succeeds(&s.vault_piped(&["add", "other", "--secret-from-stdin"], "not-this-one"));

    // A --to-file grant bundles the key that opens it: the quick local case.
    let grant_json = succeeds(&s.vault(&["grant", "personal/site", "--to-file"]));
    assert!(
        !grant_json.contains("the-secret"),
        "the secret is in the grant in the clear: {grant_json}"
    );
    assert!(
        !grant_json.contains("not-this-one"),
        "the grant leaked another secret"
    );

    let grant_path = s.root.join("deploy.grant");
    std::fs::write(&grant_path, &grant_json).unwrap();
    let redeemed = succeeds(&s.vault(&["redeem", grant_path.to_str().unwrap()]));
    assert_eq!(redeemed, "the-secret");
}

#[test]
fn a_grant_needs_no_write_key() {
    // A reader-only device holds no write key, yet can still issue a grant,
    // because a grant is a read: it can already print the secret.
    let writer = Sandbox::new("grant-ro-writer");
    writer.init();
    succeeds(&writer.vault_piped(&["add", "site", "--secret-from-stdin"], "shared"));

    let reader = Sandbox::new("grant-ro-reader");
    std::fs::create_dir_all(reader.home().join("vaults")).unwrap();
    for name in [
        "identity.age",
        "writers",
        "trust.json",
        "vaults/personal.vault.age",
    ] {
        std::fs::copy(writer.home().join(name), reader.home().join(name)).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [reader.home(), reader.home().join("vaults")] {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    // It cannot write, but it can grant.
    assert!(fails(&reader.vault(&["rm", "site", "--yes"])).contains("read only"));
    let grant_json = succeeds(&reader.vault(&["grant", "personal/site", "--to-file"]));
    let grant_path = reader.root.join("g.grant");
    std::fs::write(&grant_path, &grant_json).unwrap();
    assert_eq!(
        succeeds(&reader.vault(&["redeem", grant_path.to_str().unwrap()])),
        "shared"
    );
}

#[test]
fn rotating_the_write_key_re_signs_every_vault_and_can_retire_the_old() {
    let s = Sandbox::new("rotate");
    s.init();
    succeeds(&s.vault_piped(&["add", "site", "--secret-from-stdin"], "s1"));
    succeeds(&s.vault(&["create", "work"]));
    succeeds(&s.vault_piped(
        &[
            "add",
            "work/deploy",
            "--kind",
            "api-key",
            "--secret-from-stdin",
        ],
        "s2",
    ));

    let old = writer_key(&s);
    succeeds(&s.vault(&["writer", "--rotate"]));
    let new = writer_key(&s);
    assert_ne!(old, new, "the write key did not change");

    // Both writers are pinned, and every vault still opens after re-signing.
    assert_eq!(succeeds(&s.vault(&["writers"])).lines().count(), 2);
    assert_eq!(succeeds(&s.vault(&["copy", "site", "--print"])), "s1");
    assert_eq!(
        succeeds(&s.vault(&["copy", "work/deploy", "--print"])),
        "s2"
    );

    // A new write goes through with the new key.
    succeeds(&s.vault_piped(&["add", "site2", "--secret-from-stdin"], "s3"));

    // Retiring the old writer leaves everything open, since all vaults are on
    // the new key now.
    succeeds(&s.vault(&["writers", "--remove", &old, "--yes"]));
    assert_eq!(succeeds(&s.vault(&["writers"])).lines().count(), 1);
    assert_eq!(succeeds(&s.vault(&["copy", "site", "--print"])), "s1");
    assert_eq!(
        succeeds(&s.vault(&["copy", "work/deploy", "--print"])),
        "s2"
    );
}

#[test]
fn rotating_needs_the_current_write_key() {
    // An agent holding only the identity cannot rotate the write key to one it
    // controls: rotation unlocks the current write key first.
    let s = Sandbox::new("rotate-auth");
    s.init();

    let mut command = Command::new(BIN);
    command
        .arg("vault")
        .arg("--home")
        .arg(s.home())
        .arg("--passphrase-file")
        .arg(s.root.join("pass"))
        // The identity's passphrase, which is not the write key's.
        .arg("--write-passphrase-file")
        .arg(s.root.join("pass"))
        .args(["writer", "--rotate"])
        .env("TXC_VAULT_TEST_WORK_FACTOR", "10")
        .env_remove("TXC_VAULT_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command
        .spawn()
        .expect("txc starts")
        .wait_with_output()
        .unwrap();
    let error = fails(&output);
    assert!(
        error.contains("wrong passphrase") || error.contains("write key"),
        "{error}"
    );
    // The writer is unchanged.
    assert_eq!(succeeds(&s.vault(&["writers"])).lines().count(), 1);
}

#[test]
fn a_session_opens_the_vault_without_the_passphrase() {
    let sandbox = Sandbox::new("session");
    sandbox.init();
    succeeds(&sandbox.vault_piped(&["add", "github", "--secret-from-stdin"], "hunter2\n"));
    if !sandbox.unlock(&[]) {
        return;
    }

    let copied = succeeds(&sandbox.vault_without_passphrase(&["copy", "github", "--print"]));
    assert_eq!(copied.trim(), "hunter2");

    // --no-session asks for the passphrase, and the wrong one fails.
    fails(&sandbox.vault_without_passphrase(&["--no-session", "copy", "github", "--print"]));

    assert!(stderr(&sandbox.vault(&["lock"])).contains("closed"));
    fails(&sandbox.vault_without_passphrase(&["copy", "github", "--print"]));
    assert!(stderr(&sandbox.vault(&["lock"])).contains("no open session"));
}

#[test]
fn an_idle_session_ends() {
    let sandbox = Sandbox::new("session-idle");
    sandbox.init();
    succeeds(&sandbox.vault_piped(&["add", "github", "--secret-from-stdin"], "hunter2\n"));
    if !sandbox.unlock(&["--idle", "1"]) {
        return;
    }
    // Pretend the last use was long ago.
    let used: Vec<PathBuf> = ["run", "tmp", "local"]
        .iter()
        .flat_map(|dir| every_file(&sandbox.root.join(dir)))
        .map(|(path, _)| path)
        .filter(|path| path.extension().is_some_and(|ext| ext == "used"))
        .collect();
    assert_eq!(used.len(), 1, "one session in this sandbox");
    std::fs::write(&used[0], 0_u64.to_be_bytes()).unwrap();

    let output = sandbox.vault_without_passphrase(&["copy", "github", "--print"]);
    fails(&output);
    assert!(stderr(&output).contains("idle"), "{}", stderr(&output));
}

#[test]
fn a_session_never_holds_the_write_key() {
    let sandbox = Sandbox::new("session-write");
    sandbox.init();
    if !sandbox.unlock(&[]) {
        return;
    }
    // The session opens the identity, but a change still needs the write
    // passphrase, and this one is wrong.
    sandbox.passphrase_file("write-pass", "not the write passphrase");
    fails(&sandbox.vault_piped(&["add", "github", "--secret-from-stdin"], "hunter2\n"));
}

/// Runs `txc vault run` from inside a project directory with its template.
#[cfg(unix)]
fn run_in(sandbox: &Sandbox, template: &str, args: &[&str]) -> Output {
    let project = sandbox.private("project");
    std::fs::write(project.join(".env.txc"), template).unwrap();
    let mut command = Command::new(BIN);
    command
        .current_dir(&project)
        .arg("vault")
        .arg("--home")
        .arg(sandbox.home())
        .arg("--passphrase-file")
        .arg(sandbox.root.join("pass"))
        .arg("run")
        .args(args)
        .env("TXC_VAULT_TEST_WORK_FACTOR", "10")
        .env("XDG_RUNTIME_DIR", sandbox.private("run"))
        .env("TMPDIR", sandbox.private("tmp"))
        .env_remove("TXC_VAULT_HOME")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    finish(command.spawn().expect("txc starts"), args)
}

#[cfg(unix)]
#[test]
fn run_puts_secrets_in_the_programs_environment_and_nowhere_else() {
    let sandbox = Sandbox::new("run-env");
    sandbox.init();
    succeeds(&sandbox.vault_piped(&["add", "db", "--secret-from-stdin"], "s3cret\n"));
    let output = run_in(
        &sandbox,
        "# safe to commit\nDB=txc://personal/db\nLEVEL=debug\n",
        &["--", "sh", "-c", "printf '%s|%s' \"$DB\" \"$LEVEL\""],
    );
    assert_eq!(succeeds(&output), "s3cret|debug");
}

#[cfg(unix)]
#[test]
fn run_hands_a_secret_as_a_file_that_is_not_on_disk() {
    let sandbox = Sandbox::new("run-file");
    sandbox.init();
    succeeds(&sandbox.vault_piped(&["add", "tls", "--secret-from-stdin"], "PRIVATE KEY\n"));
    let output = run_in(
        &sandbox,
        "KEY=txc+file://personal/tls\n",
        &[
            "--",
            "sh",
            "-c",
            "case \"$KEY\" in /dev/fd/*) cat \"$KEY\";; *) echo not-a-descriptor;; esac",
        ],
    );
    assert_eq!(succeeds(&output), "PRIVATE KEY");
}

#[cfg(unix)]
#[test]
fn run_passes_on_the_programs_exit_code() {
    let sandbox = Sandbox::new("run-exit");
    sandbox.init();
    // A template with no secret needs no unlock at all.
    let output = run_in(&sandbox, "LEVEL=debug\n", &["--", "sh", "-c", "exit 7"]);
    assert_eq!(output.status.code(), Some(7));
}

#[cfg(unix)]
#[test]
fn run_refuses_a_value_on_the_command_line() {
    let sandbox = Sandbox::new("run-set");
    sandbox.init();
    let output = run_in(&sandbox, "", &["--set", "DB=hunter2", "--", "true"]);
    assert!(
        stderr(&output).contains("only references"),
        "{}",
        stderr(&output)
    );
    fails(&output);
}

#[cfg(unix)]
#[test]
fn run_names_the_variable_whose_secret_is_missing() {
    let sandbox = Sandbox::new("run-missing");
    sandbox.init();
    let output = run_in(
        &sandbox,
        "DB=txc://personal/nothing-here\n",
        &["--", "true"],
    );
    fails(&output);
    assert!(
        stderr(&output).contains("nothing-here"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn an_export_from_another_manager_is_imported_with_its_secrets() {
    let sandbox = Sandbox::new("import");
    sandbox.init();
    let csv = sandbox.root.join("export.csv");
    std::fs::write(
        &csv,
        "title,url,username,password,notes\nGitHub,https://github.com,octocat,hunter2,2fa\n",
    )
    .unwrap();
    let path = csv.to_str().unwrap();

    let dry = sandbox.vault(&["import", path, "--dry-run"]);
    assert!(
        stderr(&dry).contains("1 entries to import"),
        "{}",
        stderr(&dry)
    );
    assert!(!stdout(&sandbox.vault(&["list", "personal"])).contains("GitHub"));

    succeeds(&sandbox.vault(&["import", path, "--remove-source"]));
    assert!(!csv.exists(), "the plaintext export is gone");
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "GitHub", "--print"])).trim(),
        "hunter2"
    );
    // A second import numbers the clashing name instead of replacing it.
    std::fs::write(&csv, "title,password\nGitHub,other\n").unwrap();
    succeeds(&sandbox.vault(&["import", path]));
    assert!(stdout(&sandbox.vault(&["list", "personal"])).contains("GitHub (2)"));
}

#[test]
fn an_env_file_is_imported_as_secrets() {
    let sandbox = Sandbox::new("import-env");
    sandbox.init();
    let env = sandbox.root.join("app.env");
    std::fs::write(&env, "export OPENAI_API_KEY=sk-test\n").unwrap();
    succeeds(&sandbox.vault(&["import", env.to_str().unwrap(), "--into", "personal"]));
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "OPENAI_API_KEY", "--print"])).trim(),
        "sk-test"
    );
}

#[test]
fn an_export_is_an_age_file_any_age_tool_opens() {
    use std::io::Read;

    let sandbox = Sandbox::new("export");
    sandbox.init();
    succeeds(&sandbox.vault_piped(&["add", "github", "--secret-from-stdin"], "hunter2\n"));
    let key = age::x25519::Identity::generate();
    let output = sandbox.root.join("backup.age");
    succeeds(&sandbox.vault(&[
        "export",
        "--to",
        &key.to_public().to_string(),
        "--output",
        output.to_str().unwrap(),
    ]));

    let encrypted = std::fs::read(&output).unwrap();
    let decryptor = age::Decryptor::new(&encrypted[..]).unwrap();
    let mut json = String::new();
    decryptor
        .decrypt(std::iter::once(&key as &dyn age::Identity))
        .unwrap()
        .read_to_string(&mut json)
        .unwrap();
    let document: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(document["format"], "txc-export");
    let entry = &document["vaults"][0]["entries"][0];
    assert_eq!(entry["name"], "github");
    assert!(
        entry["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field["value"] == "hunter2" && field["secret"] == true)
    );

    // An existing file is never replaced.
    fails(&sandbox.vault(&[
        "export",
        "--to",
        &age::x25519::Identity::generate().to_public().to_string(),
        "--output",
        output.to_str().unwrap(),
    ]));
}

#[test]
fn a_plaintext_export_needs_a_person_to_confirm_it() {
    let sandbox = Sandbox::new("export-plain");
    sandbox.init();
    let output = sandbox.root.join("plain.json");
    let result = sandbox.vault(&[
        "export",
        "--plaintext",
        "--output",
        output.to_str().unwrap(),
    ]);
    fails(&result);
    assert!(!output.exists());
}

// ------------------------------------------------------------ synced vaults --

impl Sandbox {
    /// A shared sync folder, the same directory for every device in a test.
    fn folder(&self) -> PathBuf {
        let folder = self.root.join("sync");
        std::fs::create_dir_all(&folder).unwrap();
        folder
    }

    /// Marks the recovery kit as written down, which the terminal-only
    /// `recovery print` does, so pairing is allowed.
    fn kit_written(&self, home: &Path, vault: &str) {
        std::fs::remove_file(home.join("synced").join(vault).join("recovery.age")).unwrap();
    }

    /// Starts `txc vault` with piped standard input and output, for pairing.
    fn spawn(&self, home: &Path, args: &[&str]) -> Child {
        Command::new(BIN)
            .arg("vault")
            .arg("--home")
            .arg(home)
            .arg("--passphrase-file")
            .arg(self.root.join("pass"))
            .args(args)
            .env("TXC_VAULT_TEST_WORK_FACTOR", "10")
            .env("XDG_RUNTIME_DIR", self.private("run"))
            .env("TMPDIR", self.private("tmp"))
            .env("LOCALAPPDATA", self.private("local"))
            .env("TXC_VAULT_TEST_KEYSTORE", self.private("keystore"))
            .env_remove("TXC_VAULT_HOME")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("txc starts")
    }
}

/// Reads one line a pairing process printed.
fn line_from(reader: &mut impl std::io::BufRead) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    line.trim().to_owned()
}

/// Reads standard error until the code line, and returns the code.
fn code_from(reader: &mut impl std::io::BufRead) -> String {
    loop {
        let mut line = String::new();
        assert!(
            reader.read_line(&mut line).unwrap() > 0,
            "the process ended without showing a code"
        );
        if let Some(code) = line.trim().strip_prefix("This screen shows the code: ") {
            return code.to_owned();
        }
    }
}

#[test]
fn a_synced_vault_does_the_everyday_verbs_and_says_what_needs_doing() {
    let sandbox = Sandbox::new("synced-first-run");
    let folder = sandbox.folder();
    succeeds(&sandbox.vault(&["init", "--folder", folder.to_str().unwrap()]));
    // The folder holds objects only: random names, nothing readable.
    let objects: Vec<String> = std::fs::read_dir(folder.join("objects"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(objects.len() >= 2 && objects.iter().all(|name| name.len() == 64));

    let status = succeeds(&sandbox.vault(&["status"]));
    assert!(
        status.contains("● green   vault \"personal\", 1 device"),
        "{status}"
    );
    assert!(
        status.contains("● yellow  recovery sheets not written down"),
        "{status}"
    );
    assert_eq!(status.lines().count(), 2, "{status}");
    if cfg!(target_os = "linux") {
        // Landlock and seccomp are both in place here, so --all adds only
        // that no security key holds this device's keys.
        let all = succeeds(&sandbox.vault(&["status", "--all"]));
        assert_eq!(all.lines().count(), 3, "{all}");
        assert!(all.contains("no security key"), "{all}");
    }

    succeeds(&sandbox.vault_piped(
        &[
            "add",
            "github",
            "--username",
            "octocat",
            "--secret-from-stdin",
        ],
        "hunter2",
    ));
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "--print", "github"])),
        "hunter2"
    );
    let shown = succeeds(&sandbox.vault(&["show", "github"]));
    assert!(
        shown.contains("octocat") && !shown.contains("hunter2"),
        "{shown}"
    );
    assert_eq!(
        succeeds(&sandbox.vault(&["list"])).trim(),
        "personal (synced)"
    );
    assert!(succeeds(&sandbox.vault(&["list", "personal"])).contains("github"));

    succeeds(&sandbox.vault(&["edit", "github", "--username", "hubot"]));
    succeeds(&sandbox.vault(&["edit", "github", "--tag", "work"]));
    succeeds(&sandbox.vault(&["favourite", "github"]));
    let shown = succeeds(&sandbox.vault(&["show", "github"]));
    assert!(shown.contains("work") && shown.contains("★"), "{shown}");
    assert!(succeeds(&sandbox.vault(&["list", "personal", "--favourites"])).contains("github"));
    assert!(!succeeds(&sandbox.vault(&["list", "personal", "--tag", "home"])).contains("github"));
    assert!(succeeds(&sandbox.vault(&["show", "github"])).contains("hubot"));
    if cfg!(unix) {
        let ran = succeeds(&sandbox.vault(&[
            "run",
            "--set",
            "TOKEN=txc://personal/github",
            "--",
            "sh",
            "-c",
            "printf %s \"$TOKEN\"",
        ]));
        assert_eq!(ran, "hunter2");
    }

    // No name or secret is readable anywhere in the home or the folder.
    for (path, bytes) in every_file(&sandbox.root) {
        if path.starts_with(sandbox.root.join("pass"))
            || path.starts_with(sandbox.root.join("write-pass"))
        {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("hunter2") && !text.contains("octocat"),
            "{}",
            path.display()
        );
    }

    let report = succeeds(&sandbox.vault(&["doctor"]));
    assert!(
        report.contains("devices: 1") && !report.contains("github"),
        "{report}"
    );
    let compared = succeeds(&sandbox.vault(&["compare"]));
    assert!(compared.contains("(this device)"), "{compared}");
    let removed = stderr(&sandbox.vault(&["rm", "--yes", "github"]));
    assert!(removed.contains("txc vault restore"), "{removed}");
    fails(&sandbox.vault(&["copy", "--print", "github"]));
    let listed = succeeds(&sandbox.vault(&["list", "personal", "--removed"]));
    assert!(listed.contains("github"), "{listed}");
    succeeds(&sandbox.vault(&["restore", "github"]));
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "--print", "github"])),
        "hunter2"
    );
    assert!(!succeeds(&sandbox.vault(&["list", "personal", "--removed"])).contains("github"));
    fails(&sandbox.vault(&["restore", "github"]));
    succeeds(&sandbox.vault(&["rm", "--yes", "github"]));
    // Pairing waits for the recovery sheets.
    let refused = fails(&sandbox.vault(&["device", "add"]));
    assert!(refused.contains("recovery sheets"), "{refused}");
}

#[test]
fn two_devices_pair_through_pasted_lines_and_a_code_and_share_entries() {
    use std::io::{BufReader, Write as _};

    let sandbox = Sandbox::new("synced-pair");
    let folder = sandbox.folder();
    let (home_a, home_b) = (sandbox.root.join("home-a"), sandbox.root.join("home-b"));
    succeeds(&sandbox.vault_with(
        &home_a,
        &sandbox.root.join("pass"),
        &["init", "--folder", folder.to_str().unwrap()],
        None,
    ));
    sandbox.kit_written(&home_a, "personal");
    succeeds(&sandbox.vault_with(
        &home_a,
        &sandbox.root.join("pass"),
        &["add", "mail", "--secret-from-stdin"],
        Some("s3cret"),
    ));

    let mut admin = sandbox.spawn(&home_a, &["device", "add"]);
    let mut admin_out = BufReader::new(admin.stdout.take().unwrap());
    let mut admin_err = BufReader::new(admin.stderr.take().unwrap());
    let mut admin_in = admin.stdin.take().unwrap();
    let mut device = sandbox.spawn(&home_b, &["join", "--folder", folder.to_str().unwrap()]);
    let mut device_out = BufReader::new(device.stdout.take().unwrap());
    let mut device_err = BufReader::new(device.stderr.take().unwrap());
    let mut device_in = device.stdin.take().unwrap();

    writeln!(device_in, "{}", line_from(&mut admin_out)).unwrap();
    writeln!(admin_in, "{}", line_from(&mut device_out)).unwrap();
    writeln!(device_in, "{}", line_from(&mut admin_out)).unwrap();
    let admin_code = code_from(&mut admin_err);
    let device_code = code_from(&mut device_err);
    assert_eq!(admin_code.len(), 7);
    // Each person types the code the other screen shows.
    writeln!(admin_in, "{device_code}").unwrap();
    writeln!(device_in, "{admin_code}").unwrap();
    drop((admin_in, device_in));
    assert!(admin.wait().unwrap().success());
    assert!(device.wait().unwrap().success());

    let pass = sandbox.root.join("pass");
    assert_eq!(
        succeeds(&sandbox.vault_with(&home_b, &pass, &["copy", "--print", "mail"], None)),
        "s3cret"
    );
    succeeds(&sandbox.vault_with(
        &home_b,
        &pass,
        &["add", "bank", "--secret-from-stdin"],
        Some("pin"),
    ));
    assert_eq!(
        succeeds(&sandbox.vault_with(&home_a, &pass, &["copy", "--print", "bank"], None)),
        "pin"
    );
    // Both devices see the same history: every checkpoint both hold shows
    // the same digest on each.
    let digests = |home: &Path| -> std::collections::BTreeMap<String, String> {
        succeeds(&sandbox.vault_with(home, &pass, &["compare"], None))
            .lines()
            .skip(1)
            .map(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                (words[0].to_owned(), words[words.len() - 3..].join(" "))
            })
            .collect()
    };
    let (seen_a, seen_b) = (digests(&home_a), digests(&home_b));
    let shared: Vec<&String> = seen_a
        .keys()
        .filter(|id| seen_b.contains_key(*id))
        .collect();
    assert!(!shared.is_empty(), "{seen_a:?} {seen_b:?}");
    for id in shared {
        assert_eq!(seen_a[id], seen_b[id]);
    }
    let devices = succeeds(&sandbox.vault_with(&home_a, &pass, &["device", "list"], None));
    assert_eq!(devices.lines().count(), 3, "{devices}");

    // Removing the second device with --wipe flags what it could read, and
    // it wipes its keys when it next opens the vault.
    let other = devices
        .lines()
        .skip(1)
        .find(|line| !line.contains("this device"))
        .and_then(|line| line.split_whitespace().next())
        .unwrap()
        .to_owned();
    let removed = stderr(&sandbox.vault_with(
        &home_a,
        &pass,
        &["device", "remove", &other, "--wipe", "--yes"],
        None,
    ));
    assert!(removed.contains("--stale"), "{removed}");
    let stale =
        succeeds(&sandbox.vault_with(&home_a, &pass, &["list", "personal", "--stale"], None));
    assert!(stale.contains("mail") && stale.contains("bank"), "{stale}");
    let status = succeeds(&sandbox.vault_with(&home_a, &pass, &["status"], None));
    assert!(
        status.contains("2 entries a removed device could read"),
        "{status}"
    );
    succeeds(&sandbox.vault_with(
        &home_a,
        &pass,
        &["edit", "mail", "--secret-from-stdin"],
        Some("new-mail"),
    ));
    let stale =
        succeeds(&sandbox.vault_with(&home_a, &pass, &["list", "personal", "--stale"], None));
    assert!(!stale.contains("mail") && stale.contains("bank"), "{stale}");
    let wiped = fails(&sandbox.vault_with(&home_b, &pass, &["list", "personal"], None));
    assert!(wiped.contains("wipe its keys"), "{wiped}");
    assert!(!home_b.join("synced").join("personal").exists());
}

#[test]
fn a_vault_migrates_into_a_synced_vault_and_the_old_one_stays() {
    let sandbox = Sandbox::new("synced-migrate");
    sandbox.init();
    succeeds(&sandbox.vault_piped(
        &[
            "add",
            "github",
            "--username",
            "octocat",
            "--tag",
            "code",
            "--favourite",
            "--secret-from-stdin",
        ],
        "hunter2",
    ));
    let folder = sandbox.folder();
    succeeds(&sandbox.vault(&[
        "migrate",
        "personal",
        "--folder",
        folder.to_str().unwrap(),
        "--name",
        "work",
    ]));
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "--print", "work/github"])),
        "hunter2"
    );
    let shown = succeeds(&sandbox.vault(&["show", "work/github"]));
    assert!(shown.contains("octocat"), "{shown}");
    assert!(shown.contains("code"), "tags are carried over: {shown}");
    assert!(shown.contains('★'), "the star is carried over: {shown}");
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "--print", "personal/github"])),
        "hunter2"
    );
    // Migrating again copies nothing twice.
    succeeds(&sandbox.vault(&["migrate", "personal", "--name", "work"]));
    assert_eq!(
        succeeds(&sandbox.vault(&["list", "work"]))
            .matches("github")
            .count(),
        1
    );
}

#[test]
fn a_synced_grant_opens_for_its_runner_against_the_pinned_vault_id() {
    use age::secrecy::ExposeSecret;

    let sandbox = Sandbox::new("synced-grant");
    let folder = sandbox.folder();
    succeeds(&sandbox.vault(&["init", "--folder", folder.to_str().unwrap()]));
    succeeds(&sandbox.vault_piped(
        &["add", "deploy", "--kind", "api-key", "--secret-from-stdin"],
        "tok-123",
    ));

    let runner = txc::vault::pq::Identity::generate();
    let key = sandbox.root.join("runner.key");
    std::fs::write(&key, format!("{}\n", runner.to_string().expose_secret())).unwrap();
    let issued = sandbox.vault(&[
        "grant",
        "deploy",
        "--to",
        &runner.to_public().to_string(),
        "--origin",
        "ci",
    ]);
    succeeds(&issued);
    let grant = sandbox.root.join("deploy.grant");
    std::fs::write(&grant, &issued.stdout).unwrap();
    let said = stderr(&issued);
    let vault_id = said
        .split_whitespace()
        .skip_while(|word| *word != "--vault-id")
        .nth(1)
        .unwrap()
        .to_owned();
    let (grant, key) = (grant.to_str().unwrap(), key.to_str().unwrap());

    let redeemed = sandbox.vault(&["redeem", grant, "--identity", key, "--vault-id", &vault_id]);
    assert_eq!(succeeds(&redeemed), "tok-123");
    fails(&sandbox.vault(&[
        "redeem",
        grant,
        "--identity",
        key,
        "--vault-id",
        &"0".repeat(96),
    ]));
    fails(&sandbox.vault(&[
        "redeem",
        grant,
        "--identity",
        key,
        "--vault-id",
        &vault_id,
        "--min-version",
        "99999999999",
    ]));
    let other = sandbox.root.join("other.key");
    std::fs::write(
        &other,
        format!(
            "{}\n",
            txc::vault::pq::Identity::generate()
                .to_string()
                .expose_secret()
        ),
    )
    .unwrap();
    fails(&sandbox.vault(&[
        "redeem",
        grant,
        "--identity",
        other.to_str().unwrap(),
        "--vault-id",
        &vault_id,
    ]));
}

#[test]
#[cfg(unix)]
fn ssh_gets_a_fresh_key_and_a_short_certificate_from_a_ca_that_never_leaves() {
    use std::os::unix::fs::PermissionsExt;

    if Command::new("ssh-keygen").arg("-?").output().is_err() {
        return eprintln!("ssh-keygen is not installed; skipped");
    }
    let sandbox = Sandbox::new("synced-ssh");
    let folder = sandbox.folder();
    succeeds(&sandbox.vault(&["init", "--folder", folder.to_str().unwrap()]));
    let setup = succeeds(&sandbox.vault(&["ssh-ca", "infra"]));
    assert!(setup.starts_with("ssh-ed25519 "), "{setup}");
    let public = sandbox.root.join("ca.pub");
    std::fs::write(&public, &setup).unwrap();
    let fingerprint = String::from_utf8(
        Command::new("ssh-keygen")
            .arg("-lf")
            .arg(&public)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let fingerprint = fingerprint.split_whitespace().nth(1).unwrap().to_owned();

    // The CA key is never released.
    fails(&sandbox.vault(&["copy", "--print", "infra"]));
    fails(&sandbox.vault(&["grant", "infra", "--to", "age1pq1x"]));
    assert!(succeeds(&sandbox.vault(&["show", "infra"])).contains("••••"));

    // A stand-in for ssh that checks what it was given with OpenSSH itself.
    let fake = sandbox.root.join("fake-ssh");
    std::fs::write(
        &fake,
        "#!/bin/sh\nset -e\nkey=\"$2\"\ncert=\"${4#CertificateFile=}\"\n\
         ssh-keygen -L -f \"$cert\"\nssh-keygen -y -f \"$key\" >/dev/null\necho \"host $7\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
    let shown = succeeds(&sandbox.vault(&[
        "ssh",
        "--user",
        "deploy",
        "--minutes",
        "2",
        "server.example",
    ]));
    assert!(
        shown.contains(&format!("Signing CA: ED25519 {fingerprint}")),
        "{shown}"
    );
    assert!(shown.contains("deploy"), "{shown}");
    assert!(
        shown.contains("Type: ssh-ed25519-cert-v01@openssh.com user certificate"),
        "{shown}"
    );
    assert!(shown.contains("host server.example"), "{shown}");
}

#[test]
fn the_keyholder_process_holds_a_synced_vault_and_releases_one_secret_at_a_time() {
    use age::secrecy::{ExposeSecret, SecretString};
    use txc::vault::keyholder::Holder;

    let sandbox = Sandbox::new("keyholder");
    let folder = sandbox.folder();
    succeeds(&sandbox.vault(&["init", "--folder", folder.to_str().unwrap()]));
    succeeds(&sandbox.vault_piped(
        &[
            "add",
            "github",
            "--username",
            "octocat",
            "--secret-from-stdin",
        ],
        "hunter2",
    ));

    let mut command = Command::new(BIN);
    command
        .arg("vault")
        .arg("--home")
        .arg(sandbox.home())
        .arg("keyholder")
        .env("TXC_VAULT_TEST_WORK_FACTOR", "10")
        .env("XDG_RUNTIME_DIR", sandbox.private("run"))
        .env("TXC_VAULT_TEST_KEYSTORE", sandbox.private("keystore"));
    let passphrase = SecretString::from(PASSPHRASE.to_owned());
    let mut holder = Holder::start(command, "personal", Some(&passphrase)).unwrap();

    let entries = holder.entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].plain("username"), Some("octocat"));
    assert!(!serde_json::to_string(&entries).unwrap().contains("hunter2"));
    assert_eq!(
        holder.reveal("github", "password").unwrap().expose_secret(),
        "hunter2"
    );
    // The screen's status lines come from the keyholder, as the CLI's do.
    assert!(
        holder
            .status()
            .unwrap()
            .iter()
            .any(|line| line.contains("recovery sheets"))
    );
    assert!(holder.classes().unwrap().is_empty());

    // On Linux the keyholder has confined itself: seccomp is on.
    #[cfg(target_os = "linux")]
    {
        let pid = holder.process_id().unwrap();
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(
            status
                .lines()
                .any(|line| line.starts_with("Seccomp:") && line.ends_with('2')),
            "{status}"
        );
    }

    let new = txc::vault::NewEntry {
        name: "bank".into(),
        kind: txc::vault::model::Kind::Login,
        plain: Vec::new(),
        secrets: vec![("password".into(), SecretString::from("1234".to_owned()))],
        tags: Vec::new(),
        favourite: false,
    };
    holder.add(&new).unwrap();
    drop(holder);
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "--print", "bank"])),
        "1234"
    );
}

#[test]
fn a_password_in_an_imported_breach_list_is_reported_offline() {
    use sha1::{Digest, Sha1};

    let sandbox = Sandbox::new("breach");
    let folder = sandbox.folder();
    succeeds(&sandbox.vault(&["init", "--folder", folder.to_str().unwrap()]));
    succeeds(&sandbox.vault_piped(&["add", "weak", "--secret-from-stdin"], "password"));
    succeeds(&sandbox.vault_piped(&["add", "strong", "--secret-from-stdin"], "xq7-Vt!9s-wP2e"));

    let list = sandbox.root.join("pwned.txt");
    let lines: Vec<String> = ["password", "123456", "qwerty"]
        .iter()
        .map(|leaked| {
            format!(
                "{}:1000",
                data_encoding::HEXUPPER.encode(&Sha1::digest(leaked.as_bytes()))
            )
        })
        .collect();
    std::fs::write(&list, lines.join("\n")).unwrap();
    succeeds(&sandbox.vault(&["breach", "import", list.to_str().unwrap()]));

    let found = succeeds(&sandbox.vault(&["breach", "check"]));
    assert!(found.contains("weak: password"), "{found}");
    assert!(!found.contains("strong"), "{found}");
    let status = succeeds(&sandbox.vault(&["status"]));
    assert!(
        status.contains("1 password is in the breach list"),
        "{status}"
    );
}

#[test]
fn a_synced_vault_imports_in_one_change_and_exports_to_a_post_quantum_key() {
    use std::io::Read as _;

    let sandbox = Sandbox::new("synced-import-export");
    let folder = sandbox.folder();
    succeeds(&sandbox.vault(&["init", "--folder", folder.to_str().unwrap()]));
    let env = sandbox.root.join("app.env");
    std::fs::write(&env, "API_TOKEN=tok-1\nDB_PASSWORD=pw-2\n").unwrap();
    let before = std::fs::read_dir(folder.join("objects")).unwrap().count();
    succeeds(&sandbox.vault(&["import", env.to_str().unwrap(), "--into", "personal"]));
    let after = std::fs::read_dir(folder.join("objects")).unwrap().count();
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "--print", "API_TOKEN"])),
        "tok-1"
    );
    // One object for the whole import, plus this device's sender key and
    // checkpoint bookkeeping at most.
    assert!(after - before <= 3, "{before} -> {after}");
    succeeds(&sandbox.vault(&["ssh-ca", "infra"]));

    let key = txc::vault::pq::Identity::generate();
    let exported = sandbox.vault(&["export", "personal", "--to", &key.to_public().to_string()]);
    succeeds(&exported);
    let decryptor = age::Decryptor::new(exported.stdout.as_slice()).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(&key as &dyn age::Identity))
        .unwrap();
    let mut json = String::new();
    reader.read_to_string(&mut json).unwrap();
    assert!(json.contains("pw-2"), "{json}");
    assert!(
        !json.contains("infra"),
        "an operation-only entry was exported"
    );
    assert!(stderr(&exported).contains("infra"));
}

#[test]
fn format_details_live_under_advanced_and_create_makes_a_second_synced_vault() {
    let sandbox = Sandbox::new("advanced");
    sandbox.init();
    let help = succeeds(&sandbox.vault(&["--help"]));
    assert!(
        help.contains("advanced") && !help.contains("  writers "),
        "{help}"
    );
    // The grouped spelling and the old one both still work.
    let grouped = succeeds(&sandbox.vault(&["advanced", "identity"]));
    assert_eq!(grouped, succeeds(&sandbox.vault(&["identity"])));

    let (first, second) = (sandbox.root.join("sync-one"), sandbox.root.join("sync-two"));
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    succeeds(&sandbox.vault(&[
        "init",
        "--folder",
        first.to_str().unwrap(),
        "--name",
        "home",
    ]));
    succeeds(&sandbox.vault(&["create", "work", "--folder", second.to_str().unwrap()]));
    let listed = succeeds(&sandbox.vault(&["list"]));
    assert!(
        listed.contains("home (synced)")
            && listed.contains("work (synced)")
            && listed.contains("personal"),
        "{listed}"
    );
}

#[test]
fn passwd_changes_the_identity_and_the_synced_vaults_it_opens() {
    let sandbox = Sandbox::new("passwd-synced");
    sandbox.init();
    let (one, two) = (sandbox.root.join("sync-one"), sandbox.root.join("sync-two"));
    std::fs::create_dir_all(&one).unwrap();
    std::fs::create_dir_all(&two).unwrap();
    succeeds(&sandbox.vault(&["create", "home", "--folder", one.to_str().unwrap()]));
    succeeds(&sandbox.vault_piped(&["add", "home/mail", "--secret-from-stdin"], "s3cret"));
    let other = sandbox.passphrase_file("other-pass", "a different passphrase for work");
    succeeds(&sandbox.vault_with(
        &sandbox.home(),
        &other,
        &["create", "work", "--folder", two.to_str().unwrap()],
        None,
    ));

    let new = sandbox.passphrase_file("new-pass", "a brand new passphrase for both");
    let changed = sandbox.vault(&["passwd", "--new-passphrase-file", new.to_str().unwrap()]);
    succeeds(&changed);
    let said = stderr(&changed);
    assert!(
        said.contains("your identity")
            && said.contains("home")
            && said.contains("work keeps its own"),
        "{said}"
    );

    let home = sandbox.home();
    fails(&sandbox.vault(&["copy", "--print", "--no-session", "home/mail"]));
    assert_eq!(
        succeeds(&sandbox.vault_with(
            &home,
            &new,
            &["copy", "--print", "--no-session", "home/mail"],
            None
        )),
        "s3cret"
    );
    succeeds(&sandbox.vault_with(&home, &new, &["advanced", "identity"], None));
    // The vault with its own passphrase is unchanged, and --vault changes only it.
    succeeds(&sandbox.vault_with(&home, &other, &["list", "work", "--no-session"], None));
    let third = sandbox.passphrase_file("third-pass", "yet another passphrase for work");
    succeeds(&sandbox.vault_with(
        &home,
        &other,
        &[
            "passwd",
            "--vault",
            "work",
            "--new-passphrase-file",
            third.to_str().unwrap(),
        ],
        None,
    ));
    succeeds(&sandbox.vault_with(&home, &third, &["list", "work", "--no-session"], None));
    fails(&sandbox.vault_with(&home, &other, &["list", "work", "--no-session"], None));
}

#[test]
fn two_sheets_and_the_card_rehearse_and_restore_a_vault_from_its_folder() {
    let sandbox = Sandbox::new("synced-recovery");
    let folder = sandbox.folder();
    succeeds(&sandbox.vault(&["init", "--folder", folder.to_str().unwrap()]));
    succeeds(&sandbox.vault_piped(
        &[
            "add",
            "github",
            "--username",
            "octocat",
            "--tag",
            "code",
            "--secret-from-stdin",
        ],
        "hunter2",
    ));
    let kit = succeeds(&sandbox.vault(&["recovery", "print"]));
    let kit: Vec<&str> = kit.lines().collect();
    assert_eq!(kit.len(), 4, "three sheets and a card");
    let (sheets, card) = (&kit[..3], kit[3]);

    let drilled = stderr(&sandbox.vault_piped(
        &["recovery", "drill"],
        &format!("{}\n{}\n{card}\n", sheets[0], sheets[2]),
    ));
    assert!(
        drilled.contains("Drill passed: sheets 1 and 3"),
        "{drilled}"
    );
    assert!(drilled.contains("of 1 entries"), "{drilled}");
    let refused = fails(&sandbox.vault_piped(
        &["recovery", "drill"],
        &format!("{}\n{}\n{card}\n", sheets[0], sheets[0]),
    ));
    assert!(refused.contains("do not combine"), "{refused}");
    fails(&sandbox.vault_piped(
        &["recovery", "drill"],
        &format!("{}\n{}\nwrong card words\n", sheets[0], sheets[1]),
    ));

    let new_folder = sandbox.root.join("sync-new");
    std::fs::create_dir_all(&new_folder).unwrap();
    let restored = stderr(&sandbox.vault_piped(
        &[
            "recovery",
            "restore",
            "restored",
            "--from",
            folder.to_str().unwrap(),
            "--folder",
            new_folder.to_str().unwrap(),
        ],
        &format!("{}\n{}\n{card}\n", sheets[1], sheets[2]),
    ));
    assert!(restored.contains("Restored 1 entries"), "{restored}");
    assert_eq!(
        succeeds(&sandbox.vault(&["copy", "--print", "restored/github"])),
        "hunter2"
    );
    let shown = succeeds(&sandbox.vault(&["show", "restored/github"]));
    assert!(
        shown.contains("octocat") && shown.contains("code"),
        "{shown}"
    );
    // The restored vault has sheets of its own, and the old ones do not
    // read it.
    let new_kit = succeeds(&sandbox.vault(&["recovery", "print", "restored"]));
    assert_eq!(new_kit.lines().count(), 4);
    assert!(!new_kit.contains(sheets[0]));
    fails(&sandbox.vault_piped(
        &["recovery", "drill", "restored"],
        &format!("{}\n{}\n{card}\n", sheets[0], sheets[1]),
    ));
}

#[test]
fn reissued_sheets_replace_the_old_ones_for_everything_written_afterwards() {
    let sandbox = Sandbox::new("synced-reissue");
    let folder = sandbox.folder();
    succeeds(&sandbox.vault(&["init", "--folder", folder.to_str().unwrap()]));
    succeeds(&sandbox.vault_piped(&["add", "github", "--secret-from-stdin"], "hunter2"));
    let old = succeeds(&sandbox.vault(&["recovery", "print"]));
    let old: Vec<String> = old.lines().map(str::to_owned).collect();
    let old_card = old[3].clone();
    succeeds(&sandbox.vault_piped(&["recovery", "check"], &format!("{}\n{old_card}\n", old[1])));

    succeeds(&sandbox.vault_piped(
        &["recovery", "reissue"],
        &format!("{}\n{}\n{old_card}\n", old[0], old[2]),
    ));
    let status = succeeds(&sandbox.vault(&["status"]));
    assert!(
        status.contains("recovery sheets not written down"),
        "{status}"
    );
    let new = succeeds(&sandbox.vault(&["recovery", "print"]));
    let new: Vec<String> = new.lines().map(str::to_owned).collect();
    assert_eq!(new.len(), 4);
    assert!(new.iter().all(|line| !old.contains(line)));
    let new_card = new[3].clone();

    // The old sheets no longer check, sign or read what comes next.
    fails(&sandbox.vault_piped(&["recovery", "check"], &format!("{}\n{old_card}\n", old[1])));
    succeeds(&sandbox.vault_piped(&["recovery", "check"], &format!("{}\n{new_card}\n", new[1])));
    fails(&sandbox.vault_piped(
        &["recovery", "reissue"],
        &format!("{}\n{}\n{old_card}\n", old[0], old[1]),
    ));
    succeeds(&sandbox.vault_piped(&["add", "later", "--secret-from-stdin"], "s3cret"));

    let with_new = stderr(&sandbox.vault_piped(
        &["recovery", "drill"],
        &format!("{}\n{}\n{new_card}\n", new[0], new[2]),
    ));
    assert!(with_new.contains("of 2 entries"), "{with_new}");
    let with_old = stderr(&sandbox.vault_piped(
        &["recovery", "drill"],
        &format!("{}\n{}\n{old_card}\n", old[0], old[2]),
    ));
    // At most what came before; once the snapshot the reissue wrote is
    // collected, not even that.
    assert!(
        !with_old.contains("of 2 entries"),
        "the old sheets never read what came after: {with_old}"
    );
}

#[test]
fn root_actions_take_the_sheets_and_forget_leaves_the_folder_alone() {
    let sandbox = Sandbox::new("synced-root");
    let folder = sandbox.folder();
    succeeds(&sandbox.vault(&["init", "--folder", folder.to_str().unwrap()]));
    let kit = succeeds(&sandbox.vault(&["recovery", "print"]));
    let kit: Vec<&str> = kit.lines().collect();
    let listed = succeeds(&sandbox.vault(&["device", "list"]));
    let me = listed
        .lines()
        .find(|line| line.contains("this device"))
        .and_then(|line| line.split_whitespace().next())
        .unwrap()
        .to_owned();
    let allowed = stderr(&sandbox.vault_piped(
        &["device", "allow", &me, "--more", "2"],
        &format!("{}\n{}\n{}\n", kit[0], kit[2], kit[3]),
    ));
    assert!(allowed.contains("may add more"), "{allowed}");
    let receipt = allowed
        .split("--receipt ")
        .nth(1)
        .unwrap()
        .trim()
        .to_owned();
    let checked = stderr(&sandbox.vault(&["compare", "--receipt", &receipt]));
    assert!(
        checked.contains("a change to the devices or keys"),
        "{checked}"
    );
    fails(&sandbox.vault(&["compare", "--receipt", "0123456789abcdef"]));
    fails(&sandbox.vault_piped(
        &["device", "allow", &me, "--more", "2"],
        &format!("{}\n{}\nwrong card words\n", kit[0], kit[2]),
    ));
    fails(&sandbox.vault(&["hardware", "remove", "nothing-by-that-name"]));

    let before = std::fs::read_dir(&folder).unwrap().count();
    succeeds(&sandbox.vault(&["device", "forget", "--yes"]));
    assert!(!succeeds(&sandbox.vault(&["list"])).contains("personal"));
    assert_eq!(std::fs::read_dir(&folder).unwrap().count(), before);
}
