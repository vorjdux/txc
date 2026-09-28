//! Cross-implementation checks against Go age, the reference implementation
//! of the `mlkem768x25519` recipient type txc composes itself (study
//! sections 6 and 13).
//!
//! These run only when `TXC_AGE_DIR` names a directory holding the `age` and
//! `age-keygen` binaries of age 1.3 or later; CI downloads them. Without it
//! each test says so and passes, so a plain `cargo test` needs no Go.

#![cfg(feature = "vault")]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use age::secrecy::ExposeSecret;
use txc::vault::authority::recovery_identity;
use txc::vault::composite::SigningKey;
use txc::vault::object::{Addressing, Kind, Payload, Signed, open_control, seal_control};
use txc::vault::pq;

fn age_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("TXC_AGE_DIR")?);
    assert!(
        dir.join("age").exists() || dir.join("age.exe").exists(),
        "TXC_AGE_DIR has no age binary"
    );
    Some(dir)
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("txc-age-{label}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(dir: &Path, program: &str, args: &[&str], input: &[u8]) -> Vec<u8> {
    let mut child = Command::new(dir.join(program))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("{program} does not start: {error}"));
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn encrypt(recipient: &pq::Recipient, plain: &[u8]) -> Vec<u8> {
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient)).unwrap();
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).unwrap();
    writer.write_all(plain).unwrap();
    writer.finish().unwrap();
    out
}

fn decrypt(identity: &pq::Identity, sealed: &[u8]) -> Vec<u8> {
    let decryptor = age::Decryptor::new(sealed).unwrap();
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .unwrap();
    let mut out = Vec::new();
    reader.read_to_end(&mut out).unwrap();
    out
}

#[test]
fn keys_mean_the_same_to_txc_and_go_age() {
    let Some(dir) = age_dir() else {
        return eprintln!("TXC_AGE_DIR is not set; skipped");
    };
    let scratch = Scratch::new("keys");

    // A key Go age made, read by txc.
    let key = scratch.0.join("go.key");
    run(
        &dir,
        "age-keygen",
        &["-pq", "-o", key.to_str().unwrap()],
        b"",
    );
    let text = std::fs::read_to_string(&key).unwrap();
    let secret = text
        .lines()
        .find(|line| line.starts_with("AGE-SECRET-KEY-PQ-"))
        .unwrap();
    let identity: pq::Identity = secret.parse().unwrap();
    let go_recipient =
        String::from_utf8(run(&dir, "age-keygen", &["-y", key.to_str().unwrap()], b"")).unwrap();
    assert_eq!(identity.to_public().to_string(), go_recipient.trim());

    // A key txc made, read by Go age.
    let ours = pq::Identity::generate();
    let ours_file = scratch.0.join("txc.key");
    std::fs::write(
        &ours_file,
        format!("{}\n", ours.to_string().expose_secret()),
    )
    .unwrap();
    let derived = String::from_utf8(run(
        &dir,
        "age-keygen",
        &["-y", ours_file.to_str().unwrap()],
        b"",
    ))
    .unwrap();
    assert_eq!(derived.trim(), ours.to_public().to_string());
}

#[test]
fn files_cross_between_txc_and_go_age_both_ways() {
    let Some(dir) = age_dir() else {
        return eprintln!("TXC_AGE_DIR is not set; skipped");
    };
    let scratch = Scratch::new("files");
    let identity = pq::Identity::generate();
    let key = scratch.0.join("txc.key");
    std::fs::write(&key, format!("{}\n", identity.to_string().expose_secret())).unwrap();
    let recipient = identity.to_public().to_string();

    let message = b"sealed by txc, opened by Go age";
    let sealed = encrypt(&identity.to_public(), message);
    assert_eq!(
        run(&dir, "age", &["-d", "-i", key.to_str().unwrap()], &sealed),
        message
    );

    let message = b"sealed by Go age, opened by txc";
    let sealed = run(&dir, "age", &["-r", &recipient], message);
    assert_eq!(decrypt(&identity, &sealed), message);
}

#[test]
fn a_vault_control_object_opens_with_go_age_and_the_recovery_identity() {
    let Some(dir) = age_dir() else {
        return eprintln!("TXC_AGE_DIR is not set; skipped");
    };
    let scratch = Scratch::new("control");

    // The recovery identity is the recovery secret used as the seed, so
    // standard tools can rebuild it from two sheets and the card.
    let recovery = recovery_identity(&[0x5a; 32]);
    let key = scratch.0.join("recovery.key");
    std::fs::write(&key, format!("{}\n", recovery.to_string().expose_secret())).unwrap();

    let author = SigningKey::generate();
    let payload = Payload {
        genesis: [1; 48],
        kind: Kind::Fact,
        author: [2; 16],
        author_cert: [3; 16],
        seq: 0,
        prev: [0; 48],
        deps: Vec::new(),
        fact_set: [4; 48],
        addressing: Addressing::Control(vec![([5; 16], [6; 16], 0)]),
        body: b"a membership fact".to_vec(),
    };
    let signed = Signed::sign(&payload, &author).unwrap();
    let member = pq::Identity::generate();
    // Two real recipients and two filler stanzas, as every control object.
    let sealed = seal_control(&signed, &[member.to_public(), recovery.to_public()]).unwrap();

    let plain = run(&dir, "age", &["-d", "-i", key.to_str().unwrap()], &sealed);
    let encoded = payload.encode();
    assert!(
        plain
            .windows(encoded.len())
            .any(|window| window == encoded.as_slice())
    );
    assert_eq!(open_control(&sealed, &member).unwrap().unwrap(), signed);
}

/// Answers nothing: age-plugin-pq never asks.
struct Silent;

impl txc::vault::hardware::Prompter for Silent {
    fn message(&self, _text: &str) {}
    fn secret(&self, _question: &str) -> Option<age::secrecy::SecretString> {
        None
    }
    fn public(&self, _question: &str) -> Option<String> {
        None
    }
    fn confirm(&self, _question: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }
}

#[test]
fn a_secret_sealed_through_a_pinned_plugin_opens_through_it_and_a_changed_plugin_is_refused() {
    use txc::vault::hardware::Hardware;

    let Some(dir) = age_dir() else {
        return eprintln!("TXC_AGE_DIR is not set; skipped");
    };
    let scratch = Scratch::new("plugin");
    // age-plugin-pq is a software plugin: it stands in for hardware here,
    // speaking the same protocol a security key's plugin does.
    let native = pq::Identity::generate();
    let recipient = native.to_public().to_string();
    let converted = run(
        &dir,
        "age-plugin-pq",
        &["-identity"],
        format!("{}\n", native.to_string().expose_secret()).as_bytes(),
    );
    let plugin_identity = String::from_utf8(converted)
        .unwrap()
        .lines()
        .find(|line| line.starts_with("AGE-PLUGIN-PQ-"))
        .unwrap()
        .to_owned();
    let plugin = dir.join("age-plugin-pq");
    let hardware =
        Hardware::set_up(&recipient, &plugin_identity, Some(&plugin), Some(&plugin)).unwrap();

    let sealed = hardware.seal(b"second factor", &Silent).unwrap();
    assert_eq!(
        &hardware.open(&sealed, &Silent).unwrap()[..],
        b"second factor"
    );
    // What the plugin sealed is a plain age file Go age opens natively.
    let key = scratch.0.join("native.key");
    std::fs::write(&key, format!("{}\n", native.to_string().expose_secret())).unwrap();
    assert_eq!(
        run(&dir, "age", &["-d", "-i", key.to_str().unwrap()], &sealed),
        b"second factor"
    );

    // A plugin binary that changed after it was pinned is never run.
    let copy = scratch.0.join("age-plugin-pq");
    std::fs::copy(&plugin, &copy).unwrap();
    let pinned = Hardware::set_up(&recipient, &plugin_identity, Some(&copy), Some(&copy)).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&copy)
        .unwrap()
        .write_all(b"tampered")
        .unwrap();
    assert!(pinned.open(&sealed, &Silent).is_err());
    assert!(pinned.seal(b"x", &Silent).is_err());
}

#[test]
fn a_synced_vault_moves_its_second_factor_to_a_plugin_and_needs_it_from_then_on() {
    let Some(dir) = age_dir() else {
        return eprintln!("TXC_AGE_DIR is not set; skipped");
    };
    let scratch = Scratch::new("hardware-vault");
    let (home, folder, keystore, run_dir) = (
        scratch.0.join("home"),
        scratch.0.join("sync"),
        scratch.0.join("keystore"),
        scratch.0.join("run"),
    );
    for path in [&folder, &keystore, &run_dir] {
        std::fs::create_dir_all(path).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let pass = scratch.0.join("pass");
    std::fs::write(&pass, "correct horse battery staple\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let txc = |args: &[&str], input: &[u8]| -> std::process::Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_txc"))
            .arg("vault")
            .arg("--home")
            .arg(&home)
            .arg("--passphrase-file")
            .arg(&pass)
            .args(args)
            .env("TXC_VAULT_TEST_WORK_FACTOR", "10")
            .env("TXC_VAULT_TEST_KEYSTORE", &keystore)
            .env("XDG_RUNTIME_DIR", &run_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    };
    let ok = |output: std::process::Output| {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    ok(txc(&["init", "--folder", folder.to_str().unwrap()], b""));
    ok(txc(&["add", "mail", "--secret-from-stdin"], b"s3cret"));

    // A pinned copy of the plugin stands in for the hardware's.
    let plugin = scratch.0.join("age-plugin-pq");
    std::fs::copy(dir.join("age-plugin-pq"), &plugin).unwrap();
    let native = pq::Identity::generate();
    let converted = run(
        &dir,
        "age-plugin-pq",
        &["-identity"],
        format!("{}\n", native.to_string().expose_secret()).as_bytes(),
    );
    let identity_file = scratch.0.join("hardware.key");
    std::fs::write(&identity_file, converted).unwrap();
    ok(txc(
        &[
            "hardware",
            "add",
            "--recipient",
            &native.to_public().to_string(),
            "--identity-file",
            identity_file.to_str().unwrap(),
            "--recipient-plugin",
            plugin.to_str().unwrap(),
            "--identity-plugin",
            plugin.to_str().unwrap(),
        ],
        b"",
    ));
    assert_eq!(
        std::fs::read_dir(&keystore).unwrap().count(),
        0,
        "the keystore factor was forgotten"
    );
    assert_eq!(ok(txc(&["copy", "--print", "mail"], b"")), "s3cret");

    std::fs::OpenOptions::new()
        .append(true)
        .open(&plugin)
        .unwrap()
        .write_all(b"tampered")
        .unwrap();
    let refused = txc(&["copy", "--print", "mail"], b"");
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("changed"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
}
