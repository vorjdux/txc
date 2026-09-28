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
