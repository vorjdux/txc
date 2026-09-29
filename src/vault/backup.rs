//! Offline backups of a synced vault (study section 12): one plain age
//! file, sealed to the recovery recipient and to the device that wrote it,
//! whose body is the whole vault as documented JSON. With the recovery
//! identity from two sheets and the card, `age -d` alone reads it: no
//! reference script, no sender keys, no txc.
//!
//! A detached signature by the writing device sits beside it, so a backup
//! can be checked against the vault's signed membership before it is
//! trusted.
//!
//! The JSON, `txc-backup-v1`:
//!
//! ```text
//! { "format": "txc-backup-v1", "vault": NAME, "written": RFC 3339,
//!   "entries": [ { "name", "kind", "tags", "favourite", "sensitivity",
//!                  "fields": [ { "name", "value", "secret" }
//!                            | { "name", "protected": BASE64 age file } ] } ],
//!   "removed": [ { "name", "removed": RFC 3339, "fields": [ ... ] } ] }
//! ```
//!
//! A protected field stays sealed as it is in the vault, an age file to the
//! security keys and the recovery recipient: the same identity opens it.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow, ensure};
use zeroize::Zeroizing;

use crate::vault::entries::{Entries, FieldKind, KIND, NAME, STAR, Sensitivity, Slot, TAGS};
use crate::vault::home::{self, Home, PRIVATE};
use crate::vault::synced::{Synced, now};

const FORMAT: &str = "txc-backup-v1";
const SIGNATURE_CONTEXT: &[u8] = b"txc/v1/backup";
const SETTINGS: &str = "backup";
/// How often a backup is written on its own while its folder is present.
pub const EVERY: u64 = 7 * 24 * 60 * 60;
/// How old the last backup may get before status asks for one.
pub const OVERDUE: u64 = 30 * 24 * 60 * 60;

fn stamp(at: u64) -> String {
    i64::try_from(at)
        .ok()
        .and_then(|at| chrono::DateTime::from_timestamp(at, 0))
        .map_or_else(String::new, |at| {
            at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        })
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn field_json(kind: FieldKind, label: &str, value: &[u8]) -> serde_json::Value {
    if kind == FieldKind::Protected {
        serde_json::json!({
            "name": label,
            "protected": data_encoding::BASE64.encode(value),
        })
    } else {
        serde_json::json!({
            "name": label,
            "value": text(value),
            "secret": kind.is_secret(),
        })
    }
}

/// The vault as the backup's JSON, every value decrypted but protected ones.
fn document(vault: &Synced) -> Result<Zeroizing<Vec<u8>>> {
    let entries = vault.entries()?;
    let mut listed = Vec::new();
    for view in entries.list() {
        let mut fields = Vec::new();
        for field in &view.fields {
            let values = entries.reveal(&view.id, &field.id, Slot::Value)?;
            if let Some(value) = values.first() {
                fields.push(field_json(field.kind, &field.label, value));
            }
        }
        listed.push(serde_json::json!({
            "name": view.names.join(" / "),
            "kind": view.kinds.first().cloned().unwrap_or_default(),
            "tags": view.tags,
            "favourite": view.starred,
            "sensitivity": match view.sensitivity {
                Sensitivity::Normal => "normal",
                Sensitivity::High => "protected",
                Sensitivity::RootGrade => "root-grade",
                Sensitivity::OperationOnly => "operation-only",
            },
            "fields": fields,
        }));
    }
    let removed = removed_json(&entries)?;
    let body = serde_json::json!({
        "format": FORMAT,
        "vault": vault.name,
        "written": stamp(now()),
        "entries": listed,
        "removed": removed,
    });
    Ok(Zeroizing::new(serde_json::to_vec_pretty(&body)?))
}

/// Entries removed inside the retention window, with what their
/// tombstones keep.
fn removed_json(entries: &Entries) -> Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    for removed in entries.removed() {
        let kept = entries.removed_values(&removed.id)?;
        let labels: std::collections::BTreeMap<_, _> = kept
            .iter()
            .filter(|((_, _, slot), _, _)| *slot == Slot::Label)
            .map(|((_, field, _), _, value)| (*field, text(value)))
            .collect();
        let fields: Vec<serde_json::Value> = kept
            .iter()
            .filter(|((_, field, slot), _, _)| {
                *slot == Slot::Value && ![NAME, KIND, TAGS, STAR].contains(field)
            })
            .filter(|(_, kind, _)| *kind != FieldKind::Sensitivity)
            .map(|((_, field, _), kind, value)| {
                field_json(*kind, labels.get(field).map_or("", String::as_str), value)
            })
            .collect();
        out.push(serde_json::json!({
            "name": removed.names.join(" / "),
            "removed": stamp(removed.at),
            "fields": fields,
        }));
    }
    Ok(out)
}

/// Writes a backup into `dir`: the age file and its signature beside it.
/// Returns the backup's path.
///
/// # Errors
///
/// Returns an error when the folder cannot be written or a value does not
/// open.
pub fn write(vault: &Synced, dir: &Path) -> Result<PathBuf> {
    ensure!(dir.is_dir(), "{} is not a folder", dir.display());
    let body = document(vault)?;
    let recovery = vault
        .device()
        .authority()
        .context("the vault's genesis is not read yet")?
        .set
        .recovery;
    let mine = vault.device().me().identity.to_public();
    let sealed = crate::vault::crypto::encrypt_to(
        &[
            &recovery as &dyn age::Recipient,
            &mine as &dyn age::Recipient,
        ],
        &body,
    )?;
    let signature = vault
        .device()
        .me()
        .signing
        .sign(&crate::vault::crypto::sha256(&[&sealed]), SIGNATURE_CONTEXT)?;
    let when = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let path = dir.join(format!("txc-backup-{}-{when}.age", vault.name));
    home::write_atomic(&path, &sealed, None)?;
    let certificate = vault.device().me().certificate.unwrap_or_default();
    let detached = format!(
        "txc-backup-signature-v1\ndevice {}\ncertificate {}\nsignature {}\n",
        data_encoding::HEXLOWER.encode(&vault.device().me().device),
        data_encoding::HEXLOWER.encode(&certificate),
        data_encoding::BASE64.encode(&signature),
    );
    home::write_atomic(&signature_path(&path), detached.as_bytes(), None)?;
    Ok(path)
}

fn signature_path(backup: &Path) -> PathBuf {
    let mut name = backup.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

/// Checks a backup's detached signature against a certificate this vault
/// knows. Returns the signing device's short id.
///
/// # Errors
///
/// Returns an error when the signature is missing, malformed, by a device
/// this vault does not know, or does not verify.
pub fn verify(vault: &Synced, backup: &Path) -> Result<String> {
    let sealed =
        std::fs::read(backup).with_context(|| format!("cannot read {}", backup.display()))?;
    let detached = std::fs::read_to_string(signature_path(backup))
        .context("the signature file beside the backup is missing")?;
    let mut lines = detached.lines();
    ensure!(
        lines.next() == Some("txc-backup-signature-v1"),
        "not a txc backup signature"
    );
    let mut field = |label: &str| -> Result<String> {
        lines
            .next()
            .and_then(|line| line.strip_prefix(label))
            .map(|value| value.trim().to_owned())
            .ok_or_else(|| anyhow!("the signature file lacks its {label}"))
    };
    let (device, certificate, signature) = (
        field("device ")?,
        field("certificate ")?,
        field("signature ")?,
    );
    let certificate: [u8; 16] = data_encoding::HEXLOWER
        .decode(certificate.as_bytes())?
        .try_into()
        .map_err(|_bytes| anyhow!("a malformed certificate id"))?;
    let known = vault
        .device()
        .certificate(&certificate)
        .context("the backup was signed by a device this vault does not know")?;
    ensure!(
        data_encoding::HEXLOWER.encode(&known.device) == device,
        "the signature names another device than its certificate"
    );
    let signature = data_encoding::BASE64.decode(signature.as_bytes())?;
    ensure!(
        known.signing_key.verify(
            &crate::vault::crypto::sha256(&[&sealed]),
            SIGNATURE_CONTEXT,
            &signature
        ),
        "the signature does not match the backup: it was changed or is another's"
    );
    Ok(device.chars().take(8).collect())
}

/// Where backups go on their own, and when the last was written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    /// The folder, when one was given.
    pub dir: Option<PathBuf>,
    /// When the last backup was written.
    pub last: Option<u64>,
}

fn settings_path(home: &Home, name: &str) -> PathBuf {
    home.root().join("synced").join(name).join(SETTINGS)
}

/// This device's backup settings for a synced vault.
#[must_use]
pub fn settings(home: &Home, name: &str) -> Settings {
    let Ok(bytes) = home::read_private(&settings_path(home, name), 8192, PRIVATE) else {
        return Settings::default();
    };
    let text = String::from_utf8_lossy(&bytes);
    let mut settings = Settings::default();
    for line in text.lines() {
        if let Some(dir) = line.strip_prefix("dir ") {
            settings.dir = Some(PathBuf::from(dir));
        } else if let Some(last) = line.strip_prefix("last ") {
            settings.last = last.parse().ok();
        }
    }
    settings
}

/// Records where backups go and when the last was written.
///
/// # Errors
///
/// Returns an error when the write fails.
pub fn record(home: &Home, name: &str, settings: &Settings) -> Result<()> {
    let mut text = String::new();
    if let Some(dir) = &settings.dir {
        text.push_str("dir ");
        text.push_str(&dir.to_string_lossy());
        text.push('\n');
    }
    if let Some(last) = settings.last {
        text.push_str("last ");
        text.push_str(&last.to_string());
        text.push('\n');
    }
    home::write_atomic(&settings_path(home, name), text.as_bytes(), None)
}

/// Writes a backup on its own when one is due and its folder is there, as
/// when the backup drive is plugged in. Best effort: returns the path when
/// it wrote one.
#[must_use]
pub fn when_due(home: &Home, vault: &Synced) -> Option<PathBuf> {
    let mut settings = settings(home, &vault.name);
    let dir = settings.dir.clone()?;
    let due = settings
        .last
        .is_none_or(|last| now().saturating_sub(last) >= EVERY);
    if !due || !dir.is_dir() {
        return None;
    }
    let path = write(vault, &dir).ok()?;
    settings.last = Some(now());
    record(home, &vault.name, &settings).ok()?;
    Some(path)
}
