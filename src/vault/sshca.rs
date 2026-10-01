//! An SSH certificate authority held in a vault (study section 10).
//!
//! The CA key is an operation-only field: it is never shown, copied, granted
//! or put in a program's environment. Each connection gets a fresh Ed25519
//! user key and a certificate for it that lives for minutes, and both reach
//! `ssh` as sealed in-memory files. Servers trust the CA once, with
//! `TrustedUserCAKeys`; there is no agent socket and no long-lived key on
//! disk.

use anyhow::{Result, anyhow};
use ssh_key::certificate::{Builder, CertType};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use zeroize::Zeroizing;

/// How long a certificate lives unless asked otherwise.
pub const DEFAULT_MINUTES: u64 = 5;
/// The longest a certificate may live.
pub const LONGEST_MINUTES: u64 = 60;
/// Clocks differ; a certificate is valid from a minute before it was made.
const CLOCK_SLACK: u64 = 60;

/// A new CA key, in the OpenSSH private key format, to keep in the vault.
///
/// # Errors
///
/// Returns an error when the key cannot be encoded.
pub fn new_ca() -> Result<Zeroizing<String>> {
    let key = PrivateKey::random(&mut rand08::rngs::OsRng, Algorithm::Ed25519)
        .map_err(|error| anyhow!("cannot make the CA key: {error}"))?;
    key.to_openssh(LineEnding::LF)
        .map_err(|error| anyhow!("cannot encode the CA key: {error}"))
}

/// The CA's public key, the line servers trust with `TrustedUserCAKeys`.
///
/// # Errors
///
/// Returns an error when the stored key is not an OpenSSH private key.
pub fn ca_public(ca: &str) -> Result<String> {
    let key =
        PrivateKey::from_openssh(ca).map_err(|error| anyhow!("the CA key is damaged: {error}"))?;
    key.public_key()
        .to_openssh()
        .map_err(|error| anyhow!("{error}"))
}

/// The CA's fingerprint, as `ssh-keygen -l` shows it.
///
/// # Errors
///
/// Returns an error when the stored key is not an OpenSSH private key.
pub fn ca_fingerprint(ca: &str) -> Result<String> {
    let key =
        PrivateKey::from_openssh(ca).map_err(|error| anyhow!("the CA key is damaged: {error}"))?;
    Ok(key.public_key().fingerprint(HashAlg::Sha256).to_string())
}

/// A user key and its certificate, for one connection.
pub struct Issued {
    /// The user's private key, in the OpenSSH format.
    pub key: Zeroizing<String>,
    /// The certificate, one line.
    pub certificate: String,
}

/// Signs a fresh user key for `principal`, valid for `minutes` from `now`.
///
/// # Errors
///
/// Returns an error when the CA key is damaged or signing fails.
pub fn issue(ca: &str, principal: &str, minutes: u64, now: u64, key_id: &str) -> Result<Issued> {
    let ca =
        PrivateKey::from_openssh(ca).map_err(|error| anyhow!("the CA key is damaged: {error}"))?;
    let user = PrivateKey::random(&mut rand08::rngs::OsRng, Algorithm::Ed25519)
        .map_err(|error| anyhow!("cannot make a user key: {error}"))?;
    let minutes = minutes.clamp(1, LONGEST_MINUTES);
    let mut builder = Builder::new_with_random_nonce(
        &mut rand08::rngs::OsRng,
        user.public_key().key_data().clone(),
        now.saturating_sub(CLOCK_SLACK),
        now.saturating_add(minutes.saturating_mul(60)),
    )
    .map_err(|error| anyhow!("{error}"))?;
    let mut serial = [0_u8; 8];
    rand::fill(&mut serial[..]);
    builder
        .serial(u64::from_be_bytes(serial))
        .and_then(|builder| builder.key_id(key_id))
        .and_then(|builder| builder.cert_type(CertType::User))
        .and_then(|builder| builder.valid_principal(principal))
        .and_then(|builder| builder.extension("permit-pty", ""))
        .map_err(|error| anyhow!("{error}"))?;
    let certificate = builder
        .sign(&ca)
        .map_err(|error| anyhow!("cannot sign the certificate: {error}"))?;
    Ok(Issued {
        key: user
            .to_openssh(LineEnding::LF)
            .map_err(|error| anyhow!("{error}"))?,
        certificate: certificate
            .to_openssh()
            .map_err(|error| anyhow!("{error}"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_certificate_is_for_the_user_key_signed_by_the_ca_and_short_lived() {
        let ca = new_ca().unwrap();
        let issued = issue(&ca, "deploy", 5, 1_000_000, "txc laptop").unwrap();
        let certificate = ssh_key::Certificate::from_openssh(&issued.certificate).unwrap();
        let user = PrivateKey::from_openssh(&*issued.key).unwrap();
        assert_eq!(certificate.public_key(), user.public_key().key_data());
        assert_eq!(certificate.valid_principals(), ["deploy".to_owned()]);
        assert_eq!(
            certificate.valid_before() - certificate.valid_after(),
            5 * 60 + 60
        );
        let ca_key = PrivateKey::from_openssh(&*ca).unwrap();
        assert_eq!(certificate.signature_key(), ca_key.public_key().key_data());
        certificate
            .validate_at(
                1_000_100,
                [&ca_key.public_key().fingerprint(HashAlg::Sha256)],
            )
            .unwrap();
        assert!(
            certificate
                .validate_at(
                    1_000_000 + 10 * 60,
                    [&ca_key.public_key().fingerprint(HashAlg::Sha256)]
                )
                .is_err()
        );
        assert!(ca_public(&ca).unwrap().starts_with("ssh-ed25519 "));
    }

    #[test]
    fn a_certificate_lives_an_hour_at_most() {
        let ca = new_ca().unwrap();
        let issued = issue(&ca, "deploy", 10_000, 0, "id").unwrap();
        let certificate = ssh_key::Certificate::from_openssh(&issued.certificate).unwrap();
        assert_eq!(certificate.valid_before(), LONGEST_MINUTES * 60);
    }
}
