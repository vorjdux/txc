//! Grants: one secret sealed to another key, so an automated host can be given
//! exactly one secret without the identity or its passphrase.
//!
//! A grant is a small file. It holds the entry's secret sealed to a recipient,
//! never the identity, so the file at rest is useless to anyone but that
//! recipient. Two limits are inherent and are stated wherever a grant is made:
//! a grant is a snapshot, so it does not follow later edits, and it cannot be
//! revoked, because the holder already has the sealed value. The only real
//! revocation is rotating the underlying secret; the expiry is hygiene that
//! `redeem` checks, not enforcement.

// A damaged grant is reported as damaged without forwarding the parser's own
// error, so map_err discards the source on purpose here.
#![allow(clippy::map_err_ignore)]

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Result, anyhow, ensure};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};

use crate::vault::crypto::{self, Identity, Recipient};
use crate::vault::document::{now, seal_to};
use crate::vault::model::MAX_SECRET_BYTES;

const FORMAT: &str = "txc-grant";
const VERSION: u32 = 1;

/// A sealed secret, issued to a recipient, with when it was made and when it
/// stops being fresh.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    format: String,
    version: u32,
    /// Which entry it came from, for the person reading the file. Not secret.
    entry: String,
    /// The secret, sealed as base64 age ciphertext.
    sealed: String,
    /// The public key it was sealed to.
    recipient: String,
    /// The secret key that opens it, present only for a `--to-file` grant,
    /// which is then equivalent to the secret itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    /// When it was issued, RFC 3339.
    issued: String,
    /// When it stops being fresh, RFC 3339, if a limit was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires: Option<String>,
}

impl Grant {
    /// Seals a secret to a recipient. With `bundled`, the recipient's own
    /// secret key is written into the grant as well, for the quick local case
    /// where the file travels with the key that opens it.
    ///
    /// # Errors
    ///
    /// Returns an error when the secret cannot be sealed.
    pub fn issue(
        entry: &str,
        secret: &SecretString,
        recipient: &Recipient,
        recipient_text: &str,
        expires: Option<String>,
        bundled: Option<&Identity>,
    ) -> Result<Self> {
        Ok(Self {
            format: FORMAT.to_string(),
            version: VERSION,
            entry: entry.to_string(),
            sealed: seal_to(std::slice::from_ref(recipient), secret)?,
            recipient: recipient_text.to_string(),
            identity: bundled.map(|identity| identity.to_string().expose_secret().to_owned()),
            issued: now(),
            expires,
        })
    }

    /// The grant as pretty JSON, for writing to a file.
    ///
    /// # Errors
    ///
    /// Returns an error only if serialisation fails, which it does not here.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Reads and checks a grant's shape.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is not a grant this version reads.
    pub fn from_json(text: &str) -> Result<Self> {
        let grant: Self = serde_json::from_str(text)
            .map_err(|_| anyhow!("this is not a grant this version of txc reads"))?;
        ensure!(grant.format == FORMAT, "this is not a txc grant");
        ensure!(
            grant.version == VERSION,
            "the grant was written in a format this version of txc does not read"
        );
        Ok(grant)
    }

    /// Whether the grant bundles the key that opens it.
    #[must_use]
    pub const fn is_bundled(&self) -> bool {
        self.identity.is_some()
    }

    /// Opens the grant with an identity, after checking it has not expired.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant has expired, when the identity is not
    /// the one it was sealed to, or when it is damaged.
    pub fn redeem(&self, identity: &Identity) -> Result<SecretString> {
        if let Some(expires) = &self.expires
            && let Ok(deadline) = chrono::DateTime::parse_from_rfc3339(expires)
        {
            ensure!(
                chrono::Utc::now() < deadline,
                "this grant expired at {expires}; issue a fresh one, or rotate the secret"
            );
        }
        let ciphertext = BASE64
            .decode(self.sealed.as_bytes())
            .map_err(|_| anyhow!("the grant is damaged"))?;
        let plaintext = crypto::decrypt(identity, &ciphertext, MAX_SECRET_BYTES)
            .map_err(|_| anyhow!("this grant was not sealed to this identity, or it is damaged"))?;
        let text = std::str::from_utf8(&plaintext)
            .map_err(|_| anyhow!("the grant is damaged"))?
            .to_owned();
        Ok(SecretString::from(text))
    }

    /// Opens a `--to-file` grant with the key bundled inside it.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant bundles no key, or cannot be opened.
    pub fn redeem_bundled(&self) -> Result<SecretString> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| anyhow!("this grant has no bundled key; redeem it with --identity"))?;
        let identity = crypto::parse_identity(identity)?;
        self.redeem(&identity)
    }
}

/// Turns a duration such as `1h`, `30m`, `7d` or `45s` into an RFC 3339 time
/// that far from now.
///
/// # Errors
///
/// Returns an error when the text is not a number followed by s, m, h or d.
pub fn expiry_from(spec: &str) -> Result<String> {
    let spec = spec.trim();
    let (number, unit) = spec.split_at(
        spec.find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| anyhow!("{spec:?} needs a unit: s, m, h or d, as in 1h"))?,
    );
    let count: i64 = number
        .parse()
        .map_err(|_| anyhow!("{spec:?} does not start with a number"))?;
    let duration = match unit {
        "s" => chrono::Duration::try_seconds(count),
        "m" => chrono::Duration::try_minutes(count),
        "h" => chrono::Duration::try_hours(count),
        "d" => chrono::Duration::try_days(count),
        other => return Err(anyhow!("{other:?} is not a unit; use s, m, h or d")),
    }
    .ok_or_else(|| anyhow!("{spec:?} is too long a time"))?;
    let deadline = chrono::Utc::now()
        .checked_add_signed(duration)
        .ok_or_else(|| anyhow!("{spec:?} is too long a time"))?;
    Ok(deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_opens_only_with_the_key_it_was_sealed_to() {
        let host = crypto::new_identity();
        let recipient = crypto::parse_recipient(&host.to_public().to_string()).unwrap();
        let grant = Grant::issue(
            "personal/site.password",
            &"hunter2".to_string().into(),
            &recipient,
            &host.to_public().to_string(),
            None,
            None,
        )
        .unwrap();

        assert_eq!(grant.redeem(&host).unwrap().expose_secret(), "hunter2");

        // A different identity cannot open it.
        let stranger = crypto::new_identity();
        assert!(grant.redeem(&stranger).is_err());
    }

    #[test]
    fn an_expired_grant_is_refused() {
        let host = crypto::new_identity();
        let recipient = crypto::parse_recipient(&host.to_public().to_string()).unwrap();
        let mut grant = Grant::issue(
            "personal/site.password",
            &"hunter2".to_string().into(),
            &recipient,
            &host.to_public().to_string(),
            Some("2000-01-01T00:00:00Z".to_string()),
            None,
        )
        .unwrap();
        assert!(grant.redeem(&host).is_err(), "an expired grant opened");

        // Fresh again, it opens.
        grant.expires = Some(expiry_from("1h").unwrap());
        assert!(grant.redeem(&host).is_ok());
    }

    #[test]
    fn a_bundled_grant_carries_its_own_key() {
        let ephemeral = crypto::new_identity();
        let recipient = crypto::parse_recipient(&ephemeral.to_public().to_string()).unwrap();
        let grant = Grant::issue(
            "personal/site.password",
            &"hunter2".to_string().into(),
            &recipient,
            &ephemeral.to_public().to_string(),
            None,
            Some(&ephemeral),
        )
        .unwrap();
        assert!(grant.is_bundled());
        assert_eq!(grant.redeem_bundled().unwrap().expose_secret(), "hunter2");
    }

    #[test]
    fn a_duration_needs_a_unit() {
        assert!(expiry_from("1h").is_ok());
        assert!(expiry_from("30m").is_ok());
        assert!(expiry_from("7d").is_ok());
        assert!(expiry_from("100").is_err());
        assert!(expiry_from("soon").is_err());
        assert!(expiry_from("5y").is_err());
    }
}
