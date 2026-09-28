//! Grant v2: one secret for one machine, such as a CI runner, from a synced
//! vault (study section 10).
//!
//! A grant is an age file sealed to the runner's own post-quantum recipient.
//! Inside, a statement signed with the composite key of the issuing device's
//! certificate names the vault, the runner, the entry, the field, the
//! entry's version, where it may be used, when it was issued and when it
//! expires, and holds the secret. The genesis and the issuer's certificate
//! chain travel with it, so the runner verifies it offline against the vault
//! id alone, pinned in its configuration.
//!
//! Naming the runner inside the signature stops a grant that one compromised
//! runner decrypted from being sealed again to another (the Tamarin model
//! `TxcGrant`). An expiry that does not parse fails closed. Two limits are
//! inherent and stated wherever a grant is made: it is a snapshot, and it
//! cannot be revoked once issued; rotating the secret is the revocation.

use std::io::{Read, Write};

use age::secrecy::SecretString;
use anyhow::{Context as _, Result, anyhow, bail, ensure};
use zeroize::Zeroizing;

use crate::vault::authority::{Genesis, IssuedCertificate, SignedGenesis};
use crate::vault::composite::SigningKey;
use crate::vault::object::{Hash, Id};
use crate::vault::pq;
use crate::vault::wire::{Reader, Writer};

const STATEMENT_TAG: &[u8] = b"txc/v1/grant";
const CONTEXT: &[u8] = b"txc/v1/grant";
const MAX_TEXT: usize = 4096;
const MAX_CHAIN: usize = 16;
const MAX_GRANT_BYTES: usize = 1024 * 1024;

/// What a grant says, all of it signed.
#[derive(Clone, PartialEq, Eq)]
pub struct Statement {
    /// The vault.
    pub genesis: Hash,
    /// The runner it is for: its `age1pq1...` recipient.
    pub runner: String,
    /// The entry's name.
    pub entry: String,
    /// The field's name.
    pub field: String,
    /// When the field's value was written: redeem can require a minimum.
    pub version: u64,
    /// Where it may be used, in words, for the runner's operator.
    pub origin: String,
    /// When it was issued, in seconds since the epoch.
    pub issued: u64,
    /// When it expires, in seconds since the epoch.
    pub expires: u64,
    /// The issuing device's certificate.
    pub issuer: Id,
    /// The secret.
    pub secret: Zeroizing<Vec<u8>>,
}

impl Statement {
    fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Writer::default();
        out.fixed(STATEMENT_TAG);
        out.fixed(&self.genesis);
        out.str(&self.runner);
        out.str(&self.entry);
        out.str(&self.field);
        out.u64(self.version);
        out.str(&self.origin);
        out.u64(self.issued);
        out.u64(self.expires);
        out.fixed(&self.issuer);
        out.bytes(&self.secret);
        Zeroizing::new(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        ensure!(
            input.take(STATEMENT_TAG.len())? == STATEMENT_TAG,
            "not a grant"
        );
        let statement = Self {
            genesis: input.fixed()?,
            runner: input.str(MAX_TEXT)?,
            entry: input.str(MAX_TEXT)?,
            field: input.str(MAX_TEXT)?,
            version: input.u64()?,
            origin: input.str(MAX_TEXT)?,
            issued: input.u64()?,
            expires: input.u64()?,
            issuer: input.fixed()?,
            secret: Zeroizing::new(input.bytes()?.to_vec()),
        };
        input.finish()?;
        Ok(statement)
    }
}

/// Issues a grant: signs the statement with the issuing device's key and
/// seals it, with the genesis and the certificate chain, to the runner.
///
/// # Errors
///
/// Returns an error when the runner's recipient is not a post-quantum one or
/// sealing fails.
pub fn issue(
    statement: &Statement,
    key: &SigningKey,
    genesis: &SignedGenesis,
    chain: &[IssuedCertificate],
) -> Result<Vec<u8>> {
    let runner: pq::Recipient = statement.runner.parse().map_err(|error: &str| {
        anyhow!("the runner's key: {error} (make one with age-keygen -pq)")
    })?;
    ensure!(
        !chain.is_empty() && chain.len() <= MAX_CHAIN,
        "a grant carries its issuer's certificate chain"
    );
    let encoded = statement.encode();
    let signature = key.sign(&encoded, CONTEXT)?;
    let mut out = Writer::default();
    out.bytes(&genesis.encode());
    out.count(chain.len());
    for issued in chain {
        out.bytes(&issued.encode());
    }
    out.bytes(&encoded);
    out.bytes(&signature);
    let plain = Zeroizing::new(out.finish());
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&runner as &dyn age::Recipient))
            .map_err(|_error| anyhow!("cannot seal the grant"))?;
    let mut sealed = Vec::new();
    let mut writer = encryptor.wrap_output(&mut sealed)?;
    writer.write_all(&plain)?;
    writer.finish()?;
    Ok(sealed)
}

/// What redeeming checks, and against what.
pub struct Expect<'a> {
    /// The vault id the runner pinned: the genesis hash.
    pub vault: &'a Hash,
    /// The time now, in seconds since the epoch.
    pub now: u64,
    /// The oldest entry version the runner accepts.
    pub min_version: u64,
}

/// Opens a grant with the runner's identity and checks everything: the
/// vault, the certificate chain, the signature, that it names this runner,
/// its expiry and the entry version.
///
/// # Errors
///
/// Returns an error naming what does not hold.
pub fn redeem(sealed: &[u8], identity: &pq::Identity, expect: &Expect<'_>) -> Result<Statement> {
    ensure!(sealed.len() <= MAX_GRANT_BYTES, "the grant is too large");
    let decryptor =
        age::Decryptor::new(sealed).map_err(|_error| anyhow!("this is not a grant file"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_error| anyhow!("this grant is not for this key"))?;
    let mut plain = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(MAX_GRANT_BYTES as u64)
        .read_to_end(&mut plain)?;

    let mut input = Reader(&plain);
    let genesis = SignedGenesis::decode(input.bytes()?)?.genesis;
    ensure!(
        genesis.hash() == *expect.vault,
        "the grant is from another vault"
    );
    let chain = (0..input.count(MAX_CHAIN)?)
        .map(|_| IssuedCertificate::decode(input.bytes()?))
        .collect::<Result<Vec<_>>>()?;
    let encoded = input.bytes()?;
    let signature = input.bytes()?;
    input.finish()?;

    let issuer = verify_chain(&genesis, &chain)?;
    ensure!(
        issuer
            .certificate
            .signing_key
            .verify(encoded, CONTEXT, signature),
        "the grant's signature does not verify"
    );
    let statement = Statement::decode(encoded)?;
    ensure!(
        statement.issuer == issuer.certificate.id,
        "the grant names another issuer"
    );
    ensure!(
        statement.genesis == *expect.vault,
        "the grant is from another vault"
    );
    ensure!(
        statement.runner == identity.to_public().to_string(),
        "the grant was issued to another runner"
    );
    ensure!(expect.now < statement.expires, "the grant expired");
    ensure!(
        statement.version >= expect.min_version,
        "the grant holds an older version of {} than this runner accepts",
        statement.entry
    );
    Ok(statement)
}

/// Verifies a chain, each certificate against those before it, and returns
/// the last: the issuer.
fn verify_chain<'a>(
    genesis: &Genesis,
    chain: &'a [IssuedCertificate],
) -> Result<&'a IssuedCertificate> {
    for (index, issued) in chain.iter().enumerate() {
        let earlier = chain.get(..index).unwrap_or_default();
        let known = |id: &Id| {
            earlier
                .iter()
                .find(|other| other.certificate.id == *id)
                .map(|other| other.certificate.clone())
        };
        issued
            .verify(genesis, &known)
            .context("the grant's certificate chain does not verify")?;
    }
    let Some(issuer) = chain.last() else {
        bail!("the grant has no issuer")
    };
    Ok(issuer)
}

/// The secret, as text for a pipe.
///
/// # Errors
///
/// Returns an error when it is not UTF-8.
pub fn secret_text(statement: &Statement) -> Result<SecretString> {
    let text = std::str::from_utf8(&statement.secret)
        .map_err(|_error| anyhow!("the secret is not text"))?;
    Ok(SecretString::from(text.to_owned()))
}

/// A vault id as text: the genesis hash in hex.
#[must_use]
pub fn vault_id(genesis: &Hash) -> String {
    data_encoding::HEXLOWER.encode(genesis)
}

/// Reads a vault id.
///
/// # Errors
///
/// Returns an error when it is not 96 hex digits.
pub fn parse_vault_id(text: &str) -> Result<Hash> {
    let bytes = data_encoding::HEXLOWER_PERMISSIVE
        .decode(text.trim().as_bytes())
        .map_err(|_error| anyhow!("a vault id is 96 hex digits"))?;
    bytes
        .try_into()
        .map_err(|_bytes| anyhow!("a vault id is 96 hex digits"))
}

impl std::fmt::Debug for Statement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Statement")
            .field("entry", &self.entry)
            .field("field", &self.field)
            .field("version", &self.version)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::authority::tests::{certificate, roots};
    use crate::vault::authority::{Issuer, Role};

    struct Setup {
        genesis: SignedGenesis,
        chain: Vec<IssuedCertificate>,
        key: SigningKey,
    }

    fn setup() -> Setup {
        let roots = roots();
        let signed = SignedGenesis::sign(
            roots.genesis.clone(),
            [(&roots.keys[0], 0), (&roots.keys[1], 1)],
        )
        .unwrap();
        let admin_key = SigningKey::generate();
        let admin = IssuedCertificate::by_roots(
            certificate(&roots.genesis, Role::Admin, Issuer::Root, &admin_key),
            [(&roots.keys[0], 0), (&roots.keys[2], 2)],
        )
        .unwrap();
        let member_key = SigningKey::generate();
        let member = IssuedCertificate::by_admin(
            certificate(
                &roots.genesis,
                Role::Writer,
                Issuer::Admin(admin.certificate.id),
                &member_key,
            ),
            &admin_key,
        )
        .unwrap();
        Setup {
            genesis: signed,
            chain: vec![admin, member],
            key: member_key,
        }
    }

    fn statement(setup: &Setup, runner: &pq::Identity) -> Statement {
        Statement {
            genesis: setup.genesis.genesis.hash(),
            runner: runner.to_public().to_string(),
            entry: "deploy-token".into(),
            field: "secret".into(),
            version: 100,
            origin: "github.com/example/app, deploy job".into(),
            issued: 1_000,
            expires: 2_000,
            issuer: setup.chain.last().unwrap().certificate.id,
            secret: Zeroizing::new(b"token-value".to_vec()),
        }
    }

    #[test]
    fn a_grant_opens_only_for_its_runner_its_vault_and_its_time() {
        let setup = setup();
        let runner = pq::Identity::generate();
        let sealed = issue(
            &statement(&setup, &runner),
            &setup.key,
            &setup.genesis,
            &setup.chain,
        )
        .unwrap();
        let vault = setup.genesis.genesis.hash();
        let expect = Expect {
            vault: &vault,
            now: 1_500,
            min_version: 50,
        };
        let redeemed = redeem(&sealed, &runner, &expect).unwrap();
        assert_eq!(&redeemed.secret[..], b"token-value");

        assert!(redeem(&sealed, &pq::Identity::generate(), &expect).is_err());
        assert!(
            redeem(
                &sealed,
                &runner,
                &Expect {
                    now: 2_000,
                    ..expect
                }
            )
            .is_err()
        );
        assert!(
            redeem(
                &sealed,
                &runner,
                &Expect {
                    min_version: 101,
                    ..expect
                }
            )
            .is_err()
        );
        assert!(
            redeem(
                &sealed,
                &runner,
                &Expect {
                    vault: &[0; 48],
                    ..expect
                }
            )
            .is_err()
        );
    }

    #[test]
    fn a_grant_sealed_again_to_another_runner_is_refused() {
        let setup = setup();
        let (first, second) = (pq::Identity::generate(), pq::Identity::generate());
        let sealed = issue(
            &statement(&setup, &first),
            &setup.key,
            &setup.genesis,
            &setup.chain,
        )
        .unwrap();
        // The first runner decrypts it and seals the same plaintext to the second.
        let decryptor = age::Decryptor::new(sealed.as_slice()).unwrap();
        let mut reader = decryptor
            .decrypt(std::iter::once(&first as &dyn age::Identity))
            .unwrap();
        let mut plain = Vec::new();
        reader.read_to_end(&mut plain).unwrap();
        let recipient = second.to_public();
        let encryptor =
            age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                .unwrap();
        let mut resealed = Vec::new();
        let mut writer = encryptor.wrap_output(&mut resealed).unwrap();
        writer.write_all(&plain).unwrap();
        writer.finish().unwrap();

        let vault = setup.genesis.genesis.hash();
        let error = redeem(
            &resealed,
            &second,
            &Expect {
                vault: &vault,
                now: 1_500,
                min_version: 0,
            },
        )
        .unwrap_err();
        assert!(format!("{error}").contains("another runner"), "{error}");
    }

    #[test]
    fn a_grant_signed_by_a_key_outside_the_chain_is_refused() {
        let setup = setup();
        let runner = pq::Identity::generate();
        let forger = SigningKey::generate();
        let sealed = issue(
            &statement(&setup, &runner),
            &forger,
            &setup.genesis,
            &setup.chain,
        )
        .unwrap();
        let vault = setup.genesis.genesis.hash();
        assert!(
            redeem(
                &sealed,
                &runner,
                &Expect {
                    vault: &vault,
                    now: 1_500,
                    min_version: 0
                }
            )
            .is_err()
        );
    }

    #[test]
    fn vault_ids_round_trip() {
        assert_eq!(parse_vault_id(&vault_id(&[7; 48])).unwrap(), [7; 48]);
        assert!(parse_vault_id("abc").is_err());
    }
}
