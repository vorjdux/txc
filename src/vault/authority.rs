//! Who may do what in a vault (study section 5): the three root keys, the
//! genesis they sign, and the device certificates that chain to it.
//!
//! - **Root keys** come from the recovery sheets: each mixes one share with
//!   the card, so one or two stolen sheets without the card yield nothing.
//!   Root actions need two distinct root signatures, made one sheet at a
//!   time; root keys are never combined.
//! - **Genesis** names the root public keys, the recovery recipient, a
//!   commitment to each share, and the initial policy. Its hash is bound into
//!   every object of the vault.
//! - **Certificates** bind a device's keys to its principal, role, scope and
//!   lifetime. Admin certificates are issued by two roots; member
//!   certificates by an admin; renewals rotate the device's keys and are
//!   signed with both the old and the new key.

// Protocol code: no unsafe block, and no module-level exception either.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail, ensure};
use hkdf::Hkdf;
use sha2::{Digest, Sha384};
use zeroize::Zeroizing;

use crate::vault::composite::{self, SigningKey, VerifyingKey};
use crate::vault::object::{Hash, Id, SUITE};
use crate::vault::pq;
use crate::vault::wire::{Reader, Writer};

/// How many root keys a vault has, one per recovery sheet.
pub const ROOTS: usize = 3;
/// How many distinct root signatures a root action needs.
pub const ROOT_QUORUM: usize = 2;
/// The default number of additions a new admin may make before root must
/// grant more.
pub const DEFAULT_MINT_ALLOWANCE: u32 = 4;

const DAY: u64 = 24 * 60 * 60;
const ROOT_CONTEXT: &[u8] = b"txc/v1/root";
const CERT_CONTEXT: &[u8] = b"txc/v1/cert";
const RENEWAL_CONTEXT: &[u8] = b"txc/v1/renewal";
const GENESIS_TAG: &[u8] = b"txc/v1/genesis";
const SHARE_TAG: &[u8] = b"txc/v1/share";
const CERT_TAG: &[u8] = b"txc/v1/certificate";
const RENEWAL_TAG: &[u8] = b"txc/v1/renewal-request";
const MAX_TEXT: usize = 256;
/// A post-quantum recipient string is about 1,950 characters.
const MAX_RECIPIENT: usize = 4096;
const MAX_AUTHENTICATORS: usize = 32;

/// A fresh random id.
#[must_use]
pub fn new_id() -> Id {
    let mut id = [0; 16];
    rand::fill(&mut id[..]);
    id
}

fn sha384(tag: &[u8], bytes: &[u8]) -> Hash {
    let mut hash = Sha384::new();
    Digest::update(&mut hash, tag);
    Digest::update(&mut hash, bytes);
    hash.finalize().into()
}

// ------------------------------------------------------------------ roots --

/// The card's one canonical form: lowercase ASCII words separated by single
/// spaces. Applied before both SLIP-39 and root derivation, so a stray space
/// or capital cannot break one path and not the other.
///
/// # Errors
///
/// Returns an error when the card holds anything but ASCII letters and
/// whitespace, or no word at all.
pub fn normalize_card(card: &str) -> Result<Zeroizing<String>> {
    ensure!(
        card.chars()
            .all(|c| c.is_ascii_alphabetic() || c.is_whitespace()),
        "the card holds only words of letters"
    );
    let words: Vec<String> = card
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect();
    ensure!(!words.is_empty(), "the card is empty");
    Ok(Zeroizing::new(words.join(" ")))
}

/// Derives root key `index` (0, 1 or 2) from its sheet's share and the card:
/// `HKDF-SHA-384(ikm = share || card)` with info `txc/v1/root/<i>/mldsa65`
/// for the ML-DSA-65 seed and `txc/v1/root/<i>/ed25519` for the Ed25519 key.
///
/// # Errors
///
/// Returns an error when the index is out of range or the card is malformed.
pub fn root_key(share: &[u8], card: &str, index: usize) -> Result<SigningKey> {
    ensure!(index < ROOTS, "there are {ROOTS} root keys");
    let card = normalize_card(card)?;
    let mut ikm = Zeroizing::new(Vec::with_capacity(share.len().saturating_add(card.len())));
    ikm.extend_from_slice(share);
    ikm.extend_from_slice(card.as_bytes());
    let hkdf = Hkdf::<Sha384>::new(None, &ikm);
    let mut seeds = Zeroizing::new([0_u8; composite::PRIVATE_KEY_BYTES]);
    let (mldsa, ed25519) = seeds.split_at_mut(32);
    hkdf.expand(format!("txc/v1/root/{index}/mldsa65").as_bytes(), mldsa)
        .and_then(|()| hkdf.expand(format!("txc/v1/root/{index}/ed25519").as_bytes(), ed25519))
        .map_err(|_length| anyhow!("cannot derive a root key"))?;
    Ok(SigningKey::from_bytes(&seeds))
}

/// The commitment to a share that genesis records and each sheet prints.
#[must_use]
pub fn share_commitment(share: &[u8]) -> Hash {
    sha384(SHARE_TAG, share)
}

/// The recovery identity: the recovery secret is its seed, so standard
/// tools can rebuild it from two sheets and the card.
#[must_use]
pub fn recovery_identity(secret: &[u8; 32]) -> pq::Identity {
    pq::Identity::from_seed(*secret)
}

/// One root key's signature over a root action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endorsement {
    /// Which root key signed.
    pub root: u8,
    /// Its signature.
    pub signature: Vec<u8>,
}

impl Endorsement {
    /// Signs `message` with root key `root`.
    ///
    /// # Errors
    ///
    /// Returns an error when the system has no randomness.
    pub fn sign(key: &SigningKey, root: u8, message: &[u8]) -> Result<Self> {
        Ok(Self {
            root,
            signature: key.sign(message, ROOT_CONTEXT)?,
        })
    }

    fn write(list: &[Self], out: &mut Writer) {
        out.count(list.len());
        for endorsement in list {
            out.u8(endorsement.root);
            out.bytes(&endorsement.signature);
        }
    }

    fn read(input: &mut Reader<'_>) -> Result<Vec<Self>> {
        (0..input.count(ROOTS)?)
            .map(|_| {
                Ok(Self {
                    root: input.u8()?,
                    signature: input.bytes()?.to_vec(),
                })
            })
            .collect()
    }
}

/// Whether at least two distinct root keys endorsed `message`.
#[must_use]
pub fn quorum(roots: &[VerifyingKey; ROOTS], message: &[u8], endorsements: &[Endorsement]) -> bool {
    let signers: BTreeSet<u8> = endorsements
        .iter()
        .filter(|endorsement| {
            roots
                .get(usize::from(endorsement.root))
                .is_some_and(|key| key.verify(message, ROOT_CONTEXT, &endorsement.signature))
        })
        .map(|endorsement| endorsement.root)
        .collect();
    signers.len() >= ROOT_QUORUM
}

// ---------------------------------------------------------------- genesis --

/// Vault policy: settings that only signed objects may change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Older clients drop to read-only.
    pub min_client_version: u64,
    /// The additions each admin may make before root grants more.
    pub mint_allowance: u32,
    /// How long tombstones are kept, in days.
    pub retention_days: u32,
    /// How old a membership view may be before membership changes are
    /// refused, in days.
    pub staleness_days: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_client_version: 1,
            mint_allowance: DEFAULT_MINT_ALLOWANCE,
            retention_days: 90,
            staleness_days: 7,
        }
    }
}

/// A vault's genesis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    /// The three composite root public keys.
    pub roots: [VerifyingKey; ROOTS],
    /// The recovery recipient, a recipient of every control object.
    pub recovery: pq::Recipient,
    /// A commitment to each recovery share.
    pub commitments: [Hash; ROOTS],
    /// The initial policy.
    pub policy: Policy,
}

/// The root keys, recovery recipient and share commitments in force:
/// genesis's, until a reissue of the recovery sheets replaces them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootSet {
    /// The three composite root public keys.
    pub roots: [VerifyingKey; ROOTS],
    /// The recovery recipient, a recipient of every control object.
    pub recovery: pq::Recipient,
    /// A commitment to each recovery share.
    pub commitments: [Hash; ROOTS],
}

impl RootSet {
    /// Writes it, for a reissue fact.
    pub fn write(&self, out: &mut Writer) {
        for root in &self.roots {
            out.bytes(&root.to_bytes());
        }
        out.str(&self.recovery.to_string());
        for commitment in &self.commitments {
            out.fixed(commitment);
        }
    }

    /// Reads it back.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed.
    pub fn read(input: &mut Reader<'_>) -> Result<Self> {
        let mut roots = Vec::with_capacity(ROOTS);
        for _ in 0..ROOTS {
            roots.push(VerifyingKey::from_bytes(input.bytes()?)?);
        }
        let roots: [VerifyingKey; ROOTS] = roots
            .try_into()
            .map_err(|_roots| anyhow!("three root keys are needed"))?;
        let recovery = input
            .str(MAX_RECIPIENT)?
            .parse()
            .map_err(|error: &str| anyhow!("recovery recipient: {error}"))?;
        let commitments = [input.fixed()?, input.fixed()?, input.fixed()?];
        Ok(Self {
            roots,
            recovery,
            commitments,
        })
    }
}

impl Genesis {
    /// The roots, recovery recipient and commitments genesis starts with.
    #[must_use]
    pub fn root_set(&self) -> RootSet {
        RootSet {
            roots: self.roots.clone(),
            recovery: self.recovery.clone(),
            commitments: self.commitments,
        }
    }

    /// The canonical encoding the roots sign.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::default();
        out.fixed(GENESIS_TAG);
        out.u8(SUITE);
        for root in &self.roots {
            out.bytes(&root.to_bytes());
        }
        out.str(&self.recovery.to_string());
        for commitment in &self.commitments {
            out.fixed(commitment);
        }
        out.u64(self.policy.min_client_version);
        out.u64(u64::from(self.policy.mint_allowance));
        out.u64(u64::from(self.policy.retention_days));
        out.u64(u64::from(self.policy.staleness_days));
        out.finish()
    }

    /// Reads the canonical encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed or not canonical.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        ensure!(
            input.take(GENESIS_TAG.len())? == GENESIS_TAG,
            "not a genesis"
        );
        ensure!(input.u8()? == SUITE, "a genesis of an unknown suite");
        let mut roots = Vec::with_capacity(ROOTS);
        for _ in 0..ROOTS {
            roots.push(VerifyingKey::from_bytes(input.bytes()?)?);
        }
        let roots: [VerifyingKey; ROOTS] = roots
            .try_into()
            .map_err(|_keys| anyhow!("three root keys"))?;
        let recovery = input
            .str(MAX_RECIPIENT)?
            .parse()
            .map_err(|error: &str| anyhow!("recovery recipient: {error}"))?;
        let commitments = [input.fixed()?, input.fixed()?, input.fixed()?];
        let policy = Policy {
            min_client_version: input.u64()?,
            mint_allowance: small(input.u64()?)?,
            retention_days: small(input.u64()?)?,
            staleness_days: small(input.u64()?)?,
        };
        input.finish()?;
        let genesis = Self {
            roots,
            recovery,
            commitments,
            policy,
        };
        ensure!(
            genesis.encode() == bytes,
            "the genesis is not in its canonical encoding"
        );
        Ok(genesis)
    }

    /// The genesis hash every object of the vault binds.
    #[must_use]
    pub fn hash(&self) -> Hash {
        sha384(b"txc/v1/genesis-hash", &self.encode())
    }
}

fn small(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_value| anyhow!("a policy value is out of range"))
}

/// A genesis with its root endorsements: the body of the genesis object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedGenesis {
    /// The genesis.
    pub genesis: Genesis,
    /// At least two root signatures over its encoding.
    pub endorsements: Vec<Endorsement>,
}

impl SignedGenesis {
    /// Signs a genesis with two root keys.
    ///
    /// # Errors
    ///
    /// Returns an error when the keys are not two distinct roots of the
    /// genesis.
    pub fn sign(genesis: Genesis, signers: [(&SigningKey, u8); ROOT_QUORUM]) -> Result<Self> {
        let message = genesis.encode();
        let endorsements = signers
            .iter()
            .map(|(key, root)| Endorsement::sign(key, *root, &message))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            quorum(&genesis.roots, &message, &endorsements),
            "genesis needs two distinct root keys"
        );
        Ok(Self {
            genesis,
            endorsements,
        })
    }

    /// The object body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::default();
        out.bytes(&self.genesis.encode());
        Endorsement::write(&self.endorsements, &mut out);
        out.finish()
    }

    /// Reads a genesis body and checks its root quorum.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed or lacks two root signatures.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        let encoded = input.bytes()?;
        let genesis = Genesis::decode(encoded)?;
        let endorsements = Endorsement::read(&mut input)?;
        input.finish()?;
        ensure!(
            quorum(&genesis.roots, encoded, &endorsements),
            "the genesis lacks two root signatures"
        );
        Ok(Self {
            genesis,
            endorsements,
        })
    }
}

// ----------------------------------------------------------- certificates --

/// What a device may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Adds, renews and removes member devices.
    Admin,
    /// Reads and writes entries.
    Writer,
    /// Reads entries.
    Reader,
}

impl Role {
    const fn code(self) -> u8 {
        match self {
            Self::Admin => 1,
            Self::Writer => 2,
            Self::Reader => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        Ok(match code {
            1 => Self::Admin,
            2 => Self::Writer,
            3 => Self::Reader,
            other => bail!("unknown role {other}"),
        })
    }

    /// Whether the role may write entries.
    #[must_use]
    pub const fn writes(self) -> bool {
        matches!(self, Self::Admin | Self::Writer)
    }
}

/// How long a certificate may live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifetime {
    /// An admin: one year, issued by root, renewed at unlock.
    Admin,
    /// A desktop member: 90 days.
    Desktop,
    /// A phone: 7 days, renewed automatically.
    Mobile,
    /// A member without key hardware: 30 days.
    Software,
}

impl Lifetime {
    const fn code(self) -> u8 {
        match self {
            Self::Admin => 1,
            Self::Desktop => 2,
            Self::Mobile => 3,
            Self::Software => 4,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        Ok(match code {
            1 => Self::Admin,
            2 => Self::Desktop,
            3 => Self::Mobile,
            4 => Self::Software,
            other => bail!("unknown lifetime class {other}"),
        })
    }

    /// The longest a certificate of this class may be valid, in seconds.
    #[must_use]
    pub const fn max_seconds(self) -> u64 {
        match self {
            Self::Admin => 365 * DAY,
            Self::Desktop => 90 * DAY,
            Self::Mobile => 7 * DAY,
            Self::Software => 30 * DAY,
        }
    }
}

/// A hardware authenticator registered to a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authenticator {
    /// Its random id.
    pub id: Id,
    /// The name the owner gave it.
    pub nickname: String,
    /// Its fingerprint, shown when it is added.
    pub fingerprint: Hash,
    /// The recipient protected fields are wrapped to.
    pub recipient: String,
}

impl Authenticator {
    /// A new authenticator for a hardware recipient, named as its owner
    /// calls it.
    #[must_use]
    pub fn new(nickname: &str, recipient: &str) -> Self {
        Self {
            id: new_id(),
            nickname: nickname.to_owned(),
            fingerprint: sha384(b"txc/v1/authenticator", recipient.as_bytes()),
            recipient: recipient.to_owned(),
        }
    }

    fn write(&self, out: &mut Writer) {
        out.fixed(&self.id);
        out.str(&self.nickname);
        out.fixed(&self.fingerprint);
        out.str(&self.recipient);
    }

    fn read(input: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            id: input.fixed()?,
            nickname: input.str(MAX_TEXT)?,
            fingerprint: input.fixed()?,
            recipient: input.str(MAX_RECIPIENT)?,
        })
    }
}

/// Who issued a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Issuer {
    /// Two root keys.
    Root,
    /// An admin, by its certificate id.
    Admin(Id),
}

/// A device certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// Its random id.
    pub id: Id,
    /// The vault it belongs to.
    pub genesis: Hash,
    /// The person the device belongs to.
    pub principal: Id,
    /// The device, which keeps its id across renewals.
    pub device: Id,
    /// The device's signing key.
    pub signing_key: VerifyingKey,
    /// The device's age recipient.
    pub recipient: pq::Recipient,
    /// Its registered authenticators.
    pub authenticators: Vec<Authenticator>,
    /// What it may do.
    pub role: Role,
    /// The vault it is scoped to.
    pub scope: String,
    /// Its lifetime class.
    pub lifetime: Lifetime,
    /// Who issued it.
    pub issuer: Issuer,
    /// For an admin, its hardware presence-signing key.
    pub presence_key: Option<Vec<u8>>,
    /// The certificate this one renews, if any.
    pub renews: Option<Id>,
    /// Valid from, in seconds since the epoch.
    pub not_before: u64,
    /// Valid until, in seconds since the epoch; drives write-side decisions
    /// and expiry objects, never the fold.
    pub not_after: u64,
}

fn write_option(out: &mut Writer, value: Option<&[u8]>) {
    out.bool(value.is_some());
    if let Some(value) = value {
        out.bytes(value);
    }
}

impl Certificate {
    /// The canonical encoding its issuer signs.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::default();
        out.fixed(CERT_TAG);
        out.fixed(&self.id);
        out.fixed(&self.genesis);
        out.fixed(&self.principal);
        out.fixed(&self.device);
        out.bytes(&self.signing_key.to_bytes());
        out.str(&self.recipient.to_string());
        out.count(self.authenticators.len());
        for authenticator in &self.authenticators {
            authenticator.write(&mut out);
        }
        out.u8(self.role.code());
        out.str(&self.scope);
        out.u8(self.lifetime.code());
        match self.issuer {
            Issuer::Root => out.u8(0),
            Issuer::Admin(id) => {
                out.u8(1);
                out.fixed(&id);
            }
        }
        write_option(&mut out, self.presence_key.as_deref());
        write_option(&mut out, self.renews.as_ref().map(|id| &id[..]));
        out.u64(self.not_before);
        out.u64(self.not_after);
        out.finish()
    }

    /// Reads the canonical encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed or not canonical.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        ensure!(input.take(CERT_TAG.len())? == CERT_TAG, "not a certificate");
        let id = input.fixed()?;
        let genesis = input.fixed()?;
        let principal = input.fixed()?;
        let device = input.fixed()?;
        let signing_key = VerifyingKey::from_bytes(input.bytes()?)?;
        let recipient = input
            .str(MAX_RECIPIENT)?
            .parse()
            .map_err(|error: &str| anyhow!("device recipient: {error}"))?;
        let authenticators = (0..input.count(MAX_AUTHENTICATORS)?)
            .map(|_| Authenticator::read(&mut input))
            .collect::<Result<_>>()?;
        let role = Role::from_code(input.u8()?)?;
        let scope = input.str(MAX_TEXT)?;
        let lifetime = Lifetime::from_code(input.u8()?)?;
        let issuer = match input.u8()? {
            0 => Issuer::Root,
            1 => Issuer::Admin(input.fixed()?),
            other => bail!("unknown issuer {other}"),
        };
        let presence_key = if input.bool()? {
            Some(input.bytes()?.to_vec())
        } else {
            None
        };
        let renews = if input.bool()? {
            Some(
                input
                    .bytes()?
                    .try_into()
                    .map_err(|_bytes| anyhow!("a certificate id is 16 bytes"))?,
            )
        } else {
            None
        };
        let not_before = input.u64()?;
        let not_after = input.u64()?;
        input.finish()?;
        let certificate = Self {
            id,
            genesis,
            principal,
            device,
            signing_key,
            recipient,
            authenticators,
            role,
            scope,
            lifetime,
            issuer,
            presence_key,
            renews,
            not_before,
            not_after,
        };
        ensure!(
            certificate.encode() == bytes,
            "the certificate is not in its canonical encoding"
        );
        Ok(certificate)
    }

    /// Checks what a certificate must satisfy on its own: the vault, the
    /// lifetime and the pairing of role, class and issuer.
    fn check_shape(&self, genesis: Hash) -> Result<()> {
        ensure!(
            self.genesis == genesis,
            "the certificate belongs to another vault"
        );
        ensure!(
            self.not_before < self.not_after,
            "the certificate ends before it starts"
        );
        ensure!(
            self.not_after.saturating_sub(self.not_before) <= self.lifetime.max_seconds(),
            "the certificate lives longer than its class allows"
        );
        let admin = self.role == Role::Admin;
        ensure!(
            admin == (self.lifetime == Lifetime::Admin),
            "only admins have the admin lifetime"
        );
        ensure!(
            admin == (self.issuer == Issuer::Root),
            "admin certificates come from root and member certificates from an admin"
        );
        Ok(())
    }
}

/// How a certificate was authorised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Issuance {
    /// Two root keys signed it: an admin certificate.
    Root(Vec<Endorsement>),
    /// The issuing admin's device signed it: a member certificate.
    Admin(Vec<u8>),
    /// An admin renewed its own certificate with new keys, signed by the old
    /// and the new key, and co-signed by another device of the same
    /// principal when the vault has one.
    SelfRenewal {
        /// The old key's signature.
        old: Vec<u8>,
        /// The new key's signature.
        new: Vec<u8>,
        /// Another device of the same principal: its certificate id and
        /// signature.
        cosigner: Option<(Id, Vec<u8>)>,
    },
}

/// A certificate with what authorises it: the body of a certificate object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedCertificate {
    /// The certificate.
    pub certificate: Certificate,
    /// Its authorisation.
    pub issuance: Issuance,
}

impl IssuedCertificate {
    /// Issues an admin certificate with two root keys.
    ///
    /// # Errors
    ///
    /// Returns an error when the certificate is not a root-issued admin
    /// certificate or the system has no randomness.
    pub fn by_roots(
        certificate: Certificate,
        signers: [(&SigningKey, u8); ROOT_QUORUM],
    ) -> Result<Self> {
        ensure!(
            certificate.role == Role::Admin && certificate.issuer == Issuer::Root,
            "roots issue admin certificates"
        );
        let message = certificate.encode();
        let endorsements = signers
            .iter()
            .map(|(key, root)| Endorsement::sign(key, *root, &message))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            certificate,
            issuance: Issuance::Root(endorsements),
        })
    }

    /// Issues a member certificate with an admin's device key.
    ///
    /// # Errors
    ///
    /// Returns an error when the system has no randomness.
    pub fn by_admin(certificate: Certificate, admin: &SigningKey) -> Result<Self> {
        let signature = admin.sign(&certificate.encode(), CERT_CONTEXT)?;
        Ok(Self {
            certificate,
            issuance: Issuance::Admin(signature),
        })
    }

    /// Renews an admin's own certificate with its new keys.
    ///
    /// # Errors
    ///
    /// Returns an error when the system has no randomness.
    pub fn self_renewal(
        certificate: Certificate,
        old: &SigningKey,
        new: &SigningKey,
        cosigner: Option<(Id, &SigningKey)>,
    ) -> Result<Self> {
        let cosigner = match cosigner {
            Some((id, key)) => Some((id, cosign(&certificate, key)?)),
            None => None,
        };
        Renewal::admin(certificate, old, new)?.issue(cosigner)
    }

    /// The object body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::default();
        out.bytes(&self.certificate.encode());
        match &self.issuance {
            Issuance::Root(endorsements) => {
                out.u8(0);
                Endorsement::write(endorsements, &mut out);
            }
            Issuance::Admin(signature) => {
                out.u8(1);
                out.bytes(signature);
            }
            Issuance::SelfRenewal { old, new, cosigner } => {
                out.u8(2);
                out.bytes(old);
                out.bytes(new);
                out.bool(cosigner.is_some());
                if let Some((id, signature)) = cosigner {
                    out.fixed(id);
                    out.bytes(signature);
                }
            }
        }
        out.finish()
    }

    /// Reads the object body; [`verify`](Self::verify) checks it.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        let certificate = Certificate::decode(input.bytes()?)?;
        let issuance = match input.u8()? {
            0 => Issuance::Root(Endorsement::read(&mut input)?),
            1 => Issuance::Admin(input.bytes()?.to_vec()),
            2 => Issuance::SelfRenewal {
                old: input.bytes()?.to_vec(),
                new: input.bytes()?.to_vec(),
                cosigner: if input.bool()? {
                    Some((input.fixed()?, input.bytes()?.to_vec()))
                } else {
                    None
                },
            },
            other => bail!("unknown issuance {other}"),
        };
        input.finish()?;
        Ok(Self {
            certificate,
            issuance,
        })
    }

    /// Checks the certificate against genesis and the certificates it names:
    /// its issuing admin, the certificate it renews, and its co-signer. The
    /// caller looks those up among the certificates it has already verified
    /// and still holds valid; whether they were removed or expired is the
    /// fold's business.
    ///
    /// # Errors
    ///
    /// Returns an error naming what does not hold.
    pub fn verify(
        &self,
        genesis: &Genesis,
        known: &dyn Fn(&Id) -> Option<Certificate>,
    ) -> Result<()> {
        self.verify_with(genesis.hash(), &genesis.roots, false, known)
    }

    /// The same, against the roots in force, which a reissue of the sheets
    /// may have replaced; `kept` says the reissue carried this certificate
    /// over, signed by the roots before it.
    ///
    /// # Errors
    ///
    /// Returns an error naming what does not hold.
    pub fn verify_with(
        &self,
        genesis: Hash,
        roots: &[VerifyingKey; ROOTS],
        kept: bool,
        known: &dyn Fn(&Id) -> Option<Certificate>,
    ) -> Result<()> {
        let certificate = &self.certificate;
        certificate.check_shape(genesis)?;
        let message = certificate.encode();
        match (&self.issuance, certificate.issuer) {
            (Issuance::Root(endorsements), Issuer::Root) => {
                ensure!(
                    certificate.role == Role::Admin,
                    "roots issue admin certificates only"
                );
                ensure!(
                    kept || quorum(roots, &message, endorsements),
                    "the certificate lacks two root signatures"
                );
            }
            (Issuance::Admin(signature), Issuer::Admin(admin)) => {
                let issuer =
                    known(&admin).ok_or_else(|| anyhow!("the issuing admin is unknown"))?;
                ensure!(issuer.role == Role::Admin, "the issuer is not an admin");
                ensure!(certificate.role != Role::Admin, "admins cannot add admins");
                ensure!(
                    issuer.signing_key.verify(&message, CERT_CONTEXT, signature),
                    "the issuing admin's signature does not verify"
                );
                if let Some(previous) = certificate.renews {
                    let previous = known(&previous)
                        .ok_or_else(|| anyhow!("the renewed certificate is unknown"))?;
                    ensure!(
                        previous.device == certificate.device
                            && previous.principal == certificate.principal,
                        "a renewal keeps its device and principal"
                    );
                }
            }
            (Issuance::SelfRenewal { old, new, cosigner }, _) => {
                let previous_id = certificate
                    .renews
                    .ok_or_else(|| anyhow!("a renewal names what it renews"))?;
                let previous = known(&previous_id)
                    .ok_or_else(|| anyhow!("the renewed certificate is unknown"))?;
                ensure!(
                    previous.role == Role::Admin && certificate.role == Role::Admin,
                    "only an admin renews itself"
                );
                ensure!(
                    previous.device == certificate.device
                        && previous.principal == certificate.principal
                        && previous.scope == certificate.scope
                        && previous.issuer == certificate.issuer,
                    "a renewal changes keys, never the device, principal, scope or issuer"
                );
                ensure!(
                    previous.signing_key.verify(&message, RENEWAL_CONTEXT, old),
                    "the old key did not sign the renewal"
                );
                ensure!(
                    certificate
                        .signing_key
                        .verify(&message, RENEWAL_CONTEXT, new),
                    "the new key did not sign the renewal"
                );
                if let Some((cosigner, signature)) = cosigner {
                    let cosigner = known(cosigner)
                        .ok_or_else(|| anyhow!("the co-signing device is unknown"))?;
                    ensure!(
                        cosigner.principal == certificate.principal
                            && cosigner.device != certificate.device,
                        "the co-signer is another device of the same person"
                    );
                    ensure!(
                        cosigner
                            .signing_key
                            .verify(&message, CERT_CONTEXT, signature),
                        "the co-signature does not verify"
                    );
                }
            }
            _ => bail!("the certificate's issuer and its signatures disagree"),
        }
        Ok(())
    }
}

/// A co-signature by another device of the same person on an admin's
/// renewal: "Approve renewal of laptop x1?".
///
/// # Errors
///
/// Returns an error when the system has no randomness.
pub fn cosign(certificate: &Certificate, key: &SigningKey) -> Result<Vec<u8>> {
    key.sign(&certificate.encode(), CERT_CONTEXT)
}

// ---------------------------------------------------------------- renewal --

/// A device asking for its certificate to be renewed with fresh keys,
/// proving it holds both the old and the new signing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenewalRequest {
    /// The certificate to renew.
    pub certificate: Id,
    /// The device asking.
    pub device: Id,
    /// Its new signing key.
    pub signing_key: VerifyingKey,
    /// Its new age recipient.
    pub recipient: pq::Recipient,
    /// Authenticators to add: hardware this device proved it holds.
    pub authenticators: Vec<Authenticator>,
    /// The old key's signature.
    pub old: Vec<u8>,
    /// The new key's signature.
    pub new: Vec<u8>,
}

impl RenewalRequest {
    fn message(&self) -> Vec<u8> {
        let mut out = Writer::default();
        out.fixed(RENEWAL_TAG);
        out.fixed(&self.certificate);
        out.fixed(&self.device);
        out.bytes(&self.signing_key.to_bytes());
        out.str(&self.recipient.to_string());
        out.count(self.authenticators.len());
        for authenticator in &self.authenticators {
            authenticator.write(&mut out);
        }
        out.finish()
    }

    /// Makes a request signed with both keys.
    ///
    /// # Errors
    ///
    /// Returns an error when the system has no randomness.
    pub fn new(
        current: &Certificate,
        old: &SigningKey,
        new: &SigningKey,
        recipient: pq::Recipient,
        authenticators: Vec<Authenticator>,
    ) -> Result<Self> {
        let mut request = Self {
            certificate: current.id,
            device: current.device,
            signing_key: new.verifying_key(),
            recipient,
            authenticators,
            old: Vec::new(),
            new: Vec::new(),
        };
        let message = request.message();
        request.old = old.sign(&message, RENEWAL_CONTEXT)?;
        request.new = new.sign(&message, RENEWAL_CONTEXT)?;
        Ok(request)
    }

    /// Checks both signatures against the certificate being renewed.
    ///
    /// # Errors
    ///
    /// Returns an error when the request is not for this certificate or a
    /// signature does not verify.
    pub fn verify(&self, current: &Certificate) -> Result<()> {
        ensure!(
            self.certificate == current.id && self.device == current.device,
            "the request is for another certificate"
        );
        let message = self.message();
        ensure!(
            current
                .signing_key
                .verify(&message, RENEWAL_CONTEXT, &self.old),
            "the old key did not sign the request"
        );
        ensure!(
            self.signing_key
                .verify(&message, RENEWAL_CONTEXT, &self.new),
            "the new key did not sign the request"
        );
        Ok(())
    }

    /// The object body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::default();
        out.bytes(&self.message());
        out.bytes(&self.old);
        out.bytes(&self.new);
        out.finish()
    }

    /// Reads the object body.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut outer = Reader(bytes);
        let message = outer.bytes()?;
        let old = outer.bytes()?.to_vec();
        let new = outer.bytes()?.to_vec();
        outer.finish()?;
        let mut input = Reader(message);
        ensure!(
            input.take(RENEWAL_TAG.len())? == RENEWAL_TAG,
            "not a renewal request"
        );
        let certificate = input.fixed()?;
        let device = input.fixed()?;
        let signing_key = VerifyingKey::from_bytes(input.bytes()?)?;
        let recipient = input
            .str(MAX_RECIPIENT)?
            .parse()
            .map_err(|error: &str| anyhow!("new recipient: {error}"))?;
        let authenticators = (0..input.count(MAX_AUTHENTICATORS)?)
            .map(|_| Authenticator::read(&mut input))
            .collect::<Result<_>>()?;
        input.finish()?;
        Ok(Self {
            certificate,
            device,
            signing_key,
            recipient,
            authenticators,
            old,
            new,
        })
    }
}

/// The body of a renewal-request object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Renewal {
    /// A member asks an admin for a certificate for its new keys.
    Member(RenewalRequest),
    /// An admin asks another device of its owner to co-sign its renewal:
    /// the new certificate, signed with its old and new keys.
    Admin {
        /// The proposed certificate.
        certificate: Certificate,
        /// The old key's signature.
        old: Vec<u8>,
        /// The new key's signature.
        new: Vec<u8>,
    },
    /// The co-signature, sent back to the admin.
    Cosign {
        /// The proposed certificate's id.
        certificate: Id,
        /// The co-signature over it.
        signature: Vec<u8>,
    },
}

impl Renewal {
    /// An admin's proposal, signed with both keys.
    ///
    /// # Errors
    ///
    /// Returns an error when the system has no randomness.
    pub fn admin(certificate: Certificate, old: &SigningKey, new: &SigningKey) -> Result<Self> {
        let message = certificate.encode();
        Ok(Self::Admin {
            old: old.sign(&message, RENEWAL_CONTEXT)?,
            new: new.sign(&message, RENEWAL_CONTEXT)?,
            certificate,
        })
    }

    /// Turns an admin's proposal into its certificate, with the
    /// co-signature when there is one.
    ///
    /// # Errors
    ///
    /// Returns an error when this is not an admin's proposal.
    pub fn issue(self, cosigner: Option<(Id, Vec<u8>)>) -> Result<IssuedCertificate> {
        let Self::Admin {
            certificate,
            old,
            new,
        } = self
        else {
            bail!("not an admin's renewal")
        };
        Ok(IssuedCertificate {
            certificate,
            issuance: Issuance::SelfRenewal { old, new, cosigner },
        })
    }

    /// The object body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::default();
        match self {
            Self::Member(request) => {
                out.u8(1);
                out.bytes(&request.encode());
            }
            Self::Admin {
                certificate,
                old,
                new,
            } => {
                out.u8(2);
                out.bytes(&certificate.encode());
                out.bytes(old);
                out.bytes(new);
            }
            Self::Cosign {
                certificate,
                signature,
            } => {
                out.u8(3);
                out.fixed(certificate);
                out.bytes(signature);
            }
        }
        out.finish()
    }

    /// Reads the object body.
    ///
    /// # Errors
    ///
    /// Returns an error when it is malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        let renewal = match input.u8()? {
            1 => Self::Member(RenewalRequest::decode(input.bytes()?)?),
            2 => Self::Admin {
                certificate: Certificate::decode(input.bytes()?)?,
                old: input.bytes()?.to_vec(),
                new: input.bytes()?.to_vec(),
            },
            3 => Self::Cosign {
                certificate: input.fixed()?,
                signature: input.bytes()?.to_vec(),
            },
            other => bail!("unknown renewal {other}"),
        };
        input.finish()?;
        Ok(renewal)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const CARD: &str = "apple river stone cloud maple tiger";

    pub(crate) struct Roots {
        pub keys: [SigningKey; ROOTS],
        pub genesis: Genesis,
    }

    pub(crate) fn roots() -> Roots {
        let shares = [[1_u8; 33], [2; 33], [3; 33]];
        let keys = [0, 1, 2].map(|index| root_key(&shares[index], CARD, index).unwrap());
        let genesis = Genesis {
            roots: [0, 1, 2].map(|index| keys[index].verifying_key()),
            recovery: recovery_identity(&[9; 32]).to_public(),
            commitments: shares.map(|share| share_commitment(&share)),
            policy: Policy::default(),
        };
        Roots { keys, genesis }
    }

    pub(crate) fn certificate(
        genesis: &Genesis,
        role: Role,
        issuer: Issuer,
        key: &SigningKey,
    ) -> Certificate {
        let lifetime = if role == Role::Admin {
            Lifetime::Admin
        } else {
            Lifetime::Desktop
        };
        Certificate {
            id: new_id(),
            genesis: genesis.hash(),
            principal: [7; 16],
            device: new_id(),
            signing_key: key.verifying_key(),
            recipient: pq::Identity::generate().to_public(),
            authenticators: Vec::new(),
            role,
            scope: "personal".into(),
            lifetime,
            issuer,
            presence_key: None,
            renews: None,
            not_before: 1_000,
            not_after: 1_000 + lifetime.max_seconds(),
        }
    }

    #[test]
    fn the_card_has_one_canonical_form() {
        assert_eq!(
            *normalize_card("  Apple   RIVER\tstone ").unwrap(),
            "apple river stone"
        );
        assert!(normalize_card("apple r1ver").is_err());
        assert!(normalize_card("   ").is_err());
        let share = [5; 33];
        assert_eq!(
            root_key(&share, "Apple  river", 0).unwrap().verifying_key(),
            root_key(&share, "apple river", 0).unwrap().verifying_key()
        );
    }

    #[test]
    fn each_root_key_needs_its_share_and_the_card() {
        let share = [5; 33];
        let key = root_key(&share, CARD, 0).unwrap().verifying_key();
        assert_ne!(key, root_key(&share, CARD, 1).unwrap().verifying_key());
        assert_ne!(
            key,
            root_key(&share, "another card", 0).unwrap().verifying_key()
        );
        assert_ne!(key, root_key(&[6; 33], CARD, 0).unwrap().verifying_key());
        assert!(root_key(&share, CARD, 3).is_err());
    }

    #[test]
    fn genesis_needs_two_distinct_roots() {
        let Roots { keys, genesis } = roots();
        let signed = SignedGenesis::sign(genesis.clone(), [(&keys[0], 0), (&keys[2], 2)]).unwrap();
        assert_eq!(SignedGenesis::decode(&signed.encode()).unwrap(), signed);
        assert!(SignedGenesis::sign(genesis.clone(), [(&keys[0], 0), (&keys[0], 0)]).is_err());
        // A key signing under another root's index does not count.
        assert!(SignedGenesis::sign(genesis, [(&keys[0], 0), (&keys[0], 1)]).is_err());
    }

    #[test]
    fn a_genesis_round_trips_canonically() {
        let genesis = roots().genesis;
        let encoded = genesis.encode();
        assert_eq!(Genesis::decode(&encoded).unwrap(), genesis);
        let mut longer = encoded;
        longer.push(0);
        assert!(Genesis::decode(&longer).is_err());
    }

    #[test]
    fn certificates_chain_to_genesis() {
        let Roots { keys, genesis } = roots();
        let admin_key = SigningKey::generate();
        let admin = IssuedCertificate::by_roots(
            certificate(&genesis, Role::Admin, Issuer::Root, &admin_key),
            [(&keys[1], 1), (&keys[2], 2)],
        )
        .unwrap();
        let none = |_: &Id| None;
        admin.verify(&genesis, &none).unwrap();
        assert_eq!(IssuedCertificate::decode(&admin.encode()).unwrap(), admin);

        let member_key = SigningKey::generate();
        let member = IssuedCertificate::by_admin(
            certificate(
                &genesis,
                Role::Writer,
                Issuer::Admin(admin.certificate.id),
                &member_key,
            ),
            &admin_key,
        )
        .unwrap();
        let admin_cert = admin.certificate.clone();
        let known = move |id: &Id| (*id == admin_cert.id).then(|| admin_cert.clone());
        member.verify(&genesis, &known).unwrap();
        assert!(member.verify(&genesis, &none).is_err());

        // An admin cannot mint an admin, nor sign as another admin.
        let rogue = IssuedCertificate::by_admin(
            certificate(
                &genesis,
                Role::Admin,
                Issuer::Admin(admin.certificate.id),
                &member_key,
            ),
            &admin_key,
        )
        .unwrap();
        assert!(rogue.verify(&genesis, &known).is_err());
        let forged = IssuedCertificate::by_admin(
            certificate(
                &genesis,
                Role::Writer,
                Issuer::Admin(admin.certificate.id),
                &member_key,
            ),
            &member_key,
        )
        .unwrap();
        assert!(forged.verify(&genesis, &known).is_err());

        // Another vault's certificate, or one living too long, is refused.
        let mut long = certificate(
            &genesis,
            Role::Writer,
            Issuer::Admin(admin.certificate.id),
            &member_key,
        );
        long.not_after += 1;
        assert!(
            IssuedCertificate::by_admin(long, &admin_key)
                .unwrap()
                .verify(&genesis, &known)
                .is_err()
        );
        let mut other = certificate(
            &genesis,
            Role::Writer,
            Issuer::Admin(admin.certificate.id),
            &member_key,
        );
        other.genesis = [0; 48];
        assert!(
            IssuedCertificate::by_admin(other, &admin_key)
                .unwrap()
                .verify(&genesis, &known)
                .is_err()
        );
    }

    #[test]
    fn an_admin_renews_itself_with_both_keys_and_a_cosigner() {
        let Roots { genesis, .. } = roots();
        let old_key = SigningKey::generate();
        let first = certificate(&genesis, Role::Admin, Issuer::Root, &old_key);
        let phone_key = SigningKey::generate();
        let mut phone = certificate(&genesis, Role::Writer, Issuer::Admin(first.id), &phone_key);
        phone.principal = first.principal;
        let known = {
            let (first, phone) = (first.clone(), phone.clone());
            move |id: &Id| {
                [&first, &phone]
                    .into_iter()
                    .find(|cert| cert.id == *id)
                    .cloned()
            }
        };

        let new_key = SigningKey::generate();
        let mut renewed = first.clone();
        renewed.id = new_id();
        renewed.signing_key = new_key.verifying_key();
        renewed.renews = Some(first.id);
        let ok = IssuedCertificate::self_renewal(
            renewed.clone(),
            &old_key,
            &new_key,
            Some((phone.id, &phone_key)),
        )
        .unwrap();
        ok.verify(&genesis, &known).unwrap();
        assert_eq!(IssuedCertificate::decode(&ok.encode()).unwrap(), ok);

        // Without the old key, or with a different device, it fails.
        let thief = SigningKey::generate();
        assert!(
            IssuedCertificate::self_renewal(renewed.clone(), &thief, &new_key, None)
                .unwrap()
                .verify(&genesis, &known)
                .is_err()
        );
        let mut moved = renewed;
        moved.device = new_id();
        assert!(
            IssuedCertificate::self_renewal(moved, &old_key, &new_key, None)
                .unwrap()
                .verify(&genesis, &known)
                .is_err()
        );
    }

    #[test]
    fn a_renewal_request_proves_both_keys() {
        let genesis = roots().genesis;
        let old = SigningKey::generate();
        let current = certificate(&genesis, Role::Writer, Issuer::Admin([1; 16]), &old);
        let new = SigningKey::generate();
        let request = RenewalRequest::new(
            &current,
            &old,
            &new,
            pq::Identity::generate().to_public(),
            Vec::new(),
        )
        .unwrap();
        request.verify(&current).unwrap();
        let read = RenewalRequest::decode(&request.encode()).unwrap();
        assert_eq!(read, request);
        let thief = SigningKey::generate();
        assert!(
            RenewalRequest::new(
                &current,
                &thief,
                &new,
                request.recipient.clone(),
                Vec::new()
            )
            .unwrap()
            .verify(&current)
            .is_err()
        );
    }

    #[test]
    fn every_renewal_body_round_trips() {
        let genesis = roots().genesis;
        let old = SigningKey::generate();
        let new = SigningKey::generate();
        let current = certificate(&genesis, Role::Writer, Issuer::Admin([1; 16]), &old);
        let member = Renewal::Member(
            RenewalRequest::new(
                &current,
                &old,
                &new,
                pq::Identity::generate().to_public(),
                Vec::new(),
            )
            .unwrap(),
        );
        let admin = Renewal::admin(
            certificate(&genesis, Role::Admin, Issuer::Root, &new),
            &old,
            &new,
        )
        .unwrap();
        let cosign = Renewal::Cosign {
            certificate: [3; 16],
            signature: vec![1, 2],
        };
        for body in [member, admin, cosign] {
            assert_eq!(Renewal::decode(&body.encode()).unwrap(), body);
        }
    }
}
