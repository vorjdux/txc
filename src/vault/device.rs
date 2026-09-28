//! A device's view of a vault (study sections 5, 7 and 8): what it has read
//! from the folder and verified, and what it writes there.
//!
//! [`Device::sync`] reads every object it has not seen: a control object is
//! opened with the device's identity, a content object by its tag under a
//! sender key the device holds. Each is verified against the certificates
//! and facts known so far; an object whose author or key is not yet known is
//! kept and retried as more arrives, so arrival order never matters.
//! Validity is evaluated lazily from the facts held, so a removal that
//! arrives late still voids everything its device wrote after the cutoff.
//!
//! Writes follow rule 12: control objects go to the members of this
//! device's view at their newest certificates, plus the recovery recipient;
//! content goes under the device's current sender key, which is replaced
//! before the next write whenever the view has changed (rule 11).
//!
//! The device never reads a clock: `now` is passed in where certificates
//! are issued or expiry is judged, and never reaches the fold.

use std::collections::{BTreeMap, BTreeSet};

use age_core::secrecy::ExposeSecret;
use anyhow::{Context, Result, anyhow, bail, ensure};
use zeroize::Zeroizing;

use crate::vault::authority::{
    Certificate, Endorsement, Genesis, Issuance, IssuedCertificate, Issuer, Lifetime, Renewal,
    RenewalRequest, Role, SignedGenesis, new_id, quorum,
};
use crate::vault::composite::SigningKey;
use crate::vault::control::{
    Checkpoint, Counter, Cutoff, Fact, FactKind, Forward, Join, SenderKeyBody, effective_cutoff,
    fact_set_hash,
};
use crate::vault::core::membership;
use crate::vault::object::{
    Addressing, Hash, Id, Kind, Payload, SenderKey, Signed, open_content, open_control,
    seal_content, seal_control,
};
use crate::vault::pairing;
use crate::vault::pq;
use crate::vault::store::{Name, Store};
use crate::vault::wire::{Reader, Writer};

const AGE_MAGIC: &[u8] = b"age-encryption.org/v1\n";

/// This device's own secrets.
pub struct Me {
    /// Its id, kept across renewals.
    pub device: Id,
    /// Its signing key.
    pub signing: SigningKey,
    /// Its age identity.
    pub identity: pq::Identity,
    /// Identities replaced at renewal, kept to read older control objects.
    pub retired: Vec<pq::Identity>,
    /// Its current certificate, once it has one.
    pub certificate: Option<Id>,
}

impl Me {
    /// A new device with fresh keys.
    #[must_use]
    pub fn generate() -> Self {
        Self {
            device: new_id(),
            signing: SigningKey::generate(),
            identity: pq::Identity::generate(),
            retired: Vec::new(),
            certificate: None,
        }
    }

    /// The public keys this device shows when pairing.
    #[must_use]
    pub fn keys(&self) -> pairing::Keys {
        pairing::Keys {
            device: self.device,
            signing_key: self.signing.verifying_key(),
            recipient: self.identity.to_public(),
        }
    }
}

/// Where an object sits: its author and its place in the author's chain.
#[derive(Clone, Copy)]
struct At {
    author: Id,
    seq: u64,
    hash: Hash,
}

/// A sender key this device can read with.
struct Key {
    writer: Id,
    certificate: Id,
    sender: SenderKey,
}

/// This device's current sender key.
struct Mine {
    key: SenderKey,
    recipients: BTreeSet<(Id, Id)>,
    next: u64,
}

/// A co-signing device's certificate id and its signature.
type Cosigner = (Id, Vec<u8>);

/// A content object accepted for the layers above.
#[derive(Clone, Debug)]
pub struct Content {
    /// Its object hash.
    pub hash: Hash,
    /// Its verified payload.
    pub payload: Payload,
}

/// Something every device should show in its status.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Alarm {
    /// Two different objects for one position in a device's chain.
    Fork(Id),
    /// A renewal for this device that it did not make: it stops writing
    /// and must be paired again under a new id.
    Hijack,
    /// This device was removed, expired or killed.
    Removed,
    /// The folder holds this device's objects beyond its local position:
    /// it was restored from a backup and must be paired again.
    Restored,
}

/// A device's view of one vault.
pub struct Device {
    me: Me,
    genesis_hash: Hash,
    genesis: Option<Genesis>,
    pinned_admin: Option<pairing::Keys>,
    certificates: BTreeMap<Id, (Certificate, Option<At>)>,
    /// Admin self-renewals made without a co-signature.
    lone_renewals: BTreeSet<Id>,
    /// This admin's renewal waiting for a co-signature, and the co-signature
    /// once it arrives.
    proposal: Option<(Renewal, Option<Cosigner>)>,
    /// Renewals of this owner's admin waiting for approval here.
    approvals: BTreeMap<Id, Certificate>,
    facts: BTreeMap<Hash, (Fact, At)>,
    certificate_objects: BTreeMap<Id, Hash>,
    renewal: Option<(SigningKey, pq::Identity)>,
    /// Verified control objects, kept for joins and forwards.
    held: BTreeMap<Hash, Signed>,
    keys: BTreeMap<Id, Key>,
    mine: Option<Mine>,
    seq: u64,
    prev: Hash,
    heads: BTreeMap<Id, (u64, Hash)>,
    positions: BTreeMap<(Id, u64), Hash>,
    key_counters: BTreeMap<Id, Counter>,
    control_counters: BTreeMap<Id, Counter>,
    sent: BTreeMap<Id, u64>,
    done: BTreeSet<Name>,
    unreadable: BTreeSet<Name>,
    waiting: BTreeMap<Name, Signed>,
    content: BTreeMap<Hash, Content>,
    checkpoints: BTreeMap<Id, (u64, Checkpoint)>,
    alarms: BTreeSet<Alarm>,
    originated: BTreeSet<Id>,
    /// This device's own content objects in the folder, for collection.
    written: BTreeMap<Hash, Name>,
    /// Snapshots this device verified (rule 13); remembered because what
    /// they cover is collected afterwards.
    verified: BTreeSet<Hash>,
}

impl Device {
    const fn empty(me: Me, genesis_hash: Hash) -> Self {
        Self {
            me,
            genesis_hash,
            genesis: None,
            pinned_admin: None,
            certificates: BTreeMap::new(),
            lone_renewals: BTreeSet::new(),
            proposal: None,
            approvals: BTreeMap::new(),
            facts: BTreeMap::new(),
            certificate_objects: BTreeMap::new(),
            renewal: None,
            held: BTreeMap::new(),
            keys: BTreeMap::new(),
            mine: None,
            seq: 0,
            prev: [0; 48],
            heads: BTreeMap::new(),
            positions: BTreeMap::new(),
            key_counters: BTreeMap::new(),
            control_counters: BTreeMap::new(),
            sent: BTreeMap::new(),
            done: BTreeSet::new(),
            unreadable: BTreeSet::new(),
            waiting: BTreeMap::new(),
            content: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            alarms: BTreeSet::new(),
            originated: BTreeSet::new(),
            written: BTreeMap::new(),
            verified: BTreeSet::new(),
        }
    }

    /// Creates a vault: genesis signed by two roots, and this device's admin
    /// certificate issued by them. Writes both to the folder.
    ///
    /// # Errors
    ///
    /// Returns an error when the roots do not sign or the write fails.
    pub fn create(
        store: &Store,
        me: Me,
        genesis: Genesis,
        roots: [(&SigningKey, u8); 2],
        principal: Id,
        scope: &str,
        now: u64,
    ) -> Result<Self> {
        let signed_genesis = SignedGenesis::sign(genesis.clone(), roots)?;
        let genesis_hash = genesis.hash();
        let mut device = Self::empty(me, genesis_hash);
        device.genesis = Some(genesis);
        let certificate = Certificate {
            id: new_id(),
            genesis: genesis_hash,
            principal,
            device: device.me.device,
            signing_key: device.me.signing.verifying_key(),
            recipient: device.me.identity.to_public(),
            authenticators: Vec::new(),
            role: Role::Admin,
            scope: scope.to_owned(),
            lifetime: Lifetime::Admin,
            issuer: Issuer::Root,
            presence_key: None,
            renews: None,
            not_before: now,
            not_after: now.saturating_add(Lifetime::Admin.max_seconds()),
        };
        let id = certificate.id;
        let issued = IssuedCertificate::by_roots(certificate, roots)?;
        device.accept_certificate(&issued, None)?;
        device.me.certificate = Some(id);
        device.originated.insert(id);
        device.write_control(
            store,
            Kind::Genesis,
            &signed_genesis.encode(),
            &[device.me.device],
        )?;
        device.write_control(
            store,
            Kind::Certificate,
            &issued.encode(),
            &[device.me.device],
        )?;
        Ok(device)
    }

    /// A device that has just paired: it pins the genesis hash and the
    /// admin's keys from the ceremony and waits for its join package.
    #[must_use]
    pub fn joining(me: Me, paired: &pairing::Paired) -> Self {
        let mut device = Self::empty(me, paired.genesis);
        device.pinned_admin = Some(paired.peer.clone());
        device
    }

    /// This device's secrets.
    #[must_use]
    pub const fn me(&self) -> &Me {
        &self.me
    }

    /// The vault's genesis hash.
    #[must_use]
    pub const fn genesis_hash(&self) -> Hash {
        self.genesis_hash
    }

    /// The admin this device paired with, whose join snapshot it trusts.
    #[must_use]
    pub fn paired_admin(&self) -> Option<Id> {
        self.pinned_admin.as_ref().map(|keys| keys.device)
    }

    /// Alarms raised so far.
    #[must_use]
    pub const fn alarms(&self) -> &BTreeSet<Alarm> {
        &self.alarms
    }

    /// The certificate with this id, if verified.
    #[must_use]
    pub fn certificate(&self, id: &Id) -> Option<&Certificate> {
        self.certificates
            .get(id)
            .map(|(certificate, _)| certificate)
    }

    fn my_certificate(&self) -> Result<&Certificate> {
        self.me
            .certificate
            .and_then(|id| self.certificate(&id))
            .ok_or_else(|| anyhow!("this device has no certificate in this vault yet"))
    }

    // ------------------------------------------------------------ validity --

    /// The cutoff of every device taken out, from the facts that are valid.
    /// Root facts are always valid; an admin's facts only up to any cutoff
    /// root set for it; and expiry of an admin by another device of its
    /// owner only while that device is itself within its cutoff.
    fn cutoffs(&self) -> BTreeMap<Id, Cutoff> {
        let Some(genesis) = &self.genesis else {
            return BTreeMap::new();
        };
        let rooted = |fact: &Fact| quorum(&genesis.roots, &fact.statement(), &fact.endorsements);
        let within = Self::within;
        let collect = |valid: &dyn Fn(&Fact, &At) -> bool| -> BTreeMap<Id, Cutoff> {
            let facts: Vec<&Fact> = self
                .facts
                .values()
                .filter(|(fact, held)| valid(fact, held))
                .map(|(fact, _)| fact)
                .collect();
            let devices: BTreeSet<Id> = facts.iter().map(|fact| fact.device).collect();
            devices
                .into_iter()
                .filter_map(|device| {
                    effective_cutoff(facts.iter().copied(), &device).map(|cutoff| (device, cutoff))
                })
                .collect()
        };
        let roots_only = collect(&|fact, _| rooted(fact));
        let with_admins = collect(&|fact, held| {
            rooted(fact)
                || (self.is_admin_device(&held.author)
                    && within(&roots_only, held)
                    && !self.is_admin_device(&fact.device))
        });
        collect(&|fact, held| {
            rooted(fact)
                || (self.is_admin_device(&held.author)
                    && within(&with_admins, held)
                    && !self.is_admin_device(&fact.device))
                || (matches!(fact.kind, FactKind::Expire(_))
                    && self.is_admin_device(&fact.device)
                    && self.same_principal(&held.author, &fact.device)
                    && within(&with_admins, held))
        })
    }

    fn is_admin_device(&self, device: &Id) -> bool {
        self.certificates
            .values()
            .any(|(cert, _)| cert.device == *device && cert.role == Role::Admin)
    }

    fn same_principal(&self, a: &Id, b: &Id) -> bool {
        let principal = |device: &Id| {
            self.certificates
                .values()
                .find(|(cert, _)| cert.device == *device)
                .map(|(cert, _)| cert.principal)
        };
        a != b && principal(a).is_some() && principal(a) == principal(b)
    }

    /// Whether an object is valid under the cutoffs: before its author's
    /// cutoff, or the very object the cutoff names. Another object at the
    /// cutoff's position is a fork and is not.
    fn within(cutoffs: &BTreeMap<Id, Cutoff>, at: &At) -> bool {
        cutoffs.get(&at.author).is_none_or(|cutoff| {
            at.seq < cutoff.seq || (at.seq == cutoff.seq && at.hash == cutoff.hash)
        })
    }

    fn principal_of(&self, device: &Id) -> Option<Id> {
        self.certificates
            .values()
            .find(|(cert, _)| cert.device == *device)
            .map(|(cert, _)| cert.principal)
    }

    fn rooted(&self, fact: &Fact) -> bool {
        self.genesis
            .as_ref()
            .is_some_and(|genesis| quorum(&genesis.roots, &fact.statement(), &fact.endorsements))
    }

    /// How many devices an admin may add: the policy's allowance plus every
    /// root grant, counted over facts, never time.
    fn allowance(&self, admin: &Id) -> u64 {
        let base = self
            .genesis
            .as_ref()
            .map_or(0, |genesis| u64::from(genesis.policy.mint_allowance));
        self.facts
            .values()
            .filter(|(fact, _)| fact.device == *admin && self.rooted(fact))
            .filter_map(|(fact, _)| match fact.kind {
                FactKind::MintAllowance(count) => Some(u64::from(count)),
                _ => None,
            })
            .fold(base, u64::saturating_add)
    }

    /// The adds an admin had made up to and including a position in its
    /// chain.
    fn adds_by(&self, admin: &Id, up_to: u64) -> u64 {
        self.facts
            .values()
            .filter(|(fact, at)| {
                matches!(fact.kind, FactKind::Add { .. }) && at.author == *admin && at.seq <= up_to
            })
            .fold(0, |count, _| count.saturating_add(1))
    }

    /// Whether a certificate is valid: its issuer was within its cutoff when
    /// it published it.
    fn certificate_valid(&self, cutoffs: &BTreeMap<Id, Cutoff>, id: &Id) -> bool {
        let Some((certificate, published)) = self.certificates.get(id) else {
            return false;
        };
        if self.lone_renewals.contains(id)
            && published
                .as_ref()
                .is_some_and(|at| self.needed_cosigner(cutoffs, certificate, at))
        {
            return false;
        }
        match (certificate.issuer, published) {
            (Issuer::Root, _) => true,
            (Issuer::Admin(_), Some(at)) => Self::within(cutoffs, at),
            (Issuer::Admin(_), None) => false,
        }
    }

    /// An admin renewing itself needs a co-signature once it had added
    /// another device of its owner that is still a member: a stolen admin
    /// cannot renew itself alone.
    fn needed_cosigner(
        &self,
        cutoffs: &BTreeMap<Id, Cutoff>,
        certificate: &Certificate,
        at: &At,
    ) -> bool {
        self.facts.values().any(|(fact, added)| {
            matches!(fact.kind, FactKind::Add { .. })
                && added.author == certificate.device
                && added.seq < at.seq
                && fact.device != certificate.device
                && !cutoffs.contains_key(&fact.device)
                && self.principal_of(&fact.device) == Some(certificate.principal)
        })
    }

    /// The member set: every device with a valid root-issued admin
    /// certificate, plus added devices, minus every device taken out.
    #[must_use]
    pub fn members(&self) -> BTreeSet<Id> {
        let cutoffs = self.cutoffs();
        let genesis: BTreeSet<Id> = self
            .certificates
            .values()
            .filter(|(cert, _)| cert.issuer == Issuer::Root)
            .map(|(cert, _)| cert.device)
            .collect();
        let facts: BTreeSet<membership::Fact<Id>> = self
            .facts
            .values()
            .filter(|(fact, held)| match fact.kind {
                FactKind::Add { certificate } => {
                    self.is_admin_device(&held.author)
                        && Self::within(&cutoffs, held)
                        && self.certificate_valid(&cutoffs, &certificate)
                        && self.adds_by(&held.author, held.seq) <= self.allowance(&held.author)
                }
                _ => cutoffs.contains_key(&fact.device),
            })
            .filter_map(|(fact, _)| fact.membership())
            .collect();
        membership::members(&genesis, &facts)
    }

    /// Each member at its newest valid certificate: the latest to start,
    /// ties broken by id, so every device picks the same one.
    #[must_use]
    pub fn view(&self) -> BTreeMap<Id, Certificate> {
        let cutoffs = self.cutoffs();
        let members = self.members();
        let mut view: BTreeMap<Id, Certificate> = BTreeMap::new();
        for (id, (certificate, _)) in &self.certificates {
            if !members.contains(&certificate.device) || !self.certificate_valid(&cutoffs, id) {
                continue;
            }
            let newer = view.get(&certificate.device).is_none_or(|current| {
                (certificate.not_before, certificate.id) > (current.not_before, current.id)
            });
            if newer {
                view.insert(certificate.device, certificate.clone());
            }
        }
        view
    }

    // -------------------------------------------------------------- reading --

    /// Reads every object not yet seen and verifies what it can. Returns how
    /// many objects were accepted.
    ///
    /// # Errors
    ///
    /// Returns an error when the folder cannot be read.
    pub fn sync(&mut self, store: &Store) -> Result<usize> {
        let listing = store.list()?;
        let mut accepted = 0_usize;
        let mut fresh: Vec<Name> = listing
            .names
            .into_iter()
            .filter(|name| !self.done.contains(name))
            .collect();
        fresh.retain(|name| !self.unreadable.contains(name) && !self.waiting.contains_key(name));
        for name in fresh {
            let Some(object) = store
                .read(&name)
                .with_context(|| format!("reading {name}"))?
            else {
                continue;
            };
            accepted = accepted.saturating_add(self.classify(name, &object.bytes));
        }
        // Retry whatever waited for a certificate, a fact or a key until
        // nothing more can be accepted.
        loop {
            let before = accepted;
            for (name, signed) in std::mem::take(&mut self.waiting) {
                accepted = accepted.saturating_add(self.accept_signed(name, signed));
            }
            for name in std::mem::take(&mut self.unreadable) {
                if let Some(object) = store.read(&name)? {
                    accepted = accepted.saturating_add(self.classify(name, &object.bytes));
                }
            }
            if accepted == before {
                break;
            }
        }
        self.check_restored();
        self.finish_self_renewal(store)?;
        Ok(accepted)
    }

    fn classify(&mut self, name: Name, bytes: &[u8]) -> usize {
        if bytes.starts_with(AGE_MAGIC) {
            let identities = std::iter::once(&self.me.identity).chain(&self.me.retired);
            for identity in identities {
                match open_control(bytes, identity) {
                    Ok(Some(signed)) => return self.accept_signed(name, signed),
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
            // Not addressed to this device, or damaged: either way final.
            self.done.insert(name);
            return 0;
        }
        let keys: Vec<SenderKey> = self
            .keys
            .values()
            .map(|key| SenderKey::from_parts(key.sender.id, key.sender.secret().clone()))
            .collect();
        match open_content(bytes, &keys) {
            Ok(Some((_, signed))) => self.accept_signed(name, signed),
            // Under a key this device may receive later.
            Ok(None) => {
                self.unreadable.insert(name);
                0
            }
            Err(_) => {
                self.done.insert(name);
                0
            }
        }
    }

    /// Verifies and applies one opened object. Returns 1 when accepted; an
    /// object that cannot be verified yet waits.
    fn accept_signed(&mut self, name: Name, signed: Signed) -> usize {
        match self.apply(&signed) {
            Ok(true) => {
                self.done.insert(name);
                1
            }
            Ok(false) => {
                self.waiting.insert(name, signed);
                0
            }
            Err(_) => {
                self.done.insert(name);
                0
            }
        }
    }

    /// Applies a signed object: `Ok(true)` accepted, `Ok(false)` not yet
    /// verifiable, `Err` invalid for good.
    fn apply(&mut self, signed: &Signed) -> Result<bool> {
        let payload = Payload::decode(&signed.payload)?;
        ensure!(
            payload.genesis == self.genesis_hash,
            "the object belongs to another vault"
        );
        let hash = payload.hash();
        if self.held.contains_key(&hash) || self.content.contains_key(&hash) {
            return Ok(true);
        }
        match payload.kind {
            Kind::Genesis => return self.apply_genesis(signed, &payload),
            Kind::Join if self.genesis.is_none() => return self.apply_join(signed, &payload),
            _ => {}
        }
        if self.genesis.is_none() {
            return Ok(false);
        }
        // The author's key: a verified certificate, or for a certificate
        // object published by its own subject, the certificate inside.
        let author_key = match self.certificate(&payload.author_cert) {
            Some(cert) => {
                ensure!(
                    cert.device == payload.author,
                    "the author does not own its certificate"
                );
                cert.signing_key.clone()
            }
            None if payload.kind == Kind::Certificate => {
                let issued = IssuedCertificate::decode(&payload.body)?;
                if issued.certificate.id != payload.author_cert {
                    return Ok(false);
                }
                issued.certificate.signing_key
            }
            None => return Ok(false),
        };
        let payload = signed.verify(&author_key)?;
        if let Addressing::Control(recipients) = &payload.addressing
            && let Some((_, _, counter)) = recipients
                .iter()
                .find(|(device, _, _)| *device == self.me.device)
        {
            self.control_counters
                .entry(payload.author)
                .or_default()
                .insert(*counter);
        }
        let accepted = match payload.kind {
            Kind::Certificate => self.apply_certificate(&payload)?,
            Kind::Fact => self.apply_fact(&payload)?,
            Kind::SenderKey => self.apply_sender_key(&payload)?,
            Kind::Forward => self.apply_forward(&payload)?,
            Kind::Join => true,
            Kind::RenewalRequest => self.apply_renewal(&payload)?,
            Kind::Op | Kind::Snapshot | Kind::Checkpoint | Kind::Policy => {
                self.apply_content(&payload)?
            }
            Kind::Genesis => unreachable!("handled above"),
        };
        if accepted {
            self.record_position(&payload, hash);
            if payload.kind.is_control() {
                self.held.insert(hash, signed.clone());
            }
        }
        Ok(accepted)
    }

    fn apply_renewal(&mut self, payload: &Payload) -> Result<bool> {
        // This device's own requests are held from when it wrote them, so
        // one read here was made by someone else.
        if payload.author == self.me.device {
            self.alarms.insert(Alarm::Hijack);
            return Ok(true);
        }
        match Renewal::decode(&payload.body)? {
            Renewal::Member(_) => {}
            Renewal::Admin { certificate, .. } => {
                let mine = self.my_certificate()?;
                ensure!(
                    certificate.device == payload.author && certificate.principal == mine.principal,
                    "only this owner's admin asks this device to co-sign"
                );
                self.approvals.insert(certificate.id, certificate);
            }
            Renewal::Cosign {
                certificate,
                signature,
            } => {
                if let Some((
                    Renewal::Admin {
                        certificate: proposed,
                        ..
                    },
                    cosigner,
                )) = &mut self.proposal
                    && proposed.id == certificate
                {
                    *cosigner = Some((payload.author_cert, signature));
                }
            }
        }
        Ok(true)
    }

    fn record_position(&mut self, payload: &Payload, hash: Hash) {
        match self.positions.insert((payload.author, payload.seq), hash) {
            Some(other) if other != hash => {
                self.alarms.insert(Alarm::Fork(payload.author));
            }
            _ => {}
        }
        let head = self
            .heads
            .entry(payload.author)
            .or_insert((payload.seq, hash));
        if payload.seq > head.0 {
            *head = (payload.seq, hash);
        }
    }

    fn apply_genesis(&mut self, signed: &Signed, payload: &Payload) -> Result<bool> {
        let body = SignedGenesis::decode(&payload.body)?;
        ensure!(
            body.genesis.hash() == self.genesis_hash,
            "not this vault's genesis"
        );
        self.genesis = Some(body.genesis);
        let hash = payload.hash();
        self.held.insert(hash, signed.clone());
        self.record_position(payload, hash);
        Ok(true)
    }

    fn apply_certificate(&mut self, payload: &Payload) -> Result<bool> {
        let issued = IssuedCertificate::decode(&payload.body)?;
        let Some(genesis) = self.genesis.clone() else {
            return Ok(false);
        };
        let known = |id: &Id| self.certificate(id).cloned();
        match issued.verify(&genesis, &known) {
            Ok(()) => {}
            Err(_) if self.names_unknown(&issued) => return Ok(false),
            Err(error) => return Err(error),
        }
        if let Issuer::Admin(admin) = issued.certificate.issuer {
            let publisher = self.certificate(&admin).map(|cert| cert.device);
            ensure!(
                publisher == Some(payload.author),
                "a member certificate is published by its issuing admin"
            );
        }
        let certificate = &issued.certificate;
        let for_me =
            certificate.device == self.me.device && !self.originated.contains(&certificate.id);
        self.accept_certificate(
            &issued,
            Some(At {
                author: payload.author,
                seq: payload.seq,
                hash: payload.hash(),
            }),
        )?;
        self.certificate_objects
            .insert(issued.certificate.id, payload.hash());
        if for_me {
            self.adopt(&issued.certificate);
        }
        Ok(true)
    }

    /// A certificate for this device: its first one, its renewal, or a
    /// hijack.
    fn adopt(&mut self, certificate: &Certificate) {
        let key = &certificate.signing_key;
        if *key == self.me.signing.verifying_key() {
            self.me.certificate = Some(certificate.id);
        } else if let Some((signing, identity)) = self
            .renewal
            .take_if(|(signing, _)| signing.verifying_key() == *key)
        {
            let old = std::mem::replace(&mut self.me.identity, identity);
            self.me.retired.push(old);
            self.me.signing = signing;
            self.me.certificate = Some(certificate.id);
        } else {
            self.alarms.insert(Alarm::Hijack);
            return;
        }
        self.originated.insert(certificate.id);
    }

    fn names_unknown(&self, issued: &IssuedCertificate) -> bool {
        let admin = match issued.certificate.issuer {
            Issuer::Admin(id) => Some(id),
            Issuer::Root => None,
        };
        let cosigner = match &issued.issuance {
            Issuance::SelfRenewal {
                cosigner: Some((id, _)),
                ..
            } => Some(*id),
            _ => None,
        };
        [admin, issued.certificate.renews, cosigner]
            .into_iter()
            .flatten()
            .any(|id| self.certificate(&id).is_none())
    }

    fn accept_certificate(
        &mut self,
        issued: &IssuedCertificate,
        published: Option<At>,
    ) -> Result<()> {
        let genesis = self
            .genesis
            .as_ref()
            .ok_or_else(|| anyhow!("no genesis yet"))?;
        let known = |id: &Id| self.certificate(id).cloned();
        issued.verify(genesis, &known)?;
        if matches!(
            issued.issuance,
            Issuance::SelfRenewal { cosigner: None, .. }
        ) {
            self.lone_renewals.insert(issued.certificate.id);
        }
        self.certificates.insert(
            issued.certificate.id,
            (issued.certificate.clone(), published),
        );
        Ok(())
    }

    fn apply_fact(&mut self, payload: &Payload) -> Result<bool> {
        let fact = Fact::decode(&payload.body)?;
        let genesis = self
            .genesis
            .as_ref()
            .ok_or_else(|| anyhow!("no genesis yet"))?;
        if fact.needs_root() {
            ensure!(
                quorum(&genesis.roots, &fact.statement(), &fact.endorsements),
                "a root fact lacks two root signatures"
            );
        }
        if let FactKind::Add { certificate } = &fact.kind {
            let Some(cert) = self.certificate(certificate) else {
                return Ok(false);
            };
            ensure!(
                cert.device == fact.device,
                "an add names another device's certificate"
            );
        }
        if fact.device == self.me.device && fact.cutoff().is_some() {
            self.alarms.insert(Alarm::Removed);
        }
        // Whether the author may state it is decided lazily in `cutoffs`
        // and `members`, since a later fact can void its author.
        let hash = payload.hash();
        self.facts.insert(
            hash,
            (
                fact,
                At {
                    author: payload.author,
                    seq: payload.seq,
                    hash,
                },
            ),
        );
        Ok(true)
    }

    fn apply_sender_key(&mut self, payload: &Payload) -> Result<bool> {
        let Addressing::Control(recipients) = &payload.addressing else {
            bail!("a sender key is a control object")
        };
        let writer = self
            .certificate(&payload.author_cert)
            .ok_or_else(|| anyhow!("unknown writer"))?;
        ensure!(writer.role.writes(), "the author may not write");
        // Accept only under this device's current certificate (Tamarin:
        // the key object names the reader's certificate).
        let mine = self.me.certificate;
        ensure!(
            recipients
                .iter()
                .any(|(device, cert, _)| *device == self.me.device && Some(*cert) == mine),
            "the sender key is not for this device's current certificate"
        );
        let body = SenderKeyBody::decode(&payload.body)?;
        self.keys.insert(
            body.id,
            Key {
                writer: payload.author,
                certificate: payload.author_cert,
                sender: body.into_key(),
            },
        );
        Ok(true)
    }

    fn apply_forward(&mut self, payload: &Payload) -> Result<bool> {
        ensure!(
            self.is_admin_device(&payload.author),
            "only an admin forwards facts"
        );
        let Forward(objects) = Forward::decode(&payload.body)?;
        // Certificates first, so the facts that name them verify; each
        // object is checked on its own signature, and a bad one is skipped.
        for wanted in [Kind::Certificate, Kind::Fact] {
            for signed in &objects {
                if Payload::decode(&signed.payload).is_ok_and(|inner| inner.kind == wanted) {
                    match self.apply(signed) {
                        Ok(_) | Err(_) => {}
                    }
                }
            }
        }
        Ok(true)
    }

    fn apply_join(&mut self, signed: &Signed, payload: &Payload) -> Result<bool> {
        let admin = self
            .pinned_admin
            .clone()
            .ok_or_else(|| anyhow!("no pairing to join from"))?;
        ensure!(
            payload.author == admin.device,
            "the join package is not from the paired admin"
        );
        let payload = signed.verify(&admin.signing_key)?;
        let join = Join::decode(&payload.body)?;
        // Genesis first, then certificates until no more verify, then facts.
        let mut pending: Vec<Signed> = join.objects;
        loop {
            let before = pending.len();
            let mut rest = Vec::new();
            for object in pending {
                match self.apply(&object) {
                    Ok(true) | Err(_) => {}
                    Ok(false) => rest.push(object),
                }
            }
            pending = rest;
            if pending.is_empty() || pending.len() == before {
                break;
            }
        }
        ensure!(self.genesis.is_some(), "the join package lacks genesis");
        for (writer, certificate, body) in join.keys {
            self.keys.insert(
                body.id,
                Key {
                    writer,
                    certificate,
                    sender: body.into_key(),
                },
            );
        }
        if let Some(snapshot) = join.snapshot {
            let keys: Vec<SenderKey> = self
                .keys
                .values()
                .map(|key| SenderKey::from_parts(key.sender.id, key.sender.secret().clone()))
                .collect();
            if let Ok(Some((_, inner))) = open_content(&snapshot, &keys) {
                self.apply(&inner)?;
            }
        }
        let hash = payload.hash();
        self.held.insert(hash, signed.clone());
        self.record_position(&payload, hash);
        Ok(true)
    }

    fn apply_content(&mut self, payload: &Payload) -> Result<bool> {
        let Addressing::Content { key, seq } = payload.addressing else {
            bail!("content without a sender key")
        };
        let owner = self
            .keys
            .get(&key)
            .ok_or_else(|| anyhow!("unknown sender key"))?;
        // The payload's author and certificate must own the matched key.
        ensure!(
            owner.writer == payload.author && owner.certificate == payload.author_cert,
            "the object's author does not own its sender key"
        );
        self.key_counters.entry(key).or_default().insert(seq);
        if payload.kind == Kind::Checkpoint {
            let checkpoint = Checkpoint::decode(&payload.body)?;
            let newer = self
                .checkpoints
                .get(&payload.author)
                .is_none_or(|(at, _)| payload.seq > *at);
            if newer {
                self.checkpoints
                    .insert(payload.author, (payload.seq, checkpoint));
            }
        }
        let hash = payload.hash();
        self.content.insert(
            hash,
            Content {
                hash,
                payload: payload.clone(),
            },
        );
        Ok(true)
    }

    /// The folder holds an object of this device at or beyond the next
    /// position it would write: it was restored from a backup or cloned.
    fn check_restored(&mut self) {
        if self
            .heads
            .get(&self.me.device)
            .is_some_and(|(seq, _)| *seq >= self.seq)
        {
            self.alarms.insert(Alarm::Restored);
        }
    }

    /// Content accepted and still valid: written within its author's cutoff,
    /// by an author not quarantined for a fork.
    #[must_use]
    pub fn content(&self) -> Vec<&Content> {
        let cutoffs = self.cutoffs();
        self.content
            .values()
            .filter(|content| {
                let at = At {
                    author: content.payload.author,
                    seq: content.payload.seq,
                    hash: content.hash,
                };
                Self::within(&cutoffs, &at) && !self.alarms.contains(&Alarm::Fork(at.author))
            })
            .collect()
    }

    /// Numbers missing below the highest seen, per sender key and per author
    /// of control objects sealed to this device.
    #[must_use]
    pub fn gaps(&self) -> Vec<(Id, Vec<u64>)> {
        self.key_counters
            .iter()
            .chain(&self.control_counters)
            .map(|(id, counter)| (*id, counter.gaps()))
            .filter(|(_, gaps)| !gaps.is_empty())
            .collect()
    }

    // -------------------------------------------------------------- writing --

    fn fact_hashes(&self) -> BTreeSet<Hash> {
        self.facts.keys().copied().collect()
    }

    fn payload(&self, kind: Kind, addressing: Addressing, body: Vec<u8>) -> Result<Payload> {
        let certificate = self
            .me
            .certificate
            .ok_or_else(|| anyhow!("this device has no certificate yet"))?;
        Ok(Payload {
            genesis: self.genesis_hash,
            kind,
            author: self.me.device,
            author_cert: certificate,
            seq: self.seq,
            prev: self.prev,
            deps: self
                .heads
                .iter()
                .filter(|(device, _)| **device != self.me.device)
                .map(|(_, (_, hash))| *hash)
                .collect(),
            fact_set: fact_set_hash(&self.fact_hashes()),
            addressing,
            body,
        })
    }

    fn advance(&mut self, payload: &Payload) {
        let hash = payload.hash();
        self.prev = hash;
        self.seq = self.seq.saturating_add(1);
        self.record_position(payload, hash);
    }

    fn refuse_if_alarmed(&self) -> Result<()> {
        ensure!(
            !self.alarms.contains(&Alarm::Hijack) && !self.alarms.contains(&Alarm::Restored),
            "this device must be paired again before it writes"
        );
        ensure!(
            !self.alarms.contains(&Alarm::Removed),
            "this device was removed from the vault"
        );
        Ok(())
    }

    /// Seals a control object to the given devices at their newest
    /// certificates, plus the recovery recipient.
    fn write_control(&mut self, store: &Store, kind: Kind, body: &[u8], to: &[Id]) -> Result<Hash> {
        let view = self.view();
        let mut addressing = Vec::new();
        let mut recipients = Vec::new();
        for device in to {
            let certificate = view
                .get(device)
                .cloned()
                .or_else(|| {
                    self.certificates
                        .values()
                        .map(|(c, _)| c)
                        .find(|c| c.device == *device)
                        .cloned()
                })
                .ok_or_else(|| anyhow!("no certificate for a recipient"))?;
            let counter = self.sent.entry(*device).or_insert(0);
            addressing.push((*device, certificate.id, *counter));
            *counter = counter.saturating_add(1);
            recipients.push(certificate.recipient.clone());
        }
        recipients.push(
            self.genesis
                .as_ref()
                .ok_or_else(|| anyhow!("no genesis"))?
                .recovery
                .clone(),
        );
        let payload = self.payload(kind, Addressing::Control(addressing), body.to_vec())?;
        let signed = Signed::sign(&payload, &self.me.signing)?;
        let name = store.write(&seal_control(&signed, &recipients)?)?;
        self.done.insert(name);
        let hash = payload.hash();
        self.held.insert(hash, signed);
        self.advance(&payload);
        Ok(hash)
    }

    /// Writes content under the current sender key, replacing it first when
    /// the view changed since it was made (rule 11).
    ///
    /// # Errors
    ///
    /// Returns an error when this device may not write or the write fails.
    pub fn write_content(&mut self, store: &Store, kind: Kind, body: Vec<u8>) -> Result<Hash> {
        ensure!(!kind.is_control(), "not a content kind");
        self.refuse_if_alarmed()?;
        ensure!(
            self.my_certificate()?.role.writes() || kind == Kind::Checkpoint,
            "this device may only read"
        );
        self.rotate_if_needed(store)?;
        let mine = self.mine.as_mut().ok_or_else(|| anyhow!("no sender key"))?;
        let addressing = Addressing::Content {
            key: mine.key.id,
            seq: mine.next,
        };
        mine.next = mine.next.saturating_add(1);
        let payload = self.payload(kind, addressing, body)?;
        let signed = Signed::sign(&payload, &self.me.signing)?;
        let mine = self.mine.as_ref().ok_or_else(|| anyhow!("no sender key"))?;
        let name = store.write(&seal_content(&signed, &mine.key)?)?;
        self.done.insert(name);
        let key_id = mine.key.id;
        let hash = payload.hash();
        self.written.insert(hash, name);
        if let Addressing::Content { seq, .. } = payload.addressing {
            self.key_counters.entry(key_id).or_default().insert(seq);
        }
        self.content.insert(
            hash,
            Content {
                hash,
                payload: payload.clone(),
            },
        );
        self.advance(&payload);
        Ok(hash)
    }

    fn rotate_if_needed(&mut self, store: &Store) -> Result<()> {
        let view: BTreeSet<(Id, Id)> = self
            .view()
            .values()
            .map(|cert| (cert.device, cert.id))
            .collect();
        if self
            .mine
            .as_ref()
            .is_some_and(|mine| mine.recipients == view)
        {
            return Ok(());
        }
        let key = SenderKey::generate();
        let body = SenderKeyBody::from_key(&key).encode();
        let to: Vec<Id> = view.iter().map(|(device, _)| *device).collect();
        self.write_control(store, Kind::SenderKey, &body, &to)?;
        let certificate = self
            .me
            .certificate
            .ok_or_else(|| anyhow!("no certificate"))?;
        self.keys.insert(
            key.id,
            Key {
                writer: self.me.device,
                certificate,
                sender: SenderKey::from_parts(key.id, key.secret().clone()),
            },
        );
        self.mine = Some(Mine {
            key,
            recipients: view,
            next: 0,
        });
        Ok(())
    }

    fn require_admin(&self) -> Result<()> {
        self.refuse_if_alarmed()?;
        ensure!(
            self.my_certificate()?.role == Role::Admin,
            "only an admin changes membership"
        );
        Ok(())
    }

    fn members_except(&self, device: &Id) -> Vec<Id> {
        self.view()
            .keys()
            .filter(|member| *member != device)
            .copied()
            .collect()
    }

    /// Adds a paired device: issues its certificate, states the add, and
    /// seals a join package with this device's whole view to it.
    ///
    /// # Errors
    ///
    /// Returns an error when this device is not an admin, the lifetime does
    /// not fit the role, or a write fails.
    pub fn add(
        &mut self,
        store: &Store,
        keys: &pairing::Keys,
        principal: Id,
        role: Role,
        lifetime: Lifetime,
        now: u64,
    ) -> Result<Id> {
        self.require_admin()?;
        ensure!(
            role != Role::Admin,
            "making a device an admin is a root action"
        );
        ensure!(
            self.adds_by(&self.me.device, u64::MAX) < self.allowance(&self.me.device),
            "this admin has used its mint allowance: root must grant more"
        );
        ensure!(
            lifetime != Lifetime::Admin,
            "members do not get the admin lifetime"
        );
        let admin = self.my_certificate()?.clone();
        let certificate = Certificate {
            id: new_id(),
            genesis: self.genesis_hash,
            principal,
            device: keys.device,
            signing_key: keys.signing_key.clone(),
            recipient: keys.recipient.clone(),
            authenticators: Vec::new(),
            role,
            scope: admin.scope.clone(),
            lifetime,
            issuer: Issuer::Admin(admin.id),
            presence_key: None,
            renews: None,
            not_before: now,
            not_after: now.saturating_add(lifetime.max_seconds()),
        };
        let id = certificate.id;
        let issued = IssuedCertificate::by_admin(certificate, &self.me.signing)?;
        let mut to = self.members_except(&keys.device);
        self.publish_certificate(store, &issued, &to)?;
        let fact = Fact {
            device: keys.device,
            kind: FactKind::Add { certificate: id },
            endorsements: Vec::new(),
        };
        to.push(keys.device);
        self.publish_fact(store, fact, &to)?;
        self.send_join(store, keys.device)?;
        Ok(id)
    }

    /// Where the object this device wrote last sits.
    const fn last_written(&self, hash: Hash) -> At {
        At {
            author: self.me.device,
            seq: self.seq.saturating_sub(1),
            hash,
        }
    }

    fn publish_certificate(
        &mut self,
        store: &Store,
        issued: &IssuedCertificate,
        to: &[Id],
    ) -> Result<Hash> {
        let object = self.write_control(store, Kind::Certificate, &issued.encode(), to)?;
        let at = self.last_written(object);
        self.accept_certificate(issued, Some(at))?;
        self.certificate_objects
            .insert(issued.certificate.id, object);
        Ok(object)
    }

    fn publish_fact(&mut self, store: &Store, fact: Fact, to: &[Id]) -> Result<Hash> {
        let hash = self.write_control(store, Kind::Fact, &fact.encode(), to)?;
        let at = self.last_written(hash);
        self.facts.insert(hash, (fact, at));
        Ok(hash)
    }

    fn send_join(&mut self, store: &Store, device: Id) -> Result<()> {
        let objects: Vec<Signed> = self
            .held
            .values()
            .filter(|held| {
                Payload::decode(&held.payload).is_ok_and(|payload| {
                    matches!(payload.kind, Kind::Genesis | Kind::Certificate | Kind::Fact)
                })
            })
            .cloned()
            .collect();
        let keys = self
            .keys
            .iter()
            .map(|(id, key)| {
                (
                    key.writer,
                    key.certificate,
                    SenderKeyBody {
                        id: *id,
                        key: key.sender.secret().clone(),
                    },
                )
            })
            .collect();
        let join = Join {
            objects,
            keys,
            snapshot: None,
        };
        self.write_control(store, Kind::Join, &join.encode(), &[device])?;
        Ok(())
    }

    fn take_out(
        &mut self,
        store: &Store,
        device: Id,
        kind: fn(Cutoff) -> FactKind,
    ) -> Result<Hash> {
        self.require_admin()?;
        ensure!(device != self.me.device, "an admin does not remove itself");
        ensure!(
            !self.is_admin_device(&device),
            "removing an admin is a root action"
        );
        let (seq, hash) = self.heads.get(&device).copied().unwrap_or((0, [0; 48]));
        let cutoff = Cutoff { seq, hash };
        let fact = Fact {
            device,
            kind: kind(cutoff),
            endorsements: Vec::new(),
        };
        // The removed device never receives another control object.
        let to = self.members_except(&device);
        let hash = self.publish_fact(store, fact, &to)?;
        Ok(hash)
    }

    /// Removes a member, with a cutoff at the last object this admin has
    /// seen from it.
    ///
    /// # Errors
    ///
    /// Returns an error when this device is not an admin or the target is
    /// an admin.
    pub fn remove(&mut self, store: &Store, device: Id) -> Result<Hash> {
        self.take_out(store, device, FactKind::Remove)
    }

    /// Tells a member to wipe its keys, and takes it out.
    ///
    /// # Errors
    ///
    /// As for [`remove`](Self::remove).
    pub fn kill(&mut self, store: &Store, device: Id) -> Result<Hash> {
        self.take_out(store, device, FactKind::Kill)
    }

    /// Writes an expiry fact for every member whose certificate this
    /// admin's clock says has ended and that has no newer one.
    ///
    /// # Errors
    ///
    /// Returns an error when a write fails.
    pub fn expire_due(&mut self, store: &Store, now: u64) -> Result<Vec<Id>> {
        if self.require_admin().is_err() {
            return Ok(Vec::new());
        }
        let due: Vec<Id> = self
            .view()
            .values()
            .filter(|cert| cert.role != Role::Admin && cert.not_after <= now)
            .map(|cert| cert.device)
            .collect();
        for device in &due {
            self.take_out(store, *device, FactKind::Expire)?;
        }
        Ok(due)
    }

    /// Renews a member with fresh keys from its renewal request.
    ///
    /// # Errors
    ///
    /// Returns an error when the request does not verify or this device is
    /// not an admin.
    pub fn renew(&mut self, store: &Store, request: &RenewalRequest, now: u64) -> Result<Id> {
        self.require_admin()?;
        let current = self
            .certificate(&request.certificate)
            .cloned()
            .ok_or_else(|| anyhow!("unknown certificate"))?;
        request.verify(&current)?;
        ensure!(current.role != Role::Admin, "admins renew themselves");
        let admin = self.my_certificate()?.clone();
        let certificate = Certificate {
            id: new_id(),
            signing_key: request.signing_key.clone(),
            recipient: request.recipient.clone(),
            issuer: Issuer::Admin(admin.id),
            renews: Some(current.id),
            not_before: now,
            not_after: now.saturating_add(current.lifetime.max_seconds()),
            ..current
        };
        let id = certificate.id;
        let issued = IssuedCertificate::by_admin(certificate, &self.me.signing)?;
        let to: Vec<Id> = self.view().keys().copied().collect();
        self.publish_certificate(store, &issued, &to)?;
        Ok(id)
    }

    /// A member asks for renewal with fresh keys, which it switches to
    /// when the admin's certificate for them arrives.
    ///
    /// # Errors
    ///
    /// Returns an error when this device has no certificate or the write
    /// fails.
    pub fn request_renewal(&mut self, store: &Store) -> Result<()> {
        self.refuse_if_alarmed()?;
        let current = self.my_certificate()?.clone();
        let signing = SigningKey::generate();
        let identity = pq::Identity::generate();
        let request =
            RenewalRequest::new(&current, &self.me.signing, &signing, identity.to_public())?;
        let admins: Vec<Id> = self
            .view()
            .values()
            .filter(|cert| cert.role == Role::Admin)
            .map(|cert| cert.device)
            .collect();
        self.write_control(
            store,
            Kind::RenewalRequest,
            &Renewal::Member(request).encode(),
            &admins,
        )?;
        self.renewal = Some((signing, identity));
        Ok(())
    }

    /// The renewal requests this admin has read, for [`renew`](Self::renew).
    #[must_use]
    pub fn renewal_requests(&self) -> Vec<RenewalRequest> {
        self.held
            .values()
            .filter_map(|held| Payload::decode(&held.payload).ok())
            .filter(|payload| {
                payload.kind == Kind::RenewalRequest && payload.author != self.me.device
            })
            .filter_map(|payload| match Renewal::decode(&payload.body) {
                Ok(Renewal::Member(request)) => Some(request),
                _ => None,
            })
            .filter(|request| {
                !self
                    .certificates
                    .values()
                    .any(|(cert, _)| cert.renews == Some(request.certificate))
            })
            .collect()
    }

    /// Renews this admin's own certificate with fresh keys. A vault with no
    /// other device of the same owner renews at once; otherwise the new
    /// certificate goes to those devices for one of them to approve, and is
    /// published by [`sync`](Self::sync) once the co-signature arrives.
    /// Returns whether the renewal is already done.
    ///
    /// # Errors
    ///
    /// Returns an error when this device is not an admin or a write fails.
    pub fn request_self_renewal(&mut self, store: &Store, now: u64) -> Result<bool> {
        self.require_admin()?;
        let current = self.my_certificate()?.clone();
        let signing = SigningKey::generate();
        let identity = pq::Identity::generate();
        let certificate = Certificate {
            id: new_id(),
            signing_key: signing.verifying_key(),
            recipient: identity.to_public(),
            renews: Some(current.id),
            not_before: now,
            not_after: now.saturating_add(Lifetime::Admin.max_seconds()),
            ..current.clone()
        };
        let proposal = Renewal::admin(certificate, &self.me.signing, &signing)?;
        let owners: Vec<Id> = self
            .view()
            .values()
            .filter(|cert| cert.principal == current.principal && cert.device != self.me.device)
            .map(|cert| cert.device)
            .collect();
        self.renewal = Some((signing, identity));
        if owners.is_empty() {
            self.proposal = Some((proposal, None));
            self.finish_self_renewal(store)?;
            return Ok(true);
        }
        self.write_control(store, Kind::RenewalRequest, &proposal.encode(), &owners)?;
        self.proposal = Some((proposal, None));
        Ok(false)
    }

    /// Publishes this admin's renewal once it may: co-signed, or alone when
    /// the owner has no other device.
    fn finish_self_renewal(&mut self, store: &Store) -> Result<()> {
        let Some((Renewal::Admin { certificate, .. }, cosigner)) = &self.proposal else {
            return Ok(());
        };
        let alone = !self.view().values().any(|cert| {
            cert.principal == certificate.principal && cert.device != certificate.device
        });
        if cosigner.is_none() && !alone {
            return Ok(());
        }
        let Some((proposal, cosigner)) = self.proposal.take() else {
            return Ok(());
        };
        let issued = proposal.issue(cosigner)?;
        let to: Vec<Id> = self.view().keys().copied().collect();
        self.publish_certificate(store, &issued, &to)?;
        self.adopt(&issued.certificate);
        Ok(())
    }

    /// Renewals of this owner's admin waiting for approval on this device.
    #[must_use]
    pub fn approvals(&self) -> Vec<&Certificate> {
        self.approvals.values().collect()
    }

    /// Approves an admin's renewal: one touch, once a year.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no such request or the write fails.
    pub fn approve(&mut self, store: &Store, certificate: &Id) -> Result<()> {
        self.refuse_if_alarmed()?;
        let proposed = self
            .approvals
            .remove(certificate)
            .ok_or_else(|| anyhow!("no renewal waits for approval"))?;
        let signature = crate::vault::authority::cosign(&proposed, &self.me.signing)?;
        let body = Renewal::Cosign {
            certificate: proposed.id,
            signature,
        };
        self.write_control(
            store,
            Kind::RenewalRequest,
            &body.encode(),
            &[proposed.device],
        )?;
        Ok(())
    }

    // ---------------------------------------------------------- root acts --

    /// The admin certificate a root ceremony signs for a device: each sheet
    /// in turn signs its encoding with [`Endorsement::sign`].
    ///
    /// # Errors
    ///
    /// Returns an error when this device has no certificate.
    pub fn admin_certificate(
        &self,
        keys: &pairing::Keys,
        principal: Id,
        now: u64,
    ) -> Result<Certificate> {
        let scope = self.my_certificate()?.scope.clone();
        Ok(Certificate {
            id: new_id(),
            genesis: self.genesis_hash,
            principal,
            device: keys.device,
            signing_key: keys.signing_key.clone(),
            recipient: keys.recipient.clone(),
            authenticators: Vec::new(),
            role: Role::Admin,
            scope,
            lifetime: Lifetime::Admin,
            issuer: Issuer::Root,
            presence_key: None,
            renews: None,
            not_before: now,
            not_after: now.saturating_add(Lifetime::Admin.max_seconds()),
        })
    }

    /// Publishes an admin certificate two roots signed, and sends the new
    /// admin a join package when it is not a member yet.
    ///
    /// # Errors
    ///
    /// Returns an error when the signatures are not two distinct roots'.
    pub fn publish_admin(
        &mut self,
        store: &Store,
        certificate: Certificate,
        endorsements: Vec<Endorsement>,
    ) -> Result<Id> {
        self.refuse_if_alarmed()?;
        let issued = IssuedCertificate {
            certificate,
            issuance: Issuance::Root(endorsements),
        };
        let genesis = self
            .genesis
            .as_ref()
            .ok_or_else(|| anyhow!("no genesis yet"))?;
        issued.verify(genesis, &|id: &Id| self.certificate(id).cloned())?;
        let device = issued.certificate.device;
        let new = !self.members().contains(&device);
        let mut to: Vec<Id> = self.view().keys().copied().collect();
        if new {
            to.push(device);
        }
        // Known before it is sealed to its own device.
        self.accept_certificate(&issued, None)?;
        self.publish_certificate(store, &issued, &to)?;
        if new {
            self.send_join(store, device)?;
        }
        Ok(issued.certificate.id)
    }

    /// The revocation a root ceremony signs for an admin: its cutoff is the
    /// last object this device has seen from it. Each sheet in turn signs
    /// [`Fact::statement`].
    #[must_use]
    pub fn admin_revocation(&self, admin: Id) -> Fact {
        let (seq, hash) = self.heads.get(&admin).copied().unwrap_or((0, [0; 48]));
        Fact {
            device: admin,
            kind: FactKind::AdminRevoke(Cutoff { seq, hash }),
            endorsements: Vec::new(),
        }
    }

    /// Publishes a fact two roots signed: an admin revocation, a removal of
    /// an admin, or a mint grant. A device it takes out never receives it.
    ///
    /// # Errors
    ///
    /// Returns an error when the fact lacks two root signatures.
    pub fn publish_root_fact(&mut self, store: &Store, fact: Fact) -> Result<Hash> {
        self.refuse_if_alarmed()?;
        ensure!(self.rooted(&fact), "the fact lacks two root signatures");
        let to = if fact.cutoff().is_some() {
            self.members_except(&fact.device)
        } else {
            self.view().keys().copied().collect()
        };
        self.publish_fact(store, fact, &to)
    }

    /// Writes a checkpoint: the heads seen and the facts held.
    ///
    /// # Errors
    ///
    /// Returns an error when the write fails.
    pub fn checkpoint(
        &mut self,
        store: &Store,
        build: Hash,
        verified: BTreeSet<Hash>,
    ) -> Result<Hash> {
        let checkpoint = Checkpoint {
            heads: self.heads.clone(),
            facts: self.fact_hashes(),
            verified,
            build,
        };
        let previous: Vec<Hash> = self
            .content
            .values()
            .filter(|content| {
                content.payload.author == self.me.device && content.payload.kind == Kind::Checkpoint
            })
            .map(|content| content.hash)
            .collect();
        let hash = self.write_content(store, Kind::Checkpoint, checkpoint.encode())?;
        // Older checkpoints are superseded and collected like ops.
        self.collect(store, &previous.into_iter().collect())?;
        Ok(hash)
    }

    /// The latest checkpoint read from each device, with its position.
    #[must_use]
    pub const fn checkpoints(&self) -> &BTreeMap<Id, (u64, Checkpoint)> {
        &self.checkpoints
    }

    /// Records that a verified snapshot covers every object under a sender
    /// key up to `seq`, so objects collected later never look like gaps.
    pub fn cover(&mut self, key: Id, seq: u64) {
        self.key_counters.entry(key).or_default().cover(seq);
    }

    /// Removes this device's own objects among `hashes` from the folder,
    /// and forgets their content. Other devices' objects are never removed.
    ///
    /// # Errors
    ///
    /// Returns an error when a removal fails.
    pub fn collect(&mut self, store: &Store, hashes: &BTreeSet<Hash>) -> Result<usize> {
        let mut removed = 0_usize;
        for hash in hashes {
            if let Some(name) = self.written.remove(hash) {
                store.remove(&name)?;
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }

    /// Forgets content covered by a verified snapshot, keeping local state
    /// bounded; the snapshot stands in for it.
    pub fn forget(&mut self, hashes: &BTreeSet<Hash>) {
        self.content.retain(|hash, _| !hashes.contains(hash));
    }

    /// Remembers snapshots this device verified.
    pub fn mark_verified(&mut self, snapshots: &BTreeSet<Hash>) {
        self.verified.extend(snapshots);
    }

    /// The snapshots this device has verified.
    #[must_use]
    pub const fn verified(&self) -> &BTreeSet<Hash> {
        &self.verified
    }

    /// Anti-entropy: seals to each current member, in one forward, the facts
    /// this admin holds that the member's latest checkpoint lacks.
    ///
    /// # Errors
    ///
    /// Returns an error when a write fails.
    pub fn forward_missing(&mut self, store: &Store) -> Result<usize> {
        if self.require_admin().is_err() {
            return Ok(0);
        }
        let mut sent = 0_usize;
        for device in self.members_except(&self.me.device) {
            let Some((_, checkpoint)) = self.checkpoints.get(&device) else {
                continue;
            };
            let facts: Vec<&Hash> = self
                .facts
                .keys()
                .filter(|hash| !checkpoint.facts.contains(*hash))
                .collect();
            let certificates = facts.iter().filter_map(|hash| match self.facts.get(*hash) {
                Some((
                    Fact {
                        kind: FactKind::Add { certificate },
                        ..
                    },
                    _,
                )) => self.certificate_objects.get(certificate),
                _ => None,
            });
            let missing: Vec<Signed> = certificates
                .chain(facts.iter().copied())
                .filter_map(|hash| self.held.get(hash).cloned())
                .collect();
            if missing.is_empty() {
                continue;
            }
            self.write_control(store, Kind::Forward, &Forward(missing).encode(), &[device])?;
            sent = sent.saturating_add(1);
        }
        Ok(sent)
    }
}

// ------------------------------------------------------------ local state --

const STATE_TAG: &[u8] = b"txc/v1/local-state";
const MAX_STATE_ITEMS: usize = 1_000_000;
const MAX_TEXT: usize = 4096;

fn write_signed(out: &mut Writer, signed: &Signed) {
    out.bytes(&signed.payload);
    out.bytes(&signed.signature);
}

fn read_signed(input: &mut Reader<'_>) -> Result<Signed> {
    Ok(Signed {
        payload: input.bytes()?.to_vec(),
        signature: input.bytes()?.to_vec(),
    })
}

fn write_at(out: &mut Writer, at: &At) {
    out.fixed(&at.author);
    out.u64(at.seq);
    out.fixed(&at.hash);
}

fn read_at(input: &mut Reader<'_>) -> Result<At> {
    Ok(At {
        author: input.fixed()?,
        seq: input.u64()?,
        hash: input.fixed()?,
    })
}

fn write_ids(out: &mut Writer, ids: &BTreeSet<Id>) {
    out.count(ids.len());
    for id in ids {
        out.fixed(id);
    }
}

fn read_ids(input: &mut Reader<'_>) -> Result<BTreeSet<Id>> {
    (0..input.count(MAX_STATE_ITEMS)?)
        .map(|_| input.fixed())
        .collect()
}

fn write_hashes(out: &mut Writer, hashes: &BTreeSet<Hash>) {
    out.count(hashes.len());
    for hash in hashes {
        out.fixed(hash);
    }
}

fn write_names(out: &mut Writer, names: &BTreeSet<Name>) {
    out.count(names.len());
    for name in names {
        out.fixed(&name.to_bytes());
    }
}

fn read_names(input: &mut Reader<'_>) -> Result<BTreeSet<Name>> {
    (0..input.count(MAX_STATE_ITEMS)?)
        .map(|_| Ok(Name::from_bytes(input.fixed()?)))
        .collect()
}

fn write_counters(out: &mut Writer, counters: &BTreeMap<Id, Counter>) {
    out.count(counters.len());
    for (id, counter) in counters {
        out.fixed(id);
        counter.write(out);
    }
}

fn read_counters(input: &mut Reader<'_>) -> Result<BTreeMap<Id, Counter>> {
    (0..input.count(MAX_STATE_ITEMS)?)
        .map(|_| Ok((input.fixed()?, Counter::read(input)?)))
        .collect()
}

fn write_option<T>(out: &mut Writer, value: Option<&T>, write: impl FnOnce(&mut Writer, &T)) {
    out.bool(value.is_some());
    if let Some(value) = value {
        write(out, value);
    }
}

fn read_option<T>(
    input: &mut Reader<'_>,
    read: impl FnOnce(&mut Reader<'_>) -> Result<T>,
) -> Result<Option<T>> {
    if input.bool()? {
        read(input).map(Some)
    } else {
        Ok(None)
    }
}

fn write_identity(out: &mut Writer, identity: &pq::Identity) {
    out.bytes(identity.to_string().expose_secret().as_bytes());
}

fn read_identity(input: &mut Reader<'_>) -> Result<pq::Identity> {
    let text = Zeroizing::new(input.str(MAX_TEXT)?);
    text.parse()
        .map_err(|error: &str| anyhow!("identity: {error}"))
}

impl Alarm {
    fn write(&self, out: &mut Writer) {
        match self {
            Self::Fork(device) => {
                out.u8(1);
                out.fixed(device);
            }
            Self::Hijack => out.u8(2),
            Self::Removed => out.u8(3),
            Self::Restored => out.u8(4),
        }
    }

    fn read(input: &mut Reader<'_>) -> Result<Self> {
        Ok(match input.u8()? {
            1 => Self::Fork(input.fixed()?),
            2 => Self::Hijack,
            3 => Self::Removed,
            4 => Self::Restored,
            other => bail!("unknown alarm {other}"),
        })
    }
}

impl Device {
    /// Everything this device knows, for sealed local state. It holds the
    /// sender keys and the pending renewal keys, so it is secret.
    #[must_use]
    pub fn encode_state(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Writer::default();
        out.fixed(STATE_TAG);
        out.fixed(&self.me.device);
        out.fixed(&self.genesis_hash);
        write_option(&mut out, self.genesis.as_ref(), |out, genesis| {
            out.bytes(&genesis.encode());
        });
        write_option(&mut out, self.pinned_admin.as_ref(), |out, keys| {
            out.bytes(&keys.encode());
        });
        out.count(self.certificates.len());
        for (certificate, published) in self.certificates.values() {
            out.bytes(&certificate.encode());
            write_option(&mut out, published.as_ref(), write_at);
        }
        write_ids(&mut out, &self.lone_renewals);
        write_option(
            &mut out,
            self.proposal.as_ref(),
            |out, (renewal, cosigner)| {
                out.bytes(&renewal.encode());
                write_option(out, cosigner.as_ref(), |out, (id, signature)| {
                    out.fixed(id);
                    out.bytes(signature);
                });
            },
        );
        out.count(self.approvals.len());
        for certificate in self.approvals.values() {
            out.bytes(&certificate.encode());
        }
        out.count(self.facts.len());
        for (hash, (fact, at)) in &self.facts {
            out.fixed(hash);
            out.bytes(&fact.encode());
            write_at(&mut out, at);
        }
        out.count(self.certificate_objects.len());
        for (id, hash) in &self.certificate_objects {
            out.fixed(id);
            out.fixed(hash);
        }
        write_option(
            &mut out,
            self.renewal.as_ref(),
            |out, (signing, identity)| {
                out.fixed(&signing.to_bytes()[..]);
                write_identity(out, identity);
            },
        );
        out.count(self.held.len());
        for (hash, signed) in &self.held {
            out.fixed(hash);
            write_signed(&mut out, signed);
        }
        out.count(self.keys.len());
        for key in self.keys.values() {
            out.fixed(&key.writer);
            out.fixed(&key.certificate);
            out.fixed(&key.sender.id);
            out.fixed(&key.sender.secret()[..]);
        }
        write_option(&mut out, self.mine.as_ref(), |out, mine| {
            out.fixed(&mine.key.id);
            out.fixed(&mine.key.secret()[..]);
            out.count(mine.recipients.len());
            for (device, certificate) in &mine.recipients {
                out.fixed(device);
                out.fixed(certificate);
            }
            out.u64(mine.next);
        });
        out.u64(self.seq);
        out.fixed(&self.prev);
        out.count(self.heads.len());
        for (device, (seq, hash)) in &self.heads {
            out.fixed(device);
            out.u64(*seq);
            out.fixed(hash);
        }
        out.count(self.positions.len());
        for ((device, seq), hash) in &self.positions {
            out.fixed(device);
            out.u64(*seq);
            out.fixed(hash);
        }
        write_counters(&mut out, &self.key_counters);
        write_counters(&mut out, &self.control_counters);
        out.count(self.sent.len());
        for (device, counter) in &self.sent {
            out.fixed(device);
            out.u64(*counter);
        }
        write_names(&mut out, &self.done);
        write_names(&mut out, &self.unreadable);
        out.count(self.waiting.len());
        for (name, signed) in &self.waiting {
            out.fixed(&name.to_bytes());
            write_signed(&mut out, signed);
        }
        out.count(self.content.len());
        for content in self.content.values() {
            out.bytes(&content.payload.encode());
        }
        out.count(self.checkpoints.len());
        for (device, (seq, checkpoint)) in &self.checkpoints {
            out.fixed(device);
            out.u64(*seq);
            out.bytes(&checkpoint.encode());
        }
        out.count(self.alarms.len());
        for alarm in &self.alarms {
            alarm.write(&mut out);
        }
        write_ids(&mut out, &self.originated);
        write_hashes(&mut out, &self.verified);
        out.count(self.written.len());
        for (hash, name) in &self.written {
            out.fixed(hash);
            out.fixed(&name.to_bytes());
        }
        Zeroizing::new(out.finish())
    }

    /// Rebuilds a device from its sealed local state and its secrets.
    ///
    /// # Errors
    ///
    /// Returns an error when the state is malformed or belongs to another
    /// device.
    pub fn decode_state(me: Me, bytes: &[u8]) -> Result<Self> {
        let mut input = Reader(bytes);
        ensure!(
            input.take(STATE_TAG.len())? == STATE_TAG,
            "not txc local state"
        );
        let device: Id = input.fixed()?;
        ensure!(
            device == me.device,
            "the local state belongs to another device"
        );
        let mut state = Self::empty(me, input.fixed()?);
        state.genesis = read_option(&mut input, |input| Genesis::decode(input.bytes()?))?;
        state.pinned_admin =
            read_option(&mut input, |input| pairing::Keys::decode(input.bytes()?))?;
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            let certificate = Certificate::decode(input.bytes()?)?;
            let published = read_option(&mut input, read_at)?;
            state
                .certificates
                .insert(certificate.id, (certificate, published));
        }
        state.lone_renewals = read_ids(&mut input)?;
        state.proposal = read_option(&mut input, |input| {
            let renewal = Renewal::decode(input.bytes()?)?;
            let cosigner =
                read_option(input, |input| Ok((input.fixed()?, input.bytes()?.to_vec())))?;
            Ok((renewal, cosigner))
        })?;
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            let certificate = Certificate::decode(input.bytes()?)?;
            state.approvals.insert(certificate.id, certificate);
        }
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            let hash = input.fixed()?;
            let fact = Fact::decode(input.bytes()?)?;
            state.facts.insert(hash, (fact, read_at(&mut input)?));
        }
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            state
                .certificate_objects
                .insert(input.fixed()?, input.fixed()?);
        }
        state.renewal = read_option(&mut input, |input| {
            let signing = SigningKey::from_bytes(&Zeroizing::new(input.fixed()?));
            Ok((signing, read_identity(input)?))
        })?;
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            state.held.insert(input.fixed()?, read_signed(&mut input)?);
        }
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            let (writer, certificate, id) = (input.fixed()?, input.fixed()?, input.fixed()?);
            let sender = SenderKey::from_parts(id, Zeroizing::new(input.fixed()?));
            state.keys.insert(
                id,
                Key {
                    writer,
                    certificate,
                    sender,
                },
            );
        }
        state.mine = read_option(&mut input, |input| {
            let id = input.fixed()?;
            let key = SenderKey::from_parts(id, Zeroizing::new(input.fixed()?));
            let recipients = (0..input.count(MAX_STATE_ITEMS)?)
                .map(|_| Ok((input.fixed()?, input.fixed()?)))
                .collect::<Result<_>>()?;
            Ok(Mine {
                key,
                recipients,
                next: input.u64()?,
            })
        })?;
        state.seq = input.u64()?;
        state.prev = input.fixed()?;
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            state
                .heads
                .insert(input.fixed()?, (input.u64()?, input.fixed()?));
        }
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            state
                .positions
                .insert((input.fixed()?, input.u64()?), input.fixed()?);
        }
        state.key_counters = read_counters(&mut input)?;
        state.control_counters = read_counters(&mut input)?;
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            state.sent.insert(input.fixed()?, input.u64()?);
        }
        state.done = read_names(&mut input)?;
        state.unreadable = read_names(&mut input)?;
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            state
                .waiting
                .insert(Name::from_bytes(input.fixed()?), read_signed(&mut input)?);
        }
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            let payload = Payload::decode(input.bytes()?)?;
            let hash = payload.hash();
            state.content.insert(hash, Content { hash, payload });
        }
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            let device = input.fixed()?;
            let seq = input.u64()?;
            state
                .checkpoints
                .insert(device, (seq, Checkpoint::decode(input.bytes()?)?));
        }
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            state.alarms.insert(Alarm::read(&mut input)?);
        }
        state.originated = read_ids(&mut input)?;
        state.verified = (0..input.count(MAX_STATE_ITEMS)?)
            .map(|_| input.fixed())
            .collect::<Result<_>>()?;
        for _ in 0..input.count(MAX_STATE_ITEMS)? {
            state
                .written
                .insert(input.fixed()?, Name::from_bytes(input.fixed()?));
        }
        input.finish()?;
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::vault::authority::tests::roots;
    use crate::vault::pairing::{AdminStart, DeviceReply};
    use crate::vault::test_support::Scratch;

    const NOW: u64 = 1_700_000_000;
    const PRINCIPAL: Id = [7; 16];

    struct World {
        _scratch: Scratch,
        store: Store,
    }

    fn world() -> World {
        let scratch = Scratch::new("device");
        std::fs::create_dir_all(&scratch.0).unwrap();
        let store = Store::open(&scratch.0, true).unwrap();
        World {
            _scratch: scratch,
            store,
        }
    }

    fn create(store: &Store) -> Device {
        let roots = roots();
        Device::create(
            store,
            Me::generate(),
            roots.genesis,
            [(&roots.keys[0], 0), (&roots.keys[1], 1)],
            PRINCIPAL,
            "personal",
            NOW,
        )
        .unwrap()
    }

    /// Pairs a new device over the pasted path and adds it.
    fn pair(store: &Store, admin: &mut Device, role: Role) -> Device {
        let me = Me::generate();
        let (start, commit) = AdminStart::new(&admin.me().keys(), admin.genesis_hash());
        let (reply_state, reply) = DeviceReply::new(&me.keys(), &commit).unwrap();
        let (on_admin, reveal) = start.reveal(&reply).unwrap();
        let on_device = reply_state.check(&reveal).unwrap();
        assert_eq!(on_admin.code, on_device.code);
        admin
            .add(
                store,
                &on_admin.peer,
                PRINCIPAL,
                role,
                Lifetime::Desktop,
                NOW,
            )
            .unwrap();
        let mut device = Device::joining(me, &on_device);
        device.sync(store).unwrap();
        device
    }

    fn texts(device: &Device) -> BTreeSet<String> {
        device
            .content()
            .into_iter()
            .filter(|content| content.payload.kind == Kind::Op)
            .map(|content| String::from_utf8(content.payload.body.clone()).unwrap())
            .collect()
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn a_paired_device_joins_and_both_read_each_other() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let mut laptop = pair(&store, &mut admin, Role::Writer);

        assert_eq!(laptop.members(), admin.members());
        assert_eq!(laptop.members().len(), 2);
        assert!(laptop.me().certificate.is_some());

        laptop
            .write_content(&store, Kind::Op, b"from laptop".to_vec())
            .unwrap();
        admin.sync(&store).unwrap();
        assert_eq!(texts(&admin), set(&["from laptop"]));

        admin
            .write_content(&store, Kind::Op, b"from admin".to_vec())
            .unwrap();
        laptop.sync(&store).unwrap();
        assert_eq!(texts(&laptop), set(&["from laptop", "from admin"]));
        assert!(admin.alarms().is_empty() && laptop.alarms().is_empty());
    }

    #[test]
    fn history_from_before_the_join_is_readable() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        admin
            .write_content(&store, Kind::Op, b"early".to_vec())
            .unwrap();
        let laptop = pair(&store, &mut admin, Role::Reader);
        assert_eq!(texts(&laptop), set(&["early"]));
    }

    #[test]
    fn a_removed_device_learns_nothing_new_and_its_later_writes_are_void() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let mut laptop = pair(&store, &mut admin, Role::Writer);
        let mut phone = pair(&store, &mut admin, Role::Writer);
        laptop.sync(&store).unwrap();
        phone
            .write_content(&store, Kind::Op, b"phone before".to_vec())
            .unwrap();
        admin.sync(&store).unwrap();
        laptop.sync(&store).unwrap();

        admin.remove(&store, phone.me().device).unwrap();
        laptop.sync(&store).unwrap();
        assert!(!laptop.members().contains(&phone.me().device));

        laptop
            .write_content(&store, Kind::Op, b"after removal".to_vec())
            .unwrap();
        phone.sync(&store).unwrap();
        assert!(!texts(&phone).contains("after removal"));

        // The phone does not know; what it writes now is past its cutoff.
        phone
            .write_content(&store, Kind::Op, b"phone after".to_vec())
            .unwrap();
        admin.sync(&store).unwrap();
        laptop.sync(&store).unwrap();
        for device in [&admin, &laptop] {
            let seen = texts(device);
            assert!(
                seen.contains("phone before") && !seen.contains("phone after"),
                "{seen:?}"
            );
        }
        assert!(admin.remove(&store, admin.me().device).is_err());
    }

    #[test]
    fn a_withheld_fact_reaches_the_member_by_anti_entropy() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let mut laptop = pair(&store, &mut admin, Role::Writer);
        let phone = pair(&store, &mut admin, Role::Writer);
        laptop.sync(&store).unwrap();

        // The storage withholds the removal from the laptop.
        let before: BTreeSet<Name> = store.list().unwrap().names.into_iter().collect();
        admin.remove(&store, phone.me().device).unwrap();
        let removal: Vec<Name> = store
            .list()
            .unwrap()
            .names
            .into_iter()
            .filter(|name| !before.contains(name))
            .collect();
        for name in &removal {
            store.remove(name).unwrap();
        }
        laptop.sync(&store).unwrap();
        assert!(laptop.members().contains(&phone.me().device));

        laptop.checkpoint(&store, [0; 48], BTreeSet::new()).unwrap();
        admin.sync(&store).unwrap();
        assert_eq!(admin.forward_missing(&store).unwrap(), 1);
        laptop.sync(&store).unwrap();
        assert!(!laptop.members().contains(&phone.me().device));
        // The storage kept the fact from the laptop, and it notices the
        // missing per-recipient counter once later objects arrive.
        assert!(!laptop.gaps().is_empty());
    }

    #[test]
    fn a_member_renews_with_fresh_keys_and_keeps_reading_and_writing() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let mut laptop = pair(&store, &mut admin, Role::Writer);
        let old = laptop.me().certificate;

        laptop.request_renewal(&store).unwrap();
        admin.sync(&store).unwrap();
        let requests = admin.renewal_requests();
        assert_eq!(requests.len(), 1);
        admin.renew(&store, &requests[0], NOW + 10).unwrap();
        assert!(admin.renewal_requests().is_empty());

        laptop.sync(&store).unwrap();
        assert_ne!(laptop.me().certificate, old);
        assert!(laptop.alarms().is_empty(), "{:?}", laptop.alarms());
        assert_eq!(laptop.members(), admin.members());

        laptop
            .write_content(&store, Kind::Op, b"renewed".to_vec())
            .unwrap();
        admin
            .write_content(&store, Kind::Op, b"to renewed".to_vec())
            .unwrap();
        admin.sync(&store).unwrap();
        laptop.sync(&store).unwrap();
        assert!(texts(&admin).contains("renewed"));
        assert!(texts(&laptop).contains("to renewed"));
    }

    #[test]
    fn a_member_past_its_certificate_is_expired_by_the_admin() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let laptop = pair(&store, &mut admin, Role::Writer);
        assert!(admin.expire_due(&store, NOW + 10).unwrap().is_empty());
        let later = NOW + Lifetime::Desktop.max_seconds();
        assert_eq!(
            admin.expire_due(&store, later).unwrap(),
            vec![laptop.me().device]
        );
        assert!(!admin.members().contains(&laptop.me().device));
    }

    #[test]
    fn a_device_restored_from_a_backup_stops_writing() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let mut laptop = pair(&store, &mut admin, Role::Writer);
        laptop
            .write_content(&store, Kind::Op, b"one".to_vec())
            .unwrap();

        // The same keys with the local state of before it wrote anything.
        let me = laptop.me();
        let clone = Me {
            device: me.device,
            signing: SigningKey::from_bytes(&me.signing.to_bytes()),
            identity: me.identity.clone(),
            retired: Vec::new(),
            certificate: None,
        };
        let (start, commit) = AdminStart::new(&admin.me().keys(), admin.genesis_hash());
        let (reply_state, reply) = DeviceReply::new(&clone.keys(), &commit).unwrap();
        let (_, reveal) = start.reveal(&reply).unwrap();
        let mut restored = Device::joining(clone, &reply_state.check(&reveal).unwrap());
        restored.sync(&store).unwrap();
        assert!(restored.alarms().contains(&Alarm::Restored));
        assert!(
            restored
                .write_content(&store, Kind::Op, b"two".to_vec())
                .is_err()
        );
    }

    #[test]
    fn a_withheld_content_object_is_a_gap() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let mut laptop = pair(&store, &mut admin, Role::Writer);
        laptop
            .write_content(&store, Kind::Op, b"a".to_vec())
            .unwrap();
        let before: BTreeSet<Name> = store.list().unwrap().names.into_iter().collect();
        laptop
            .write_content(&store, Kind::Op, b"b".to_vec())
            .unwrap();
        let withheld: Vec<Name> = store
            .list()
            .unwrap()
            .names
            .into_iter()
            .filter(|name| !before.contains(name))
            .collect();
        for name in &withheld {
            store.remove(name).unwrap();
        }
        laptop
            .write_content(&store, Kind::Op, b"c".to_vec())
            .unwrap();
        admin.sync(&store).unwrap();
        assert_eq!(texts(&admin), set(&["a", "c"]));
        assert_eq!(admin.gaps().len(), 1);
    }

    #[test]
    fn only_admins_change_membership() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let mut laptop = pair(&store, &mut admin, Role::Writer);
        let phone = pair(&store, &mut admin, Role::Reader);
        laptop.sync(&store).unwrap();
        assert!(laptop.remove(&store, phone.me().device).is_err());
        assert!(
            laptop
                .add(
                    &store,
                    &Me::generate().keys(),
                    PRINCIPAL,
                    Role::Writer,
                    Lifetime::Desktop,
                    NOW
                )
                .is_err()
        );
        assert!(
            admin
                .add(
                    &store,
                    &Me::generate().keys(),
                    PRINCIPAL,
                    Role::Admin,
                    Lifetime::Admin,
                    NOW
                )
                .is_err()
        );
        let mut phone = phone;
        assert!(
            phone
                .write_content(&store, Kind::Op, b"reader".to_vec())
                .is_err()
        );
    }

    fn endorse(message: &[u8]) -> Vec<Endorsement> {
        let keys = roots().keys;
        // One sheet at a time: each root key signs on its own.
        vec![
            Endorsement::sign(&keys[0], 0, message).unwrap(),
            Endorsement::sign(&keys[2], 2, message).unwrap(),
        ]
    }

    fn join_as(store: &Store, admin: &Device, me: Me) -> Device {
        let (start, commit) = AdminStart::new(&admin.me().keys(), admin.genesis_hash());
        let (reply_state, reply) = DeviceReply::new(&me.keys(), &commit).unwrap();
        let (_, reveal) = start.reveal(&reply).unwrap();
        let mut device = Device::joining(me, &reply_state.check(&reveal).unwrap());
        device.sync(store).unwrap();
        device
    }

    #[test]
    fn an_admin_adds_only_what_its_allowance_permits_until_root_grants_more() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        for _ in 0..4 {
            pair(&store, &mut admin, Role::Reader);
        }
        let extra = Me::generate();
        assert!(
            admin
                .add(
                    &store,
                    &extra.keys(),
                    PRINCIPAL,
                    Role::Reader,
                    Lifetime::Desktop,
                    NOW
                )
                .is_err()
        );

        let mut grant = Fact {
            device: admin.me().device,
            kind: FactKind::MintAllowance(1),
            endorsements: Vec::new(),
        };
        assert!(admin.publish_root_fact(&store, grant.clone()).is_err());
        grant.endorsements = endorse(&grant.statement());
        admin.publish_root_fact(&store, grant).unwrap();
        admin
            .add(
                &store,
                &extra.keys(),
                PRINCIPAL,
                Role::Reader,
                Lifetime::Desktop,
                NOW,
            )
            .unwrap();
        assert_eq!(admin.members().len(), 6);
    }

    #[test]
    fn root_adds_an_admin_and_later_revokes_it() {
        let World { _scratch, store } = world();
        let mut first = create(&store);
        let me = Me::generate();
        let certificate = first.admin_certificate(&me.keys(), PRINCIPAL, NOW).unwrap();
        let endorsements = endorse(&certificate.encode());
        first
            .publish_admin(&store, certificate, endorsements)
            .unwrap();
        let mut second = join_as(&store, &first, me);
        assert_eq!(second.members().len(), 2);

        let early = pair(&store, &mut second, Role::Reader);
        first.sync(&store).unwrap();
        assert!(first.members().contains(&early.me().device));

        let mut revocation = first.admin_revocation(second.me().device);
        revocation.endorsements = endorse(&revocation.statement());
        first.publish_root_fact(&store, revocation).unwrap();

        // The revoked admin does not know yet; what it adds now is void.
        let late = pair(&store, &mut second, Role::Reader);
        first.sync(&store).unwrap();
        let members = first.members();
        assert!(!members.contains(&second.me().device));
        assert!(members.contains(&early.me().device));
        assert!(!members.contains(&late.me().device));
    }

    #[test]
    fn a_lone_admin_renews_itself_at_once() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let before = admin.me().certificate;
        assert!(admin.request_self_renewal(&store, NOW + 100).unwrap());
        assert_ne!(admin.me().certificate, before);
        assert_eq!(admin.me().retired.len(), 1);
        admin
            .write_content(&store, Kind::Op, b"after renewal".to_vec())
            .unwrap();
        let laptop = pair(&store, &mut admin, Role::Reader);
        assert!(texts(&laptop).contains("after renewal"));
    }

    #[test]
    fn an_admin_with_another_device_renews_only_with_its_approval() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let mut laptop = pair(&store, &mut admin, Role::Writer);
        let before = admin.me().certificate;

        assert!(!admin.request_self_renewal(&store, NOW + 100).unwrap());
        admin.sync(&store).unwrap();
        assert_eq!(admin.me().certificate, before);

        laptop.sync(&store).unwrap();
        let waiting: Vec<Id> = laptop.approvals().iter().map(|cert| cert.id).collect();
        assert_eq!(waiting.len(), 1);
        laptop.approve(&store, &waiting[0]).unwrap();

        admin.sync(&store).unwrap();
        assert_eq!(admin.me().certificate, Some(waiting[0]));
        laptop.sync(&store).unwrap();
        assert_eq!(laptop.view()[&admin.me().device].id, waiting[0]);

        admin
            .write_content(&store, Kind::Op, b"renewed admin".to_vec())
            .unwrap();
        laptop.sync(&store).unwrap();
        assert!(texts(&laptop).contains("renewed admin"));
    }

    #[test]
    fn a_stolen_admin_cannot_renew_itself_alone() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let mut laptop = pair(&store, &mut admin, Role::Writer);
        let current = admin.my_certificate().unwrap().clone();
        let new = SigningKey::generate();
        let forged = Certificate {
            id: new_id(),
            signing_key: new.verifying_key(),
            renews: Some(current.id),
            not_before: NOW + 100,
            not_after: NOW + 100 + Lifetime::Admin.max_seconds(),
            ..current.clone()
        };
        let issued = Renewal::admin(forged, &admin.me.signing, &new)
            .unwrap()
            .issue(None)
            .unwrap();
        let to: Vec<Id> = admin.view().keys().copied().collect();
        admin.publish_certificate(&store, &issued, &to).unwrap();

        laptop.sync(&store).unwrap();
        assert_eq!(laptop.view()[&admin.me().device].id, current.id);
        assert_eq!(admin.view()[&admin.me().device].id, current.id);
    }

    #[test]
    fn a_forked_writer_is_quarantined() {
        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let mut laptop = pair(&store, &mut admin, Role::Writer);
        laptop
            .write_content(&store, Kind::Op, b"first".to_vec())
            .unwrap();
        // Two different objects at one position of the laptop's chain.
        laptop.seq -= 1;
        laptop
            .write_content(&store, Kind::Op, b"second".to_vec())
            .unwrap();

        admin.sync(&store).unwrap();
        assert!(admin.alarms().contains(&Alarm::Fork(laptop.me().device)));
        assert!(texts(&admin).is_empty());
    }

    #[test]
    fn a_device_sealed_and_reopened_carries_on() {
        use crate::vault::local::{open_state, seal_state};

        let World { _scratch, store } = world();
        let mut admin = create(&store);
        let mut laptop = pair(&store, &mut admin, Role::Writer);
        laptop
            .write_content(&store, Kind::Op, b"before".to_vec())
            .unwrap();
        admin.sync(&store).unwrap();

        let copy = |me: &Me| Me {
            device: me.device,
            signing: SigningKey::from_bytes(&me.signing.to_bytes()),
            identity: me.identity.clone(),
            retired: me.retired.clone(),
            certificate: me.certificate,
        };
        let sealed = seal_state(&admin).unwrap();
        let mut reopened = open_state(&sealed, copy(admin.me())).unwrap();
        assert_eq!(reopened.encode_state(), admin.encode_state());
        assert_eq!(texts(&reopened), set(&["before"]));

        // A state sealed by another device, or changed, does not open.
        assert!(open_state(&sealed, copy(laptop.me())).is_err());
        let mut changed = sealed;
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(open_state(&changed, copy(admin.me())).is_err());

        laptop
            .write_content(&store, Kind::Op, b"after".to_vec())
            .unwrap();
        assert_eq!(reopened.sync(&store).unwrap(), 1);
        reopened
            .write_content(&store, Kind::Op, b"reply".to_vec())
            .unwrap();
        laptop.sync(&store).unwrap();
        assert_eq!(texts(&reopened), set(&["before", "after", "reply"]));
        assert!(texts(&laptop).contains("reply"));
        assert!(reopened.alarms().is_empty());
    }
}
