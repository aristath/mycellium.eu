//! The Mycellium directory (Layers 6 & 8.4): the one hosted piece of the system.
//!
//! It does three tightly-bounded things and nothing else:
//! 1. **login** — a SIWE-style challenge the client signs with its wallet key;
//! 2. **lookup** — `handle → signed record`, open to everyone;
//! 3. **publish** — store a self-signed record under a handle.
//!
//! It is an *untrusted* directory: records are signed by their owner's wallet,
//! so the store cannot forge one. The worst it can do is withhold or serve a
//! stale record. The security-relevant rules — self-certification, permanent
//! handle binding, and `seq` anti-rollback — all live in [`Directory::publish`].
//!
//! This module is transport-agnostic and fully unit-tested; `main.rs` is only a
//! thin HTTP shell over it.

use std::collections::HashMap;

use mycellium_core::identity::{Handle, Signature, WalletPublicKey};
use mycellium_core::record::SignedRecord;

mod http;
pub use http::serve;

/// A request the directory rejected, with the HTTP status it maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    /// No such outstanding challenge, or wallet mismatch.
    BadChallenge,
    /// The login signature did not verify.
    BadSignature,
    /// Missing or unknown session token.
    Unauthorized,
    /// The record's handle does not match the target handle.
    HandleMismatch,
    /// The record's wallet is not the authenticated wallet.
    WalletMismatch,
    /// The handle is permanently bound to a different wallet.
    HandleTaken,
    /// The record is older than (or equal to) the stored one.
    Stale,
    /// The record failed self-certification.
    InvalidRecord,
    /// The target handle is not registered.
    NotFound,
    /// The caller is authenticated but not permitted (e.g. not the owner).
    Forbidden,
    /// A malformed request (e.g. an invalid email).
    BadRequest,
}

impl ApiError {
    /// The HTTP status code for this error.
    pub fn status(self) -> u16 {
        match self {
            ApiError::BadChallenge | ApiError::BadSignature => 400,
            ApiError::Unauthorized => 401,
            ApiError::HandleTaken | ApiError::WalletMismatch => 403,
            ApiError::HandleMismatch | ApiError::InvalidRecord => 422,
            ApiError::Stale => 409,
            ApiError::NotFound => 404,
            ApiError::Forbidden => 403,
            ApiError::BadRequest => 400,
        }
    }

    /// A short human-readable reason.
    pub fn reason(self) -> &'static str {
        match self {
            ApiError::BadChallenge => "unknown or mismatched challenge",
            ApiError::BadSignature => "login signature did not verify",
            ApiError::Unauthorized => "missing or invalid session token",
            ApiError::HandleMismatch => "record handle does not match target",
            ApiError::WalletMismatch => "record wallet is not the logged-in wallet",
            ApiError::HandleTaken => "handle is bound to another wallet",
            ApiError::Stale => "record is not newer than the stored one",
            ApiError::InvalidRecord => "record failed signature verification",
            ApiError::NotFound => "no such handle",
            ApiError::Forbidden => "not permitted",
            ApiError::BadRequest => "malformed request",
        }
    }
}

/// The in-memory directory state (POC). A real deployment swaps the maps for a
/// database or, ultimately, an on-chain registry — the logic is unchanged.
#[derive(Default)]
pub struct Directory {
    /// Outstanding login challenges: nonce → the wallet it was issued to.
    challenges: HashMap<String, WalletPublicKey>,
    /// Active sessions: token → authenticated wallet.
    tokens: HashMap<String, WalletPublicKey>,
    /// Permanent handle bindings: handle → owning wallet (never reassigned).
    bindings: HashMap<Handle, WalletPublicKey>,
    /// The published records: handle → latest signed record.
    records: HashMap<Handle, SignedRecord>,
    /// Presence: handle → last-seen unix seconds.
    presence: HashMap<Handle, u64>,
    /// Username claims awaiting email verification: pending token → claim.
    pending: HashMap<String, Pending>,
    /// Recovery emails for verified names: handle → email.
    emails: HashMap<Handle, String>,
}

/// A username claim awaiting one-tap email verification (Layer 6 auth).
struct Pending {
    username: Handle,
    email: String,
    wallet: WalletPublicKey,
    code: String,
    verified: bool,
    created: u64,
}

/// How long after its last heartbeat a handle is still considered online.
pub const PRESENCE_TTL: u64 = 60;

/// How long an email verification code / link stays valid (15 minutes).
pub const VERIFY_TTL: u64 = 900;

impl Directory {
    /// A fresh, empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// The exact bytes a client signs to prove control of its wallet.
    /// Delegates to the shared [`mycellium_core::login`] contract.
    pub fn challenge_message(nonce: &str) -> Vec<u8> {
        mycellium_core::login::challenge_message(nonce)
    }

    /// Step 1 of login: issue a challenge nonce for `wallet`.
    pub fn challenge(&mut self, wallet: WalletPublicKey) -> String {
        let nonce = random_hex::<16>();
        self.challenges.insert(nonce.clone(), wallet);
        nonce
    }

    /// Step 2 of login: verify the signed challenge and issue a session token.
    pub fn verify(
        &mut self,
        wallet: &WalletPublicKey,
        nonce: &str,
        signature: &Signature,
    ) -> Result<String, ApiError> {
        match self.challenges.get(nonce) {
            Some(w) if w == wallet => {}
            _ => return Err(ApiError::BadChallenge),
        }
        let message = Self::challenge_message(nonce);
        wallet
            .verify(&message, signature)
            .map_err(|_| ApiError::BadSignature)?;

        self.challenges.remove(nonce);
        let token = random_hex::<24>();
        self.tokens.insert(token.clone(), *wallet);
        Ok(token)
    }

    /// Begin an email-verified username claim for the logged-in wallet.
    ///
    /// Returns `(pending_token, code)`. The code is what the verification email
    /// carries; the caller decides whether to also surface it (dev) or only mail
    /// it (prod). A name already owned by a *different* wallet is rejected.
    pub fn auth_start(
        &mut self,
        token: &str,
        username: &Handle,
        email: &str,
        now: u64,
    ) -> Result<(String, String), ApiError> {
        let wallet = *self.tokens.get(token).ok_or(ApiError::Unauthorized)?;
        if let Some(bound) = self.bindings.get(username) {
            if *bound != wallet {
                return Err(ApiError::HandleTaken);
            }
        }
        if !email.contains('@') || email.len() < 3 {
            return Err(ApiError::BadRequest);
        }
        let pending_token = random_hex::<24>();
        let code = format!("{:06}", u32::from_le_bytes(random_bytes::<4>()) % 1_000_000);
        deliver_email(email, username.as_str(), &code, &pending_token);
        self.pending.insert(
            pending_token.clone(),
            Pending {
                username: username.clone(),
                email: email.to_string(),
                wallet,
                code: code.clone(),
                verified: false,
                created: now,
            },
        );
        Ok((pending_token, code))
    }

    /// Confirm an email code (typed, or embedded in the one-tap link). On
    /// success the name is bound to the wallet and the recovery email stored.
    pub fn auth_confirm(&mut self, pending_token: &str, code: &str, now: u64) -> Result<Handle, ApiError> {
        let p = self.pending.get_mut(pending_token).ok_or(ApiError::NotFound)?;
        if now.saturating_sub(p.created) > VERIFY_TTL {
            return Err(ApiError::Stale);
        }
        if p.code != code {
            return Err(ApiError::BadSignature);
        }
        p.verified = true;
        let (username, wallet, email) = (p.username.clone(), p.wallet, p.email.clone());
        if let Some(bound) = self.bindings.get(&username) {
            if *bound != wallet {
                return Err(ApiError::HandleTaken);
            }
        }
        self.bindings.insert(username.clone(), wallet);
        self.emails.insert(username.clone(), email);
        Ok(username)
    }

    /// Poll a pending claim: `(verified, username)`.
    pub fn auth_status(&self, pending_token: &str) -> Option<(bool, String)> {
        self.pending.get(pending_token).map(|p| (p.verified, p.username.as_str().to_string()))
    }

    /// Publish (or update) a signed record under `handle`.
    ///
    /// Enforces every directory rule: a valid session, handle/wallet agreement,
    /// self-certification, permanent binding, and `seq` anti-rollback.
    pub fn publish(
        &mut self,
        token: &str,
        handle: &Handle,
        record: SignedRecord,
    ) -> Result<(), ApiError> {
        let wallet = *self.tokens.get(token).ok_or(ApiError::Unauthorized)?;

        if &record.record.handle != handle {
            return Err(ApiError::HandleMismatch);
        }
        if record.record.wallet != wallet {
            return Err(ApiError::WalletMismatch);
        }
        record.verify().map_err(|_| ApiError::InvalidRecord)?;

        if let Some(bound) = self.bindings.get(handle) {
            if *bound != wallet {
                return Err(ApiError::HandleTaken); // permanent binding (Layer 9.2)
            }
        }
        if let Some(existing) = self.records.get(handle) {
            if record.record.seq <= existing.record.seq {
                return Err(ApiError::Stale); // anti-rollback (Layer 9.4)
            }
        }

        self.bindings.insert(handle.clone(), wallet);
        self.records.insert(handle.clone(), record);
        Ok(())
    }

    /// Look up the record for `handle`. Open to everyone; no auth.
    pub fn lookup(&self, handle: &Handle) -> Option<&SignedRecord> {
        self.records.get(handle)
    }

    /// Record a heartbeat: the authenticated owner of `handle` is online at `now`.
    pub fn heartbeat(&mut self, token: &str, handle: &Handle, now: u64) -> Result<(), ApiError> {
        let wallet = *self.tokens.get(token).ok_or(ApiError::Unauthorized)?;
        match self.bindings.get(handle) {
            Some(owner) if *owner == wallet => {}
            _ => return Err(ApiError::Forbidden),
        }
        self.presence.insert(handle.clone(), now);
        Ok(())
    }

    /// Whether `handle` was seen within [`PRESENCE_TTL`] of `now`. Open to all.
    pub fn presence(&self, handle: &Handle, now: u64) -> bool {
        self.presence
            .get(handle)
            .is_some_and(|last| now.saturating_sub(*last) <= PRESENCE_TTL)
    }
}

/// `N` random bytes rendered as lowercase hex, from the OS CSPRNG.
fn random_hex<const N: usize>() -> String {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).expect("OS RNG must be available");
    let mut out = String::with_capacity(N * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).expect("OS RNG must be available");
    bytes
}

/// Deliver a verification email. Dev default: log it to the console. Production
/// swaps this body for an SMTP send (self-hosted; never a US SMS/email gateway).
fn deliver_email(email: &str, username: &str, code: &str, pending_token: &str) {
    eprintln!(
        "[mycellium-directory] verify '{username}' for {email}: code {code}  (pending {pending_token})"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycellium_core::identity::Identity;
    use mycellium_core::platform::Platform;
    use mycellium_core::record::{Device, Record, SignedPreKey};

    struct OsPlatform;
    impl Platform for OsPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            getrandom::getrandom(buf).expect("OS RNG");
        }
        fn now_unix_secs(&self) -> u64 {
            0
        }
    }

    fn record_for(id: &Identity, handle: &str, seq: u64) -> SignedRecord {
        let record = Record {
            handle: Handle::new(handle).unwrap(),
            wallet: id.wallet_public(),
            queue: String::new(),
            devices: vec![Device {
                device_key: id.device_public(),
                peer_id: id.peer_id(),
                id_key: id.messaging_public(),
                signed_pre_key: SignedPreKey::create(id.signed_pre_key_public(), id),
            }],
            seq,
        };
        SignedRecord::sign(record, id)
    }

    /// Drive a full login for `id`, returning the session token.
    fn login(dir: &mut Directory, id: &Identity) -> String {
        let nonce = dir.challenge(id.wallet_public());
        let sig = id.sign(&Directory::challenge_message(&nonce));
        dir.verify(&id.wallet_public(), &nonce, &sig).unwrap()
    }

    #[test]
    fn full_login_publish_lookup() {
        let mut dir = Directory::new();
        let ari = Identity::generate(&mut OsPlatform).unwrap();
        let handle = Handle::new("ari").unwrap();

        let token = login(&mut dir, &ari);
        dir.publish(&token, &handle, record_for(&ari, "ari", 1)).unwrap();

        let got = dir.lookup(&handle).expect("record present");
        assert!(got.verify().is_ok());
        assert_eq!(got.record.wallet, ari.wallet_public());
    }

    #[test]
    fn login_rejects_bad_signature() {
        let mut dir = Directory::new();
        let ari = Identity::generate(&mut OsPlatform).unwrap();
        let nonce = dir.challenge(ari.wallet_public());
        // Sign the wrong message.
        let bad = ari.sign(b"not the challenge");
        assert_eq!(
            dir.verify(&ari.wallet_public(), &nonce, &bad),
            Err(ApiError::BadSignature)
        );
    }

    #[test]
    fn publish_requires_a_token() {
        let mut dir = Directory::new();
        let ari = Identity::generate(&mut OsPlatform).unwrap();
        let handle = Handle::new("ari").unwrap();
        assert_eq!(
            dir.publish("not-a-token", &handle, record_for(&ari, "ari", 1)),
            Err(ApiError::Unauthorized)
        );
    }

    #[test]
    fn handle_binding_is_permanent() {
        let mut dir = Directory::new();
        let ari = Identity::generate(&mut OsPlatform).unwrap();
        let mallory = Identity::generate(&mut OsPlatform).unwrap();
        let handle = Handle::new("ari").unwrap();

        let ari_token = login(&mut dir, &ari);
        dir.publish(&ari_token, &handle, record_for(&ari, "ari", 1)).unwrap();

        // Mallory logs in and tries to steal "ari".
        let mal_token = login(&mut dir, &mallory);
        assert_eq!(
            dir.publish(&mal_token, &handle, record_for(&mallory, "ari", 2)),
            Err(ApiError::HandleTaken)
        );
    }

    #[test]
    fn presence_reflects_heartbeats_within_ttl() {
        let mut dir = Directory::new();
        let bob = Identity::generate(&mut OsPlatform).unwrap();
        let handle = Handle::new("bob").unwrap();
        let token = login(&mut dir, &bob);
        dir.publish(&token, &handle, record_for(&bob, "bob", 1)).unwrap();

        // Never heard of: offline.
        assert!(!dir.presence(&handle, 1000));
        // Heartbeat at t=1000 → online now, and still just inside the TTL...
        dir.heartbeat(&token, &handle, 1000).unwrap();
        assert!(dir.presence(&handle, 1000));
        assert!(dir.presence(&handle, 1000 + PRESENCE_TTL));
        // ...but stale once past it.
        assert!(!dir.presence(&handle, 1000 + PRESENCE_TTL + 1));
    }

    #[test]
    fn heartbeat_requires_owning_the_handle() {
        let mut dir = Directory::new();
        let bob = Identity::generate(&mut OsPlatform).unwrap();
        let mallory = Identity::generate(&mut OsPlatform).unwrap();
        let handle = Handle::new("bob").unwrap();
        let bob_token = login(&mut dir, &bob);
        dir.publish(&bob_token, &handle, record_for(&bob, "bob", 1)).unwrap();

        let mal_token = login(&mut dir, &mallory);
        assert_eq!(dir.heartbeat(&mal_token, &handle, 5), Err(ApiError::Forbidden));
    }

    #[test]
    fn stale_updates_are_rejected() {
        let mut dir = Directory::new();
        let ari = Identity::generate(&mut OsPlatform).unwrap();
        let handle = Handle::new("ari").unwrap();
        let token = login(&mut dir, &ari);

        dir.publish(&token, &handle, record_for(&ari, "ari", 5)).unwrap();
        // Newer seq is fine.
        dir.publish(&token, &handle, record_for(&ari, "ari", 6)).unwrap();
        // Replaying an old seq is not.
        assert_eq!(
            dir.publish(&token, &handle, record_for(&ari, "ari", 6)),
            Err(ApiError::Stale)
        );
    }
}
