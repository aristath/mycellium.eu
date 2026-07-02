//! The Messe directory (Layers 6 & 8.4): the one hosted piece of the system.
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

use messe_core::identity::{Handle, Signature, WalletPublicKey};
use messe_core::record::SignedRecord;

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
    /// The recipient's mailbox is full.
    MailboxFull,
    /// Too many requests in the rate-limit window.
    RateLimited,
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
            ApiError::MailboxFull | ApiError::RateLimited => 429,
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
            ApiError::MailboxFull => "recipient mailbox is full",
            ApiError::RateLimited => "rate limit exceeded",
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
    /// Offline mailboxes: handle → queued opaque encrypted envelopes.
    mailboxes: HashMap<Handle, Vec<String>>,
    /// Presence: handle → last-seen unix seconds.
    presence: HashMap<Handle, u64>,
    /// Fixed-window rate counters: (wallet, action) → (window_start, count).
    rate: HashMap<([u8; 33], &'static str), (u64, u32)>,
}

/// Maximum number of queued messages per mailbox.
pub const MAX_MAILBOX: usize = 256;

/// How long after its last heartbeat a handle is still considered online.
pub const PRESENCE_TTL: u64 = 60;

/// Mailbox deposits allowed per wallet per [`RATE_WINDOW`].
pub const DEPOSIT_RATE_LIMIT: u32 = 30;

/// The rate-limit window, in seconds.
pub const RATE_WINDOW: u64 = 60;

impl Directory {
    /// A fresh, empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// The exact bytes a client signs to prove control of its wallet.
    pub fn challenge_message(nonce: &str) -> Vec<u8> {
        let mut msg = b"messe-login:".to_vec();
        msg.extend_from_slice(nonce.as_bytes());
        msg
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

    /// A fixed-window rate check for `(wallet, action)` at `now`.
    fn allow(&mut self, wallet: [u8; 33], action: &'static str, now: u64, limit: u32) -> bool {
        let entry = self.rate.entry((wallet, action)).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= RATE_WINDOW {
            *entry = (now, 0);
        }
        if entry.1 >= limit {
            return false;
        }
        entry.1 += 1;
        true
    }

    /// Deposit an opaque encrypted envelope into `handle`'s mailbox.
    ///
    /// Any authenticated sender may deposit (rate-limited); the recipient must
    /// be registered. The directory stores the blob without reading it (Layer 3).
    pub fn deposit(
        &mut self,
        token: &str,
        handle: &Handle,
        blob: String,
        now: u64,
    ) -> Result<(), ApiError> {
        let wallet = *self.tokens.get(token).ok_or(ApiError::Unauthorized)?;
        if !self.allow(wallet.0, "deposit", now, DEPOSIT_RATE_LIMIT) {
            return Err(ApiError::RateLimited);
        }
        if !self.bindings.contains_key(handle) {
            return Err(ApiError::NotFound);
        }
        let mailbox = self.mailboxes.entry(handle.clone()).or_default();
        if mailbox.len() >= MAX_MAILBOX {
            return Err(ApiError::MailboxFull);
        }
        mailbox.push(blob);
        Ok(())
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

    /// Drain `handle`'s mailbox. Only the handle's owner may collect.
    pub fn collect(&mut self, token: &str, handle: &Handle) -> Result<Vec<String>, ApiError> {
        let wallet = *self.tokens.get(token).ok_or(ApiError::Unauthorized)?;
        match self.bindings.get(handle) {
            Some(owner) if *owner == wallet => {}
            _ => return Err(ApiError::Forbidden),
        }
        Ok(self.mailboxes.remove(handle).unwrap_or_default())
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

#[cfg(test)]
mod tests {
    use super::*;
    use messe_core::identity::Identity;
    use messe_core::platform::Platform;
    use messe_core::record::{Record, SignedPreKey};

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
            peer_id: id.peer_id(),
            id_key: id.messaging_public(),
            signed_pre_key: SignedPreKey::create(id.signed_pre_key_public(), id),
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
    fn mailbox_deposit_and_owner_only_collect() {
        let mut dir = Directory::new();
        let bob = Identity::generate(&mut OsPlatform).unwrap();
        let alice = Identity::generate(&mut OsPlatform).unwrap();
        let bob_handle = Handle::new("bob").unwrap();

        // Bob registers so his mailbox exists.
        let bob_token = login(&mut dir, &bob);
        dir.publish(&bob_token, &bob_handle, record_for(&bob, "bob", 1)).unwrap();

        // Alice logs in and deposits a message for Bob.
        let alice_token = login(&mut dir, &alice);
        dir.deposit(&alice_token, &bob_handle, "sealed-envelope".into(), 0).unwrap();

        // Alice must NOT be able to read Bob's mailbox.
        assert_eq!(dir.collect(&alice_token, &bob_handle), Err(ApiError::Forbidden));

        // Bob drains his own mailbox, then it's empty.
        assert_eq!(dir.collect(&bob_token, &bob_handle).unwrap(), vec!["sealed-envelope".to_string()]);
        assert_eq!(dir.collect(&bob_token, &bob_handle).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn deposit_requires_auth_and_a_registered_recipient() {
        let mut dir = Directory::new();
        let alice = Identity::generate(&mut OsPlatform).unwrap();
        let bob_handle = Handle::new("bob").unwrap();

        assert_eq!(
            dir.deposit("no-token", &bob_handle, "x".into(), 0),
            Err(ApiError::Unauthorized)
        );
        let alice_token = login(&mut dir, &alice);
        // Bob never registered.
        assert_eq!(
            dir.deposit(&alice_token, &bob_handle, "x".into(), 0),
            Err(ApiError::NotFound)
        );
    }

    #[test]
    fn deposits_are_rate_limited_then_reset() {
        let mut dir = Directory::new();
        let bob = Identity::generate(&mut OsPlatform).unwrap();
        let alice = Identity::generate(&mut OsPlatform).unwrap();
        let bob_handle = Handle::new("bob").unwrap();
        let bob_token = login(&mut dir, &bob);
        dir.publish(&bob_token, &bob_handle, record_for(&bob, "bob", 1)).unwrap();
        let alice_token = login(&mut dir, &alice);

        // Up to the limit succeeds within one window (t=0).
        for _ in 0..DEPOSIT_RATE_LIMIT {
            dir.deposit(&alice_token, &bob_handle, "x".into(), 0).unwrap();
        }
        // The next one is rejected.
        assert_eq!(
            dir.deposit(&alice_token, &bob_handle, "x".into(), 0),
            Err(ApiError::RateLimited)
        );
        // A later window resets the counter.
        assert!(dir.deposit(&alice_token, &bob_handle, "x".into(), RATE_WINDOW).is_ok());
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
