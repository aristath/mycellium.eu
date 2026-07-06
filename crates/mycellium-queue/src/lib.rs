//! The Mycellium message queue — decoupled from the directory (Layer 6 split).
//!
//! A **per-recipient store-and-forward mailbox**, keyed by the recipient's
//! **wallet** (not their handle), so it needs *no* directory data to work: it
//! stores opaque, end-to-end-encrypted blobs and hands them back only to the
//! wallet that owns them.
//!
//! This is deliberately *not* the directory: the tiny name registry can be
//! cloned across thousands of opportunistic nodes, but people's queued messages
//! must not be — so a queue is a service you (or a provider) run separately,
//! and the directory record points at its endpoint.
//!
//! Authentication is a SIWE-style wallet login (the shared
//! [`mycellium_core::login`] contract). Deposits are **sender-authenticated** —
//! the depositor logs in with their own wallet and is rate-limited per sender —
//! and only the owning wallet may collect. (Removing the queue's view of the
//! sender is the separate sealed-sender lever; see docs/research/SEALED-SENDER.md.)

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub mod native_push;
mod persist;
mod push;

/// A wake target for one device — a **tagged, versioned** push subscription.
///
/// This replaces the bare endpoint `String` the queue used to store per wallet,
/// so a single per-wallet list can hold browser Web Push, native APNs/FCM, and
/// de-Googled UnifiedPush registrations side by side. The wake to every variant
/// is **contentless** (see [`native_push`] and [`push`]); only the transport
/// differs. Serialized with an internal `kind` tag; existing bare-string
/// web-push records are upgraded to [`Subscription::WebPush`] on load
/// (`persist::load_subs`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Subscription {
    /// Browser Web Push (VAPID, RFC 8292) — the original, still-shipping form.
    /// `endpoint` is the browser push service URL.
    WebPush { endpoint: String },
    /// Apple Push Notification service. `token` is the device token; `topic` is
    /// the app bundle id.
    Apns { token: String, topic: String },
    /// Firebase Cloud Messaging (HTTP v1). `token` is the registration token.
    Fcm { token: String },
    /// UnifiedPush / ntfy — a VAPID-style HTTPS endpoint (de-Googled Android).
    UnifiedPush { endpoint: String },
}

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use mycellium_core::identity::{Signature, WalletPublicKey};
use serde::{Deserialize, Serialize};

/// A request the queue rejected, with the HTTP status it maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    /// No such outstanding challenge, or wallet mismatch.
    BadChallenge,
    /// The login signature did not verify.
    BadSignature,
    /// Missing or unknown session token.
    Unauthorized,
    /// Authenticated, but collecting a wallet that isn't yours.
    Forbidden,
    /// Too many deposits in the rate-limit window.
    RateLimited,
    /// The recipient's mailbox is full.
    MailboxFull,
    /// The queue is at its global mailbox ceiling and can't mint a new one.
    Capacity,
    /// Malformed request.
    BadRequest,
    /// A durable-storage write failed.
    Storage,
}

impl ApiError {
    /// The HTTP status code for this error.
    pub fn status(self) -> u16 {
        match self {
            ApiError::BadChallenge | ApiError::BadSignature | ApiError::BadRequest => 400,
            ApiError::Unauthorized => 401,
            ApiError::Forbidden => 403,
            ApiError::RateLimited | ApiError::MailboxFull => 429,
            ApiError::Capacity => 507,
            ApiError::Storage => 500,
        }
    }

    /// A short human-readable reason.
    pub fn reason(self) -> &'static str {
        match self {
            ApiError::BadChallenge => "unknown or mismatched challenge",
            ApiError::BadSignature => "login signature did not verify",
            ApiError::Unauthorized => "missing or invalid session token",
            ApiError::Forbidden => "you may only collect your own mailbox",
            ApiError::RateLimited => "rate limit exceeded",
            ApiError::MailboxFull => "recipient mailbox is full",
            ApiError::Capacity => "queue is at capacity",
            ApiError::BadRequest => "malformed request",
            ApiError::Storage => "storage write failed",
        }
    }
}

/// Maximum number of queued messages per (wallet, slot) mailbox.
pub const MAX_MAILBOX: usize = 256;

/// Global ceiling on the number of *distinct* mailboxes the queue will hold.
/// The per-sender rate limit bounds how fast one sender deposits, but nothing
/// bounded how many distinct (wallet, slot) mailboxes could be minted overall,
/// so a spread-out flood could exhaust memory/disk. Once this many mailboxes
/// exist, a deposit that would create a *new* one is refused (`Capacity`); a
/// deposit into an already-existing mailbox still succeeds (up to `MAX_MAILBOX`).
pub const MAX_MAILBOXES: usize = 100_000;

/// Hard ceiling on outstanding login challenges. `challenge()` is unauthenticated,
/// so TTL pruning alone let the map grow without bound within a window; at this
/// ceiling the oldest challenge is evicted to make room, keeping memory bounded
/// no matter the request rate.
pub const MAX_CHALLENGES: usize = 10_000;

/// Largest request body the queue will buffer. Deposits carry sealed envelopes
/// (which may embed an attachment up to ~256 KiB), so this leaves headroom.
pub const MAX_BODY: usize = 1024 * 1024;

/// Deposits allowed per sender wallet per [`RATE_WINDOW`].
pub const DEPOSIT_RATE_LIMIT: u32 = 30;

/// The rate-limit window, in seconds.
pub const RATE_WINDOW: u64 = 60;
/// Prune expired rate buckets once the map exceeds this, bounding its memory.
pub const RATE_PRUNE_AT: usize = 10_000;

/// How long a session token lives before it expires and is pruned (24 hours).
pub const TOKEN_TTL: u64 = 24 * 3600;

/// How long an unsigned login challenge stays valid (5 minutes), matching the
/// directory. Expired challenges are pruned when a new one is issued.
pub const CHALLENGE_TTL: u64 = 300;

/// Push subscriptions kept per wallet. Generous for a multi-device account;
/// the oldest is evicted past this, so the list (and per-deposit fan-out) is
/// bounded no matter how many subscriptions a client registers.
pub const MAX_SUBS_PER_WALLET: usize = 20;

/// Largest push-endpoint URL accepted (they're short HTTPS URLs in practice).
pub const MAX_ENDPOINT_LEN: usize = 2048;

/// Largest native push token / APNs topic accepted. APNs device tokens are short
/// hex; FCM registration tokens are longer opaque strings — this bounds both so a
/// client can't wedge storage with an oversized token.
pub const MAX_TOKEN_LEN: usize = 4096;

/// How long a pairing rendezvous slot lives (5 minutes) before it's pruned.
pub const PAIR_TTL: u64 = 300;
/// Max relayed messages per rendezvous id (bounds a griefer who knows the id).
pub const PAIR_MAX: usize = 8;
/// Max concurrent rendezvous slots, bounding memory.
pub const MAX_RENDEZVOUS: usize = 10_000;
/// Largest single pairing message accepted (base64 of a small sealed payload).
pub const MAX_PAIR_MSG: usize = 8192;

/// The queue state. In-memory maps hold the hot working set; when opened with
/// [`Queue::open`], mailboxes and push subscriptions are loaded from and written
/// through to the durable redb store.
#[derive(Default)]
pub struct Queue {
    /// Outstanding login challenges: nonce → (wallet, issued_at). Pruned past
    /// `CHALLENGE_TTL` so abandoned/unsigned challenges can't accumulate.
    challenges: HashMap<String, (WalletPublicKey, u64)>,
    /// Active sessions: token → authenticated wallet.
    tokens: HashMap<String, WalletPublicKey>,
    /// Token issue times, for `TOKEN_TTL` expiry + pruning (bounds accumulation).
    token_times: HashMap<String, u64>,
    /// Mailboxes: (recipient wallet hex, device slot) → queued opaque blobs.
    /// The slot is a device id (targeted) or `"account"` (cluster-wide).
    mailboxes: HashMap<(String, String), Vec<String>>,
    /// Fixed-window rate counters: (wallet, action) → (window_start, count).
    rate: HashMap<([u8; 33], &'static str), (u64, u32)>,
    /// Push subscriptions: recipient wallet hex → tagged per-device wake targets
    /// (Web Push / APNs / FCM / UnifiedPush). Each wake is contentless.
    subs: HashMap<String, Vec<Subscription>>,
    /// Device-pairing rendezvous: rendezvous id → (relayed messages, first-seen).
    /// Ephemeral and unauthenticated — the id is the capability, the payloads are
    /// end-to-end sealed (see `mycellium_core::pairing`), and everything is pruned
    /// past `PAIR_TTL`, so the queue only briefly relays opaque bytes.
    pairing: HashMap<String, (Vec<String>, u64)>,
    /// Durable backing store. `None` = in-memory (tests); `Some` = write-through.
    store: Option<persist::Store>,
}

impl Queue {
    /// A fresh, in-memory queue (tests).
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a **durable** queue backed by the store at `path`, loading any
    /// queued mail and push subscriptions.
    pub fn open(path: &str) -> Result<Self, String> {
        let store = persist::Store::open(path)?;
        let loaded = store.load()?;
        Ok(Queue {
            mailboxes: loaded.mailboxes,
            subs: loaded.subs,
            store: Some(store),
            ..Default::default()
        })
    }

    /// Step 1 of login: issue a challenge nonce for `wallet`.
    pub fn challenge(&mut self, wallet: WalletPublicKey, now: u64) -> String {
        // Housekeeping: drop challenges never signed within the TTL so the map
        // stays bounded rather than growing with every unfinished login.
        self.challenges
            .retain(|_, (_, issued)| now.saturating_sub(*issued) <= CHALLENGE_TTL);
        // Hard ceiling: if TTL pruning didn't free a slot (a burst of fresh,
        // still-valid challenges), evict the oldest so an unauthenticated flood
        // can't grow the map without bound.
        if self.challenges.len() >= MAX_CHALLENGES {
            if let Some(oldest) = self
                .challenges
                .iter()
                .min_by_key(|(_, (_, issued))| *issued)
                .map(|(nonce, _)| nonce.clone())
            {
                self.challenges.remove(&oldest);
            }
        }
        let nonce = random_hex::<16>();
        self.challenges.insert(nonce.clone(), (wallet, now));
        nonce
    }

    /// Step 2 of login: verify the signed challenge and issue a session token.
    pub fn verify(
        &mut self,
        wallet: &WalletPublicKey,
        nonce: &str,
        signature: &Signature,
        now: u64,
    ) -> Result<String, ApiError> {
        match self.challenges.get(nonce) {
            Some((w, issued)) if w == wallet && now.saturating_sub(*issued) <= CHALLENGE_TTL => {}
            _ => return Err(ApiError::BadChallenge),
        }
        wallet
            .verify(&mycellium_core::login::challenge_message(nonce), signature)
            .map_err(|_| ApiError::BadSignature)?;
        self.challenges.remove(nonce);
        // Housekeeping: drop tokens older than the TTL so the map can't grow
        // without bound over a long-running process.
        let expired: Vec<String> = self
            .token_times
            .iter()
            .filter(|(_, &issued)| now.saturating_sub(issued) > TOKEN_TTL)
            .map(|(t, _)| t.clone())
            .collect();
        for t in expired {
            self.tokens.remove(&t);
            self.token_times.remove(&t);
        }
        let token = random_hex::<24>();
        self.tokens.insert(token.clone(), *wallet);
        self.token_times.insert(token.clone(), now);
        Ok(token)
    }

    /// Resolve a token to its wallet, rejecting one past `TOKEN_TTL`.
    fn authed(&self, token: &str, now: u64) -> Result<WalletPublicKey, ApiError> {
        let wallet = *self.tokens.get(token).ok_or(ApiError::Unauthorized)?;
        let issued = self.token_times.get(token).copied().unwrap_or(0);
        if now.saturating_sub(issued) > TOKEN_TTL {
            return Err(ApiError::Unauthorized);
        }
        Ok(wallet)
    }

    /// Register a push subscription for the logged-in wallet (idempotent). The
    /// subscription is validated per variant (§2.2); a duplicate is a no-op, so a
    /// device re-registering a rotated token stays a single entry.
    pub fn subscribe(&mut self, token: &str, sub: Subscription, now: u64) -> Result<(), ApiError> {
        let wallet = self.authed(token, now)?;
        if !is_valid_subscription(&sub) {
            return Err(ApiError::BadRequest);
        }
        let wallet_hex = hex33(&wallet.0);
        let list = self.subs.entry(wallet_hex.clone()).or_default();
        if !list.contains(&sub) {
            list.push(sub);
            // Cap per wallet by evicting the oldest, so a device rotating its
            // token doesn't wedge the list and a client can't grow it forever.
            while list.len() > MAX_SUBS_PER_WALLET {
                list.remove(0);
            }
            if let Some(store) = &self.store {
                store
                    .put_subs(&wallet_hex, list)
                    .map_err(|_| ApiError::Storage)?;
            }
        }
        Ok(())
    }

    /// Remove a push subscription for the logged-in wallet (explicit unsubscribe).
    pub fn unsubscribe(
        &mut self,
        token: &str,
        sub: &Subscription,
        now: u64,
    ) -> Result<(), ApiError> {
        let wallet = self.authed(token, now)?;
        let wallet_hex = hex33(&wallet.0);
        if let Some(list) = self.subs.get_mut(&wallet_hex) {
            let before = list.len();
            list.retain(|s| s != sub);
            if list.len() != before {
                if let Some(store) = &self.store {
                    store
                        .put_subs(&wallet_hex, list)
                        .map_err(|_| ApiError::Storage)?;
                }
            }
        }
        Ok(())
    }

    /// Drop subscriptions a transport reported as gone (Web Push 404/410, APNs
    /// `Unregistered`, FCM `UNREGISTERED`). Called off the request path after a
    /// deposit's fan-out, so dead subscriptions don't linger and waste a send on
    /// every future deposit.
    pub fn remove_subs(&mut self, wallet_hex: &str, gone: &[Subscription]) {
        if let Some(list) = self.subs.get_mut(wallet_hex) {
            let before = list.len();
            list.retain(|s| !gone.contains(s));
            if list.len() != before {
                if let Some(store) = &self.store {
                    let _ = store.put_subs(wallet_hex, list);
                }
            }
        }
    }

    /// The push subscriptions registered for a recipient wallet.
    pub fn subscriptions(&self, wallet_hex: &str) -> Vec<Subscription> {
        self.subs.get(wallet_hex).cloned().unwrap_or_default()
    }

    /// Deposit an opaque blob into `recipient`'s (`wallet hex`) mailbox `slot`.
    /// Any authenticated sender may deposit (rate-limited per sender wallet).
    pub fn deposit(
        &mut self,
        token: &str,
        recipient_wallet_hex: &str,
        slot: &str,
        blob: String,
        now: u64,
    ) -> Result<(), ApiError> {
        // Reject malformed/oversized keys before they can mint a sparse mailbox
        // (a valid wallet is 66 hex chars; a valid slot is `account` or 64 hex).
        if !is_wallet_hex(recipient_wallet_hex) || !is_slot(slot) {
            return Err(ApiError::BadRequest);
        }
        let sender = self.authed(token, now)?;
        if !self.allow(sender.0, "deposit", now) {
            return Err(ApiError::RateLimited);
        }
        let key = (recipient_wallet_hex.to_string(), slot.to_string());
        // Global mailbox ceiling: refuse a deposit that would mint a *new*
        // mailbox once we're at capacity (O(1): `HashMap::len` + `contains_key`),
        // so a spread-out flood of distinct (wallet, slot) targets can't exhaust
        // storage. A deposit into an already-existing mailbox is unaffected.
        if self.mailboxes.len() >= MAX_MAILBOXES && !self.mailboxes.contains_key(&key) {
            return Err(ApiError::Capacity);
        }
        let mailbox = self.mailboxes.entry(key).or_default();
        if mailbox.len() >= MAX_MAILBOX {
            return Err(ApiError::MailboxFull);
        }
        mailbox.push(blob);
        if let Some(store) = &self.store {
            store
                .put_mailbox(recipient_wallet_hex, slot, mailbox)
                .map_err(|_| ApiError::Storage)?;
        }
        Ok(())
    }

    /// Drain one mailbox slot. The `token` proves the caller controls a wallet;
    /// they may only collect *their own* wallet (`wallet_hex`).
    pub fn collect(
        &mut self,
        token: &str,
        wallet_hex: &str,
        slot: &str,
        now: u64,
    ) -> Result<Vec<String>, ApiError> {
        if !is_slot(slot) {
            return Err(ApiError::BadRequest);
        }
        let caller = self.authed(token, now)?;
        if hex33(&caller.0) != wallet_hex {
            return Err(ApiError::Forbidden);
        }
        let drained = self
            .mailboxes
            .remove(&(wallet_hex.to_string(), slot.to_string()))
            .unwrap_or_default();
        if let Some(store) = &self.store {
            store
                .del_mailbox(wallet_hex, slot)
                .map_err(|_| ApiError::Storage)?;
        }
        Ok(drained)
    }

    /// Relay one opaque, end-to-end-sealed pairing message into rendezvous `rid`.
    /// Unauthenticated by design (the id is the capability); bounded per id and in
    /// total, and pruned past `PAIR_TTL`.
    pub fn pair_post(&mut self, rid: &str, msg: String, now: u64) -> Result<(), ApiError> {
        if !is_rendezvous_id(rid) || msg.len() > MAX_PAIR_MSG {
            return Err(ApiError::BadRequest);
        }
        self.prune_pairing(now);
        if self.pairing.len() >= MAX_RENDEZVOUS && !self.pairing.contains_key(rid) {
            return Err(ApiError::RateLimited);
        }
        let entry = self
            .pairing
            .entry(rid.to_string())
            .or_insert((Vec::new(), now));
        if entry.0.len() >= PAIR_MAX {
            return Err(ApiError::MailboxFull);
        }
        entry.0.push(msg);
        Ok(())
    }

    /// Drain the messages relayed to rendezvous `rid` (one-shot).
    pub fn pair_fetch(&mut self, rid: &str, now: u64) -> Result<Vec<String>, ApiError> {
        if !is_rendezvous_id(rid) {
            return Err(ApiError::BadRequest);
        }
        self.prune_pairing(now);
        Ok(self.pairing.remove(rid).map(|(m, _)| m).unwrap_or_default())
    }

    /// Drop rendezvous slots older than `PAIR_TTL` so they can't accumulate.
    fn prune_pairing(&mut self, now: u64) {
        self.pairing
            .retain(|_, (_, seen)| now.saturating_sub(*seen) < PAIR_TTL);
    }

    /// A fixed-window rate check for `(wallet, action)` at `now`.
    fn allow(&mut self, wallet: [u8; 33], action: &'static str, now: u64) -> bool {
        // Bound memory: prune fully-elapsed buckets once the map grows large.
        if self.rate.len() > RATE_PRUNE_AT {
            self.rate
                .retain(|_, (start, _)| now.saturating_sub(*start) < RATE_WINDOW);
        }
        let entry = self.rate.entry((wallet, action)).or_insert((now, 0));
        if now.saturating_sub(entry.0) >= RATE_WINDOW {
            *entry = (now, 0);
        }
        if entry.1 >= DEPOSIT_RATE_LIMIT {
            return false;
        }
        entry.1 += 1;
        true
    }
}

/// The shared state the queue handlers need. axum threads a single `State`
/// type, so the queue, its VAPID keypair, and the native-push transports travel
/// together.
#[derive(Clone)]
pub struct QueueState {
    queue: Arc<Mutex<Queue>>,
    vapid: Arc<push::Vapid>,
    native: Arc<native_push::NativePush>,
    push_allow_hosts: Arc<HashSet<String>>,
}

/// Queue HTTP serving config.
#[derive(Clone, Debug, Default)]
pub struct ServeConfig {
    /// Durable data directory. `None` means explicit in-memory development mode.
    pub data_dir: Option<String>,
    /// Shared HTTP runtime options.
    pub http: mycellium_serve::HttpConfig,
    /// Exact `host:port` authorities that may receive push POSTs even if they
    /// resolve to private/internal addresses. This is only for operator-owned
    /// self-hosted push distributors; subscribe-time validation remains strict.
    pub push_allow_hosts: Vec<String>,
}

impl ServeConfig {
    /// Explicit in-memory development config.
    pub fn dev() -> Self {
        Self::default()
    }
}

/// Bind `addr` and serve the queue until a shutdown signal arrives.
pub async fn serve(addr: &str, config: ServeConfig) -> std::io::Result<()> {
    serve_with(
        addr,
        Arc::new(Mutex::new(open_queue(config.data_dir.as_deref())?)),
        config,
    )
    .await
}

/// Serve the queue over an **externally-owned** queue handle, so an embedder or
/// test can seed/observe the same [`Queue`] the routes mutate.
pub async fn serve_with(
    addr: &str,
    queue: Arc<Mutex<Queue>>,
    config: ServeConfig,
) -> std::io::Result<()> {
    let push_allow_hosts = Arc::new(normalize_allow_hosts(config.push_allow_hosts));
    let vapid = Arc::new(load_or_generate_vapid(
        config.data_dir.as_deref(),
        (*push_allow_hosts).clone(),
    ));
    let native = Arc::new(native_push::NativePush::default());
    println!("  push: VAPID enabled");
    let state = QueueState {
        queue,
        vapid,
        native,
        push_allow_hosts,
    };
    mycellium_serve::Server::new("queue", MAX_BODY)
        .run(addr, router(state), config.http)
        .await
}

/// Build the queue's [`Router`] over an externally-owned queue handle, with an
/// ephemeral VAPID key. For in-process embedding and tests that want a handle to
/// the same [`Queue`] the routes mutate.
pub fn router_for(queue: Arc<Mutex<Queue>>) -> Router {
    router(QueueState {
        queue,
        vapid: Arc::new(push::Vapid::generate()),
        native: Arc::new(native_push::NativePush::default()),
        push_allow_hosts: Arc::new(HashSet::new()),
    })
}

/// Dispatches a contentless wake to the right transport for a [`Subscription`].
/// Abstracted so the fan-out is unit-testable with a stub in place of the real
/// VAPID / APNs / FCM senders.
trait Waker {
    /// Wake one device via its subscription's transport. `None` means that
    /// transport isn't configured at this operator, so it's skipped (mail stays
    /// queued — the reliability invariant).
    fn wake(&self, sub: &Subscription, now: u64) -> Option<push::SendResult>;
}

/// The live dispatcher: Web Push over VAPID and UnifiedPush over a bare
/// contentless POST (the shipping self-hostable paths), APNs / FCM over the
/// native transports.
struct LiveWaker {
    vapid: Arc<push::Vapid>,
    native: Arc<native_push::NativePush>,
    push_allow_hosts: Arc<HashSet<String>>,
}

impl Waker for LiveWaker {
    fn wake(&self, sub: &Subscription, now: u64) -> Option<push::SendResult> {
        match sub {
            // Web Push is VAPID (RFC 8292) — a signed, contentless POST.
            Subscription::WebPush { endpoint } => Some(self.vapid.send(endpoint, now)),
            // UnifiedPush needs **no** VAPID: the distributor just accepts a bare
            // contentless POST to the endpoint. Route it through the plain sender.
            Subscription::UnifiedPush { endpoint } => Some(push::unifiedpush_send(
                endpoint,
                now,
                &self.push_allow_hosts,
            )),
            Subscription::Apns { .. } | Subscription::Fcm { .. } => self.native.wake(sub, now),
        }
    }
}

/// Wake every subscription for a recipient and return the ones a transport
/// reported `Gone` (to be pruned via [`Queue::remove_subs`]). Pure over the
/// [`Waker`], so it's testable without touching the network.
fn wake_all(subs: Vec<Subscription>, waker: &dyn Waker, now: u64) -> Vec<Subscription> {
    let mut gone = Vec::new();
    for sub in subs {
        if waker.wake(&sub, now) == Some(push::SendResult::Gone) {
            gone.push(sub);
        }
    }
    gone
}

/// The queue's routes, over already-constructed state. Split out so tests can
/// mount it without the process-level startup.
pub fn router(state: QueueState) -> Router {
    Router::new()
        .route("/login/challenge", post(login_challenge))
        .route("/login/verify", post(login_verify))
        .route("/push/key", get(push_key))
        .route("/push/subscribe", post(push_subscribe))
        .route("/push/unsubscribe", post(push_unsubscribe))
        .route(
            "/mailbox/{wallet}/{slot}",
            post(mailbox_post).get(mailbox_get),
        )
        .route("/pair/{rid}", post(pair_post).get(pair_get))
        .with_state(state)
}

/// Open the queue durably from an explicit data directory. `None` is explicit
/// in-memory development mode.
fn open_queue(data: Option<&str>) -> std::io::Result<Queue> {
    match data {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            let path = format!("{}/queue.redb", dir.trim_end_matches('/'));
            let queue = Queue::open(&path).map_err(|e| {
                std::io::Error::other(format!(
                    "the durable queue store at {path} could not be opened: {e}"
                ))
            })?;
            println!("  persistence: {path}");
            Ok(queue)
        }
        None => {
            println!("  storage: in-memory development mode");
            Ok(Queue::new())
        }
    }
}

/// Load the VAPID keypair from `{data_dir}/vapid.key`, or generate one and
/// persist it there (0600) so browser push subscriptions survive restarts. With
/// no data dir, use an ephemeral keypair for explicit development mode.
fn load_or_generate_vapid(
    data_dir: Option<&str>,
    push_allow_hosts: HashSet<String>,
) -> push::Vapid {
    let dir = match data_dir {
        Some(d) => d,
        None => return push::Vapid::generate_with_allowlist(push_allow_hosts),
    };
    let _ = std::fs::create_dir_all(dir);
    let path = format!("{}/vapid.key", dir.trim_end_matches('/'));
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
            if let Some(v) = push::Vapid::from_seed_with_allowlist(&seed, push_allow_hosts.clone())
            {
                println!("  push: VAPID key loaded ({path})");
                return v;
            }
        }
        eprintln!("  push: {path} is unreadable; regenerating");
    }
    let v = push::Vapid::generate_with_allowlist(push_allow_hosts);
    match std::fs::write(&path, v.seed()) {
        Ok(()) => {
            restrict_perms(&path);
            println!("  push: VAPID key generated + persisted ({path})");
        }
        Err(e) => eprintln!("  push: could not persist VAPID key ({e}); it will change on restart"),
    }
    v
}

fn normalize_allow_hosts(hosts: Vec<String>) -> HashSet<String> {
    hosts
        .into_iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
}

#[cfg(unix)]
fn restrict_perms(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_perms(_path: &str) {}

// --- handlers ---------------------------------------------------------------

async fn login_challenge(State(st): State<QueueState>, body: String) -> Result<Response, ApiError> {
    let req: ChallengeReq = parse(&body)?;
    let nonce = st.queue.lock().unwrap().challenge(req.wallet, now_secs());
    Ok(Json(ChallengeResp { nonce }).into_response())
}

async fn login_verify(State(st): State<QueueState>, body: String) -> Result<Response, ApiError> {
    let req: VerifyReq = parse(&body)?;
    let token =
        st.queue
            .lock()
            .unwrap()
            .verify(&req.wallet, &req.nonce, &req.signature, now_secs())?;
    Ok(Json(VerifyResp { token }).into_response())
}

// The VAPID public key clients need to subscribe to Web Push (open, no auth).
async fn push_key(State(st): State<QueueState>) -> Response {
    Json(PushKey {
        key: st.vapid.public_key().to_string(),
    })
    .into_response()
}

async fn push_subscribe(
    State(st): State<QueueState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, ApiError> {
    let token = bearer(&headers).ok_or(ApiError::Unauthorized)?;
    let req: SubscribeReq = parse(&body)?;
    st.queue
        .lock()
        .unwrap()
        .subscribe(token, req.into_subscription(), now_secs())?;
    Ok(ok())
}

async fn push_unsubscribe(
    State(st): State<QueueState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, ApiError> {
    let token = bearer(&headers).ok_or(ApiError::Unauthorized)?;
    let req: SubscribeReq = parse(&body)?;
    st.queue
        .lock()
        .unwrap()
        .unsubscribe(token, &req.into_subscription(), now_secs())?;
    Ok(ok())
}

async fn mailbox_post(
    State(st): State<QueueState>,
    Path((wallet, slot)): Path<(String, String)>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, ApiError> {
    let token = bearer(&headers).ok_or(ApiError::Unauthorized)?;
    let now = now_secs();
    st.queue
        .lock()
        .unwrap()
        .deposit(token, &wallet, &slot, body, now)?;
    // Wake the recipient's devices — contentless, and off the lock/thread so a
    // slow push transport never stalls the queue. Each subscription dispatches
    // to its transport (Web Push over VAPID, UnifiedPush over a bare POST, APNs /
    // FCM over the native transports, skipped when the operator hasn't configured
    // them).
    let subs = st.queue.lock().unwrap().subscriptions(&wallet);
    if !subs.is_empty() {
        let waker = LiveWaker {
            vapid: Arc::clone(&st.vapid),
            native: Arc::clone(&st.native),
            push_allow_hosts: Arc::clone(&st.push_allow_hosts),
        };
        let queue = Arc::clone(&st.queue);
        std::thread::spawn(move || {
            // Prune the subscriptions a transport says are gone, so we don't
            // wake them on every future deposit.
            let gone = wake_all(subs, &waker, now);
            if !gone.is_empty() {
                queue.lock().unwrap().remove_subs(&wallet, &gone);
            }
        });
    }
    Ok(ok())
}

async fn mailbox_get(
    State(st): State<QueueState>,
    Path((wallet, slot)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = bearer(&headers).ok_or(ApiError::Unauthorized)?;
    let messages = st
        .queue
        .lock()
        .unwrap()
        .collect(token, &wallet, &slot, now_secs())?;
    Ok(Json(Messages { messages }).into_response())
}

// Device-pairing rendezvous — unauthenticated by design (the id is the
// capability; the payloads are end-to-end sealed).
async fn pair_post(
    State(st): State<QueueState>,
    Path(rid): Path<String>,
    body: String,
) -> Result<Response, ApiError> {
    let req: PairPost = parse(&body)?;
    st.queue
        .lock()
        .unwrap()
        .pair_post(&rid, req.msg, now_secs())?;
    Ok(ok())
}

async fn pair_get(
    State(st): State<QueueState>,
    Path(rid): Path<String>,
) -> Result<Response, ApiError> {
    let msgs = st.queue.lock().unwrap().pair_fetch(&rid, now_secs())?;
    Ok(Json(PairFetch { msgs }).into_response())
}

#[derive(Deserialize)]
struct ChallengeReq {
    wallet: WalletPublicKey,
}
#[derive(Serialize)]
struct ChallengeResp {
    nonce: String,
}
#[derive(Deserialize)]
struct VerifyReq {
    wallet: WalletPublicKey,
    nonce: String,
    signature: Signature,
}
#[derive(Serialize)]
struct VerifyResp {
    token: String,
}
#[derive(Serialize)]
struct Messages {
    messages: Vec<String>,
}
#[derive(Serialize)]
struct PushKey {
    key: String,
}
/// The `/push/subscribe` + `/push/unsubscribe` request body — a **superset** of
/// the legacy shape, so existing PWA clients keep working across the upgrade:
///
/// - `{ "kind": "apns", "token": "…", "topic": "…" }` (and the other tagged
///   variants) — the versioned native/web form.
/// - `{ "endpoint": "https://…" }` — the legacy bare web-push endpoint.
///
/// `Tagged` is tried first so a `unified_push` (which also carries an `endpoint`)
/// isn't misread as web push; a body with no `kind` falls through to `Legacy`.
#[derive(Deserialize)]
#[serde(untagged)]
enum SubscribeReq {
    Tagged(Subscription),
    Legacy { endpoint: String },
}

impl SubscribeReq {
    fn into_subscription(self) -> Subscription {
        match self {
            SubscribeReq::Tagged(sub) => sub,
            SubscribeReq::Legacy { endpoint } => Subscription::WebPush { endpoint },
        }
    }
}
#[derive(Deserialize)]
struct PairPost {
    msg: String,
}
#[derive(Serialize)]
struct PairFetch {
    msgs: Vec<String>,
}

// --- helpers ----------------------------------------------------------------

/// Map a domain [`ApiError`] to an HTTP status + `{"error": reason}` body.
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status()).unwrap_or(StatusCode::BAD_REQUEST);
        (status, Json(serde_json::json!({ "error": self.reason() }))).into_response()
    }
}

/// The canonical `"ok"` success body (a JSON string), as the clients expect.
fn ok() -> Response {
    Json("ok").into_response()
}

/// Parse a JSON request body, content-type-agnostically (the clients don't always
/// set `Content-Type`), mapping any failure to a domain error.
fn parse<T: for<'de> Deserialize<'de>>(body: &str) -> Result<T, ApiError> {
    serde_json::from_str(body).map_err(|_| ApiError::BadRequest)
}

/// Extract a `Bearer` token from the `Authorization` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercase hex of a 33-byte compressed wallet key.
pub fn hex33(bytes: &[u8; 33]) -> String {
    let mut out = String::with_capacity(66);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// The cluster-wide mailbox slot (mirrors the engine's `ACCOUNT_SLOT`).
pub const ACCOUNT_SLOT: &str = "account";

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A recipient key is exactly one 66-char compressed-wallet hex (as `hex33`
/// produces). Anything else can't name a real mailbox.
fn is_wallet_hex(s: &str) -> bool {
    is_lower_hex(s, 66)
}

/// A slot is either the account slot or a 64-char device id (`device_slot` hex).
fn is_slot(s: &str) -> bool {
    s == ACCOUNT_SLOT || is_lower_hex(s, 64)
}

/// A pairing rendezvous id: 16..=64 lowercase-hex chars (high-entropy capability).
fn is_rendezvous_id(s: &str) -> bool {
    let n = s.len();
    (16..=64).contains(&n)
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// A plausible Web Push endpoint: a bounded HTTPS URL with a host, whose host is
/// not statically an internal target. (Requiring HTTPS keeps the queue off
/// plain-HTTP internal URLs; the internal-host guard blocks loopback/link-local/
/// private/metadata literals at subscribe time — a DNS name that only *resolves*
/// internally is caught again, with a fresh resolution, right before the POST in
/// `push::endpoint_is_safe_to_connect`.)
fn is_push_endpoint(e: &str) -> bool {
    e.len() <= MAX_ENDPOINT_LEN
        && push::origin_of(e)
            .map(|o| o.starts_with("https://"))
            .unwrap_or(false)
        && !push::is_blocked_endpoint_static(e)
}

/// Validate a [`Subscription`] per variant before it can enter storage, so a
/// malformed client can't wedge the subs map. Endpoint variants reuse the HTTPS
/// URL check; native tokens are bounded (APNs tokens are hex, FCM tokens are
/// opaque printable ASCII, the APNs topic is a bounded bundle id).
fn is_valid_subscription(sub: &Subscription) -> bool {
    match sub {
        Subscription::WebPush { endpoint } | Subscription::UnifiedPush { endpoint } => {
            is_push_endpoint(endpoint)
        }
        Subscription::Apns { token, topic } => is_apns_token(token) && is_bounded_token(topic),
        Subscription::Fcm { token } => is_bounded_token(token),
    }
}

/// An APNs device token: non-empty, bounded, all hex (32 bytes → 64 chars in
/// practice, but accept any bounded hex to tolerate platform differences).
fn is_apns_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_TOKEN_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A bounded opaque token/topic: non-empty printable ASCII, no whitespace or
/// control characters (covers FCM tokens and APNs bundle-id topics).
fn is_bounded_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_TOKEN_LEN && s.bytes().all(|b| b.is_ascii_graphic())
}

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
    use mycellium_core::identity::Identity;
    use mycellium_core::platform::Platform;

    struct P(u8);
    impl Platform for P {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
        fn now_unix_secs(&self) -> u64 {
            0
        }
    }

    fn login(q: &mut Queue, id: &Identity) -> String {
        let nonce = q.challenge(id.wallet_public(), 0);
        let sig = id.sign(&mycellium_core::login::challenge_message(&nonce));
        q.verify(&id.wallet_public(), &nonce, &sig, 0).unwrap()
    }

    #[test]
    fn mail_and_subs_survive_a_reopen() {
        let path = std::env::temp_dir().join(format!("myc-q-persist-{}.redb", random_hex::<8>()));
        let path_str = path.to_str().unwrap();
        let bob = Identity::generate(&mut P(90)).unwrap();
        let bob_hex = hex33(&bob.wallet_public().0);
        let alice = Identity::generate(&mut P(1)).unwrap();

        {
            let mut q = Queue::open(path_str).unwrap();
            let atoken = login(&mut q, &alice);
            q.deposit(&atoken, &bob_hex, ACCOUNT_SLOT, "sealed".into(), 0)
                .unwrap();
            let btoken = login(&mut q, &bob);
            q.subscribe(
                &btoken,
                Subscription::WebPush {
                    endpoint: "https://push.example/abc".into(),
                },
                0,
            )
            .unwrap();
        } // drop → flushed

        // Reopen: the queued blob and the push subscription are both still there.
        let mut q2 = Queue::open(path_str).unwrap();
        assert_eq!(
            q2.subscriptions(&bob_hex),
            vec![Subscription::WebPush {
                endpoint: "https://push.example/abc".into()
            }]
        );
        let btoken = login(&mut q2, &bob);
        assert_eq!(
            q2.collect(&btoken, &bob_hex, ACCOUNT_SLOT, 0).unwrap(),
            vec!["sealed".to_string()]
        );
        // ...and after collecting, the drain is persisted (empty on next reopen).
        drop(q2);
        let mut q3 = Queue::open(path_str).unwrap();
        let btoken2 = login(&mut q3, &bob);
        assert!(q3
            .collect(&btoken2, &bob_hex, ACCOUNT_SLOT, 0)
            .unwrap()
            .is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn token_expires_after_ttl() {
        let mut q = Queue::new();
        let alice = Identity::generate(&mut P(3)).unwrap();
        let bob = Identity::generate(&mut P(4)).unwrap();
        let bob_hex = hex33(&bob.wallet_public().0);
        let token = login(&mut q, &alice); // issued at now = 0
        assert!(q
            .deposit(&token, &bob_hex, ACCOUNT_SLOT, "x".into(), 10)
            .is_ok());
        assert_eq!(
            q.deposit(&token, &bob_hex, ACCOUNT_SLOT, "x".into(), TOKEN_TTL + 1),
            Err(ApiError::Unauthorized),
        );
    }

    #[test]
    fn durable_open_fails_closed_on_a_bad_data_dir() {
        // No data dir → explicit in-memory development mode.
        assert!(super::open_queue(None).is_ok());
        // A valid data dir → durable mode.
        let good = std::env::temp_dir().join(format!("myc-q-good-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&good);
        assert!(super::open_queue(Some(good.to_str().unwrap())).is_ok());
        let _ = std::fs::remove_dir_all(&good);
        // Configured but unusable (the path is a file, not a dir) → fail closed,
        // never a silent in-memory fallback.
        let bad = std::env::temp_dir().join(format!("myc-q-bad-{}", std::process::id()));
        let _ = std::fs::remove_file(&bad);
        std::fs::write(&bad, b"not a dir").unwrap();
        assert!(super::open_queue(Some(bad.to_str().unwrap())).is_err());
        let _ = std::fs::remove_file(&bad);
    }

    #[test]
    fn pairing_rendezvous_relays_drains_and_expires() {
        let mut q = Queue::new();
        let rid = "abcdef0123456789";
        q.pair_post(rid, "msg1".into(), 0).unwrap();
        q.pair_post(rid, "msg2".into(), 1).unwrap();
        // Fetch drains everything, and a second fetch is empty (one-shot).
        assert_eq!(q.pair_fetch(rid, 2).unwrap(), vec!["msg1", "msg2"]);
        assert!(q.pair_fetch(rid, 3).unwrap().is_empty());
        // A malformed rendezvous id is rejected.
        assert_eq!(
            q.pair_post("SHORT", "x".into(), 0),
            Err(ApiError::BadRequest)
        );
        // A slot older than the TTL is pruned rather than served.
        q.pair_post(rid, "stale".into(), 0).unwrap();
        assert!(q.pair_fetch(rid, PAIR_TTL + 1).unwrap().is_empty());
    }

    #[test]
    fn expired_token_cannot_collect_or_subscribe() {
        // Token TTL must be enforced on *every* authenticated op, not just deposit.
        let mut q = Queue::new();
        let bob = Identity::generate(&mut P(21)).unwrap();
        let bob_hex = hex33(&bob.wallet_public().0);
        let token = login(&mut q, &bob); // issued at now = 0

        // Fresh token works for both collect and subscribe.
        assert!(q
            .subscribe(
                &token,
                Subscription::WebPush {
                    endpoint: "https://push.example/ok".into()
                },
                10
            )
            .is_ok());
        assert!(q.collect(&token, &bob_hex, ACCOUNT_SLOT, 10).is_ok());

        // Past TOKEN_TTL the same token is rejected for every authenticated op.
        assert_eq!(
            q.collect(&token, &bob_hex, ACCOUNT_SLOT, TOKEN_TTL + 1),
            Err(ApiError::Unauthorized),
        );
        assert_eq!(
            q.subscribe(
                &token,
                Subscription::WebPush {
                    endpoint: "https://push.example/late".into()
                },
                TOKEN_TTL + 1
            ),
            Err(ApiError::Unauthorized),
        );
        assert_eq!(
            q.unsubscribe(
                &token,
                &Subscription::WebPush {
                    endpoint: "https://push.example/ok".into()
                },
                TOKEN_TTL + 1
            ),
            Err(ApiError::Unauthorized),
        );
    }

    fn web(endpoint: &str) -> Subscription {
        Subscription::WebPush {
            endpoint: endpoint.into(),
        }
    }

    #[test]
    fn push_subscriptions_are_validated_capped_and_removable() {
        let mut q = Queue::new();
        let a = Identity::generate(&mut P(11)).unwrap();
        let token = login(&mut q, &a);
        let hex = hex33(&a.wallet_public().0);

        // Non-HTTPS / malformed web-push endpoints are refused.
        assert_eq!(
            q.subscribe(&token, web("http://insecure/x"), 0),
            Err(ApiError::BadRequest)
        );
        assert_eq!(
            q.subscribe(&token, web("not a url"), 0),
            Err(ApiError::BadRequest)
        );
        // UnifiedPush reuses the HTTPS check; a plain-HTTP one is refused too.
        assert_eq!(
            q.subscribe(
                &token,
                Subscription::UnifiedPush {
                    endpoint: "http://insecure/up".into()
                },
                0
            ),
            Err(ApiError::BadRequest)
        );
        // Native tokens are validated: an APNs token must be hex, an FCM/topic
        // token must be non-empty printable ASCII.
        assert_eq!(
            q.subscribe(
                &token,
                Subscription::Apns {
                    token: "not-hex!".into(),
                    topic: "eu.mycellium.app".into()
                },
                0
            ),
            Err(ApiError::BadRequest)
        );
        assert_eq!(
            q.subscribe(&token, Subscription::Fcm { token: "".into() }, 0),
            Err(ApiError::BadRequest)
        );

        // Valid variants of every kind are accepted and stored side by side.
        q.subscribe(&token, web("https://push.example/a"), 0)
            .unwrap();
        q.subscribe(
            &token,
            Subscription::Apns {
                token: "abcdef0123456789".into(),
                topic: "eu.mycellium.app".into(),
            },
            0,
        )
        .unwrap();
        q.subscribe(
            &token,
            Subscription::Fcm {
                token: "fcm-registration-token".into(),
            },
            0,
        )
        .unwrap();
        q.subscribe(
            &token,
            Subscription::UnifiedPush {
                endpoint: "https://ntfy.example/up".into(),
            },
            0,
        )
        .unwrap();
        assert_eq!(q.subscriptions(&hex).len(), 4);

        // Duplicate subscribes are idempotent, per variant (a re-registered
        // token stays a single entry).
        q.subscribe(&token, web("https://push.example/a"), 0)
            .unwrap();
        q.subscribe(
            &token,
            Subscription::Fcm {
                token: "fcm-registration-token".into(),
            },
            0,
        )
        .unwrap();
        assert_eq!(q.subscriptions(&hex).len(), 4);

        // The list is capped, evicting the oldest.
        for i in 0..MAX_SUBS_PER_WALLET + 5 {
            q.subscribe(&token, web(&format!("https://push.example/{i}")), 0)
                .unwrap();
        }
        assert_eq!(q.subscriptions(&hex).len(), MAX_SUBS_PER_WALLET);

        // Explicit unsubscribe removes exactly the matching subscription.
        let s0 = q.subscriptions(&hex)[0].clone();
        q.unsubscribe(&token, &s0, 0).unwrap();
        assert!(!q.subscriptions(&hex).contains(&s0));

        // Gone-removal (the Gone/Unregistered path) drops dead subscriptions.
        let s1 = q.subscriptions(&hex)[0].clone();
        q.remove_subs(&hex, std::slice::from_ref(&s1));
        assert!(!q.subscriptions(&hex).contains(&s1));
    }

    #[test]
    fn fan_out_selects_transport_per_variant_and_collects_gone() {
        // A stub Waker records how each variant is dispatched, and reports Gone
        // for chosen entries + None (skip) for an unconfigured native transport.
        struct Stub;
        impl Waker for Stub {
            fn wake(&self, sub: &Subscription, _now: u64) -> Option<push::SendResult> {
                match sub {
                    // A dead web-push endpoint is Gone (to be pruned).
                    Subscription::WebPush { endpoint } if endpoint.ends_with("dead") => {
                        Some(push::SendResult::Gone)
                    }
                    Subscription::WebPush { .. } | Subscription::UnifiedPush { .. } => {
                        Some(push::SendResult::Ok)
                    }
                    // APNs here stands in for an unconfigured transport → skipped.
                    Subscription::Apns { .. } => None,
                    // FCM here reports Gone (an UNREGISTERED token).
                    Subscription::Fcm { .. } => Some(push::SendResult::Gone),
                }
            }
        }

        let subs = vec![
            web("https://push.example/live"),
            web("https://push.example/dead"),
            Subscription::UnifiedPush {
                endpoint: "https://ntfy.example/up".into(),
            },
            Subscription::Apns {
                token: "abcd".into(),
                topic: "eu.mycellium.app".into(),
            },
            Subscription::Fcm {
                token: "dead-fcm".into(),
            },
        ];

        let gone = wake_all(subs, &Stub, 0);
        // Only the dead web-push and the UNREGISTERED FCM are collected for
        // pruning; the live/skipped ones are left in place.
        assert_eq!(
            gone,
            vec![
                web("https://push.example/dead"),
                Subscription::Fcm {
                    token: "dead-fcm".into()
                },
            ]
        );
    }

    #[test]
    fn subscribe_req_parses_legacy_and_tagged_forms() {
        // Legacy bare endpoint → WebPush.
        let legacy: SubscribeReq =
            serde_json::from_str(r#"{"endpoint":"https://push.example/x"}"#).unwrap();
        assert_eq!(legacy.into_subscription(), web("https://push.example/x"));
        // Tagged web push.
        let wp: SubscribeReq =
            serde_json::from_str(r#"{"kind":"web_push","endpoint":"https://push.example/y"}"#)
                .unwrap();
        assert_eq!(wp.into_subscription(), web("https://push.example/y"));
        // Tagged UnifiedPush must NOT be misread as web push (it also has an
        // endpoint) — the `kind` tag wins.
        let up: SubscribeReq =
            serde_json::from_str(r#"{"kind":"unified_push","endpoint":"https://ntfy.example/u"}"#)
                .unwrap();
        assert_eq!(
            up.into_subscription(),
            Subscription::UnifiedPush {
                endpoint: "https://ntfy.example/u".into()
            }
        );
        // Tagged APNs + FCM.
        let apns: SubscribeReq =
            serde_json::from_str(r#"{"kind":"apns","token":"abcd","topic":"eu.mycellium.app"}"#)
                .unwrap();
        assert_eq!(
            apns.into_subscription(),
            Subscription::Apns {
                token: "abcd".into(),
                topic: "eu.mycellium.app".into()
            }
        );
        let fcm: SubscribeReq = serde_json::from_str(r#"{"kind":"fcm","token":"tok"}"#).unwrap();
        assert_eq!(
            fcm.into_subscription(),
            Subscription::Fcm {
                token: "tok".into()
            }
        );
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let mut q = Queue::new();
        let a = Identity::generate(&mut P(7)).unwrap();
        let nonce = q.challenge(a.wallet_public(), 0);
        let sig = a.sign(&mycellium_core::login::challenge_message(&nonce));
        // A signature arriving after the challenge TTL is refused.
        assert_eq!(
            q.verify(&a.wallet_public(), &nonce, &sig, CHALLENGE_TTL + 1),
            Err(ApiError::BadChallenge),
        );
        // Within the TTL the same handshake still works.
        let nonce2 = q.challenge(a.wallet_public(), 0);
        let sig2 = a.sign(&mycellium_core::login::challenge_message(&nonce2));
        assert!(q
            .verify(&a.wallet_public(), &nonce2, &sig2, CHALLENGE_TTL)
            .is_ok());
    }

    #[test]
    fn malformed_deposit_targets_are_rejected() {
        let mut q = Queue::new();
        let a = Identity::generate(&mut P(9)).unwrap();
        let b = Identity::generate(&mut P(10)).unwrap();
        let token = login(&mut q, &a);
        let bob_hex = hex33(&b.wallet_public().0);
        // A too-short wallet hex names no real mailbox.
        assert_eq!(
            q.deposit(&token, "abc", ACCOUNT_SLOT, "x".into(), 0),
            Err(ApiError::BadRequest)
        );
        // An oversized / non-hex slot can't mint a sparse mailbox.
        let huge = "z".repeat(10_000);
        assert_eq!(
            q.deposit(&token, &bob_hex, &huge, "x".into(), 0),
            Err(ApiError::BadRequest)
        );
        assert!(
            q.mailboxes.is_empty(),
            "no mailbox created for malformed targets"
        );
        // A well-formed target still works.
        assert!(q
            .deposit(&token, &bob_hex, ACCOUNT_SLOT, "x".into(), 0)
            .is_ok());
    }

    #[test]
    fn expired_challenges_are_pruned() {
        let mut q = Queue::new();
        let a = Identity::generate(&mut P(8)).unwrap();
        let _ = q.challenge(a.wallet_public(), 0);
        assert_eq!(q.challenges.len(), 1);
        // Issuing a new challenge past the TTL prunes the stale one first.
        let _ = q.challenge(a.wallet_public(), CHALLENGE_TTL + 1);
        assert_eq!(q.challenges.len(), 1, "the expired challenge was pruned");
    }

    #[test]
    fn deposit_then_owner_collects_by_wallet() {
        let mut q = Queue::new();
        let alice = Identity::generate(&mut P(1)).unwrap();
        let bob = Identity::generate(&mut P(90)).unwrap();
        let bob_hex = hex33(&bob.wallet_public().0);

        let alice_token = login(&mut q, &alice);
        q.deposit(&alice_token, &bob_hex, ACCOUNT_SLOT, "sealed".into(), 0)
            .unwrap();

        // A non-owner can't collect Bob's mailbox.
        let alice_hex = hex33(&alice.wallet_public().0);
        assert_eq!(
            q.collect(&alice_token, &alice_hex, ACCOUNT_SLOT, 0)
                .unwrap(),
            Vec::<String>::new()
        );

        // Bob collects his own, then it's drained.
        let bob_token = login(&mut q, &bob);
        assert_eq!(
            q.collect(&bob_token, &bob_hex, ACCOUNT_SLOT, 0).unwrap(),
            vec!["sealed".to_string()]
        );
        assert_eq!(
            q.collect(&bob_token, &bob_hex, ACCOUNT_SLOT, 0).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn deposits_are_rate_limited() {
        let mut q = Queue::new();
        let alice = Identity::generate(&mut P(1)).unwrap();
        let bob_hex = hex33(&Identity::generate(&mut P(90)).unwrap().wallet_public().0);
        let token = login(&mut q, &alice);
        for _ in 0..DEPOSIT_RATE_LIMIT {
            q.deposit(&token, &bob_hex, ACCOUNT_SLOT, "x".into(), 0)
                .unwrap();
        }
        assert_eq!(
            q.deposit(&token, &bob_hex, ACCOUNT_SLOT, "x".into(), 0),
            Err(ApiError::RateLimited)
        );
        assert!(q
            .deposit(&token, &bob_hex, ACCOUNT_SLOT, "x".into(), RATE_WINDOW)
            .is_ok());
    }

    #[test]
    fn push_endpoints_to_internal_hosts_are_rejected_at_subscribe() {
        // Fix 1 (SSRF): before the fix these all passed the HTTPS-prefix check and
        // were stored, so a later deposit's fan-out would POST to them. Now the
        // internal-host guard rejects literal-IP / metadata / loopback endpoints
        // at subscribe time, while a normal public host is still accepted.
        for bad in [
            "https://169.254.169.254/x", // cloud metadata (link-local)
            "https://127.0.0.1/x",       // loopback
            "https://[::1]/x",           // IPv6 loopback
            "https://10.0.0.5/x",        // private 10/8
            "https://metadata.google.internal/x",
        ] {
            assert!(
                !is_push_endpoint(bad),
                "expected internal endpoint {bad} to be rejected"
            );
        }
        // A non-internal public-looking HTTPS host is still a valid endpoint.
        assert!(is_push_endpoint("https://push.example.com/abc"));

        // End-to-end through subscribe(): an internal endpoint is a BadRequest and
        // never enters the subs map.
        let mut q = Queue::new();
        let a = Identity::generate(&mut P(31)).unwrap();
        let token = login(&mut q, &a);
        let hex = hex33(&a.wallet_public().0);
        assert_eq!(
            q.subscribe(&token, web("https://127.0.0.1:2379/x"), 0),
            Err(ApiError::BadRequest)
        );
        assert_eq!(
            q.subscribe(&token, web("https://169.254.169.254/latest/meta-data/"), 0),
            Err(ApiError::BadRequest)
        );
        assert!(q.subscriptions(&hex).is_empty());
        // A legit endpoint still subscribes.
        assert!(q
            .subscribe(&token, web("https://push.example.com/ok"), 0)
            .is_ok());
    }

    #[test]
    fn deposit_is_capped_at_the_global_mailbox_ceiling() {
        // Fix 2: before the fix, deposits to unbounded distinct recipients each
        // minted a durable mailbox with no global cap. Now, at the ceiling, a
        // deposit that would create a NEW mailbox is refused, while a deposit into
        // an already-existing mailbox still succeeds.
        let mut q = Queue::new();
        let alice = Identity::generate(&mut P(41)).unwrap();
        let token = login(&mut q, &alice);

        // Seed the map to exactly the ceiling with distinct mailboxes (directly,
        // to stay off the per-sender rate limit and keep the test fast). One of
        // these, `existing_hex`, we'll deposit into again below.
        let existing = Identity::generate(&mut P(200)).unwrap();
        let existing_hex = hex33(&existing.wallet_public().0);
        q.mailboxes.insert(
            (existing_hex.clone(), ACCOUNT_SLOT.to_string()),
            vec!["seed".into()],
        );
        for i in 1..MAX_MAILBOXES {
            // 66-char lowercase-hex wallet keys, all distinct.
            let w = format!("{i:066x}");
            q.mailboxes
                .insert((w, ACCOUNT_SLOT.to_string()), Vec::new());
        }
        assert_eq!(q.mailboxes.len(), MAX_MAILBOXES);

        // A deposit that would mint a brand-new mailbox is refused at capacity.
        let newcomer = Identity::generate(&mut P(201)).unwrap();
        let newcomer_hex = hex33(&newcomer.wallet_public().0);
        assert_eq!(
            q.deposit(&token, &newcomer_hex, ACCOUNT_SLOT, "x".into(), 0),
            Err(ApiError::Capacity),
        );
        // ...and no new mailbox was created.
        assert_eq!(q.mailboxes.len(), MAX_MAILBOXES);

        // A deposit into an already-existing mailbox still succeeds at capacity.
        assert!(q
            .deposit(&token, &existing_hex, ACCOUNT_SLOT, "y".into(), 0)
            .is_ok());
    }

    #[test]
    fn challenge_map_is_bounded_under_a_flood() {
        // Fix 3: challenge() is unauthenticated; before the fix, only TTL pruning
        // bounded it, so a burst of fresh challenges at one instant grew the map
        // without limit. Now the map stays at the ceiling by evicting the oldest.
        let mut q = Queue::new();
        let a = Identity::generate(&mut P(51)).unwrap();
        // Issue well past the ceiling at a fixed clock (so TTL never fires).
        for _ in 0..MAX_CHALLENGES + 25 {
            let _ = q.challenge(a.wallet_public(), 0);
        }
        assert!(
            q.challenges.len() <= MAX_CHALLENGES,
            "challenge map must stay bounded (was {})",
            q.challenges.len()
        );
    }

    /// End-to-end proof of the UnifiedPush push path (#71): a deposit through the
    /// **running queue server** fans out a **contentless** wake POST to a mock
    /// UnifiedPush distributor, and a distributor that reports `410 Gone` has its
    /// subscription pruned. This exercises the *real* `push::unifiedpush_send` (via
    /// the deposit handler's fan-out), not a stub — if delivery breaks, the mock
    /// never sees the POST and the poll below times out, so the test fails
    /// (non-vacuous: pointing the sub at a dead port yields `Failed`, no request is
    /// recorded, and this assertion fails).
    #[test]
    fn deposit_wakes_unifiedpush_contentless_end_to_end() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::time::{Duration, Instant};

        // A one-shot mock UnifiedPush distributor: accept one connection, record
        // the request's (method, path, body length), reply `status_line`, exit.
        #[derive(Clone, Debug)]
        struct Hit {
            method: String,
            path: String,
            body_len: usize,
        }
        fn spawn_mock(status_line: &'static str) -> (String, Arc<Mutex<Option<Hit>>>) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}/up", listener.local_addr().unwrap());
            let slot: Arc<Mutex<Option<Hit>>> = Arc::new(Mutex::new(None));
            let out = slot.clone();
            std::thread::spawn(move || {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 512];
                // Read until the header terminator, then the declared body.
                let head_end = loop {
                    match stream.read(&mut tmp) {
                        Ok(0) | Err(_) => break None,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break Some(p);
                            }
                        }
                    }
                };
                if let Some(p) = head_end {
                    let head = String::from_utf8_lossy(&buf[..p]).into_owned();
                    let content_length = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    let body_start = p + 4;
                    while buf.len() - body_start < content_length {
                        match stream.read(&mut tmp) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    let mut first = head.lines().next().unwrap_or("").split_whitespace();
                    let method = first.next().unwrap_or("").to_string();
                    let path = first.next().unwrap_or("").to_string();
                    *out.lock().unwrap() = Some(Hit {
                        method,
                        path,
                        body_len: buf.len() - body_start,
                    });
                }
                let _ = stream.write_all(status_line.as_bytes());
                let _ = stream.flush();
            });
            (url, slot)
        }

        // Poll `f` until it yields `Some`, or give up after `within`.
        fn poll<T>(mut f: impl FnMut() -> Option<T>, within: Duration) -> Option<T> {
            let deadline = Instant::now() + within;
            loop {
                if let Some(v) = f() {
                    return Some(v);
                }
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        // Two mock distributors: one healthy (200 → the contentless wake lands),
        // one that reports the endpoint gone (410 → the sub must be pruned).
        let (good_url, good_hit) =
            spawn_mock("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let (gone_url, _gone_hit) =
            spawn_mock("HTTP/1.1 410 Gone\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

        // These mocks live on loopback, which the SSRF guard blocks by default.
        // Register them as operator-allowlisted internal distributors (exact
        // host:port) so the *delivery* path can reach them — mirroring an operator
        // self-hosting a UnifiedPush distributor on an internal address. Subscribe
        // stays strict; these subs are seeded directly below.
        let push_allow_hosts: Vec<String> = [&good_url, &gone_url]
            .into_iter()
            .filter_map(|url| {
                let (_, authority) = url.split_once("://")?;
                Some(authority.split('/').next().unwrap_or(authority).to_string())
            })
            .collect();

        // A shared queue the routes mutate and the test can seed/inspect.
        let queue = Arc::new(Mutex::new(Queue::new()));
        let alice = Identity::generate(&mut P(1)).unwrap();
        let bob = Identity::generate(&mut P(90)).unwrap();
        let bob_hex = hex33(&bob.wallet_public().0);

        // Log Alice in on the shared queue with the real clock (so the token the
        // HTTP deposit presents is valid), and seed Bob's UnifiedPush subs
        // directly: the mock is plain-http, which `/push/subscribe`'s HTTPS check
        // rightly rejects, so we install the subs behind it to drive the delivery
        // path itself.
        let now = now_secs();
        let atoken = {
            let mut g = queue.lock().unwrap();
            let nonce = g.challenge(alice.wallet_public(), now);
            let sig = alice.sign(&mycellium_core::login::challenge_message(&nonce));
            let t = g.verify(&alice.wallet_public(), &nonce, &sig, now).unwrap();
            g.subs.insert(
                bob_hex.clone(),
                vec![
                    Subscription::UnifiedPush {
                        endpoint: good_url.clone(),
                    },
                    Subscription::UnifiedPush {
                        endpoint: gone_url.clone(),
                    },
                ],
            );
            t
        };

        // Bind a free port, then start the real async queue server over the handle.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr = format!("127.0.0.1:{port}");
        let serve_addr = addr.clone();
        let served = queue.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            rt.block_on(async {
                let _ = serve_with(
                    &serve_addr,
                    served,
                    ServeConfig {
                        push_allow_hosts,
                        ..ServeConfig::dev()
                    },
                )
                .await;
            });
        });
        assert!(
            poll(
                || TcpStream::connect(&addr).ok().map(|_| ()),
                Duration::from_secs(5)
            )
            .is_some(),
            "queue server never came up"
        );

        // Deposit through the running server → the handler's fan-out wakes Bob's
        // subscriptions off-thread.
        let resp = ureq::post(&format!("http://{addr}/mailbox/{bob_hex}/account"))
            .set("Authorization", &format!("Bearer {atoken}"))
            .send_string("sealed-envelope");
        assert!(resp.is_ok(), "deposit failed: {resp:?}");

        // The healthy distributor received a POST with an EMPTY body (contentless).
        let hit = poll(|| good_hit.lock().unwrap().clone(), Duration::from_secs(5))
            .expect("UnifiedPush distributor never received the wake — delivery is broken");
        assert_eq!(hit.method, "POST", "the wake must be a POST");
        assert_eq!(hit.path, "/up", "the wake must hit the endpoint path");
        assert_eq!(
            hit.body_len, 0,
            "the UnifiedPush wake MUST be contentless (empty body)"
        );

        // Bonus: the 410 endpoint is reported Gone, so its sub is pruned e2e, while
        // the healthy sub survives the prune.
        let pruned = poll(
            || {
                let subs = queue.lock().unwrap().subscriptions(&bob_hex);
                let gone_present = subs.iter().any(|s| {
                    matches!(s, Subscription::UnifiedPush { endpoint } if *endpoint == gone_url)
                });
                (!gone_present).then_some(subs)
            },
            Duration::from_secs(5),
        )
        .expect("the 410 UnifiedPush sub was never pruned");
        assert!(
            pruned.iter().any(
                |s| matches!(s, Subscription::UnifiedPush { endpoint } if *endpoint == good_url)
            ),
            "the healthy UnifiedPush sub must remain after pruning the gone one"
        );
    }
}
