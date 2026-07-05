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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod persist;
mod push;

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
            ApiError::BadRequest => "malformed request",
            ApiError::Storage => "storage write failed",
        }
    }
}

/// Maximum number of queued messages per (wallet, slot) mailbox.
pub const MAX_MAILBOX: usize = 256;

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

/// Web Push endpoints kept per wallet. Generous for a multi-device account;
/// the oldest is evicted past this, so the list (and per-deposit fan-out) is
/// bounded no matter how many endpoints a client registers.
pub const MAX_SUBS_PER_WALLET: usize = 20;

/// Largest push-endpoint URL accepted (they're short HTTPS URLs in practice).
pub const MAX_ENDPOINT_LEN: usize = 2048;

/// How long a pairing rendezvous slot lives (5 minutes) before it's pruned.
pub const PAIR_TTL: u64 = 300;
/// Max relayed messages per rendezvous id (bounds a griefer who knows the id).
pub const PAIR_MAX: usize = 8;
/// Max concurrent rendezvous slots, bounding memory.
pub const MAX_RENDEZVOUS: usize = 10_000;
/// Largest single pairing message accepted (base64 of a small sealed payload).
pub const MAX_PAIR_MSG: usize = 8192;

/// The in-memory queue state (POC). A real deployment swaps the maps for a
/// durable store; the logic is unchanged.
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
    /// Web Push subscriptions: recipient wallet hex → browser push endpoints.
    subs: HashMap<String, Vec<String>>,
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

    /// Register a browser push endpoint for the logged-in wallet (idempotent).
    pub fn subscribe(&mut self, token: &str, endpoint: String, now: u64) -> Result<(), ApiError> {
        let wallet = self.authed(token, now)?;
        if !is_push_endpoint(&endpoint) {
            return Err(ApiError::BadRequest);
        }
        let wallet_hex = hex33(&wallet.0);
        let list = self.subs.entry(wallet_hex.clone()).or_default();
        if !list.contains(&endpoint) {
            list.push(endpoint);
            // Cap per wallet by evicting the oldest, so a device rotating its
            // endpoint doesn't wedge the list and a client can't grow it forever.
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

    /// Remove a push endpoint for the logged-in wallet (explicit unsubscribe).
    pub fn unsubscribe(&mut self, token: &str, endpoint: &str, now: u64) -> Result<(), ApiError> {
        let wallet = self.authed(token, now)?;
        let wallet_hex = hex33(&wallet.0);
        if let Some(list) = self.subs.get_mut(&wallet_hex) {
            let before = list.len();
            list.retain(|e| e != endpoint);
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

    /// Drop endpoints a push service reported as gone (404/410). Called off the
    /// request path after a deposit's fan-out, so dead endpoints don't linger and
    /// waste a POST on every future deposit.
    pub fn remove_endpoints(&mut self, wallet_hex: &str, gone: &[String]) {
        if let Some(list) = self.subs.get_mut(wallet_hex) {
            let before = list.len();
            list.retain(|e| !gone.contains(e));
            if list.len() != before {
                if let Some(store) = &self.store {
                    let _ = store.put_subs(wallet_hex, list);
                }
            }
        }
    }

    /// The push endpoints registered for a recipient wallet.
    pub fn subscriptions(&self, wallet_hex: &str) -> Vec<String> {
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

/// Both pieces of shared state the queue handlers need. axum threads a single
/// `State` type, so the queue and its VAPID keypair travel together.
#[derive(Clone)]
pub struct QueueState {
    queue: Arc<Mutex<Queue>>,
    vapid: Arc<push::Vapid>,
}

/// Bind `addr` and serve the queue until a shutdown signal arrives.
pub async fn serve(addr: &str) -> std::io::Result<()> {
    let queue = Arc::new(Mutex::new(open_queue()?));
    let vapid = Arc::new(load_or_generate_vapid());
    println!("  push: VAPID enabled");
    let state = QueueState { queue, vapid };
    mycellium_serve::Server::new("queue", MAX_BODY)
        .run(addr, router(state))
        .await
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

/// Open the queue durably from `MYCELLIUM_DATA` (a data *directory*; we use
/// `queue.redb` inside it). Setting `MYCELLIUM_DATA` expresses durable intent, so
/// if the store can't be opened we **fail closed** rather than silently drop to
/// in-memory (which would look healthy while mail/subscriptions don't persist —
/// issue #45). No `MYCELLIUM_DATA` is the explicit in-memory development mode.
fn open_queue() -> std::io::Result<Queue> {
    let data = std::env::var("MYCELLIUM_DATA")
        .ok()
        .filter(|d| !d.is_empty());
    open_queue_at(data.as_deref())
}

/// The env-free core of [`open_queue`], so the three startup modes are testable.
fn open_queue_at(data: Option<&str>) -> std::io::Result<Queue> {
    match data {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            let path = format!("{}/queue.redb", dir.trim_end_matches('/'));
            let queue = Queue::open(&path).map_err(|e| {
                std::io::Error::other(format!(
                    "MYCELLIUM_DATA is set but the durable store at {path} could not be opened: {e}"
                ))
            })?;
            println!("  persistence: {path}");
            Ok(queue)
        }
        None => {
            println!("  storage: in-memory (set MYCELLIUM_DATA to persist)");
            Ok(Queue::new())
        }
    }
}

/// Load the VAPID keypair from `MYCELLIUM_DATA/vapid.key`, or generate one and
/// persist it there (0600) so browser push subscriptions survive restarts.
/// Without `MYCELLIUM_DATA`, use an ephemeral keypair (dev).
fn load_or_generate_vapid() -> push::Vapid {
    let dir = match std::env::var("MYCELLIUM_DATA") {
        Ok(d) if !d.trim().is_empty() => d,
        _ => return push::Vapid::generate(),
    };
    let _ = std::fs::create_dir_all(&dir);
    let path = format!("{}/vapid.key", dir.trim_end_matches('/'));
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(seed) = <[u8; 32]>::try_from(bytes.as_slice()) {
            if let Some(v) = push::Vapid::from_seed(&seed) {
                println!("  push: VAPID key loaded ({path})");
                return v;
            }
        }
        eprintln!("  push: {path} is unreadable; regenerating");
    }
    let v = push::Vapid::generate();
    match std::fs::write(&path, v.seed()) {
        Ok(()) => {
            restrict_perms(&path);
            println!("  push: VAPID key generated + persisted ({path})");
        }
        Err(e) => eprintln!("  push: could not persist VAPID key ({e}); it will change on restart"),
    }
    v
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
        .subscribe(token, req.endpoint, now_secs())?;
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
        .unsubscribe(token, &req.endpoint, now_secs())?;
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
    // slow push endpoint never stalls the queue.
    let endpoints = st.queue.lock().unwrap().subscriptions(&wallet);
    if !endpoints.is_empty() {
        let vapid = Arc::clone(&st.vapid);
        let queue = Arc::clone(&st.queue);
        std::thread::spawn(move || {
            let mut gone = Vec::new();
            for endpoint in endpoints {
                if vapid.send(&endpoint, now) == push::SendResult::Gone {
                    gone.push(endpoint);
                }
            }
            // Prune subscriptions the push service says are gone, so we don't
            // POST to them on every future deposit.
            if !gone.is_empty() {
                queue.lock().unwrap().remove_endpoints(&wallet, &gone);
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
#[derive(Deserialize)]
struct SubscribeReq {
    endpoint: String,
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

/// A plausible Web Push endpoint: a bounded HTTPS URL with a host. (Requiring
/// HTTPS also keeps the queue from being pointed at plain-HTTP internal URLs.)
fn is_push_endpoint(e: &str) -> bool {
    e.len() <= MAX_ENDPOINT_LEN
        && push::origin_of(e)
            .map(|o| o.starts_with("https://"))
            .unwrap_or(false)
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
            q.subscribe(&btoken, "https://push.example/abc".into(), 0)
                .unwrap();
        } // drop → flushed

        // Reopen: the queued blob and the push subscription are both still there.
        let mut q2 = Queue::open(path_str).unwrap();
        assert_eq!(
            q2.subscriptions(&bob_hex),
            vec!["https://push.example/abc".to_string()]
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
        assert!(super::open_queue_at(None).is_ok());
        // A valid data dir → durable mode.
        let good = std::env::temp_dir().join(format!("myc-q-good-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&good);
        assert!(super::open_queue_at(Some(good.to_str().unwrap())).is_ok());
        let _ = std::fs::remove_dir_all(&good);
        // Configured but unusable (the path is a file, not a dir) → fail closed,
        // never a silent in-memory fallback.
        let bad = std::env::temp_dir().join(format!("myc-q-bad-{}", std::process::id()));
        let _ = std::fs::remove_file(&bad);
        std::fs::write(&bad, b"not a dir").unwrap();
        assert!(super::open_queue_at(Some(bad.to_str().unwrap())).is_err());
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
            .subscribe(&token, "https://push.example/ok".into(), 10)
            .is_ok());
        assert!(q.collect(&token, &bob_hex, ACCOUNT_SLOT, 10).is_ok());

        // Past TOKEN_TTL the same token is rejected for every authenticated op.
        assert_eq!(
            q.collect(&token, &bob_hex, ACCOUNT_SLOT, TOKEN_TTL + 1),
            Err(ApiError::Unauthorized),
        );
        assert_eq!(
            q.subscribe(&token, "https://push.example/late".into(), TOKEN_TTL + 1),
            Err(ApiError::Unauthorized),
        );
        assert_eq!(
            q.unsubscribe(&token, "https://push.example/ok", TOKEN_TTL + 1),
            Err(ApiError::Unauthorized),
        );
    }

    #[test]
    fn push_subscriptions_are_validated_capped_and_removable() {
        let mut q = Queue::new();
        let a = Identity::generate(&mut P(11)).unwrap();
        let token = login(&mut q, &a);
        let hex = hex33(&a.wallet_public().0);

        // Non-HTTPS / malformed endpoints are refused.
        assert_eq!(
            q.subscribe(&token, "http://insecure/x".into(), 0),
            Err(ApiError::BadRequest)
        );
        assert_eq!(
            q.subscribe(&token, "not a url".into(), 0),
            Err(ApiError::BadRequest)
        );

        // Duplicate subscribes are idempotent.
        q.subscribe(&token, "https://push.example/a".into(), 0)
            .unwrap();
        q.subscribe(&token, "https://push.example/a".into(), 0)
            .unwrap();
        assert_eq!(q.subscriptions(&hex).len(), 1);

        // The list is capped, evicting the oldest.
        for i in 0..MAX_SUBS_PER_WALLET + 5 {
            q.subscribe(&token, format!("https://push.example/{i}"), 0)
                .unwrap();
        }
        assert_eq!(q.subscriptions(&hex).len(), MAX_SUBS_PER_WALLET);

        // Explicit unsubscribe removes an endpoint.
        let e0 = q.subscriptions(&hex)[0].clone();
        q.unsubscribe(&token, &e0, 0).unwrap();
        assert!(!q.subscriptions(&hex).contains(&e0));

        // Gone-removal (the 404/410 path) drops dead endpoints.
        let e1 = q.subscriptions(&hex)[0].clone();
        q.remove_endpoints(&hex, std::slice::from_ref(&e1));
        assert!(!q.subscriptions(&hex).contains(&e1));
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
}
