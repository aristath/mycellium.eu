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
//! [`mycellium_core::login`] contract). Deposits are open (anyone may drop an
//! opaque blob for a wallet, rate-limited); only the owning wallet may collect.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

mod persist;
mod push;

use mycellium_core::identity::{Signature, WalletPublicKey};
use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Request, Response, Server};

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

/// Deposits allowed per sender wallet per [`RATE_WINDOW`].
pub const DEPOSIT_RATE_LIMIT: u32 = 30;

/// The rate-limit window, in seconds.
pub const RATE_WINDOW: u64 = 60;

/// The in-memory queue state (POC). A real deployment swaps the maps for a
/// durable store; the logic is unchanged.
#[derive(Default)]
pub struct Queue {
    /// Outstanding login challenges: nonce → the wallet it was issued to.
    challenges: HashMap<String, WalletPublicKey>,
    /// Active sessions: token → authenticated wallet.
    tokens: HashMap<String, WalletPublicKey>,
    /// Mailboxes: (recipient wallet hex, device slot) → queued opaque blobs.
    /// The slot is a device id (targeted) or `"account"` (cluster-wide).
    mailboxes: HashMap<(String, String), Vec<String>>,
    /// Fixed-window rate counters: (wallet, action) → (window_start, count).
    rate: HashMap<([u8; 33], &'static str), (u64, u32)>,
    /// Web Push subscriptions: recipient wallet hex → browser push endpoints.
    subs: HashMap<String, Vec<String>>,
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
        wallet
            .verify(&mycellium_core::login::challenge_message(nonce), signature)
            .map_err(|_| ApiError::BadSignature)?;
        self.challenges.remove(nonce);
        let token = random_hex::<24>();
        self.tokens.insert(token.clone(), *wallet);
        Ok(token)
    }

    /// Register a browser push endpoint for the logged-in wallet (idempotent).
    pub fn subscribe(&mut self, token: &str, endpoint: String) -> Result<(), ApiError> {
        let wallet = *self.tokens.get(token).ok_or(ApiError::Unauthorized)?;
        let wallet_hex = hex33(&wallet.0);
        let list = self.subs.entry(wallet_hex.clone()).or_default();
        if !list.contains(&endpoint) {
            list.push(endpoint);
            if let Some(store) = &self.store {
                store.put_subs(&wallet_hex, list).map_err(|_| ApiError::Storage)?;
            }
        }
        Ok(())
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
        let sender = *self.tokens.get(token).ok_or(ApiError::Unauthorized)?;
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
            store.put_mailbox(recipient_wallet_hex, slot, mailbox).map_err(|_| ApiError::Storage)?;
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
    ) -> Result<Vec<String>, ApiError> {
        let caller = *self.tokens.get(token).ok_or(ApiError::Unauthorized)?;
        if hex33(&caller.0) != wallet_hex {
            return Err(ApiError::Forbidden);
        }
        let drained = self.mailboxes.remove(&(wallet_hex.to_string(), slot.to_string())).unwrap_or_default();
        if let Some(store) = &self.store {
            store.del_mailbox(wallet_hex, slot).map_err(|_| ApiError::Storage)?;
        }
        Ok(drained)
    }

    /// A fixed-window rate check for `(wallet, action)` at `now`.
    fn allow(&mut self, wallet: [u8; 33], action: &'static str, now: u64) -> bool {
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

/// Run the queue as an HTTP service on `addr` (blocks).
pub fn serve(addr: &str) -> std::io::Result<()> {
    let server = Arc::new(Server::http(addr).map_err(|e| std::io::Error::other(e.to_string()))?);
    let queue = Arc::new(Mutex::new(open_queue()));
    let vapid = Arc::new(push::Vapid::generate());
    println!("  push: VAPID enabled");

    // A worker pool so many clients are served concurrently (Tier 0.2).
    let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 32);
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let (server, queue, vapid) = (Arc::clone(&server), Arc::clone(&queue), Arc::clone(&vapid));
        handles.push(std::thread::spawn(move || {
            while let Ok(request) = server.recv() {
                handle_request(&queue, &vapid, request);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// Open the queue durably from `MYCELLIUM_DATA` (a data *directory*; we use
/// `queue.redb` inside it), falling back to in-memory.
fn open_queue() -> Queue {
    match std::env::var("MYCELLIUM_DATA") {
        Ok(dir) if !dir.is_empty() => {
            let _ = std::fs::create_dir_all(&dir);
            let path = format!("{}/queue.redb", dir.trim_end_matches('/'));
            match Queue::open(&path) {
                Ok(queue) => {
                    println!("  persistence: {path}");
                    queue
                }
                Err(e) => {
                    eprintln!("  persistence open failed ({e}); using in-memory");
                    Queue::new()
                }
            }
        }
        _ => {
            println!("  storage: in-memory (set MYCELLIUM_DATA to persist)");
            Queue::new()
        }
    }
}

fn handle_request(queue: &Mutex<Queue>, vapid: &Arc<push::Vapid>, mut request: Request) {
    let mut body = String::new();
    let _ = std::io::Read::read_to_string(request.as_reader(), &mut body);
    let token = bearer(&request);
    let (status, payload) = match route(queue, vapid, &request, &body, token.as_deref()) {
        Ok(ok) => ok,
        Err(err) => (err.status(), format!("{{\"error\":\"{}\"}}", err.reason())),
    };
    let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
    let _ = request.respond(Response::from_string(payload).with_status_code(status).with_header(header));
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

fn route(
    queue: &Mutex<Queue>,
    vapid: &Arc<push::Vapid>,
    request: &Request,
    body: &str,
    token: Option<&str>,
) -> Result<(u16, String), ApiError> {
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("");
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    let now = now_secs();

    match (request.method(), segments.as_slice()) {
        (Method::Get, ["health"]) => Ok((200, "\"ok\"".into())),

        (Method::Post, ["login", "challenge"]) => {
            let req: ChallengeReq = serde_json::from_str(body).map_err(|_| ApiError::BadRequest)?;
            let nonce = queue.lock().unwrap().challenge(req.wallet);
            Ok((200, to_json(&ChallengeResp { nonce })))
        }
        (Method::Post, ["login", "verify"]) => {
            let req: VerifyReq = serde_json::from_str(body).map_err(|_| ApiError::BadRequest)?;
            let token = queue.lock().unwrap().verify(&req.wallet, &req.nonce, &req.signature)?;
            Ok((200, to_json(&VerifyResp { token })))
        }

        (Method::Get, ["push", "key"]) => {
            Ok((200, to_json(&PushKey { key: vapid.public_key().to_string() })))
        }
        (Method::Post, ["push", "subscribe"]) => {
            let token = token.ok_or(ApiError::Unauthorized)?;
            let req: SubscribeReq = serde_json::from_str(body).map_err(|_| ApiError::BadRequest)?;
            queue.lock().unwrap().subscribe(token, req.endpoint)?;
            Ok((200, "\"ok\"".into()))
        }

        (Method::Post, ["mailbox", wallet_hex, slot]) => {
            let token = token.ok_or(ApiError::Unauthorized)?;
            queue.lock().unwrap().deposit(token, wallet_hex, slot, body.to_string(), now)?;
            // Wake the recipient's devices — contentless, and off the lock/thread
            // so a slow push endpoint never stalls the queue.
            let endpoints = queue.lock().unwrap().subscriptions(wallet_hex);
            if !endpoints.is_empty() {
                let vapid = Arc::clone(vapid);
                std::thread::spawn(move || {
                    for endpoint in endpoints {
                        let _ = vapid.send(&endpoint, now);
                    }
                });
            }
            Ok((200, "\"ok\"".into()))
        }
        (Method::Get, ["mailbox", wallet_hex, slot]) => {
            let token = token.ok_or(ApiError::Unauthorized)?;
            let messages = queue.lock().unwrap().collect(token, wallet_hex, slot)?;
            Ok((200, to_json(&Messages { messages })))
        }

        _ => Err(ApiError::BadRequest),
    }
}

fn bearer(request: &Request) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .and_then(|h| h.value.as_str().strip_prefix("Bearer ").map(str::to_string))
}

fn to_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".into())
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
        let nonce = q.challenge(id.wallet_public());
        let sig = id.sign(&mycellium_core::login::challenge_message(&nonce));
        q.verify(&id.wallet_public(), &nonce, &sig).unwrap()
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
            q.deposit(&atoken, &bob_hex, "s", "sealed".into(), 0).unwrap();
            let btoken = login(&mut q, &bob);
            q.subscribe(&btoken, "https://push.example/abc".into()).unwrap();
        } // drop → flushed

        // Reopen: the queued blob and the push subscription are both still there.
        let mut q2 = Queue::open(path_str).unwrap();
        assert_eq!(q2.subscriptions(&bob_hex), vec!["https://push.example/abc".to_string()]);
        let btoken = login(&mut q2, &bob);
        assert_eq!(q2.collect(&btoken, &bob_hex, "s").unwrap(), vec!["sealed".to_string()]);
        // ...and after collecting, the drain is persisted (empty on next reopen).
        drop(q2);
        let mut q3 = Queue::open(path_str).unwrap();
        let btoken2 = login(&mut q3, &bob);
        assert!(q3.collect(&btoken2, &bob_hex, "s").unwrap().is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn deposit_then_owner_collects_by_wallet() {
        let mut q = Queue::new();
        let alice = Identity::generate(&mut P(1)).unwrap();
        let bob = Identity::generate(&mut P(90)).unwrap();
        let bob_hex = hex33(&bob.wallet_public().0);

        let alice_token = login(&mut q, &alice);
        q.deposit(&alice_token, &bob_hex, "s", "sealed".into(), 0).unwrap();

        // A non-owner can't collect Bob's mailbox.
        let alice_hex = hex33(&alice.wallet_public().0);
        assert_eq!(q.collect(&alice_token, &alice_hex, "s").unwrap(), Vec::<String>::new());

        // Bob collects his own, then it's drained.
        let bob_token = login(&mut q, &bob);
        assert_eq!(q.collect(&bob_token, &bob_hex, "s").unwrap(), vec!["sealed".to_string()]);
        assert_eq!(q.collect(&bob_token, &bob_hex, "s").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn deposits_are_rate_limited() {
        let mut q = Queue::new();
        let alice = Identity::generate(&mut P(1)).unwrap();
        let bob_hex = hex33(&Identity::generate(&mut P(90)).unwrap().wallet_public().0);
        let token = login(&mut q, &alice);
        for _ in 0..DEPOSIT_RATE_LIMIT {
            q.deposit(&token, &bob_hex, "s", "x".into(), 0).unwrap();
        }
        assert_eq!(q.deposit(&token, &bob_hex, "s", "x".into(), 0), Err(ApiError::RateLimited));
        assert!(q.deposit(&token, &bob_hex, "s", "x".into(), RATE_WINDOW).is_ok());
    }
}
