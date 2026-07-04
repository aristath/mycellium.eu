//! HTTP shell over [`Directory`] (Layer 8.4).
//!
//! Endpoints:
//! - `POST /login/challenge`  `{wallet}`                 → `{nonce}`
//! - `POST /login/verify`     `{wallet,nonce,signature}` → `{token}`
//! - `PUT  /records/{handle}` (Bearer) `SignedRecord`    → 200
//! - `GET  /records/{handle}`                            → `SignedRecord` | 404
//! - `GET  /health`                                      → `ok`
//!
//! The offline mailbox now lives in a separate service (`mycellium-queue`).
//!
//! Deliberately minimal: all real logic and rules live in [`Directory`].

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tiny_http::{Header, Method, Request, Response, Server};

use std::io::Read;

use mycellium_observe::Metrics;

/// Largest request body the directory will buffer (records are a few KB; this is
/// generous headroom). Anything larger is refused with 413.
const MAX_BODY: usize = 256 * 1024;

use mycellium_core::identity::{Handle, Signature, WalletPublicKey};
use mycellium_core::record::SignedRecord;

use crate::{ApiError, Directory};

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
struct Presence {
    online: bool,
}

#[derive(Deserialize)]
struct AuthStartReq {
    username: String,
    email: String,
}

#[derive(Deserialize)]
struct AuthConfirmReq {
    pending: String,
    code: String,
}

#[derive(Deserialize)]
struct AuthStatusReq {
    pending: String,
}

/// Collapse id-bearing path segments to a route template, so access logs record
/// *which* endpoint was hit but never the specific handle that was looked up
/// (social-graph metadata). Fixed routes (login, auth, metrics) log verbatim.
fn redact_path(path: &str) -> String {
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
    match segs.as_slice() {
        ["records", _] => "/records/:handle".to_string(),
        ["presence", _] => "/presence/:handle".to_string(),
        _ => path.to_string(),
    }
}

/// Current wall-clock time in whole seconds (for presence TTL).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Bind `addr` and serve the directory until the process ends.
pub fn serve(addr: &str) -> std::io::Result<()> {
    let server = Arc::new(bind_server(addr)?);
    let directory = Arc::new(Mutex::new(open_directory()));
    let metrics = Arc::new(Metrics::default());

    // A worker pool so many clients are served concurrently, not one-at-a-time
    // (Tier 0.2). tiny_http's `recv` is safe to call from multiple threads.
    let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 32);
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let server = Arc::clone(&server);
        let directory = Arc::clone(&directory);
        let metrics = Arc::clone(&metrics);
        handles.push(std::thread::spawn(move || {
            while let Ok(request) = server.recv() {
                handle_request(&directory, &metrics, request);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// Bind an HTTP or HTTPS server. TLS is enabled when both `MYCELLIUM_TLS_CERT`
/// and `MYCELLIUM_TLS_KEY` point at PEM files; otherwise plain HTTP (typically
/// behind a TLS-terminating reverse proxy — see docs/DEPLOY.md).
fn bind_server(addr: &str) -> std::io::Result<Server> {
    let to_io = |e: Box<dyn std::error::Error + Send + Sync>| std::io::Error::other(e.to_string());
    match (env_str("MYCELLIUM_TLS_CERT"), env_str("MYCELLIUM_TLS_KEY")) {
        (Some(cert), Some(key)) => {
            let config = tiny_http::SslConfig { certificate: std::fs::read(&cert)?, private_key: std::fs::read(&key)? };
            println!("  tls: enabled ({cert})");
            Server::https(addr, config).map_err(to_io)
        }
        _ => {
            println!("  tls: disabled (set MYCELLIUM_TLS_CERT + MYCELLIUM_TLS_KEY, or terminate at a proxy)");
            Server::http(addr).map_err(to_io)
        }
    }
}

fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

/// Open the directory durably from `MYCELLIUM_DATA` (a data *directory*; we use
/// `directory.redb` inside it), falling back to in-memory.
fn open_directory() -> Directory {
    match std::env::var("MYCELLIUM_DATA") {
        Ok(dir) if !dir.is_empty() => {
            let _ = std::fs::create_dir_all(&dir);
            let path = format!("{}/directory.redb", dir.trim_end_matches('/'));
            match Directory::open(&path) {
                Ok(directory) => {
                    println!("  persistence: {path}");
                    directory
                }
                Err(e) => {
                    eprintln!("  persistence open failed ({e}); using in-memory");
                    Directory::new()
                }
            }
        }
        _ => {
            println!("  storage: in-memory (set MYCELLIUM_DATA to persist)");
            Directory::new()
        }
    }
}

fn handle_request(directory: &Mutex<Directory>, metrics: &Metrics, mut request: Request) {
    let start = std::time::Instant::now();
    let method = request.method().clone();

    // CORS: the browser PWA is served from a different origin than this API, so
    // answer preflight and tag every response with permissive CORS headers.
    if method == Method::Options {
        let mut resp = Response::empty(204);
        for h in cors_headers() {
            resp.add_header(h);
        }
        let _ = request.respond(resp);
        return;
    }

    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("").to_string();
    // Routing uses the real `path`; logging uses a redacted template so access
    // logs never carry the specific handle that was looked up (only the route).
    let log_path = redact_path(&path);

    // Operational metrics (Prometheus text). Open, no auth.
    if method == Method::Get && path == "/metrics" {
        metrics.record(200);
        let resp = Response::from_string(metrics.render("directory"))
            .with_header(Header::from_bytes(&b"Content-Type"[..], &b"text/plain; version=0.0.4"[..]).unwrap());
        let _ = request.respond(resp);
        return;
    }

    // Reject oversized bodies before buffering them (memory-DoS defense). The
    // Content-Length check is a fast path; we then read one byte *past* the cap so
    // a missing or lying Content-Length can't slip an over-cap body through by
    // truncation — if that extra byte materializes, it's 413.
    let over_cap = request.body_length().map(|n| n > MAX_BODY).unwrap_or(false);
    let token = bearer_token(&request);
    let mut buf = Vec::new();
    {
        let mut limited = std::io::Read::take(request.as_reader(), MAX_BODY as u64 + 1);
        let _ = limited.read_to_end(&mut buf);
    }
    if over_cap || buf.len() > MAX_BODY {
        metrics.record(413);
        mycellium_observe::access_log("directory", method.as_str(), &log_path, 413, start.elapsed().as_millis());
        let mut resp = Response::from_string(error_json("payload too large")).with_status_code(413).with_header(json_header());
        for h in cors_headers() {
            resp.add_header(h);
        }
        let _ = request.respond(resp);
        return;
    }
    let body = String::from_utf8_lossy(&buf).into_owned();

    let (code, json) = match route(directory, &method, &path, token.as_deref(), &body) {
        Ok((code, json)) => (code, json),
        Err(err) => (err.status(), error_json(err.reason())),
    };
    metrics.record(code);
    mycellium_observe::access_log("directory", method.as_str(), &log_path, code, start.elapsed().as_millis());
    let mut response = Response::from_string(json).with_status_code(code).with_header(json_header());
    for h in cors_headers() {
        response.add_header(h);
    }
    let _ = request.respond(response);
}

/// Permissive CORS headers so the browser-served PWA can call this API.
fn cors_headers() -> Vec<Header> {
    [
        (&b"Access-Control-Allow-Origin"[..], &b"*"[..]),
        (&b"Access-Control-Allow-Methods"[..], &b"GET, POST, PUT, DELETE, OPTIONS"[..]),
        (&b"Access-Control-Allow-Headers"[..], &b"Authorization, Content-Type"[..]),
    ]
    .iter()
    .filter_map(|(k, v)| Header::from_bytes(*k, *v).ok())
    .collect()
}

/// Dispatch one request. Returns `(status, json_body)`.
fn route(
    directory: &Mutex<Directory>,
    method: &Method,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> Result<(u16, String), ApiError> {
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();

    match (method, segments.as_slice()) {
        (Method::Get, ["health"]) => Ok((200, "\"ok\"".into())),

        (Method::Post, ["login", "challenge"]) => {
            let req: ChallengeReq = parse(body)?;
            let nonce = directory.lock().unwrap().challenge(req.wallet, now_secs());
            Ok((200, to_json(&ChallengeResp { nonce })))
        }

        (Method::Post, ["login", "verify"]) => {
            let req: VerifyReq = parse(body)?;
            let token = directory
                .lock()
                .unwrap()
                .verify(&req.wallet, &req.nonce, &req.signature, now_secs())?;
            Ok((200, to_json(&VerifyResp { token })))
        }

        (Method::Put, ["records", handle]) => {
            let token = token.ok_or(ApiError::Unauthorized)?;
            let handle = Handle::new(*handle).map_err(|_| ApiError::HandleMismatch)?;
            let record: SignedRecord = parse(body)?;
            directory.lock().unwrap().publish(token, &handle, record, now_secs())?;
            Ok((200, "\"ok\"".into()))
        }

        (Method::Get, ["records", handle]) => {
            let handle = Handle::new(*handle).map_err(|_| ApiError::HandleMismatch)?;
            match directory.lock().unwrap().lookup(&handle) {
                Some(record) => Ok((200, to_json(record))),
                None => Ok((404, error_json("no such handle"))),
            }
        }

        // Email-verified username claim (one-tap onboarding).
        (Method::Post, ["auth", "start"]) => {
            let token = token.ok_or(ApiError::Unauthorized)?;
            let req: AuthStartReq = parse(body)?;
            let username = Handle::new(&req.username).map_err(|_| ApiError::BadRequest)?;
            let (pending, code) =
                directory.lock().unwrap().auth_start(token, &username, &req.email, now_secs())?;
            // Send the code off the lock — a slow SMTP server must never stall
            // the directory. Dev mode logs it; production emails it.
            // Send to the *canonical* address, matching what auth_start stored/hashed.
            let (email, thread_code) = (crate::normalize_email(&req.email), code.clone());
            std::thread::spawn(move || crate::mailer::send_verification(&email, &thread_code));
            // Dev mode (no SMTP) also returns the code so local flows need no inbox.
            let resp = if crate::mailer::is_dev() {
                serde_json::json!({ "pending": pending, "dev_code": code })
            } else {
                serde_json::json!({ "pending": pending })
            };
            Ok((200, resp.to_string()))
        }

        (Method::Post, ["auth", "confirm"]) => {
            let req: AuthConfirmReq = parse(body)?;
            let username = directory.lock().unwrap().auth_confirm(&req.pending, &req.code, now_secs())?;
            Ok((200, serde_json::json!({ "ok": true, "username": username.as_str() }).to_string()))
        }

        (Method::Post, ["auth", "status"]) => {
            let req: AuthStatusReq = parse(body)?;
            match directory.lock().unwrap().auth_status(&req.pending) {
                Some((verified, username)) => {
                    Ok((200, serde_json::json!({ "verified": verified, "username": username }).to_string()))
                }
                None => Err(ApiError::NotFound),
            }
        }

        // Presence: heartbeat (owner) or query (open).
        (Method::Post, ["presence", handle]) => {
            let token = token.ok_or(ApiError::Unauthorized)?;
            let handle = Handle::new(*handle).map_err(|_| ApiError::NotFound)?;
            directory.lock().unwrap().heartbeat(token, &handle, now_secs())?;
            Ok((200, "\"ok\"".into()))
        }

        (Method::Get, ["presence", handle]) => {
            let handle = Handle::new(*handle).map_err(|_| ApiError::NotFound)?;
            let online = directory.lock().unwrap().presence(&handle, now_secs());
            Ok((200, to_json(&Presence { online })))
        }

        _ => Ok((404, error_json("not found"))),
    }
}

fn parse<T: for<'de> Deserialize<'de>>(body: &str) -> Result<T, ApiError> {
    serde_json::from_str(body).map_err(|_| ApiError::InvalidRecord)
}

fn to_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("serializable response")
}

fn error_json(reason: &str) -> String {
    format!("{{\"error\":{}}}", serde_json::to_string(reason).unwrap())
}

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()
}

fn bearer_token(request: &Request) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .and_then(|h| h.value.as_str().strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::redact_path;

    #[test]
    fn access_log_paths_are_redacted() {
        // Id-bearing routes collapse to a template — no handle in the log.
        assert_eq!(redact_path("/records/deadbeefcafe"), "/records/:handle");
        assert_eq!(redact_path("/presence/deadbeefcafe"), "/presence/:handle");
        // Fixed routes log verbatim (no identifier to leak).
        assert_eq!(redact_path("/login/verify"), "/login/verify");
        assert_eq!(redact_path("/metrics"), "/metrics");
    }
}
