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

/// Current wall-clock time in whole seconds (for presence TTL).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Bind `addr` and serve the directory until the process ends.
pub fn serve(addr: &str) -> std::io::Result<()> {
    let server = Arc::new(
        Server::http(addr).map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrInUse, e.to_string()))?,
    );
    let directory = Arc::new(Mutex::new(open_directory()));

    // A worker pool so many clients are served concurrently, not one-at-a-time
    // (Tier 0.2). tiny_http's `recv` is safe to call from multiple threads.
    let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 32);
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let server = Arc::clone(&server);
        let directory = Arc::clone(&directory);
        handles.push(std::thread::spawn(move || {
            while let Ok(request) = server.recv() {
                handle_request(&directory, request);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// Open the directory durably from `MYCELLIUM_DATA`, falling back to in-memory.
fn open_directory() -> Directory {
    match std::env::var("MYCELLIUM_DATA") {
        Ok(path) if !path.is_empty() => match Directory::open(&path) {
            Ok(dir) => {
                println!("  persistence: {path}");
                dir
            }
            Err(e) => {
                eprintln!("  persistence open failed ({e}); using in-memory");
                Directory::new()
            }
        },
        _ => {
            println!("  storage: in-memory (set MYCELLIUM_DATA to persist)");
            Directory::new()
        }
    }
}

fn handle_request(directory: &Mutex<Directory>, mut request: Request) {
    let method = request.method().clone();
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("").to_string();
    let token = bearer_token(&request);

    let mut body = String::new();
    let _ = request.as_reader().read_to_string(&mut body);

    let (code, json) = match route(directory, &method, &path, token.as_deref(), &body) {
        Ok((code, json)) => (code, json),
        Err(err) => (err.status(), error_json(err.reason())),
    };
    let response = Response::from_string(json).with_status_code(code).with_header(json_header());
    let _ = request.respond(response);
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
            let nonce = directory.lock().unwrap().challenge(req.wallet);
            Ok((200, to_json(&ChallengeResp { nonce })))
        }

        (Method::Post, ["login", "verify"]) => {
            let req: VerifyReq = parse(body)?;
            let token = directory
                .lock()
                .unwrap()
                .verify(&req.wallet, &req.nonce, &req.signature)?;
            Ok((200, to_json(&VerifyResp { token })))
        }

        (Method::Put, ["records", handle]) => {
            let token = token.ok_or(ApiError::Unauthorized)?;
            let handle = Handle::new(*handle).map_err(|_| ApiError::HandleMismatch)?;
            let record: SignedRecord = parse(body)?;
            directory.lock().unwrap().publish(token, &handle, record)?;
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
            // Dev mode (no SMTP configured) surfaces the code so the flow works
            // locally; production emails it and returns only the pending token.
            let dev = std::env::var("MYCELLIUM_DEV_EMAIL").map(|v| v != "0").unwrap_or(true);
            let resp = if dev {
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
