//! HTTP shell over [`Directory`] (Layer 8.4).
//!
//! Endpoints:
//! - `POST /login/challenge`  `{wallet}`                 → `{nonce}`
//! - `POST /login/verify`     `{wallet,nonce,signature}` → `{token}`
//! - `PUT  /records/{handle}` (Bearer) `SignedRecord`    → 200
//! - `GET  /records/{handle}`                            → `SignedRecord` | 404
//! - `POST /mailbox/{handle}` (Bearer) `<envelope>`      → 200
//! - `GET  /mailbox/{handle}` (Bearer)                   → `{messages}`
//! - `GET  /health`                                      → `ok`
//!
//! Deliberately minimal: all real logic and rules live in [`Directory`].

use std::sync::Mutex;

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
struct Messages {
    messages: Vec<String>,
}

#[derive(Serialize)]
struct Presence {
    online: bool,
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
    let server = Server::http(addr)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrInUse, e.to_string()))?;
    let directory = Mutex::new(Directory::new());

    for mut request in server.incoming_requests() {
        let method = request.method().clone();
        let url = request.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();
        let token = bearer_token(&request);

        let mut body = String::new();
        let _ = request.as_reader().read_to_string(&mut body);

        let (code, json) = match route(&directory, &method, &path, token.as_deref(), &body) {
            Ok((code, json)) => (code, json),
            Err(err) => (err.status(), error_json(err.reason())),
        };

        let response = Response::from_string(json)
            .with_status_code(code)
            .with_header(json_header());
        let _ = request.respond(response);
    }
    Ok(())
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

        // Offline mailbox: deposit to a device slot, or drain your own slot.
        (Method::Post, ["mailbox", handle, slot]) => {
            let token = token.ok_or(ApiError::Unauthorized)?;
            let handle = Handle::new(*handle).map_err(|_| ApiError::NotFound)?;
            directory
                .lock()
                .unwrap()
                .deposit(token, &handle, slot, body.to_string(), now_secs())?;
            Ok((200, "\"ok\"".into()))
        }

        (Method::Get, ["mailbox", handle, slot]) => {
            let token = token.ok_or(ApiError::Unauthorized)?;
            let handle = Handle::new(*handle).map_err(|_| ApiError::NotFound)?;
            let messages = directory.lock().unwrap().collect(token, &handle, slot)?;
            Ok((200, to_json(&Messages { messages })))
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
