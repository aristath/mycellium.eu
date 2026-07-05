//! HTTP shell over [`Directory`] (Layer 8.4).
//!
//! Endpoints:
//! - `POST /login/challenge`  `{wallet}`                 → `{nonce}`
//! - `POST /login/verify`     `{wallet,nonce,signature}` → `{token}`
//! - `POST /auth/{start,confirm,status}`                 → email-verified claim
//! - `PUT  /records/{handle}` (Bearer) `SignedRecord`    → 200
//! - `GET  /records/{handle}`                            → `SignedRecord` | 404
//! - `POST /presence/{handle}` (Bearer)                  → heartbeat
//! - `GET  /presence/{handle}`                           → `{online}`
//!
//! `/health` and `/metrics` are added by [`mycellium_serve`]. The offline mailbox
//! lives in a separate service (`mycellium-queue`).
//!
//! Deliberately minimal: all real logic and rules live in [`Directory`]. The
//! serving concern (TLS, CORS, body limits, redacted access logs, graceful
//! shutdown) is shared through `mycellium-serve`.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use mycellium_core::identity::{Handle, Signature, WalletPublicKey};
use mycellium_core::record::SignedRecord;

use crate::{ApiError, Directory};

/// Largest request body the directory will buffer (records are a few KB; this is
/// generous headroom). Anything larger is refused with 413 by the runtime.
const MAX_BODY: usize = 256 * 1024;

/// Shared, mutex-guarded directory state. The core is synchronous and its
/// critical sections are short (in-memory maps + fast redb writes), so a single
/// mutex serializes access without the async runtime ever blocking meaningfully.
type AppState = Arc<Mutex<Directory>>;

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

/// Bind `addr` and serve the directory until a shutdown signal arrives.
pub async fn serve(addr: &str) -> std::io::Result<()> {
    // Fail closed on an email-auth misconfiguration (no SMTP and no explicit dev
    // mode) rather than silently running the development auth path (issue #47).
    crate::mailer::require_valid_config().map_err(std::io::Error::other)?;

    let directory = Arc::new(Mutex::new(open_directory()?));
    mycellium_serve::Server::new("directory", MAX_BODY)
        .run(addr, router(directory))
        .await
}

/// The directory's routes, over an already-constructed [`Directory`] state. Split
/// out so tests can mount it without the process-level startup checks.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/login/challenge", post(login_challenge))
        .route("/login/verify", post(login_verify))
        .route("/auth/start", post(auth_start))
        .route("/auth/confirm", post(auth_confirm))
        .route("/auth/status", post(auth_status))
        .route("/records/{handle}", put(put_record).get(get_record))
        .route("/presence/{handle}", post(presence_post).get(presence_get))
        .with_state(state)
}

// --- handlers ---------------------------------------------------------------

async fn login_challenge(State(dir): State<AppState>, body: String) -> Result<Response, ApiError> {
    let req: ChallengeReq = parse(&body)?;
    let nonce = dir.lock().unwrap().challenge(req.wallet, now_secs());
    Ok(Json(ChallengeResp { nonce }).into_response())
}

async fn login_verify(State(dir): State<AppState>, body: String) -> Result<Response, ApiError> {
    let req: VerifyReq = parse(&body)?;
    let token = dir
        .lock()
        .unwrap()
        .verify(&req.wallet, &req.nonce, &req.signature, now_secs())?;
    Ok(Json(VerifyResp { token }).into_response())
}

async fn put_record(
    State(dir): State<AppState>,
    Path(handle): Path<String>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, ApiError> {
    let token = bearer(&headers).ok_or(ApiError::Unauthorized)?;
    let handle = Handle::new(&handle).map_err(|_| ApiError::HandleMismatch)?;
    let record: SignedRecord = parse(&body)?;
    dir.lock()
        .unwrap()
        .publish(token, &handle, record, now_secs())?;
    Ok(ok())
}

async fn get_record(
    State(dir): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Response, ApiError> {
    let handle = Handle::new(&handle).map_err(|_| ApiError::HandleMismatch)?;
    match dir.lock().unwrap().lookup(&handle) {
        Some(record) => Ok(Json(record).into_response()),
        None => Err(ApiError::NotFound),
    }
}

// Email-verified username claim (one-tap onboarding).
async fn auth_start(
    State(dir): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response, ApiError> {
    let token = bearer(&headers).ok_or(ApiError::Unauthorized)?;
    let req: AuthStartReq = parse(&body)?;
    let username = Handle::new(&req.username).map_err(|_| ApiError::BadRequest)?;
    let (pending, code) =
        dir.lock()
            .unwrap()
            .auth_start(token, &username, &req.email, now_secs())?;
    // Send the code off the lock — a slow SMTP server must never stall the
    // directory. A detached OS thread is right here: `send_verification` is
    // blocking I/O, and it must outlive this request. Send to the *canonical*
    // address, matching what `auth_start` stored/hashed.
    let (email, thread_code) = (crate::normalize_email(&req.email), code.clone());
    std::thread::spawn(move || crate::mailer::send_verification(&email, &thread_code));
    // Dev mode (no SMTP) also returns the code so local flows need no inbox.
    let resp = if crate::mailer::is_dev() {
        serde_json::json!({ "pending": pending, "dev_code": code })
    } else {
        serde_json::json!({ "pending": pending })
    };
    Ok(Json(resp).into_response())
}

async fn auth_confirm(State(dir): State<AppState>, body: String) -> Result<Response, ApiError> {
    let req: AuthConfirmReq = parse(&body)?;
    let username = dir
        .lock()
        .unwrap()
        .auth_confirm(&req.pending, &req.code, now_secs())?;
    Ok(Json(serde_json::json!({ "ok": true, "username": username.as_str() })).into_response())
}

async fn auth_status(State(dir): State<AppState>, body: String) -> Result<Response, ApiError> {
    let req: AuthStatusReq = parse(&body)?;
    match dir.lock().unwrap().auth_status(&req.pending) {
        Some((verified, username)) => Ok(Json(
            serde_json::json!({ "verified": verified, "username": username }),
        )
        .into_response()),
        None => Err(ApiError::NotFound),
    }
}

// Presence: heartbeat (owner) or query (open).
async fn presence_post(
    State(dir): State<AppState>,
    Path(handle): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = bearer(&headers).ok_or(ApiError::Unauthorized)?;
    let handle = Handle::new(&handle).map_err(|_| ApiError::NotFound)?;
    dir.lock().unwrap().heartbeat(token, &handle, now_secs())?;
    Ok(ok())
}

async fn presence_get(
    State(dir): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Response, ApiError> {
    let handle = Handle::new(&handle).map_err(|_| ApiError::NotFound)?;
    let online = dir.lock().unwrap().presence(&handle, now_secs());
    Ok(Json(Presence { online }).into_response())
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
    serde_json::from_str(body).map_err(|_| ApiError::InvalidRecord)
}

/// Extract a `Bearer` token from the `Authorization` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Current wall-clock time in whole seconds (for challenge/presence TTLs).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Open the directory durably from `MYCELLIUM_DATA` (a data *directory*; we use
/// `directory.redb` inside it). Setting `MYCELLIUM_DATA` expresses durable intent,
/// so if the store can't be opened we **fail closed** rather than silently drop to
/// in-memory (which would look healthy while nothing persists — issue #45). No
/// `MYCELLIUM_DATA` is the explicit in-memory development mode.
fn open_directory() -> std::io::Result<Directory> {
    let data = std::env::var("MYCELLIUM_DATA")
        .ok()
        .filter(|d| !d.is_empty());
    open_directory_at(data.as_deref())
}

/// The env-free core of [`open_directory`], so the three startup modes are testable.
fn open_directory_at(data: Option<&str>) -> std::io::Result<Directory> {
    match data {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            let path = format!("{}/directory.redb", dir.trim_end_matches('/'));
            let directory = Directory::open(&path).map_err(|e| {
                std::io::Error::other(format!(
                    "MYCELLIUM_DATA is set but the durable store at {path} could not be opened: {e}"
                ))
            })?;
            println!("  persistence: {path}");
            Ok(directory)
        }
        None => {
            println!("  storage: in-memory (set MYCELLIUM_DATA to persist)");
            Ok(Directory::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::open_directory_at;

    #[test]
    fn durable_open_fails_closed_on_a_bad_data_dir() {
        // No data dir → explicit in-memory development mode.
        assert!(open_directory_at(None).is_ok());
        // A valid data dir → durable mode.
        let good = std::env::temp_dir().join(format!("myc-d-good-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&good);
        assert!(open_directory_at(Some(good.to_str().unwrap())).is_ok());
        let _ = std::fs::remove_dir_all(&good);
        // Configured but unusable (the path is a file, not a dir) → fail closed.
        let bad = std::env::temp_dir().join(format!("myc-d-bad-{}", std::process::id()));
        let _ = std::fs::remove_file(&bad);
        std::fs::write(&bad, b"not a dir").unwrap();
        assert!(open_directory_at(Some(bad.to_str().unwrap())).is_err());
        let _ = std::fs::remove_file(&bad);
    }
}
