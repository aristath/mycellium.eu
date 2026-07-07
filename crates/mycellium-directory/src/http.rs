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

use crate::{mailer, persist, ApiError, Directory};

/// Largest request body the directory will buffer (records are a few KB; this is
/// generous headroom). Anything larger is refused with 413 by the runtime.
const MAX_BODY: usize = 256 * 1024;

/// Shared, mutex-guarded directory state. The core is synchronous and its
/// critical sections are short (in-memory maps + fast redb writes), so a single
/// mutex serializes access without the async runtime ever blocking meaningfully.
type DirectoryHandle = Arc<Mutex<Directory>>;

#[derive(Clone)]
struct AppState {
    directory: DirectoryHandle,
    /// The durable store, held **outside** the directory `Mutex` so a write
    /// handler commits (an fsync) off the state lock and off the async worker (on
    /// `spawn_blocking`). `None` = in-memory development mode.
    store: Option<Arc<persist::Store>>,
    auth: AuthConfig,
}

/// Directory HTTP serving config.
#[derive(Clone, Debug)]
pub struct ServeConfig {
    /// Durable data directory. `None` means explicit in-memory development mode.
    pub data_dir: Option<String>,
    /// Email verification mode.
    pub auth: AuthConfig,
    /// Shared HTTP runtime options.
    pub http: mycellium_serve::HttpConfig,
}

impl ServeConfig {
    /// Explicit in-memory development config.
    pub fn dev() -> Self {
        Self {
            data_dir: None,
            auth: AuthConfig::Dev,
            http: mycellium_serve::HttpConfig::default(),
        }
    }
}

pub use mailer::{AuthConfig, SmtpConfig};

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
pub async fn serve(addr: &str, config: ServeConfig) -> std::io::Result<()> {
    let (directory, store) = open_directory(config.data_dir.as_deref())?;
    let http = config.http.clone();
    let state = AppState {
        directory: Arc::new(Mutex::new(directory)),
        store,
        auth: config.auth,
    };
    mycellium_serve::Server::new("directory", MAX_BODY)
        .run(addr, router(state), http)
        .await
}

/// Serve a caller-owned, in-memory directory state. Useful for tests and
/// embedders. (A caller-owned handle has no durable store; use [`serve`] for
/// durability.)
pub async fn serve_with(
    addr: &str,
    directory: DirectoryHandle,
    config: ServeConfig,
) -> std::io::Result<()> {
    let state = AppState {
        directory,
        store: None,
        auth: config.auth,
    };
    mycellium_serve::Server::new("directory", MAX_BODY)
        .run(addr, router(state), config.http)
        .await
}

/// Persist one durable [`persist::Write`] **off the state lock and off the async
/// worker**: the commit (an fsync) runs on `spawn_blocking`, and the handler
/// awaits it so durability precedes the response. A join failure (a panicked
/// blocking task) or a commit error both fail the request closed via
/// [`ApiError::Storage`]. In-memory mode (`None`) is a no-op.
async fn persist(
    store: &Option<Arc<persist::Store>>,
    write: persist::Write,
) -> Result<(), ApiError> {
    let Some(store) = store else {
        return Ok(());
    };
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || store.apply(write))
        .await
        .map_err(|_| ApiError::Storage)?
        .map_err(|_| ApiError::Storage)
}

/// The directory's routes, over an already-constructed [`Directory`] state. Split
/// out so tests can mount it without the process-level startup checks.
fn router(state: AppState) -> Router {
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
    let nonce = dir
        .directory
        .lock()
        .unwrap()
        .challenge(req.wallet, now_secs());
    Ok(Json(ChallengeResp { nonce }).into_response())
}

async fn login_verify(State(dir): State<AppState>, body: String) -> Result<Response, ApiError> {
    let req: VerifyReq = parse(&body)?;
    let token = dir
        .directory
        .lock()
        .unwrap_or_else(|e| e.into_inner())
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
    // Lock → validate + mutate memory + capture the snapshot → DROP the lock, then
    // commit (fsync) off the lock and off the async worker, awaiting it so the
    // publish is durable before we respond (a commit error fails it closed).
    let write = dir
        .directory
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .publish(token, &handle, record, now_secs())?;
    persist(&dir.store, write).await?;
    Ok(ok())
}

async fn get_record(
    State(dir): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Response, ApiError> {
    let handle = Handle::new(&handle).map_err(|_| ApiError::HandleMismatch)?;
    match dir
        .directory
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .lookup(&handle)
    {
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
        dir.directory
            .lock()
            .unwrap()
            .auth_start(token, &username, &req.email, now_secs())?;
    // Send the code off the lock — a slow SMTP server must never stall the
    // directory. A detached OS thread is right here: `send_verification` is
    // blocking I/O, and it must outlive this request. Send to the *canonical*
    // address, matching what `auth_start` stored/hashed.
    let (email, thread_code, auth) = (
        crate::normalize_email(&req.email),
        code.clone(),
        dir.auth.clone(),
    );
    std::thread::spawn(move || crate::mailer::send_verification(&auth, &email, &thread_code));
    // Dev mode (no SMTP) also returns the code so local flows need no inbox.
    let resp = if matches!(dir.auth, AuthConfig::Dev) {
        serde_json::json!({ "pending": pending, "dev_code": code })
    } else {
        serde_json::json!({ "pending": pending })
    };
    Ok(Json(resp).into_response())
}

async fn auth_confirm(State(dir): State<AppState>, body: String) -> Result<Response, ApiError> {
    let req: AuthConfirmReq = parse(&body)?;
    let (username, write) = dir
        .directory
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .auth_confirm(&req.pending, &req.code, now_secs())?;
    persist(&dir.store, write).await?;
    Ok(Json(serde_json::json!({ "ok": true, "username": username.as_str() })).into_response())
}

async fn auth_status(State(dir): State<AppState>, body: String) -> Result<Response, ApiError> {
    let req: AuthStatusReq = parse(&body)?;
    match dir
        .directory
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .auth_status(&req.pending)
    {
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
    dir.directory
        .lock()
        .unwrap()
        .heartbeat(token, &handle, now_secs())?;
    Ok(ok())
}

async fn presence_get(
    State(dir): State<AppState>,
    Path(handle): Path<String>,
) -> Result<Response, ApiError> {
    let handle = Handle::new(&handle).map_err(|_| ApiError::NotFound)?;
    let online = dir
        .directory
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .presence(&handle, now_secs());
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

/// Open the directory durably from an explicit data directory. `None` is explicit
/// in-memory development mode.
fn open_directory(data: Option<&str>) -> std::io::Result<(Directory, Option<Arc<persist::Store>>)> {
    match data {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            let path = format!("{}/directory.redb", dir.trim_end_matches('/'));
            let (directory, store) = Directory::open(&path).map_err(|e| {
                std::io::Error::other(format!(
                    "the durable directory store at {path} could not be opened: {e}"
                ))
            })?;
            tracing::info!(%path, "persistence enabled");
            Ok((directory, Some(Arc::new(store))))
        }
        None => {
            tracing::info!("storage: in-memory development mode");
            Ok((Directory::new(), None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::open_directory;

    #[test]
    fn durable_open_fails_closed_on_a_bad_data_dir() {
        // No data dir → explicit in-memory development mode.
        assert!(open_directory(None).is_ok());
        // A valid data dir → durable mode.
        let good = std::env::temp_dir().join(format!("myc-d-good-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&good);
        assert!(open_directory(Some(good.to_str().unwrap())).is_ok());
        let _ = std::fs::remove_dir_all(&good);
        // Configured but unusable (the path is a file, not a dir) → fail closed.
        let bad = std::env::temp_dir().join(format!("myc-d-bad-{}", std::process::id()));
        let _ = std::fs::remove_file(&bad);
        std::fs::write(&bad, b"not a dir").unwrap();
        assert!(open_directory(Some(bad.to_str().unwrap())).is_err());
        let _ = std::fs::remove_file(&bad);
    }
}
