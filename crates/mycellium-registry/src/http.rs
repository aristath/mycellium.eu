//! Tiny HTTP API for the registry core.
//!
//! This layer exposes account UX, signed public-record discovery, backup, and
//! recovery. It does not store, queue, relay, acknowledge, introduce, or carry
//! messages.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::connect_info::MockConnectInfo;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use mycellium_core::identity::Identity;
use mycellium_core::record::SignedRecord;
use mycellium_core::userid::UserId;
use mycellium_core::wire;
use serde::{Deserialize, Serialize};

use crate::recovery::RecoveryCipher;
use crate::{
    AccountBlobKind, AccountId, BlobSwap, FileBlobStore, LoginIdentityHash, RedbRegistryStore,
    Registry, RegistryError, RegistryStore, Result,
};

const LOGIN_TTL_SECS: i64 = 15 * 60;
const SESSION_TTL_SECS: i64 = 15 * 60;
const EMAIL_LOGIN_LIMIT: u64 = 5;
const EMAIL_LOGIN_SOURCE_LIMIT: u64 = 100;
const LOGIN_CONFIRM_SOURCE_LIMIT: u64 = 300;
const MAX_BACKUP_BYTES: usize = 16 * 1024 * 1024;
const MAX_PUBLIC_RECORD_BYTES: usize = 1024 * 1024;
const MAX_CONTROL_BYTES: usize = 1024 * 1024;
const RECOVERY_SECRET_BYTES: usize = 32;

/// HTTP app state.
pub struct AppState<S> {
    registry: Arc<Registry<S>>,
    blobs: FileBlobStore,
    email_sender: Arc<dyn EmailLoginSender>,
    recovery_cipher: RecoveryCipher,
}

impl<S> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            registry: Arc::clone(&self.registry),
            blobs: self.blobs.clone(),
            email_sender: Arc::clone(&self.email_sender),
            recovery_cipher: self.recovery_cipher.clone(),
        }
    }
}

/// Sends a verified email-login token over the selected email provider.
pub trait EmailLoginSender: Send + Sync + 'static {
    /// Deliver the token to `email`.
    fn send_login_token(&self, email: &str, token: &str, expires_at: i64) -> Result<()>;
}

#[derive(Clone, Debug, Default)]
struct NoopEmailLoginSender;

impl EmailLoginSender for NoopEmailLoginSender {
    fn send_login_token(&self, _email: &str, _token: &str, _expires_at: i64) -> Result<()> {
        Ok(())
    }
}

impl<S: RegistryStore> AppState<S> {
    /// Build app state from a registry and blob store.
    pub fn new(
        registry: Registry<S>,
        blobs: FileBlobStore,
        recovery_cipher: RecoveryCipher,
    ) -> Self {
        Self::with_email_sender(registry, blobs, NoopEmailLoginSender, recovery_cipher)
    }

    /// Build app state with a concrete email sender.
    pub fn with_email_sender(
        registry: Registry<S>,
        blobs: FileBlobStore,
        sender: impl EmailLoginSender,
        recovery_cipher: RecoveryCipher,
    ) -> Self {
        Self {
            registry: Arc::new(registry),
            blobs,
            email_sender: Arc::new(sender),
            recovery_cipher,
        }
    }

    /// Run one bounded metadata cleanup pass.
    pub fn purge_expired(&self, now: i64, limit: usize) -> Result<usize> {
        self.registry.store().purge_expired(now, limit)
    }
}

/// Build the registry router.
pub fn router<S>(state: AppState<S>) -> Router
where
    S: RegistryStore + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/users/{user_id}/record",
            get(get_public_record_by_user_id::<S>),
        )
        .route(
            "/login/email/request",
            post(request_email_login::<S>).layer(DefaultBodyLimit::max(MAX_CONTROL_BYTES)),
        )
        .route(
            "/login/confirm",
            post(confirm_login::<S>).layer(DefaultBodyLimit::max(MAX_CONTROL_BYTES)),
        )
        .route(
            "/accounts/{account_id}/backup",
            put(put_backup::<S>)
                .layer(DefaultBodyLimit::max(MAX_BACKUP_BYTES))
                .get(get_backup::<S>),
        )
        .route(
            "/accounts/{account_id}/recovery",
            put(put_recovery::<S>)
                .layer(DefaultBodyLimit::max(MAX_CONTROL_BYTES))
                .get(get_recovery::<S>),
        )
        .route(
            "/accounts/{account_id}/record",
            put(put_public_record::<S>)
                .layer(DefaultBodyLimit::max(MAX_PUBLIC_RECORD_BYTES))
                .get(get_public_record::<S>),
        )
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))))
        .with_state(state)
}

/// Build a router using the default redb/file stores.
pub fn redb_router(
    data_dir: impl Into<std::path::PathBuf>,
    recovery_cipher: RecoveryCipher,
) -> Result<Router> {
    redb_router_with_email_sender(data_dir, NoopEmailLoginSender, recovery_cipher)
}

/// Build a router using the default redb/file stores and a configured email sender.
pub fn redb_router_with_email_sender(
    data_dir: impl Into<std::path::PathBuf>,
    sender: impl EmailLoginSender,
    recovery_cipher: RecoveryCipher,
) -> Result<Router> {
    Ok(router(redb_state_with_email_sender(
        data_dir,
        sender,
        recovery_cipher,
    )?))
}

/// Build reusable HTTP state using the default redb/file stores.
pub fn redb_state_with_email_sender(
    data_dir: impl Into<std::path::PathBuf>,
    sender: impl EmailLoginSender,
    recovery_cipher: RecoveryCipher,
) -> Result<AppState<RedbRegistryStore>> {
    let data_dir = data_dir.into();
    let store = RedbRegistryStore::open(data_dir.join("registry.redb"))?;
    let blobs = FileBlobStore::new(data_dir.join("blobs"));
    Ok(AppState::with_email_sender(
        Registry::new(store),
        blobs,
        sender,
        recovery_cipher,
    ))
}

#[derive(Debug, Deserialize)]
struct EmailLoginRequest {
    email: String,
}

#[derive(Debug, Serialize)]
struct EmailLoginResponse {
    expires_at: i64,
}

async fn request_email_login<S>(
    State(state): State<AppState<S>>,
    source: ConnectInfo<SocketAddr>,
    Json(body): Json<EmailLoginRequest>,
) -> ApiResult<(StatusCode, Json<EmailLoginResponse>)>
where
    S: RegistryStore + Send + Sync + 'static,
{
    run_blocking(move || {
        let request_time = now();
        check_rate_limit(
            &state,
            &format!("login:source:{}", source_key(&source)),
            request_time,
            LOGIN_TTL_SECS,
            EMAIL_LOGIN_SOURCE_LIMIT,
        )?;
        check_rate_limit(
            &state,
            &format!(
                "login:email:{}",
                LoginIdentityHash::email(&body.email)?.as_str()
            ),
            request_time,
            LOGIN_TTL_SECS,
            EMAIL_LOGIN_LIMIT,
        )?;
        let challenge =
            state
                .registry
                .request_email_login(&body.email, request_time, LOGIN_TTL_SECS)?;
        state
            .email_sender
            .send_login_token(&body.email, &challenge.token, challenge.expires_at)?;
        Ok((
            StatusCode::ACCEPTED,
            Json(EmailLoginResponse {
                expires_at: challenge.expires_at,
            }),
        ))
    })
    .await
}

#[derive(Debug, Deserialize)]
struct ConfirmLoginRequest {
    token: String,
}

#[derive(Debug, Serialize)]
struct ConfirmLoginResponse {
    account_id: String,
    created: bool,
    session_token: String,
    session_expires_at: i64,
}

async fn confirm_login<S>(
    State(state): State<AppState<S>>,
    source: ConnectInfo<SocketAddr>,
    Json(body): Json<ConfirmLoginRequest>,
) -> ApiResult<Json<ConfirmLoginResponse>>
where
    S: RegistryStore + Send + Sync + 'static,
{
    run_blocking(move || {
        let request_time = now();
        check_rate_limit(
            &state,
            &format!("confirm:source:{}", source_key(&source)),
            request_time,
            LOGIN_TTL_SECS,
            LOGIN_CONFIRM_SOURCE_LIMIT,
        )?;
        let login = state.registry.confirm_login(&body.token, request_time)?;
        let session =
            state
                .registry
                .create_session(login.account_id, request_time, SESSION_TTL_SECS)?;
        Ok(Json(ConfirmLoginResponse {
            account_id: session.account_id.to_string(),
            created: login.created,
            session_token: session.token,
            session_expires_at: session.expires_at,
        }))
    })
    .await
}

async fn put_backup<S>(
    State(state): State<AppState<S>>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult<Json<BlobResponse>>
where
    S: RegistryStore + Send + Sync + 'static,
{
    run_blocking(move || {
        let account_id = parse_account_id(&account_id)?;
        authorize(&state, &headers, &account_id)?;
        require_size_at_most(bytes.len(), MAX_BACKUP_BYTES)?;
        let blob = state
            .blobs
            .put(&account_id, AccountBlobKind::Backup, &bytes)?;
        let mut expected = state
            .registry
            .store()
            .blob_ref(&account_id, AccountBlobKind::Backup)?;
        loop {
            match state.registry.store().compare_and_swap_blob_ref(
                &account_id,
                AccountBlobKind::Backup,
                expected.as_ref(),
                &blob,
            )? {
                BlobSwap::Applied { previous } => {
                    remove_replaced_blob(&state, &account_id, previous.as_ref(), &blob);
                    break;
                }
                BlobSwap::Mismatch { current } => expected = current,
            }
        }
        Ok(Json(BlobResponse::from(blob)))
    })
    .await
}

async fn get_backup<S>(
    State(state): State<AppState<S>>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response>
where
    S: RegistryStore + Send + Sync + 'static,
{
    run_blocking(move || {
        let account_id = parse_account_id(&account_id)?;
        authorize(&state, &headers, &account_id)?;
        let Some((_, bytes)) = load_current_blob(&state, &account_id, AccountBlobKind::Backup)?
        else {
            return Err(ApiError::not_found("backup not found"));
        };
        Ok((StatusCode::OK, bytes).into_response())
    })
    .await
}

async fn put_recovery<S>(
    State(state): State<AppState<S>>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult<Json<BlobResponse>>
where
    S: RegistryStore + Send + Sync + 'static,
{
    run_blocking(move || {
        let account_id = parse_account_id(&account_id)?;
        authorize(&state, &headers, &account_id)?;
        if bytes.len() != RECOVERY_SECRET_BYTES {
            return Err(ApiError::bad_request(
                "recovery material must be exactly 32 bytes",
            ));
        }
        let wallet_secret: [u8; RECOVERY_SECRET_BYTES] = bytes
            .as_ref()
            .try_into()
            .map_err(|_| ApiError::bad_request("invalid recovery material"))?;
        Identity::from_wallet_secret(wallet_secret, [0u8; 32])
            .map_err(|_| ApiError::bad_request("recovery material is not a valid wallet key"))?;
        let sealed = state.recovery_cipher.seal(&account_id, &bytes)?;
        let blob = state
            .blobs
            .put(&account_id, AccountBlobKind::Recovery, &sealed)?;
        loop {
            let current = load_current_blob(&state, &account_id, AccountBlobKind::Recovery)?;
            if let Some((current_ref, current_sealed)) = current {
                let current_secret = state.recovery_cipher.open(&account_id, &current_sealed)?;
                if current_secret != bytes.as_ref() {
                    state.blobs.remove(&account_id, &blob)?;
                    return Err(ApiError::conflict(
                        "account recovery identity cannot be replaced",
                    ));
                }
                if current_ref != blob {
                    state.blobs.remove(&account_id, &blob)?;
                }
                return Ok(Json(BlobResponse::from(current_ref)));
            }
            match state.registry.store().compare_and_swap_blob_ref(
                &account_id,
                AccountBlobKind::Recovery,
                None,
                &blob,
            )? {
                BlobSwap::Applied { .. } => return Ok(Json(BlobResponse::from(blob))),
                BlobSwap::Mismatch { .. } => continue,
            }
        }
    })
    .await
}

async fn get_recovery<S>(
    State(state): State<AppState<S>>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response>
where
    S: RegistryStore + Send + Sync + 'static,
{
    run_blocking(move || {
        let account_id = parse_account_id(&account_id)?;
        authorize(&state, &headers, &account_id)?;
        let Some((_, sealed)) = load_current_blob(&state, &account_id, AccountBlobKind::Recovery)?
        else {
            return Err(ApiError::not_found("recovery material not found"));
        };
        let secret = state.recovery_cipher.open(&account_id, &sealed)?;
        if secret.len() != RECOVERY_SECRET_BYTES {
            return Err(ApiError::bad_request("stored recovery material is invalid"));
        }
        Ok((StatusCode::OK, secret).into_response())
    })
    .await
}

async fn put_public_record<S>(
    State(state): State<AppState<S>>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
    bytes: Bytes,
) -> ApiResult<Json<BlobResponse>>
where
    S: RegistryStore + Send + Sync + 'static,
{
    run_blocking(move || {
        let account_id = parse_account_id(&account_id)?;
        authorize(&state, &headers, &account_id)?;
        require_size_at_most(bytes.len(), MAX_PUBLIC_RECORD_BYTES)?;
        let record = decode_signed_public_record(&bytes)?;
        let blob = state
            .blobs
            .put(&account_id, AccountBlobKind::PublicRecord, &bytes)?;
        loop {
            let update = match enforce_public_record_update(&state, &account_id, &record, &bytes) {
                Ok(update) => update,
                Err(error) => {
                    let _ = state.blobs.remove(&account_id, &blob);
                    return Err(error);
                }
            };
            match state.registry.store().compare_and_swap_public_record_ref(
                &account_id,
                &record.record.user_id,
                update.previous_user_id.as_ref(),
                update.expected.as_ref(),
                &blob,
            )? {
                BlobSwap::Applied { previous } => {
                    remove_replaced_blob(&state, &account_id, previous.as_ref(), &blob);
                    return Ok(Json(BlobResponse::from(blob)));
                }
                BlobSwap::Mismatch { .. } => continue,
            }
        }
    })
    .await
}

async fn get_public_record<S>(
    State(state): State<AppState<S>>,
    Path(account_id): Path<String>,
) -> ApiResult<Response>
where
    S: RegistryStore + Send + Sync + 'static,
{
    run_blocking(move || {
        let account_id = parse_account_id(&account_id)?;
        public_record_response(&state, &account_id)
    })
    .await
}

async fn get_public_record_by_user_id<S>(
    State(state): State<AppState<S>>,
    Path(user_id): Path<String>,
) -> ApiResult<Response>
where
    S: RegistryStore + Send + Sync + 'static,
{
    run_blocking(move || {
        let user_id =
            UserId::new(user_id).map_err(|_| ApiError::bad_request("invalid protocol user id"))?;
        let Some(account_id) = state.registry.store().account_id_by_user_id(&user_id)? else {
            return Err(ApiError::not_found("record not found"));
        };
        public_record_response(&state, &account_id)
    })
    .await
}

fn public_record_response<S>(state: &AppState<S>, account_id: &AccountId) -> ApiResult<Response>
where
    S: RegistryStore,
{
    let Some((_, bytes)) = load_current_blob(state, account_id, AccountBlobKind::PublicRecord)?
    else {
        return Err(ApiError::not_found("record not found"));
    };
    decode_signed_public_record(&bytes).map_err(|_| ApiError::not_found("record not found"))?;
    Ok((StatusCode::OK, bytes).into_response())
}

/// Resolve a slot pointer and its bytes consistently across a concurrent
/// replacement. A reader that raced cleanup simply retries the current pointer.
fn load_current_blob<S: RegistryStore>(
    state: &AppState<S>,
    account_id: &AccountId,
    kind: AccountBlobKind,
) -> Result<Option<(crate::BlobRef, Vec<u8>)>> {
    loop {
        let Some(blob) = state.registry.store().blob_ref(account_id, kind)? else {
            return Ok(None);
        };
        if let Some(bytes) = state.blobs.get(account_id, &blob)? {
            return Ok(Some((blob, bytes)));
        }
        // A writer may have replaced and removed this immutable blob after we
        // read its pointer. Retry only when the pointer actually advanced;
        // a stable pointer to missing bytes is corruption, not a transient.
        if state.registry.store().blob_ref(account_id, kind)?.as_ref() == Some(&blob) {
            return Err(RegistryError::new("current blob is missing"));
        }
    }
}

fn remove_replaced_blob<S>(
    state: &AppState<S>,
    account_id: &AccountId,
    previous: Option<&crate::BlobRef>,
    current: &crate::BlobRef,
) {
    let Some(previous) = previous.filter(|previous| *previous != current) else {
        return;
    };
    if let Err(error) = state.blobs.remove(account_id, previous) {
        eprintln!("registry blob cleanup failed for {account_id}: {error}");
    }
}

#[derive(Debug, Serialize)]
struct BlobResponse {
    id: String,
    size: u64,
    sha256: String,
}

impl From<crate::BlobRef> for BlobResponse {
    fn from(blob: crate::BlobRef) -> Self {
        Self {
            id: blob.id,
            size: blob.size,
            sha256: blob.sha256,
        }
    }
}

type ApiResult<T> = std::result::Result<T, ApiError>;

async fn run_blocking<T, F>(work: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> ApiResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| ApiError::internal())?
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized".into(),
        }
    }

    fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: "forbidden".into(),
        }
    }

    fn not_found(message: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn rate_limited() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "rate limited".into(),
        }
    }

    fn payload_too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: "payload too large".into(),
        }
    }

    fn conflict(message: &str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".into(),
        }
    }
}

impl From<RegistryError> for ApiError {
    fn from(err: RegistryError) -> Self {
        match err.kind {
            crate::RegistryErrorKind::InvalidInput => Self {
                status: StatusCode::BAD_REQUEST,
                message: err.to_string(),
            },
            crate::RegistryErrorKind::Conflict => Self::conflict(&err.to_string()),
            crate::RegistryErrorKind::Internal => {
                eprintln!("registry request failed: {err}");
                Self::internal()
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct ErrorBody {
            error: String,
        }
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

fn authorize<S: RegistryStore>(
    state: &AppState<S>,
    headers: &HeaderMap,
    account_id: &AccountId,
) -> ApiResult<()> {
    let token = bearer_token(headers).ok_or_else(ApiError::unauthorized)?;
    let Some(session_account) = state.registry.account_for_session(token, now())? else {
        return Err(ApiError::unauthorized());
    };
    if &session_account != account_id {
        return Err(ApiError::forbidden());
    }
    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("authorization")?.to_str().ok()?;
    value.strip_prefix("Bearer ")
}

fn parse_account_id(value: &str) -> ApiResult<AccountId> {
    value.parse().map_err(ApiError::from)
}

fn require_size_at_most(size: usize, max: usize) -> ApiResult<()> {
    if size > max {
        return Err(ApiError::payload_too_large());
    }
    Ok(())
}

fn decode_signed_public_record(bytes: &[u8]) -> ApiResult<SignedRecord> {
    let record: SignedRecord = wire::decode(bytes).map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: "bad signed public record".into(),
    })?;
    record.verify().map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: "public record failed verification".into(),
    })?;
    Ok(record)
}

struct PublicRecordUpdate {
    expected: Option<crate::BlobRef>,
    previous_user_id: Option<UserId>,
}

fn enforce_public_record_update<S: RegistryStore>(
    state: &AppState<S>,
    account_id: &AccountId,
    next: &SignedRecord,
    next_bytes: &[u8],
) -> ApiResult<PublicRecordUpdate> {
    let (_, recovery_sealed) = load_current_blob(state, account_id, AccountBlobKind::Recovery)?
        .ok_or_else(|| ApiError::conflict("store account recovery before publishing a record"))?;
    let recovery = state.recovery_cipher.open(account_id, &recovery_sealed)?;
    let wallet_secret: [u8; RECOVERY_SECRET_BYTES] = recovery
        .try_into()
        .map_err(|_| ApiError::bad_request("stored recovery material is invalid"))?;
    let identity = Identity::from_wallet_secret(wallet_secret, [0u8; 32])
        .map_err(|_| ApiError::bad_request("stored recovery material is invalid"))?;
    if next.record.wallet != identity.wallet_public() {
        return Err(ApiError::conflict(
            "public record does not belong to the account recovery identity",
        ));
    }
    let Some((current_ref, current_bytes)) =
        load_current_blob(state, account_id, AccountBlobKind::PublicRecord)?
    else {
        return Ok(PublicRecordUpdate {
            expected: None,
            previous_user_id: None,
        });
    };
    let current: SignedRecord = wire::decode(&current_bytes).map_err(|_| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: "stored public record is invalid".into(),
    })?;
    if current.verify().is_err() {
        return Ok(PublicRecordUpdate {
            expected: Some(current_ref),
            previous_user_id: Some(current.record.user_id),
        });
    }
    if current.record.user_id != next.record.user_id {
        return Err(ApiError::conflict(
            "public record belongs to a different user",
        ));
    }
    if next.freshness() < current.freshness()
        || (next.freshness() == current.freshness() && next_bytes != current_bytes.as_slice())
    {
        return Err(ApiError::conflict("stale public record"));
    }
    Ok(PublicRecordUpdate {
        expected: Some(current_ref),
        previous_user_id: Some(current.record.user_id),
    })
}

fn check_rate_limit<S: RegistryStore>(
    state: &AppState<S>,
    key: &str,
    now: i64,
    window_secs: i64,
    limit: u64,
) -> ApiResult<()> {
    let bucket = state
        .registry
        .store()
        .bump_rate_limit(key, now, window_secs)?;
    if bucket.count > limit {
        return Err(ApiError::rate_limited());
    }
    Ok(())
}

fn source_key(source: &ConnectInfo<SocketAddr>) -> String {
    source.0.ip().to_string()
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Method, Request};
    use mycellium_core::identity::{Handle, Identity};
    use mycellium_core::platform::Platform;
    use mycellium_core::record::{Device, Record};
    use mycellium_core::userid::user_id;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    use super::*;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).unwrap();
        path.push(format!(
            "mycellium-registry-http-{name}-{}",
            crate::hex(&bytes)
        ));
        path
    }

    #[derive(Clone, Default)]
    struct CaptureEmailSender {
        tokens: Arc<Mutex<Vec<String>>>,
    }

    impl CaptureEmailSender {
        fn take_token(&self) -> String {
            self.tokens.lock().unwrap().pop().unwrap()
        }
    }

    impl EmailLoginSender for CaptureEmailSender {
        fn send_login_token(&self, _email: &str, token: &str, _expires_at: i64) -> Result<()> {
            self.tokens.lock().unwrap().push(token.to_string());
            Ok(())
        }
    }

    fn app_with_mail(name: &str) -> (Router, CaptureEmailSender) {
        let dir = tmpdir(name);
        let store = RedbRegistryStore::open(dir.join("registry.redb")).unwrap();
        let sender = CaptureEmailSender::default();
        let app = router(AppState::with_email_sender(
            Registry::new(store),
            FileBlobStore::new(dir.join("blobs")),
            sender.clone(),
            RecoveryCipher::new([7; 32]),
        ));
        (app, sender)
    }

    fn state_with_mail(name: &str) -> (AppState<RedbRegistryStore>, Router, CaptureEmailSender) {
        let dir = tmpdir(name);
        let store = RedbRegistryStore::open(dir.join("registry.redb")).unwrap();
        let sender = CaptureEmailSender::default();
        let state = AppState::with_email_sender(
            Registry::new(store),
            FileBlobStore::new(dir.join("blobs")),
            sender.clone(),
            RecoveryCipher::new([7; 32]),
        );
        let app = router(state.clone());
        (state, app, sender)
    }

    struct TestPlatform(u8);

    impl Platform for TestPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for b in buf {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }

        fn now_unix_secs(&self) -> u64 {
            100
        }
    }

    fn signed_public_record_bytes(seq: u64) -> Vec<u8> {
        let mut platform = TestPlatform(1);
        let identity = Identity::generate(&mut platform).unwrap();
        signed_public_record_bytes_for(&identity, seq)
    }

    fn signed_public_record_bytes_for(identity: &Identity, seq: u64) -> Vec<u8> {
        let record = Record {
            user_id: user_id(&identity.wallet_public()),
            handle: Handle::new("alice").unwrap(),
            name: "Alice".into(),
            wallet: identity.wallet_public(),
            device: Device::create(identity, seq),
            seq,
        };
        wire::encode(&SignedRecord::sign(record, identity))
    }

    async fn request_login(app: Router, sender: &CaptureEmailSender) -> String {
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/login/email/request")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"email":"ari@example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = response_json(response).await;
        assert!(body.get("dev_token").is_none());
        sender.take_token()
    }

    async fn response_json(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn login_session(app: &Router, sender: &CaptureEmailSender) -> (String, String) {
        let login_token = request_login(app.clone(), sender).await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/login/confirm")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"token":"{login_token}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        (
            body["account_id"].as_str().unwrap().to_string(),
            body["session_token"].as_str().unwrap().to_string(),
        )
    }

    async fn store_recovery(
        app: &Router,
        account_id: &str,
        session_token: &str,
        identity: &Identity,
    ) -> StatusCode {
        app.clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/accounts/{account_id}/recovery"))
                    .header("authorization", format!("Bearer {session_token}"))
                    .body(Body::from(identity.wallet_secret().to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn login_upload_and_lookup_public_record() {
        let (app, sender) = app_with_mail("flow");

        let (account_id, session_token) = login_session(&app, &sender).await;
        let mut platform = TestPlatform(1);
        let identity = Identity::generate(&mut platform).unwrap();
        assert_eq!(
            store_recovery(&app, &account_id, &session_token, &identity).await,
            StatusCode::OK
        );
        let public_record = signed_public_record_bytes_for(&identity, 1);
        let protocol_user_id = user_id(&identity.wallet_public());

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/accounts/{account_id}/record"))
                    .header("authorization", format!("Bearer {session_token}"))
                    .body(Body::from(public_record.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/accounts/{account_id}/record"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], &public_record[..]);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/users/{}/record", protocol_user_id.as_str()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], &public_record[..]);
    }

    #[tokio::test]
    async fn backup_requires_session() {
        let app = redb_router(tmpdir("auth"), RecoveryCipher::new([7; 32])).unwrap();
        let account_id = AccountId::generate().unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/accounts/{account_id}/backup"))
                    .body(Body::from("secret"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn email_login_is_rate_limited() {
        let (app, _sender) = app_with_mail("rate");

        for _ in 0..EMAIL_LOGIN_LIMIT {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/login/email/request")
                        .header("content-type", "application/json")
                        .body(Body::from(r#"{"email":"ari@example.com"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/login/email/request")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"email":"ari@example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn distinct_emails_cannot_bypass_the_source_login_limit() {
        let (app, _sender) = app_with_mail("source-rate-limit");

        for index in 0..EMAIL_LOGIN_SOURCE_LIMIT {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/login/email/request")
                        .header("content-type", "application/json")
                        .body(Body::from(format!(
                            r#"{{"email":"person-{index}@example.com"}}"#
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/login/email/request")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"email":"one-too-many@example.com"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn record_upload_is_size_limited() {
        let (app, sender) = app_with_mail("size");

        let (account_id, session_token) = login_session(&app, &sender).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/accounts/{account_id}/record"))
                    .header("authorization", format!("Bearer {session_token}"))
                    .body(Body::from(vec![0u8; MAX_PUBLIC_RECORD_BYTES + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn public_record_must_be_a_verified_signed_record() {
        let (app, sender) = app_with_mail("record-verify");
        let (account_id, session_token) = login_session(&app, &sender).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/accounts/{account_id}/record"))
                    .header("authorization", format!("Bearer {session_token}"))
                    .body(Body::from("not-a-signed-record"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn account_owner_can_replace_legacy_invalid_public_record() {
        let (state, app, sender) = state_with_mail("record-legacy-invalid");
        let (account_id, session_token) = login_session(&app, &sender).await;
        let account_id: AccountId = account_id.parse().unwrap();
        let identity = Identity::generate(&mut TestPlatform(80)).unwrap();
        assert_eq!(
            store_recovery(&app, account_id.as_str(), &session_token, &identity).await,
            StatusCode::OK
        );

        let mut legacy = signed_public_record_bytes_for(&identity, 3);
        let last = legacy.last_mut().unwrap();
        *last ^= 0x80;
        let legacy_record: SignedRecord = wire::decode(&legacy).unwrap();
        assert!(legacy_record.verify().is_err());
        let legacy_ref = state
            .blobs
            .put(&account_id, AccountBlobKind::PublicRecord, &legacy)
            .unwrap();
        assert!(matches!(
            state
                .registry
                .store()
                .compare_and_swap_public_record_ref(
                    &account_id,
                    &legacy_record.record.user_id,
                    None,
                    None,
                    &legacy_ref,
                )
                .unwrap(),
            BlobSwap::Applied { .. }
        ));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/accounts/{account_id}/record"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let fresh = signed_public_record_bytes_for(&identity, 4);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/accounts/{account_id}/record"))
                    .header("authorization", format!("Bearer {session_token}"))
                    .body(Body::from(fresh.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!(
                        "/users/{}/record",
                        user_id(&identity.wallet_public()).as_str()
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], &fresh[..]);
    }

    #[tokio::test]
    async fn public_record_update_rejects_other_user_and_rollback() {
        let (app, sender) = app_with_mail("record-update");
        let (account_id, session_token) = login_session(&app, &sender).await;
        let mut platform = TestPlatform(10);
        let identity = Identity::generate(&mut platform).unwrap();
        assert_eq!(
            store_recovery(&app, &account_id, &session_token, &identity).await,
            StatusCode::OK
        );
        let current = signed_public_record_bytes_for(&identity, 3);
        let stale = signed_public_record_bytes_for(&identity, 2);
        let other = signed_public_record_bytes(4);

        let upload = |bytes: Vec<u8>| {
            let app = app.clone();
            let account_id = account_id.clone();
            let session_token = session_token.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .method(Method::PUT)
                        .uri(format!("/accounts/{account_id}/record"))
                        .header("authorization", format!("Bearer {session_token}"))
                        .body(Body::from(bytes))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
            }
        };

        assert_eq!(upload(current).await, StatusCode::OK);
        assert_eq!(upload(stale).await, StatusCode::CONFLICT);
        assert_eq!(upload(other).await, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn concurrent_public_record_updates_converge_on_the_freshest_record() {
        let (app, sender) = app_with_mail("record-concurrent");
        let (account_id, session_token) = login_session(&app, &sender).await;
        let identity = Identity::generate(&mut TestPlatform(40)).unwrap();
        assert_eq!(
            store_recovery(&app, &account_id, &session_token, &identity).await,
            StatusCode::OK
        );
        let older = signed_public_record_bytes_for(&identity, 10);
        let newest = signed_public_record_bytes_for(&identity, 11);

        let upload = |bytes: Vec<u8>| {
            let app = app.clone();
            let account_id = account_id.clone();
            let session_token = session_token.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .method(Method::PUT)
                        .uri(format!("/accounts/{account_id}/record"))
                        .header("authorization", format!("Bearer {session_token}"))
                        .body(Body::from(bytes))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
            }
        };
        let (older_status, newest_status) = tokio::join!(upload(older), upload(newest.clone()));
        assert!(matches!(
            older_status,
            StatusCode::OK | StatusCode::CONFLICT
        ));
        assert_eq!(newest_status, StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/accounts/{account_id}/record"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], newest.as_slice());
    }

    #[tokio::test]
    async fn backup_upload_uses_the_configured_16mib_body_limit() {
        let (app, sender) = app_with_mail("backup-limit");
        let (account_id, session_token) = login_session(&app, &sender).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/accounts/{account_id}/backup"))
                    .header("authorization", format!("Bearer {session_token}"))
                    .body(Body::from(vec![0u8; 3 * 1024 * 1024]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn recovery_secret_is_sealed_at_rest_and_requires_its_session() {
        let (app, sender) = app_with_mail("recovery");
        let (account_id, session_token) = login_session(&app, &sender).await;
        let secret = [19u8; RECOVERY_SECRET_BYTES];

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/accounts/{account_id}/recovery"))
                    .header("authorization", format!("Bearer {session_token}"))
                    .body(Body::from(secret.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/accounts/{account_id}/recovery"))
                    .header("authorization", format!("Bearer {session_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], &secret);

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/accounts/{account_id}/recovery"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn account_recovery_identity_is_write_once() {
        let (app, sender) = app_with_mail("recovery-write-once");
        let (account_id, session_token) = login_session(&app, &sender).await;
        let mut first_platform = TestPlatform(1);
        let first = Identity::generate(&mut first_platform).unwrap();
        let mut second_platform = TestPlatform(99);
        let second = Identity::generate(&mut second_platform).unwrap();

        assert_eq!(
            store_recovery(&app, &account_id, &session_token, &first).await,
            StatusCode::OK
        );
        assert_eq!(
            store_recovery(&app, &account_id, &session_token, &first).await,
            StatusCode::OK
        );
        assert_eq!(
            store_recovery(&app, &account_id, &session_token, &second).await,
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn upload_limits_are_explicit_abuse_guards() {
        assert!(require_size_at_most(MAX_BACKUP_BYTES, MAX_BACKUP_BYTES).is_ok());
        assert!(require_size_at_most(MAX_PUBLIC_RECORD_BYTES, MAX_PUBLIC_RECORD_BYTES).is_ok());

        assert_eq!(
            require_size_at_most(MAX_BACKUP_BYTES + 1, MAX_BACKUP_BYTES)
                .unwrap_err()
                .status,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            require_size_at_most(MAX_PUBLIC_RECORD_BYTES + 1, MAX_PUBLIC_RECORD_BYTES)
                .unwrap_err()
                .status,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn internal_errors_do_not_leak_backend_details() {
        let response = ApiError::from(RegistryError::new(
            "secret database path /srv/registry/registry.redb",
        ))
        .into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = response_json(response).await;
        assert_eq!(body["error"], "internal server error");
        assert!(!body.to_string().contains("registry.redb"));
    }
}
