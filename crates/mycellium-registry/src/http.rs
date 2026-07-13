//! Tiny HTTP API for the registry core.
//!
//! This layer exposes account UX only. It does not store, queue, relay, or route
//! messages.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use axum::{Json, Router};
use mycellium_core::record::SignedRecord;
use mycellium_core::wire;
use serde::{Deserialize, Serialize};

use crate::{
    AccountBlobKind, AccountId, FileBlobStore, LoginIdentityHash, RedbRegistryStore, Registry,
    RegistryError, RegistryStore, Result,
};

const LOGIN_TTL_SECS: i64 = 15 * 60;
const SESSION_TTL_SECS: i64 = 30 * 24 * 60 * 60;
const EMAIL_LOGIN_LIMIT: u64 = 5;
const MAX_BACKUP_BYTES: usize = 16 * 1024 * 1024;
const MAX_PUBLIC_RECORD_BYTES: usize = 1024 * 1024;

/// HTTP app state.
pub struct AppState<S> {
    registry: Arc<Registry<S>>,
    blobs: FileBlobStore,
    email_sender: Arc<dyn EmailLoginSender>,
}

impl<S> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            registry: Arc::clone(&self.registry),
            blobs: self.blobs.clone(),
            email_sender: Arc::clone(&self.email_sender),
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
    pub fn new(registry: Registry<S>, blobs: FileBlobStore) -> Self {
        Self::with_email_sender(registry, blobs, NoopEmailLoginSender)
    }

    /// Build app state with a concrete email sender.
    pub fn with_email_sender(
        registry: Registry<S>,
        blobs: FileBlobStore,
        sender: impl EmailLoginSender,
    ) -> Self {
        Self {
            registry: Arc::new(registry),
            blobs,
            email_sender: Arc::new(sender),
        }
    }
}

/// Build the registry router.
pub fn router<S>(state: AppState<S>) -> Router
where
    S: RegistryStore + Send + Sync + 'static,
{
    Router::new()
        .route("/login/email/request", post(request_email_login::<S>))
        .route("/login/confirm", post(confirm_login::<S>))
        .route(
            "/accounts/{account_id}/backup",
            put(put_backup::<S>).get(get_backup::<S>),
        )
        .route(
            "/accounts/{account_id}/record",
            put(put_public_record::<S>).get(get_public_record::<S>),
        )
        .layer(DefaultBodyLimit::max(MAX_BACKUP_BYTES))
        .with_state(state)
}

/// Build a router using the default redb/file stores.
pub fn redb_router(data_dir: impl Into<std::path::PathBuf>) -> Result<Router> {
    let data_dir = data_dir.into();
    let store = RedbRegistryStore::open(data_dir.join("registry.redb"))?;
    let blobs = FileBlobStore::new(data_dir.join("blobs"));
    Ok(router(AppState::new(Registry::new(store), blobs)))
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
    Json(body): Json<EmailLoginRequest>,
) -> ApiResult<(StatusCode, Json<EmailLoginResponse>)>
where
    S: RegistryStore + Send + Sync + 'static,
{
    check_rate_limit(
        &state,
        &format!(
            "login:email:{}",
            LoginIdentityHash::email(&body.email)?.as_str()
        ),
        now(),
        LOGIN_TTL_SECS,
        EMAIL_LOGIN_LIMIT,
    )?;
    let challenge = state
        .registry
        .request_email_login(&body.email, now(), LOGIN_TTL_SECS)?;
    state
        .email_sender
        .send_login_token(&body.email, &challenge.token, challenge.expires_at)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(EmailLoginResponse {
            expires_at: challenge.expires_at,
        }),
    ))
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
    Json(body): Json<ConfirmLoginRequest>,
) -> ApiResult<Json<ConfirmLoginResponse>>
where
    S: RegistryStore + Send + Sync + 'static,
{
    let login = state.registry.confirm_login(&body.token, now())?;
    let session = state
        .registry
        .create_session(login.account_id, now(), SESSION_TTL_SECS)?;
    Ok(Json(ConfirmLoginResponse {
        account_id: session.account_id.to_string(),
        created: login.created,
        session_token: session.token,
        session_expires_at: session.expires_at,
    }))
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
    let account_id = parse_account_id(&account_id)?;
    authorize(&state, &headers, &account_id)?;
    require_size_at_most(bytes.len(), MAX_BACKUP_BYTES)?;
    let blob = state
        .blobs
        .put(&account_id, AccountBlobKind::Backup, &bytes)?;
    state
        .registry
        .store()
        .put_blob_ref(&account_id, AccountBlobKind::Backup, &blob)?;
    Ok(Json(BlobResponse::from(blob)))
}

async fn get_backup<S>(
    State(state): State<AppState<S>>,
    Path(account_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response>
where
    S: RegistryStore + Send + Sync + 'static,
{
    let account_id = parse_account_id(&account_id)?;
    authorize(&state, &headers, &account_id)?;
    let Some(blob) = state
        .registry
        .store()
        .blob_ref(&account_id, AccountBlobKind::Backup)?
    else {
        return Err(ApiError::not_found("backup not found"));
    };
    let Some(bytes) = state.blobs.get(&account_id, &blob)? else {
        return Err(ApiError::not_found("backup blob not found"));
    };
    Ok((StatusCode::OK, bytes).into_response())
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
    let account_id = parse_account_id(&account_id)?;
    authorize(&state, &headers, &account_id)?;
    require_size_at_most(bytes.len(), MAX_PUBLIC_RECORD_BYTES)?;
    let record = decode_signed_public_record(&bytes)?;
    enforce_public_record_update(&state, &account_id, &record, &bytes)?;
    let blob = state
        .blobs
        .put(&account_id, AccountBlobKind::PublicRecord, &bytes)?;
    state
        .registry
        .store()
        .put_blob_ref(&account_id, AccountBlobKind::PublicRecord, &blob)?;
    Ok(Json(BlobResponse::from(blob)))
}

async fn get_public_record<S>(
    State(state): State<AppState<S>>,
    Path(account_id): Path<String>,
) -> ApiResult<Response>
where
    S: RegistryStore + Send + Sync + 'static,
{
    let account_id = parse_account_id(&account_id)?;
    let Some(blob) = state
        .registry
        .store()
        .blob_ref(&account_id, AccountBlobKind::PublicRecord)?
    else {
        return Err(ApiError::not_found("record not found"));
    };
    let Some(bytes) = state.blobs.get(&account_id, &blob)? else {
        return Err(ApiError::not_found("record blob not found"));
    };
    Ok((StatusCode::OK, bytes).into_response())
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

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
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
}

impl From<RegistryError> for ApiError {
    fn from(err: RegistryError) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: err.to_string(),
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

fn enforce_public_record_update<S: RegistryStore>(
    state: &AppState<S>,
    account_id: &AccountId,
    next: &SignedRecord,
    next_bytes: &[u8],
) -> ApiResult<()> {
    let Some(current_ref) = state
        .registry
        .store()
        .blob_ref(account_id, AccountBlobKind::PublicRecord)?
    else {
        return Ok(());
    };
    let Some(current_bytes) = state.blobs.get(account_id, &current_ref)? else {
        return Err(ApiError::not_found("current public record blob not found"));
    };
    let current = decode_signed_public_record(&current_bytes)?;
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
    Ok(())
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
    use mycellium_core::identity::{Handle, Identity, PeerId};
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
        ));
        (app, sender)
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
            device: Device::create(identity, PeerId(b"127.0.0.1:1".to_vec()), seq),
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

    #[tokio::test]
    async fn login_upload_and_lookup_public_record() {
        let (app, sender) = app_with_mail("flow");

        let (account_id, session_token) = login_session(&app, &sender).await;
        let public_record = signed_public_record_bytes(1);

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
    }

    #[tokio::test]
    async fn backup_requires_session() {
        let app = redb_router(tmpdir("auth")).unwrap();
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
    async fn public_record_update_rejects_other_user_and_rollback() {
        let (app, sender) = app_with_mail("record-update");
        let (account_id, session_token) = login_session(&app, &sender).await;
        let mut platform = TestPlatform(10);
        let identity = Identity::generate(&mut platform).unwrap();
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
}
