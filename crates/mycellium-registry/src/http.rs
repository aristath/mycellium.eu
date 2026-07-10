//! Tiny HTTP API for the registry core.
//!
//! This layer exposes account UX only. It does not store, queue, relay, or route
//! messages.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::{
    AccountBlobKind, AccountId, FileBlobStore, LoginIdentityHash, RedbRegistryStore, Registry,
    RegistryError, RegistryStore, Result,
};

const LOGIN_TTL_SECS: i64 = 15 * 60;
const SESSION_TTL_SECS: i64 = 30 * 24 * 60 * 60;
const EMAIL_LOGIN_LIMIT: u64 = 5;

/// HTTP app state.
pub struct AppState<S> {
    registry: Arc<Registry<S>>,
    blobs: FileBlobStore,
}

impl<S> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            registry: Arc::clone(&self.registry),
            blobs: self.blobs.clone(),
        }
    }
}

impl<S: RegistryStore> AppState<S> {
    /// Build app state from a registry and blob store.
    pub fn new(registry: Registry<S>, blobs: FileBlobStore) -> Self {
        Self {
            registry: Arc::new(registry),
            blobs,
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
    /// Development placeholder until a real email sender is wired in.
    dev_token: String,
}

async fn request_email_login<S>(
    State(state): State<AppState<S>>,
    Json(body): Json<EmailLoginRequest>,
) -> ApiResult<Json<EmailLoginResponse>>
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
    Ok(Json(EmailLoginResponse {
        expires_at: challenge.expires_at,
        dev_token: challenge.token,
    }))
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
    use serde_json::Value;
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

    async fn response_json(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn login_upload_and_lookup_public_record() {
        let app = redb_router(tmpdir("flow")).unwrap();

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
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        let login_token = body["dev_token"].as_str().unwrap();

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
        let account_id = body["account_id"].as_str().unwrap();
        let session_token = body["session_token"].as_str().unwrap();

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/accounts/{account_id}/record"))
                    .header("authorization", format!("Bearer {session_token}"))
                    .body(Body::from("signed-public-record"))
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
        assert_eq!(&bytes[..], b"signed-public-record");
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
        let app = redb_router(tmpdir("rate")).unwrap();

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
            assert_eq!(response.status(), StatusCode::OK);
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
}
