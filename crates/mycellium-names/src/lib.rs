//! **`mycellium-names`** — the `@mycellium.eu` NIP-05 name service.
//!
//! Nostr already owns the name↔key binding ([NIP-05]): a client resolves
//! `alice@mycellium.eu` by fetching `/.well-known/nostr.json?name=alice` and
//! reading the npub back. This crate is the *server* side of that binding for a
//! domain we operate — the "controlled namespace" of the project's direction: the
//! npub stays open and portable, while the human-readable name under our domain is
//! one we issue under a policy.
//!
//! It does three things:
//! 1. **Serve** `/.well-known/nostr.json` (the resolution clients already speak).
//! 2. **Register** a `name → npub` binding, self-service, authenticated with
//!    [NIP-98] (the caller signs the request, proving control of the key).
//! 3. **Reassign / release** a name — also NIP-98-authed by the current owner, so
//!    a name can follow an account-key rotation and nobody can grab a live name.
//!
//! The hardened *verification* of this binding (rebinding/mismatch detection) lives
//! in the client (`mycellium-app`'s `nip05` layer); the server just publishes the
//! signed truth honestly.
//!
//! [NIP-05]: https://github.com/nostr-protocol/nips/blob/master/05.md
//! [NIP-98]: https://github.com/nostr-protocol/nips/blob/master/98.md

mod auth;
mod policy;
mod registry;

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use nostr::nips::nip98::HttpMethod;
use nostr::{PublicKey, RelayUrl, Url};
use serde::Deserialize;
use serde_json::json;

pub use auth::{verify_http_auth, AuthError};
pub use policy::{Policy, PolicyError};
pub use registry::{NameRecord, Registry, RegistryError};

/// Shared handler state: the registry behind an `Arc`.
#[derive(Clone)]
struct AppState {
    registry: Arc<Registry>,
}

/// Build the router for a given registry — the whole HTTP surface, so tests can
/// drive it with `tower::ServiceExt::oneshot` without binding a socket.
pub fn router(registry: Arc<Registry>) -> Router {
    Router::new()
        .route("/.well-known/nostr.json", get(well_known))
        .route("/register", post(register))
        .route("/reassign", post(reassign))
        .route("/release", post(release))
        .with_state(AppState { registry })
}

#[derive(Deserialize)]
struct WellKnownQuery {
    name: Option<String>,
}

/// NIP-05 resolution. Public, cacheable, and CORS-open (clients fetch it
/// cross-origin), returning `{"names": {..}, "relays": {..}}`.
async fn well_known(State(st): State<AppState>, Query(q): Query<WellKnownQuery>) -> Response {
    let body = match q.name {
        Some(name) => st.registry.well_known(&name),
        None => json!({ "names": {} }),
    };
    ([(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], Json(body)).into_response()
}

#[derive(Deserialize)]
struct RegisterBody {
    name: String,
    #[serde(default)]
    relays: Vec<String>,
}

/// Register `name → the authenticated key`. NIP-98-authed; the name binds to the
/// signer of the auth event, never to a key named in the body.
async fn register(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let pubkey = match authenticate(&st, &headers, HttpMethod::POST, "register", &body) {
        Ok(pk) => pk,
        Err((s, m)) => return error(s, &m),
    };
    let req: RegisterBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let relays = match parse_relays(&req.relays) {
        Ok(r) => r,
        Err(msg) => return error(StatusCode::BAD_REQUEST, &msg),
    };
    match st.registry.register(&req.name, pubkey, relays) {
        Ok(name) => bound(&st, StatusCode::CREATED, &name, &pubkey),
        Err(e) => registry_error(e),
    }
}

#[derive(Deserialize)]
struct ReassignBody {
    name: String,
    new_pubkey: String,
    #[serde(default)]
    relays: Vec<String>,
}

/// Point a name at a new key, authed by its **current** owner — the name follows
/// an account-key rotation without anyone else being able to seize it.
async fn reassign(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let owner = match authenticate(&st, &headers, HttpMethod::POST, "reassign", &body) {
        Ok(pk) => pk,
        Err((s, m)) => return error(s, &m),
    };
    let req: ReassignBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let new_pubkey = match parse_pubkey(&req.new_pubkey) {
        Ok(pk) => pk,
        Err(msg) => return error(StatusCode::BAD_REQUEST, &msg),
    };
    let relays = match parse_relays(&req.relays) {
        Ok(r) => r,
        Err(msg) => return error(StatusCode::BAD_REQUEST, &msg),
    };
    match st.registry.reassign(&req.name, owner, new_pubkey, relays) {
        Ok(name) => bound(&st, StatusCode::OK, &name, &new_pubkey),
        Err(e) => registry_error(e),
    }
}

#[derive(Deserialize)]
struct ReleaseBody {
    name: String,
}

/// Release a name, authed by its owner. (NIP-98 has no DELETE method, so this is
/// a payload-bound POST like the other writes.)
async fn release(State(st): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let owner = match authenticate(&st, &headers, HttpMethod::POST, "release", &body) {
        Ok(pk) => pk,
        Err((s, m)) => return error(s, &m),
    };
    let req: ReleaseBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    match st.registry.release(&req.name, owner) {
        Ok(name) => (StatusCode::OK, Json(json!({ "released": name }))).into_response(),
        Err(e) => registry_error(e),
    }
}

/// Verify the NIP-98 header for `(method, our-domain/path, body)` and return the
/// authenticated key, or a `(401, reason)` the caller turns into a response.
fn authenticate(
    st: &AppState,
    headers: &HeaderMap,
    method: HttpMethod,
    path: &str,
    body: &[u8],
) -> Result<PublicKey, (StatusCode, String)> {
    let reject = |msg: String| (StatusCode::UNAUTHORIZED, msg);
    let header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| reject("missing Authorization header".to_string()))?;
    // Pin the expected URL to our public domain (not the raw socket address) so a
    // TLS-terminating reverse proxy in front of us doesn't break the signature.
    let url = Url::parse(&format!("https://{}/{}", st.registry.policy().domain, path))
        .expect("domain+path is a valid https url");
    verify_http_auth(header, method, &url, body, unix_now()).map_err(|e| reject(e.to_string()))
}

/// A successful bind/reassign response: the full `name@domain` and its key.
fn bound(st: &AppState, status: StatusCode, name: &str, pubkey: &PublicKey) -> Response {
    let address = format!("{name}@{}", st.registry.policy().domain);
    (
        status,
        Json(json!({ "name": address, "pubkey": pubkey.to_hex() })),
    )
        .into_response()
}

fn registry_error(e: RegistryError) -> Response {
    let status = match &e {
        RegistryError::Policy(_) => StatusCode::BAD_REQUEST,
        RegistryError::Taken | RegistryError::KeyLimit(_) => StatusCode::CONFLICT,
        RegistryError::NotFound => StatusCode::NOT_FOUND,
        RegistryError::NotOwner => StatusCode::FORBIDDEN,
        RegistryError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error(status, &e.to_string())
}

fn error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn parse_pubkey(s: &str) -> Result<PublicKey, String> {
    let s = s.trim();
    if s.starts_with("npub1") {
        PublicKey::parse(s).map_err(|e| format!("invalid npub: {e}"))
    } else {
        PublicKey::from_hex(s).map_err(|e| format!("invalid pubkey: {e}"))
    }
}

fn parse_relays(relays: &[String]) -> Result<Vec<RelayUrl>, String> {
    relays
        .iter()
        .map(|r| RelayUrl::parse(r).map_err(|e| format!("invalid relay url '{r}': {e}")))
        .collect()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
