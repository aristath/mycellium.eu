//! Request authentication via **NIP-98** (HTTP Auth). A write request carries an
//! `Authorization: Nostr <base64-event>` header holding a kind-27235 event the
//! caller signed with their key. Verifying it proves control of that key, so the
//! registry can bind a name to `event.pubkey` — reusing a standard NIP rather
//! than inventing our own auth (the citizen-of-Nostr way).

use base64::Engine as _;
use nostr::hashes::{sha256::Hash as Sha256Hash, Hash as _};
use nostr::nips::nip98::{HttpData, HttpMethod};
use nostr::{Event, JsonUtil, Kind, PublicKey, Url};
use thiserror::Error;

/// How far an auth event's timestamp may be from the server clock (seconds).
const MAX_SKEW_SECS: u64 = 60;
const AUTH_PREFIX: &str = "Nostr ";

/// Why a NIP-98 `Authorization` header was rejected. Every variant maps to `401`.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing or malformed Authorization header (expected 'Nostr <base64>')")]
    Header,
    #[error("auth event is not valid JSON: {0}")]
    Json(String),
    #[error("auth event id/signature is invalid")]
    Signature,
    #[error("auth event is not a NIP-98 HTTP Auth event (kind 27235)")]
    Kind,
    #[error("auth event is missing its url/method tags: {0}")]
    Tags(String),
    #[error("auth is scoped to a different request (url/method mismatch)")]
    Scope,
    #[error("auth event timestamp is outside the allowed {MAX_SKEW_SECS}s window")]
    Stale,
    #[error("auth payload hash does not match the request body")]
    Payload,
}

/// Verify a NIP-98 header for the request `(method, url, body)` at wall-clock
/// `now` (unix seconds) and return the authenticated public key.
///
/// Checks, in order: header shape → event id+signature → kind 27235 → freshness
/// → the signed url/method match this request → for a non-empty body, the signed
/// `payload` tag equals `sha256(body)` (so the auth can't be replayed onto a
/// different body).
pub fn verify_http_auth(
    header: &str,
    method: HttpMethod,
    url: &Url,
    body: &[u8],
    now: u64,
) -> Result<PublicKey, AuthError> {
    let b64 = header.strip_prefix(AUTH_PREFIX).ok_or(AuthError::Header)?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| AuthError::Header)?;
    let event = Event::from_json(&raw).map_err(|e| AuthError::Json(e.to_string()))?;

    event.verify().map_err(|_| AuthError::Signature)?;
    if event.kind != Kind::HttpAuth {
        return Err(AuthError::Kind);
    }
    if now.abs_diff(event.created_at.as_secs()) > MAX_SKEW_SECS {
        return Err(AuthError::Stale);
    }

    let data =
        HttpData::try_from(event.tags.to_vec()).map_err(|e| AuthError::Tags(e.to_string()))?;
    if data.method != method || &data.url != url {
        return Err(AuthError::Scope);
    }
    if !body.is_empty() && data.payload != Some(Sha256Hash::hash(body)) {
        return Err(AuthError::Payload);
    }
    Ok(event.pubkey)
}
