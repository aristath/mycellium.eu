//! End-to-end exercise of the name service over its real router (no socket): a key
//! registers a name, it resolves via `/.well-known/nostr.json`, the anti-squat and
//! ownership rules hold, a name follows a key rotation (reassign) and can be
//! released — and every NIP-98 auth failure mode is rejected with `401`.

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use axum::Router;
use mycellium_names::{router, Policy, Registry};
use nostr::hashes::{sha256::Hash as Sha256Hash, Hash as _};
use nostr::nips::nip98::{HttpData, HttpMethod};
use nostr::{Keys, Url};
use serde_json::{json, Value};
use tower::ServiceExt;

const DOMAIN: &str = "mycellium.eu";

fn app() -> Router {
    let registry = Registry::open_in_memory(Policy::default()).unwrap();
    router(Arc::new(registry))
}

/// A NIP-98-signed POST for `path` carrying `body`, exactly as a client sends it.
async fn signed_post(keys: &Keys, path: &str, body: &Value) -> Request<Body> {
    let bytes = serde_json::to_vec(body).unwrap();
    let url = Url::parse(&format!("https://{DOMAIN}/{path}")).unwrap();
    let auth = HttpData::new(url, HttpMethod::POST)
        .payload(Sha256Hash::hash(&bytes))
        .to_authorization(keys)
        .await
        .unwrap();
    Request::builder()
        .method("POST")
        .uri(format!("/{path}"))
        .header(header::AUTHORIZATION, auth)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(bytes))
        .unwrap()
}

async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn resolve(app: &Router, name: &str) -> Value {
    let req = Request::builder()
        .uri(format!("/.well-known/nostr.json?name={name}"))
        .body(Body::empty())
        .unwrap();
    send(app, req).await.1
}

#[tokio::test]
async fn register_resolve_reassign_release_and_the_rules() {
    let app = app();
    let alice = Keys::generate();
    let alice_hex = alice.public_key().to_hex();

    // --- register -> 201, bound to the signer -----------------------------
    let (status, body) = send(
        &app,
        signed_post(
            &alice,
            "register",
            &json!({"name": "Alice", "relays": ["wss://relay.mycellium.eu"]}),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "register: {body}");
    assert_eq!(body["name"], "alice@mycellium.eu");
    assert_eq!(body["pubkey"], alice_hex);

    // --- resolves via NIP-05, name lowercased, relays echoed --------------
    let wk = resolve(&app, "alice").await;
    assert_eq!(wk["names"]["alice"], alice_hex);
    assert_eq!(wk["relays"][&alice_hex][0], "wss://relay.mycellium.eu");

    // an unknown name -> empty names map (NIP-05 "unverified")
    assert_eq!(resolve(&app, "nobody").await, json!({"names": {}}));

    // --- rules: taken, per-key limit, reserved, charset -------------------
    let bob = Keys::generate();
    let (status, _) = send(
        &app,
        signed_post(&bob, "register", &json!({"name": "alice"})).await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "a taken name is refused");

    let (status, _) = send(
        &app,
        signed_post(&alice, "register", &json!({"name": "alice2"})).await,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "one key, one name (default policy)"
    );

    let (status, _) = send(
        &app,
        signed_post(&bob, "register", &json!({"name": "admin"})).await,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a reserved name is refused"
    );

    // --- reassign: alice's name follows a key rotation to `carol` ---------
    let carol = Keys::generate();
    let carol_hex = carol.public_key().to_hex();
    // only the current owner may reassign: bob trying -> 403
    let (status, _) = send(
        &app,
        signed_post(
            &bob,
            "reassign",
            &json!({"name": "alice", "new_pubkey": carol_hex}),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "non-owner cannot reassign");
    // the real owner (alice) can
    let (status, _) = send(
        &app,
        signed_post(
            &alice,
            "reassign",
            &json!({"name": "alice", "new_pubkey": carol_hex}),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner reassigns");
    assert_eq!(resolve(&app, "alice").await["names"]["alice"], carol_hex);

    // --- release: only the new owner (carol) can now ----------------------
    let (status, _) = send(
        &app,
        signed_post(&alice, "release", &json!({"name": "alice"})).await,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "old owner can no longer release"
    );
    let (status, _) = send(
        &app,
        signed_post(&carol, "release", &json!({"name": "alice"})).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "current owner releases");
    assert_eq!(
        resolve(&app, "alice").await,
        json!({"names": {}}),
        "name is free again"
    );
}

#[tokio::test]
async fn auth_failures_are_rejected() {
    let app = app();
    let keys = Keys::generate();

    // 1. missing Authorization header
    let req = Request::builder()
        .method("POST")
        .uri("/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(br#"{"name":"x"}"#.to_vec()))
        .unwrap();
    assert_eq!(
        send(&app, req).await.0,
        StatusCode::UNAUTHORIZED,
        "no header"
    );

    // 2. wrong scope: a header signed for /register replayed onto /reassign
    let mut req = signed_post(&keys, "register", &json!({"name": "x"})).await;
    let auth = req.headers().get(header::AUTHORIZATION).unwrap().clone();
    let mut replay = Request::builder()
        .method("POST")
        .uri("/reassign")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            br#"{"name":"x","new_pubkey":"deadbeef"}"#.to_vec(),
        ))
        .unwrap();
    replay.headers_mut().insert(header::AUTHORIZATION, auth);
    assert_eq!(
        send(&app, replay).await.0,
        StatusCode::UNAUTHORIZED,
        "cross-endpoint replay"
    );

    // 3. tampered body: valid header for one body, a different body sent
    let auth2 = req.headers_mut().remove(header::AUTHORIZATION).unwrap();
    let mut tampered = Request::builder()
        .method("POST")
        .uri("/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(br#"{"name":"different"}"#.to_vec()))
        .unwrap();
    tampered.headers_mut().insert(header::AUTHORIZATION, auth2);
    assert_eq!(
        send(&app, tampered).await.0,
        StatusCode::UNAUTHORIZED,
        "payload hash mismatch"
    );
}
