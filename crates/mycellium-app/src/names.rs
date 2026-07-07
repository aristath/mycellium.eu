//! Client for a NIP-05 **name service** (our `mycellium-names` server, or any
//! compatible host): claim or release a `name@domain` binding by POSTing a
//! NIP-98-signed request to the domain's registration endpoints.
//!
//! The domain in the address *is* the service host — `alice@mycellium.eu` registers
//! against `https://mycellium.eu/register` — so there is nothing extra to configure.
//! The request is signed with the **account** key (proving control of the identity
//! the name will point at); the blocking HTTP call runs on a `spawn_blocking` worker,
//! matching the NIP-05 resolver, so it never stalls the async runtime.

use nostr::hashes::{sha256::Hash as Sha256Hash, Hash as _};
use nostr::nips::nip98::{HttpData, HttpMethod};
use nostr::{Keys, PublicKey, Url};
use serde_json::json;

use crate::nip05::Nip05Address;

/// A failure talking to the name service.
#[derive(Debug, thiserror::Error)]
pub enum NameError {
    /// The `https://{domain}/{path}` request URL could not be built.
    #[error("invalid name-service domain '{0}'")]
    Url(String),
    /// The NIP-98 authorization event could not be signed.
    #[error("could not sign the name-service request: {0}")]
    Sign(String),
    /// The request never completed (DNS/TLS/connection/read error).
    #[error("name-service request failed: {0}")]
    Network(String),
    /// The server answered, but rejected the request (taken, reserved, not owner…).
    #[error("name service rejected the request ({status}): {message}")]
    Rejected { status: u16, message: String },
}

/// Register `address` for the account: `POST /register {name, relays}`.
pub async fn register(
    account_keys: &Keys,
    address: &Nip05Address,
    relays: &[String],
) -> Result<(), NameError> {
    let url = endpoint(address, "register")?;
    let transport = url.to_string();
    let body = json!({ "name": address.name(), "relays": relays });
    post_signed(account_keys, url, transport, body)
        .await
        .map(drop)
}

/// Point `address` at `new_pubkey` — a `POST /reassign {name, new_pubkey, relays}`
/// authorized by the **current** owner (`account_keys`). Used to carry a name to a
/// rotated account key.
pub async fn reassign(
    account_keys: &Keys,
    address: &Nip05Address,
    new_pubkey: PublicKey,
    relays: &[String],
) -> Result<(), NameError> {
    let url = endpoint(address, "reassign")?;
    let transport = url.to_string();
    let body = json!({
        "name": address.name(),
        "new_pubkey": new_pubkey.to_hex(),
        "relays": relays,
    });
    post_signed(account_keys, url, transport, body)
        .await
        .map(drop)
}

/// Release `address` at its domain's name service: `POST /release {name}`.
pub async fn release(account_keys: &Keys, address: &Nip05Address) -> Result<(), NameError> {
    let url = endpoint(address, "release")?;
    let transport = url.to_string();
    post_signed(
        account_keys,
        url,
        transport,
        json!({ "name": address.name() }),
    )
    .await
    .map(drop)
}

fn endpoint(address: &Nip05Address, path: &str) -> Result<Url, NameError> {
    Url::parse(&format!("https://{}/{path}", address.domain()))
        .map_err(|_| NameError::Url(address.domain().to_string()))
}

/// Sign `body` with NIP-98 for `POST signed_url` (the canonical `https://{domain}`
/// URL the server verifies against) and send it to `transport_url` (normally the
/// same, but separable so a name service can be reached off-domain). Returns the
/// response body on 2xx; maps a non-2xx to [`NameError::Rejected`] carrying the
/// server's `{"error": …}` message.
async fn post_signed(
    account_keys: &Keys,
    signed_url: Url,
    transport_url: String,
    body: serde_json::Value,
) -> Result<String, NameError> {
    let bytes = serde_json::to_vec(&body).expect("a serde_json::Value serializes");
    let auth = HttpData::new(signed_url, HttpMethod::POST)
        .payload(Sha256Hash::hash(&bytes))
        .to_authorization(account_keys)
        .await
        .map_err(|e| NameError::Sign(e.to_string()))?;
    let url = transport_url;

    tokio::task::spawn_blocking(move || {
        match ureq::post(&url)
            .set("Authorization", &auth)
            .set("Content-Type", "application/json")
            .send_bytes(&bytes)
        {
            Ok(resp) => resp
                .into_string()
                .map_err(|e| NameError::Network(e.to_string())),
            Err(ureq::Error::Status(status, resp)) => {
                let raw = resp.into_string().unwrap_or_default();
                let message = serde_json::from_str::<serde_json::Value>(&raw)
                    .ok()
                    .and_then(|v| v.get("error").and_then(|e| e.as_str().map(String::from)))
                    .unwrap_or(raw);
                Err(NameError::Rejected { status, message })
            }
            Err(e) => Err(NameError::Network(e.to_string())),
        }
    })
    .await
    .map_err(|e| NameError::Network(e.to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::IntoFuture;
    use std::sync::Arc;

    use mycellium_names::{router, Policy, Registry};
    use nostr::Keys;

    /// The client registers a name against the **real** `mycellium-names` server
    /// over a genuine socket: the account signs `https://mycellium.eu/register`
    /// (canonical) while the request is transported to the test's local server
    /// (configured with the same domain, so the signature verifies), and the name
    /// ends up bound to the signing key.
    #[tokio::test(flavor = "multi_thread")]
    async fn registers_and_releases_against_the_real_server() {
        let registry = Arc::new(Registry::open_in_memory(Policy::default()).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, router(registry.clone())).into_future());

        let keys = Keys::generate();
        let address = Nip05Address::parse("alice@mycellium.eu").unwrap();

        // register: sign the canonical https URL, ship it to the local server.
        post_signed(
            &keys,
            endpoint(&address, "register").unwrap(),
            format!("http://{addr}/register"),
            json!({ "name": address.name(), "relays": ["wss://relay.mycellium.eu"] }),
        )
        .await
        .expect("register succeeds");

        let rec = registry.resolve("alice").expect("alice is now registered");
        assert_eq!(rec.pubkey, keys.public_key(), "bound to the signing key");

        // reassign: carry the name to a rotated key, authed by the *old* key.
        let rotated = Keys::generate();
        post_signed(
            &keys,
            endpoint(&address, "reassign").unwrap(),
            format!("http://{addr}/reassign"),
            json!({ "name": address.name(), "new_pubkey": rotated.public_key().to_hex() }),
        )
        .await
        .expect("reassign succeeds");
        assert_eq!(
            registry.resolve("alice").unwrap().pubkey,
            rotated.public_key(),
            "name now points at the rotated key"
        );

        // release: only the new owner (the rotated key) can now free it.
        post_signed(
            &rotated,
            endpoint(&address, "release").unwrap(),
            format!("http://{addr}/release"),
            json!({ "name": address.name() }),
        )
        .await
        .expect("release succeeds");
        assert!(registry.resolve("alice").is_none(), "name freed");
    }
}
