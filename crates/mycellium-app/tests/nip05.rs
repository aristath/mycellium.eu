//! **NIP-05 verification + rebinding detection** — with a *stub* resolver, no real
//! network. NIP-05 is an additional binding to verify against the trust pin, never
//! an identity override; these tests prove exactly that:
//!
//! 1. Parse/display round-trip for `alice@mycellium.eu` and `_@mycellium.eu`.
//! 2. `add_contact_by_nip05` pins the resolved key (TOFU) and records the binding
//!    verified; `verify_nip05` returns `Verified`.
//! 3. **Rebinding detection:** flip the stub so the name resolves to an attacker
//!    key → `verify_nip05` returns `Mismatch{attacker}` (NOT Verified), the pin is
//!    **untouched** (no auto-re-pin), and the mismatch is surfaced as the trust
//!    signal `TrustEvent::Nip05Mismatch`.
//! 4. `Unreachable` on resolver error; the name-not-found error path.

use std::collections::HashMap;
use std::sync::Mutex;

use mycellium_app::{
    App, Nip05Address, Nip05Record, Nip05Resolver, Nip05Status, ResolveError, TrustEvent,
    TrustStatus,
};
use nostr::{Keys, PublicKey};
use tempfile::TempDir;

/// What the stub should do for a given address on resolve.
enum Outcome {
    /// Resolve to this key.
    Maps(PublicKey),
    /// The name is absent from the domain's `nostr.json`.
    NotFound,
    /// The endpoint is unreachable (network error).
    Network,
}

/// A fully in-memory NIP-05 resolver: no DNS, no TLS. The mapping is mutable so a
/// test can *rebind* a name to a different key mid-flight (the attack we detect).
#[derive(Default)]
struct StubResolver {
    map: Mutex<HashMap<String, Outcome>>,
}

impl StubResolver {
    fn set(&self, address: &str, outcome: Outcome) {
        self.map
            .lock()
            .unwrap()
            .insert(address.to_string(), outcome);
    }
}

impl Nip05Resolver for StubResolver {
    async fn resolve(&self, address: &Nip05Address) -> Result<Nip05Record, ResolveError> {
        let key = address.to_string();
        match self.map.lock().unwrap().get(&key) {
            Some(Outcome::Maps(pubkey)) => Ok(Nip05Record {
                pubkey: *pubkey,
                relays: Vec::new(),
            }),
            Some(Outcome::NotFound) => Err(ResolveError::NameNotFound(key)),
            Some(Outcome::Network) | None => {
                Err(ResolveError::Network(key, "stub: unreachable".into()))
            }
        }
    }
}

/// A solo app with on-disk stores but no relay connection — the stub-resolver
/// paths (pin + resolve) never touch the network, so no relay is needed.
fn open_app(dir: &TempDir) -> App {
    App::open_solo(Keys::generate(), Vec::new(), dir.path()).expect("open app")
}

#[test]
fn parse_display_round_trip() {
    for input in ["alice@mycellium.eu", "_@mycellium.eu"] {
        let addr = Nip05Address::parse(input).expect("parse");
        assert_eq!(addr.to_string(), input);
    }
    // `_@domain` is the domain-root identity.
    assert!(Nip05Address::parse("_@mycellium.eu").unwrap().is_root());
}

#[tokio::test]
async fn add_by_nip05_pins_and_verifies() {
    let dir = TempDir::new().unwrap();
    let mut app = open_app(&dir);

    let bob = Keys::generate().public_key();
    let addr = Nip05Address::parse("bob@mycellium.eu").unwrap();
    let resolver = StubResolver::default();
    resolver.set("bob@mycellium.eu", Outcome::Maps(bob));

    // add_contact_by_nip05 pins bob_pubkey (TOFU) and records the binding verified.
    let status = app
        .add_contact_by_nip05(&resolver, &addr, Some("bob".into()))
        .await
        .expect("add by nip05");
    assert_eq!(status, TrustStatus::Pinned);

    let contact = app.contact("bob").unwrap().expect("contact stored");
    assert_eq!(contact.account, bob, "the RESOLVED key is what got pinned");
    assert_eq!(contact.nip05.as_deref(), Some("bob@mycellium.eu"));
    assert!(contact.nip05_verified, "the binding is recorded verified");

    // verify_nip05 re-resolves and confirms the binding still holds.
    assert_eq!(
        app.verify_nip05(&resolver, "bob").await.unwrap(),
        Nip05Status::Verified
    );
}

#[tokio::test]
async fn rebinding_is_detected_and_never_auto_repins() {
    let dir = TempDir::new().unwrap();
    let mut app = open_app(&dir);

    let bob = Keys::generate().public_key();
    let attacker = Keys::generate().public_key();
    let addr = Nip05Address::parse("bob@mycellium.eu").unwrap();
    let resolver = StubResolver::default();
    resolver.set("bob@mycellium.eu", Outcome::Maps(bob));

    app.add_contact_by_nip05(&resolver, &addr, Some("bob".into()))
        .await
        .expect("add by nip05");

    // The domain operator (or an impersonator) rebinds the name to a DIFFERENT key.
    resolver.set("bob@mycellium.eu", Outcome::Maps(attacker));

    // verify_nip05 flags the rebinding — NOT Verified.
    assert_eq!(
        app.verify_nip05(&resolver, "bob").await.unwrap(),
        Nip05Status::Mismatch {
            resolved_pubkey: attacker
        },
        "a name now pointing at a different key must be a Mismatch, never Verified"
    );

    // The pin is UNTOUCHED — no auto-re-pin to the attacker's key.
    let contact = app.contact("bob").unwrap().expect("still there");
    assert_eq!(
        contact.account, bob,
        "the pin must NOT move to the rebound key"
    );

    // The mismatch is surfaced through the trust layer as a distinct signal.
    let signal = app
        .verify_nip05_signal(&resolver, "bob")
        .await
        .expect("signal ok");
    assert_eq!(
        signal,
        Some(TrustEvent::Nip05Mismatch {
            contact: "bob".into(),
            address: "bob@mycellium.eu".into(),
            resolved_pubkey: attacker,
        }),
        "a rebinding must surface as the Nip05Mismatch trust signal"
    );
}

#[tokio::test]
async fn unreachable_and_name_not_found_paths() {
    let dir = TempDir::new().unwrap();
    let mut app = open_app(&dir);

    let bob = Keys::generate().public_key();
    let addr = Nip05Address::parse("bob@mycellium.eu").unwrap();
    let resolver = StubResolver::default();
    resolver.set("bob@mycellium.eu", Outcome::Maps(bob));
    app.add_contact_by_nip05(&resolver, &addr, Some("bob".into()))
        .await
        .expect("add");

    // Endpoint down → the binding cannot be confirmed → Unreachable (not Mismatch).
    resolver.set("bob@mycellium.eu", Outcome::Network);
    assert_eq!(
        app.verify_nip05(&resolver, "bob").await.unwrap(),
        Nip05Status::Unreachable
    );

    // Name-not-found is a distinct typed error surfaced from resolution.
    let missing = Nip05Address::parse("ghost@mycellium.eu").unwrap();
    resolver.set("ghost@mycellium.eu", Outcome::NotFound);
    let err = app
        .add_contact_by_nip05(&resolver, &missing, Some("ghost".into()))
        .await
        .expect_err("name-not-found must be an error");
    assert!(
        matches!(
            err,
            mycellium_app::Error::Nip05Resolve(ResolveError::NameNotFound(_))
        ),
        "expected NameNotFound, got: {err}"
    );
    // A failed add pins nothing.
    assert!(app.contact("ghost").unwrap().is_none());
}
