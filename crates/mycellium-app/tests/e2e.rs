//! The app-engine acceptance proof, over a **real in-process relay** — nothing
//! is handed between devices directly. Every KeyPackage, device list, gift-wrapped
//! Welcome, commit, and message traverses the relay socket. State (MLS + app
//! data) is persisted to SQLCipher-encrypted SQLite; the restart step reopens the
//! store from disk.
//!
//! Scenario (mirrors the phase-4 acceptance test):
//! 1. **Alice** (single device) and **Bob** (account, 2 devices) set up: publish
//!    KeyPackages + device lists, connect, subscribe.
//! 2. Alice `add_contact(bob)`, `start_conversation(bob)` (enrols both Bob
//!    devices), `send_text("hi bob")`.
//! 3. Assert **both Bob devices** receive + persist "hi bob" in their transcript.
//! 4. Bob (dev-1) `send_text("hi alice")`; assert Alice receives + persists it.
//! 5. **Persistence:** reopen Alice's app against the same store; assert the
//!    transcript with Bob still holds both messages.
//! 6. **Key-change detection:** a *different* key publishes a device list claiming
//!    to be Bob; assert Alice's app raises `IdentityChanged` rather than silently
//!    trusting it, and the original pin is untouched.

use std::time::Duration;

use mycellium_app::{App, Device, TrustStatus};
use mycellium_multidevice::DeviceAccount;
use nostr::Keys;
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use tempfile::TempDir;

const RECV_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn app_engine_end_to_end_over_relay() {
    // ---- Relay ----------------------------------------------------------
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.expect("relay runs");
    let relay_url = relay.url().await;
    let relays = vec![relay_url.clone()];

    // ---- Per-device on-disk stores (persist across restart) -------------
    let alice_dir = TempDir::new().expect("alice dir");
    let bob1_dir = TempDir::new().expect("bob1 dir");
    let bob2_dir = TempDir::new().expect("bob2 dir");

    // ---- Identities -----------------------------------------------------
    let alice_keys = Keys::generate();
    let bob_account = Keys::generate();
    let bob_dev1_keys = Keys::generate();
    let bob_dev2_keys = Keys::generate();

    // ---- 1. Setup: open apps, connect, subscribe, publish identity ------
    let mut alice =
        App::open_solo(alice_keys.clone(), relays.clone(), alice_dir.path()).expect("open alice");
    // Bob dev-1 holds the account key (manager); dev-2 is an ordinary member.
    let mut bob1 = App::open_manager(
        bob_account.clone(),
        bob_dev1_keys.clone(),
        relays.clone(),
        bob1_dir.path(),
    )
    .expect("open bob1");
    let mut bob2 = App::open_member(
        bob_account.public_key(),
        bob_dev2_keys.clone(),
        relays.clone(),
        bob2_dir.path(),
    )
    .expect("open bob2");

    for app in [&alice, &bob1, &bob2] {
        app.connect().await.expect("connect");
    }
    // Subscribe (captures the receiver) before anything is published.
    alice.subscribe().await.expect("alice subscribe");
    bob1.subscribe().await.expect("bob1 subscribe");
    bob2.subscribe().await.expect("bob2 subscribe");

    // Bob's devices publish KeyPackages; the manager publishes the device list.
    bob1.publish_key_package().await.expect("bob1 kp");
    bob2.publish_key_package().await.expect("bob2 kp");
    bob1.publish_device_list(vec![
        Device::named(bob_dev1_keys.public_key(), "bob-dev-1"),
        Device::named(bob_dev2_keys.public_key(), "bob-dev-2"),
    ])
    .await
    .expect("bob device list");
    // Alice publishes her own KeyPackage + (solo) device list.
    alice.publish_key_package().await.expect("alice kp");
    alice
        .publish_device_list(vec![Device::named(alice_keys.public_key(), "alice")])
        .await
        .expect("alice device list");

    // ---- 2. Alice adds Bob, starts the conversation, sends --------------
    let status = alice
        .add_contact(
            "bob",
            bob_account.public_key(),
            Some("bob@example.com".into()),
            Some("Bob".into()),
        )
        .await
        .expect("add contact");
    assert_eq!(status, TrustStatus::Pinned, "first add pins TOFU");

    let convo = alice
        .start_conversation("bob")
        .await
        .expect("start conversation enrolls both Bob devices");

    alice
        .send_text(&convo, "hi bob")
        .await
        .expect("alice sends");

    // ---- 3. Both Bob devices receive + persist "hi bob" -----------------
    let m1 = bob1
        .next_message(RECV_TIMEOUT)
        .await
        .expect("bob1 recv ok")
        .expect("bob1 gets a message");
    let m2 = bob2
        .next_message(RECV_TIMEOUT)
        .await
        .expect("bob2 recv ok")
        .expect("bob2 gets a message");
    assert_eq!(m1.text, "hi bob", "bob-dev-1 decrypts");
    assert_eq!(m2.text, "hi bob", "bob-dev-2 decrypts");
    assert_eq!(
        m1.author,
        alice.device_pubkey(),
        "authored by Alice's device"
    );

    // Persisted in each device's transcript for that conversation.
    let t1 = bob1.transcript(&m1.conversation).expect("bob1 transcript");
    let t2 = bob2.transcript(&m2.conversation).expect("bob2 transcript");
    assert!(t1.iter().any(|m| m.text == "hi bob" && !m.from_me));
    assert!(t2.iter().any(|m| m.text == "hi bob" && !m.from_me));
    // The conversation is titled after Alice's group name ("Bob") on Bob's side.
    let bob1_convos = bob1.conversations().expect("bob1 convos");
    assert!(
        bob1_convos.iter().any(|(id, _)| id == &m1.conversation),
        "bob1 recorded the conversation"
    );

    // ---- 4. Bob (dev-1) replies; Alice receives + persists --------------
    bob1.send_text(&m1.conversation, "hi alice")
        .await
        .expect("bob1 replies");

    let back = alice
        .next_message(RECV_TIMEOUT)
        .await
        .expect("alice recv ok")
        .expect("alice gets Bob's reply");
    assert_eq!(back.text, "hi alice", "Alice decrypts Bob's reply");
    assert_eq!(back.conversation, convo, "same conversation");

    let alice_transcript = alice.transcript(&convo).expect("alice transcript");
    let texts: Vec<&str> = alice_transcript.iter().map(|m| m.text.as_str()).collect();
    assert!(texts.contains(&"hi bob"), "Alice's own send persisted");
    assert!(texts.contains(&"hi alice"), "Bob's reply persisted");

    // ---- 5. Persistence: reopen Alice's app from the same store ---------
    alice.shutdown().await;
    drop(alice);

    let mut alice_reopened = App::open_solo(alice_keys.clone(), relays.clone(), alice_dir.path())
        .expect("reopen alice from disk");
    alice_reopened.connect().await.expect("reconnect alice");
    let reopened = alice_reopened
        .transcript(&convo)
        .expect("reopened transcript");
    let reopened_texts: Vec<&str> = reopened.iter().map(|m| m.text.as_str()).collect();
    assert!(
        reopened_texts.contains(&"hi bob") && reopened_texts.contains(&"hi alice"),
        "both messages survive restart: {reopened_texts:?}"
    );
    // The pinned contact also survived restart.
    let bob_contact = alice_reopened
        .contact("bob")
        .expect("contact query")
        .expect("bob still pinned");
    assert_eq!(bob_contact.account, bob_account.public_key());

    // ---- 6. Key-change detection ----------------------------------------
    // A DIFFERENT key comes online claiming to be "Bob": it publishes a device
    // list to the relay (genuine traversal). Alice fetches it, then asks her
    // engine about this observed identity for the "bob" handle.
    let bob_imposter_account = Keys::generate();
    let imposter_dev = Keys::generate();
    let imposter = DeviceAccount::manager(
        bob_imposter_account.clone(),
        imposter_dev.clone(),
        relays.clone(),
    );
    imposter.connect().await.expect("imposter connect");
    imposter.publish_key_package().await.expect("imposter kp");
    imposter
        .publish_device_list(vec![Device::named(imposter_dev.public_key(), "imposter")])
        .await
        .expect("imposter device list");

    // Alice sees a live device list for the imposter key over the relay.
    let observed = alice_reopened
        .fetch_device_list(bob_imposter_account.public_key())
        .await
        .expect("fetch imposter list")
        .expect("imposter list must come back from the relay");
    assert_eq!(observed.account, bob_imposter_account.public_key());

    // The engine refuses to silently trust it as Bob.
    let verdict = alice_reopened
        .observe_identity("bob", bob_imposter_account.public_key())
        .expect("observe identity");
    assert_eq!(
        verdict,
        TrustStatus::IdentityChanged,
        "a different key for a pinned contact must raise IdentityChanged"
    );
    // Re-adding under the same handle with the new key is also refused (no re-pin).
    let readd = alice_reopened
        .add_contact("bob", bob_imposter_account.public_key(), None, None)
        .await
        .expect("re-add");
    assert_eq!(readd, TrustStatus::IdentityChanged, "re-pin refused");
    // The original pin is untouched.
    assert_eq!(
        alice_reopened
            .contact("bob")
            .expect("contact")
            .expect("still there")
            .account,
        bob_account.public_key(),
        "pin unchanged after an identity-change attempt"
    );

    // The matching key still classifies as trusted (sanity).
    assert_eq!(
        alice_reopened
            .observe_identity("bob", bob_account.public_key())
            .expect("observe real"),
        TrustStatus::Pinned,
    );

    for app in [&bob1, &bob2] {
        app.shutdown().await;
    }
    alice_reopened.shutdown().await;
    imposter.transport().shutdown().await;
}
