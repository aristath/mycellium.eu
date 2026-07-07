//! **Live trust subscriptions** — phase 9, over a **real in-process relay**.
//!
//! Phases 4/8 gave the app key-change / migration / device-list detection, but
//! only *pull*-based: a contact's account-key migration (30445) or device-list
//! change (30444) was noticed only when the user explicitly fetched. This proves
//! the detection is now **passive and live**: Alice pins Bob, sits in the receive
//! loop, and the instant Bob rotates his key or changes his device list, Alice's
//! loop *emits* a trust event — with **no fetch/detect call** — while never
//! auto-accepting anything.
//!
//! What is asserted:
//! 1. Baseline: Alice (solo) pins Bob (manager: account key ≠ device key), starts a
//!    conversation, they message.
//! 2. **Bob `rotate_account_key()`** → Alice's `next_event` LIVE-emits
//!    `KeyMigrationPending{ new_pubkey = Bob's new key, new_safety_number }` with no
//!    fetch — and Bob's pin is STILL the old key (not auto-changed). Only after the
//!    (asserted-matching) safety number does Alice `accept_key_migration`, moving
//!    the pin.
//! 3. **Bob adds a device** (publishes an updated 30444 under his new key) → Alice's
//!    loop LIVE-emits `ContactDevicesChanged{ contact = bob, devices ∋ new device }`.
//! 4. **Forgery negative:** a 30445 for Bob authored by a NON-pinned key is NOT
//!    surfaced as a pending migration (dropped) and the pin is untouched.
//!
//! Every wait is bounded and driven by the subscription, never a manual fetch.

use std::time::Duration;

use mycellium_app::{App, AppEvent, Device, MigrationSignal, TrustEvent, TrustStatus};
use mycellium_multidevice::migration;
use nostr::Keys;
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use tempfile::TempDir;

const RECV_TIMEOUT: Duration = Duration::from_secs(10);
const SETTLE: Duration = Duration::from_millis(600);

/// Drive Alice's receive loop until it yields a trust event (or time out). This is
/// the LIVE path — it only ever calls `next_event`, never a fetch/detect.
async fn next_trust(app: &mut App, timeout: Duration) -> Option<TrustEvent> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match app.next_event(remaining).await.expect("next_event ok") {
            Some(AppEvent::Trust(t)) => return Some(t),
            Some(AppEvent::Message(_)) => continue, // ignore interleaved messages
            None => return None,
        }
    }
    None
}

#[tokio::test]
async fn live_trust_subscription_emits_migration_and_device_change() {
    // ---- Relay ----------------------------------------------------------
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.expect("relay runs");
    let relays = vec![relay.url().await];

    // ---- On-disk stores -------------------------------------------------
    let alice_dir = TempDir::new().expect("alice dir");
    let bob_dir = TempDir::new().expect("bob dir");

    // ---- Identities -----------------------------------------------------
    let alice_keys = Keys::generate();
    let bob_account = Keys::generate(); // Bob's OLD account key (what Alice pins)
    let bob_dev_keys = Keys::generate(); // Bob's device key — NEVER changes
    let bob_dev2_keys = Keys::generate(); // the device Bob adds in step 3

    let mut alice =
        App::open_solo(alice_keys.clone(), relays.clone(), alice_dir.path()).expect("open alice");
    let mut bob = App::open_manager(
        bob_account.clone(),
        bob_dev_keys.clone(),
        relays.clone(),
        bob_dir.path(),
    )
    .expect("open bob");

    for app in [&alice, &bob] {
        app.connect().await.expect("connect");
    }
    alice.subscribe().await.expect("alice subscribe");
    bob.subscribe().await.expect("bob subscribe");

    // ---- 1. Baseline: Bob announces, Alice pins his OLD key, they talk ---
    bob.publish_key_package().await.expect("bob kp");
    bob.publish_device_list(vec![Device::named(bob_dev_keys.public_key(), "bob-phone")])
        .await
        .expect("bob device list (old key)");
    alice.publish_key_package().await.expect("alice kp");
    alice
        .publish_device_list(vec![Device::named(alice_keys.public_key(), "alice")])
        .await
        .expect("alice device list");

    // Pinning Bob widens Alice's live trust subscription to Bob's account key and
    // seeds the device-list baseline (so the initial re-delivery is not a "change").
    let status = alice
        .add_contact("bob", bob_account.public_key(), None, Some("Bob".into()))
        .await
        .expect("alice pins bob");
    assert_eq!(
        status,
        TrustStatus::Pinned,
        "baseline TOFU pin on the old key"
    );

    let convo = alice
        .start_conversation("bob")
        .await
        .expect("alice starts the conversation");
    bob.pump(SETTLE).await.expect("bob joins");
    alice
        .send_text(&convo, "before rotation")
        .await
        .expect("send");
    let m = bob
        .next_message(RECV_TIMEOUT)
        .await
        .expect("bob recv ok")
        .expect("bob gets the baseline message");
    assert_eq!(m.text, "before rotation", "baseline conversation works");

    // Settle Alice's loop so the seeded device-list re-delivery is consumed and
    // does NOT count as a change (proves the baseline suppresses startup noise).
    let noise = alice.drain_events(SETTLE).await.expect("drain settle");
    assert!(
        !noise
            .iter()
            .any(|e| matches!(e, AppEvent::Trust(TrustEvent::ContactDevicesChanged { .. }))),
        "the initial unchanged device list must NOT surface as a change: {noise:?}"
    );

    // ---- 2. Bob rotates his account key → Alice LIVE-emits pending -------
    bob.pump(SETTLE).await.expect("bob settles pre-rotation");
    let bob_new_keys = bob
        .rotate_account_key()
        .await
        .expect("bob rotates")
        .new_keys;
    assert_ne!(
        bob_new_keys.public_key(),
        bob_account.public_key(),
        "rotation produced a genuinely new key"
    );

    // THE LIVE ASSERTION: Alice never calls detect/fetch — the subscription
    // delivers the 30445, and her receive loop emits the pending signal.
    let trust = next_trust(&mut alice, RECV_TIMEOUT)
        .await
        .expect("alice LIVE-emits a trust event on Bob's rotation");
    let (old_pubkey, new_pubkey, alice_side_number) = match trust {
        TrustEvent::KeyMigrationPending {
            contact,
            old_pubkey,
            new_pubkey,
            new_safety_number,
        } => {
            assert_eq!(
                contact, "bob",
                "the migration is attributed to the pinned contact"
            );
            (old_pubkey, new_pubkey, new_safety_number)
        }
        other => panic!("expected KeyMigrationPending, got {other:?}"),
    };
    assert_eq!(old_pubkey, bob_account.public_key(), "old key = pinned key");
    assert_eq!(
        new_pubkey,
        bob_new_keys.public_key(),
        "new key = Bob's new key"
    );

    // NO AUTO-ACCEPT: the live signal did not touch the pin — it is still the OLD key.
    assert_eq!(
        alice.contact("bob").expect("contact").expect("bob").account,
        bob_account.public_key(),
        "a LIVE migration signal must NOT auto-re-pin — the old key is still pinned"
    );

    // Out-of-band re-verification: Alice's new safety number matches Bob's side.
    let bob_side_number =
        mycellium_app::safety_number(&bob_new_keys.public_key(), &alice.account());
    assert_eq!(
        alice_side_number, bob_side_number,
        "the out-of-band safety numbers for the NEW identity match on both sides"
    );

    // Only now, after the matching compare, does Alice accept — moving the pin.
    alice
        .accept_key_migration("bob", bob_new_keys.public_key())
        .await
        .expect("alice accepts the re-verified migration");
    let repinned = alice.contact("bob").expect("contact").expect("bob");
    assert_eq!(
        repinned.account,
        bob_new_keys.public_key(),
        "after acceptance the pin follows the new key"
    );
    assert!(
        repinned.verified,
        "acceptance records the out-of-band verification"
    );

    // ---- 3. Bob adds a device → Alice LIVE-emits ContactDevicesChanged --
    // Bob is now on his new account key; acceptance moved Alice's live subscription
    // to follow it, so his new-key 30444 reaches her. He publishes an updated list
    // that adds a second device.
    bob.publish_device_list(vec![
        Device::named(bob_dev_keys.public_key(), "bob-phone"),
        Device::named(bob_dev2_keys.public_key(), "bob-laptop"),
    ])
    .await
    .expect("bob publishes an updated device list (adds a device)");

    let trust = next_trust(&mut alice, RECV_TIMEOUT)
        .await
        .expect("alice LIVE-emits a device-change event");
    match trust {
        TrustEvent::ContactDevicesChanged { contact, devices } => {
            assert_eq!(contact, "bob");
            assert!(
                devices
                    .iter()
                    .any(|d| d.pubkey == bob_dev2_keys.public_key()),
                "the changed device list includes the newly added device"
            );
            assert!(
                devices
                    .iter()
                    .any(|d| d.pubkey == bob_dev_keys.public_key()),
                "the original device is still listed"
            );
        }
        other => panic!("expected ContactDevicesChanged, got {other:?}"),
    }

    // ---- 4. Forgery negative --------------------------------------------
    // An attacker (a key Alice never pinned) publishes a real, self-consistent
    // 30445 migration by rotating its own account key — it traverses the relay
    // just like a legitimate one. Because it is not authored by Bob's pinned key,
    // Alice's author-scoped subscription does not deliver it and her loop guard
    // (verify + pinned-key match) would drop it regardless: no pending migration
    // is ever surfaced, and Bob's pin is untouched.
    let pin_before = alice.contact("bob").expect("contact").expect("bob").account;
    let attacker_account = Keys::generate();
    let attacker_dev = Keys::generate();
    let attacker_dir = TempDir::new().expect("attacker dir");
    let mut attacker = App::open_manager(
        attacker_account.clone(),
        attacker_dev.clone(),
        relays.clone(),
        attacker_dir.path(),
    )
    .expect("open attacker");
    attacker.connect().await.expect("attacker connect");
    attacker.publish_key_package().await.expect("attacker kp");
    attacker
        .publish_device_list(vec![Device::new(attacker_dev.public_key())])
        .await
        .expect("attacker device list");
    // Publishes a genuine 30445 authored by the attacker's (non-pinned) key.
    let _attacker_new = attacker
        .rotate_account_key()
        .await
        .expect("attacker publishes a migration by rotating its own key");

    let stray = alice
        .drain_events(SETTLE)
        .await
        .expect("drain after forgery");
    assert!(
        !stray
            .iter()
            .any(|e| matches!(e, AppEvent::Trust(TrustEvent::KeyMigrationPending { .. }))),
        "a migration NOT signed by the pinned key must never surface as pending: {stray:?}"
    );
    assert_eq!(
        alice.contact("bob").expect("contact").expect("bob").account,
        pin_before,
        "a forged/irrelevant migration must not alter the pin"
    );

    // And the loop guard itself (mirrored by the public `classify_migration`)
    // rejects such an attestation for Bob outright, never as pending.
    let forged_for_bob = migration::build_migration(&attacker_account, &attacker_dev)
        .await
        .expect("build a self-consistent but irrelevant migration");
    match alice
        .classify_migration("bob", &forged_for_bob)
        .expect("classify")
    {
        MigrationSignal::Forged { .. } => {}
        other => panic!("a migration not signed by Bob's pinned key must be Forged, got {other:?}"),
    }

    alice.shutdown().await;
    bob.shutdown().await;
}
