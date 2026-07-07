//! **Account-key rotation / identity migration**, end-to-end over a **real
//! in-process relay**. The account key is the Nostr identity and the signer of the
//! device list; this proves an account can rotate it (hygiene or post-compromise
//! recovery) and have a contact **safely** transition trust — never automatically.
//!
//! The security property under test is the *refusal to auto-accept*: a migration,
//! even one carrying valid signatures from both the old and new keys, is surfaced
//! as a signal that requires out-of-band re-verification before the contact
//! re-pins. A migration not signed by the pinned old key is rejected outright.
//!
//! Scenario:
//! 1. **Alice** (solo) and **Bob** (manager: account key ≠ device key) message
//!    normally — Alice pins Bob's account key (baseline TOFU).
//! 2. **Bob `rotate_account_key()`** → publishes the mutual old→new migration
//!    attestation and re-signs + republishes the device list under the new key.
//!    Bob's *device* key is unchanged, so the MLS group is untouched.
//! 3. Alice `detect_migration("bob")` → a `PendingReverification` signal that (a)
//!    verified the old+new mutual signatures and (b) did **NOT** silently re-pin:
//!    Bob's pin is still the old key.
//! 4. Alice compares the new safety number out of band (it matches), then
//!    `accept_key_migration` → the pin is now the new key, and Alice keeps
//!    messaging Bob over the same MLS conversation under the new identity, whose
//!    new-key-signed device list she can resolve.
//! 5. **Forgery negative:** a migration whose old key is NOT Bob's pinned key
//!    (attacker-fabricated) classifies as `Forged` — not acceptable, not pinned.
//! 6. **Equivocation honesty** (documented): a *compromised* old key could sign
//!    two conflicting-but-individually-valid migrations. Both would surface as
//!    `PendingReverification`; the app auto-accepts neither. Only the out-of-band
//!    safety-number compare distinguishes the legitimate one — the signature
//!    cannot. See the assertions and comments at the end.

use std::time::Duration;

use mycellium_app::{App, Device, MigrationSignal, TrustStatus};
use mycellium_multidevice::migration;
use nostr::Keys;
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use tempfile::TempDir;

const RECV_TIMEOUT: Duration = Duration::from_secs(10);
const SETTLE: Duration = Duration::from_millis(600);

#[tokio::test]
async fn account_key_rotation_migrates_trust_without_auto_accept() {
    // ---- Relay ----------------------------------------------------------
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.expect("relay runs");
    let relay_url = relay.url().await;
    let relays = vec![relay_url.clone()];

    // ---- On-disk stores -------------------------------------------------
    let alice_dir = TempDir::new().expect("alice dir");
    let bob_dir = TempDir::new().expect("bob dir");

    // ---- Identities -----------------------------------------------------
    let alice_keys = Keys::generate();
    let bob_account = Keys::generate(); // Bob's OLD account key (what Alice pins)
    let bob_dev_keys = Keys::generate(); // Bob's device key — NEVER changes

    let mut alice =
        App::open_solo(alice_keys.clone(), relays.clone(), alice_dir.path()).expect("open alice");
    // Bob is a manager: account key ≠ device key, so rotating the account leaves
    // the device leaf (and thus every MLS group) untouched.
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

    // ---- 1. Baseline: Alice pins Bob's OLD account key, they message ----
    bob.publish_key_package().await.expect("bob kp");
    bob.publish_device_list(vec![Device::named(bob_dev_keys.public_key(), "bob-phone")])
        .await
        .expect("bob device list (old key)");
    alice.publish_key_package().await.expect("alice kp");
    alice
        .publish_device_list(vec![Device::named(alice_keys.public_key(), "alice")])
        .await
        .expect("alice device list");

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
        .expect("bob gets baseline message");
    assert_eq!(m.text, "before rotation", "baseline conversation works");

    // ---- 2. Bob rotates his account key ---------------------------------
    // Settle Bob's own echoed traffic before he authors the rotation.
    bob.pump(SETTLE).await.expect("bob settles");
    let bob_new_keys = bob
        .rotate_account_key()
        .await
        .expect("bob rotates account key")
        .new_keys;
    assert_ne!(
        bob_new_keys.public_key(),
        bob_account.public_key(),
        "rotation produced a genuinely new key"
    );
    assert_eq!(
        bob.account(),
        bob_new_keys.public_key(),
        "Bob's own account identity is now the new key"
    );
    // Give the relay a moment to accept the migration + new device list.
    bob.pump(SETTLE).await.expect("bob settles post-rotation");

    // ---- 3. Alice detects the migration — but is NOT auto-migrated ------
    let signal = alice
        .detect_migration("bob")
        .await
        .expect("alice probes for a migration");
    let (old_pubkey, new_pubkey, alice_side_number) = match signal {
        MigrationSignal::PendingReverification {
            old_pubkey,
            new_pubkey,
            new_safety_number,
        } => (old_pubkey, new_pubkey, new_safety_number),
        other => panic!("expected a valid pending migration, got {other:?}"),
    };
    // (a) The mutual old+new signatures verified and named the right identities.
    assert_eq!(old_pubkey, bob_account.public_key(), "old key = pinned key");
    assert_eq!(
        new_pubkey,
        bob_new_keys.public_key(),
        "new key = Bob's new key"
    );

    // (b) THE SECURITY: detection did not silently re-pin. Bob's pin is unchanged.
    let still_pinned = alice.contact("bob").expect("contact").expect("bob").account;
    assert_eq!(
        still_pinned,
        bob_account.public_key(),
        "a detected migration must NOT auto-re-pin — the old key is still pinned"
    );

    // The new key, observed as a raw device-list identity, still classifies as a
    // hard IdentityChanged until the user accepts — never silently trusted.
    assert_eq!(
        alice
            .observe_identity("bob", bob_new_keys.public_key())
            .expect("observe new key"),
        TrustStatus::IdentityChanged,
        "the new key is an identity change until the user accepts the migration"
    );

    // ---- 4. Out-of-band re-verification, then accept --------------------
    // Alice reads her new safety number to Bob (who computes the same value from
    // his new account key vs. Alice) — they match. Only THEN does she accept.
    let bob_side_number =
        mycellium_app::safety_number(&bob_new_keys.public_key(), &alice.account());
    assert_eq!(
        alice_side_number, bob_side_number,
        "the out-of-band safety numbers for the NEW identity match on both sides"
    );

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

    // Alice can now resolve Bob's NEW-key-signed device list (same device leaf).
    let new_list = alice
        .fetch_device_list(bob_new_keys.public_key())
        .await
        .expect("fetch new-key device list")
        .expect("new-key device list is published");
    assert_eq!(new_list.account, bob_new_keys.public_key());
    assert!(
        new_list.contains(&bob_dev_keys.public_key()),
        "the device leaf is unchanged across the account rotation"
    );

    // And messaging continues over the SAME MLS conversation under the new identity.
    alice
        .send_text(&convo, "after rotation")
        .await
        .expect("alice messages Bob under the new identity");
    let after = bob
        .next_message(RECV_TIMEOUT)
        .await
        .expect("bob recv ok")
        .expect("bob still decrypts on the same MLS group");
    assert_eq!(
        after.text, "after rotation",
        "the conversation survives account-key rotation untouched"
    );

    // ---- 5. Forgery negative --------------------------------------------
    // An attacker fabricates a migration and publishes it, but they do NOT hold
    // Bob's (old) pinned key, so the attestation's old key is the attacker's own —
    // not the key Alice pinned. Classifying it for "bob" rejects it outright: a
    // migration must be authored by the very key we pinned. (The complementary
    // case — an event whose CONTENT claims Bob's key but is signed by someone else —
    // is rejected by `verify_migration` itself; see the multidevice unit tests.)
    let attacker_old = Keys::generate();
    let attacker_new = Keys::generate();
    let forged = migration::build_migration(&attacker_old, &attacker_new)
        .await
        .expect("attacker builds a (self-consistent but irrelevant) migration");
    let verdict = alice
        .classify_migration("bob", &forged)
        .expect("classify the forged migration");
    match verdict {
        MigrationSignal::Forged { .. } => {}
        other => {
            panic!("a migration not signed by the pinned old key must be Forged, got {other:?}")
        }
    }
    // The forgery changed nothing: the pin is still Bob's (accepted) new key.
    assert_eq!(
        alice.contact("bob").expect("contact").expect("bob").account,
        bob_new_keys.public_key(),
        "a forged migration must not alter the pin"
    );

    // ---- 6. Equivocation honesty (documented, asserted where testable) --
    // A COMPROMISED old key can sign two conflicting migrations, each individually
    // valid (both signed by the old key + a new key). `verify_migration` would
    // accept EITHER — the signature alone cannot say which is legitimate. The app
    // never auto-accepts: both surface as `PendingReverification`, and only the
    // out-of-band safety-number compare (step 4) tells them apart. We assert the
    // engine treats a second, differently-keyed valid migration as pending, not as
    // an automatic re-pin. (Here we craft it from Alice's already-rotated pin only
    // to show the shape; a real attacker would author it under the compromised key.)
    let rival_new = Keys::generate();
    let rival = migration::build_migration(&bob_new_keys, &rival_new)
        .await
        .expect("a rival valid migration signed by the (now-pinned) key");
    let rival_verdict = alice
        .classify_migration("bob", &rival)
        .expect("classify the rival migration");
    assert!(
        matches!(rival_verdict, MigrationSignal::PendingReverification { .. }),
        "a second valid migration is still only PENDING — never auto-accepted: {rival_verdict:?}"
    );

    alice.shutdown().await;
    bob.shutdown().await;
}
