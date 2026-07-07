//! **Secure device pairing**, end-to-end over a **real in-process relay** —
//! nothing is handed between devices directly. The pairing offer is the only thing
//! that crosses out of band (a copyable string / QR); everything else — the new
//! device's KeyPackage, the account device list, the fan-out `add_members` commit,
//! the gift-wrapped Welcome, and the messages — traverses the relay socket.
//!
//! Scenario:
//! 1. **Bob** is a manager account with one device (`dev-1`); **Carol** is solo.
//!    Carol starts a 1:1 with Bob and sends a message — Bob's dev-1 decrypts it
//!    (baseline: the account works before pairing).
//! 2. **Bob's new device (dev-2)** comes online, publishes its KeyPackage, and
//!    mints a [`PairingOffer`]. Assert the SAS the **manager** computes from the
//!    offer's pubkey **equals** the SAS the **new device** shows — the match check
//!    the human performs out of band.
//! 3. The manager (dev-1) `approve_device(offer)` — dev-2 is signed into the
//!    device list and fanned into the existing conversation.
//! 4. Carol (after applying the fan-out commit) sends another message; assert
//!    **dev-2 decrypts it** (it securely joined) AND dev-1 still does.
//! 5. Negative: a **tampered** offer (a swapped device pubkey) yields a
//!    **different** SAS than the real device's — the mismatch a MITM would cause is
//!    detectable, which is exactly the property that makes pairing secure.

use std::time::Duration;

use mycellium_app::{sas_for, App, Device, PairingOffer, TrustStatus};
use nostr::Keys;
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use tempfile::TempDir;

const RECV_TIMEOUT: Duration = Duration::from_secs(10);
const SETTLE: Duration = Duration::from_millis(600);

#[tokio::test]
async fn secure_device_pairing_over_relay() {
    // ---- Relay ----------------------------------------------------------
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.expect("relay runs");
    let relay_url = relay.url().await;
    let relays = vec![relay_url.clone()];

    // ---- On-disk stores -------------------------------------------------
    let bob1_dir = TempDir::new().expect("bob1 dir");
    let bob2_dir = TempDir::new().expect("bob2 dir");
    let carol_dir = TempDir::new().expect("carol dir");

    // ---- Identities -----------------------------------------------------
    let bob_account = Keys::generate();
    let bob_dev1_keys = Keys::generate();
    let bob_dev2_keys = Keys::generate();
    let carol_keys = Keys::generate();

    // dev-1 is Bob's manager device (holds the account key); Carol is solo.
    let mut bob1 = App::open_manager(
        bob_account.clone(),
        bob_dev1_keys.clone(),
        relays.clone(),
        bob1_dir.path(),
    )
    .expect("open bob1");
    let mut carol =
        App::open_solo(carol_keys.clone(), relays.clone(), carol_dir.path()).expect("open carol");

    for app in [&bob1, &carol] {
        app.connect().await.expect("connect");
    }
    bob1.subscribe().await.expect("bob1 subscribe");
    carol.subscribe().await.expect("carol subscribe");

    // ---- 1. Baseline: Bob (dev-1 only) messages with Carol --------------
    bob1.publish_key_package().await.expect("bob1 kp");
    bob1.publish_device_list(vec![Device::named(bob_dev1_keys.public_key(), "bob-dev-1")])
        .await
        .expect("bob device list {dev-1}");
    carol.publish_key_package().await.expect("carol kp");
    carol
        .publish_device_list(vec![Device::named(carol_keys.public_key(), "carol")])
        .await
        .expect("carol device list");

    let status = carol
        .add_contact("bob", bob_account.public_key(), None, Some("Bob".into()))
        .await
        .expect("carol pins bob");
    assert_eq!(status, TrustStatus::Pinned);

    let convo = carol
        .start_conversation("bob")
        .await
        .expect("carol starts the conversation with Bob");
    carol
        .send_text(&convo, "hi bob (dev-1 only)")
        .await
        .expect("carol sends baseline");

    let baseline = bob1
        .next_message(RECV_TIMEOUT)
        .await
        .expect("bob1 recv ok")
        .expect("bob1-dev-1 gets the baseline message");
    assert_eq!(
        baseline.text, "hi bob (dev-1 only)",
        "dev-1 decrypts baseline"
    );

    // ---- 2. Bob's new device (dev-2) comes online; mint an offer --------
    let mut bob2 = App::open_member(
        bob_account.public_key(),
        bob_dev2_keys.clone(),
        relays.clone(),
        bob2_dir.path(),
    )
    .expect("open bob2");
    bob2.connect().await.expect("bob2 connect");
    bob2.subscribe().await.expect("bob2 subscribe");
    bob2.publish_key_package().await.expect("bob2 kp");

    let offer = bob2.pairing_offer();
    assert_eq!(
        offer.device_pubkey,
        bob_dev2_keys.public_key(),
        "the offer carries the new device's own pubkey"
    );

    // The SAS-match check: the manager derives the SAS from the offer's pubkey and
    // it MUST equal the SAS the new device is showing on its own screen. (Both call
    // the one shared derivation — this is what the human compares out of band.)
    let manager_sas = sas_for(&offer.device_pubkey);
    assert_eq!(
        manager_sas,
        offer.sas(),
        "manager's computed SAS matches the new device's SAS"
    );
    // And it survives an offer that has round-tripped through its string encoding
    // (the QR/copy channel), as it does in the CLI.
    let relayed: PairingOffer = offer.to_string().parse().expect("offer round-trips");
    assert_eq!(sas_for(&relayed.device_pubkey), offer.sas());

    // ---- 3. Manager approves (SAS confirmed) → dev-2 pinned + fanned in --
    bob1.approve_device(&offer)
        .await
        .expect("manager approves dev-2 after SAS match");

    // The account's device list now names both devices.
    let list = bob1
        .fetch_device_list(bob_account.public_key())
        .await
        .expect("fetch updated list")
        .expect("device list present");
    assert!(list.contains(&bob_dev1_keys.public_key()), "dev-1 listed");
    assert!(
        list.contains(&bob_dev2_keys.public_key()),
        "dev-2 now listed after approval"
    );

    // dev-2 receives its gift-wrapped Welcome and joins the existing conversation;
    // Carol applies the fan-out commit so she encrypts at the new epoch.
    bob2.pump(SETTLE).await.expect("bob2 processes its Welcome");
    carol.pump(SETTLE).await.expect("carol applies the commit");

    assert!(
        bob2.conversations()
            .expect("bob2 convos")
            .iter()
            .any(|(id, _)| id == &convo),
        "dev-2 joined the existing conversation"
    );

    // ---- 4. Carol sends again; BOTH Bob devices decrypt -----------------
    carol
        .send_text(&convo, "hi bob (all devices)")
        .await
        .expect("carol sends post-pairing");

    let on_dev1 = bob1
        .next_message(RECV_TIMEOUT)
        .await
        .expect("bob1 recv ok")
        .expect("dev-1 still gets messages");
    let on_dev2 = bob2
        .next_message(RECV_TIMEOUT)
        .await
        .expect("bob2 recv ok")
        .expect("dev-2 gets the message it securely joined for");
    assert_eq!(on_dev1.text, "hi bob (all devices)", "dev-1 still decrypts");
    assert_eq!(
        on_dev2.text, "hi bob (all devices)",
        "dev-2 decrypts — it securely joined via pairing"
    );
    assert_eq!(on_dev1.conversation, convo);
    assert_eq!(on_dev2.conversation, convo);

    // ---- 5. Negative: a tampered offer has a different SAS --------------
    // A MITM swaps the pubkey on the copy/QR channel. The SAS the manager would
    // then compute no longer matches the real device's — the human sees a mismatch.
    let rogue_keys = Keys::generate();
    let tampered = PairingOffer::new(rogue_keys.public_key());
    assert_ne!(
        tampered.sas(),
        offer.sas(),
        "a swapped device pubkey yields a DIFFERENT SAS — the mismatch is detectable"
    );
    assert_eq!(
        sas_for(&rogue_keys.public_key()),
        tampered.sas(),
        "the SAS derivation is a pure function of the (rogue) pubkey"
    );

    // ---- 6. A member device cannot authorize a pairing -----------------
    // Only the account-key holder may sign a device into the list; dev-2 (a member)
    // must be refused even though it is now a valid device of the account.
    let another = Keys::generate();
    let member_attempt = bob2
        .approve_device(&PairingOffer::new(another.public_key()))
        .await;
    assert!(
        matches!(member_attempt, Err(mycellium_app::Error::NotManager)),
        "a non-manager device cannot approve a new device: {member_attempt:?}"
    );

    for app in [&bob1, &bob2, &carol] {
        app.shutdown().await;
    }
}
