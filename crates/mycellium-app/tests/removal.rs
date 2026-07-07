//! **Device removal with Post-Compromise Security**, end-to-end over a **real
//! in-process relay** — the counterpart to the pairing proof. Nothing is handed
//! between devices directly: the removal is a `remove_members` commit that
//! traverses the relay socket, and the whole point is what happens to the removed
//! device's ability to decrypt *afterwards*.
//!
//! Scenario:
//! 1. **Bob** is a manager account with **two** devices (`dev-1` = manager,
//!    `dev-2` = member), both enrolled in a 1:1 conversation with **Carol**.
//!    Carol sends `M1`; assert **both** Bob devices decrypt it (baseline: the
//!    account works before removal).
//! 2. dev-1 `remove_device(dev-2)` — dev-2 is dropped from the signed device list
//!    and its leaf is evicted from the group (a `remove_members` commit is
//!    published, advancing the epoch).
//! 3. Carol applies the eviction commit, then sends `M2` at the new epoch.
//! 4. **Assert dev-1 decrypts `M2`** but **dev-2 does NOT** — dev-2 was evicted at
//!    the prior epoch and never held the new epoch's keys. This is the PCS
//!    property: the removed device is cryptographically locked out of
//!    post-removal traffic.
//! 5. Assert dev-2 is absent from the refetched device list.
//! 6. Negatives: a member (non-manager) device calling `remove_device` gets
//!    [`mycellium_app::Error::NotManager`]; a manager removing its own current
//!    (here last) device is rejected.

use std::time::Duration;

use mycellium_app::{App, Device, TrustStatus};
use nostr::Keys;
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use tempfile::TempDir;

const RECV_TIMEOUT: Duration = Duration::from_secs(10);
const SETTLE: Duration = Duration::from_millis(600);
/// A drain window used to *prove a negative*: after M2 has already reached dev-1
/// over the same relay, dev-2 is given this long to surface any decryptable
/// message. It must surface none.
const LOCKOUT_DRAIN: Duration = Duration::from_millis(1200);

#[tokio::test]
async fn device_removal_locks_out_post_compromise_traffic() {
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

    // dev-1 is Bob's manager device (holds the account key); dev-2 is an ordinary
    // member device. Carol is a solo account.
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
    let mut carol =
        App::open_solo(carol_keys.clone(), relays.clone(), carol_dir.path()).expect("open carol");

    for app in [&bob1, &bob2, &carol] {
        app.connect().await.expect("connect");
    }
    bob1.subscribe().await.expect("bob1 subscribe");
    bob2.subscribe().await.expect("bob2 subscribe");
    carol.subscribe().await.expect("carol subscribe");

    // ---- 1. Baseline: BOTH Bob devices enrolled, both decrypt M1 --------
    // Both Bob devices advertise KeyPackages; Bob's list names both devices, so
    // Carol enrols both when she creates the conversation.
    bob1.publish_key_package().await.expect("bob1 kp");
    bob2.publish_key_package().await.expect("bob2 kp");
    bob1.publish_device_list(vec![
        Device::named(bob_dev1_keys.public_key(), "bob-dev-1"),
        Device::named(bob_dev2_keys.public_key(), "bob-dev-2"),
    ])
    .await
    .expect("bob device list {dev-1, dev-2}");
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
        .expect("carol starts the conversation enrolling both Bob devices");

    // Both Bob devices receive their gift-wrapped Welcome and join.
    bob1.pump(SETTLE).await.expect("bob1 joins");
    bob2.pump(SETTLE).await.expect("bob2 joins");
    assert!(
        bob1.conversations()
            .expect("bob1 convos")
            .iter()
            .any(|(id, _)| id == &convo),
        "dev-1 joined the conversation"
    );
    assert!(
        bob2.conversations()
            .expect("bob2 convos")
            .iter()
            .any(|(id, _)| id == &convo),
        "dev-2 joined the conversation"
    );

    carol
        .send_text(&convo, "M1 before removal")
        .await
        .expect("carol sends M1");

    let m1_dev1 = bob1
        .next_message(RECV_TIMEOUT)
        .await
        .expect("bob1 recv ok")
        .expect("dev-1 gets M1");
    let m1_dev2 = bob2
        .next_message(RECV_TIMEOUT)
        .await
        .expect("bob2 recv ok")
        .expect("dev-2 gets M1");
    assert_eq!(m1_dev1.text, "M1 before removal", "dev-1 decrypts baseline");
    assert_eq!(m1_dev2.text, "M1 before removal", "dev-2 decrypts baseline");

    // ---- 2. Manager (dev-1) removes dev-2 -------------------------------
    // Settle dev-1's view (its own echoed traffic) before it authors the eviction.
    bob1.pump(SETTLE).await.expect("bob1 settles");
    bob1.remove_device(bob_dev2_keys.public_key())
        .await
        .expect("dev-1 removes dev-2");

    // ---- 5. (checked early) dev-2 is gone from the refetched list -------
    let list = bob1
        .fetch_device_list(bob_account.public_key())
        .await
        .expect("fetch updated list")
        .expect("device list present");
    assert!(
        list.contains(&bob_dev1_keys.public_key()),
        "dev-1 still listed"
    );
    assert!(
        !list.contains(&bob_dev2_keys.public_key()),
        "dev-2 dropped from the device list after removal"
    );

    // ---- 3. Carol applies the eviction commit, then sends M2 ------------
    carol
        .pump(SETTLE)
        .await
        .expect("carol applies the eviction commit (epoch advance)");
    carol
        .send_text(&convo, "M2 after removal")
        .await
        .expect("carol sends M2 at the new epoch");

    // ---- 4. dev-1 decrypts M2; dev-2 is cryptographically locked out ----
    let m2_dev1 = bob1
        .next_message(RECV_TIMEOUT)
        .await
        .expect("bob1 recv ok")
        .expect("dev-1 gets M2");
    assert_eq!(
        m2_dev1.text, "M2 after removal",
        "dev-1 still decrypts post-removal traffic"
    );

    // M2 has now demonstrably traversed the relay (dev-1 got it). dev-2 shares that
    // relay + subscription, so the M2 event reaches it too — but it was evicted at
    // the prior epoch and cannot decrypt it. Draining dev-2 must surface NOTHING:
    // MDK rejects the ciphertext (use-after-eviction / wrong-epoch), which the
    // receive loop treats as unactionable and drops. This is the PCS lockout.
    let leaked = bob2.pump(LOCKOUT_DRAIN).await.expect("bob2 drains");
    assert!(
        leaked.iter().all(|m| m.text != "M2 after removal"),
        "PCS VIOLATION: removed dev-2 decrypted post-removal M2: {leaked:?}"
    );
    assert!(
        bob2.transcript(&convo)
            .unwrap_or_default()
            .iter()
            .all(|m| m.text != "M2 after removal"),
        "PCS VIOLATION: M2 landed in removed dev-2's transcript"
    );

    // ---- 6. Negatives ---------------------------------------------------
    // A member (non-manager) device cannot remove anything from the account.
    let member_attempt = bob2.remove_device(Keys::generate().public_key()).await;
    assert!(
        matches!(member_attempt, Err(mycellium_app::Error::NotManager)),
        "a non-manager device cannot remove a device: {member_attempt:?}"
    );
    // A manager cannot evict the device it is operating from (its own leaf) — which
    // for dev-1, now the account's sole device, is also the last-device case.
    let self_attempt = bob1.remove_device(bob1.device_pubkey()).await;
    assert!(
        matches!(
            self_attempt,
            Err(mycellium_app::Error::CannotRemoveCurrentDevice)
        ),
        "a manager cannot remove its own current device: {self_attempt:?}"
    );

    for app in [&bob1, &bob2, &carol] {
        app.shutdown().await;
    }
}
