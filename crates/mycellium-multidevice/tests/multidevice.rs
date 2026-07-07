//! The multi-device proof, over a **real in-process relay** — nothing is handed
//! between devices directly. Every KeyPackage, device list, gift-wrapped Welcome,
//! commit, and message traverses the relay socket; if the relay is not actually
//! carrying an event the bounded waits below return `None` and the test fails.
//!
//! Scenario:
//! 1. Account **Bob** has two devices (`bob-dev-1`, `bob-dev-2`), each its own
//!    MLS engine + KeyPackage; Bob publishes a device list `{dev-1, dev-2}`.
//! 2. **Carol** (single device) messages Bob's *account*: she fetches Bob's
//!    device list, fetches BOTH device KeyPackages, creates a group enrolling
//!    both, gift-wraps a Welcome to each, and sends a kind:445 message.
//! 3. Assert **both** bob-dev-1 AND bob-dev-2 receive + decrypt it.
//! 4. A **third** device (`bob-dev-3`) comes online; an existing Bob device
//!    fans it into the group (commit + Welcome); Carol applies the commit and
//!    sends another message; assert **dev-3 also decrypts** it — and dev-1/dev-2
//!    still do.

use std::time::Duration;

use mycellium_mls::{GroupId, Keys, Kind};
use mycellium_multidevice::{DeviceAccount, DeviceEntry, Incoming, KIND_GROUP_MESSAGE};
use mycellium_nostr::NostrTransport;
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::Event;
use tokio::sync::broadcast;

const RECV_TIMEOUT: Duration = Duration::from_secs(10);

/// Await the next kind:445 event on `incoming`, route it through `dev`, and keep
/// going until a decrypted [`Incoming::Message`] surfaces — transparently
/// applying any intervening commit (epoch advance) first. Fails if no message
/// arrives before the timeout.
async fn recv_message(
    dev: &DeviceAccount,
    incoming: &mut broadcast::Receiver<mycellium_nostr::Notification>,
) -> (GroupId, String) {
    loop {
        let event: Event = NostrTransport::next_event(incoming, RECV_TIMEOUT, |e| {
            e.kind == Kind::Custom(KIND_GROUP_MESSAGE)
        })
        .await
        .expect("a kind:445 event must arrive over the relay");

        match dev.process_incoming(&event).await.expect("process 445") {
            Incoming::Message { group, content, .. } => return (group, content),
            Incoming::CommitApplied { .. } | Incoming::Ignored => continue,
            other => panic!("unexpected 445 outcome: {other:?}"),
        }
    }
}

/// Await and apply the next kind:445 **commit** on `incoming` via `dev`.
async fn recv_commit(
    dev: &DeviceAccount,
    incoming: &mut broadcast::Receiver<mycellium_nostr::Notification>,
) {
    loop {
        let event: Event = NostrTransport::next_event(incoming, RECV_TIMEOUT, |e| {
            e.kind == Kind::Custom(KIND_GROUP_MESSAGE)
        })
        .await
        .expect("a kind:445 commit must arrive over the relay");
        match dev.process_incoming(&event).await.expect("process commit") {
            Incoming::CommitApplied { .. } => return,
            Incoming::Ignored => continue,
            other => panic!("expected a commit, got: {other:?}"),
        }
    }
}

/// Await and accept a gift-wrapped Welcome on `incoming` via `dev`, returning the
/// joined group id.
async fn recv_join(
    dev: &DeviceAccount,
    incoming: &mut broadcast::Receiver<mycellium_nostr::Notification>,
) -> GroupId {
    let event: Event =
        NostrTransport::next_event(incoming, RECV_TIMEOUT, |e| e.kind == Kind::GiftWrap)
            .await
            .expect("a gift-wrapped Welcome must arrive over the relay");
    match dev.process_incoming(&event).await.expect("process welcome") {
        Incoming::Joined { group } => group,
        other => panic!("expected a join, got: {other:?}"),
    }
}

#[tokio::test]
async fn one_account_many_devices_all_receive() {
    // ---- Relay ----------------------------------------------------------
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.expect("relay runs");
    let relay_url = relay.url().await;
    let relays = vec![relay_url.clone()];

    // ---- Identities -----------------------------------------------------
    // Bob: one account key + three device keys. Carol: a single-device account.
    let bob_account = Keys::generate();
    let bob_dev1_keys = Keys::generate();
    let bob_dev2_keys = Keys::generate();
    let bob_dev3_keys = Keys::generate();
    let carol_keys = Keys::generate();

    // dev-1 holds the account key (it manages Bob's device list); dev-2/dev-3 are
    // ordinary member devices. Carol is a solo account.
    let bob_dev1 =
        DeviceAccount::manager(bob_account.clone(), bob_dev1_keys.clone(), relays.clone());
    let bob_dev2 = DeviceAccount::member(
        bob_account.public_key(),
        bob_dev2_keys.clone(),
        relays.clone(),
    );
    let bob_dev3 = DeviceAccount::member(
        bob_account.public_key(),
        bob_dev3_keys.clone(),
        relays.clone(),
    );
    let carol = DeviceAccount::solo(carol_keys.clone(), relays.clone());

    for dev in [&bob_dev1, &bob_dev2, &bob_dev3, &carol] {
        dev.connect().await.expect("connect");
    }

    // ---- 1. Bob's two devices publish KeyPackages; Bob publishes a list ----
    bob_dev1.publish_key_package().await.expect("dev1 kp");
    bob_dev2.publish_key_package().await.expect("dev2 kp");
    bob_dev1
        .publish_device_list(vec![
            DeviceEntry::named(bob_dev1_keys.public_key(), "bob-dev-1"),
            DeviceEntry::named(bob_dev2_keys.public_key(), "bob-dev-2"),
        ])
        .await
        .expect("publish device list");

    // Sanity: Carol resolves Bob's account to BOTH devices off the relay.
    let fetched = carol
        .fetch_device_list(bob_account.public_key())
        .await
        .expect("fetch device list")
        .expect("Bob's device list must come back from the relay");
    assert_eq!(fetched.devices.len(), 2, "Bob lists two devices");
    assert!(fetched.contains(&bob_dev1_keys.public_key()));
    assert!(fetched.contains(&bob_dev2_keys.public_key()));

    // ---- 2. Both Bob devices subscribe; Carol creates the group -----------
    bob_dev1.subscribe_incoming().await.expect("dev1 subscribe");
    bob_dev2.subscribe_incoming().await.expect("dev2 subscribe");
    let mut dev1_in = bob_dev1.transport().notifications();
    let mut dev2_in = bob_dev2.transport().notifications();

    // Carol also subscribes so she can apply the fan-out commit later.
    carol.subscribe_incoming().await.expect("carol subscribe");
    let mut carol_in = carol.transport().notifications();

    let group = carol
        .create_group_with(
            &[bob_account.public_key()],
            "Bob & Carol",
            "multi-device proof",
        )
        .await
        .expect("create group enrolling all of Bob's devices");

    // Both devices receive their gift-wrapped Welcome and join the same group.
    let joined1 = recv_join(&bob_dev1, &mut dev1_in).await;
    let joined2 = recv_join(&bob_dev2, &mut dev2_in).await;
    assert_eq!(joined1, group, "dev-1 joined Carol's group");
    assert_eq!(joined2, group, "dev-2 joined Carol's group");

    // ---- 3. Carol messages the account; BOTH devices decrypt --------------
    carol
        .send_message(&group, "hi bob (all devices)")
        .await
        .expect("carol sends");

    let (g1, m1) = recv_message(&bob_dev1, &mut dev1_in).await;
    let (g2, m2) = recv_message(&bob_dev2, &mut dev2_in).await;
    assert_eq!(g1, group);
    assert_eq!(g2, group);
    assert_eq!(m1, "hi bob (all devices)", "dev-1 decrypts");
    assert_eq!(m2, "hi bob (all devices)", "dev-2 decrypts");

    // ---- 4. A third device comes online and is fanned into the group ------
    bob_dev3.publish_key_package().await.expect("dev3 kp");
    bob_dev3.subscribe_incoming().await.expect("dev3 subscribe");
    let mut dev3_in = bob_dev3.transport().notifications();

    // An existing Bob device (dev-1, an admin) enrolls dev-3 into every group.
    let fanned = bob_dev1
        .add_device_to_all_groups(bob_dev3_keys.public_key())
        .await
        .expect("fan dev-3 into all groups");
    assert_eq!(fanned, 1, "dev-3 was fanned into the one existing group");

    // dev-2 and Carol apply the commit (epoch advance); dev-3 joins via Welcome.
    recv_commit(&bob_dev2, &mut dev2_in).await;
    recv_commit(&carol, &mut carol_in).await;
    let joined3 = recv_join(&bob_dev3, &mut dev3_in).await;
    assert_eq!(joined3, group, "dev-3 joined the same group");

    // Carol sends a second message at the new epoch; all THREE devices decrypt.
    carol
        .send_message(&group, "and hello dev-3")
        .await
        .expect("carol sends again");

    let (_, r1) = recv_message(&bob_dev1, &mut dev1_in).await;
    let (_, r2) = recv_message(&bob_dev2, &mut dev2_in).await;
    let (_, r3) = recv_message(&bob_dev3, &mut dev3_in).await;
    assert_eq!(r1, "and hello dev-3", "dev-1 still decrypts post-fan-out");
    assert_eq!(r2, "and hello dev-3", "dev-2 still decrypts post-fan-out");
    assert_eq!(r3, "and hello dev-3", "dev-3 decrypts the new message");

    for dev in [&bob_dev1, &bob_dev2, &bob_dev3, &carol] {
        dev.transport().shutdown().await;
    }
}
