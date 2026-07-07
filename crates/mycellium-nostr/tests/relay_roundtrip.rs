//! End-to-end proof that the FULL MLS-over-Nostr (Marmot) flow traverses a
//! **real relay socket**. Nothing is handed between Alice and Bob directly:
//! every KeyPackage, gift-wrapped Welcome, and group message is published to an
//! in-process [`LocalRelay`] and pulled back out over a subscription / fetch.
//!
//! Flow: Bob publishes his KeyPackage → Alice fetches it, creates the group,
//! gift-wraps the Welcome, publishes it → Bob receives the gift wrap over his
//! subscription, unwraps + joins → Alice publishes a kind:445 group message →
//! Bob receives it over the relay and decrypts the plaintext.
//!
//! If the relay is not actually carrying the events the bounded waits below
//! return `None` and the test fails — there is no direct fallback path.

use std::time::Duration;

use mycellium_mls::{
    wire, EventBuilder, Keys, Kind, MlsEngine, NostrGroupConfigData, KIND_GROUP_MESSAGE,
};
use mycellium_nostr::NostrTransport;
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::Filter;

/// Generous but bounded ceilings so a slow CI box doesn't flake while a genuine
/// failure (relay not carrying events) still fails fast enough.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const RECV_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn full_marmot_flow_over_a_real_relay() {
    // 1. Start an in-process relay and learn its ws:// url.
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.expect("relay runs");
    let relay_url = relay.url().await;
    assert!(
        relay_url.to_string().starts_with("ws://127.0.0.1:"),
        "expected a loopback ws url, got {relay_url}"
    );

    // 2. Alice and Bob: keys, an MLS engine, and a transport connected to the relay.
    let alice_keys = Keys::generate();
    let bob_keys = Keys::generate();
    let alice_mls = MlsEngine::in_memory();
    let bob_mls = MlsEngine::in_memory();
    let alice = NostrTransport::new(&alice_keys);
    let bob = NostrTransport::new(&bob_keys);
    let relays = [relay_url.clone()];
    alice
        .connect(&relays, CONNECT_TIMEOUT)
        .await
        .expect("alice connects");
    bob.connect(&relays, CONNECT_TIMEOUT)
        .await
        .expect("bob connects");

    // 3. Bob publishes his KeyPackage (kind:30443) to the relay.
    let bob_kp = bob_mls
        .key_package_for(&bob_keys.public_key(), [relay_url.clone()])
        .expect("build key package");
    let bob_kp_event = wire::key_package_event(&bob_keys, &bob_kp)
        .await
        .expect("sign key package event");
    let published_kp_id = bob
        .publish(&bob_kp_event)
        .await
        .expect("publish key package");

    // 4. Alice FETCHES Bob's KeyPackage back off the relay, then creates the group.
    let fetched_kp = alice
        .fetch_key_package(bob_keys.public_key(), FETCH_TIMEOUT)
        .await
        .expect("fetch query")
        .expect("Bob's KeyPackage must come back from the relay");
    assert_eq!(
        fetched_kp.id, published_kp_id,
        "fetched KeyPackage must be the exact event Bob published"
    );

    let cfg = NostrGroupConfigData::new(
        "Alice & Bob".to_string(),
        "real-relay round-trip".to_string(),
        None,
        None,
        None,
        vec![relay_url.clone()],
        vec![alice_keys.public_key(), bob_keys.public_key()],
    );
    let created = alice_mls
        .create_group(&alice_keys.public_key(), vec![fetched_kp], cfg)
        .expect("create group");
    let gid = created.group.mls_group_id.clone();
    let welcome_rumor = created
        .welcome_rumors
        .first()
        .cloned()
        .expect("one welcome rumor");
    let gift = wire::gift_wrap_welcome(&alice_keys, &bob_keys.public_key(), welcome_rumor)
        .await
        .expect("gift-wrap welcome");

    // 5. Bob subscribes for gift wraps addressed to him AND kind:445 group
    //    messages, and grabs the notification stream BEFORE Alice publishes so
    //    nothing is missed. Then Alice publishes the gift wrap.
    bob.subscribe(
        Filter::new()
            .kind(Kind::GiftWrap)
            .pubkey(bob_keys.public_key()),
    )
    .await
    .expect("subscribe to gift wraps");
    bob.subscribe(Filter::new().kind(Kind::Custom(KIND_GROUP_MESSAGE)))
        .await
        .expect("subscribe to group messages");
    let mut incoming = bob.notifications();

    let published_gift_id = alice.publish(&gift).await.expect("publish gift wrap");

    // Bob receives the gift wrap over the relay, unwraps, and joins.
    let received_gift =
        NostrTransport::next_event(&mut incoming, RECV_TIMEOUT, |e| e.kind == Kind::GiftWrap)
            .await
            .expect("gift wrap must arrive over the relay");
    assert_eq!(
        received_gift.id, published_gift_id,
        "received gift wrap must be Alice's published event"
    );

    let recovered = wire::unwrap_welcome(&bob_keys, &received_gift)
        .await
        .expect("unwrap welcome");
    bob_mls
        .process_welcome(&received_gift.id, &recovered)
        .expect("process welcome");
    let pending = bob_mls.pending_welcomes().expect("pending welcomes");
    let welcome = pending.first().expect("one pending welcome");
    assert_eq!(welcome.member_count, 2);
    bob_mls.accept_welcome(welcome).expect("accept welcome");
    let gid_bob = bob_mls.groups().expect("groups")[0].mls_group_id.clone();
    assert_eq!(gid_bob, gid, "Bob joined the same MLS group");

    // 6. Alice publishes a kind:445 group message over the relay.
    let rumor = EventBuilder::new(Kind::Custom(9), "hello over a real relay")
        .build(alice_keys.public_key());
    let msg_event = alice_mls
        .encrypt_message(&gid, rumor)
        .expect("encrypt message");
    assert_eq!(msg_event.kind, Kind::Custom(KIND_GROUP_MESSAGE));
    alice.publish(&msg_event).await.expect("publish 445");

    // 7. Bob receives the 445 over the relay, processes it, and decrypts.
    let received_445 = NostrTransport::next_event(&mut incoming, RECV_TIMEOUT, |e| {
        e.kind == Kind::Custom(KIND_GROUP_MESSAGE)
    })
    .await
    .expect("group message must arrive over the relay");
    bob_mls
        .process_incoming(&received_445)
        .expect("process incoming 445");
    let messages = bob_mls.messages(&gid_bob).expect("messages");
    let decrypted = messages.first().expect("one decrypted message");
    assert_eq!(
        decrypted.content, "hello over a real relay",
        "plaintext must round-trip over the relay"
    );
    assert_eq!(decrypted.pubkey, alice_keys.public_key());

    alice.shutdown().await;
    bob.shutdown().await;
}
