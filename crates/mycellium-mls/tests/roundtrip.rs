//! End-to-end proof that the wrapper drives a real MLS-over-Nostr round-trip:
//! Alice creates a group, adds Bob via his KeyPackage, gift-wraps the Welcome,
//! Bob unwraps + joins, Alice sends an encrypted message that Bob decrypts, then
//! a key rotation advances the epoch on both sides and a post-rotation message
//! still decrypts. Ported from the MDK de-risking spike, hardened to exercise
//! the NIP-59 gift-wrap path through the wrapper's `wire` helpers.

use mycellium_mls::{wire, EventBuilder, Keys, Kind, MlsEngine, NostrGroupConfigData, RelayUrl};

#[tokio::test]
async fn marmot_roundtrip_with_rotation() {
    let relay = RelayUrl::parse("ws://localhost:8080").unwrap();

    let alice_keys = Keys::generate();
    let bob_keys = Keys::generate();
    let alice = MlsEngine::in_memory();
    let bob = MlsEngine::in_memory();

    // 1. Bob builds and "publishes" a KeyPackage event (kind:30443).
    let bob_kp = bob
        .key_package_for(&bob_keys.public_key(), [relay.clone()])
        .expect("key package");
    let bob_kp_event = wire::key_package_event(&bob_keys, &bob_kp)
        .await
        .expect("sign key package event");
    assert_eq!(bob_kp_event.kind.as_u16(), mycellium_mls::KIND_KEY_PACKAGE);

    // 2. Alice creates the group, consuming Bob's KeyPackage event.
    let cfg = NostrGroupConfigData::new(
        "Alice & Bob".to_string(),
        "round-trip group".to_string(),
        None,
        None,
        None,
        vec![relay.clone()],
        vec![alice_keys.public_key(), bob_keys.public_key()],
    );
    let created = alice
        .create_group(&alice_keys.public_key(), vec![bob_kp_event], cfg)
        .expect("create group");
    let gid = created.group.mls_group_id.clone();
    let welcome_rumor = created
        .welcome_rumors
        .first()
        .cloned()
        .expect("welcome rumor");

    // 3. Alice gift-wraps the Welcome (kind:444 rumor -> NIP-59 wrap) to Bob.
    let gift = wire::gift_wrap_welcome(&alice_keys, &bob_keys.public_key(), welcome_rumor)
        .await
        .expect("gift wrap welcome");

    // 4. Alice encrypts a group message (epoch N).
    let rumor = EventBuilder::new(Kind::Custom(9), "hello marmot").build(alice_keys.public_key());
    let msg_event = alice.encrypt_message(&gid, rumor).expect("encrypt message");
    assert_eq!(msg_event.kind.as_u16(), mycellium_mls::KIND_GROUP_MESSAGE);

    // 5. Bob unwraps the gift, previews the Welcome, and joins.
    let recovered = wire::unwrap_welcome(&bob_keys, &gift)
        .await
        .expect("unwrap welcome");
    bob.process_welcome(&gift.id, &recovered)
        .expect("process welcome");
    let pending = bob.pending_welcomes().expect("pending welcomes");
    let welcome = pending.first().expect("one pending welcome");
    assert_eq!(welcome.member_count, 2);
    bob.accept_welcome(welcome).expect("accept welcome");
    let gid_bob = bob.groups().expect("groups")[0].mls_group_id.clone();
    assert_eq!(gid_bob, gid, "Bob joined the same MLS group");

    // 6. Bob decrypts Alice's message.
    bob.process_incoming(&msg_event).expect("process message");
    let got = bob.messages(&gid_bob).expect("messages");
    let m = got.first().expect("decrypted message");
    assert_eq!(m.content, "hello marmot", "plaintext must round-trip");
    assert_eq!(m.pubkey, alice_keys.public_key());

    // 7. PCS: Alice rotates keys (self_update); the epoch advances and converges.
    let epoch_before = alice.epoch(&gid).expect("epoch").expect("in group");
    let evolution = alice.rotate(&gid).expect("rotate");
    bob.process_incoming(&evolution).expect("apply commit");
    let epoch_alice = alice.epoch(&gid).expect("epoch").expect("in group");
    let epoch_bob = bob.epoch(&gid_bob).expect("epoch").expect("in group");
    assert_eq!(epoch_alice, epoch_before + 1, "epoch must advance");
    assert_eq!(epoch_bob, epoch_alice, "both members converge");

    // 8. A message sent after rotation still decrypts.
    let rumor2 =
        EventBuilder::new(Kind::Custom(9), "post-rotation msg").build(alice_keys.public_key());
    let msg2 = alice
        .encrypt_message(&gid, rumor2)
        .expect("encrypt post-rotation");
    bob.process_incoming(&msg2).expect("process post-rotation");
    let after = bob.messages(&gid_bob).expect("messages after rotation");
    let last = after
        .iter()
        .find(|m| m.content == "post-rotation msg")
        .expect("post-rotation message decrypted");
    assert_eq!(last.content, "post-rotation msg");
}
