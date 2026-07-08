//! Proof that the desktop **controller** works end-to-end over a real relay,
//! driven exactly as the UI drives it — via [`Command`]s in and [`UiEvent`]s out,
//! with no direct access to the engine.
//!
//! Two controllers (Alice, Bob), each on its own runtime, are pointed at one
//! in-process relay. Alice pins Bob, starts a conversation, and sends a message;
//! Bob's controller emits a transcript containing the decrypted text. This
//! exercises the whole bridge: startup/announce, command handling, the incoming
//! poll loop, and the view-model projections — everything the egui layer sits on.
//!
//! Built without the `gui` feature so it links without windowing/GL libraries.

use std::time::{Duration, Instant};

use mycellium_app::Config;
use mycellium_desktop::engine::{spawn, Command, EngineHandle, UiEvent};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use tempfile::TempDir;

/// Drain events until `pred` yields a value or `secs` elapse.
fn drain_until<T>(
    handle: &EngineHandle,
    secs: u64,
    mut pred: impl FnMut(UiEvent) -> Option<T>,
) -> Option<T> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        while let Some(ev) = handle.try_recv() {
            if let Some(v) = pred(ev) {
                return Some(v);
            }
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    None
}

fn wait_ready(handle: &EngineHandle) {
    let ready = drain_until(handle, 15, |ev| matches!(ev, UiEvent::Ready).then_some(()));
    assert!(ready.is_some(), "engine never reported Ready");
}

#[test]
fn controller_delivers_a_message_over_a_relay() {
    // Relay on its own multi-thread runtime, kept alive for the whole test.
    let relay_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let relay = relay_rt.block_on(async {
        let r = LocalRelay::new(RelayBuilder::default());
        r.run().await.expect("relay runs");
        r
    });
    let relay_url = relay_rt.block_on(relay.url()).to_string();

    // Two solo accounts pointed at that relay.
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();
    let alice_cfg = Config::generate(vec![relay_url.clone()]);
    let bob_cfg = Config::generate(vec![relay_url.clone()]);

    let alice = spawn(alice_cfg, alice_dir.path().to_path_buf(), || {});
    let bob = spawn(bob_cfg, bob_dir.path().to_path_buf(), || {});
    let bob_npub = bob.account_npub.clone();

    // Both must finish announcing (KeyPackage + device list) before Alice can
    // build a group that enrolls Bob.
    wait_ready(&alice);
    wait_ready(&bob);

    // Alice pins Bob, opens a conversation, and sends.
    alice.send(Command::AddContact {
        handle: bob_npub,
        name: Some("bob".into()),
    });
    alice.send(Command::StartConversation {
        contact: "bob".into(),
    });
    let conversation = drain_until(&alice, 15, |ev| match ev {
        UiEvent::ConversationStarted { conversation, .. } => Some(conversation),
        _ => None,
    })
    .expect("Alice's conversation was created");

    alice.send(Command::SendText {
        conversation: conversation.clone(),
        text: "hello from alice".into(),
    });

    // Bob's controller emits a transcript containing the decrypted, received text.
    let got = drain_until(&bob, 20, |ev| match ev {
        UiEvent::Transcript { messages, .. } => messages
            .iter()
            .find(|m| m.text == "hello from alice" && !m.from_me)
            .map(|m| m.author.clone()),
        _ => None,
    });
    assert!(
        got.is_some(),
        "Bob's controller never surfaced the received message"
    );

    // Alice's own transcript also reflects the sent message (from_me).
    alice.send(Command::OpenConversation {
        conversation: conversation.clone(),
    });
    let mine = drain_until(&alice, 5, |ev| match ev {
        UiEvent::Transcript { messages, .. } => messages
            .iter()
            .any(|m| m.text == "hello from alice" && m.from_me)
            .then_some(()),
        _ => None,
    });
    assert!(mine.is_some(), "Alice's own send is in her transcript");

    alice.send(Command::Shutdown);
    bob.send(Command::Shutdown);
}
