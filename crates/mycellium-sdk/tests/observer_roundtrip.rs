//! End-to-end proof that the UniFFI surface works over a **real in-process relay**:
//! two [`MycelliumClient`]s (built exactly as a foreign caller would), one adds the
//! other as a contact, starts a conversation, and `send_text`s — and the peer's
//! **registered [`MycelliumObserver`] callback** fires with the decrypted text. The
//! observer is a Rust impl of the same foreign trait a Kotlin/Swift UI would
//! implement, so this exercises the callback bridge, not the engine directly.
//!
//! The relay runs on its own multi-thread runtime kept alive for the test; the
//! clients each own their internal runtime and are driven with their blocking API
//! from the (runtime-free) test thread — the same way a foreign UI thread calls in.

use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mycellium_sdk::{
    generate_identity, MycelliumClient, MycelliumObserver, ReceivedMessageInfo, TrustEventInfo,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use tempfile::TempDir;

/// A test observer: forwards every `on_message` onto a channel the test drains,
/// and records trust/error callbacks for inspection.
struct Recorder {
    messages: Sender<ReceivedMessageInfo>,
    trust: Mutex<Vec<TrustEventInfo>>,
    errors: Mutex<Vec<String>>,
}

impl MycelliumObserver for Recorder {
    fn on_message(&self, message: ReceivedMessageInfo) {
        let _ = self.messages.send(message);
    }
    fn on_trust_event(&self, event: TrustEventInfo) {
        self.trust.lock().unwrap().push(event);
    }
    fn on_error(&self, message: String) {
        self.errors.lock().unwrap().push(message);
    }
}

#[test]
fn observer_receives_sent_text_over_relay() {
    // ---- Relay on its own runtime, kept alive for the whole test ----------
    let relay_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("relay runtime");
    let relay = LocalRelay::new(RelayBuilder::default());
    let relay_url = relay_rt.block_on(async {
        relay.run().await.expect("relay runs");
        relay.url().await
    });
    // The SDK speaks string relay URLs at its boundary (as a foreign caller would).
    let relays = vec![relay_url.to_string()];

    // ---- Two clients, built the foreign way (nsec + relays + data dir) -----
    let alice_dir = TempDir::new().expect("alice dir");
    let bob_dir = TempDir::new().expect("bob dir");

    let alice = MycelliumClient::open_solo(
        generate_identity(),
        relays.clone(),
        alice_dir.path().to_string_lossy().to_string(),
    )
    .expect("open alice");
    let bob = MycelliumClient::open_solo(
        generate_identity(),
        relays.clone(),
        bob_dir.path().to_string_lossy().to_string(),
    )
    .expect("open bob");

    // ---- Connect, subscribe, publish identity -----------------------------
    alice.connect().expect("alice connect");
    bob.connect().expect("bob connect");
    alice.subscribe().expect("alice subscribe");
    bob.subscribe().expect("bob subscribe");
    alice.publish(Some("alice".into())).expect("alice publish");
    bob.publish(Some("bob".into())).expect("bob publish");

    // ---- Bob starts receiving into a registered observer ------------------
    let (tx, rx) = channel();
    let recorder = Arc::new(Recorder {
        messages: tx,
        trust: Mutex::new(Vec::new()),
        errors: Mutex::new(Vec::new()),
    });
    bob.start_receiving(recorder.clone())
        .expect("bob starts receiving");

    // ---- Alice adds Bob, starts a conversation, sends ---------------------
    let bob_npub = bob.account_npub();
    let status = alice
        .add_contact(bob_npub, Some("bob".into()))
        .expect("alice adds bob");
    assert!(
        matches!(status, mycellium_sdk::TrustStatusFfi::Pinned),
        "first add pins TOFU, got {status:?}"
    );

    let convo = alice
        .start_conversation("bob".into())
        .expect("alice starts conversation");
    alice
        .send_text(convo.clone(), "hi bob".into())
        .expect("alice sends");

    // ---- The observer callback must fire with the decrypted text ----------
    let received = rx
        .recv_timeout(Duration::from_secs(15))
        .expect("bob's observer on_message must fire within the timeout");
    assert_eq!(received.text, "hi bob", "observer got the decrypted text");
    assert_eq!(
        received.conversation_id, convo,
        "observer reports the same conversation id alice sent to"
    );
    assert_eq!(
        received.from_npub,
        alice.device_npub(),
        "authored by alice's device"
    );

    // The message is also persisted in Bob's transcript for that conversation.
    let deadline = Instant::now() + Duration::from_secs(5);
    let persisted = loop {
        let t = bob.transcript(received.conversation_id.clone()).unwrap();
        if t.iter().any(|m| m.text == "hi bob" && !m.from_me) {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        persisted,
        "received message is persisted in Bob's transcript"
    );

    // No error callbacks fired during the round trip.
    assert!(
        recorder.errors.lock().unwrap().is_empty(),
        "no receive-loop errors: {:?}",
        recorder.errors.lock().unwrap()
    );

    // ---- Clean shutdown (stops the receive loop) --------------------------
    bob.stop_receiving();
    alice.shutdown();
    bob.shutdown();
    // The relay is torn down when its runtime is dropped at end of scope.
    drop(relay_rt);
}
