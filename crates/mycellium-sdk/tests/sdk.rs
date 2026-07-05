//! End-to-end integration test for the native SDK: spin up an in-process
//! directory + queue, create two `MyceliumClient`s in temp data dirs, register
//! both, send alice → bob, and assert bob's `sync()` decrypts it and that the
//! transcript / conversation list reflect it.

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mycellium_sdk::{DeliveryState, EventListener, Message, MyceliumClient, TrustLevel};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A free TCP port (bind to :0, read the assigned port, release it).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Block until `port` accepts connections, or panic after a timeout.
fn wait_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("port {port} never opened");
}

/// Start the shared queue once; return its URL.
fn ensure_queue() -> String {
    static QUEUE_URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    QUEUE_URL
        .get_or_init(|| {
            let port = free_port();
            let addr = format!("127.0.0.1:{port}");
            let serve_addr = addr.clone();
            std::thread::spawn(move || {
                // Each async server gets its own tokio runtime (the harness is sync).
                let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                rt.block_on(async {
                    let _ = mycellium_queue::serve(&serve_addr).await;
                });
            });
            wait_port(port);
            format!("http://{addr}")
        })
        .clone()
}

/// Start a directory on a fresh port. Returns its URL.
fn start_directory() -> String {
    // The directory fails closed without SMTP unless dev auth is explicit (#47).
    std::env::set_var("MYCELLIUM_DEV_AUTH", "1");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let serve_addr = addr.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async {
            let _ = mycellium_directory::serve(&serve_addr).await;
        });
    });
    wait_port(port);
    format!("http://{addr}")
}

/// A unique, isolated data directory for one client.
fn data_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "mycellium-sdk-test-{}-{}-{}",
        tag,
        std::process::id(),
        n
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// A listener that records every message it's handed, for asserting on callbacks.
#[derive(Default)]
struct Recorder {
    got: Mutex<Vec<Message>>,
}
impl EventListener for Recorder {
    fn on_message(&self, message: Message) {
        self.got.lock().unwrap().push(message);
    }
    fn on_delivery(&self, _message_id: String, _state: DeliveryState) {}
    fn on_key_change(&self, _handle: String) {}
    fn on_pairing(&self, _event: String) {}
}

#[test]
fn register_send_sync_read_core() {
    let dir = start_directory();
    let queue = ensure_queue();

    // Two accounts in isolated data dirs.
    let alice =
        MyceliumClient::new(data_dir("alice").to_string_lossy().into_owned()).expect("open alice");
    let bob =
        MyceliumClient::new(data_dir("bob").to_string_lossy().into_owned()).expect("open bob");

    // Before registering, sending fails with NotRegistered.
    assert!(
        alice.send_text("bob".into(), "too early".into()).is_err(),
        "send before register must fail"
    );

    alice
        .register(dir.clone(), queue.clone(), "alice".into(), "Alice".into())
        .expect("alice register");
    bob.register(dir.clone(), queue.clone(), "bob".into(), "Bob".into())
        .expect("bob register");

    // Account reflects the registration; wallet address is stable hex.
    let acct = alice.account();
    assert_eq!(acct.handle, "alice");
    assert_eq!(acct.name, "Alice");
    assert_eq!(acct.wallet_address, alice.wallet_address());
    assert!(!acct.wallet_address.is_empty());

    // Bob wires up a listener to prove push delivery on sync().
    let rec = Arc::new(Recorder::default());
    bob.set_listener(Box::new(RecorderHandle(rec.clone())));

    // Alice sends to bob.
    let sent = alice
        .send_text("bob".into(), "hello over the sdk".into())
        .expect("alice send");
    assert!(sent.from_me);
    assert_eq!(sent.thread, "bob");
    assert_eq!(sent.sender, "alice");
    assert_eq!(sent.delivery, DeliveryState::Sent);

    // Bob syncs and sees exactly the decrypted message.
    let inbound = bob.sync().expect("bob sync");
    assert_eq!(inbound.len(), 1, "bob should receive one message");
    let m = &inbound[0];
    assert!(!m.from_me);
    assert_eq!(m.sender, "alice");
    assert_eq!(m.thread, "alice");
    assert_eq!(m.text, "hello over the sdk");
    assert_eq!(m.delivery, DeliveryState::Delivered);

    // The listener was fired with the same message.
    let pushed = rec.got.lock().unwrap();
    assert_eq!(pushed.len(), 1, "on_message should have fired once");
    assert_eq!(pushed[0].text, "hello over the sdk");
    drop(pushed);

    // Bob's transcript with alice reflects it.
    let thread = bob.thread("alice".into()).expect("bob thread");
    assert_eq!(thread.len(), 1);
    assert_eq!(thread[0].text, "hello over the sdk");
    assert!(!thread[0].from_me);

    // Bob's conversation list shows alice with the preview and learned name.
    let convos = bob.conversations().expect("bob conversations");
    assert_eq!(convos.len(), 1);
    assert_eq!(convos[0].peer, "alice");
    assert_eq!(convos[0].display_name, "Alice");
    assert_eq!(convos[0].last_preview, "hello over the sdk");

    // Alice's own transcript records the sent copy.
    let alice_thread = alice.thread("bob".into()).expect("alice thread");
    assert_eq!(alice_thread.len(), 1);
    assert!(alice_thread[0].from_me);
    assert_eq!(alice_thread[0].text, "hello over the sdk");

    // A second sync is empty (the mailbox drained).
    let again = bob.sync().expect("bob sync again");
    assert!(again.is_empty(), "second sync should be empty");

    // Free-form settings round-trip.
    assert_eq!(bob.get_setting("theme".into()), None);
    bob.set_setting("theme".into(), "dark".into());
    assert_eq!(bob.get_setting("theme".into()), Some("dark".into()));
}

#[test]
fn config_persists_across_reopen() {
    let dir = start_directory();
    let queue = ensure_queue();
    let dd = data_dir("persist");

    let wallet = {
        let c = MyceliumClient::new(dd.to_string_lossy().into_owned()).expect("open");
        c.register(dir, queue, "carol".into(), "Carol".into())
            .expect("register");
        c.wallet_address()
    };

    // Reopen the same data dir: identity and config survive.
    let reopened = MyceliumClient::new(dd.to_string_lossy().into_owned()).expect("reopen");
    assert_eq!(reopened.wallet_address(), wallet, "identity must persist");
    let acct = reopened.account();
    assert_eq!(acct.handle, "carol");
    assert_eq!(acct.name, "Carol");
}

/// Register two fresh clients (alice, bob) against `dir`/`queue`.
fn two_clients(dir: &str, queue: &str) -> (Arc<MyceliumClient>, Arc<MyceliumClient>) {
    let alice =
        MyceliumClient::new(data_dir("alice").to_string_lossy().into_owned()).expect("open alice");
    let bob =
        MyceliumClient::new(data_dir("bob").to_string_lossy().into_owned()).expect("open bob");
    alice
        .register(dir.into(), queue.into(), "alice".into(), "Alice".into())
        .expect("alice register");
    bob.register(dir.into(), queue.into(), "bob".into(), "Bob".into())
        .expect("bob register");
    (alice, bob)
}

#[test]
fn contacts_and_verification() {
    let dir = start_directory();
    let queue = ensure_queue();
    let (alice, bob) = two_clients(&dir, &queue);

    // Safety numbers are symmetric across both devices.
    assert_eq!(
        alice.safety_number("bob".into()).expect("alice sn"),
        bob.safety_number("alice".into()).expect("bob sn"),
    );

    // Add + TOFU-pin a contact.
    alice
        .add_contact("bobby".into(), "bob".into())
        .expect("add contact");
    let contacts = alice.contacts();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].nickname, "bobby");
    assert_eq!(contacts[0].handle, "bob");
    assert_eq!(contacts[0].trust, TrustLevel::Pinned);
    assert_eq!(
        alice.trust_level("bob".into()).expect("trust level"),
        TrustLevel::Pinned
    );

    // Mark verified out of band — trust rises to Verified.
    alice.mark_verified("bob".into()).expect("mark verified");
    assert_eq!(
        alice.trust_level("bob".into()).expect("trust level 2"),
        TrustLevel::Verified
    );
    assert_eq!(alice.contacts()[0].trust, TrustLevel::Verified);

    // A contact card round-trips: bob's card verifies against the directory.
    let card = bob.contact_card().expect("bob card");
    assert_eq!(alice.verify_card(card).expect("verify card"), "bob");

    // Remove the contact.
    alice.remove_contact("bobby".into()).expect("remove");
    assert!(alice.contacts().is_empty());
}

#[test]
fn group_create_send_thread() {
    let dir = start_directory();
    let queue = ensure_queue();
    let (alice, bob) = two_clients(&dir, &queue);

    // Alice creates the group; the invite is deposited to bob.
    let gid = alice
        .group_create("team".into(), vec!["bob".into()])
        .expect("group create");

    // Bob syncs to join (and reciprocate his sender key); alice learns bob's key.
    let _ = bob.sync().expect("bob sync invite");
    let _ = alice.sync().expect("alice sync invite");

    // Alice sends to the group.
    let sent = alice
        .group_send(gid.clone(), "hello team".into())
        .expect("group send");
    assert!(sent.from_me);
    assert_eq!(sent.sender, "alice");

    // Bob syncs and decrypts the group message.
    let inbound = bob.sync().expect("bob sync text");
    assert!(
        inbound.iter().any(|m| m.text == "hello team"),
        "bob should receive the group message"
    );

    // Bob's group thread shows it, attributed to alice.
    let thread = bob.group_thread(gid.clone()).expect("bob group thread");
    assert!(thread
        .iter()
        .any(|m| m.text == "hello team" && m.sender == "alice" && !m.from_me));

    // The group appears in bob's group list with its name + members.
    let groups = bob.groups();
    let g = groups.iter().find(|g| g.id == gid).expect("group in list");
    assert_eq!(g.name, "team");
    assert!(g.members.iter().any(|m| m == "bob"));
    assert!(g.members.iter().any(|m| m == "alice"));

    // Alice's own transcript records the sent copy.
    let alice_thread = alice.group_thread(gid).expect("alice group thread");
    assert!(alice_thread
        .iter()
        .any(|m| m.text == "hello team" && m.from_me));
}

#[test]
fn reply_and_react_round_trip() {
    let dir = start_directory();
    let queue = ensure_queue();
    let (alice, bob) = two_clients(&dir, &queue);

    // Alice sends; bob receives and learns the message id.
    alice
        .send_text("bob".into(), "original".into())
        .expect("send");
    let inbound = bob.sync().expect("bob sync");
    assert_eq!(inbound.len(), 1);
    let orig_id = inbound[0].id.clone();

    // Bob replies to it.
    let reply = bob
        .reply("alice".into(), orig_id.clone(), "a reply".into())
        .expect("reply");
    assert!(reply.from_me);
    assert!(reply.text.contains("a reply"));

    // Alice receives the reply.
    let got = alice.sync().expect("alice sync reply");
    assert_eq!(got.len(), 1);
    assert!(got[0].text.contains("a reply"));
    assert!(!got[0].from_me);

    // Bob reacts to the original; alice receives the reaction.
    let react = bob
        .react("alice".into(), orig_id, "👍".into())
        .expect("react");
    assert!(react.text.contains("👍"));
    let got2 = alice.sync().expect("alice sync react");
    assert_eq!(got2.len(), 1);
    assert!(got2[0].text.contains("👍"));
}

/// A newtype so the callback-interface `Box<dyn EventListener>` can wrap our
/// `Arc<Recorder>` (which we also keep a handle to for assertions).
struct RecorderHandle(Arc<Recorder>);
impl EventListener for RecorderHandle {
    fn on_message(&self, message: Message) {
        self.0.on_message(message);
    }
    fn on_delivery(&self, message_id: String, state: DeliveryState) {
        self.0.on_delivery(message_id, state);
    }
    fn on_key_change(&self, handle: String) {
        self.0.on_key_change(handle);
    }
    fn on_pairing(&self, event: String) {
        self.0.on_pairing(event);
    }
}
