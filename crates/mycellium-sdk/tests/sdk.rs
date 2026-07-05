//! End-to-end integration test for the native SDK: spin up an in-process
//! directory + queue, create two `MyceliumClient`s in temp data dirs, register
//! both, send alice → bob, and assert bob's `sync()` decrypts it and that the
//! transcript / conversation list reflect it.

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mycellium_sdk::{DeliveryState, EventListener, Message, MyceliumClient};

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
