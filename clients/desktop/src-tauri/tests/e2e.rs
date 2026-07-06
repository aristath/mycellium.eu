//! The desktop client's verifiable messaging round-trip.
//!
//! This exercises the exact SDK surface the Tauri commands wrap — but directly,
//! without a webview — so it runs headless in CI. It stands up an in-process
//! directory + queue (dev auth, like the CLI e2e), onboards two accounts through
//! the real email-verification flow, sends alice→bob, and asserts bob receives it
//! via `sync()` and sees it in the thread.
//!
//! It deliberately uses the SDK's dev `MyceliumClient::new` (a plaintext-file
//! secret store) rather than the production `KeyringSecretStore`: the OS keyring
//! needs a running Secret Service / Credential Manager that a headless CI box
//! lacks. The keyring adapter is compiled by `cargo build`; this test proves the
//! messaging path the app drives on top of it.

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use mycellium_sdk::MyceliumClient;

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

/// Serve `mycellium-queue` in a background thread; returns its base URL.
fn start_queue() -> String {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let serve = addr.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async {
            let _ = mycellium_queue::serve(&serve).await;
        });
    });
    wait_port(port);
    format!("http://{addr}")
}

/// Serve `mycellium-directory` in a background thread; returns its base URL. The
/// directory fails closed without SMTP unless dev auth is explicit (#47), so we
/// set `MYCELLIUM_DEV_AUTH=1` — which also makes email verification echo the code.
fn start_directory() -> String {
    std::env::set_var("MYCELLIUM_DEV_AUTH", "1");
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let serve = addr.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async {
            let _ = mycellium_directory::serve(&serve).await;
        });
    });
    wait_port(port);
    format!("http://{addr}")
}

/// A unique, isolated data directory for one account.
fn data_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "mycellium-desktop-e2e-{}-{}-{}",
        tag,
        std::process::id(),
        n
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

#[test]
fn messaging_round_trip_alice_to_bob() {
    let dir_url = start_directory();
    let queue_url = start_queue();

    let alice = onboard_arc(&dir_url, &queue_url, "alice");
    let bob = onboard_arc(&dir_url, &queue_url, "bob");

    // Alice sends bob a message.
    let sent = alice
        .send_text(
            "bob".to_string(),
            "hello from the desktop client".to_string(),
        )
        .expect("alice send_text");
    assert!(sent.from_me, "sent message should be marked from_me");
    assert_eq!(sent.text, "hello from the desktop client");

    // Bob drains his queue; the inbound message is returned by sync().
    let received = bob.sync().expect("bob sync");
    assert!(
        received
            .iter()
            .any(|m| m.text == "hello from the desktop client" && !m.from_me),
        "bob's sync did not return alice's message: {:?}",
        received.iter().map(|m| &m.text).collect::<Vec<_>>()
    );

    // And it lands in the thread with alice.
    let thread = bob.thread("alice".to_string()).expect("bob thread");
    assert!(
        thread
            .iter()
            .any(|m| m.text == "hello from the desktop client"),
        "message not in bob's thread with alice: {:?}",
        thread.iter().map(|m| &m.text).collect::<Vec<_>>()
    );

    // A second sync is empty (the mailbox drained).
    let again = bob.sync().expect("bob second sync");
    assert!(
        !again
            .iter()
            .any(|m| m.text == "hello from the desktop client"),
        "message should only be delivered once"
    );
}

/// Onboard and keep the `Arc<MyceliumClient>` (the natural constructor return).
fn onboard_arc(dir_url: &str, queue_url: &str, handle: &str) -> std::sync::Arc<MyceliumClient> {
    let client = MyceliumClient::new(data_dir(handle).to_string_lossy().to_string())
        .expect("open dev client");
    let email = format!("{handle}@example.test");
    let ev = client
        .start_email_verification(dir_url.to_string(), handle.to_string(), email)
        .expect("start email verification");
    let code = ev
        .dev_code
        .expect("directory dev mode must echo the verification code");
    client
        .confirm_email_verification(dir_url.to_string(), ev.pending, code)
        .expect("confirm email verification");
    client
        .register(
            dir_url.to_string(),
            queue_url.to_string(),
            handle.to_string(),
            handle.to_string(),
        )
        .expect("register");
    client
}
