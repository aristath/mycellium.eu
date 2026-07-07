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
            let _ = mycellium_queue::serve(&serve, mycellium_queue::ServeConfig::dev()).await;
        });
    });
    wait_port(port);
    format!("http://{addr}")
}

/// Serve `mycellium-directory` in a background thread; returns its base URL.
fn start_directory() -> String {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let serve = addr.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async {
            let _ =
                mycellium_directory::serve(&serve, mycellium_directory::ServeConfig::dev()).await;
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

/// A multi-step group flow: alice creates a group with bob; bob processes the
/// `GroupInvite` on `sync()` and joins (learning the *same* group id); alice
/// sends to the group; bob receives it in the group thread on a later `sync()`.
///
/// This drives the real engine group lifecycle end-to-end through the SDK on two
/// in-process clients — exactly what the desktop `group_*` commands wrap.
#[test]
fn group_round_trip() {
    let dir_url = start_directory();
    let queue_url = start_queue();

    let alice = onboard_arc(&dir_url, &queue_url, "alice");
    let bob = onboard_arc(&dir_url, &queue_url, "bob");

    // Alice creates the group with bob as a member: the SDK seals her group
    // sender-key to bob as a GroupInvite deposited on his queue.
    let gid = alice
        .group_create("g".to_string(), vec!["bob".to_string()])
        .expect("alice group_create");
    assert!(
        alice.groups().iter().any(|g| g.id == gid),
        "alice's own group list should contain the new group"
    );

    // Bob must sync() to process the invite and join. He learns the group (and
    // its id) from the invite; poll a few ticks for eventual delivery.
    let mut joined = false;
    for _ in 0..40 {
        let _ = bob.sync().expect("bob sync (invite)");
        if bob.groups().iter().any(|g| g.id == gid) {
            joined = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(joined, "bob never joined the group via the invite");

    // Bob's group id matches alice's (both refer to the same group), with name.
    let bob_group = bob
        .groups()
        .into_iter()
        .find(|g| g.id == gid)
        .expect("bob has the group");
    assert_eq!(
        bob_group.name, "g",
        "bob learned the group name from the invite"
    );

    // Alice sends a message to the group; bob receives it in the group thread.
    alice
        .group_send(gid.clone(), "hi group".to_string())
        .expect("alice group_send");

    let mut delivered = false;
    for _ in 0..40 {
        let recv = bob.sync().expect("bob sync (group text)");
        if recv
            .iter()
            .any(|m| m.text == "hi group" && m.thread == gid && !m.from_me)
        {
            delivered = true;
            break;
        }
        if bob
            .group_thread(gid.clone())
            .expect("bob group_thread")
            .iter()
            .any(|m| m.text == "hi group")
        {
            delivered = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        delivered,
        "bob never received alice's group message via sync"
    );

    // And it lands in bob's group transcript, attributed to alice.
    let thread = bob.group_thread(gid.clone()).expect("bob group_thread");
    assert!(
        thread
            .iter()
            .any(|m| m.text == "hi group" && !m.from_me && m.sender == "alice"),
        "group message not in bob's group thread (attributed to alice): {:?}",
        thread
            .iter()
            .map(|m| (&m.sender, &m.text))
            .collect::<Vec<_>>()
    );
}

/// A reply + reaction round-trip. Bob replies to and reacts to a message alice
/// sent. In this SDK there is **no** special reaction/reply history mutation:
/// both arrive as *new* transcript entries whose text is `AppMessage::summary()`
/// — a reply renders as `↪ (re <id>) <text>` and a reaction as
/// `reacted <emoji> to <id>`. This test asserts that real behavior (not a
/// fiction that reactions mutate an existing message).
#[test]
fn reply_and_react_round_trip() {
    let dir_url = start_directory();
    let queue_url = start_queue();

    let alice = onboard_arc(&dir_url, &queue_url, "alice");
    let bob = onboard_arc(&dir_url, &queue_url, "bob");

    // Alice sends bob a message; bob syncs to learn its id.
    let sent = alice
        .send_text("bob".to_string(), "original".to_string())
        .expect("alice send_text");
    let orig_id = sent.id.clone();

    let mut bob_got = false;
    for _ in 0..40 {
        let recv = bob.sync().expect("bob sync (original)");
        if recv.iter().any(|m| m.id == orig_id) {
            bob_got = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(bob_got, "bob never received alice's original message");

    // Bob replies to and reacts to alice's message (1:1 SDK operations).
    bob.reply("alice".to_string(), orig_id.clone(), "myreply".to_string())
        .expect("bob reply");
    bob.react("alice".to_string(), orig_id.clone(), "👍".to_string())
        .expect("bob react");

    // Alice syncs and sees both, each as a new inbound transcript entry rendered
    // from the message summary.
    let mut reply_seen = false;
    let mut react_seen = false;
    for _ in 0..40 {
        let _ = alice.sync().expect("alice sync");
        let thread = alice.thread("bob".to_string()).expect("alice thread");
        reply_seen = thread.iter().any(|m| {
            !m.from_me
                && m.text.starts_with('↪')
                && m.text.contains("myreply")
                && m.text.contains(&orig_id)
        });
        react_seen = thread.iter().any(|m| {
            !m.from_me
                && m.text.contains("reacted")
                && m.text.contains('👍')
                && m.text.contains(&orig_id)
        });
        if reply_seen && react_seen {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        reply_seen,
        "alice never saw bob's reply as a transcript entry"
    );
    assert!(
        react_seen,
        "alice never saw bob's reaction as a transcript entry"
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
