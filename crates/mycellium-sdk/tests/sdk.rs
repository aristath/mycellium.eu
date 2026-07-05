//! End-to-end integration test for the native SDK: spin up an in-process
//! directory + queue, create two `MyceliumClient`s in temp data dirs, register
//! both, send alice → bob, and assert bob's `sync()` decrypts it and that the
//! transcript / conversation list reflect it.

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use std::collections::HashMap;

use mycellium_sdk::{
    DeliveryState, EventListener, Message, MyceliumClient, PassphraseFileSecretStore, SdkError,
    SecretStore, TrustLevel,
};

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

#[test]
fn email_verified_registration() {
    // The in-process directory runs with MYCELLIUM_DEV_AUTH=1 (set by
    // start_directory), so auth_start echoes the code back as dev_code — the
    // local flow needs no real inbox.
    let dir = start_directory();
    let queue = ensure_queue();

    let dave =
        MyceliumClient::new(data_dir("dave").to_string_lossy().into_owned()).expect("open dave");

    // Step 1: start the email-verified claim. Dev mode returns both a pending
    // token and the code.
    let verification = dave
        .start_email_verification(dir.clone(), "dave".into(), "dave@example.com".into())
        .expect("start email verification");
    assert!(
        !verification.pending.is_empty(),
        "a pending token must come back"
    );
    let code = verification
        .dev_code
        .expect("dev mode must echo the verification code");
    assert!(!code.is_empty(), "the dev code must not be empty");

    // Step 2: confirm the code — the directory binds the handle to this wallet.
    dave.confirm_email_verification(dir.clone(), verification.pending, code)
        .expect("confirm email verification");

    // Step 3: register (publish the record) now that the handle is verified.
    dave.register(dir.clone(), queue.clone(), "dave".into(), "Dave".into())
        .expect("dave register");

    // The published record is looked-up-able: a peer can find and message dave.
    let eve =
        MyceliumClient::new(data_dir("eve").to_string_lossy().into_owned()).expect("open eve");
    eve.register(dir.clone(), queue.clone(), "eve".into(), "Eve".into())
        .expect("eve register");
    eve.add_contact("davey".into(), "dave".into())
        .expect("eve resolves dave's published record");

    // And a message round-trips end-to-end to the verified account.
    eve.send_text("dave".into(), "welcome aboard".into())
        .expect("eve send");
    let inbound = dave.sync().expect("dave sync");
    assert_eq!(inbound.len(), 1);
    assert_eq!(inbound[0].text, "welcome aboard");
    assert_eq!(inbound[0].sender, "eve");
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

// ---- secret-store integration (#65) -------------------------------------------

/// An in-memory `SecretStore` standing in for a platform's OS keystore. Its map is
/// shared behind an `Arc`, so a "reopen" (a fresh handle over the same map) sees
/// what the previous instance stored — the way a real keystore persists.
#[derive(Clone, Default)]
struct MockSecretStore {
    map: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}
impl SecretStore for MockSecretStore {
    fn store(&self, key: String, secret: Vec<u8>) -> Result<(), SdkError> {
        self.map.lock().unwrap().insert(key, secret);
        Ok(())
    }
    fn load(&self, key: String) -> Result<Option<Vec<u8>>, SdkError> {
        Ok(self.map.lock().unwrap().get(&key).cloned())
    }
    fn delete(&self, key: String) -> Result<(), SdkError> {
        self.map.lock().unwrap().remove(&key);
        Ok(())
    }
}

#[test]
fn mock_secret_store_drives_sdk_end_to_end() {
    let dir = start_directory();
    let queue = ensure_queue();

    // Two accounts whose identity secrets live only in the (in-memory) store.
    let alice_secrets = MockSecretStore::default();
    let bob_secrets = MockSecretStore::default();
    let bob_dir = data_dir("bob-mock");

    let alice = MyceliumClient::new_with_secret_store(
        data_dir("alice-mock").to_string_lossy().into_owned(),
        Box::new(alice_secrets),
    )
    .expect("open alice");
    let bob = MyceliumClient::new_with_secret_store(
        bob_dir.to_string_lossy().into_owned(),
        Box::new(bob_secrets.clone()),
    )
    .expect("open bob");

    // The identity secret was persisted through the store, not to a sidecar file.
    assert!(
        bob_secrets.map.lock().unwrap().contains_key("identity"),
        "identity must be held in the SecretStore"
    );
    assert!(
        !bob_dir.join("identity.json").exists(),
        "no plaintext identity.json sidecar should be written"
    );

    alice
        .register(dir.clone(), queue.clone(), "alice".into(), "Alice".into())
        .expect("alice register");
    bob.register(dir.clone(), queue.clone(), "bob".into(), "Bob".into())
        .expect("bob register");

    let bob_wallet = bob.wallet_address();

    // A real send/sync round-trips through the store-backed identities.
    alice
        .send_text("bob".into(), "hi via keystore".into())
        .expect("alice send");
    let inbound = bob.sync().expect("bob sync");
    assert_eq!(inbound.len(), 1);
    assert_eq!(inbound[0].text, "hi via keystore");

    // Reopen bob with a fresh handle over the *same* store map: identity and
    // config persist because the identity was loaded back out of the store.
    drop(bob);
    let bob2 = MyceliumClient::new_with_secret_store(
        bob_dir.to_string_lossy().into_owned(),
        Box::new(bob_secrets),
    )
    .expect("reopen bob");
    assert_eq!(
        bob2.wallet_address(),
        bob_wallet,
        "identity must persist across reopen through the store"
    );
    assert_eq!(bob2.account().handle, "bob");
    let thread = bob2.thread("alice".into()).expect("thread");
    assert_eq!(thread.len(), 1);
    assert_eq!(thread[0].text, "hi via keystore");
}

#[test]
fn passphrase_store_round_trips_and_fails_closed() {
    let dir = data_dir("passphrase-store");
    std::fs::create_dir_all(&dir).unwrap();

    let store = PassphraseFileSecretStore::new(dir.clone(), "correct horse battery staple");
    let secret = b"a very secret 32-byte-ish blob!!".to_vec();

    // A missing key is `None`, not an error.
    assert!(store.load("identity".into()).unwrap().is_none());

    // Round-trip: store then load returns the exact bytes.
    store.store("identity".into(), secret.clone()).unwrap();
    assert_eq!(store.load("identity".into()).unwrap(), Some(secret.clone()));

    // The on-disk file must not contain the plaintext (it's AEAD-sealed).
    let on_disk = std::fs::read(dir.join("identity")).unwrap();
    assert!(
        on_disk
            .windows(secret.len())
            .all(|w| w != secret.as_slice()),
        "plaintext secret must not appear on disk"
    );

    // Wrong passphrase fails closed (an error, never a wrong/empty plaintext).
    let wrong = PassphraseFileSecretStore::new(dir.clone(), "wrong passphrase");
    assert!(
        wrong.load("identity".into()).is_err(),
        "a wrong passphrase must fail closed"
    );

    // Delete removes it; a second delete is a no-op.
    store.delete("identity".into()).unwrap();
    assert!(store.load("identity".into()).unwrap().is_none());
    store.delete("identity".into()).unwrap();
}

#[test]
fn legacy_sidecar_migrates_into_store_then_is_removed() {
    // Produce a *real* identity secret by opening a client over a mock store, then
    // read the stored bytes back out — that is exactly the legacy sidecar's JSON.
    let seed_secrets = MockSecretStore::default();
    let seed = MyceliumClient::new_with_secret_store(
        data_dir("migrate-seed").to_string_lossy().into_owned(),
        Box::new(seed_secrets.clone()),
    )
    .expect("seed client");
    let wallet = seed.wallet_address();
    let identity_bytes = seed_secrets
        .map
        .lock()
        .unwrap()
        .get("identity")
        .cloned()
        .expect("seed identity stored");

    // Plant it as a legacy plaintext sidecar in a fresh data dir with an *empty*
    // store, then open a client there.
    let dd = data_dir("migrate-target");
    std::fs::create_dir_all(&dd).unwrap();
    std::fs::write(dd.join("identity.json"), &identity_bytes).unwrap();

    let target_secrets = MockSecretStore::default();
    let client = MyceliumClient::new_with_secret_store(
        dd.to_string_lossy().into_owned(),
        Box::new(target_secrets.clone()),
    )
    .expect("open migrating client");

    // The migrated identity is the same account...
    assert_eq!(
        client.wallet_address(),
        wallet,
        "migrated identity must match the sidecar"
    );
    // ...it was imported into the store...
    assert_eq!(
        target_secrets.map.lock().unwrap().get("identity"),
        Some(&identity_bytes),
        "sidecar must be imported into the store byte-for-byte"
    );
    // ...and the plaintext sidecar is gone.
    assert!(
        !dd.join("identity.json").exists(),
        "the legacy sidecar must be removed after migration"
    );
}
