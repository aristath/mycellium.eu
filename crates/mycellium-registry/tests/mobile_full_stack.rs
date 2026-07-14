mod support;

use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use mycellium_client::registry::RegistryClient;
use mycellium_core::identity::{Handle, Identity};
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, Record, SignedRecord};
use mycellium_core::userid::user_id;
use mycellium_mobile::{ClientState, DeliveryState, EventKind, MobileClient, MobileError};
use mycellium_transport::reticulum_net::ReticulumBackbone;
use tempfile::TempDir;

use support::TestRegistry;

struct OsPlatform;

impl Platform for OsPlatform {
    fn fill_random(&mut self, bytes: &mut [u8]) {
        getrandom::getrandom(bytes).expect("OS randomness");
    }

    fn now_unix_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_secs()
    }
}

fn login(
    client: &MobileClient,
    server: &TestRegistry,
    email: &str,
) -> mycellium_mobile::LoginResult {
    client
        .request_email_login(email.to_string())
        .unwrap_or_else(|error| panic!("request login for {email}: {error}"));
    let token = server.emails.take_token(email);
    client
        .confirm_email_login(token)
        .unwrap_or_else(|error| panic!("confirm login for {email}: {error}"))
}

fn require_connectivity(client: &MobileClient) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last_error = None;
    while Instant::now() < deadline {
        match client.refresh_connectivity() {
            Ok(()) => return,
            Err(error) => last_error = Some(error.to_string()),
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "client did not establish Reticulum connectivity: {}",
        last_error.unwrap_or_else(|| "unknown error".into())
    );
}

fn wait_for_message(client: &MobileClient, user_id: &str, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        let messages = client
            .messages(user_id.to_string())
            .unwrap_or_else(|error| panic!("read messages: {error}"));
        if messages
            .iter()
            .any(|message| message.text == expected && !message.from_me)
        {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("recipient did not persist message {expected:?}");
}

fn identity_secret(identity: &Identity) -> Vec<u8> {
    let mut secret = Vec::with_capacity(64);
    secret.extend_from_slice(&identity.wallet_secret());
    secret.extend_from_slice(&identity.device_seed());
    secret
}

fn publish_offline_account(
    server: &TestRegistry,
    email: &str,
    handle: &str,
    display_name: &str,
) -> (Identity, SignedRecord) {
    let registry = RegistryClient::new(&server.base_url).expect("registry client");
    registry
        .request_email_login(email)
        .expect("request offline-account login");
    let login = registry
        .confirm_login(&server.emails.take_token(email))
        .expect("confirm offline-account login");
    let identity = Identity::generate(&mut OsPlatform).expect("offline identity");
    registry
        .put_recovery(&login.session, &identity.wallet_secret())
        .expect("store offline account recovery");
    let seq = OsPlatform.now_unix_secs();
    let record = SignedRecord::sign(
        Record {
            user_id: user_id(&identity.wallet_public()),
            handle: Handle::new(handle).expect("offline handle"),
            name: display_name.to_string(),
            wallet: identity.wallet_public(),
            device: Device::create(&identity, seq),
            seq,
        },
        &identity,
    );
    registry
        .put_record(&login.session, &record)
        .expect("publish offline signed record");
    (identity, record)
}

fn assert_tree_does_not_contain(root: &Path, plaintext: &[u8]) {
    for entry in std::fs::read_dir(root).expect("read registry data directory") {
        let path = entry.expect("registry data entry").path();
        if path.is_dir() {
            assert_tree_does_not_contain(&path, plaintext);
        } else {
            let bytes = std::fs::read(&path).expect("read registry data file");
            assert!(
                !bytes
                    .windows(plaintext.len())
                    .any(|window| window == plaintext),
                "registry persisted message plaintext in {}",
                path.display()
            );
        }
    }
}

fn error_text(result: Result<DeliveryState, MobileError>) -> String {
    result
        .expect_err("operation unexpectedly succeeded")
        .to_string()
}

#[test]
fn native_clients_complete_online_offline_and_device_switch_flows() {
    let root = TempDir::new().expect("test directory");
    let registry_dir = root.path().join("registry");
    let server = TestRegistry::start(&registry_dir, [0x5a; 32]);
    let probe = std::net::TcpListener::bind("[::1]:0").expect("reserve Reticulum test port");
    let backbone_addr = probe.local_addr().expect("Reticulum test listener address");
    drop(probe);
    let _reticulum_backbone =
        ReticulumBackbone::tcp(backbone_addr.to_string()).expect("start Reticulum test backbone");
    std::env::set_var("MYCELLIUM_RETICULUM_TCP_NODES", backbone_addr.to_string());

    let alice = MobileClient::open(
        root.path().join("alice").display().to_string(),
        None,
        Some(server.base_url.clone()),
    )
    .expect("open Alice client");
    let bob = MobileClient::open(
        root.path().join("bob").display().to_string(),
        None,
        Some(server.base_url.clone()),
    )
    .expect("open Bob client");
    assert_eq!(alice.state(), ClientState::NeedsLogin);
    assert_eq!(bob.state(), ClientState::NeedsLogin);

    let alice_login = login(&alice, &server, "alice@example.test");
    let bob_login = login(&bob, &server, "bob@example.test");
    assert!(alice_login.created && alice_login.identity_secret.is_some());
    assert!(bob_login.created && bob_login.identity_secret.is_some());
    assert_eq!(alice_login.state, ClientState::NeedsProfile);
    assert_eq!(bob_login.state, ClientState::NeedsProfile);

    let alice_profile = alice
        .save_profile("alice".into(), "Alice Example".into())
        .expect("publish Alice profile");
    let bob_profile = bob
        .save_profile("bob".into(), "Bob Example".into())
        .expect("publish Bob profile");
    alice
        .add_contact(bob_profile.connection_card.clone(), None)
        .expect("Alice saves Bob");
    bob.add_contact(alice_profile.connection_card.clone(), None)
        .expect("Bob saves Alice");
    require_connectivity(&alice);
    require_connectivity(&bob);

    let online_text = "online-e2e-7a13b0";
    assert_eq!(
        alice
            .send_text(bob_profile.user_id.clone(), online_text.into())
            .expect("Alice sends an online message"),
        DeliveryState::Delivered
    );
    assert_eq!(alice.pending_count().expect("Alice pending count"), 0);
    wait_for_message(&bob, &alice_profile.user_id, online_text);
    let outgoing = alice
        .messages(bob_profile.user_id.clone())
        .expect("Alice history");
    assert!(
        outgoing
            .iter()
            .any(|message| message.text == online_text && message.from_me),
        "sender did not persist its outgoing history"
    );
    assert!(bob
        .conversations()
        .expect("Bob conversations")
        .iter()
        .any(|conversation| conversation.user_id == alice_profile.user_id));
    assert!(bob
        .poll_events()
        .iter()
        .any(|event| event.kind == EventKind::Message));

    // Publish a legitimate account/device record but keep the device offline.
    // The registry knows how to discover it, but cannot receive its payload.
    let (charlie_identity, charlie_record) = publish_offline_account(
        &server,
        "charlie@example.test",
        "charlie",
        "Charlie Offline",
    );
    alice
        .add_contact(mycellium_client::encode_record(&charlie_record), None)
        .expect("Alice saves Charlie");
    let offline_text = "sender-held-offline-e2e-91c7";
    assert_eq!(
        alice
            .send_text(
                charlie_record.record.user_id.as_str().to_string(),
                offline_text.into(),
            )
            .expect("Alice queues an offline message"),
        DeliveryState::Pending
    );
    assert_eq!(alice.pending_count().expect("pending offline message"), 1);

    let charlie = MobileClient::open(
        root.path().join("charlie").display().to_string(),
        Some(identity_secret(&charlie_identity)),
        Some(server.base_url.clone()),
    )
    .expect("open Charlie client");
    let charlie_login = login(&charlie, &server, "charlie@example.test");
    assert!(!charlie_login.created);
    assert_eq!(charlie_login.state, ClientState::Ready);
    require_connectivity(&charlie);
    let retry_deadline = Instant::now() + Duration::from_secs(15);
    while alice.pending_count().expect("Alice pending count") != 0
        && Instant::now() < retry_deadline
    {
        let _ = alice.retry_pending();
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(alice.pending_count().expect("offline retry completed"), 0);
    wait_for_message(&charlie, &alice_profile.user_id, offline_text);
    assert_eq!(
        charlie
            .messages(alice_profile.user_id.clone())
            .expect("Charlie history")
            .iter()
            .filter(|message| message.text == offline_text)
            .count(),
        1,
        "retry must not duplicate recipient history"
    );

    // A second login adopts the same account wallet but creates a fresh device.
    let old_record = RegistryClient::new(&server.base_url)
        .expect("registry client")
        .get_record_for_user(&alice_profile.user_id)
        .expect("load old Alice record")
        .expect("old Alice record exists");
    let alice_replacement = MobileClient::open(
        root.path().join("alice-replacement").display().to_string(),
        None,
        Some(server.base_url.clone()),
    )
    .expect("open replacement Alice client");
    let replacement_login = login(&alice_replacement, &server, "alice@example.test");
    assert!(!replacement_login.created);
    assert!(replacement_login.identity_secret.is_some());
    assert_eq!(replacement_login.state, ClientState::Ready);
    let replacement_profile = alice_replacement
        .profile()
        .expect("replacement profile")
        .expect("replacement profile exists");
    assert_eq!(replacement_profile.user_id, alice_profile.user_id);
    require_connectivity(&alice_replacement);

    let new_record = RegistryClient::new(&server.base_url)
        .expect("registry client")
        .get_record_for_user(&alice_profile.user_id)
        .expect("load replacement Alice record")
        .expect("replacement Alice record exists");
    assert_ne!(
        old_record.record.device.device_key, new_record.record.device.device_key,
        "device switching must create fresh device keys"
    );
    assert_eq!(
        alice.refresh_device_status().expect("refresh old device"),
        ClientState::Replaced
    );
    assert!(
        error_text(alice.send_text(bob_profile.user_id.clone(), "blocked".into()))
            .contains("replaced")
    );

    let replacement_text = "replacement-device-only-e2e-42de";
    assert_eq!(
        bob.send_text(alice_profile.user_id.clone(), replacement_text.into())
            .expect("Bob sends to Alice's replacement device"),
        DeliveryState::Delivered
    );
    wait_for_message(&alice_replacement, &bob_profile.user_id, replacement_text);
    assert!(
        alice
            .messages(bob_profile.user_id.clone())
            .expect("old Alice history")
            .iter()
            .all(|message| message.text != replacement_text),
        "the retired device received traffic intended for the replacement"
    );

    // Only endpoint stores may contain message content. Registry account,
    // record and recovery files must remain payload-blind.
    assert_tree_does_not_contain(&registry_dir, online_text.as_bytes());
    assert_tree_does_not_contain(&registry_dir, offline_text.as_bytes());
    assert_tree_does_not_contain(&registry_dir, replacement_text.as_bytes());
}
