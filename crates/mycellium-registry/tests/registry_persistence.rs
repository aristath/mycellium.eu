mod support;

use std::path::Path;

use mycellium_client::registry::{RegistryClient, RegistrySession};
use mycellium_core::identity::{Handle, Identity};
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, Record, SignedRecord};
use mycellium_core::userid::user_id;
use serde_json::json;
use tempfile::TempDir;
use ureq::{Agent, Error};

use support::TestRegistry;

struct OsPlatform;

impl Platform for OsPlatform {
    fn fill_random(&mut self, bytes: &mut [u8]) {
        getrandom::getrandom(bytes).expect("OS randomness");
    }

    fn now_unix_secs(&self) -> u64 {
        1_700_000_000
    }
}

fn request_and_confirm(
    server: &TestRegistry,
    email: &str,
) -> (String, mycellium_client::registry::ConfirmedLogin) {
    let registry = RegistryClient::new(&server.base_url).expect("registry client");
    registry
        .request_email_login(email)
        .expect("request login email");
    let token = server.emails.take_token(email);
    let login = registry.confirm_login(&token).expect("confirm login");
    (token, login)
}

fn bearer(session: &RegistrySession) -> String {
    format!("Bearer {}", session.session_token)
}

fn assert_status(error: Error, expected: u16) {
    assert!(
        matches!(error, Error::StatusCode(status) if status == expected),
        "expected HTTP {expected}, got {error}"
    );
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
                "registry persisted forbidden plaintext in {}",
                path.display()
            );
        }
    }
}

#[test]
fn registry_authentication_and_state_survive_a_clean_restart() {
    let root = TempDir::new().expect("test directory");
    let data_dir = root.path().join("registry");
    let recovery_key = [0xa7; 32];
    let email = "restart-owner@example.test";
    let identity = Identity::generate(&mut OsPlatform).expect("identity");
    let wallet_secret = identity.wallet_secret();
    let seq = OsPlatform.now_unix_secs();
    let record = SignedRecord::sign(
        Record {
            user_id: user_id(&identity.wallet_public()),
            handle: Handle::new("restart_owner").expect("handle"),
            name: "Restart Owner".into(),
            wallet: identity.wallet_public(),
            device: Device::create(&identity, seq),
            seq,
        },
        &identity,
    );

    let first_account;
    let first_rendezvous_peer;
    {
        let server = TestRegistry::start(&data_dir, recovery_key);
        let registry = RegistryClient::new(&server.base_url).expect("registry client");
        let (used_token, owner) = request_and_confirm(&server, email);
        assert!(owner.created);
        first_account = owner.session.account_id.clone();
        registry
            .put_recovery(&owner.session, &wallet_secret)
            .expect("store recovery material");
        registry
            .put_record(&owner.session, &record)
            .expect("store public record");
        assert_eq!(
            registry
                .get_record_for_user(record.record.user_id.as_str())
                .expect("resolve by user id"),
            Some(record.clone())
        );
        first_rendezvous_peer = registry
            .rendezvous_address()
            .expect("rendezvous address")
            .split("/p2p/")
            .nth(1)
            .expect("rendezvous PeerId")
            .to_string();

        let (_, intruder) = request_and_confirm(&server, "intruder@example.test");
        let agent = Agent::new_with_defaults();
        let recovery_url = format!(
            "{}/accounts/{}/recovery",
            server.base_url, owner.session.account_id
        );
        let error = agent
            .put(&recovery_url)
            .header("authorization", &bearer(&intruder.session))
            .send(&wallet_secret[..])
            .expect_err("cross-account write was accepted");
        assert_status(error, 403);

        let error = agent
            .get(&recovery_url)
            .header("authorization", "Bearer invalid-session")
            .call()
            .expect_err("invalid bearer token was accepted");
        assert_status(error, 401);

        let error = agent
            .post(format!("{}/login/confirm", server.base_url))
            .send_json(json!({ "token": used_token }))
            .expect_err("one-time login token was accepted twice");
        assert_status(error, 400);

        // Public identity records are intentionally discoverable without an
        // account session; recovery material is not.
        agent
            .get(format!(
                "{}/users/{}/record",
                server.base_url,
                record.record.user_id.as_str()
            ))
            .call()
            .expect("public record lookup");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(data_dir.join("rendezvous.key"))
            .expect("rendezvous identity metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "rendezvous secret must be owner-only");
    }

    // Neither the login identity nor the recovery root may be recoverable by
    // scanning persistent registry files.
    assert_tree_does_not_contain(&data_dir, email.as_bytes());
    assert_tree_does_not_contain(&data_dir, &wallet_secret);

    {
        let server = TestRegistry::start(&data_dir, recovery_key);
        let registry = RegistryClient::new(&server.base_url).expect("registry client");
        let (_, owner) = request_and_confirm(&server, email);
        assert!(!owner.created);
        assert_eq!(owner.session.account_id, first_account);
        assert_eq!(
            registry
                .get_recovery(&owner.session)
                .expect("recover wallet root"),
            Some(wallet_secret)
        );
        assert_eq!(
            registry
                .get_record(&owner.session.account_id)
                .expect("load account record"),
            Some(record.clone())
        );
        assert_eq!(
            registry
                .get_record_for_user(record.record.user_id.as_str())
                .expect("resolve restarted record by user id"),
            Some(record)
        );
        let restarted_peer = registry
            .rendezvous_address()
            .expect("restarted rendezvous address")
            .split("/p2p/")
            .nth(1)
            .expect("restarted rendezvous PeerId")
            .to_string();
        assert_eq!(restarted_peer, first_rendezvous_peer);
    }
}
