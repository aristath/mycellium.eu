//! The import path a native client uses when the user already holds a Nostr key:
//! [`import_identity`] validates the pasted secret and returns the `npub` to show
//! ("Importing aristath — npub1… — correct?"), and the *same* nsec then opens the
//! account under that exact identity. A public `npub` must be refused, since a
//! public key cannot sign and so cannot back an account.

use mycellium_sdk::{generate_identity, import_identity, MycelliumClient};
use tempfile::TempDir;

#[test]
fn import_identity_returns_npub_and_matches_the_opened_account() {
    let nsec = generate_identity();

    // Validating the secret yields an npub the UI can confirm before committing.
    let npub = import_identity(nsec.clone()).expect("a generated nsec is valid");
    assert!(npub.starts_with("npub1"), "expected an npub, got {npub}");

    // The identity import previews is exactly the one the app opens with that nsec.
    let dir = TempDir::new().unwrap();
    let client = MycelliumClient::open_solo(
        nsec,
        vec!["wss://relay.example".to_string()],
        dir.path().to_string_lossy().into_owned(),
    )
    .expect("opening a solo account from the imported nsec");
    assert_eq!(client.account_npub(), npub);
}

#[test]
fn import_identity_rejects_a_public_key() {
    // A real npub (its matching secret is not known to us) — importing it must fail.
    let npub = "npub1zgmluqqg9uv2adezvjm5fjnv85ng7fkqhk856ywtq78shak78qyqefdldm";
    let err = import_identity(npub.to_string()).expect_err("a public key cannot be imported");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("public key") && msg.contains("nsec"),
        "error should explain a public key can't be imported: {msg}"
    );
}
