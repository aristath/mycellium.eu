//! Encrypted identity storage (Layer 9 hardening).
//!
//! The account is a random **wallet secret** plus this device's own seed (there is
//! no hosted recovery authority), so those 32-byte secrets must not sit in
//! plaintext. We derive a key from a user passphrase with **Argon2id** and seal
//! the `wallet_secret + device_seed` with **ChaCha20-Poly1305**. Moving an account
//! to a fresh device is an explicit wallet-secret transfer.
//!
//! Interactive callers can type the passphrase at a **no-echo** terminal prompt.
//! Noninteractive callers pass an explicit [`ClientConfig`] before using the
//! store.

use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use mycellium_core::identity::Identity;

use crate::seal::{self, SealError};

/// Process-local client configuration.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Root directory for identity, history, downloads, and other local state.
    pub data_dir: PathBuf,
    /// Optional noninteractive passphrase for identity encryption.
    pub passphrase: Option<String>,
    /// This account's display name, recorded in peer records.
    pub display_name: String,
    /// Optional DHT bootstrap peer multiaddrs for non-authoritative discovery.
    pub dht_bootstrap: Vec<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(".mycellium"),
            passphrase: None,
            display_name: String::new(),
            dht_bootstrap: Vec::new(),
        }
    }
}

static CONFIG: OnceLock<Mutex<ClientConfig>> = OnceLock::new();

fn config_cell() -> &'static Mutex<ClientConfig> {
    CONFIG.get_or_init(|| Mutex::new(ClientConfig::default()))
}

/// Replace the process-local client config.
pub fn configure(config: ClientConfig) {
    *config_cell().lock().unwrap() = config;
}

/// Return the current process-local client config.
pub fn config() -> ClientConfig {
    config_cell().lock().unwrap().clone()
}

/// Update just the configured display name.
pub fn set_display_name(display_name: impl Into<String>) {
    config_cell().lock().unwrap().display_name = display_name.into();
}

/// This account's display name, recorded in peer records.
pub fn display_name() -> String {
    config().display_name
}

/// The secret material sealed on disk: the account wallet secret plus
/// this device's own seed (Layer 11), so reloading reproduces the *same* device.
#[derive(Serialize, Deserialize)]
struct Secret {
    wallet_secret: Vec<u8>,
    device_seed: Vec<u8>,
}

/// The configured data directory.
fn home() -> PathBuf {
    config().data_dir
}

/// Path to the encrypted identity file.
pub fn path() -> PathBuf {
    home().join("identity.enc")
}

/// The data directory root, for other local state.
pub fn data_dir() -> PathBuf {
    home()
}

/// Whether an identity already exists on disk.
pub fn exists() -> bool {
    path().exists()
}

/// The minimum passphrase length enforced when *creating* an identity. Unlocking
/// an existing one never checks length, so older shorter passphrases still work.
pub const MIN_PASSPHRASE_LEN: usize = 8;

/// Encrypt and store `identity` under a passphrase.
pub fn save_identity(identity: &Identity) -> Result<()> {
    let passphrase = new_passphrase("Choose a passphrase to encrypt your identity")?;
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        bail!("passphrase must be at least {MIN_PASSPHRASE_LEN} characters");
    }

    let secret = Secret {
        wallet_secret: identity.wallet_secret().to_vec(),
        device_seed: identity.device_seed().to_vec(),
    };
    let plaintext = serde_json::to_vec(&secret)?;
    let sealed = seal::seal(&passphrase, &plaintext)
        .map_err(|e| anyhow!("failed to encrypt identity: {e}"))?;

    fs::create_dir_all(home())?;
    crate::perms::restrict_dir(&home());
    fs::write(path(), sealed)?;
    crate::perms::restrict_file(&path());
    Ok(())
}

/// Load and decrypt the stored identity.
pub fn load_identity() -> Result<Identity> {
    let bytes =
        fs::read(path()).context("no identity found — run `mycellium identity-new` first")?;

    let passphrase = passphrase("Passphrase to unlock your identity")?;
    let plaintext = seal::open(&passphrase, &bytes).map_err(|e| match e {
        SealError::Corrupt => anyhow!("identity file is corrupt"),
        SealError::WrongKeyOrCorrupt => anyhow!("wrong passphrase or corrupt identity"),
        other => anyhow!("{other}"),
    })?;
    let secret: Secret =
        serde_json::from_slice(&plaintext).context("decrypted identity is corrupt")?;
    let device_seed: [u8; 32] = secret
        .device_seed
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("identity file has a malformed device seed"))?;
    let wallet_secret: [u8; 32] = secret
        .wallet_secret
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("identity file has a malformed wallet secret"))?;

    Identity::from_wallet_secret(wallet_secret, device_seed)
        .map_err(|_| anyhow!("stored account key is invalid"))
}

/// Obtain the configured passphrase or, failing that, a **no-echo** terminal
/// prompt (so it isn't left in scrollback / screen shares).
fn passphrase(prompt: &str) -> Result<String> {
    if let Some(p) = config().passphrase {
        return Ok(p);
    }
    let line = rpassword::prompt_password(format!("{prompt}: "))?;
    let line = line.trim_end_matches(['\r', '\n']).to_string();
    if line.is_empty() {
        bail!("an empty passphrase is not allowed");
    }
    Ok(line)
}

/// Like [`passphrase`], but on interactive creation prompts a second time and
/// requires the two to match (typos in a new passphrase are unrecoverable).
fn new_passphrase(prompt: &str) -> Result<String> {
    if config().passphrase.is_some() {
        return passphrase(prompt); // noninteractive: nothing to confirm against
    }
    let first = passphrase(prompt)?;
    let again = rpassword::prompt_password("Confirm passphrase: ")?;
    if first != again.trim_end_matches(['\r', '\n']) {
        bail!("passphrases did not match");
    }
    Ok(first)
}
