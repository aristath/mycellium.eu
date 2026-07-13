//! Encrypted identity storage (Layer 9 hardening).
//!
//! The account is a random **wallet secret** plus this device's own seed, so
//! those 32-byte secrets must not sit in plaintext. We derive a key from a user
//! passphrase with **Argon2id** and seal the `wallet_secret + device_seed` with
//! **ChaCha20-Poly1305**. Moving an account to a fresh device is either an
//! explicit wallet-secret transfer or a local decrypt of a registry-provided
//! encrypted wallet backup.
//!
//! Interactive callers can type the passphrase at a **no-echo** terminal prompt.
//! Noninteractive callers pass an explicit [`ClientConfig`] before using the
//! store.

use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

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

static CONFIG: OnceLock<ClientConfig> = OnceLock::new();

/// Set the immutable process-local client config exactly once.
pub fn configure(config: ClientConfig) -> Result<()> {
    CONFIG
        .set(config)
        .map_err(|_| anyhow!("client storage is already configured"))
}

/// Return the current process-local client config.
pub fn config() -> ClientConfig {
    CONFIG.get().cloned().unwrap_or_default()
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
    identity_path(home())
}

/// Path to an encrypted identity file under `data_dir`.
pub fn identity_path(data_dir: impl Into<PathBuf>) -> PathBuf {
    data_dir.into().join("identity.enc")
}

/// The data directory root, for other local state.
pub fn data_dir() -> PathBuf {
    home()
}

/// Whether an identity already exists on disk.
pub fn exists() -> bool {
    path().exists()
}

/// Whether an identity exists under `data_dir`.
pub fn exists_in(data_dir: impl Into<PathBuf>) -> bool {
    identity_path(data_dir).exists()
}

/// The minimum passphrase length enforced when *creating* an identity. Unlocking
/// an existing one never checks length, so older shorter passphrases still work.
pub const MIN_PASSPHRASE_LEN: usize = 8;

/// Encrypt and store `identity` under a passphrase.
pub fn save_identity(identity: &Identity) -> Result<()> {
    let passphrase = new_passphrase("Choose a passphrase to encrypt your identity")?;
    save_identity_with_passphrase_at(home(), identity, &passphrase)
}

/// Encrypt and store `identity` under `data_dir` using an explicit passphrase.
///
/// GUI and service callers use this instead of the process-global prompt/config
/// path, so a failed unlock does not poison process state.
pub fn save_identity_with_passphrase_at(
    data_dir: impl Into<PathBuf>,
    identity: &Identity,
    passphrase: &str,
) -> Result<()> {
    if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
        bail!("passphrase must be at least {MIN_PASSPHRASE_LEN} characters");
    }
    let sealed = seal_identity(identity, passphrase)?;
    crate::atomic_write(&identity_path(data_dir), &sealed)?;
    Ok(())
}

/// Load and decrypt the stored identity.
pub fn load_identity() -> Result<Identity> {
    let bytes =
        fs::read(path()).context("no identity found — run `mycellium identity-new` first")?;

    open_identity(&bytes)
}

/// Load an identity from `data_dir` using an explicit passphrase.
pub fn load_identity_with_passphrase_from(
    data_dir: impl Into<PathBuf>,
    passphrase: &str,
) -> Result<Identity> {
    let path = identity_path(data_dir);
    let bytes =
        fs::read(&path).with_context(|| format!("no identity found at {}", path.display()))?;
    open_identity_with_passphrase(&bytes, passphrase)
}

/// Validate and decrypt an encoded identity blob using the configured
/// passphrase. Backup import uses this before writing anything to disk.
pub fn open_identity(bytes: &[u8]) -> Result<Identity> {
    let passphrase = passphrase("Passphrase to unlock your identity")?;
    open_identity_with_passphrase(bytes, &passphrase)
}

/// Validate and decrypt an encoded identity blob using an explicit passphrase.
pub fn open_identity_with_passphrase(bytes: &[u8], passphrase: &str) -> Result<Identity> {
    let plaintext = seal::open(passphrase, bytes).map_err(|e| match e {
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

fn seal_identity(identity: &Identity, passphrase: &str) -> Result<Vec<u8>> {
    let secret = Secret {
        wallet_secret: identity.wallet_secret().to_vec(),
        device_seed: identity.device_seed().to_vec(),
    };
    let plaintext = serde_json::to_vec(&secret)?;
    seal::seal(passphrase, &plaintext).map_err(|e| anyhow!("failed to encrypt identity: {e}"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use mycellium_core::identity::Identity;
    use mycellium_core::platform::Platform;

    struct SeededPlatform(u8);

    impl Platform for SeededPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }

        fn now_unix_secs(&self) -> u64 {
            42
        }
    }

    #[test]
    fn explicit_identity_storage_round_trips_without_global_config() {
        let mut platform = SeededPlatform(1);
        let identity = Identity::generate(&mut platform).unwrap();
        let root = std::env::temp_dir().join(format!(
            "mycellium-store-test-{}",
            crate::seal::seal("pw", b"nonce").unwrap().len()
        ));
        let _ = std::fs::remove_dir_all(&root);

        save_identity_with_passphrase_at(&root, &identity, "long enough").unwrap();
        assert!(exists_in(&root));
        let loaded = load_identity_with_passphrase_from(&root, "long enough").unwrap();
        assert_eq!(loaded.wallet_public(), identity.wallet_public());
        assert_eq!(loaded.device_public(), identity.device_public());
        assert!(load_identity_with_passphrase_from(&root, "wrong passphrase").is_err());

        let _ = std::fs::remove_dir_all(&root);
    }
}
