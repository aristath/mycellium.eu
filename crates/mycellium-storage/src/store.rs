//! Encrypted identity storage (Layer 9 hardening).
//!
//! The account is a random **wallet secret** plus this device's own seed (there is
//! no seed phrase — recovery is via email, see #6), so those 32-byte secrets must
//! not sit in plaintext. We derive a key from a user passphrase with **Argon2id**
//! and seal the `wallet_secret + device_seed` with **ChaCha20-Poly1305**. Losing
//! the passphrase means losing this on-disk copy; the account is then recovered by
//! re-binding the handle from a fresh device via email verification.
//!
//! The passphrase comes from `MYCELLIUM_PASSPHRASE` if set (for non-interactive
//! use — convenient but it lands in the environment/process table, so prefer the
//! prompt for real use), otherwise it is read from a **no-echo** terminal prompt.

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};

use mycellium_core::identity::Identity;

/// On-disk encrypted identity.
#[derive(Serialize, Deserialize)]
struct Sealed {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// The secret material sealed inside [`Sealed`]: the account wallet secret plus
/// this device's own seed (Layer 11), so reloading reproduces the *same* device.
#[derive(Serialize, Deserialize)]
struct Secret {
    wallet_secret: Vec<u8>,
    device_seed: Vec<u8>,
}

/// The data directory (`MYCELLIUM_HOME`, default `.mycellium`).
fn home() -> PathBuf {
    std::env::var("MYCELLIUM_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".mycellium"))
}

/// Path to the encrypted identity file.
pub fn path() -> PathBuf {
    home().join("identity.enc")
}

/// The data directory root (`MYCELLIUM_HOME`), for other local state.
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

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut salt)?;
    getrandom::getrandom(&mut nonce)?;

    let key = derive_key(&passphrase, &salt)?;
    let key_ga: Key = key.into();
    let nonce_ga: Nonce = nonce.into();
    let secret = Secret {
        wallet_secret: identity.wallet_secret().to_vec(),
        device_seed: identity.device_seed().to_vec(),
    };
    let plaintext = serde_json::to_vec(&secret)?;
    let ciphertext = ChaCha20Poly1305::new(&key_ga)
        .encrypt(&nonce_ga, plaintext.as_ref())
        .map_err(|_| anyhow!("failed to encrypt identity"))?;

    let sealed = Sealed {
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    };

    fs::create_dir_all(home())?;
    crate::perms::restrict_dir(&home());
    let json = serde_json::to_string(&sealed)?;
    fs::write(path(), json)?;
    crate::perms::restrict_file(&path());
    Ok(())
}

/// Load and decrypt the stored identity.
pub fn load_identity() -> Result<Identity> {
    let json = fs::read_to_string(path())
        .context("no identity found — run `mycellium identity-new` first")?;
    let sealed: Sealed = serde_json::from_str(&json).context("identity file is corrupt")?;

    let passphrase = passphrase("Passphrase to unlock your identity")?;
    let key = derive_key(&passphrase, &sealed.salt)?;
    let key_ga: Key = key.into();

    let nonce_arr: [u8; 12] = sealed
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("identity file is corrupt"))?;
    let nonce_ga: Nonce = nonce_arr.into();

    let plaintext = ChaCha20Poly1305::new(&key_ga)
        .decrypt(&nonce_ga, sealed.ciphertext.as_ref())
        .map_err(|_| anyhow!("wrong passphrase or corrupt identity"))?;
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

/// Derive a 32-byte key from a passphrase and salt with Argon2id.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Obtain the passphrase from the environment or, failing that, a **no-echo**
/// terminal prompt (so it isn't left in scrollback / screen shares).
fn passphrase(prompt: &str) -> Result<String> {
    if let Ok(p) = std::env::var("MYCELLIUM_PASSPHRASE") {
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
    if std::env::var("MYCELLIUM_PASSPHRASE").is_ok() {
        return passphrase(prompt); // noninteractive: nothing to confirm against
    }
    let first = passphrase(prompt)?;
    let again = rpassword::prompt_password("Confirm passphrase: ")?;
    if first != again.trim_end_matches(['\r', '\n']) {
        bail!("passphrases did not match");
    }
    Ok(first)
}
