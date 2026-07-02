//! Encrypted identity storage (Layer 9 hardening).
//!
//! The seed phrase is the whole identity, so it must not sit in plaintext. We
//! derive a key from a user passphrase with **Argon2id** and seal the mnemonic
//! with **ChaCha20-Poly1305**. Losing the passphrase means losing the on-disk
//! copy — the 24 words remain the ultimate backup (Layer 9.4/9.5).
//!
//! The passphrase comes from `MESSE_PASSPHRASE` if set (for non-interactive
//! use), otherwise it is read from stdin.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};

use messe_core::identity::Identity;

/// On-disk encrypted identity.
#[derive(Serialize, Deserialize)]
struct Sealed {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// The data directory (`MESSE_HOME`, default `.messe`).
fn home() -> PathBuf {
    std::env::var("MESSE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".messe"))
}

/// Path to the encrypted identity file.
pub fn path() -> PathBuf {
    home().join("identity.enc")
}

/// The data directory root (`MESSE_HOME`), for other local state.
pub fn data_dir() -> PathBuf {
    home()
}

/// Whether an identity already exists on disk.
pub fn exists() -> bool {
    path().exists()
}

/// Encrypt and store `identity` under a passphrase.
pub fn save_identity(identity: &Identity) -> Result<()> {
    let passphrase = passphrase("Choose a passphrase to encrypt your identity")?;

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut salt)?;
    getrandom::getrandom(&mut nonce)?;

    let key = derive_key(&passphrase, &salt)?;
    let key_ga: Key = key.into();
    let nonce_ga: Nonce = nonce.into();
    let ciphertext = ChaCha20Poly1305::new(&key_ga)
        .encrypt(&nonce_ga, identity.mnemonic().as_bytes())
        .map_err(|_| anyhow!("failed to encrypt identity"))?;

    let sealed = Sealed {
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    };

    fs::create_dir_all(home())?;
    let json = serde_json::to_string(&sealed)?;
    fs::write(path(), json)?;
    Ok(())
}

/// Load and decrypt the stored identity.
pub fn load_identity() -> Result<Identity> {
    let json = fs::read_to_string(path())
        .context("no identity found — run `messe identity-new` first")?;
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
    let phrase = String::from_utf8(plaintext).context("decrypted seed is not valid text")?;

    Identity::from_phrase(phrase.trim()).map_err(|_| anyhow!("stored seed phrase is invalid"))
}

/// Derive a 32-byte key from a passphrase and salt with Argon2id.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Obtain the passphrase from the environment or, failing that, stdin.
fn passphrase(prompt: &str) -> Result<String> {
    if let Ok(p) = std::env::var("MESSE_PASSPHRASE") {
        return Ok(p);
    }
    eprint!("{prompt}: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let line = line.trim_end_matches(['\r', '\n']).to_string();
    if line.is_empty() {
        bail!("an empty passphrase is not allowed");
    }
    Ok(line)
}
