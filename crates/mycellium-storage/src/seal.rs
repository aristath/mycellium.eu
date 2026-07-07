//! The one passphrase-sealing primitive: **Argon2id** key derivation +
//! **ChaCha20-Poly1305** AEAD, with a small JSON `Sealed` wire struct
//! (salt + nonce + ciphertext).
//!
//! Both at-rest secret stores ride on this exact code so their on-disk format
//! stays **bit-compatible**: the CLI's identity file ([`crate::store`]) and the
//! SDK's passphrase [`SecretStore`](../../mycellium_sdk/secrets) both call
//! [`seal`] / [`open`]. Security material that must decrypt across two crates
//! cannot afford two hand-copied implementations that silently drift apart.
//!
//! Fails **closed**: a wrong passphrase (or any tampering) trips the AEAD tag and
//! returns [`SealError::WrongKeyOrCorrupt`] — never a wrong or empty plaintext.

use argon2::Argon2;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};

/// One sealed blob on disk: a random per-blob salt + nonce and the AEAD
/// ciphertext, serialized as JSON.
#[derive(Serialize, Deserialize)]
struct Sealed {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Why a [`seal`] / [`open`] failed. Callers map this onto their own error
/// taxonomy (anyhow in the CLI store, `SdkError` in the SDK).
#[derive(Debug)]
pub enum SealError {
    /// Argon2id key derivation failed.
    KeyDerivation(String),
    /// The system RNG failed while generating a salt or nonce.
    Random(String),
    /// Encryption itself failed (not expected with a valid key/nonce).
    Encrypt,
    /// The AEAD refused the ciphertext: wrong passphrase or tampering. The
    /// fail-closed signal — never treat this as a recoverable "absent" value.
    WrongKeyOrCorrupt,
    /// The sealed blob is structurally malformed (bad JSON or a bad nonce length).
    Corrupt,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealError::KeyDerivation(e) => write!(f, "key derivation failed: {e}"),
            SealError::Random(e) => write!(f, "failed to gather randomness: {e}"),
            SealError::Encrypt => write!(f, "failed to seal secret"),
            SealError::WrongKeyOrCorrupt => write!(f, "wrong passphrase or corrupt data"),
            SealError::Corrupt => write!(f, "sealed data is corrupt"),
        }
    }
}

impl std::error::Error for SealError {}

/// Derive a 32-byte key from a passphrase and salt with Argon2id (default params).
/// The params are part of the on-disk format — changing them breaks every
/// previously sealed blob, so both stores share this one definition.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], SealError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| SealError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

/// Seal `plaintext` under `passphrase`, returning the serialized `Sealed` blob
/// (a fresh random salt + nonce embedded). This is the exact byte format both
/// stores read back with [`open`].
pub fn seal(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut salt).map_err(|e| SealError::Random(e.to_string()))?;
    getrandom::getrandom(&mut nonce).map_err(|e| SealError::Random(e.to_string()))?;

    let key_ga: Key = derive_key(passphrase, &salt)?.into();
    let nonce_ga: Nonce = nonce.into();
    let ciphertext = ChaCha20Poly1305::new(&key_ga)
        .encrypt(&nonce_ga, plaintext)
        .map_err(|_| SealError::Encrypt)?;

    let sealed = Sealed {
        salt: salt.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext,
    };
    // Serializing three `Vec<u8>` fields to JSON cannot fail in practice.
    serde_json::to_vec(&sealed).map_err(|_| SealError::Encrypt)
}

/// Open a blob produced by [`seal`] under `passphrase`. Fails **closed**
/// ([`SealError::WrongKeyOrCorrupt`]) on a wrong passphrase or any tampering.
pub fn open(passphrase: &str, bytes: &[u8]) -> Result<Vec<u8>, SealError> {
    let sealed: Sealed = serde_json::from_slice(bytes).map_err(|_| SealError::Corrupt)?;
    let key_ga: Key = derive_key(passphrase, &sealed.salt)?.into();
    let nonce_arr: [u8; 12] = sealed
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| SealError::Corrupt)?;
    let nonce_ga: Nonce = nonce_arr.into();
    // Wrong passphrase (or tampering) fails the AEAD tag — fail closed.
    ChaCha20Poly1305::new(&key_ga)
        .decrypt(&nonce_ga, sealed.ciphertext.as_ref())
        .map_err(|_| SealError::WrongKeyOrCorrupt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trips() {
        let blob = seal("correct horse battery staple", b"the account key").unwrap();
        let out = open("correct horse battery staple", &blob).unwrap();
        assert_eq!(out, b"the account key");
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let blob = seal("right passphrase", b"secret").unwrap();
        let err = open("wrong passphrase", &blob).unwrap_err();
        assert!(
            matches!(err, SealError::WrongKeyOrCorrupt),
            "wrong passphrase must fail closed, got {err:?}"
        );
    }

    #[test]
    fn plaintext_never_appears_on_disk() {
        let secret = b"a very secret blob value!!!!!!!!";
        let blob = seal("pw", secret).unwrap();
        assert!(
            blob.windows(secret.len()).all(|w| w != secret.as_slice()),
            "plaintext must not appear in the sealed blob"
        );
    }

    #[test]
    fn corrupt_blob_is_rejected() {
        let err = open("pw", b"not valid json").unwrap_err();
        assert!(matches!(err, SealError::Corrupt), "got {err:?}");
    }
}
