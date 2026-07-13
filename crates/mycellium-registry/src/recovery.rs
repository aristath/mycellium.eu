//! Registry-assisted protocol-identity recovery.
//!
//! The client sends the 32-byte wallet root over authenticated HTTPS. The
//! registry seals it before writing it to blob storage and only opens it for an
//! authenticated session belonging to the same account.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::{AccountId, RegistryError, Result};

const MAGIC: &[u8; 5] = b"MCRK\x01";
const NONCE_LEN: usize = 24;

/// Encrypts recovery material before it reaches persistent storage.
#[derive(Clone)]
pub struct RecoveryCipher {
    key: [u8; 32],
}

impl Drop for RecoveryCipher {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

impl RecoveryCipher {
    /// Build a recovery cipher from a 32-byte master key.
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Load the registry master key from its required environment variable.
    pub fn from_env() -> Result<Self> {
        let value = std::env::var("MYCELLIUM_REGISTRY_RECOVERY_KEY")
            .map_err(|_| RegistryError::new("MYCELLIUM_REGISTRY_RECOVERY_KEY is required"))?;
        Self::from_hex(value.trim())
    }

    /// Parse a 64-character hexadecimal master key.
    pub fn from_hex(value: &str) -> Result<Self> {
        if value.len() != 64 {
            return Err(RegistryError::new(
                "MYCELLIUM_REGISTRY_RECOVERY_KEY must be 64 hexadecimal characters",
            ));
        }
        let mut key = [0u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            key[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        Ok(Self::new(key))
    }

    /// Seal bytes for one account.
    pub fn seal(&self, account_id: &AccountId, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| RegistryError::new("recovery encryption randomness failed"))?;
        let cipher = XChaCha20Poly1305::new((&self.key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: recovery_aad(account_id).as_bytes(),
                },
            )
            .map_err(|_| RegistryError::new("recovery encryption failed"))?;
        let mut sealed = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(MAGIC);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// Open bytes for one account.
    pub fn open(&self, account_id: &AccountId, sealed: &[u8]) -> Result<Vec<u8>> {
        let Some(rest) = sealed.strip_prefix(MAGIC) else {
            return Err(RegistryError::new("unsupported recovery blob"));
        };
        if rest.len() <= NONCE_LEN {
            return Err(RegistryError::new("corrupt recovery blob"));
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        XChaCha20Poly1305::new((&self.key).into())
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: recovery_aad(account_id).as_bytes(),
                },
            )
            .map_err(|_| RegistryError::new("recovery blob authentication failed"))
    }
}

fn recovery_aad(account_id: &AccountId) -> String {
    format!("mycellium-registry-recovery-v1:{account_id}")
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RegistryError::new(
            "MYCELLIUM_REGISTRY_RECOVERY_KEY must be hexadecimal",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_material_is_encrypted_and_bound_to_account() {
        let cipher = RecoveryCipher::new([7; 32]);
        let first = "00000000000000000000000000000001"
            .parse::<AccountId>()
            .unwrap();
        let second = "00000000000000000000000000000002"
            .parse::<AccountId>()
            .unwrap();
        let secret = [9u8; 32];

        let sealed = cipher.seal(&first, &secret).unwrap();

        assert!(!sealed.windows(secret.len()).any(|bytes| bytes == secret));
        assert_eq!(cipher.open(&first, &sealed).unwrap(), secret);
        assert!(cipher.open(&second, &sealed).is_err());
    }

    #[test]
    fn recovery_key_requires_exact_hex() {
        assert!(RecoveryCipher::from_hex(&"ab".repeat(32)).is_ok());
        assert!(RecoveryCipher::from_hex("ab").is_err());
        assert!(RecoveryCipher::from_hex(&"zz".repeat(32)).is_err());
    }
}
