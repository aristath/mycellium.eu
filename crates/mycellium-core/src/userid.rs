//! Stable protocol user identifiers.
//!
//! A handle is only a readable label. The protocol identity is the wallet key.
//! `UserId` is a domain-separated SHA-256 digest of the wallet public key,
//! rendered as lowercase hex so it is easy to store, copy, and route on tiny
//! systems without pulling in formatting-heavy helpers.

use alloc::string::String;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::identity::WalletPublicKey;

/// Stable account/user id derived from the wallet public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UserId(String);

impl TryFrom<String> for UserId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        UserId::new(value)
    }
}

impl From<UserId> for String {
    fn from(id: UserId) -> Self {
        id.0
    }
}

impl UserId {
    /// Hex length of a user id.
    pub const LEN: usize = 64;

    /// Validate and wrap a user id.
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if value.len() != Self::LEN || !value.bytes().all(is_lower_hex) {
            return Err(Error::Malformed);
        }
        Ok(Self(value))
    }

    /// Derive the stable user id from a wallet public key.
    pub fn from_wallet(wallet: &WalletPublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"mycellium-user-id-v1:");
        hasher.update(wallet.0);
        Self(hex(&hasher.finalize()))
    }

    /// Borrow the id as lowercase hex.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Derive the stable user id for `wallet`.
pub fn user_id(wallet: &WalletPublicKey) -> UserId {
    UserId::from_wallet(wallet)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::platform::Platform;

    struct Seeded(u8);

    impl Platform for Seeded {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for b in buf {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }

        fn now_unix_secs(&self) -> u64 {
            0
        }
    }

    #[test]
    fn user_id_is_wallet_derived_not_handle_derived() {
        let identity = Identity::generate(&mut Seeded(1)).unwrap();
        let adopted = Identity::adopt(&mut Seeded(200), identity.wallet_secret()).unwrap();
        let other = Identity::generate(&mut Seeded(80)).unwrap();

        assert_eq!(
            user_id(&identity.wallet_public()),
            user_id(&adopted.wallet_public())
        );
        assert_ne!(
            user_id(&identity.wallet_public()),
            user_id(&other.wallet_public())
        );
    }

    #[test]
    fn user_id_is_lowercase_hex() {
        let identity = Identity::generate(&mut Seeded(3)).unwrap();
        let id = user_id(&identity.wallet_public());
        assert_eq!(id.as_str().len(), UserId::LEN);
        assert!(id.as_str().bytes().all(is_lower_hex));
        assert!(UserId::new(id.as_str().to_ascii_uppercase()).is_err());
    }
}
