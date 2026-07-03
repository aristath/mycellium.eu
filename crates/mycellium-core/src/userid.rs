//! Username → public identifier (Layer 6 privacy).
//!
//! The directory keys on `user_id(username)`, **never the plaintext username**.
//! The id is a 128-bit hash rendered as 32 hex chars — a valid [`Handle`] — so a
//! client that knows the name can compute it and look someone up, but a leaked
//! or curious directory only ever holds opaque ids. It cannot be dumped into a
//! phonebook of every user; at most someone can *test* a name they already guess
//! (unavoidable, since lookup itself must be answerable).
//!
//! The plaintext username lives only on users' devices — shown in the UI, and
//! carried inside messages as a self-verifying display name (its hash must equal
//! the `user_id` in the sender's wallet-signed record).

use alloc::string::String;

use sha2::{Digest, Sha256};

use crate::identity::Handle;

/// The public directory identifier for a username (hash, not the name).
pub fn user_id(username: &str) -> Handle {
    let mut hasher = Sha256::new();
    hasher.update(b"mycellium-user:");
    hasher.update(username.trim().to_lowercase().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    for b in &digest[..16] {
        hex.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        hex.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    Handle::new(hex).expect("32 hex chars is always a valid handle")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_case_insensitive() {
        assert_eq!(user_id("mary"), user_id("mary"));
        assert_eq!(user_id("Mary"), user_id("mary")); // normalized
        assert_eq!(user_id("  mary "), user_id("mary")); // trimmed
        assert_ne!(user_id("mary"), user_id("john"));
    }

    #[test]
    fn is_a_valid_32_char_handle() {
        let id = user_id("someone");
        assert_eq!(id.as_str().len(), 32);
        assert!(Handle::new(id.as_str()).is_ok());
    }
}
