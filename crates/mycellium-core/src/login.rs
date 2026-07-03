//! The login-challenge contract (Layer 8.4, SIWE-style).
//!
//! The exact bytes a client signs with its wallet key to prove control at
//! login. It lives in the core so the directory **server** and any directory
//! **client** share one definition and can never disagree on the format.

use alloc::vec::Vec;

/// The message a client signs to answer a login `nonce`.
pub fn challenge_message(nonce: &str) -> Vec<u8> {
    let mut msg = b"mycellium-login:".to_vec();
    msg.extend_from_slice(nonce.as_bytes());
    msg
}
