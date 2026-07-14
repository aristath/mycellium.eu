//! Self-contained encryption for one direct-delivery envelope.
//!
//! Every envelope runs a fresh X3DH handshake, so its shared secret is used for
//! exactly one AEAD ciphertext. This gives each message an ephemeral-derived
//! key without pretending that independent envelopes form a persistent Double
//! Ratchet session. Replay rejection belongs to the durable delivery-id layer.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::cipher::{aead_decrypt, aead_encrypt};
use crate::error::Error;
use crate::x3dh::SharedSecret;

/// The versioned encryption suite carried by a direct envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OneShotMessage {
    /// Fresh-X3DH key with ChaCha20-Poly1305 authenticated encryption.
    X3dhChaCha20Poly1305V1 {
        /// Ciphertext including the Poly1305 authentication tag.
        ciphertext: Vec<u8>,
    },
}

/// Encrypt one payload under a fresh X3DH shared secret.
pub fn seal(shared: &SharedSecret, plaintext: &[u8], associated_data: &[u8]) -> OneShotMessage {
    OneShotMessage::X3dhChaCha20Poly1305V1 {
        ciphertext: aead_encrypt(shared.as_bytes(), plaintext, associated_data),
    }
}

/// Authenticate and decrypt one payload under the matching X3DH secret.
pub fn open(
    shared: &SharedSecret,
    message: &OneShotMessage,
    associated_data: &[u8],
) -> Result<Vec<u8>, Error> {
    match message {
        OneShotMessage::X3dhChaCha20Poly1305V1 { ciphertext } => {
            aead_decrypt(shared.as_bytes(), ciphertext, associated_data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::platform::Platform;
    use crate::x3dh;

    struct Seeded(u8);

    impl Platform for Seeded {
        fn fill_random(&mut self, bytes: &mut [u8]) {
            for byte in bytes {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }

        fn now_unix_secs(&self) -> u64 {
            0
        }
    }

    #[test]
    fn matching_x3dh_secrets_open_the_message() {
        let mut platform = Seeded(1);
        let alice = Identity::generate(&mut platform).unwrap();
        let bob = Identity::generate(&mut platform).unwrap();
        let initiated = x3dh::initiate(
            &mut platform,
            &alice,
            &bob.messaging_public(),
            &bob.signed_pre_key_public(),
        )
        .unwrap();
        let responder = x3dh::respond(&bob, &initiated.init).unwrap();
        let message = seal(&initiated.shared_secret, b"hello", b"alice|bob");

        assert_eq!(open(&responder, &message, b"alice|bob").unwrap(), b"hello");
        assert!(open(&responder, &message, b"mallory|bob").is_err());
    }

    #[test]
    fn tampering_is_rejected() {
        let mut platform = Seeded(9);
        let alice = Identity::generate(&mut platform).unwrap();
        let bob = Identity::generate(&mut platform).unwrap();
        let initiated = x3dh::initiate(
            &mut platform,
            &alice,
            &bob.messaging_public(),
            &bob.signed_pre_key_public(),
        )
        .unwrap();
        let responder = x3dh::respond(&bob, &initiated.init).unwrap();
        let mut message = seal(&initiated.shared_secret, b"hello", b"ad");
        let OneShotMessage::X3dhChaCha20Poly1305V1 { ciphertext } = &mut message;
        ciphertext[0] ^= 1;

        assert!(open(&responder, &message, b"ad").is_err());
    }
}
