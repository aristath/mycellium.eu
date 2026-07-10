//! Recipient-authenticated acceptance acknowledgements.
//!
//! A transport write is not delivery. A sender may mark one device copy as
//! delivered only after the intended recipient device signs an acknowledgement
//! bound to both the stable delivery id and the exact transmitted payload.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::identity::{DevicePublicKey, Identity, Signature};

const ACK_DOMAIN: &[u8] = b"mycellium-delivery-ack-v1\0";

/// Maximum textual delivery-id length accepted from the wire.
pub const MAX_DELIVERY_ID_LEN: usize = 64;

/// SHA-256 of the exact encoded payload carried by a delivery frame.
pub type PayloadDigest = [u8; 32];

/// Hash an encoded delivery payload for acknowledgement binding.
pub fn payload_digest(payload: &[u8]) -> PayloadDigest {
    Sha256::digest(payload).into()
}

#[derive(Serialize)]
struct AckBody<'a> {
    delivery_id: &'a str,
    payload_digest: PayloadDigest,
    recipient_device: DevicePublicKey,
}

fn signing_bytes(
    delivery_id: &str,
    digest: PayloadDigest,
    recipient_device: DevicePublicKey,
) -> Vec<u8> {
    let body = crate::wire::canonical(&AckBody {
        delivery_id,
        payload_digest: digest,
        recipient_device,
    });
    let mut bytes = Vec::with_capacity(ACK_DOMAIN.len() + body.len());
    bytes.extend_from_slice(ACK_DOMAIN);
    bytes.extend_from_slice(&body);
    bytes
}

/// Proof that one recipient device durably accepted one exact delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryAck {
    /// Stable sender-generated id of the per-device delivery.
    pub delivery_id: String,
    /// Hash of the encoded application payload. The core intentionally does not
    /// know the engine's payload type; it binds the bytes supplied by the caller.
    pub payload_digest: PayloadDigest,
    /// Device that accepted the payload and produced the signature.
    pub recipient_device: DevicePublicKey,
    /// Domain-separated Ed25519 signature by `recipient_device`.
    pub signature: Signature,
}

impl DeliveryAck {
    /// Sign an acceptance acknowledgement with this device's key.
    pub fn accepted(identity: &Identity, delivery_id: String, payload: &[u8]) -> Self {
        let payload_digest = payload_digest(payload);
        let recipient_device = identity.device_public();
        let signature = identity.sign_device(&signing_bytes(
            &delivery_id,
            payload_digest,
            recipient_device,
        ));
        Self {
            delivery_id,
            payload_digest,
            recipient_device,
            signature,
        }
    }

    /// Verify that this ACK belongs to the expected delivery, payload and device.
    pub fn verify(
        &self,
        expected_delivery_id: &str,
        expected_payload: &[u8],
        expected_device: &DevicePublicKey,
    ) -> Result<(), Error> {
        if self.delivery_id.is_empty()
            || self.delivery_id.len() > MAX_DELIVERY_ID_LEN
            || self.delivery_id != expected_delivery_id
            || &self.recipient_device != expected_device
            || self.payload_digest != payload_digest(expected_payload)
        {
            return Err(Error::Malformed);
        }
        self.recipient_device.verify(
            &signing_bytes(
                &self.delivery_id,
                self.payload_digest,
                self.recipient_device,
            ),
            &self.signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Platform;

    struct TestPlatform(u8);

    impl Platform for TestPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for byte in buf {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }

        fn now_unix_secs(&self) -> u64 {
            1
        }
    }

    #[test]
    fn ack_is_bound_to_delivery_payload_and_recipient_device() {
        let alice = Identity::generate(&mut TestPlatform(1)).unwrap();
        let bob = Identity::generate(&mut TestPlatform(80)).unwrap();
        let ack = DeliveryAck::accepted(&bob, "delivery-1".into(), b"ciphertext");

        assert!(ack
            .verify("delivery-1", b"ciphertext", &bob.device_public())
            .is_ok());
        assert!(ack
            .verify("delivery-2", b"ciphertext", &bob.device_public())
            .is_err());
        assert!(ack
            .verify("delivery-1", b"tampered", &bob.device_public())
            .is_err());
        assert!(ack
            .verify("delivery-1", b"ciphertext", &alice.device_public())
            .is_err());
    }
}
