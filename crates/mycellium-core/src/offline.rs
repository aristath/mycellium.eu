//! Deferred delivery payloads for direct handoff and local retry.
//!
//! When the recipient isn't online for a live handshake, the sender uses the
//! keys the recipient *already published* (identity + signed pre-key) to run
//! X3DH **asynchronously**, encrypts the message with a fresh ratchet, and packs
//! everything a recipient needs into one [`Envelope`]. The sender can retry this
//! opaque envelope later without learning anything new or involving custody.
//!
//! Each offline message is a self-contained one-shot session — simple, and
//! enough for the POC. Long-lived asynchronous ratchets are future work.

use serde::{Deserialize, Serialize};

use crate::identity::Handle;
use crate::ratchet::RatchetMessage;
use crate::record::SignedRecord;
use crate::x3dh::HandshakeInit;

/// Everything the recipient needs to authenticate the sender and decrypt one
/// deferred message. Opaque to local retry storage and direct transports.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    /// The sender's handle (authenticated by `sender_record`).
    pub from: Handle,
    /// The sender's self-signed record, so the recipient can verify identity.
    pub sender_record: SignedRecord,
    /// The X3DH init that lets the recipient derive the shared secret.
    pub init: HandshakeInit,
    /// The single ratchet-encrypted message.
    pub message: RatchetMessage,
    /// Sender's clock, for display/ordering only (not a security boundary).
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::platform::Platform;
    use crate::ratchet::Ratchet;
    use crate::record::{Device, Record};
    use crate::x3dh;

    struct SeededPlatform(u8);
    impl Platform for SeededPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
        fn now_unix_secs(&self) -> u64 {
            0
        }
    }

    fn record_for(id: &Identity, handle: &str) -> SignedRecord {
        let record = Record {
            handle: Handle::new(handle).unwrap(),
            name: String::new(),
            wallet: id.wallet_public(),
            devices: alloc::vec![Device::create(
                id,
                crate::identity::PeerId(alloc::vec![]),
                1,
            )],
            seq: 1,
        };
        SignedRecord::sign(record, id)
    }

    fn ad(initiator: &Identity, responder: &Identity) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::new();
        v.extend_from_slice(&initiator.messaging_public().0);
        v.extend_from_slice(&responder.messaging_public().0);
        v
    }

    #[test]
    fn offline_message_round_trip() {
        let mut p = SeededPlatform(0);
        let alice = Identity::generate(&mut p).unwrap();
        let bob = Identity::generate(&mut p).unwrap();

        // Bob's published record is all Alice has (Bob is offline).
        let bob_record = record_for(&bob, "bob");

        // Alice seals a message asynchronously.
        let initiated = x3dh::initiate(
            &mut p,
            &alice,
            &bob_record.record.primary().id_key,
            &bob_record.record.primary().signed_pre_key.public,
        )
        .unwrap();
        let mut ratchet = Ratchet::new_initiator(
            &mut p,
            &initiated.shared_secret,
            &bob_record.record.primary().signed_pre_key.public,
        )
        .unwrap();
        let ad_bytes = ad(&alice, &bob);
        let message = ratchet.encrypt(b"see you tomorrow", &ad_bytes);

        let envelope = Envelope {
            from: Handle::new("alice").unwrap(),
            sender_record: record_for(&alice, "alice"),
            init: initiated.init,
            message,
            timestamp: 0,
        };

        // ... time passes, Bob comes online and opens the envelope.
        assert!(envelope.sender_record.verify().is_ok());
        assert_eq!(
            envelope.init.initiator_ik,
            envelope.sender_record.record.primary().id_key
        );

        let shared = x3dh::respond(&bob, &envelope.init).unwrap();
        let mut bob_ratchet = Ratchet::new_responder(&shared, &bob);
        let recovered = bob_ratchet
            .decrypt(&mut p, &envelope.message, &ad(&alice, &bob))
            .unwrap();
        assert_eq!(recovered, b"see you tomorrow");
    }
}
