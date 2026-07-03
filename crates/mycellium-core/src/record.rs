//! The self-certifying directory record (Layer 8.2, Layer 6).
//!
//! A record answers *"given a handle, who and where is this person?"* It is
//! **signed by the owner's wallet key**, so whoever hosts the directory holds
//! data they cannot forge — the worst a dishonest directory can do is withhold
//! or serve a stale record, never impersonate anyone.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::identity::{
    DevicePublicKey, Handle, Identity, MessagingPublicKey, PeerId, Signature, WalletPublicKey,
};

/// A medium-term messaging key, signed by the wallet, that lets a peer start a
/// session. Present now so the same record format also serves the deferred
/// offline/async case without a change (Layer 8.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPreKey {
    /// The pre-key itself.
    pub public: MessagingPublicKey,
    /// Wallet signature over `public`.
    pub signature: Signature,
}

impl SignedPreKey {
    /// Certify a pre-key with the owner's wallet signature.
    pub fn create(public: MessagingPublicKey, owner: &Identity) -> Self {
        let signature = owner.sign(&public.0);
        SignedPreKey { public, signature }
    }
}

/// One device in an account's cluster (Layer 11).
///
/// Each device carries its **own** transport and messaging keys; the account's
/// single wallet signature over the whole record is what vouches that every
/// listed device belongs to the account. A new device adds itself to the set
/// (the seed is the authority) rather than sharing seed-derived keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// This device's Ed25519 key — its stable identifier within the cluster.
    pub device_key: DevicePublicKey,
    /// Where to open the direct line to this device.
    pub peer_id: PeerId,
    /// Long-term messaging key for X3DH.
    pub id_key: MessagingPublicKey,
    /// Medium-term signed pre-key.
    pub signed_pre_key: SignedPreKey,
}

/// The unsigned body of a directory record.
///
/// Everything a peer needs to find you and open a session: your root identity
/// and the set of devices (Layer 11) you can be reached and messaged on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The public name this record is claimed under.
    pub handle: Handle,
    /// Root identity — the wallet that signs this record.
    pub wallet: WalletPublicKey,
    /// The account's devices. One entry today; a cluster once linking lands.
    pub devices: Vec<Device>,
    /// Monotonic sequence number — freshness and anti-rollback (Layer 9.4).
    pub seq: u64,
}

impl Record {
    /// The account's first (primary) device. Records always carry at least one
    /// device — [`SignedRecord::verify`] rejects an empty set.
    pub fn primary(&self) -> &Device {
        &self.devices[0]
    }

    /// Find a device in the cluster by its key.
    pub fn device(&self, key: &DevicePublicKey) -> Option<&Device> {
        self.devices.iter().find(|d| &d.device_key == key)
    }

    /// The canonical byte encoding that is signed and verified.
    ///
    /// Delegates to [`crate::wire::canonical`] so the exact same deterministic
    /// bytes are produced on every device, from a microcontroller to a desktop.
    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::canonical(self)
    }
}

/// A [`Record`] plus the wallet signature over its [`signing_bytes`].
///
/// [`signing_bytes`]: Record::signing_bytes
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecord {
    /// The signed body.
    pub record: Record,
    /// Wallet signature over `record.signing_bytes()`.
    pub signature: Signature,
}

impl SignedRecord {
    /// Sign a record with its owner's wallet key.
    pub fn sign(record: Record, owner: &Identity) -> Self {
        let signature = owner.sign(&record.signing_bytes());
        SignedRecord { record, signature }
    }

    /// Verify the record is intact and self-certifying.
    ///
    /// Checks that the wallet in the record signed both the record body and its
    /// embedded pre-key. This is what makes the directory unable to forge a
    /// record (Layer 6) — the signatures must validate against the wallet the
    /// record claims.
    pub fn verify(&self) -> Result<(), Error> {
        let wallet = &self.record.wallet;
        wallet.verify(&self.record.signing_bytes(), &self.signature)?;
        if self.record.devices.is_empty() {
            return Err(Error::Malformed);
        }
        for device in &self.record.devices {
            wallet.verify(&device.signed_pre_key.public.0, &device.signed_pre_key.signature)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::MessagingPublicKey;
    use crate::platform::Platform;

    /// Deterministic, INSECURE entropy — tests only.
    struct TestPlatform;
    impl Platform for TestPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(7).wrapping_add(1);
            }
        }
        fn now_unix_secs(&self) -> u64 {
            0
        }
    }

    fn sample_record(seq: u64) -> Record {
        Record {
            handle: Handle::new("ari").unwrap(),
            wallet: WalletPublicKey([2u8; 33]),
            devices: alloc::vec![Device {
                device_key: DevicePublicKey([1u8; 32]),
                peer_id: PeerId(alloc::vec![3u8; 34]),
                id_key: MessagingPublicKey([4u8; 32]),
                signed_pre_key: SignedPreKey {
                    public: MessagingPublicKey([5u8; 32]),
                    signature: Signature(alloc::vec![6u8; 64]),
                },
            }],
            seq,
        }
    }

    #[test]
    fn signing_bytes_are_deterministic() {
        let r = sample_record(42);
        assert_eq!(r.signing_bytes(), r.signing_bytes());
    }

    #[test]
    fn signing_bytes_change_with_seq() {
        assert_ne!(sample_record(1).signing_bytes(), sample_record(2).signing_bytes());
    }

    #[test]
    fn handle_rules() {
        assert!(Handle::new("ari").is_ok());
        assert!(Handle::new("a_1").is_ok());
        assert!(Handle::new("").is_err());
        assert!(Handle::new("Ari").is_err()); // uppercase
        assert!(Handle::new("a b").is_err()); // space
    }

    #[test]
    fn recovery_preserves_the_account_wallet() {
        let mut p = TestPlatform;
        let id = Identity::generate(&mut p).unwrap();
        // Recovering from the phrase preserves the account (wallet); the device
        // keys are fresh per device (Layer 11), so only the wallet must match.
        let recovered = Identity::from_phrase(id.mnemonic(), &mut p).unwrap();
        assert_eq!(id.wallet_public(), recovered.wallet_public());
        // Reloading *this* device from its seed reproduces its device keys.
        let same = Identity::restore(id.mnemonic(), id.device_seed()).unwrap();
        assert_eq!(id.device_public(), same.device_public());
    }

    #[test]
    fn record_round_trip() {
        let mut p = TestPlatform;
        let id = Identity::generate(&mut p).unwrap();

        let record = Record {
            handle: Handle::new("ari").unwrap(),
            wallet: id.wallet_public(),
            devices: alloc::vec![Device {
                device_key: id.device_public(),
                peer_id: id.peer_id(),
                id_key: id.messaging_public(),
                signed_pre_key: SignedPreKey::create(id.signed_pre_key_public(), &id),
            }],
            seq: 1,
        };
        let signed = SignedRecord::sign(record, &id);
        assert!(signed.verify().is_ok(), "freshly signed record must verify");

        // Tampering with any signed field breaks verification.
        let mut tampered = signed.clone();
        tampered.record.seq = 2;
        assert!(tampered.verify().is_err(), "tampered seq must fail");
    }

    #[test]
    fn record_with_two_devices_verifies() {
        let mut p = TestPlatform;
        let id = Identity::generate(&mut p).unwrap();

        // A second device entry (distinct keys), still signed by the one wallet.
        let dev2 = Device {
            device_key: DevicePublicKey([9u8; 32]),
            peer_id: PeerId(alloc::vec![8u8; 34]),
            id_key: MessagingPublicKey([7u8; 32]),
            signed_pre_key: SignedPreKey::create(MessagingPublicKey([7u8; 32]), &id),
        };
        let record = Record {
            handle: Handle::new("ari").unwrap(),
            wallet: id.wallet_public(),
            devices: alloc::vec![
                Device {
                    device_key: id.device_public(),
                    peer_id: id.peer_id(),
                    id_key: id.messaging_public(),
                    signed_pre_key: SignedPreKey::create(id.signed_pre_key_public(), &id),
                },
                dev2.clone(),
            ],
            seq: 1,
        };
        let signed = SignedRecord::sign(record, &id);
        assert!(signed.verify().is_ok(), "two-device record must verify");
        assert_eq!(signed.record.devices.len(), 2);
        assert_eq!(signed.record.primary().device_key, id.device_public());
        assert_eq!(signed.record.device(&dev2.device_key), Some(&dev2));
    }

    #[test]
    fn empty_device_set_is_rejected() {
        let mut p = TestPlatform;
        let id = Identity::generate(&mut p).unwrap();
        let record = Record {
            handle: Handle::new("ari").unwrap(),
            wallet: id.wallet_public(),
            devices: alloc::vec![],
            seq: 1,
        };
        assert!(SignedRecord::sign(record, &id).verify().is_err());
    }

    #[test]
    fn signed_record_survives_wire_round_trip() {
        let mut p = TestPlatform;
        let id = Identity::generate(&mut p).unwrap();
        let record = Record {
            handle: Handle::new("ari").unwrap(),
            wallet: id.wallet_public(),
            devices: alloc::vec![Device {
                device_key: id.device_public(),
                peer_id: id.peer_id(),
                id_key: id.messaging_public(),
                signed_pre_key: SignedPreKey::create(id.signed_pre_key_public(), &id),
            }],
            seq: 7,
        };
        let signed = SignedRecord::sign(record, &id);

        let bytes = crate::wire::encode(&signed);
        let decoded: SignedRecord = crate::wire::decode(&bytes).unwrap();

        assert_eq!(decoded, signed);
        assert!(decoded.verify().is_ok(), "record must still verify after the wire round trip");
    }
}
