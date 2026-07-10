//! The self-certifying peer record.
//!
//! A record answers *"given a handle, who and where is this person?"* It is
//! signed by the owner's wallet key, so whoever carries it is only a transport
//! for a claim. They can withhold or serve a stale record, never forge the
//! identity or its device set.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::identity::{
    DevicePublicKey, Handle, Identity, MessagingPublicKey, PeerId, Signature, WalletPublicKey,
};

/// Max display-name length (bytes) allowed in a record.
pub const MAX_NAME_LEN: usize = 128;
/// Max peer-id length (bytes) per device (a `host:port` or a multiaddr).
pub const MAX_PEER_ID_LEN: usize = 256;
/// Max devices in one account's record.
pub const MAX_DEVICES: usize = 32;

/// A medium-term messaging key, signed by the wallet, that lets a peer start a
/// one-shot X3DH session.
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
        let signature = owner.sign(&prekey_signing_bytes(&public));
        SignedPreKey { public, signature }
    }
}

/// One device in an account's cluster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// This device's Ed25519 key, its stable identifier within the cluster.
    pub device_key: DevicePublicKey,
    /// Where to open the direct line to this device.
    pub peer_id: PeerId,
    /// Long-term messaging key for X3DH.
    pub id_key: MessagingPublicKey,
    /// Medium-term signed pre-key.
    pub signed_pre_key: SignedPreKey,
}

/// The unsigned body of a peer record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The account's stable id, typically `user_id(handle)`.
    pub handle: Handle,
    /// Free-form display name. Non-unique.
    pub name: String,
    /// Root identity: the wallet that signs this record.
    pub wallet: WalletPublicKey,
    /// Devices that can receive direct messages for this account.
    pub devices: Vec<Device>,
    /// Monotonic sequence number for freshness and anti-rollback.
    pub seq: u64,
}

impl Record {
    /// The account's first device. Valid records always carry at least one.
    pub fn primary(&self) -> &Device {
        &self.devices[0]
    }

    /// Find a device in the cluster by its key.
    pub fn device(&self, key: &DevicePublicKey) -> Option<&Device> {
        self.devices.iter().find(|d| &d.device_key == key)
    }

    /// The canonical byte encoding that is signed and verified.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let canon = crate::wire::canonical(self);
        let mut out = Vec::with_capacity(RECORD_DOMAIN.len() + canon.len());
        out.extend_from_slice(RECORD_DOMAIN);
        out.extend_from_slice(&canon);
        out
    }
}

/// Domain + schema-version tag prefixed to a record's signed bytes.
///
/// v3 is the hard-serverless record: no queue/mailbox endpoints are part of the
/// authenticated identity claim.
const RECORD_DOMAIN: &[u8] = b"mycellium-record-v3\0";
/// Domain + schema-version tag prefixed to a signed pre-key's signed bytes.
const PREKEY_DOMAIN: &[u8] = b"mycellium-prekey-v1\0";

fn prekey_signing_bytes(public: &MessagingPublicKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREKEY_DOMAIN.len() + public.0.len());
    out.extend_from_slice(PREKEY_DOMAIN);
    out.extend_from_slice(&public.0);
    out
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
    pub fn verify(&self) -> Result<(), Error> {
        let wallet = &self.record.wallet;
        wallet.verify(&self.record.signing_bytes(), &self.signature)?;
        let r = &self.record;
        if r.devices.is_empty() || r.devices.len() > MAX_DEVICES {
            return Err(Error::Malformed);
        }
        if r.name.len() > MAX_NAME_LEN {
            return Err(Error::Malformed);
        }
        for device in &r.devices {
            if device.peer_id.0.len() > MAX_PEER_ID_LEN {
                return Err(Error::Malformed);
            }
            wallet.verify(
                &prekey_signing_bytes(&device.signed_pre_key.public),
                &device.signed_pre_key.signature,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Platform;

    struct TestPlatform;
    impl Platform for TestPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31).wrapping_add(7);
            }
        }

        fn now_unix_secs(&self) -> u64 {
            1
        }
    }

    fn record_for(id: &Identity, seq: u64) -> Record {
        Record {
            handle: Handle::new("ari").unwrap(),
            name: "Ari".to_string(),
            wallet: id.wallet_public(),
            devices: alloc::vec![Device {
                device_key: id.device_public(),
                peer_id: PeerId(b"127.0.0.1:9001".to_vec()),
                id_key: id.messaging_public(),
                signed_pre_key: SignedPreKey::create(id.signed_pre_key_public(), id),
            }],
            seq,
        }
    }

    #[test]
    fn signed_record_verifies_and_is_tamper_evident() {
        let mut p = TestPlatform;
        let id = Identity::generate(&mut p).unwrap();
        let signed = SignedRecord::sign(record_for(&id, 1), &id);
        assert!(signed.verify().is_ok());

        let mut tampered = signed.clone();
        tampered.record.seq = 2;
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn signing_bytes_are_domain_versioned() {
        let mut p = TestPlatform;
        let id = Identity::generate(&mut p).unwrap();
        assert!(record_for(&id, 1)
            .signing_bytes()
            .starts_with(RECORD_DOMAIN));
    }

    #[test]
    fn empty_or_oversized_device_sets_are_rejected() {
        let mut p = TestPlatform;
        let id = Identity::generate(&mut p).unwrap();

        let mut empty = record_for(&id, 1);
        empty.devices.clear();
        assert_eq!(
            SignedRecord::sign(empty, &id).verify(),
            Err(Error::Malformed)
        );

        let mut many = record_for(&id, 1);
        many.devices = alloc::vec![many.devices[0].clone(); MAX_DEVICES + 1];
        assert_eq!(
            SignedRecord::sign(many, &id).verify(),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn signed_record_survives_wire_round_trip() {
        let mut p = TestPlatform;
        let id = Identity::generate(&mut p).unwrap();
        let signed = SignedRecord::sign(record_for(&id, 7), &id);
        let bytes = crate::wire::encode(&signed);
        let decoded: SignedRecord = crate::wire::decode(&bytes).unwrap();
        assert_eq!(decoded, signed);
        assert!(decoded.verify().is_ok());
    }
}
