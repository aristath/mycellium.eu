//! Self-certifying identity and device records.
//!
//! A discovery bundle answers *"given a handle, who and which active device?"*
//! without storing a route. The wallet signs identity and stable device claims,
//! while each device signs its stable libp2p PeerId. Temporary network routes
//! are exchanged only during a live registry introduction.

use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Deref;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::identity::{
    DevicePublicKey, Handle, Identity, MessagingPublicKey, PeerId, Signature, WalletPublicKey,
};
use crate::userid::{user_id, UserId};

/// Max display-name length (bytes) allowed in a record.
pub const MAX_NAME_LEN: usize = 128;
/// Max encoded libp2p peer-id length (bytes) per device.
pub const MAX_PEER_ID_LEN: usize = 256;
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

/// Stable wallet-authorized device keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// This device's Ed25519 key, its stable identifier.
    pub device_key: DevicePublicKey,
    /// Long-term messaging key for X3DH.
    pub id_key: MessagingPublicKey,
    /// Medium-term signed pre-key.
    pub signed_pre_key: SignedPreKey,
    /// Monotonic version of this device's stable key material.
    pub seq: u64,
}

/// A stable device record authorized by the account wallet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDeviceRecord {
    /// Stable device-key material.
    pub record: DeviceRecord,
    /// Wallet authorization over the domain-separated device record.
    pub signature: Signature,
}

/// Device-signed stable transport identity.
///
/// The historical wire name is retained for record compatibility. This record
/// never contains an IP address or multiaddr.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityRecord {
    /// Device whose transport identity this record certifies.
    pub device_key: DevicePublicKey,
    /// Stable libp2p PeerId derived from `device_key`.
    pub peer_id: PeerId,
    /// Monotonic claim version, independent of identity/device keys.
    pub seq: u64,
}

/// A transport-identity claim signed by the device key it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReachabilityRecord {
    /// Transport identity claim and its independent sequence.
    pub record: ReachabilityRecord,
    /// Signature by `record.device_key`.
    pub signature: Signature,
}

/// One resolved device bundle carried by discovery: stable wallet-authorized
/// keys plus an independently device-signed transport identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Wallet-authorized stable device record.
    pub signed: SignedDeviceRecord,
    /// Independently device-authorized transport identity.
    pub reachability: SignedReachabilityRecord,
}

impl Deref for Device {
    type Target = DeviceRecord;

    fn deref(&self) -> &Self::Target {
        &self.signed.record
    }
}

impl Device {
    /// Create both independently signed records for this local device.
    pub fn create(owner: &Identity, seq: u64) -> Self {
        let record = DeviceRecord {
            device_key: owner.device_public(),
            id_key: owner.messaging_public(),
            signed_pre_key: SignedPreKey::create(owner.signed_pre_key_public(), owner),
            seq,
        };
        let signed = SignedDeviceRecord {
            signature: owner.sign(&device_signing_bytes(&owner.wallet_public(), &record)),
            record,
        };
        let reachability_record = ReachabilityRecord {
            device_key: owner.device_public(),
            peer_id: owner.peer_id(),
            seq,
        };
        let reachability = SignedReachabilityRecord {
            signature: owner.sign_device(&reachability_signing_bytes(&reachability_record)),
            record: reachability_record,
        };
        Self {
            signed,
            reachability,
        }
    }

    /// Stable self-authenticating libp2p peer identity.
    pub fn peer_id(&self) -> &PeerId {
        &self.reachability.record.peer_id
    }

    /// Replace a legacy route-bearing claim with this device's stable PeerId.
    /// The wallet-authorized record is preserved byte-for-byte.
    pub fn refresh_peer_id(&self, owner: &Identity, seq: u64) -> Result<Self, Error> {
        if owner.device_public() != self.device_key || seq <= self.reachability.record.seq {
            return Err(Error::Malformed);
        }
        let record = ReachabilityRecord {
            device_key: self.device_key,
            peer_id: owner.peer_id(),
            seq,
        };
        Ok(Self {
            signed: self.signed.clone(),
            reachability: SignedReachabilityRecord {
                signature: owner.sign_device(&reachability_signing_bytes(&record)),
                record,
            },
        })
    }

    /// Freshest stable-device or transport-identity version.
    pub fn freshness(&self) -> u64 {
        self.signed.record.seq.max(self.reachability.record.seq)
    }
}

/// The unsigned body of a peer record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Stable protocol id derived from `wallet`.
    pub user_id: UserId,
    /// Non-unique human-readable handle.
    pub handle: Handle,
    /// Free-form display name. Non-unique.
    pub name: String,
    /// Root identity: the wallet that signs this record.
    pub wallet: WalletPublicKey,
    /// The only active device that can receive direct messages for this account.
    pub device: Device,
    /// Monotonic sequence number for freshness and anti-rollback.
    pub seq: u64,
}

impl Record {
    /// The account's active device.
    pub fn primary(&self) -> &Device {
        &self.device
    }

    /// Return the active device if its key matches.
    pub fn device(&self, key: &DevicePublicKey) -> Option<&Device> {
        (&self.device.device_key == key).then_some(&self.device)
    }

    /// The canonical byte encoding that is signed and verified.
    pub fn signing_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct IdentityClaim<'a> {
            user_id: &'a UserId,
            handle: &'a Handle,
            name: &'a str,
            wallet: WalletPublicKey,
            device: DevicePublicKey,
            seq: u64,
        }
        let canon = crate::wire::canonical(&IdentityClaim {
            user_id: &self.user_id,
            handle: &self.handle,
            name: &self.name,
            wallet: self.wallet,
            device: self.device.device_key,
            seq: self.seq,
        });
        let mut out = Vec::with_capacity(RECORD_DOMAIN.len() + canon.len());
        out.extend_from_slice(RECORD_DOMAIN);
        out.extend_from_slice(&canon);
        out
    }
}

/// Domain + schema-version tag prefixed to a record's signed bytes.
///
/// v4 separates wallet identity authority, wallet-authorized device keys, and
/// the device-authorized transport identity into signed/versioned claims.
const RECORD_DOMAIN: &[u8] = b"mycellium-identity-record-v4\0";
const DEVICE_DOMAIN: &[u8] = b"mycellium-device-record-v1\0";
const REACHABILITY_DOMAIN: &[u8] = b"mycellium-reachability-record-v1\0";
/// Domain + schema-version tag prefixed to a signed pre-key's signed bytes.
const PREKEY_DOMAIN: &[u8] = b"mycellium-prekey-v1\0";

fn prekey_signing_bytes(public: &MessagingPublicKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(PREKEY_DOMAIN.len() + public.0.len());
    out.extend_from_slice(PREKEY_DOMAIN);
    out.extend_from_slice(&public.0);
    out
}

fn device_signing_bytes(wallet: &WalletPublicKey, record: &DeviceRecord) -> Vec<u8> {
    let canon = crate::wire::canonical(&(*wallet, record));
    let mut out = Vec::with_capacity(DEVICE_DOMAIN.len() + canon.len());
    out.extend_from_slice(DEVICE_DOMAIN);
    out.extend_from_slice(&canon);
    out
}

fn reachability_signing_bytes(record: &ReachabilityRecord) -> Vec<u8> {
    let canon = crate::wire::canonical(record);
    let mut out = Vec::with_capacity(REACHABILITY_DOMAIN.len() + canon.len());
    out.extend_from_slice(REACHABILITY_DOMAIN);
    out.extend_from_slice(&canon);
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
        if r.user_id != user_id(wallet) {
            return Err(Error::Malformed);
        }
        if r.name.len() > MAX_NAME_LEN {
            return Err(Error::Malformed);
        }
        let device = &r.device;
        if device.peer_id().0.len() > MAX_PEER_ID_LEN
            || device.reachability.record.device_key != device.device_key
            || device.peer_id() != &device.device_key.peer_id()
        {
            return Err(Error::Malformed);
        }
        wallet.verify(
            &device_signing_bytes(wallet, &device.signed.record),
            &device.signed.signature,
        )?;
        wallet.verify(
            &prekey_signing_bytes(&device.signed_pre_key.public),
            &device.signed_pre_key.signature,
        )?;
        device.device_key.verify(
            &reachability_signing_bytes(&device.reachability.record),
            &device.reachability.signature,
        )?;
        Ok(())
    }

    /// Lexicographic identity/device/transport freshness. Identity authority
    /// is compared first so a revoked device cannot make an older membership
    /// claim win merely by publishing a very large address sequence.
    pub fn freshness(&self) -> (u64, u64, u64) {
        let stable = self.record.device.signed.record.seq;
        let reachability = self.record.device.reachability.record.seq;
        (self.record.seq, stable, reachability)
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
            user_id: user_id(&id.wallet_public()),
            handle: Handle::new("ari").unwrap(),
            name: "Ari".to_string(),
            wallet: id.wallet_public(),
            device: Device::create(id, seq),
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

        let mut tampered_device = signed.clone();
        tampered_device.record.device.signed.record.seq += 1;
        assert!(tampered_device.verify().is_err());

        let mut tampered_address = signed;
        tampered_address.record.device.reachability.record.seq += 1;
        assert!(tampered_address.verify().is_err());
    }

    #[test]
    fn device_can_migrate_legacy_peer_id_without_resigning_stable_keys() {
        let mut platform = TestPlatform;
        let identity = Identity::generate(&mut platform).unwrap();
        let original = SignedRecord::sign(record_for(&identity, 7), &identity);
        let stable = original.record.device.signed.clone();
        let mut legacy = original.clone();
        legacy.record.device.reachability.record.peer_id = PeerId(b"legacy-ip".to_vec());
        legacy.record.device.reachability.signature = identity.sign_device(
            &reachability_signing_bytes(&legacy.record.device.reachability.record),
        );
        let mut refreshed = legacy.clone();
        refreshed.record.device = legacy.record.device.refresh_peer_id(&identity, 8).unwrap();

        assert_eq!(refreshed.signature, legacy.signature);
        assert_eq!(refreshed.record.device.signed, stable);
        assert_eq!(refreshed.record.device.peer_id(), &identity.peer_id());
        assert!(refreshed.verify().is_ok());
    }

    #[test]
    fn identity_freshness_outranks_an_old_device_large_address_sequence() {
        let mut platform = TestPlatform;
        let identity = Identity::generate(&mut platform).unwrap();
        let older = SignedRecord::sign(
            Record {
                device: Device::create(&identity, 10_000),
                ..record_for(&identity, 7)
            },
            &identity,
        );
        let newer = SignedRecord::sign(
            Record {
                device: Device::create(&identity, 8),
                ..record_for(&identity, 8)
            },
            &identity,
        );

        assert!(newer.freshness() > older.freshness());
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
    fn malformed_active_device_is_rejected() {
        let mut p = TestPlatform;
        let id = Identity::generate(&mut p).unwrap();

        let mut oversized_peer_id = record_for(&id, 1);
        oversized_peer_id.device.reachability.record.peer_id =
            PeerId(vec![b'x'; MAX_PEER_ID_LEN + 1]);
        assert_eq!(
            SignedRecord::sign(oversized_peer_id, &id).verify(),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn device_cannot_sign_a_peer_id_belonging_to_another_key() {
        let mut p = TestPlatform;
        let id = Identity::generate(&mut p).unwrap();
        let mut record = record_for(&id, 1);

        let mut other_peer_id = id.peer_id();
        *other_peer_id.0.last_mut().unwrap() ^= 1;
        record.device.reachability.record.peer_id = other_peer_id;
        record.device.reachability.signature = id.sign_device(&reachability_signing_bytes(
            &record.device.reachability.record,
        ));

        // Every signature is valid. The record must still fail because the
        // claimed transport identity is not derived from the active device.
        assert_eq!(
            SignedRecord::sign(record, &id).verify(),
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
