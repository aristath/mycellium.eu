//! Self-certifying identity, device, and reachability records.
//!
//! A discovery bundle answers *"given a handle, who, which devices, and where?"*
//! without giving discovery authority: the wallet signs identity and stable
//! device claims, while each device signs its own independently versioned
//! address. A carrier can withhold or replay claims, but cannot forge them.

use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Deref;

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

/// Stable wallet-authorized device keys. Address changes do not alter this
/// record or require the wallet key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// This device's Ed25519 key, its stable identifier within the cluster.
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

/// Short-lived address claim controlled by the device itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachabilityRecord {
    /// Device whose address this record advertises.
    pub device_key: DevicePublicKey,
    /// Where to open the direct line to this device.
    pub peer_id: PeerId,
    /// Monotonic address-record version, independent of identity/device keys.
    pub seq: u64,
}

/// A reachability claim signed by the device key it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReachabilityRecord {
    /// Address claim and its independent sequence.
    pub record: ReachabilityRecord,
    /// Signature by `record.device_key`.
    pub signature: Signature,
}

/// One resolved device bundle carried by discovery: stable wallet-authorized
/// keys plus independently device-signed reachability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Wallet-authorized stable device record.
    pub signed: SignedDeviceRecord,
    /// Independently device-authorized address record.
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
    pub fn create(owner: &Identity, peer_id: PeerId, seq: u64) -> Self {
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
            peer_id,
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

    /// Current self-authenticating direct address.
    pub fn peer_id(&self) -> &PeerId {
        &self.reachability.record.peer_id
    }

    /// Replace only this device's address claim. The wallet-authorized stable
    /// record is preserved byte-for-byte; only the device key is required.
    pub fn refresh_reachability(
        &self,
        owner: &Identity,
        peer_id: PeerId,
        seq: u64,
    ) -> Result<Self, Error> {
        if owner.device_public() != self.device_key || seq <= self.reachability.record.seq {
            return Err(Error::Malformed);
        }
        let record = ReachabilityRecord {
            device_key: self.device_key,
            peer_id,
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

    /// Freshest stable-device or reachability version.
    pub fn freshness(&self) -> u64 {
        self.signed.record.seq.max(self.reachability.record.seq)
    }
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
        #[derive(Serialize)]
        struct IdentityClaim<'a> {
            handle: &'a Handle,
            name: &'a str,
            wallet: WalletPublicKey,
            devices: Vec<DevicePublicKey>,
            seq: u64,
        }
        let canon = crate::wire::canonical(&IdentityClaim {
            handle: &self.handle,
            name: &self.name,
            wallet: self.wallet,
            devices: self.devices.iter().map(|d| d.device_key).collect(),
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
/// device-authorized reachability into independent signed/versioned claims.
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
        if r.devices.is_empty() || r.devices.len() > MAX_DEVICES {
            return Err(Error::Malformed);
        }
        if r.name.len() > MAX_NAME_LEN {
            return Err(Error::Malformed);
        }
        let mut seen = Vec::with_capacity(r.devices.len());
        for device in &r.devices {
            if device.peer_id().0.len() > MAX_PEER_ID_LEN
                || device.reachability.record.device_key != device.device_key
                || seen.contains(&device.device_key)
            {
                return Err(Error::Malformed);
            }
            seen.push(device.device_key);
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
        }
        Ok(())
    }

    /// Lexicographic identity/device/reachability freshness. Identity authority
    /// is compared first so a revoked device cannot make an older membership
    /// claim win merely by publishing a very large address sequence.
    pub fn freshness(&self) -> (u64, u64, u64) {
        let stable = self
            .record
            .devices
            .iter()
            .map(|device| device.signed.record.seq)
            .max()
            .unwrap_or(0);
        let reachability = self
            .record
            .devices
            .iter()
            .map(|device| device.reachability.record.seq)
            .max()
            .unwrap_or(0);
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
            handle: Handle::new("ari").unwrap(),
            name: "Ari".to_string(),
            wallet: id.wallet_public(),
            devices: alloc::vec![Device::create(id, PeerId(b"127.0.0.1:9001".to_vec()), seq,)],
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
        tampered_device.record.devices[0].signed.record.seq += 1;
        assert!(tampered_device.verify().is_err());

        let mut tampered_address = signed;
        tampered_address.record.devices[0].reachability.record.seq += 1;
        assert!(tampered_address.verify().is_err());
    }

    #[test]
    fn device_can_refresh_reachability_without_resigning_identity_or_stable_keys() {
        let mut platform = TestPlatform;
        let identity = Identity::generate(&mut platform).unwrap();
        let original = SignedRecord::sign(record_for(&identity, 7), &identity);
        let stable = original.record.devices[0].signed.clone();
        let mut refreshed = original.clone();
        refreshed.record.devices[0] = original.record.devices[0]
            .refresh_reachability(&identity, PeerId(b"127.0.0.1:9999".to_vec()), 8)
            .unwrap();

        assert_eq!(refreshed.signature, original.signature);
        assert_eq!(refreshed.record.devices[0].signed, stable);
        assert_eq!(refreshed.record.devices[0].peer_id().0, b"127.0.0.1:9999");
        assert!(refreshed.verify().is_ok());
    }

    #[test]
    fn identity_freshness_outranks_an_old_devices_large_address_sequence() {
        let mut platform = TestPlatform;
        let identity = Identity::generate(&mut platform).unwrap();
        let older = SignedRecord::sign(
            Record {
                devices: alloc::vec![Device::create(&identity, PeerId(b"old".to_vec()), 10_000,)],
                ..record_for(&identity, 7)
            },
            &identity,
        );
        let newer = SignedRecord::sign(
            Record {
                devices: alloc::vec![Device::create(&identity, PeerId(b"new".to_vec()), 8,)],
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
