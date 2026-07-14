//! Atomic anti-rollback version vectors for split peer records.
//!
//! Identity membership, stable device keys, and transport identity advance
//! independently. One wallet-scoped pin stores the high-water mark for every
//! component, so one fresh component can never hide a rolled-back claim.

use serde::{Deserialize, Serialize};

use mycellium_core::identity::{DevicePublicKey, WalletPublicKey};
use mycellium_core::record::SignedRecord;
use mycellium_core::storage::Storage;
use mycellium_core::wire;

fn key(user_id: &str, _wallet: &WalletPublicKey) -> Vec<u8> {
    let mut key = b"record-versions-v2:".to_vec();
    key.extend_from_slice(user_id.as_bytes());
    key
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct VersionPins {
    identity: u64,
    identity_digest: [u8; 32],
    devices: Vec<DevicePins>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DevicePins {
    key: DevicePublicKey,
    stable: u64,
    stable_digest: [u8; 32],
    transport: u64,
    transport_digest: [u8; 32],
}

fn digest<T: Serialize>(value: &T) -> [u8; 32] {
    mycellium_core::delivery::payload_digest(&wire::canonical(value))
}

fn load<S: Storage>(
    store: &S,
    handle: &str,
    wallet: &WalletPublicKey,
) -> Result<Option<VersionPins>, S::Error> {
    let Some(bytes) = store.get(&key(handle, wallet))? else {
        return Ok(Some(VersionPins::default()));
    };
    match wire::decode(&bytes) {
        Ok(pins) => Ok(Some(pins)),
        Err(_) => {
            crate::warn_corrupt("record anti-rollback pins");
            Ok(None)
        }
    }
}

/// Atomically validate and advance every component in a verified record.
pub fn check_and_pin<S: Storage>(
    store: &mut S,
    handle: &str,
    record: &SignedRecord,
) -> Result<bool, S::Error> {
    let wallet = &record.record.wallet;
    // A corrupt high-water mark must never be interpreted as version zero: an
    // attacker who can roll local bytes back would otherwise re-introduce a
    // retired device. Keep the bytes and reject the record until repaired.
    let Some(mut pins) = load(store, handle, wallet)? else {
        return Ok(false);
    };
    let identity_digest = mycellium_core::delivery::payload_digest(&record.record.signing_bytes());
    if record.record.seq < pins.identity
        || (record.record.seq == pins.identity
            && pins.identity != 0
            && identity_digest != pins.identity_digest)
    {
        return Ok(false);
    }
    {
        let device = &record.record.device;
        let stable_digest = digest(&device.signed.record);
        let transport_digest = digest(&device.reachability.record);
        if let Some(known) = pins
            .devices
            .iter()
            .find(|known| known.key == device.device_key)
        {
            if device.signed.record.seq < known.stable
                || (device.signed.record.seq == known.stable
                    && stable_digest != known.stable_digest)
                || device.reachability.record.seq < known.transport
                || (device.reachability.record.seq == known.transport
                    && transport_digest != known.transport_digest)
            {
                return Ok(false);
            }
        }
    }

    if record.record.seq > pins.identity || pins.identity == 0 {
        pins.identity = record.record.seq;
        pins.identity_digest = identity_digest;
    }
    {
        let device = &record.record.device;
        let stable_digest = digest(&device.signed.record);
        let transport_digest = digest(&device.reachability.record);
        match pins
            .devices
            .iter_mut()
            .find(|known| known.key == device.device_key)
        {
            Some(known) => {
                if device.signed.record.seq > known.stable {
                    known.stable = device.signed.record.seq;
                    known.stable_digest = stable_digest;
                }
                if device.reachability.record.seq > known.transport {
                    known.transport = device.reachability.record.seq;
                    known.transport_digest = transport_digest;
                }
            }
            None => pins.devices.push(DevicePins {
                key: device.device_key,
                stable: device.signed.record.seq,
                stable_digest,
                transport: device.reachability.record.seq,
                transport_digest,
            }),
        }
    }
    store.put(&key(handle, wallet), &wire::encode(&pins))?;
    Ok(true)
}

/// Clear every component high-water mark for one explicit handle/wallet reset.
pub fn clear<S: Storage>(
    store: &mut S,
    handle: &str,
    wallet: &WalletPublicKey,
) -> Result<(), S::Error> {
    store.delete(&key(handle, wallet))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycellium_core::identity::{Handle, Identity};
    use mycellium_core::platform::Platform;
    use mycellium_core::record::{Device, Record, SignedRecord};
    use mycellium_core::userid::user_id;
    use std::collections::HashMap;
    use std::convert::Infallible;

    #[derive(Default)]
    struct Mem(HashMap<Vec<u8>, Vec<u8>>);
    impl Storage for Mem {
        type Error = Infallible;
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.0.get(key).cloned())
        }
        fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
            self.0.insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error> {
            self.0.remove(key);
            Ok(())
        }
    }

    struct TestPlatform;
    impl Platform for TestPlatform {
        fn fill_random(&mut self, bytes: &mut [u8]) {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = index as u8;
            }
        }
        fn now_unix_secs(&self) -> u64 {
            1
        }
    }

    fn signed(identity: &Identity, identity_seq: u64, component_seq: u64) -> SignedRecord {
        SignedRecord::sign(
            Record {
                user_id: user_id(&identity.wallet_public()),
                handle: Handle::new("bob").unwrap(),
                name: "Bob".into(),
                wallet: identity.wallet_public(),
                device: Device::create(identity, component_seq),
                seq: identity_seq,
            },
            identity,
        )
    }

    #[test]
    fn independently_pins_identity_device_and_transport_versions() {
        let identity = Identity::generate(&mut TestPlatform).unwrap();
        let mut store = Mem::default();
        assert!(check_and_pin(&mut store, "bob", &signed(&identity, 5, 9)).unwrap());
        assert!(!check_and_pin(&mut store, "bob", &signed(&identity, 4, 10)).unwrap());
        assert!(!check_and_pin(&mut store, "bob", &signed(&identity, 6, 8)).unwrap());
        assert!(check_and_pin(&mut store, "bob", &signed(&identity, 5, 9)).unwrap());
        assert!(check_and_pin(&mut store, "bob", &signed(&identity, 6, 10)).unwrap());

        clear(&mut store, "bob", &identity.wallet_public()).unwrap();
        assert!(check_and_pin(&mut store, "bob", &signed(&identity, 1, 1)).unwrap());
    }

    #[test]
    fn corrupt_pins_fail_closed_and_are_not_overwritten() {
        let identity = Identity::generate(&mut TestPlatform).unwrap();
        let mut store = Mem::default();
        let storage_key = key("bob", &identity.wallet_public());
        store.put(&storage_key, b"corrupt").unwrap();

        assert!(!check_and_pin(&mut store, "bob", &signed(&identity, 10, 10)).unwrap());
        assert_eq!(
            store.get(&storage_key).unwrap().as_deref(),
            Some(&b"corrupt"[..])
        );
    }
}
