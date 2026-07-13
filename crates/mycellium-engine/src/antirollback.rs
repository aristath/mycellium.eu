//! Atomic anti-rollback version vectors for split peer records.
//!
//! Identity membership, stable device keys, and device reachability advance
//! independently. One wallet-scoped pin stores the high-water mark for every
//! component, so a fresh address can never hide a rolled-back identity/device
//! claim (or vice versa).

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
    reachability: u64,
    reachability_digest: [u8; 32],
}

fn digest<T: Serialize>(value: &T) -> [u8; 32] {
    mycellium_core::delivery::payload_digest(&wire::canonical(value))
}

fn load<S: Storage>(
    store: &S,
    handle: &str,
    wallet: &WalletPublicKey,
) -> Result<VersionPins, S::Error> {
    Ok(store
        .get(&key(handle, wallet))?
        .and_then(|bytes| wire::decode(&bytes).ok())
        .unwrap_or_default())
}

/// Atomically validate and advance every component in a verified record.
pub fn check_and_pin<S: Storage>(
    store: &mut S,
    handle: &str,
    record: &SignedRecord,
) -> Result<bool, S::Error> {
    let wallet = &record.record.wallet;
    let mut pins = load(store, handle, wallet)?;
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
        let reachability_digest = digest(&device.reachability.record);
        if let Some(known) = pins
            .devices
            .iter()
            .find(|known| known.key == device.device_key)
        {
            if device.signed.record.seq < known.stable
                || (device.signed.record.seq == known.stable
                    && stable_digest != known.stable_digest)
                || device.reachability.record.seq < known.reachability
                || (device.reachability.record.seq == known.reachability
                    && reachability_digest != known.reachability_digest)
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
        let reachability_digest = digest(&device.reachability.record);
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
                if device.reachability.record.seq > known.reachability {
                    known.reachability = device.reachability.record.seq;
                    known.reachability_digest = reachability_digest;
                }
            }
            None => pins.devices.push(DevicePins {
                key: device.device_key,
                stable: device.signed.record.seq,
                stable_digest,
                reachability: device.reachability.record.seq,
                reachability_digest,
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
    use mycellium_core::identity::{Handle, Identity, PeerId};
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

    fn signed(
        identity: &Identity,
        identity_seq: u64,
        component_seq: u64,
        address: &[u8],
    ) -> SignedRecord {
        SignedRecord::sign(
            Record {
                user_id: user_id(&identity.wallet_public()),
                handle: Handle::new("bob").unwrap(),
                name: "Bob".into(),
                wallet: identity.wallet_public(),
                device: Device::create(identity, PeerId(address.to_vec()), component_seq),
                seq: identity_seq,
            },
            identity,
        )
    }

    #[test]
    fn independently_pins_identity_device_and_reachability_versions() {
        let identity = Identity::generate(&mut TestPlatform).unwrap();
        let mut store = Mem::default();
        assert!(check_and_pin(&mut store, "bob", &signed(&identity, 5, 9, b"one")).unwrap());
        assert!(!check_and_pin(&mut store, "bob", &signed(&identity, 4, 10, b"one")).unwrap());
        assert!(!check_and_pin(&mut store, "bob", &signed(&identity, 6, 8, b"one")).unwrap());
        assert!(!check_and_pin(&mut store, "bob", &signed(&identity, 5, 9, b"two")).unwrap());
        assert!(check_and_pin(&mut store, "bob", &signed(&identity, 6, 10, b"two")).unwrap());

        clear(&mut store, "bob", &identity.wallet_public()).unwrap();
        assert!(check_and_pin(&mut store, "bob", &signed(&identity, 1, 1, b"reset")).unwrap());
    }
}
