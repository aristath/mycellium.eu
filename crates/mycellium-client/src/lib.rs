//! Headless Mycellium client API.
//!
//! This crate is the reusable client boundary. It owns account/device record
//! semantics and local peer-record mutations; shells decide only how to prompt,
//! print, and connect transports.

use anyhow::{anyhow, bail, Result};

use mycellium_core::identity::{Handle, Identity, PeerId};
use mycellium_core::platform::Platform;
use mycellium_core::record::SignedRecord;
use mycellium_core::storage::Storage;
use mycellium_engine::antirollback;
use mycellium_engine::peerbook::{self, PeerRecord};
use mycellium_engine::wireops;

/// Public identity material useful for display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityInfo {
    pub wallet: Vec<u8>,
    pub device: Vec<u8>,
    pub messaging: Vec<u8>,
}

pub fn identity_info(identity: &Identity) -> IdentityInfo {
    IdentityInfo {
        wallet: identity.wallet_public().0.to_vec(),
        device: identity.device_public().0.to_vec(),
        messaging: identity.messaging_public().0.to_vec(),
    }
}

pub fn create_identity(platform: &mut impl Platform) -> Result<Identity> {
    Ok(Identity::generate(platform)?)
}

pub fn adopt_identity(platform: &mut impl Platform, wallet_secret: [u8; 32]) -> Result<Identity> {
    Ok(Identity::adopt(platform, wallet_secret)?)
}

/// Build and store this account's current public record.
///
/// If the existing local record belongs to the same wallet and the same active
/// device, this refreshes only reachability. If it belongs to the same wallet but
/// a different device, this publishes the current device as the new active one.
pub fn publish_active_device_record<S, P>(
    store: &mut S,
    platform: &mut P,
    identity: &Identity,
    handle: &Handle,
    name: &str,
    location: &str,
) -> Result<SignedRecord>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
    P: Platform,
{
    let existing = reusable_own_record(identity, handle, peerbook::get(store, handle)?)?;
    let now = platform.now_unix_secs();
    let active_device = match existing.as_ref() {
        Some(record) if record.record.device.device_key == identity.device_public() => {
            let device = &record.record.device;
            let reachability_seq = now.max(device.reachability.record.seq.saturating_add(1));
            device
                .refresh_reachability(
                    identity,
                    PeerId(location.as_bytes().to_vec()),
                    reachability_seq,
                )
                .map_err(|_| anyhow!("could not sign refreshed reachability"))?
        }
        _ => wireops::this_device(identity, location, now),
    };
    let active_device_changed = existing
        .as_ref()
        .map(|record| record.record.device.device_key != active_device.device_key)
        .unwrap_or(true);
    let signed = match existing {
        Some(mut record) if !active_device_changed && record.record.name == name => {
            // Pure address refresh: preserve wallet-signed identity and stable
            // device records byte-for-byte.
            record.record.device = active_device;
            record
        }
        existing => peerbook::with_device(
            platform,
            identity,
            handle,
            name,
            active_device,
            existing.as_ref().map(|r| r.record.seq).unwrap_or(0),
        ),
    };
    peerbook::put(store, handle, signed.clone())?;
    Ok(signed)
}

pub fn reusable_own_record(
    identity: &Identity,
    handle: &Handle,
    existing: Option<SignedRecord>,
) -> Result<Option<SignedRecord>> {
    let Some(record) = existing else {
        return Ok(None);
    };
    record.verify().map_err(|_| {
        anyhow!(
            "local record for '{}' failed verification; run `record remove {}` before registering it here",
            handle.as_str(),
            handle.as_str()
        )
    })?;
    if record.record.wallet != identity.wallet_public() {
        bail!(
            "local record for '{}' belongs to a different wallet; run `record remove {}` before registering it here",
            handle.as_str(),
            handle.as_str()
        );
    }
    Ok(Some(record))
}

pub fn require_record<S: Storage>(store: &S, handle: &Handle) -> Result<SignedRecord>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    peerbook::get(store, handle)?
        .ok_or_else(|| anyhow!("no local record for '{}'", handle.as_str()))
}

pub fn require_own_record<S: Storage>(store: &S, handle: &Handle) -> Result<SignedRecord>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    peerbook::get(store, handle)?.ok_or_else(|| {
        anyhow!(
            "no local signed record for '{}' — run `register {} --addr <host:port>` first",
            handle.as_str(),
            handle.as_str()
        )
    })
}

pub fn import_record<S: Storage>(store: &mut S, handle: &Handle, record: SignedRecord) -> Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    peerbook::put(store, handle, record)
}

pub fn list_records<S: Storage>(store: &S) -> Result<Vec<PeerRecord>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    Ok(peerbook::load(store)?)
}

pub fn remove_record<S: Storage>(store: &mut S, handle: &Handle) -> Result<bool>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let wallet = peerbook::get(store, handle)?.map(|record| record.record.wallet);
    let removed = peerbook::remove(store, handle)?;
    if removed {
        if let Some(wallet) = wallet {
            antirollback::clear(store, handle.as_str(), &wallet)?;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::convert::Infallible;

    #[derive(Default)]
    struct MemStore(HashMap<Vec<u8>, Vec<u8>>);

    impl Storage for MemStore {
        type Error = Infallible;

        fn get(&self, key: &[u8]) -> std::result::Result<Option<Vec<u8>>, Infallible> {
            Ok(self.0.get(key).cloned())
        }

        fn put(&mut self, key: &[u8], value: &[u8]) -> std::result::Result<(), Infallible> {
            self.0.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> std::result::Result<(), Infallible> {
            self.0.remove(key);
            Ok(())
        }
    }

    struct SeededPlatform(u8);

    impl Platform for SeededPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.0.wrapping_add((i as u8).wrapping_mul(31));
            }
            self.0 = self.0.wrapping_add(1);
        }

        fn now_unix_secs(&self) -> u64 {
            42
        }
    }

    #[test]
    fn publishing_switches_to_the_current_active_device() {
        let handle = Handle::new("alice").unwrap();
        let mut first_platform = SeededPlatform(1);
        let mut second_platform = SeededPlatform(80);
        let first = Identity::generate(&mut first_platform).unwrap();
        let second = Identity::adopt(&mut second_platform, first.wallet_secret()).unwrap();
        let mut store = MemStore::default();

        let first_record = publish_active_device_record(
            &mut store,
            &mut first_platform,
            &first,
            &handle,
            "Alice",
            "127.0.0.1:1",
        )
        .unwrap();
        let second_record = publish_active_device_record(
            &mut store,
            &mut second_platform,
            &second,
            &handle,
            "Alice",
            "127.0.0.1:2",
        )
        .unwrap();

        assert_ne!(
            first_record.record.device.device_key,
            second_record.record.device.device_key
        );
        assert_eq!(
            require_record(&store, &handle)
                .unwrap()
                .record
                .device
                .device_key,
            second.device_public()
        );
    }

    #[test]
    fn publishing_rejects_a_foreign_wallet_record() {
        let handle = Handle::new("alice").unwrap();
        let mut mine_platform = SeededPlatform(1);
        let mut foreign_platform = SeededPlatform(99);
        let mine = Identity::generate(&mut mine_platform).unwrap();
        let foreign = Identity::generate(&mut foreign_platform).unwrap();
        let mut store = MemStore::default();
        let foreign_record = peerbook::build_record(
            &mut foreign_platform,
            &foreign,
            &handle,
            "Alice",
            "127.0.0.1:1",
        );
        peerbook::put(&mut store, &handle, foreign_record).unwrap();

        let err = publish_active_device_record(
            &mut store,
            &mut mine_platform,
            &mine,
            &handle,
            "Alice",
            "127.0.0.1:2",
        )
        .unwrap_err();

        assert!(err.to_string().contains("different wallet"));
    }
}
