//! Local signed-record book.
//!
//! This is the hard-serverless discovery floor: records are self-authenticating
//! and stored locally. A DHT, QR exchange, LAN gossip, or manual copy can feed
//! this book, but no discovery transport becomes authority.

use serde::{Deserialize, Serialize};

use mycellium_core::identity::{Handle, Identity};
use mycellium_core::record::{Device, Record, SignedRecord};
use mycellium_core::storage::Storage;
use mycellium_core::userid::user_id;
use mycellium_core::wire;

use crate::antirollback;
use crate::groups::DiscoveryRecord;

const KEY: &[u8] = b"peerbook";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerRecord {
    pub handle: String,
    pub record: SignedRecord,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PeerBook {
    records: Vec<PeerRecord>,
}

pub fn load<S: Storage>(store: &S) -> Result<Vec<PeerRecord>, S::Error> {
    let Some(bytes) = store.get(KEY)? else {
        return Ok(Vec::new());
    };
    Ok(crate::decode_or_warn::<PeerBook>(Some(bytes), "peerbook").records)
}

fn save<S: Storage>(store: &mut S, records: Vec<PeerRecord>) -> Result<(), S::Error> {
    store.put(KEY, &wire::encode(&PeerBook { records }))
}

pub fn get<S: Storage>(store: &S, handle: &Handle) -> Result<Option<SignedRecord>, S::Error> {
    Ok(load(store)?
        .into_iter()
        .find(|entry| entry.handle == handle.as_str())
        .map(|entry| entry.record))
}

pub fn put<S: Storage>(store: &mut S, handle: &Handle, record: SignedRecord) -> anyhow::Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    verify_handle(handle, &record)?;
    record
        .verify()
        .map_err(|_| anyhow::anyhow!("record failed verification"))?;
    if record
        .record
        .devices
        .iter()
        .any(|d| d.peer_id().0.is_empty())
    {
        anyhow::bail!(
            "record for '{}' has an empty device address",
            handle.as_str()
        );
    }
    if !antirollback::check_and_pin(store, handle.as_str(), &record)? {
        anyhow::bail!("stale record for '{}'", handle.as_str());
    }

    let mut records = load(store)?;
    match records
        .iter_mut()
        .find(|entry| entry.handle == handle.as_str())
    {
        Some(entry) => entry.record = record,
        None => records.push(PeerRecord {
            handle: handle.as_str().to_string(),
            record,
        }),
    }
    save(store, records)?;
    Ok(())
}

pub fn remove<S: Storage>(store: &mut S, handle: &Handle) -> Result<bool, S::Error> {
    let mut records = load(store)?;
    let before = records.len();
    records.retain(|entry| entry.handle != handle.as_str());
    let removed = before != records.len();
    save(store, records)?;
    Ok(removed)
}

pub fn pack<S: Storage>(store: &S, want: &[String]) -> Result<Vec<DiscoveryRecord>, S::Error> {
    let records = load(store)?;
    if want.is_empty() {
        return Ok(records
            .into_iter()
            .map(|entry| DiscoveryRecord {
                handle: entry.handle,
                record: entry.record,
            })
            .collect());
    }
    Ok(records
        .into_iter()
        .filter(|entry| want.iter().any(|handle| handle == &entry.handle))
        .map(|entry| DiscoveryRecord {
            handle: entry.handle,
            record: entry.record,
        })
        .collect())
}

#[derive(Debug, Default)]
pub struct ImportReport {
    pub imported: usize,
    pub skipped: Vec<(String, String)>,
}

pub fn import_records<S: Storage>(
    store: &mut S,
    records: impl IntoIterator<Item = DiscoveryRecord>,
) -> ImportReport
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let mut report = ImportReport::default();
    for entry in records {
        let handle = match Handle::new(entry.handle.clone()) {
            Ok(handle) => handle,
            Err(_) => {
                report
                    .skipped
                    .push((entry.handle, "invalid handle".to_string()));
                continue;
            }
        };
        match put(store, &handle, entry.record) {
            Ok(()) => report.imported += 1,
            Err(err) => report
                .skipped
                .push((handle.as_str().to_string(), err.to_string())),
        }
    }
    report
}

pub fn build_record(
    platform: &mut impl mycellium_core::platform::Platform,
    identity: &Identity,
    handle: &Handle,
    name: &str,
    addr: &str,
) -> SignedRecord {
    let record = Record {
        handle: user_id(handle.as_str()),
        name: name.to_string(),
        wallet: identity.wallet_public(),
        devices: vec![crate::wireops::this_device(
            identity,
            addr,
            platform.now_unix_secs(),
        )],
        seq: platform.now_unix_secs(),
    };
    SignedRecord::sign(record, identity)
}

pub fn with_devices(
    platform: &mut impl mycellium_core::platform::Platform,
    identity: &Identity,
    handle: &Handle,
    name: &str,
    devices: Vec<Device>,
    prev_seq: u64,
) -> SignedRecord {
    let record = Record {
        handle: user_id(handle.as_str()),
        name: name.to_string(),
        wallet: identity.wallet_public(),
        devices,
        seq: prev_seq.saturating_add(1).max(platform.now_unix_secs()),
    };
    SignedRecord::sign(record, identity)
}

pub fn encode(record: &SignedRecord) -> String {
    crate::wireops::hex(&wire::encode(record))
}

pub fn decode(s: &str) -> anyhow::Result<SignedRecord> {
    let bytes = from_hex(s.trim())?;
    let record: SignedRecord = wire::decode(&bytes).map_err(|_| anyhow::anyhow!("bad record"))?;
    record
        .verify()
        .map_err(|_| anyhow::anyhow!("record failed verification"))?;
    Ok(record)
}

fn verify_handle(handle: &Handle, record: &SignedRecord) -> anyhow::Result<()> {
    if record.record.handle != user_id(handle.as_str()) {
        anyhow::bail!("record does not belong to '{}'", handle.as_str());
    }
    Ok(())
}

fn from_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("hex string has an odd length");
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| anyhow::anyhow!("invalid hex"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycellium_core::platform::Platform;
    use std::collections::HashMap;
    use std::convert::Infallible;

    #[derive(Default)]
    struct MemStore(HashMap<Vec<u8>, Vec<u8>>);

    impl Storage for MemStore {
        type Error = Infallible;

        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Infallible> {
            Ok(self.0.get(key).cloned())
        }

        fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Infallible> {
            self.0.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), Infallible> {
            self.0.remove(key);
            Ok(())
        }
    }

    struct TestPlatform;

    impl Platform for TestPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(17).wrapping_add(3);
            }
        }

        fn now_unix_secs(&self) -> u64 {
            10
        }
    }

    #[test]
    fn rejects_records_with_empty_device_addresses() {
        let mut platform = TestPlatform;
        let identity = Identity::generate(&mut platform).unwrap();
        let handle = Handle::new("alice").unwrap();
        let record = build_record(&mut platform, &identity, &handle, "Alice", "");
        let mut store = MemStore::default();

        assert!(put(&mut store, &handle, record).is_err());
        assert!(get(&store, &handle).unwrap().is_none());
    }

    #[test]
    fn corrupt_peerbook_loads_empty_but_leaves_bytes_in_place() {
        let mut store = MemStore::default();
        store.put(KEY, b"not a peerbook").unwrap();

        assert!(load(&store).unwrap().is_empty());
        assert_eq!(
            store.get(KEY).unwrap().as_deref(),
            Some(&b"not a peerbook"[..])
        );
    }

    #[test]
    fn pack_filters_requested_handles() {
        let mut platform = TestPlatform;
        let identity = Identity::generate(&mut platform).unwrap();
        let alice = Handle::new("alice").unwrap();
        let record = build_record(&mut platform, &identity, &alice, "Alice", "127.0.0.1:1");
        let mut store = MemStore::default();
        put(&mut store, &alice, record).unwrap();

        let all = pack(&store, &[]).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].handle, "alice");

        let wanted = pack(&store, &["alice".to_string()]).unwrap();
        assert_eq!(wanted.len(), 1);

        let missing = pack(&store, &["bob".to_string()]).unwrap();
        assert!(missing.is_empty());
    }

    #[test]
    fn import_records_verifies_every_entry() {
        let mut platform = TestPlatform;
        let identity = Identity::generate(&mut platform).unwrap();
        let alice = Handle::new("alice").unwrap();
        let record = build_record(&mut platform, &identity, &alice, "Alice", "127.0.0.1:1");
        let mut store = MemStore::default();

        let report = import_records(
            &mut store,
            [
                DiscoveryRecord {
                    handle: "alice".to_string(),
                    record: record.clone(),
                },
                DiscoveryRecord {
                    handle: "not a handle".to_string(),
                    record,
                },
            ],
        );

        assert_eq!(report.imported, 1);
        assert_eq!(report.skipped.len(), 1);
        assert!(get(&store, &alice).unwrap().is_some());
    }
}
