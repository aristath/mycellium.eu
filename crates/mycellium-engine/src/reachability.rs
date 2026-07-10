//! Local-only reachability observations.
//!
//! Hard-serverless Mycellium has one core network path: direct peer-to-peer
//! delivery. If direct fails, the caller parks the already-sealed item in the
//! sender's local outbox. This module records coarse direct outcomes as derived,
//! clearable local state. It is never published and never authoritative.

use serde::{Deserialize, Serialize};

use mycellium_core::storage::Storage;
use mycellium_core::wire;

const KEY: &[u8] = b"reachability";

pub const SUCCESS_TTL_SECS: u64 = 24 * 3_600;
pub const REPROBE_SECS: u64 = 15 * 60;
pub const DEPRIORITIZE_AFTER: u32 = 3;
pub const COARSEN_SECS: u64 = 60;
pub const PRUNE_TTL_SECS: u64 = 30 * 86_400;
pub const MAX_DEVICES: usize = 4_096;

/// Observable outcome of a delivery attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum DeliveryPath {
    /// Live direct delivery over the peer's published address.
    Direct,
    /// Parked in this device's local encrypted outbox for a later retry.
    Outbox,
    /// Nothing worked this pass.
    Failed,
}

impl DeliveryPath {
    pub fn is_delivered(self) -> bool {
        matches!(self, DeliveryPath::Direct)
    }

    pub fn is_live_direct(self) -> bool {
        matches!(self, DeliveryPath::Direct)
    }
}

pub fn default_order() -> Vec<DeliveryPath> {
    vec![DeliveryPath::Direct]
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct PathStat {
    pub successes: u32,
    pub failures: u32,
    pub last_success: u64,
    pub last_attempt: u64,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct DeviceEntry {
    key: String,
    last_touch: u64,
    direct: PathStat,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct ScoreStore {
    devices: Vec<DeviceEntry>,
}

impl ScoreStore {
    #[cfg(test)]
    fn find(&self, key: &str) -> Option<&DeviceEntry> {
        self.devices.iter().find(|d| d.key == key)
    }

    fn entry_mut(&mut self, key: &str) -> &mut DeviceEntry {
        if let Some(i) = self.devices.iter().position(|d| d.key == key) {
            return &mut self.devices[i];
        }
        self.devices.push(DeviceEntry {
            key: key.to_string(),
            ..Default::default()
        });
        self.devices.last_mut().expect("just pushed")
    }

    fn prune(&mut self, now: u64) {
        self.devices
            .retain(|d| now.saturating_sub(d.last_touch) < PRUNE_TTL_SECS);
        if self.devices.len() > MAX_DEVICES {
            self.devices
                .sort_by_key(|d| std::cmp::Reverse(d.last_touch));
            self.devices.truncate(MAX_DEVICES);
        }
    }
}

fn coarsen(t: u64) -> u64 {
    t - (t % COARSEN_SECS)
}

fn load<S: Storage>(store: &S) -> Result<ScoreStore, S::Error> {
    match store.get(KEY)? {
        None => Ok(ScoreStore::default()),
        Some(bytes) => Ok(wire::decode(&bytes).unwrap_or_default()),
    }
}

fn save<S: Storage>(store: &mut S, st: &ScoreStore) -> Result<(), S::Error> {
    store.put(KEY, &wire::encode(st))
}

pub fn record<S: Storage>(
    store: &mut S,
    device_key: &str,
    path: DeliveryPath,
    ok: bool,
    now: u64,
) -> Result<(), S::Error> {
    if path != DeliveryPath::Direct {
        return Ok(());
    }
    let now_c = coarsen(now);
    let mut st = load(store)?;
    {
        let entry = st.entry_mut(device_key);
        entry.last_touch = now_c;
        entry.direct.last_attempt = now_c;
        if ok {
            entry.direct.successes = entry.direct.successes.saturating_add(1);
            entry.direct.failures = 0;
            entry.direct.last_success = now_c;
        } else {
            entry.direct.failures = entry.direct.failures.saturating_add(1);
        }
    }
    if st.devices.len() >= MAX_DEVICES {
        st.prune(now);
    }
    save(store, &st)
}

pub fn best_paths<S: Storage>(_store: &S, _device_key: &str, _now: u64) -> Vec<DeliveryPath> {
    default_order()
}

pub fn best_paths_for<S: Storage>(
    _store: &S,
    _device_key: &str,
    live: DeliveryPath,
    _now: u64,
) -> Vec<DeliveryPath> {
    vec![live]
}

pub fn clear<S: Storage>(store: &mut S) -> Result<(), S::Error> {
    store.delete(KEY)
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
        fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, Infallible> {
            Ok(self.0.get(k).cloned())
        }
        fn put(&mut self, k: &[u8], v: &[u8]) -> Result<(), Infallible> {
            self.0.insert(k.to_vec(), v.to_vec());
            Ok(())
        }
        fn delete(&mut self, k: &[u8]) -> Result<(), Infallible> {
            self.0.remove(k);
            Ok(())
        }
    }

    #[test]
    fn direct_is_the_only_delivered_path() {
        assert!(DeliveryPath::Direct.is_delivered());
        assert!(!DeliveryPath::Outbox.is_delivered());
        assert!(!DeliveryPath::Failed.is_delivered());
    }

    #[test]
    fn unknown_device_attempts_direct_only() {
        let store = MemStore::default();
        assert_eq!(
            best_paths(&store, "never-seen", 1_000),
            vec![DeliveryPath::Direct]
        );
    }

    #[test]
    fn outcomes_are_recorded_locally_and_coarsened() {
        let mut store = MemStore::default();
        record(&mut store, "dev", DeliveryPath::Direct, true, 12_345).unwrap();
        let st = load(&store).unwrap();
        let stat = &st.find("dev").unwrap().direct;
        assert_eq!(stat.successes, 1);
        assert_eq!(stat.failures, 0);
        assert_eq!(stat.last_success, coarsen(12_345));
    }

    #[test]
    fn failure_streak_resets_on_success() {
        let mut store = MemStore::default();
        record(&mut store, "dev", DeliveryPath::Direct, false, 100).unwrap();
        record(&mut store, "dev", DeliveryPath::Direct, false, 160).unwrap();
        record(&mut store, "dev", DeliveryPath::Direct, true, 220).unwrap();
        let st = load(&store).unwrap();
        let stat = &st.find("dev").unwrap().direct;
        assert_eq!(stat.failures, 0);
        assert_eq!(stat.successes, 1);
    }

    #[test]
    fn record_bounds_the_store_at_the_cap() {
        let mut store = MemStore::default();
        for i in 0..(MAX_DEVICES + 5) {
            record(
                &mut store,
                &format!("dev{i}"),
                DeliveryPath::Direct,
                true,
                1_000,
            )
            .unwrap();
        }
        let st = load(&store).unwrap();
        assert!(st.devices.len() <= MAX_DEVICES);
    }

    #[test]
    fn clear_wipes_the_store() {
        let mut store = MemStore::default();
        record(&mut store, "dev", DeliveryPath::Direct, true, 1_000).unwrap();
        clear(&mut store).unwrap();
        assert_eq!(best_paths(&store, "dev", 1_001), default_order());
    }
}
