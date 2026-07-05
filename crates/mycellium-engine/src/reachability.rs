//! Local-only, per-device **reachability scoring** (#60) and the shared
//! [`DeliveryPath`] outcome (#59/#60).
//!
//! The delivery ladder ([`crate::app::messaging`]) remembers, per recipient
//! *device* and per *path*, whether that path recently worked — so it can try
//! the most-likely-successful rung first instead of paying a full direct-dial
//! timeout for a device it already knows is unreachable that way. The queue and
//! outbox remain the guaranteed floor; scoring only ever *reorders* the attempts
//! within reason and never removes the floor.
//!
//! # PRIVACY — hard rules (do not weaken)
//!
//! This module is shaped like [`crate::outbox`] / [`crate::verified`]: a single
//! namespaced blob in *this* device's [`Storage`], and nothing more.
//!
//! - **Local-only, never published.** The score lives only in this device's
//!   [`Storage`] and is **never** placed in a `Record`, sent to the directory,
//!   deposited in a queue, or shared with any peer or server. It is a private
//!   cache of *my own* delivery observations, exactly like the outbox.
//! - **Not a presence oracle.** We keep aggregate per-path counts plus a single
//!   **coarse** `last_success` / `last_attempt` timestamp — **not** a
//!   per-message timeline. That is enough to order the ladder, and deliberately
//!   *not* enough to reconstruct a log of when a contact was online. Timestamps
//!   are coarsened to [`COARSEN_SECS`] to blunt fine-grained presence inference
//!   if the store is later read by malware.
//! - **No cross-peer correlation surface.** The API is strictly per-device
//!   ([`record`] / [`best_paths`]); it never aggregates a "who is online now"
//!   view across peers.
//! - **Bounded & clearable.** Entries decay (a success older than
//!   [`SUCCESS_TTL_SECS`] is treated as stale and re-probed), stale devices are
//!   pruned, the store is capped at [`MAX_DEVICES`], and it is fully
//!   [`clear`]-able. It is derived data, never authoritative.
//!
//! Cold start == today's behavior: an unknown device yields [`default_order`]
//! (direct first, queue as the floor), so the absence of data is never worse
//! than before this module existed.

use serde::{Deserialize, Serialize};

use mycellium_core::storage::Storage;
use mycellium_core::wire;

/// The namespaced key holding the whole (local-only) score blob.
const KEY: &[u8] = b"reachability";

/// A success older than this is treated as **stale** — the path is re-probed
/// rather than trusted (a device direct-reachable yesterday may not be today).
pub const SUCCESS_TTL_SECS: u64 = 24 * 3_600;

/// Even a path with several recent failures is **re-probed** once its last
/// attempt is older than this — NAT mappings, networks and port-forwards change,
/// so we never *permanently* abandon a rung ("periodically retry direct", #60).
pub const REPROBE_SECS: u64 = 15 * 60;

/// Consecutive failures (since the last success) after which a live path is
/// deprioritized below the queue. Kept high enough that an ordinary burst of a
/// few sends never abandons direct — only a persistently-dead path is reordered.
pub const DEPRIORITIZE_AFTER: u32 = 3;

/// Stored timestamps are floored to this granularity (one minute) so the store
/// records only coarse "did this work recently", never a fine presence log.
pub const COARSEN_SECS: u64 = 60;

/// Prune device entries untouched for this long, so the store can't grow without
/// bound (same discipline as the outbox).
pub const PRUNE_TTL_SECS: u64 = 30 * 86_400;

/// Hard cap on tracked devices; the oldest-touched are dropped past this.
pub const MAX_DEVICES: usize = 4_096;

/// Which rung of the delivery ladder handled (or would handle) an item — the
/// observable outcome of a delivery attempt (#59) and the scoring key (#60).
///
/// The live/direct band ([`DeliveryPath::is_live_direct`]) is best-effort,
/// end-to-end-authenticated real-time delivery; [`DeliveryPath::Queue`] /
/// [`DeliveryPath::Outbox`] are the store-and-forward safety net.
///
/// Variant order is the wire order (postcard encodes by index); **append new
/// variants at the end** to stay backward-compatible with persisted blobs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum DeliveryPath {
    /// Live push over the peer's published address (raw TCP today; Noise/libp2p
    /// once multiaddr peers are wired — see the `deliver` TODO(#59)).
    Direct,
    /// Live end-to-end stream through a Circuit-Relay v2 node (not yet wired;
    /// reserved so scoring and observability already speak the vocabulary).
    Relay,
    /// Deposited into the recipient's store-and-forward queue (offline peer).
    Queue,
    /// Parked in this device's local encrypted outbox for a later retry.
    Outbox,
    /// Nothing worked this pass (no queue reachable and no live path).
    Failed,
}

impl DeliveryPath {
    /// Whether the item was actually handed off (live or into the queue). This
    /// is the `bool` the old ladder returned: `Direct`/`Relay`/`Queue` are
    /// delivered; `Outbox` (parked locally) and `Failed` are not.
    pub fn is_delivered(self) -> bool {
        matches!(
            self,
            DeliveryPath::Direct | DeliveryPath::Relay | DeliveryPath::Queue
        )
    }

    /// Whether this is a live, direct-band rung (only attempted when the peer's
    /// presence says online), as opposed to the queue/outbox floor.
    pub fn is_live_direct(self) -> bool {
        matches!(self, DeliveryPath::Direct | DeliveryPath::Relay)
    }
}

/// The default ladder order for a device we have no memory of: try the cheapest
/// live rung first, with the queue as the guaranteed floor. Identical to the
/// pre-scoring behavior.
pub fn default_order() -> Vec<DeliveryPath> {
    vec![DeliveryPath::Direct, DeliveryPath::Queue]
}

/// Aggregate outcomes for one (device, path). Deliberately **not** a timeline:
/// counts plus a single coarse timestamp, enough to order the ladder and no
/// more (see the module privacy note).
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct PathStat {
    /// Total successes observed on this path.
    pub successes: u32,
    /// Consecutive failures **since the last success** (reset to 0 on success),
    /// so the count can't accrue forever and directly signals a dead path.
    pub failures: u32,
    /// Coarse unix seconds of the last success (`0` = never).
    pub last_success: u64,
    /// Coarse unix seconds of the last attempt (success or failure).
    pub last_attempt: u64,
}

/// All per-path stats for one device, keyed by the device's slot (hex of its
/// device key) — the *specific* device, not the account, since a laptop may be
/// relay-only while the same account's phone is direct.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct DeviceEntry {
    /// The device slot (hex of the device key).
    key: String,
    /// Coarse unix seconds this entry was last touched (drives pruning).
    last_touch: u64,
    /// Per-path stats. A short `Vec` (one entry per attempted path) rather than
    /// a map, matching the compact-wire style used elsewhere in the engine.
    paths: Vec<(DeliveryPath, PathStat)>,
}

impl DeviceEntry {
    fn stat(&self, path: DeliveryPath) -> PathStat {
        self.paths
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(_, s)| s.clone())
            .unwrap_or_default()
    }

    fn stat_mut(&mut self, path: DeliveryPath) -> &mut PathStat {
        if let Some(i) = self.paths.iter().position(|(p, _)| *p == path) {
            return &mut self.paths[i].1;
        }
        self.paths.push((path, PathStat::default()));
        &mut self.paths.last_mut().expect("just pushed").1
    }
}

/// The whole local score store: a flat list of device entries.
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
struct ScoreStore {
    devices: Vec<DeviceEntry>,
}

impl ScoreStore {
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

    /// Drop entries untouched past [`PRUNE_TTL_SECS`], then cap the total at
    /// [`MAX_DEVICES`] (keeping the most-recently-touched).
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

/// Floor `t` to [`COARSEN_SECS`] so only coarse timestamps are persisted.
fn coarsen(t: u64) -> u64 {
    t - (t % COARSEN_SECS)
}

fn load<S: Storage>(store: &S) -> Result<ScoreStore, S::Error> {
    match store.get(KEY)? {
        None => Ok(ScoreStore::default()),
        // A corrupt blob degrades to "no memory" (cold start), never a hard
        // failure of delivery — this is derived, best-effort data.
        Some(bytes) => Ok(wire::decode(&bytes).unwrap_or_default()),
    }
}

fn save<S: Storage>(store: &mut S, st: &ScoreStore) -> Result<(), S::Error> {
    store.put(KEY, &wire::encode(st))
}

/// Record the outcome of one delivery attempt to `device_key` (its slot) via
/// `path`. A success resets the consecutive-failure streak (so a path that
/// starts working again is trusted immediately); a failure bumps it. Timestamps
/// are coarsened before storage. Pruning keeps the store bounded.
///
/// Local-only: this never leaves the device (see the module privacy note).
pub fn record<S: Storage>(
    store: &mut S,
    device_key: &str,
    path: DeliveryPath,
    ok: bool,
    now: u64,
) -> Result<(), S::Error> {
    let now_c = coarsen(now);
    let mut st = load(store)?;
    {
        let entry = st.entry_mut(device_key);
        entry.last_touch = now_c;
        let stat = entry.stat_mut(path);
        stat.last_attempt = now_c;
        if ok {
            stat.successes = stat.successes.saturating_add(1);
            stat.failures = 0;
            stat.last_success = now_c;
        } else {
            stat.failures = stat.failures.saturating_add(1);
        }
    }
    st.prune(now);
    save(store, &st)
}

/// The order in which the ladder should attempt paths for `device_key`,
/// most-likely-reachable first, always ending with the queue floor.
///
/// An unknown device (or unreadable store) yields [`default_order`]
/// (direct-first, queue as fallback). A device whose direct path is
/// **demonstrably dead** — several consecutive failures, no fresh success, and
/// not yet due for a periodic re-probe — is offered the queue first so we don't
/// pay a doomed direct-dial timeout, while direct is *still listed last* so it
/// is re-probed (never permanently abandoned).
pub fn best_paths<S: Storage>(store: &S, device_key: &str, now: u64) -> Vec<DeliveryPath> {
    let Ok(st) = load(store) else {
        return default_order();
    };
    let Some(entry) = st.find(device_key) else {
        return default_order();
    };
    if direct_deprioritized(&entry.stat(DeliveryPath::Direct), now) {
        vec![DeliveryPath::Queue, DeliveryPath::Direct]
    } else {
        default_order()
    }
}

/// Whether the direct path is currently demonstrably dead (deprioritize it below
/// the queue). True only when *all* hold: no fresh success (stale/never),
/// several consecutive failures, and it is not yet time to re-probe.
fn direct_deprioritized(s: &PathStat, now: u64) -> bool {
    let stale_success =
        s.last_success == 0 || now.saturating_sub(s.last_success) >= SUCCESS_TTL_SECS;
    let doomed = s.failures >= DEPRIORITIZE_AFTER;
    let due_reprobe = now.saturating_sub(s.last_attempt) >= REPROBE_SECS;
    stale_success && doomed && !due_reprobe
}

/// Wipe the entire local score store (user-clearable derived data).
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
    fn is_delivered_semantics() {
        assert!(DeliveryPath::Direct.is_delivered());
        assert!(DeliveryPath::Relay.is_delivered());
        assert!(DeliveryPath::Queue.is_delivered());
        assert!(!DeliveryPath::Outbox.is_delivered());
        assert!(!DeliveryPath::Failed.is_delivered());
    }

    #[test]
    fn unknown_device_gets_sane_default_order() {
        let store = MemStore::default();
        // Cold start: direct first, queue as the floor — never worse than today.
        assert_eq!(
            best_paths(&store, "never-seen", 1_000),
            vec![DeliveryPath::Direct, DeliveryPath::Queue]
        );
    }

    #[test]
    fn fresh_direct_success_keeps_direct_first() {
        let mut store = MemStore::default();
        record(&mut store, "dev", DeliveryPath::Direct, true, 1_000).unwrap();
        // Even with some failures after, a *fresh* success protects direct.
        record(&mut store, "dev", DeliveryPath::Direct, false, 1_100).unwrap();
        record(&mut store, "dev", DeliveryPath::Direct, false, 1_200).unwrap();
        record(&mut store, "dev", DeliveryPath::Direct, false, 1_300).unwrap();
        assert_eq!(
            best_paths(&store, "dev", 1_400),
            vec![DeliveryPath::Direct, DeliveryPath::Queue],
            "a recent success must keep direct ahead of the queue"
        );
    }

    #[test]
    fn dead_direct_is_deprioritized_below_queue() {
        let mut store = MemStore::default();
        // No success ever, several consecutive failures, freshly attempted.
        for t in [100u64, 160, 220] {
            record(&mut store, "dev", DeliveryPath::Direct, false, t).unwrap();
        }
        let order = best_paths(&store, "dev", 260);
        assert_eq!(
            order,
            vec![DeliveryPath::Queue, DeliveryPath::Direct],
            "a persistently-dead direct path must fall behind the queue"
        );
        // ...but direct is still present, so it is never permanently abandoned.
        assert!(order.contains(&DeliveryPath::Direct));
    }

    #[test]
    fn decay_ages_out_a_stale_success() {
        let mut store = MemStore::default();
        // A success, then several failures. While the success is fresh the
        // failures don't unseat direct... (a realistic, non-zero timestamp — `0`
        // is the reserved "never" sentinel, i.e. unix epoch 1970, never a real
        // success time).
        record(&mut store, "dev", DeliveryPath::Direct, true, 600).unwrap();
        for t in [660u64, 720, 780] {
            record(&mut store, "dev", DeliveryPath::Direct, false, t).unwrap();
        }
        assert_eq!(
            best_paths(&store, "dev", 900),
            vec![DeliveryPath::Direct, DeliveryPath::Queue],
            "while the last success is still fresh, direct stays first"
        );
        // ...but once that success has aged past the TTL, the same failure record
        // now deprioritizes direct: the stale success no longer protects it.
        let aged = 600 + SUCCESS_TTL_SECS + 100;
        // A fresh failure at the aged time keeps last_attempt recent (so we are
        // not yet in the periodic re-probe window).
        record(&mut store, "dev", DeliveryPath::Direct, false, aged).unwrap();
        assert_eq!(
            best_paths(&store, "dev", aged + 30),
            vec![DeliveryPath::Queue, DeliveryPath::Direct],
            "a stale success must no longer keep direct ahead of the queue"
        );
    }

    #[test]
    fn dead_direct_is_reprobed_after_the_interval() {
        let mut store = MemStore::default();
        for t in [100u64, 160, 220] {
            record(&mut store, "dev", DeliveryPath::Direct, false, t).unwrap();
        }
        // Right after the failures: deprioritized.
        assert_eq!(
            best_paths(&store, "dev", 260),
            vec![DeliveryPath::Queue, DeliveryPath::Direct]
        );
        // After the re-probe interval since the last attempt: direct is offered
        // first again, so a changed network/NAT is rediscovered.
        assert_eq!(
            best_paths(&store, "dev", 220 + REPROBE_SECS + 1),
            vec![DeliveryPath::Direct, DeliveryPath::Queue],
            "a dead direct path must be periodically re-probed"
        );
    }

    #[test]
    fn success_resets_the_failure_streak() {
        let mut store = MemStore::default();
        for t in [100u64, 160, 220] {
            record(&mut store, "dev", DeliveryPath::Direct, false, t).unwrap();
        }
        // A success clears the streak, so direct is immediately trusted again.
        record(&mut store, "dev", DeliveryPath::Direct, true, 280).unwrap();
        assert_eq!(
            best_paths(&store, "dev", 300),
            vec![DeliveryPath::Direct, DeliveryPath::Queue]
        );
    }

    #[test]
    fn timestamps_are_coarsened() {
        let mut store = MemStore::default();
        record(&mut store, "dev", DeliveryPath::Direct, true, 12_345).unwrap();
        let st = load(&store).unwrap();
        let stat = st.find("dev").unwrap().stat(DeliveryPath::Direct);
        assert_eq!(stat.last_success % COARSEN_SECS, 0);
        assert_eq!(stat.last_success, coarsen(12_345));
    }

    #[test]
    fn prune_bounds_stale_devices() {
        let mut store = MemStore::default();
        // An old device, untouched, then time moves well past the prune TTL.
        record(&mut store, "old", DeliveryPath::Direct, true, 100).unwrap();
        record(
            &mut store,
            "fresh",
            DeliveryPath::Direct,
            true,
            PRUNE_TTL_SECS + 1_000,
        )
        .unwrap();
        let st = load(&store).unwrap();
        assert!(st.find("old").is_none(), "stale device must be pruned");
        assert!(st.find("fresh").is_some());
    }

    #[test]
    fn clear_wipes_the_store() {
        let mut store = MemStore::default();
        record(&mut store, "dev", DeliveryPath::Direct, true, 100).unwrap();
        assert!(load(&store).unwrap().find("dev").is_some());
        clear(&mut store).unwrap();
        assert!(load(&store).unwrap().find("dev").is_none());
    }

    #[test]
    fn per_path_stats_are_independent() {
        let mut store = MemStore::default();
        record(&mut store, "dev", DeliveryPath::Direct, false, 100).unwrap();
        record(&mut store, "dev", DeliveryPath::Queue, true, 100).unwrap();
        let st = load(&store).unwrap();
        let entry = st.find("dev").unwrap();
        assert_eq!(entry.stat(DeliveryPath::Direct).failures, 1);
        assert_eq!(entry.stat(DeliveryPath::Queue).successes, 1);
        assert_eq!(entry.stat(DeliveryPath::Direct).successes, 0);
    }
}
