//! Durable storage for the queue (Tier 0.1).
//!
//! Persists what must survive a restart: queued mail (per recipient wallet +
//! slot) and push subscriptions. Ephemeral state (login challenges, session
//! tokens, rate counters) stays in memory. Backed by `redb`.

use std::collections::HashMap;
use std::sync::Mutex;

use redb::{ReadableTable, TableDefinition};

use crate::Subscription;

// One redb key **per queued blob**: `"{wallet}\0{slot}\0{seq:020}" → blob`. The
// seq is the depositing state's monotonic write counter, zero-padded to 20
// digits so redb's lexicographic key order equals FIFO insertion order. This
// makes `deposit` an O(1) single-key insert (no whole-mailbox re-serialize) and
// `collect` a bounded range-delete over the `"{wallet}\0{slot}\0"` prefix.
const MAILBOX: TableDefinition<&str, &str> = TableDefinition::new("mailbox");
const SUBS: TableDefinition<&str, &[u8]> = TableDefinition::new("subs"); // wallet → json Vec<Subscription>

/// The persisted state loaded on startup.
#[derive(Default)]
pub struct Loaded {
    pub mailboxes: HashMap<(String, String), Vec<String>>,
    pub subs: HashMap<String, Vec<Subscription>>,
    /// The highest per-blob `seq` seen across all persisted blob keys. The
    /// in-memory write counter is seeded from this on open so that seqs stay
    /// **monotonic across a reopen** — otherwise a fresh counter (starting at 0)
    /// would collide with existing blob keys and a collect's bound could fail to
    /// cover blobs deposited by an earlier process (see [`crate::Queue::open`]).
    pub max_seq: u64,
}

/// One durable mutation, captured under the state lock and committed **off** it
/// (on `spawn_blocking`). Each carries a monotonic `seq` from the in-memory
/// state's write counter: because commits run off the lock they can reach redb
/// out of the order the memory was mutated, so [`Store::apply`] uses the `seq`
/// to keep the durable state consistent with the latest in-memory state despite
/// a reordered commit (see the per-variant handling in [`Store::apply`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Write {
    /// Append one opaque blob to a `(wallet, slot)` mailbox under its **own**
    /// per-blob key `"{wallet}\0{slot}\0{seq:020}"`. O(1): a single key insert,
    /// no whole-mailbox re-serialize. `seq` is the depositing state's monotonic
    /// write counter — unique across the queue and, zero-padded in the key,
    /// makes redb's range order equal FIFO insertion order for the mailbox.
    Blob {
        wallet: String,
        slot: String,
        seq: u64,
        blob: String,
    },
    /// Drain a `(wallet, slot)` mailbox (a collect emptied it): a **bounded**
    /// range-delete of every blob key for it with seq `< seq` (the collect's
    /// write counter). Bounding by `seq` is load-bearing — a deposit that lands
    /// *after* this collect necessarily carries a higher seq, so a delete that
    /// commits late can never sweep away post-collect mail.
    DrainMailbox {
        wallet: String,
        slot: String,
        seq: u64,
    },
    /// Replace the push-subscription list for one wallet.
    Subs {
        wallet: String,
        subs: Vec<Subscription>,
        seq: u64,
    },
}

pub struct Store {
    db: redb::Database,
    /// The guard that makes concurrent off-lock commits order-independent (see
    /// [`Write`]). Per durable key it holds:
    /// - `s:{wallet}` — highest committed subs `seq` (a whole-value write).
    /// - `m:{wallet}\0{slot}` — the mailbox **drain floor**: the highest collect
    ///   `seq` committed for it. A blob insert with `seq <= floor` was already
    ///   drained, so it is skipped (never resurrected); a drain raises the floor.
    ///   Blob inserts do **not** raise the floor — sibling blobs have distinct
    ///   keys and must all persist, so they must not suppress one another.
    ///
    /// Touched only on the write path (inside `spawn_blocking`), never by read
    /// handlers, so it never stalls the async runtime or the state lock.
    versions: Mutex<HashMap<String, u64>>,
}

impl Store {
    pub fn open(path: &str) -> Result<Self, String> {
        let db = redb::Database::create(path).map_err(err)?;
        let txn = db.begin_write().map_err(err)?;
        {
            txn.open_table(MAILBOX).map_err(err)?;
            txn.open_table(SUBS).map_err(err)?;
        }
        txn.commit().map_err(err)?;
        Ok(Store {
            db,
            versions: Mutex::new(HashMap::new()),
        })
    }

    pub fn load(&self) -> Result<Loaded, String> {
        let mut out = Loaded::default();
        let txn = self.db.begin_read().map_err(err)?;

        // Range-scan the per-blob keys. redb iterates in lexicographic key order,
        // and a key is `"{wallet}\0{slot}\0{seq:020}"`, so entries arrive grouped
        // by `(wallet, slot)` and, within a mailbox, in ascending seq — i.e. FIFO
        // insertion order. Appending as we go rebuilds each mailbox `Vec` in order.
        let mailbox = txn.open_table(MAILBOX).map_err(err)?;
        for entry in mailbox.iter().map_err(err)? {
            let (k, v) = entry.map_err(err)?;
            let mut parts = k.value().splitn(3, '\0');
            if let (Some(wallet), Some(slot), Some(seq)) =
                (parts.next(), parts.next(), parts.next())
            {
                if let Ok(seq) = seq.parse::<u64>() {
                    out.max_seq = out.max_seq.max(seq);
                }
                out.mailboxes
                    .entry((wallet.to_string(), slot.to_string()))
                    .or_default()
                    .push(v.value().to_string());
            }
        }
        let subs = txn.open_table(SUBS).map_err(err)?;
        for entry in subs.iter().map_err(err)? {
            let (k, v) = entry.map_err(err)?;
            out.subs.insert(k.value().to_string(), load_subs(v.value()));
        }
        Ok(out)
    }

    /// Durably apply one [`Write`], keeping the durable state consistent with the
    /// latest in-memory state despite reordered off-lock commits (see [`Write`]).
    /// Returns `Ok(())` for a fresh commit and for a deliberately-skipped stale
    /// one alike — either way the key is at least as new as this snapshot when
    /// the call returns, so the caller may report success.
    pub fn apply(&self, write: Write) -> Result<(), String> {
        match write {
            Write::Blob {
                wallet,
                slot,
                seq,
                blob,
            } => self.insert_blob(&wallet, &slot, seq, &blob),
            Write::DrainMailbox { wallet, slot, seq } => self.drain_mailbox(&wallet, &slot, seq),
            Write::Subs { wallet, subs, seq } => {
                let json = serde_json::to_vec(&subs).map_err(err)?;
                self.versioned(&format!("s:{wallet}"), seq, |txn| {
                    txn.open_table(SUBS)
                        .map_err(err)?
                        .insert(wallet.as_str(), &json[..])
                        .map_err(err)?;
                    Ok(())
                })
            }
        }
    }

    /// Insert one blob under its own per-blob key, unless a collect already
    /// drained through it. A blob is skipped iff `seq <= floor` for its mailbox
    /// (its `DrainMailbox` committed first — the blob was collected, so writing
    /// it would resurrect just-collected mail). Unlike [`Store::versioned`], a
    /// blob insert does **not** raise the floor: sibling blobs in one mailbox
    /// have distinct keys and must all persist, so they must not suppress one
    /// another. The `versions` lock spans the check + commit so a concurrent
    /// drain cannot raise the floor and delete between our check and our insert.
    fn insert_blob(&self, wallet: &str, slot: &str, seq: u64, blob: &str) -> Result<(), String> {
        let floor_key = format!("m:{wallet}\0{slot}");
        let versions = self.versions.lock().unwrap_or_else(|e| e.into_inner());
        if versions.get(&floor_key).is_some_and(|&floor| seq <= floor) {
            return Ok(()); // a collect already drained through this blob
        }
        let key = format!("{wallet}\0{slot}\0{seq:020}");
        let txn = self.db.begin_write().map_err(err)?;
        {
            txn.open_table(MAILBOX)
                .map_err(err)?
                .insert(key.as_str(), blob)
                .map_err(err)?;
        }
        txn.commit().map_err(err)?;
        Ok(())
    }

    /// Drain a mailbox durably: a bounded range-delete of every blob key for it
    /// with seq `< seq`, then raise its drain floor to `seq`. Bounding by `seq`
    /// leaves a post-collect deposit (higher seq) untouched even if this delete
    /// commits late; raising the floor makes any stale concurrent blob insert
    /// (`seq <= floor`) skip rather than resurrect collected mail. The `versions`
    /// lock spans the commit so the floor and the delete move together.
    fn drain_mailbox(&self, wallet: &str, slot: &str, seq: u64) -> Result<(), String> {
        let floor_key = format!("m:{wallet}\0{slot}");
        let mut versions = self.versions.lock().unwrap_or_else(|e| e.into_inner());
        let lo = format!("{wallet}\0{slot}\0{:020}", 0u64);
        let hi = format!("{wallet}\0{slot}\0{seq:020}");
        let txn = self.db.begin_write().map_err(err)?;
        {
            // retain nothing in [lo, hi) → remove every blob key with seq < seq.
            txn.open_table(MAILBOX)
                .map_err(err)?
                .retain_in(lo.as_str()..hi.as_str(), |_, _| false)
                .map_err(err)?;
        }
        txn.commit().map_err(err)?;
        let floor = versions.entry(floor_key).or_insert(0);
        *floor = (*floor).max(seq);
        Ok(())
    }

    /// Commit `f` iff `seq` is newer than the last committed `seq` for `vkey`,
    /// else skip it as stale (used for whole-value writes — subs). The `versions`
    /// lock spans the commit so a concurrent apply to the same key can't
    /// interleave a stale write — redb already serializes its single writer, so
    /// this adds no contention beyond that, and (unlike the state lock it
    /// replaced) it is never held across a read.
    fn versioned(
        &self,
        vkey: &str,
        seq: u64,
        f: impl FnOnce(&redb::WriteTransaction) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut versions = self.versions.lock().unwrap_or_else(|e| e.into_inner());
        if versions.get(vkey).is_some_and(|&last| seq <= last) {
            return Ok(()); // a newer snapshot already committed this key
        }
        let txn = self.db.begin_write().map_err(err)?;
        f(&txn)?;
        txn.commit().map_err(err)?;
        versions.insert(vkey.to_string(), seq);
        Ok(())
    }

    #[cfg(test)]
    fn write(
        &self,
        f: impl FnOnce(&redb::WriteTransaction) -> Result<(), String>,
    ) -> Result<(), String> {
        let txn = self.db.begin_write().map_err(err)?;
        f(&txn)?;
        txn.commit().map_err(err)
    }
}

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Decode a persisted subscription list, upgrading the pre-tagged-union format
/// (a bare `Vec<String>` of web-push endpoints) into `Vec<Subscription>`.
///
/// Current format first; on failure fall back to the old endpoint-string shape
/// (back-compat), exactly like the outbox `load()` upcast. This explicit
/// fallback is load-bearing: `serde_json` will **not** coerce a bare endpoint
/// string into a `#[serde(tag = "kind")]` enum, so a naive type change would
/// fail to decode and silently drop *every* pre-upgrade subscription. Genuinely
/// corrupt bytes decode to an empty list, as before.
fn load_subs(bytes: &[u8]) -> Vec<Subscription> {
    if let Ok(subs) = serde_json::from_slice::<Vec<Subscription>>(bytes) {
        return subs;
    }
    if let Ok(endpoints) = serde_json::from_slice::<Vec<String>>(bytes) {
        return endpoints
            .into_iter()
            .map(|endpoint| Subscription::WebPush { endpoint })
            .collect();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "myc-persist-{tag}-{}-{:?}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
        ))
    }

    #[test]
    fn old_format_web_push_subs_migrate_to_webpush() {
        let path = temp_path("subs-migrate");
        let path_str = path.to_str().unwrap();
        {
            let store = Store::open(path_str).unwrap();
            // Plant an OLD-format blob: a bare `Vec<String>` of endpoints, exactly
            // as a pre-tagged-union build persisted, straight into the SUBS table.
            let old = serde_json::to_vec(&vec![
                "https://push.example/a".to_string(),
                "https://push.example/b".to_string(),
            ])
            .unwrap();
            store
                .write(|txn| {
                    txn.open_table(SUBS)
                        .map_err(err)?
                        .insert("wallethex", &old[..])
                        .map_err(err)?;
                    Ok(())
                })
                .unwrap();
        }
        // Reopening upgrades the bare strings into tagged `WebPush` entries.
        let loaded = Store::open(path_str).unwrap().load().unwrap();
        assert_eq!(
            loaded.subs.get("wallethex").unwrap(),
            &vec![
                Subscription::WebPush {
                    endpoint: "https://push.example/a".into()
                },
                Subscription::WebPush {
                    endpoint: "https://push.example/b".into()
                },
            ],
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn drain_floor_guards_reordered_blob_and_drain_commits() {
        // Per-blob keys make sibling inserts independent, but a blob insert and
        // its mailbox's drain can still reach redb out of order. The drain floor
        // must (a) skip a stale blob whose drain already committed — no
        // resurrection of collected mail — and (b) never sweep a post-collect
        // deposit that carries a higher seq than the drain's bound.
        let path = temp_path("drain-floor");
        let path_str = path.to_str().unwrap();
        let store = Store::open(path_str).unwrap();
        let (w, s) = ("wallethex", "account");
        let blob = |seq: u64, b: &str| Write::Blob {
            wallet: w.into(),
            slot: s.into(),
            seq,
            blob: b.into(),
        };
        let drain = |seq: u64| Write::DrainMailbox {
            wallet: w.into(),
            slot: s.into(),
            seq,
        };

        // (a) A drain at seq 6 commits BEFORE a stale blob at seq 5 → the blob is
        // skipped (it was already collected), so it cannot resurrect.
        store.apply(drain(6)).unwrap();
        store.apply(blob(5, "stale")).unwrap();
        // (b) A post-collect deposit at seq 9 survives — the drain's range-delete
        // is bounded below it.
        store.apply(blob(9, "fresh")).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(
            loaded.mailboxes.get(&(w.to_string(), s.to_string())),
            Some(&vec!["fresh".to_string()]),
            "the drained blob stays gone; the post-collect blob persists"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn drain_removes_only_blobs_below_its_bound() {
        // A bounded range-delete over `{wallet}\0{slot}\0` removes exactly the
        // blobs with seq < the drain's seq, leaving a higher-seq blob in place.
        let path = temp_path("drain-bound");
        let path_str = path.to_str().unwrap();
        let store = Store::open(path_str).unwrap();
        let (w, s) = ("wallethex", "account");
        for (seq, b) in [(1u64, "a"), (2, "b"), (10, "c")] {
            store
                .apply(Write::Blob {
                    wallet: w.into(),
                    slot: s.into(),
                    seq,
                    blob: b.into(),
                })
                .unwrap();
        }
        // Drain at seq 5 sweeps seqs 1 and 2 but keeps seq 10.
        store
            .apply(Write::DrainMailbox {
                wallet: w.into(),
                slot: s.into(),
                seq: 5,
            })
            .unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(
            loaded.mailboxes.get(&(w.to_string(), s.to_string())),
            Some(&vec!["c".to_string()]),
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tagged_subscriptions_round_trip() {
        let path = temp_path("subs-roundtrip");
        let path_str = path.to_str().unwrap();
        let subs = vec![
            Subscription::WebPush {
                endpoint: "https://push.example/x".into(),
            },
            Subscription::Apns {
                token: "abcdef01".into(),
                topic: "eu.mycellium.app".into(),
            },
            Subscription::Fcm {
                token: "fcm-token".into(),
            },
            Subscription::UnifiedPush {
                endpoint: "https://ntfy.example/up".into(),
            },
        ];
        {
            let store = Store::open(path_str).unwrap();
            store
                .apply(Write::Subs {
                    wallet: "wallethex".into(),
                    subs: subs.clone(),
                    seq: 1,
                })
                .unwrap();
        }
        let loaded = Store::open(path_str).unwrap().load().unwrap();
        assert_eq!(loaded.subs.get("wallethex").unwrap(), &subs);
        let _ = std::fs::remove_file(&path);
    }
}
