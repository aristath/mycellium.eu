//! The local, encrypted **outbox**: sender-owned delivery state.
//!
//! A message is normally delivered live to a peer-published device address. If
//! that direct handoff fails, the already-sealed item is parked here and retried
//! later on an explicit outbox flush or the next sending action.
//!
//! Pending entries carry the already-sealed item for retry. Final entries remain
//! as local truth: delivered, failed, or cancelled.

use serde::{Deserialize, Serialize};

use mycellium_core::storage::Storage;
use mycellium_core::wire;

use crate::groups::MailItem;

const KEY: &[u8] = b"outbox";

/// Retry starts quickly, then backs off to avoid hammering an offline peer.
pub const RETRY_BASE_SECS: u64 = 5;
pub const RETRY_MAX_SECS: u64 = 60 * 60;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutboxStatus {
    #[default]
    Pending,
    Delivered,
    Failed,
    Cancelled,
}

/// One sender-owned delivery item.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxEntry {
    /// Stable delivery id for this exact sealed item.
    pub id: String,
    /// Stable recipient identity used to re-resolve the exact person on retry.
    pub recipient_user_id: String,
    /// Human-readable recipient handle for display only.
    pub recipient: String,
    /// The recipient's device slot this copy was sealed for.
    pub slot: String,
    /// The sealed item (an `Envelope`-bearing `MailItem`), ready to send as-is.
    pub item: MailItem,
    /// When it was first parked (unix seconds).
    pub created_at: u64,
    /// How many delivery attempts have failed so far.
    pub attempts: u32,
    /// Earliest unix-second at which this item may be retried. `0` means
    /// immediate.
    #[serde(default)]
    pub send_after: u64,
    #[serde(default)]
    pub status: OutboxStatus,
}

impl OutboxEntry {
    pub fn is_pending(&self) -> bool {
        self.status == OutboxStatus::Pending
    }

    /// Whether this entry's scheduled delay has elapsed at `now`.
    pub fn is_due(&self, now: u64) -> bool {
        self.is_pending() && now >= self.send_after
    }
}

/// What one flush pass decided about a single *due* entry, after trying direct
/// delivery. Returned by the closure passed to [`flush_pass`].
pub enum Attempt {
    /// Deposited successfully — remove it from the outbox.
    Delivered,
    /// Target is gone/unrecoverable (device removed, unparseable) — drop it
    /// without counting a retry.
    Drop,
    /// Still undeliverable — count an attempt and keep it.
    Retry,
}

/// Run one flush pass over `entries` at time `now`, retrying entries whose delay
/// has elapsed via `deliver` and returning `(delivered_count, remaining)`.
///
/// This is the pure, network-free core used by a shell's outbox flush:
/// - a **not-yet-due** entry (`now < send_after`) is skipped this pass;
/// - a **due** entry is handed to `deliver`, and the returned [`Attempt`]
///   decides whether it is removed, dropped, or bumped-and-kept.
///
/// Batching falls out for free: every entry that is due at `now` is deposited in
/// the same pass.
pub fn flush_pass<F>(
    entries: Vec<OutboxEntry>,
    now: u64,
    mut deliver: F,
) -> (usize, Vec<OutboxEntry>)
where
    F: FnMut(&OutboxEntry) -> Attempt,
{
    let mut delivered = 0;
    let mut remaining: Vec<OutboxEntry> = Vec::new();
    for mut entry in entries {
        if !entry.is_due(now) {
            remaining.push(entry);
            continue;
        }
        match deliver(&entry) {
            Attempt::Delivered => {
                entry.status = OutboxStatus::Delivered;
                delivered += 1;
                remaining.push(entry);
            }
            Attempt::Drop => {
                entry.status = OutboxStatus::Failed;
                remaining.push(entry);
            }
            Attempt::Retry => {
                entry.attempts += 1;
                entry.send_after = now.saturating_add(retry_delay(&entry));
                remaining.push(entry);
            }
        }
    }
    (delivered, remaining)
}

fn retry_delay(entry: &OutboxEntry) -> u64 {
    let exponent = entry.attempts.saturating_sub(1).min(10);
    let delay = RETRY_BASE_SECS.saturating_mul(1u64 << exponent);
    let digest = mycellium_core::delivery::payload_digest(entry.id.as_bytes());
    let jitter = u64::from(digest[0]) % RETRY_BASE_SECS;
    delay.saturating_add(jitter).min(RETRY_MAX_SECS)
}

/// Load the whole outbox.
pub fn load<S: Storage>(store: &S) -> Result<Vec<OutboxEntry>, S::Error> {
    let Some(bytes) = store.get(KEY)? else {
        return Ok(Vec::new());
    };
    Ok(crate::decode_or_warn(Some(bytes), "outbox"))
}

/// Persist the whole outbox.
pub fn save<S: Storage>(store: &mut S, entries: &[OutboxEntry]) -> Result<(), S::Error> {
    store.put(KEY, &wire::encode(&entries.to_vec()))
}

/// Park a sealed item for **immediate** retry (`send_after = 0`). This is the
/// unchanged behavior for normal/urgent sends and outbox re-parks.
pub fn enqueue<S: Storage>(
    store: &mut S,
    id: String,
    recipient_user_id: &str,
    recipient: &str,
    slot: &str,
    item: MailItem,
    now: u64,
) -> Result<(), S::Error> {
    enqueue_at(
        store,
        id,
        (recipient_user_id, recipient),
        slot,
        item,
        now,
        0,
    )
}

/// Park a sealed item that may not be deposited before `send_after` (unix
/// seconds). Pass `send_after = 0` (or any past time) for immediate.
pub fn enqueue_at<S: Storage>(
    store: &mut S,
    id: String,
    recipient: (&str, &str),
    slot: &str,
    item: MailItem,
    now: u64,
    send_after: u64,
) -> Result<(), S::Error> {
    let (recipient_user_id, recipient) = recipient;
    let mut entries = load(store)?;
    entries.push(OutboxEntry {
        id,
        recipient_user_id: recipient_user_id.to_string(),
        recipient: recipient.to_string(),
        slot: slot.to_string(),
        item,
        created_at: now,
        attempts: 0,
        send_after,
        status: OutboxStatus::Pending,
    });
    save(store, &entries)
}

/// Number of items currently waiting.
pub fn len<S: Storage>(store: &S) -> Result<usize, S::Error> {
    Ok(load(store)?
        .iter()
        .filter(|entry| entry.is_pending())
        .count())
}

fn set_status<S: Storage>(store: &mut S, id: &str, status: OutboxStatus) -> Result<bool, S::Error> {
    let mut entries = load(store)?;
    let mut found = false;
    for entry in &mut entries {
        if entry.id == id {
            entry.status = status;
            entry.send_after = 0;
            found = true;
        }
    }
    if found {
        save(store, &entries)?;
    }
    Ok(found)
}

/// Mark one delivery as accepted by the recipient device.
pub fn mark_delivered<S: Storage>(store: &mut S, id: &str) -> Result<bool, S::Error> {
    set_status(store, id, OutboxStatus::Delivered)
}

/// Mark one pending delivery as cancelled by the local user.
pub fn mark_cancelled<S: Storage>(store: &mut S, id: &str) -> Result<bool, S::Error> {
    set_status(store, id, OutboxStatus::Cancelled)
}

/// Mark one delivery as no longer retryable.
pub fn mark_failed<S: Storage>(store: &mut S, id: &str) -> Result<bool, S::Error> {
    set_status(store, id, OutboxStatus::Failed)
}

/// Explicit user retry overrides any scheduled backoff.
pub fn make_all_due<S: Storage>(store: &mut S) -> Result<(), S::Error> {
    let mut entries = load(store)?;
    for entry in &mut entries {
        if entry.is_pending() {
            entry.send_after = 0;
        }
    }
    save(store, &entries)
}

/// Apply one background attempt result if the delivery is still pending.
pub fn record_attempt<S: Storage>(
    store: &mut S,
    id: &str,
    now: u64,
    accepted: bool,
) -> Result<bool, S::Error> {
    let entries = load(store)?;
    let mut found = false;
    let mut remaining = Vec::with_capacity(entries.len());
    for mut entry in entries {
        if entry.id != id {
            remaining.push(entry);
            continue;
        }
        found = true;
        if accepted {
            entry.status = OutboxStatus::Delivered;
            entry.send_after = 0;
            remaining.push(entry);
        } else {
            entry.attempts = entry.attempts.saturating_add(1);
            entry.send_after = now.saturating_add(retry_delay(&entry));
            remaining.push(entry);
        }
    }
    if !found {
        return Ok(false);
    }
    save(store, &remaining)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycellium_core::group::GroupMessage;
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

    fn sample(id: &str) -> OutboxEntry {
        OutboxEntry {
            id: id.to_string(),
            recipient_user_id: "a".repeat(64),
            recipient: "mary".into(),
            slot: "abcd".into(),
            item: MailItem::GroupText {
                group_id: "g".into(),
                message: GroupMessage {
                    sender: vec![1],
                    iteration: 0,
                    ciphertext: vec![2, 3],
                    signature: vec![4; 64],
                },
            },
            created_at: 0,
            attempts: 0,
            send_after: 0,
            status: OutboxStatus::Pending,
        }
    }

    #[test]
    fn enqueue_load_save_roundtrip() {
        let mut store = MemStore::default();
        assert_eq!(len(&store).unwrap(), 0);

        let e = sample("1");
        enqueue(
            &mut store,
            e.id.clone(),
            &e.recipient_user_id,
            &e.recipient,
            &e.slot,
            e.item.clone(),
            0,
        )
        .unwrap();
        assert_eq!(len(&store).unwrap(), 1);

        // Remove by rewriting without it.
        let kept: Vec<OutboxEntry> = load(&store)
            .unwrap()
            .into_iter()
            .filter(|x| x.id != "1")
            .collect();
        save(&mut store, &kept).unwrap();
        assert_eq!(len(&store).unwrap(), 0);
    }

    #[test]
    fn enqueue_is_immediate_by_default() {
        let mut store = MemStore::default();
        enqueue(
            &mut store,
            "1".into(),
            &"a".repeat(64),
            "mary",
            "abcd",
            sample("1").item,
            100,
        )
        .unwrap();
        let e = &load(&store).unwrap()[0];
        assert_eq!(e.send_after, 0);
        assert!(e.is_due(0), "immediate entry must be due even at t=0");
        assert!(e.is_due(100));
    }

    #[test]
    fn scheduled_entry_survives_reload_and_flushes_once_due() {
        // Persist a scheduled entry due at t=200, then reload it (restart).
        let mut store = MemStore::default();
        enqueue_at(
            &mut store,
            "1".into(),
            (&"a".repeat(64), "mary"),
            "abcd",
            sample("1").item,
            100,
            200,
        )
        .unwrap();

        // --- reload (simulated restart) ---
        let reloaded = load(&store).unwrap();
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded[0].send_after, 200);

        // Before it's due: skipped, kept, and NOT counted as an attempt.
        let mut attempts = 0;
        let (delivered, remaining) = flush_pass(reloaded, 150, |_| {
            attempts += 1;
            Attempt::Retry
        });
        assert_eq!(delivered, 0);
        assert_eq!(
            attempts, 0,
            "not-yet-due entry must not be handed to deliver"
        );
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].attempts, 0, "no attempt counted while pending");

        // Once due: it is deposited exactly once and marked final, so it never
        // retries but still records the truth.
        let mut attempts = 0;
        let (delivered, remaining) = flush_pass(remaining, 200, |_| {
            attempts += 1;
            Attempt::Delivered
        });
        assert_eq!(attempts, 1);
        assert_eq!(delivered, 1);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].status, OutboxStatus::Delivered);
        assert!(!remaining[0].is_pending());
    }

    #[test]
    fn due_entry_retry_bumps_attempts_and_keeps() {
        let e = sample("1"); // send_after = 0 → due
        let (delivered, remaining) = flush_pass(vec![e], 10, |_| Attempt::Retry);
        assert_eq!(delivered, 0);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].attempts, 1);
        assert!(remaining[0].send_after > 10);
    }

    #[test]
    fn recording_one_attempt_does_not_mutate_other_due_deliveries() {
        let mut store = MemStore::default();
        save(&mut store, &[sample("1"), sample("2")]).unwrap();

        record_attempt(&mut store, "1", 100, false).unwrap();
        let entries = load(&store).unwrap();
        let first = entries.iter().find(|entry| entry.id == "1").unwrap();
        let second = entries.iter().find(|entry| entry.id == "2").unwrap();
        assert_eq!(first.attempts, 1);
        assert!(first.send_after > 100);
        assert_eq!(second.attempts, 0);
        assert_eq!(second.send_after, 0);

        make_all_due(&mut store).unwrap();
        assert!(load(&store)
            .unwrap()
            .iter()
            .all(|entry| entry.send_after == 0));
    }

    #[test]
    fn corrupt_outbox_loads_empty_not_silently_dropped() {
        // A present-but-undecodable blob must load as empty via the loud
        // corruption path, not a hard error and not a silent drop. The raw bytes
        // stay put for recovery.
        let mut store = MemStore::default();
        store.put(KEY, b"not valid wire bytes").unwrap();
        let loaded = load(&store).unwrap();
        assert!(loaded.is_empty());
        // Bytes are left in place until the next write so an export can recover.
        assert_eq!(
            store.get(KEY).unwrap().as_deref(),
            Some(&b"not valid wire bytes"[..])
        );
    }
}
