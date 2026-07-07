//! The local, encrypted **outbox**: messages we couldn't hand off yet.
//!
//! A message is normally delivered live (peer online) or dropped into the
//! recipient's queue. When *neither* works — the peer is offline **and** their
//! queue is unreachable or they publish none — the sealed item is parked here
//! and retried later (on every `send`/`inbox`, or an explicit `outbox` run).
//!
//! Entries are kept per (recipient, device slot) with the already-sealed item,
//! and pruned once they exceed [`MAX_ATTEMPTS`] or [`TTL_SECS`] so the outbox
//! can never grow without bound.

use serde::{Deserialize, Serialize};

use mycellium_core::platform::Platform;
use mycellium_core::storage::Storage;
use mycellium_core::wire;

use crate::groups::MailItem;
use crate::privacy::PrivacyMode;

const KEY: &[u8] = b"outbox";

/// Give up on an entry after this many failed retries.
pub const MAX_ATTEMPTS: u32 = 100;

/// Give up on an entry this long after it was first queued (7 days).
pub const TTL_SECS: u64 = 7 * 86_400;

/// One undelivered, already-sealed item awaiting a retry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxEntry {
    /// Random id, used to remove the entry once delivered.
    pub id: String,
    /// The recipient handle to re-resolve on retry.
    pub recipient: String,
    /// The recipient's device slot this copy was sealed for.
    pub slot: String,
    /// The sealed item (an `Envelope`-bearing `MailItem`), ready to send as-is.
    pub item: MailItem,
    /// When it was first queued (unix seconds).
    pub created_at: u64,
    /// How many delivery attempts have failed so far.
    pub attempts: u32,
    /// Earliest unix-second at which this item may be deposited (the privacy
    /// delay window; see [`crate::privacy`]). `0` means immediate.
    ///
    /// `#[serde(default)]` so entries persisted before this field existed load
    /// as `0` = immediate — preserving the pre-delay behavior across upgrades.
    #[serde(default)]
    pub send_after: u64,
}

impl OutboxEntry {
    /// Whether this entry has exhausted its retries or outlived its TTL at `now`.
    pub fn is_expired(&self, now: u64) -> bool {
        self.attempts >= MAX_ATTEMPTS || now.saturating_sub(self.created_at) >= TTL_SECS
    }

    /// Whether this entry's scheduled delay has elapsed at `now` (i.e. it may be
    /// deposited). A not-yet-due entry is left untouched for a later flush.
    pub fn is_due(&self, now: u64) -> bool {
        now >= self.send_after
    }
}

/// What one flush pass decided about a single *due* entry, after trying to
/// deposit it. Returned by the `deliver` closure passed to [`flush_pass`].
pub enum Attempt {
    /// Deposited successfully — remove it from the outbox.
    Delivered,
    /// Target is gone/unrecoverable (device removed, unparseable) — drop it
    /// without counting a retry.
    Drop,
    /// Still undeliverable — count an attempt and keep it unless now spent.
    Retry,
}

/// Run one flush pass over `entries` at time `now`, depositing entries whose
/// delay has elapsed via `deliver` and returning `(delivered_count, remaining)`.
///
/// This is the pure, network-free core of [`crate::app::flush_outbox`]:
/// - a **not-yet-due** entry (`now < send_after`) is skipped this pass — it is
///   *not* an attempt and does *not* count against [`MAX_ATTEMPTS`] — but a
///   not-yet-due entry that has outlived its [`TTL_SECS`] is still dropped;
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
        // Not yet due: leave it for a later flush (no attempt), but still honor
        // the TTL so a scheduled item can't outlive its expiry unnoticed.
        if !entry.is_due(now) {
            if !entry.is_expired(now) {
                remaining.push(entry);
            }
            continue;
        }
        match deliver(&entry) {
            Attempt::Delivered => delivered += 1,
            Attempt::Drop => {}
            Attempt::Retry => {
                entry.attempts += 1;
                if !entry.is_expired(now) {
                    remaining.push(entry);
                }
            }
        }
    }
    (delivered, remaining)
}

/// The pre-`send_after` shape of an entry, for decoding outboxes persisted by
/// an older build. Our wire format ([`wire`]/postcard) is compact and *not*
/// self-describing: a trailing field that is simply absent from the bytes can't
/// be `#[serde(default)]`-filled during decode (postcard reads fields
/// positionally and hits end-of-input). So we decode old blobs in their exact
/// old shape and lift them into the current one with an immediate `send_after`.
#[derive(Deserialize)]
struct OldOutboxEntry {
    id: String,
    recipient: String,
    slot: String,
    item: MailItem,
    created_at: u64,
    attempts: u32,
}

impl From<OldOutboxEntry> for OutboxEntry {
    fn from(o: OldOutboxEntry) -> Self {
        OutboxEntry {
            id: o.id,
            recipient: o.recipient,
            slot: o.slot,
            item: o.item,
            created_at: o.created_at,
            attempts: o.attempts,
            send_after: 0, // pre-delay entries are immediate
        }
    }
}

/// Load the whole outbox.
pub fn load<S: Storage>(store: &S) -> Result<Vec<OutboxEntry>, S::Error> {
    let Some(bytes) = store.get(KEY)? else {
        return Ok(Vec::new());
    };
    // Current format first; on failure, fall back to the pre-`send_after` shape
    // (upgrade back-compat) before giving up on genuinely-corrupt bytes.
    if let Ok(entries) = wire::decode::<Vec<OutboxEntry>>(&bytes) {
        return Ok(entries);
    }
    if let Ok(old) = wire::decode::<Vec<OldOutboxEntry>>(&bytes) {
        return Ok(old.into_iter().map(OutboxEntry::from).collect());
    }
    // Present but decodes as neither the current nor the legacy shape: genuinely
    // corrupt. Surface it loudly rather than silently dropping parked mail — the
    // raw bytes stay put until the next write, so an export can still recover them.
    crate::warn_corrupt("outbox");
    Ok(Vec::new())
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
    recipient: &str,
    slot: &str,
    item: MailItem,
    now: u64,
) -> Result<(), S::Error> {
    enqueue_at(store, id, recipient, slot, item, now, 0)
}

/// Park a sealed item that may not be deposited before `send_after` (unix
/// seconds). Pass `send_after = 0` (or any past time) for immediate.
pub fn enqueue_at<S: Storage>(
    store: &mut S,
    id: String,
    recipient: &str,
    slot: &str,
    item: MailItem,
    now: u64,
    send_after: u64,
) -> Result<(), S::Error> {
    let mut entries = load(store)?;
    entries.push(OutboxEntry {
        id,
        recipient: recipient.to_string(),
        slot: slot.to_string(),
        item,
        created_at: now,
        attempts: 0,
        send_after,
    });
    save(store, &entries)
}

/// Schedule a queued deposit under a [`PrivacyMode`]: compute
/// `send_after = now + mode.delivery_delay(platform)` and park the item so the
/// next due flush deposits it. The clean entry point for SDK/clients.
///
/// `Normal` yields a `0` delay (immediate); `Private`/`HighRisk` draw a
/// randomized in-window delay from the platform CSPRNG. The delayed deposit is
/// persisted, so it survives a restart and is retried, never lost.
pub fn schedule_deposit<S: Storage, P: Platform>(
    store: &mut S,
    platform: &mut P,
    id: String,
    recipient: &str,
    slot: &str,
    item: MailItem,
    mode: PrivacyMode,
) -> Result<(), S::Error> {
    let now = platform.now_unix_secs();
    let send_after = now.saturating_add(mode.delivery_delay(platform));
    enqueue_at(store, id, recipient, slot, item, now, send_after)
}

/// Number of items currently waiting.
pub fn len<S: Storage>(store: &S) -> Result<usize, S::Error> {
    Ok(load(store)?.len())
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
    fn expiry_by_attempts_or_ttl() {
        let mut e = sample("1");
        assert!(!e.is_expired(10));
        e.attempts = MAX_ATTEMPTS;
        assert!(e.is_expired(10));
        e.attempts = 0;
        assert!(e.is_expired(TTL_SECS + 1));
    }

    /// A deterministic platform: `now` is fixed and `fill_random` yields a fixed
    /// byte so `delivery_delay` for a mode is reproducible.
    struct FixedPlatform {
        now: u64,
        byte: u8,
    }
    impl Platform for FixedPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.byte;
            }
        }
        fn now_unix_secs(&self) -> u64 {
            self.now
        }
    }

    #[test]
    fn enqueue_is_immediate_by_default() {
        let mut store = MemStore::default();
        enqueue(
            &mut store,
            "1".into(),
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
    fn schedule_deposit_sets_future_send_after() {
        let mut store = MemStore::default();
        // Private window is 0..=30; byte 0xFF gives a nonzero draw, so send_after
        // is strictly in the future here. now = 1_000.
        let mut p = FixedPlatform {
            now: 1_000,
            byte: 0xFF,
        };
        schedule_deposit(
            &mut store,
            &mut p,
            "1".into(),
            "mary",
            "abcd",
            sample("1").item,
            PrivacyMode::Private,
        )
        .unwrap();
        let e = &load(&store).unwrap()[0];
        assert_eq!(e.created_at, 1_000);
        assert!(e.send_after > 1_000 && e.send_after <= 1_030);
        assert!(!e.is_due(1_000), "must not be due before the delay elapses");
        assert!(e.is_due(e.send_after));
    }

    #[test]
    fn scheduled_entry_survives_reload_and_flushes_once_due() {
        // Persist a scheduled entry due at t=200, then reload it (restart).
        let mut store = MemStore::default();
        enqueue_at(
            &mut store,
            "1".into(),
            "mary",
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

        // Once due: it is deposited exactly once and removed.
        let mut attempts = 0;
        let (delivered, remaining) = flush_pass(remaining, 200, |_| {
            attempts += 1;
            Attempt::Delivered
        });
        assert_eq!(attempts, 1);
        assert_eq!(delivered, 1);
        assert!(remaining.is_empty());
    }

    #[test]
    fn not_yet_due_but_expired_is_dropped() {
        // Scheduled far in the future but already past its TTL: expiry wins even
        // though it was never due.
        let e = OutboxEntry {
            send_after: TTL_SECS + 10_000,
            ..sample("1")
        };
        let (delivered, remaining) = flush_pass(vec![e], TTL_SECS + 1, |_| Attempt::Retry);
        assert_eq!(delivered, 0);
        assert!(
            remaining.is_empty(),
            "expired-while-pending entry must be dropped"
        );
    }

    #[test]
    fn due_entry_retry_bumps_attempts_and_keeps() {
        let e = sample("1"); // send_after = 0 → due
        let (delivered, remaining) = flush_pass(vec![e], 10, |_| Attempt::Retry);
        assert_eq!(delivered, 0);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].attempts, 1);
    }

    #[test]
    fn corrupt_outbox_loads_empty_not_silently_dropped() {
        // A present-but-undecodable blob (neither the current nor the legacy
        // shape) must load as empty via the loud corruption path — not a hard
        // error, and not a silent drop. The raw bytes stay put for recovery.
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

    #[test]
    fn old_format_entry_loads_as_immediate() {
        // Encode an entry WITHOUT `send_after`, exactly as an older build would
        // have persisted it, and confirm it deserializes to send_after = 0.
        #[derive(Serialize)]
        struct OldEntry {
            id: String,
            recipient: String,
            slot: String,
            item: MailItem,
            created_at: u64,
            attempts: u32,
        }
        let old = OldEntry {
            id: "1".into(),
            recipient: "mary".into(),
            slot: "abcd".into(),
            item: sample("1").item,
            created_at: 42,
            attempts: 3,
        };
        let bytes = wire::encode(&vec![old]);
        let mut store = MemStore::default();
        store.put(KEY, &bytes).unwrap();

        let loaded = load(&store).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].send_after, 0,
            "missing field defaults to immediate"
        );
        assert_eq!(loaded[0].created_at, 42);
        assert_eq!(loaded[0].attempts, 3);
        assert!(loaded[0].is_due(0));
    }
}
