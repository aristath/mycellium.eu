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

use mycellium_core::storage::Storage;
use mycellium_core::wire;

use crate::groups::MailItem;

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
}

impl OutboxEntry {
    /// Whether this entry has exhausted its retries or outlived its TTL at `now`.
    pub fn is_expired(&self, now: u64) -> bool {
        self.attempts >= MAX_ATTEMPTS || now.saturating_sub(self.created_at) >= TTL_SECS
    }
}

/// Load the whole outbox.
pub fn load<S: Storage>(store: &S) -> Result<Vec<OutboxEntry>, S::Error> {
    Ok(store
        .get(KEY)?
        .and_then(|b| wire::decode(&b).ok())
        .unwrap_or_default())
}

/// Persist the whole outbox.
pub fn save<S: Storage>(store: &mut S, entries: &[OutboxEntry]) -> Result<(), S::Error> {
    store.put(KEY, &wire::encode(&entries.to_vec()))
}

/// Park a sealed item for a later retry.
pub fn enqueue<S: Storage>(
    store: &mut S,
    id: String,
    recipient: &str,
    slot: &str,
    item: MailItem,
    now: u64,
) -> Result<(), S::Error> {
    let mut entries = load(store)?;
    entries.push(OutboxEntry {
        id,
        recipient: recipient.to_string(),
        slot: slot.to_string(),
        item,
        created_at: now,
        attempts: 0,
    });
    save(store, &entries)
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
}
