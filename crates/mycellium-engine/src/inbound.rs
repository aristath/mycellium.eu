//! The local **inbound retry** store: raw queue blobs whose processing didn't
//! complete yet.
//!
//! Collecting from the queue *drains* the mailbox server-side, so if a blob then
//! fails to parse, can't be decrypted yet (a group sender key hasn't arrived), or
//! hits a transient local error, it would otherwise be lost (at-most-once).
//! Instead we write collected blobs here **before** processing, retry them on the
//! next `inbox`, and drop only ones that succeed or exceed [`MAX_ATTEMPTS`] /
//! [`TTL_SECS`] — so a crash or a not-yet-decryptable item can't lose mail, and
//! the store can't grow without bound.

use serde::{Deserialize, Serialize};

use mycellium_core::storage::Storage;
use mycellium_core::wire;

const KEY: &[u8] = b"inbound_retry";

/// Give up on a blob after this many failed processing attempts (dead-letter).
pub const MAX_ATTEMPTS: u32 = 50;

/// Give up on a blob this long after it was first collected (7 days).
pub const TTL_SECS: u64 = 7 * 86_400;

/// One collected-but-not-yet-processed blob awaiting a retry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingItem {
    /// The raw mailbox blob (serialized `MailItem`), retried as-is.
    pub blob: String,
    /// When it was first collected (unix seconds).
    pub created_at: u64,
    /// How many processing attempts have failed so far.
    pub attempts: u32,
}

impl PendingItem {
    /// Whether this blob has exhausted its retries or outlived its TTL at `now`.
    pub fn is_expired(&self, now: u64) -> bool {
        self.attempts >= MAX_ATTEMPTS || now.saturating_sub(self.created_at) >= TTL_SECS
    }
}

/// Load the whole inbound-retry store.
pub fn load<S: Storage>(store: &S) -> Result<Vec<PendingItem>, S::Error> {
    Ok(store.get(KEY)?.and_then(|b| wire::decode(&b).ok()).unwrap_or_default())
}

/// Persist the whole inbound-retry store.
pub fn save<S: Storage>(store: &mut S, items: &[PendingItem]) -> Result<(), S::Error> {
    store.put(KEY, &wire::encode(&items.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_is_by_attempts_or_ttl() {
        let mk = |attempts, created| PendingItem { blob: "x".into(), created_at: created, attempts };
        assert!(!mk(0, 0).is_expired(10));
        assert!(mk(MAX_ATTEMPTS, 0).is_expired(0)); // too many tries
        assert!(mk(0, 0).is_expired(TTL_SECS + 1)); // too old
    }
}
