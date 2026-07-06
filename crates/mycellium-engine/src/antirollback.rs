//! Client-side anti-rollback for directory records.
//!
//! A record carries a wallet-signed, monotonic `seq`. The directory rejects a
//! lower-`seq` update, but a **malicious or compelled** directory can still serve
//! an older — still validly-signed, same-wallet — record to roll a peer back to a
//! stale device set or queue/relay endpoint (e.g. re-introducing a device the
//! victim removed after a compromise, so a sender seals to it again). The
//! wallet-change (TOFU) guard can't catch that: the wallet is unchanged.
//!
//! So each client pins the highest `seq` it has seen per handle and refuses a
//! regression — moving anti-rollback into the trust boundary that matters (the
//! client), not the untrusted directory (core review, HIGH).

use mycellium_core::storage::Storage;

fn key(handle: &str) -> Vec<u8> {
    let mut k = b"seqpin:".to_vec();
    k.extend_from_slice(handle.as_bytes());
    k
}

/// The highest record `seq` pinned for `handle`, if any.
pub fn highest<S: Storage>(store: &S, handle: &str) -> Result<Option<u64>, S::Error> {
    Ok(store.get(&key(handle))?.and_then(|b| {
        <[u8; 8]>::try_from(b.as_slice())
            .ok()
            .map(u64::from_le_bytes)
    }))
}

/// Check `seq` against the pinned high-water mark for `handle` and, if it is not
/// a rollback, advance the pin. Returns `Ok(true)` when the record is fresh
/// (`seq >= pinned`, or nothing pinned yet); `Ok(false)` when it is a rollback
/// (`seq < pinned`), leaving the pin unchanged.
pub fn check_and_pin<S: Storage>(store: &mut S, handle: &str, seq: u64) -> Result<bool, S::Error> {
    if let Some(seen) = highest(store, handle)? {
        if seq < seen {
            return Ok(false);
        }
    }
    store.put(&key(handle), &seq.to_le_bytes())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::convert::Infallible;

    #[derive(Default)]
    struct Mem(HashMap<Vec<u8>, Vec<u8>>);
    impl Storage for Mem {
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
    fn pins_and_rejects_rollback() {
        let mut s = Mem::default();
        // First sight of any seq is accepted and pinned.
        assert!(check_and_pin(&mut s, "bob", 5).unwrap());
        // Equal or higher is fresh and advances the pin.
        assert!(check_and_pin(&mut s, "bob", 5).unwrap());
        assert!(check_and_pin(&mut s, "bob", 9).unwrap());
        // A lower seq — the rollback a compelled directory would serve — is refused.
        assert!(!check_and_pin(&mut s, "bob", 8).unwrap());
        // ...and the rejected attempt did not lower the pin.
        assert_eq!(highest(&s, "bob").unwrap(), Some(9));
        // A different handle is independent.
        assert!(check_and_pin(&mut s, "carol", 1).unwrap());
    }
}
