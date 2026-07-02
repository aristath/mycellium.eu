//! Per-conversation default disappearing-message TTL, persisted through the
//! [`Storage`] trait. When you `send` without an explicit `--expire`, this
//! default (if set for that peer/group) applies.

use messe_core::storage::Storage;
use messe_core::wire;

fn key(peer: &str) -> Vec<u8> {
    let mut k = b"expire/".to_vec();
    k.extend_from_slice(peer.as_bytes());
    k
}

/// Set the default TTL (seconds) for messages to `peer`.
pub fn set<S: Storage>(store: &mut S, peer: &str, ttl_secs: u64) -> Result<(), S::Error> {
    store.put(&key(peer), &wire::encode(&ttl_secs))
}

/// The default TTL (seconds) for `peer`, if any.
pub fn get<S: Storage>(store: &S, peer: &str) -> Result<Option<u64>, S::Error> {
    Ok(store.get(&key(peer))?.and_then(|b| wire::decode(&b).ok()))
}

/// Clear the default for `peer`.
pub fn clear<S: Storage>(store: &mut S, peer: &str) -> Result<(), S::Error> {
    store.delete(&key(peer))
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

    #[test]
    fn set_get_clear() {
        let mut store = MemStore::default();
        assert_eq!(get(&store, "bob").unwrap(), None);
        set(&mut store, "bob", 3600).unwrap();
        assert_eq!(get(&store, "bob").unwrap(), Some(3600));
        clear(&mut store, "bob").unwrap();
        assert_eq!(get(&store, "bob").unwrap(), None);
    }
}
