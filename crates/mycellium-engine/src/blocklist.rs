//! A local, encrypted block list of handles whose messages we refuse.
//!
//! Generic over [`Storage`] (unit-tested with an in-memory store; runs on the
//! encrypted `FileStore`).

use mycellium_core::storage::Storage;
use mycellium_core::wire;

const KEY: &[u8] = b"blocklist";

/// Load the set of blocked handles.
pub fn load<S: Storage>(store: &S) -> Result<Vec<String>, S::Error> {
    Ok(store
        .get(KEY)?
        .and_then(|b| wire::decode(&b).ok())
        .unwrap_or_default())
}

/// Block a handle (idempotent).
pub fn block<S: Storage>(store: &mut S, handle: &str) -> Result<(), S::Error> {
    let mut list = load(store)?;
    if !list.iter().any(|h| h == handle) {
        list.push(handle.to_string());
        store.put(KEY, &wire::encode(&list))?;
    }
    Ok(())
}

/// Unblock a handle.
pub fn unblock<S: Storage>(store: &mut S, handle: &str) -> Result<(), S::Error> {
    let list: Vec<String> = load(store)?.into_iter().filter(|h| h != handle).collect();
    store.put(KEY, &wire::encode(&list))
}

/// Whether `handle` is in the blocked set.
pub fn is_blocked(list: &[String], handle: &str) -> bool {
    list.iter().any(|h| h == handle)
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
    fn block_unblock_roundtrip() {
        let mut store = MemStore::default();
        assert!(!is_blocked(&load(&store).unwrap(), "spammer"));

        block(&mut store, "spammer").unwrap();
        block(&mut store, "spammer").unwrap(); // idempotent
        assert!(is_blocked(&load(&store).unwrap(), "spammer"));
        assert_eq!(load(&store).unwrap().len(), 1);

        unblock(&mut store, "spammer").unwrap();
        assert!(!is_blocked(&load(&store).unwrap(), "spammer"));
    }
}
