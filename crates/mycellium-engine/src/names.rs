//! Locally-learned display names: `id → the sender's self-set name`.
//!
//! Populated when a message arrives (from the sender's wallet-signed record), so
//! an **unsaved** sender shows their chosen name (e.g. "Mary") instead of a raw
//! id. A saved contact's nickname always wins over this; this is just the
//! fallback so first contact isn't anonymous.

use mycellium_core::storage::Storage;
use mycellium_core::wire;

const KEY: &[u8] = b"names";

/// All learned `(id, name)` pairs.
pub fn load<S: Storage>(store: &S) -> Result<Vec<(String, String)>, S::Error> {
    Ok(crate::decode_or_warn(store.get(KEY)?, "learned names"))
}

/// Remember (or refresh) the display name a peer publishes for their id.
pub fn note<S: Storage>(store: &mut S, id: &str, name: &str) -> Result<(), S::Error> {
    if name.is_empty() {
        return Ok(());
    }
    let mut list = load(store)?;
    match list.iter_mut().find(|(i, _)| i == id) {
        Some(entry) if entry.1 == name => return Ok(()),
        Some(entry) => entry.1 = name.to_string(),
        None => list.push((id.to_string(), name.to_string())),
    }
    store.put(KEY, &wire::encode(&list))
}

/// The learned name for `id`, if any.
pub fn get<S: Storage>(store: &S, id: &str) -> Result<Option<String>, S::Error> {
    Ok(load(store)?
        .into_iter()
        .find(|(i, _)| i == id)
        .map(|(_, n)| n))
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
    fn note_and_get_and_refresh() {
        let mut s = MemStore::default();
        assert_eq!(get(&s, "id1").unwrap(), None);
        note(&mut s, "id1", "Mary").unwrap();
        assert_eq!(get(&s, "id1").unwrap().as_deref(), Some("Mary"));
        note(&mut s, "id1", "Mary S.").unwrap(); // refresh
        assert_eq!(get(&s, "id1").unwrap().as_deref(), Some("Mary S."));
        note(&mut s, "id1", "").unwrap(); // empty is ignored
        assert_eq!(get(&s, "id1").unwrap().as_deref(), Some("Mary S."));
    }
}
