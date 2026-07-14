//! Per-conversation draft messages, persisted through [`Storage`] (encrypted
//! at rest like everything else). Generic so it's unit-tested in memory.

use mycellium_core::storage::Storage;
use mycellium_core::wire;

fn key(peer: &str) -> Vec<u8> {
    let mut k = b"draft/".to_vec();
    k.extend_from_slice(peer.as_bytes());
    k
}

/// Save a draft for `peer`.
pub fn set<S>(store: &mut S, peer: &str, text: &str) -> anyhow::Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    store.put(&key(peer), &wire::encode(&text.to_string()))?;
    Ok(())
}

/// The saved draft for `peer`, if any.
pub fn get<S>(store: &S, peer: &str) -> anyhow::Result<Option<String>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    crate::load_state(store.get(&key(peer))?, "draft")
}

/// Clear `peer`'s draft.
pub fn clear<S>(store: &mut S, peer: &str) -> anyhow::Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    store.delete(&key(peer))?;
    Ok(())
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
        set(&mut store, "bob", "wip message").unwrap();
        assert_eq!(get(&store, "bob").unwrap().as_deref(), Some("wip message"));
        clear(&mut store, "bob").unwrap();
        assert_eq!(get(&store, "bob").unwrap(), None);
    }
}
