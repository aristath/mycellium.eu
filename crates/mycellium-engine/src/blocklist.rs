//! A local, encrypted block list of stable user identities whose messages we refuse.
//!
//! Generic over [`Storage`] (unit-tested with an in-memory store; runs on the
//! encrypted `FileStore`).

use mycellium_core::storage::Storage;
use mycellium_core::userid::UserId;
use mycellium_core::wire;

const KEY: &[u8] = b"blocklist";

/// Load the set of blocked stable user ids.
pub fn load<S: Storage>(store: &S) -> anyhow::Result<Vec<String>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let Some(bytes) = store.get(KEY)? else {
        return Ok(Vec::new());
    };
    let users: Vec<String> =
        wire::decode(&bytes).map_err(|_| anyhow::anyhow!("local block list is corrupt"))?;
    if users.iter().any(|user| UserId::new(user.clone()).is_err()) {
        anyhow::bail!("local block list contains an invalid user id");
    }
    Ok(users)
}

/// Block a stable user id (idempotent).
pub fn block<S: Storage>(store: &mut S, user_id: &str) -> anyhow::Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let user_id =
        UserId::new(user_id.to_string()).map_err(|_| anyhow::anyhow!("invalid user id"))?;
    let mut list = load(store)?;
    if !list.iter().any(|known| known == user_id.as_str()) {
        list.push(user_id.as_str().to_string());
        store.put(KEY, &wire::encode(&list))?;
    }
    Ok(())
}

/// Unblock a stable user id.
pub fn unblock<S: Storage>(store: &mut S, user_id: &str) -> anyhow::Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let user_id =
        UserId::new(user_id.to_string()).map_err(|_| anyhow::anyhow!("invalid user id"))?;
    let list: Vec<String> = load(store)?
        .into_iter()
        .filter(|known| known != user_id.as_str())
        .collect();
    store.put(KEY, &wire::encode(&list))?;
    Ok(())
}

/// Whether `user_id` is in the blocked set.
pub fn is_blocked(list: &[String], user_id: &str) -> bool {
    list.iter().any(|known| known == user_id)
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
        let user = "a".repeat(64);
        assert!(!is_blocked(&load(&store).unwrap(), &user));

        block(&mut store, &user).unwrap();
        block(&mut store, &user).unwrap(); // idempotent
        assert!(is_blocked(&load(&store).unwrap(), &user));
        assert_eq!(load(&store).unwrap().len(), 1);

        unblock(&mut store, &user).unwrap();
        assert!(!is_blocked(&load(&store).unwrap(), &user));
    }

    #[test]
    fn corrupt_blocklist_fails_closed_without_overwriting_it() {
        let mut store = MemStore::default();
        store.put(KEY, b"not valid wire bytes").unwrap();
        assert!(load(&store).is_err());
        assert_eq!(
            store.get(KEY).unwrap().as_deref(),
            Some(&b"not valid wire bytes"[..])
        );
    }
}
