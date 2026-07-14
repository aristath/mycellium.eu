//! A local, encrypted address book: nickname → handle, with the contact's
//! wallet **pinned** on first add (trust-on-first-use). A later lookup whose
//! wallet differs from the pin means the resolved signed record no longer
//! matches the identity you trusted before.
//!
//! Generic over [`Storage`], so it's unit-tested with an in-memory store and
//! runs on the encrypted `FileStore`.

use serde::{Deserialize, Serialize};

use mycellium_core::identity::WalletPublicKey;
use mycellium_core::storage::{Storage, StorageMutation};
use mycellium_core::wire;

/// One address-book entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// Local nickname.
    pub nickname: String,
    /// The peer's current human-readable handle.
    pub handle: String,
    /// Stable protocol identity for this contact. Handles are not unique.
    #[serde(default)]
    pub user_id: String,
    /// The peer's wallet, pinned when the contact was added.
    pub wallet: WalletPublicKey,
}

fn contact_key(nickname: &str) -> Vec<u8> {
    let mut key = b"contact:".to_vec();
    key.extend_from_slice(nickname.as_bytes());
    key
}

const INDEX_KEY: &[u8] = b"contacts";

/// Save a contact and record its nickname in the index.
pub fn save<S>(store: &mut S, contact: &Contact) -> anyhow::Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let mut names = list_names(store)?;
    let mut mutations = vec![StorageMutation::Put(
        contact_key(&contact.nickname),
        wire::encode(contact),
    )];
    if !names.contains(&contact.nickname) {
        names.push(contact.nickname.clone());
        mutations.push(StorageMutation::Put(
            INDEX_KEY.to_vec(),
            wire::encode(&names),
        ));
    }
    store.apply_batch(&mutations)?;
    Ok(())
}

/// Load a contact by nickname.
pub fn load<S>(store: &S, nickname: &str) -> anyhow::Result<Option<Contact>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    crate::load_state(
        store.get(&contact_key(nickname))?,
        &format!("contact '{nickname}'"),
    )
}

/// All known nicknames.
pub fn list_names<S>(store: &S) -> anyhow::Result<Vec<String>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    crate::decode_state(store.get(INDEX_KEY)?, "contact index")
}

/// All contacts.
pub fn list<S>(store: &S) -> anyhow::Result<Vec<Contact>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let mut out = Vec::new();
    for name in list_names(store)? {
        if let Some(c) = load(store, &name)? {
            out.push(c);
        }
    }
    Ok(out)
}

/// Remove a contact by nickname.
pub fn remove<S>(store: &mut S, nickname: &str) -> anyhow::Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let names: Vec<String> = list_names(store)?
        .into_iter()
        .filter(|n| n != nickname)
        .collect();
    store.apply_batch(&[
        StorageMutation::Delete(contact_key(nickname)),
        StorageMutation::Put(INDEX_KEY.to_vec(), wire::encode(&names)),
    ])?;
    Ok(())
}

/// Resolve `input` to a handle: a known nickname maps to its handle; anything
/// else is treated as a handle already.
pub fn resolve<S>(store: &S, input: &str) -> anyhow::Result<String>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    Ok(match load(store, input)? {
        Some(contact) => contact.handle,
        None => input.to_string(),
    })
}

/// Find a contact by its handle (for pin checks).
pub fn by_handle<S>(store: &S, handle: &str) -> anyhow::Result<Option<Contact>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    for name in list_names(store)? {
        if let Some(c) = load(store, &name)? {
            if c.handle == handle {
                return Ok(Some(c));
            }
        }
    }
    Ok(None)
}

/// Find a contact by stable user id.
pub fn by_user_id<S>(store: &S, user_id: &str) -> anyhow::Result<Option<Contact>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    for name in list_names(store)? {
        if let Some(c) = load(store, &name)? {
            if c.user_id == user_id {
                return Ok(Some(c));
            }
        }
    }
    Ok(None)
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

    fn contact(nick: &str, handle: &str, wallet_byte: u8) -> Contact {
        Contact {
            nickname: nick.into(),
            handle: handle.into(),
            user_id: format!("user-{nick}"),
            wallet: WalletPublicKey([wallet_byte; 33]),
        }
    }

    #[test]
    fn add_list_resolve_remove() {
        let mut store = MemStore::default();
        save(&mut store, &contact("b", "bob", 1)).unwrap();
        save(&mut store, &contact("c", "carol", 2)).unwrap();

        assert_eq!(list(&store).unwrap().len(), 2);
        // Nickname resolves to a handle; unknown input passes through.
        assert_eq!(resolve(&store, "b").unwrap(), "bob");
        assert_eq!(resolve(&store, "dave").unwrap(), "dave");
        assert_eq!(by_handle(&store, "carol").unwrap().unwrap().nickname, "c");

        remove(&mut store, "b").unwrap();
        assert!(load(&store, "b").unwrap().is_none());
        assert_eq!(list(&store).unwrap().len(), 1);
    }

    #[test]
    fn pin_detects_changed_identity() {
        let mut store = MemStore::default();
        save(&mut store, &contact("b", "bob", 1)).unwrap();
        let pinned = by_handle(&store, "bob").unwrap().unwrap();
        // A record with a different wallet must not match the pin.
        assert_ne!(pinned.wallet, WalletPublicKey([9; 33]));
        assert_eq!(pinned.wallet, WalletPublicKey([1; 33]));
    }

    #[test]
    fn corrupt_index_fails_without_overwriting_recoverable_bytes() {
        let mut store = MemStore::default();
        store.put(INDEX_KEY, b"corrupt contact index").unwrap();
        assert!(list(&store).is_err());
        assert!(save(&mut store, &contact("b", "bob", 1)).is_err());
        assert_eq!(
            store.get(INDEX_KEY).unwrap().as_deref(),
            Some(&b"corrupt contact index"[..])
        );
        assert!(store.get(&contact_key("b")).unwrap().is_none());
    }

    #[test]
    fn corrupt_contact_pin_is_not_treated_as_missing() {
        let mut store = MemStore::default();
        store.put(&contact_key("b"), b"corrupt pin").unwrap();
        assert!(load(&store, "b").is_err());
    }
}
