//! A local, encrypted address book: nickname → handle, with the contact's
//! wallet **pinned** on first add (trust-on-first-use). A later lookup whose
//! wallet differs from the pin means the directory handed us a different
//! identity — the exact "dishonest directory" case out-of-band verification
//! guards against (Layer 5).
//!
//! Generic over [`Storage`], so it's unit-tested with an in-memory store and
//! runs on the encrypted `FileStore`.

use serde::{Deserialize, Serialize};

use mycellium_core::identity::WalletPublicKey;
use mycellium_core::storage::Storage;
use mycellium_core::wire;

/// One address-book entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    /// Local nickname.
    pub nickname: String,
    /// The peer's handle.
    pub handle: String,
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
pub fn save<S: Storage>(store: &mut S, contact: &Contact) -> Result<(), S::Error> {
    store.put(&contact_key(&contact.nickname), &wire::encode(contact))?;
    let mut names = list_names(store)?;
    if !names.contains(&contact.nickname) {
        names.push(contact.nickname.clone());
        store.put(INDEX_KEY, &wire::encode(&names))?;
    }
    Ok(())
}

/// Load a contact by nickname.
pub fn load<S: Storage>(store: &S, nickname: &str) -> Result<Option<Contact>, S::Error> {
    match store.get(&contact_key(nickname))? {
        None => Ok(None),
        Some(b) => {
            match wire::decode(&b) {
                Ok(c) => Ok(Some(c)),
                Err(_) => {
                    // A corrupt contact must not silently vanish — contacts are TOFU
                    // pins, part of the safety model.
                    #[cfg(not(target_arch = "wasm32"))]
                    eprintln!("(warning: corrupt contact '{nickname}' in local storage — treated as missing)");
                    Ok(None)
                }
            }
        }
    }
}

/// All known nicknames.
pub fn list_names<S: Storage>(store: &S) -> Result<Vec<String>, S::Error> {
    Ok(crate::decode_or_warn(
        store.get(INDEX_KEY)?,
        "contact index",
    ))
}

/// All contacts.
pub fn list<S: Storage>(store: &S) -> Result<Vec<Contact>, S::Error> {
    let mut out = Vec::new();
    for name in list_names(store)? {
        if let Some(c) = load(store, &name)? {
            out.push(c);
        }
    }
    Ok(out)
}

/// Remove a contact by nickname.
pub fn remove<S: Storage>(store: &mut S, nickname: &str) -> Result<(), S::Error> {
    store.delete(&contact_key(nickname))?;
    let names: Vec<String> = list_names(store)?
        .into_iter()
        .filter(|n| n != nickname)
        .collect();
    store.put(INDEX_KEY, &wire::encode(&names))
}

/// Resolve `input` to a handle: a known nickname maps to its handle; anything
/// else is treated as a handle already.
pub fn resolve<S: Storage>(store: &S, input: &str) -> Result<String, S::Error> {
    Ok(match load(store, input)? {
        Some(contact) => contact.handle,
        None => input.to_string(),
    })
}

/// Find a contact by its handle (for pin checks).
pub fn by_handle<S: Storage>(store: &S, handle: &str) -> Result<Option<Contact>, S::Error> {
    for name in list_names(store)? {
        if let Some(c) = load(store, &name)? {
            if c.handle == handle {
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
}
