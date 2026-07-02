//! CLI-side group state: what a mailbox item can be, the invite payload, and
//! persistence of a member's group state (generic over [`Storage`], so it's
//! unit-tested with an in-memory store and runs on the encrypted `FileStore`).

use serde::{Deserialize, Serialize};

use mycellium_core::group::{GroupMessage, GroupState, SenderKeyDistribution};
use mycellium_core::offline::Envelope;
use mycellium_core::storage::Storage;
use mycellium_core::wire;

/// Anything that can sit in a mailbox. Direct messages and group invites travel
/// inside a pairwise end-to-end [`Envelope`]; group text is already end-to-end
/// under the sender key, so it rides on its own.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MailItem {
    /// A one-to-one offline message.
    Direct(Envelope),
    /// A group invite / sender-key share (its envelope decrypts to a
    /// [`GroupInvitePayload`]).
    GroupInvite(Envelope),
    /// A group message, routed by group id.
    GroupText {
        /// The group this message belongs to.
        group_id: String,
        /// The sender-key-encrypted message.
        message: GroupMessage,
    },
    /// A control message: a member was removed — drop their key and re-key.
    GroupRemove {
        /// The group this applies to.
        group_id: String,
        /// The handle that was removed.
        member: String,
    },
}

/// The end-to-end payload of a group invite: everything a member needs to join
/// and to decrypt the sender's messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupInvitePayload {
    /// Stable group identifier.
    pub group_id: String,
    /// Human-readable group name.
    pub name: String,
    /// All member handles (including the sender and the recipient).
    pub members: Vec<String>,
    /// The sender's sender-key distribution.
    pub distribution: SenderKeyDistribution,
}

/// A member's persisted view of one group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredGroup {
    /// Stable group identifier.
    pub id: String,
    /// Human-readable group name.
    pub name: String,
    /// All member handles.
    pub members: Vec<String>,
    /// This device's own handle in the group.
    pub me: String,
    /// The serialized core group session (secret — stored encrypted).
    pub state: GroupState,
}

fn group_key(id: &str) -> Vec<u8> {
    let mut key = b"group:".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

const INDEX_KEY: &[u8] = b"groups";

/// Save a group and record its id in the index.
pub fn save<S: Storage>(store: &mut S, group: &StoredGroup) -> Result<(), S::Error> {
    store.put(&group_key(&group.id), &wire::encode(group))?;
    let mut ids = list(store)?;
    if !ids.contains(&group.id) {
        ids.push(group.id.clone());
        store.put(INDEX_KEY, &wire::encode(&ids))?;
    }
    Ok(())
}

/// Load a group by id.
pub fn load<S: Storage>(store: &S, id: &str) -> Result<Option<StoredGroup>, S::Error> {
    Ok(store.get(&group_key(id))?.and_then(|b| wire::decode(&b).ok()))
}

/// List all known group ids.
pub fn list<S: Storage>(store: &S) -> Result<Vec<String>, S::Error> {
    Ok(store.get(INDEX_KEY)?.and_then(|b| wire::decode(&b).ok()).unwrap_or_default())
}

/// Forget a group (leaving it).
pub fn remove<S: Storage>(store: &mut S, id: &str) -> Result<(), S::Error> {
    store.delete(&group_key(id))?;
    let ids: Vec<String> = list(store)?.into_iter().filter(|g| g != id).collect();
    store.put(INDEX_KEY, &wire::encode(&ids))
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

    fn sample(id: &str) -> StoredGroup {
        // Build a real GroupState by exporting a fresh group.
        struct P(u8);
        impl mycellium_core::platform::Platform for P {
            fn fill_random(&mut self, buf: &mut [u8]) {
                for b in buf.iter_mut() {
                    *b = self.0;
                    self.0 = self.0.wrapping_add(1);
                }
            }
            fn now_unix_secs(&self) -> u64 {
                0
            }
        }
        let group = mycellium_core::group::Group::new(&mut P(1), b"me".to_vec());
        StoredGroup {
            id: id.into(),
            name: "team".into(),
            members: vec!["me".into(), "bob".into()],
            me: "me".into(),
            state: group.export(),
        }
    }

    #[test]
    fn save_load_and_index() {
        let mut store = MemStore::default();
        assert!(list(&store).unwrap().is_empty());

        save(&mut store, &sample("g1")).unwrap();
        save(&mut store, &sample("g2")).unwrap();
        // Saving g1 again must not duplicate the index entry.
        save(&mut store, &sample("g1")).unwrap();

        let mut ids = list(&store).unwrap();
        ids.sort();
        assert_eq!(ids, vec!["g1".to_string(), "g2".to_string()]);
        assert_eq!(load(&store, "g1").unwrap().unwrap().name, "team");
        assert!(load(&store, "missing").unwrap().is_none());
    }
}
