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
    /// A mirror of a message *you* sent, for your own other devices (Layer 11).
    /// The envelope (sealed device→device) carries the message; `peer` is the
    /// conversation it belongs to.
    SelfSync {
        /// The handle the original message was sent to.
        peer: String,
        /// The message, sealed from the sending device to this one.
        envelope: Envelope,
    },
    /// Bootstrap a sibling device into an existing group (Layer 11): the envelope
    /// (sealed device→device) decrypts to a [`GroupSyncPayload`] of every sender
    /// key this cluster holds — enough for the new device to *receive*.
    GroupSync(Envelope),
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
    /// A member is **leaving** the group (self-removal). Sealed device→device so
    /// the sender is cryptographically authenticated: a member can only announce
    /// *their own* departure. There is deliberately no "remove someone else"
    /// control — you block a peer locally, or leave yourself. Decrypts to a
    /// [`GroupLeavePayload`].
    GroupLeave(Envelope),
}

/// The end-to-end payload of a [`MailItem::GroupLeave`]: which group the
/// (authenticated) sender is leaving. The *who* is the envelope's sender, not a
/// field here — so it can't name anyone but themselves.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupLeavePayload {
    /// The group the sender is leaving.
    pub group_id: String,
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
    /// The sender's device-unique group id (Layer 11), used as the map key.
    #[serde(default)]
    pub sender_id: Vec<u8>,
    /// The sender's sender-key distribution.
    pub distribution: SenderKeyDistribution,
}

/// Handed to a sibling device to bootstrap it into an existing group (Layer 11):
/// the roster plus every sender key the cluster already holds, so the new device
/// can decrypt current members' messages. Receive-only (no private signing key).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupSyncPayload {
    /// Stable group identifier.
    pub group_id: String,
    /// Human-readable group name.
    pub name: String,
    /// All member handles.
    pub members: Vec<String>,
    /// Every sender key the cluster holds: `(sender id, distribution)`.
    pub keys: Vec<(Vec<u8>, SenderKeyDistribution)>,
    /// Each sender's device id → handle, for display on the new device.
    pub sender_handles: Vec<(Vec<u8>, String)>,
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
    /// Each sender's device id → their handle, for display and block checks
    /// (Layer 11: senders are keyed by *device*, so two devices of one handle
    /// don't collide).
    #[serde(default)]
    pub sender_handles: Vec<(Vec<u8>, String)>,
    /// The serialized core group session (secret — stored encrypted).
    pub state: GroupState,
}

impl StoredGroup {
    /// Record (or update) the handle behind a sender's device id.
    pub fn note_sender(&mut self, sender_id: Vec<u8>, handle: &str) {
        if let Some(entry) = self
            .sender_handles
            .iter_mut()
            .find(|(id, _)| *id == sender_id)
        {
            entry.1 = handle.to_string();
        } else {
            self.sender_handles.push((sender_id, handle.to_string()));
        }
    }

    /// The handle behind a sender's device id, if known.
    pub fn handle_of(&self, sender_id: &[u8]) -> Option<&str> {
        self.sender_handles
            .iter()
            .find(|(id, _)| id == sender_id)
            .map(|(_, h)| h.as_str())
    }
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
    match store.get(&group_key(id))? {
        None => Ok(None),
        Some(b) => match wire::decode(&b) {
            Ok(g) => Ok(Some(g)),
            Err(_) => {
                #[cfg(not(target_arch = "wasm32"))]
                eprintln!("(warning: corrupt group '{id}' in local storage — treated as missing)");
                Ok(None)
            }
        },
    }
}

/// List all known group ids.
pub fn list<S: Storage>(store: &S) -> Result<Vec<String>, S::Error> {
    Ok(crate::decode_or_warn(store.get(INDEX_KEY)?, "group index"))
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
            sender_handles: Vec::new(),
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
