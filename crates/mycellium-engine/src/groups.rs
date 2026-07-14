//! Group state: what a sealed peer item can be, the invite payload, and
//! persistence of a member's group state.

use serde::{Deserialize, Serialize};

use mycellium_core::delivery::DeliveryAck;
use mycellium_core::group::{GroupMessage, GroupState, SenderKeyDistribution};
use mycellium_core::offline::Envelope;
use mycellium_core::record::SignedRecord;
use mycellium_core::storage::{Storage, StorageMutation};
use mycellium_core::wire;

/// Anything that can be handed directly to a peer device. Direct messages and
/// group invites travel inside a pairwise end-to-end [`Envelope`]; group text is
/// already end-to-end under the sender key, so it rides on its own.
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
    /// A member is **leaving** the group (self-removal). Sealed device→device so
    /// the sender is cryptographically authenticated: a member can only announce
    /// *their own* departure. There is deliberately no "remove someone else"
    /// control — you block a peer locally, or leave yourself. Decrypts to a
    /// [`GroupLeavePayload`].
    GroupLeave(Envelope),
}

/// One versioned application frame carried over a direct connection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PeerFrame {
    /// A sender-owned delivery that remains pending until its ACK verifies.
    Delivery {
        delivery_id: String,
        item: Box<MailItem>,
    },
    /// Recipient-device proof of durable acceptance.
    Ack(DeliveryAck),
    /// Ask a directly reachable peer for signed peer records. Discovery is
    /// record-only: no messages, custody, or authority.
    DiscoveryRequest { want: Vec<String> },
    /// A non-authoritative signed peer-record pack.
    DiscoveryResponse { records: Vec<DiscoveryRecord> },
}

/// One signed peer record carried by discovery gossip.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryRecord {
    pub user_id: String,
    pub handle: String,
    pub record: SignedRecord,
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
    /// All stable members (including the sender and the recipient).
    pub members: Vec<GroupMember>,
    /// The sender's device-unique group id, used as the map key.
    #[serde(default)]
    pub sender_id: Vec<u8>,
    /// The sender's sender-key distribution.
    pub distribution: SenderKeyDistribution,
}

/// One group member. The user id is authoritative; the handle is display-only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    /// Stable protocol identity.
    pub user_id: String,
    /// Last authenticated human-readable handle.
    pub handle: String,
}

/// The authenticated identity behind one group sender-key device id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSender {
    /// Device id used by the group sender-key protocol.
    pub sender_id: Vec<u8>,
    /// Stable protocol identity.
    pub user_id: String,
    /// Last authenticated human-readable handle.
    pub handle: String,
}

/// The active device that has received this device's current sender key.
///
/// Only the public signing key is retained as the sender-key generation marker;
/// the secret chain key remains exclusively inside [`GroupState`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupKeyShare {
    /// Stable recipient identity.
    pub user_id: String,
    /// Recipient device key encoded as a stable slot identifier.
    pub device_slot: String,
    /// Public signing key of the sender-key generation that was shared.
    pub signing_public: [u8; 32],
}

/// A member's persisted view of one group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredGroup {
    /// Stable group identifier.
    pub id: String,
    /// Human-readable group name.
    pub name: String,
    /// All members keyed by stable user identity.
    pub members: Vec<GroupMember>,
    /// Authenticated device-id to user-id/display-handle mappings.
    pub senders: Vec<GroupSender>,
    /// Recipient devices that have this device's current sender key.
    #[serde(default)]
    pub key_shares: Vec<GroupKeyShare>,
    /// The serialized core group session (secret — stored encrypted).
    pub state: GroupState,
}

impl StoredGroup {
    /// Record or update the authenticated identity behind a sender device id.
    pub fn note_sender(&mut self, sender_id: Vec<u8>, user_id: &str, handle: &str) {
        if let Some(entry) = self
            .senders
            .iter_mut()
            .find(|entry| entry.sender_id == sender_id)
        {
            entry.user_id = user_id.to_string();
            entry.handle = handle.to_string();
        } else {
            self.senders.push(GroupSender {
                sender_id,
                user_id: user_id.to_string(),
                handle: handle.to_string(),
            });
        }
    }

    /// The stable identity behind a sender device id, if known.
    pub fn sender_of(&self, sender_id: &[u8]) -> Option<&GroupSender> {
        self.senders
            .iter()
            .find(|entry| entry.sender_id == sender_id)
    }

    /// Whether this exact active device has our current sender key.
    pub fn key_shared_with(
        &self,
        user_id: &str,
        device_slot: &str,
        signing_public: &[u8; 32],
    ) -> bool {
        self.key_shares.iter().any(|share| {
            share.user_id == user_id
                && share.device_slot == device_slot
                && &share.signing_public == signing_public
        })
    }

    /// Record the one active recipient device that has our sender key.
    pub fn note_key_share(&mut self, share: GroupKeyShare) {
        self.key_shares
            .retain(|known| known.user_id != share.user_id);
        self.key_shares.push(share);
    }
}

fn group_key(id: &str) -> Vec<u8> {
    let mut key = b"group:".to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

const INDEX_KEY: &[u8] = b"groups";

/// Save a group and record its id in the index.
pub fn save<S>(store: &mut S, group: &StoredGroup) -> anyhow::Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let mut ids = list(store)?;
    let mut mutations = vec![StorageMutation::Put(
        group_key(&group.id),
        wire::encode(group),
    )];
    if !ids.contains(&group.id) {
        ids.push(group.id.clone());
        mutations.push(StorageMutation::Put(INDEX_KEY.to_vec(), wire::encode(&ids)));
    }
    store.apply_batch(&mutations)?;
    Ok(())
}

/// Load a group by id.
pub fn load<S>(store: &S, id: &str) -> anyhow::Result<Option<StoredGroup>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    crate::load_state(store.get(&group_key(id))?, &format!("group '{id}'"))
}

/// List all known group ids.
pub fn list<S>(store: &S) -> anyhow::Result<Vec<String>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    crate::decode_state(store.get(INDEX_KEY)?, "group index")
}

/// Forget a group (leaving it).
pub fn remove<S>(store: &mut S, id: &str) -> anyhow::Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let ids: Vec<String> = list(store)?.into_iter().filter(|g| g != id).collect();
    store.apply_batch(&[
        StorageMutation::Delete(group_key(id)),
        StorageMutation::Put(INDEX_KEY.to_vec(), wire::encode(&ids)),
    ])?;
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
            members: vec![
                GroupMember {
                    user_id: "a".repeat(64),
                    handle: "me".into(),
                },
                GroupMember {
                    user_id: "b".repeat(64),
                    handle: "bob".into(),
                },
            ],
            senders: Vec::new(),
            key_shares: Vec::new(),
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

    #[test]
    fn corrupt_group_index_blocks_mutation_and_preserves_bytes() {
        let mut store = MemStore::default();
        store.put(INDEX_KEY, b"corrupt group index").unwrap();
        assert!(list(&store).is_err());
        assert!(save(&mut store, &sample("g1")).is_err());
        assert_eq!(
            store.get(INDEX_KEY).unwrap().as_deref(),
            Some(&b"corrupt group index"[..])
        );
        assert!(store.get(&group_key("g1")).unwrap().is_none());
    }
}
