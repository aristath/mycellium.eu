//! Per-peer chat transcripts, persisted through the [`Storage`] trait.
//!
//! Generic over `Storage`, so it's exercised in tests with an in-memory store
//! and in production with the encrypted the encrypted `FileStore`.

use serde::{Deserialize, Serialize};

use mycellium_core::storage::Storage;
use mycellium_core::wire;

/// One stored message in a transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMessage {
    /// The message id (for edit/delete targeting).
    #[serde(default)]
    pub id: String,
    /// Whether we sent it (vs. received it).
    pub from_me: bool,
    /// The plaintext.
    pub text: String,
    /// Unix seconds when it was stored.
    pub timestamp: u64,
    /// Unix time after which this message disappears, if any.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

/// One stored group message (any member may be the author).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupStoredMessage {
    /// The message id (for edit/delete targeting).
    #[serde(default)]
    pub id: String,
    /// The author's handle.
    pub sender: String,
    /// The plaintext.
    pub text: String,
    /// Unix seconds when it was stored.
    pub timestamp: u64,
    /// Unix time after which this message disappears, if any.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

/// Storage key for a peer's transcript.
fn history_key(peer: &str) -> Vec<u8> {
    let mut key = b"history/".to_vec();
    key.extend_from_slice(peer.as_bytes());
    key
}

/// Storage key for a group's transcript.
fn group_history_key(group_id: &str) -> Vec<u8> {
    let mut key = b"grouphist/".to_vec();
    key.extend_from_slice(group_id.as_bytes());
    key
}

/// Load a group's transcript.
pub fn group_load<S: Storage>(store: &S, group_id: &str) -> Result<Vec<GroupStoredMessage>, S::Error> {
    match store.get(&group_history_key(group_id))? {
        Some(bytes) => Ok(wire::decode(&bytes).unwrap_or_default()),
        None => Ok(Vec::new()),
    }
}

/// Append one message to a group's transcript.
pub fn group_append<S: Storage>(
    store: &mut S,
    group_id: &str,
    message: GroupStoredMessage,
) -> Result<(), S::Error> {
    let mut transcript = group_load(store, group_id)?;
    transcript.push(message);
    let bytes = wire::encode(&transcript);
    store.put(&group_history_key(group_id), &bytes)
}

/// Load a peer's transcript (empty if none / unreadable).
pub fn load<S: Storage>(store: &S, peer: &str) -> Result<Vec<StoredMessage>, S::Error> {
    match store.get(&history_key(peer))? {
        Some(bytes) => Ok(wire::decode(&bytes).unwrap_or_default()),
        None => Ok(Vec::new()),
    }
}

const PEER_INDEX: &[u8] = b"history:peers";

/// The set of peers we have 1:1 history with.
pub fn peers<S: Storage>(store: &S) -> Result<Vec<String>, S::Error> {
    Ok(store.get(PEER_INDEX)?.and_then(|b| wire::decode(&b).ok()).unwrap_or_default())
}

/// Append one message to a peer's transcript (and index the peer).
pub fn append<S: Storage>(store: &mut S, peer: &str, message: StoredMessage) -> Result<(), S::Error> {
    let mut transcript = load(store, peer)?;
    transcript.push(message);
    store.put(&history_key(peer), &wire::encode(&transcript))?;

    let mut names = peers(store)?;
    if !names.iter().any(|p| p == peer) {
        names.push(peer.to_string());
        store.put(PEER_INDEX, &wire::encode(&names))?;
    }
    Ok(())
}

/// Load a peer's transcript, pruning any messages expired as of `now`.
pub fn load_active<S: Storage>(store: &mut S, peer: &str, now: u64) -> Result<Vec<StoredMessage>, S::Error> {
    let all = load(store, peer)?;
    let active: Vec<StoredMessage> =
        all.iter().filter(|m| !matches!(m.expires_at, Some(at) if now >= at)).cloned().collect();
    if active.len() != all.len() {
        store.put(&history_key(peer), &wire::encode(&active))?;
    }
    Ok(active)
}

/// Clear a peer's whole transcript and drop them from the index.
pub fn clear<S: Storage>(store: &mut S, peer: &str) -> Result<(), S::Error> {
    store.delete(&history_key(peer))?;
    let names: Vec<String> = peers(store)?.into_iter().filter(|p| p != peer).collect();
    store.put(PEER_INDEX, &wire::encode(&names))
}

/// Edit a stored 1:1 message by id (marks it edited). No-op if not found.
/// Edit a stored 1:1 message by id — but only one authored by the same side as
/// the edit (`by_me`), so a peer can't rewrite *your* messages and vice versa.
pub fn edit<S: Storage>(store: &mut S, peer: &str, id: &str, new_text: &str, by_me: bool) -> Result<(), S::Error> {
    let mut transcript = load(store, peer)?;
    let mut changed = false;
    for m in &mut transcript {
        if m.id == id && m.from_me == by_me {
            m.text = format!("{new_text} (edited)");
            changed = true;
        }
    }
    if changed {
        store.put(&history_key(peer), &wire::encode(&transcript))?;
    }
    Ok(())
}

/// Delete a stored 1:1 message by id — only if authored by the same side as the
/// delete (`by_me`). No-op if not found or authored by the other side.
pub fn delete<S: Storage>(store: &mut S, peer: &str, id: &str, by_me: bool) -> Result<(), S::Error> {
    let transcript: Vec<StoredMessage> =
        load(store, peer)?.into_iter().filter(|m| !(m.id == id && m.from_me == by_me)).collect();
    store.put(&history_key(peer), &wire::encode(&transcript))
}

/// Edit a stored group message by id — only one whose recorded `sender` matches,
/// so a member can't rewrite another member's message.
pub fn group_edit<S: Storage>(store: &mut S, group_id: &str, id: &str, new_text: &str, sender: &str) -> Result<(), S::Error> {
    let mut transcript = group_load(store, group_id)?;
    for m in &mut transcript {
        if m.id == id && m.sender == sender {
            m.text = format!("{new_text} (edited)");
        }
    }
    store.put(&group_history_key(group_id), &wire::encode(&transcript))
}

/// Delete a stored group message by id — only if its recorded `sender` matches.
pub fn group_delete<S: Storage>(store: &mut S, group_id: &str, id: &str, sender: &str) -> Result<(), S::Error> {
    let transcript: Vec<GroupStoredMessage> =
        group_load(store, group_id)?.into_iter().filter(|m| !(m.id == id && m.sender == sender)).collect();
    store.put(&group_history_key(group_id), &wire::encode(&transcript))
}

/// Load a group's transcript, pruning expired messages as of `now`.
pub fn group_load_active<S: Storage>(store: &mut S, group_id: &str, now: u64) -> Result<Vec<GroupStoredMessage>, S::Error> {
    let all = group_load(store, group_id)?;
    let active: Vec<GroupStoredMessage> =
        all.iter().filter(|m| !matches!(m.expires_at, Some(at) if now >= at)).cloned().collect();
    if active.len() != all.len() {
        store.put(&group_history_key(group_id), &wire::encode(&active))?;
    }
    Ok(active)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::convert::Infallible;

    /// An in-memory Storage for tests.
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

    fn msg(from_me: bool, text: &str) -> StoredMessage {
        StoredMessage { id: String::new(), from_me, text: text.into(), timestamp: 0, expires_at: None }
    }

    #[test]
    fn appends_and_loads_in_order() {
        let mut store = MemStore::default();
        assert!(load(&store, "bob").unwrap().is_empty());

        append(&mut store, "bob", msg(true, "hi")).unwrap();
        append(&mut store, "bob", msg(false, "hey")).unwrap();
        append(&mut store, "bob", msg(true, "how are you")).unwrap();

        let transcript = load(&store, "bob").unwrap();
        assert_eq!(transcript.len(), 3);
        assert_eq!(transcript[0], msg(true, "hi"));
        assert_eq!(transcript[1], msg(false, "hey"));
        assert_eq!(transcript[2].text, "how are you");
    }

    #[test]
    fn expired_messages_are_pruned_on_load() {
        let mut store = MemStore::default();
        append(&mut store, "bob", StoredMessage { id: String::new(), from_me: true, text: "keep".into(), timestamp: 0, expires_at: None }).unwrap();
        append(&mut store, "bob", StoredMessage { id: String::new(), from_me: true, text: "gone".into(), timestamp: 0, expires_at: Some(100) }).unwrap();

        // Before expiry: both present.
        assert_eq!(load_active(&mut store, "bob", 50).unwrap().len(), 2);
        // After expiry: the expiring one is pruned, and stays pruned.
        let active = load_active(&mut store, "bob", 100).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].text, "keep");
        assert_eq!(load(&store, "bob").unwrap().len(), 1);
    }

    #[test]
    fn edit_and_delete_by_id() {
        let mut store = MemStore::default();
        let m = |id: &str, text: &str| StoredMessage {
            id: id.into(),
            from_me: false,
            text: text.into(),
            timestamp: 0,
            expires_at: None,
        };
        append(&mut store, "bob", m("m1", "helo")).unwrap();
        append(&mut store, "bob", m("m2", "keep me")).unwrap();

        // The peer authored these (from_me: false), so a peer edit/delete applies.
        edit(&mut store, "bob", "m1", "hello", false).unwrap();
        assert_eq!(load(&store, "bob").unwrap()[0].text, "hello (edited)");

        delete(&mut store, "bob", "m1", false).unwrap();
        let left = load(&store, "bob").unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, "m2");
    }

    #[test]
    fn edit_delete_are_author_scoped() {
        let mut store = MemStore::default();
        // A message the peer authored (from_me: false).
        append(&mut store, "bob", StoredMessage { id: "m1".into(), from_me: false, text: "theirs".into(), timestamp: 0, expires_at: None }).unwrap();

        // A "mine"-scoped edit/delete (by_me: true) must NOT touch the peer's message.
        edit(&mut store, "bob", "m1", "hacked", true).unwrap();
        assert_eq!(load(&store, "bob").unwrap()[0].text, "theirs", "a peer can't edit as if it were mine");
        delete(&mut store, "bob", "m1", true).unwrap();
        assert_eq!(load(&store, "bob").unwrap().len(), 1, "a peer can't delete my-scoped");

        // The correctly-scoped delete (by_me: false) does remove it.
        delete(&mut store, "bob", "m1", false).unwrap();
        assert!(load(&store, "bob").unwrap().is_empty());
    }

    #[test]
    fn group_edit_delete_are_sender_scoped() {
        let mut store = MemStore::default();
        let gm = |id: &str, sender: &str, text: &str| GroupStoredMessage { id: id.into(), sender: sender.into(), text: text.into(), timestamp: 0, expires_at: None };
        group_append(&mut store, "g1", gm("m1", "alice", "alice's")).unwrap();

        // Bob can't edit or delete Alice's message.
        group_edit(&mut store, "g1", "m1", "hacked", "bob").unwrap();
        assert_eq!(group_load(&store, "g1").unwrap()[0].text, "alice's", "another member can't rewrite it");
        group_delete(&mut store, "g1", "m1", "bob").unwrap();
        assert_eq!(group_load(&store, "g1").unwrap().len(), 1, "another member can't delete it");

        // Alice (the author) can.
        group_delete(&mut store, "g1", "m1", "alice").unwrap();
        assert!(group_load(&store, "g1").unwrap().is_empty());
    }

    #[test]
    fn transcripts_are_per_peer() {
        let mut store = MemStore::default();
        append(&mut store, "bob", msg(true, "to bob")).unwrap();
        append(&mut store, "carol", msg(true, "to carol")).unwrap();

        assert_eq!(load(&store, "bob").unwrap().len(), 1);
        assert_eq!(load(&store, "carol").unwrap()[0].text, "to carol");

        // Both peers are indexed for enumeration (search).
        let mut names = peers(&store).unwrap();
        names.sort();
        assert_eq!(names, vec!["bob".to_string(), "carol".to_string()]);
    }

    #[test]
    fn group_transcript_records_senders() {
        let mut store = MemStore::default();
        let gm = |sender: &str, text: &str| GroupStoredMessage {
            id: String::new(),
            sender: sender.into(),
            text: text.into(),
            timestamp: 0,
            expires_at: None,
        };
        group_append(&mut store, "g1", gm("alice", "hi all")).unwrap();
        group_append(&mut store, "g1", gm("bob", "hey")).unwrap();

        let t = group_load(&store, "g1").unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].sender, "alice");
        assert_eq!(t[1].text, "hey");
        assert!(group_load(&store, "other").unwrap().is_empty());
    }
}
