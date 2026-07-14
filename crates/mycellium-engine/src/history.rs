//! Per-user chat transcripts, persisted through the [`Storage`] trait.
//!
//! Generic over `Storage`, so it's exercised in tests with an in-memory store
//! and in production with the encrypted `FileStore`.

use serde::{Deserialize, Serialize};

use mycellium_core::storage::{Storage, StorageMutation};
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

// Segmented on-disk layout
// -------------------------
// A thread is not one giant blob; it's a run of fixed-size *segments*, each a
// `wire`-encoded `Vec<_>` of up to [`SEGMENT`] messages, plus a tiny meta key
// recording how many segments exist. This makes `append` touch only the tail
// segment (O(SEGMENT)) instead of decoding+re-encrypting the whole thread
// (which was O(n) per message, O(n²) over a conversation).
//
// Keys, per thread `id`:
//   - meta:    `{prefix}{id}:meta`               → [`SegMeta`] (segment count)
//   - segment: `{prefix}{id}:{index:012}`        → `Vec<_>` (≤ SEGMENT msgs)
//
// The zero-padded, fixed-width index keeps keys lexically ordered, and the meta
// count lets us iterate `0..count` by exact key — no prefix/range scan needed
// from the bare get/put/delete [`Storage`] KV.

/// Max messages per segment. Tuned so a tail rewrite stays cheap while segments
/// aren't so tiny that a long thread accrues a huge number of keys.
const SEGMENT: usize = 128;

/// 1:1 transcript key prefix.
const HIST: &[u8] = b"hist:";
/// Group transcript key prefix.
const GHIST: &[u8] = b"ghist:";

/// Per-thread metadata: how many segments the thread currently has.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
struct SegMeta {
    /// Number of segments (`0..segments` are valid keys).
    segments: u32,
}

/// Storage key for a thread's segment `index`.
fn seg_key(prefix: &[u8], id: &str, index: u32) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(id.as_bytes());
    key.push(b':');
    key.extend_from_slice(format!("{index:012}").as_bytes());
    key
}

/// Storage key for a thread's segment-count meta.
fn meta_key(prefix: &[u8], id: &str) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(id.as_bytes());
    key.extend_from_slice(b":meta");
    key
}

/// Read a thread's segment count (0 if the thread doesn't exist yet).
fn seg_count<S>(store: &S, prefix: &[u8], id: &str) -> anyhow::Result<u32>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let meta: SegMeta = crate::decode_state(store.get(&meta_key(prefix, id))?, "history meta")?;
    Ok(meta.segments)
}

/// Read every segment of a thread in order and concatenate them.
fn load_segments<S, T>(store: &S, prefix: &[u8], id: &str, label: &str) -> anyhow::Result<Vec<T>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
    T: serde::de::DeserializeOwned,
{
    let count = seg_count(store, prefix, id)?;
    let mut all = Vec::new();
    for i in 0..count {
        let seg: Vec<T> = crate::decode_state(store.get(&seg_key(prefix, id, i))?, label)?;
        all.extend(seg);
    }
    Ok(all)
}

/// Append `message` to a thread's tail segment (starting a fresh segment when
/// the tail is full). Touches at most the tail segment (+ meta) — O(SEGMENT),
/// independent of the thread's total length.
fn append_segment_mutations<S, T>(
    store: &S,
    prefix: &[u8],
    id: &str,
    message: T,
    label: &str,
) -> anyhow::Result<Vec<StorageMutation>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
    T: Serialize + serde::de::DeserializeOwned,
{
    let count = seg_count(store, prefix, id)?;
    // Which segment does the new message land in?
    let (target, new_count) = if count == 0 {
        (0, 1)
    } else {
        let tail_idx = count - 1;
        let tail: Vec<T> = crate::decode_state(store.get(&seg_key(prefix, id, tail_idx))?, label)?;
        if tail.len() >= SEGMENT {
            (count, count + 1) // tail full: start a new segment
        } else {
            (tail_idx, count) // append to the existing tail
        }
    };

    // Load just the target segment (empty for a fresh one), push, save.
    let mut seg: Vec<T> = if target < count {
        crate::decode_state(store.get(&seg_key(prefix, id, target))?, label)?
    } else {
        Vec::new()
    };
    seg.push(message);
    let mut mutations = vec![StorageMutation::Put(
        seg_key(prefix, id, target),
        wire::encode(&seg),
    )];
    if new_count != count {
        mutations.push(StorageMutation::Put(
            meta_key(prefix, id),
            wire::encode(&SegMeta {
                segments: new_count,
            }),
        ));
    }
    Ok(mutations)
}

/// Read a thread pruning expired messages, rewriting *only* the segment(s) a
/// pruned message was in (segments with no expiry are left untouched).
fn load_active_segments<S, T, F>(
    store: &mut S,
    prefix: &[u8],
    id: &str,
    label: &str,
    expired: F,
) -> anyhow::Result<Vec<T>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
    T: Serialize + serde::de::DeserializeOwned + Clone,
    F: Fn(&T) -> bool,
{
    let count = seg_count(store, prefix, id)?;
    let mut all = Vec::new();
    for i in 0..count {
        let seg: Vec<T> = crate::decode_state(store.get(&seg_key(prefix, id, i))?, label)?;
        let active: Vec<T> = seg.iter().filter(|m| !expired(m)).cloned().collect();
        if active.len() != seg.len() {
            // Only this segment lost a message → rewrite only this segment.
            store.put(&seg_key(prefix, id, i), &wire::encode(&active))?;
        }
        all.extend(active);
    }
    Ok(all)
}

/// Delete every message matching `remove` from a thread, rewriting only the
/// segment(s) that actually changed.
fn delete_segments<S, T, F>(
    store: &mut S,
    prefix: &[u8],
    id: &str,
    label: &str,
    remove: F,
) -> anyhow::Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
    T: Serialize + serde::de::DeserializeOwned + Clone,
    F: Fn(&T) -> bool,
{
    let count = seg_count(store, prefix, id)?;
    for i in 0..count {
        let seg: Vec<T> = crate::decode_state(store.get(&seg_key(prefix, id, i))?, label)?;
        let kept: Vec<T> = seg.iter().filter(|m| !remove(m)).cloned().collect();
        if kept.len() != seg.len() {
            store.put(&seg_key(prefix, id, i), &wire::encode(&kept))?;
        }
    }
    Ok(())
}

/// Load a group's transcript.
pub fn group_load<S>(store: &S, group_id: &str) -> anyhow::Result<Vec<GroupStoredMessage>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    load_segments(store, GHIST, group_id, "group transcript")
}

/// Append one message to a group's transcript.
pub fn group_append<S>(
    store: &mut S,
    group_id: &str,
    message: GroupStoredMessage,
) -> anyhow::Result<bool>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    if !message.id.is_empty()
        && group_load(store, group_id)?
            .iter()
            .any(|known| known.id == message.id)
    {
        return Ok(false);
    }
    let mutations = append_segment_mutations(store, GHIST, group_id, message, "group transcript")?;
    store.apply_batch(&mutations)?;
    Ok(true)
}

/// Load a stable user ID's transcript (empty if none / unreadable).
pub fn load<S>(store: &S, user_id: &str) -> anyhow::Result<Vec<StoredMessage>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    load_segments(store, HIST, user_id, "1:1 transcript")
}

const PEER_INDEX: &[u8] = b"history:peers";

/// The stable user IDs we have 1:1 history with.
pub fn peers<S>(store: &S) -> anyhow::Result<Vec<String>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    crate::decode_state(store.get(PEER_INDEX)?, "peer index")
}

/// Append one message to a user's transcript (and index the user ID).
pub fn append<S>(store: &mut S, peer: &str, message: StoredMessage) -> anyhow::Result<bool>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let inserted = message.id.is_empty()
        || !load(store, peer)?
            .iter()
            .any(|known| known.id == message.id);
    let mut names = peers(store)?;
    let mut mutations = if inserted {
        append_segment_mutations(store, HIST, peer, message, "1:1 transcript")?
    } else {
        Vec::new()
    };
    if !names.iter().any(|p| p == peer) {
        names.push(peer.to_string());
        mutations.push(StorageMutation::Put(
            PEER_INDEX.to_vec(),
            wire::encode(&names),
        ));
    }
    store.apply_batch(&mutations)?;
    Ok(inserted)
}

/// Load a peer's transcript, pruning any messages expired as of `now`.
pub fn load_active<S>(store: &mut S, peer: &str, now: u64) -> anyhow::Result<Vec<StoredMessage>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    load_active_segments(
        store,
        HIST,
        peer,
        "1:1 transcript",
        |m: &StoredMessage| matches!(m.expires_at, Some(at) if now >= at),
    )
}

/// Clear a peer's whole transcript and drop them from the index.
pub fn clear<S>(store: &mut S, peer: &str) -> anyhow::Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let count = seg_count(store, HIST, peer)?;
    let names: Vec<String> = peers(store)?.into_iter().filter(|p| p != peer).collect();
    let mut mutations = Vec::with_capacity(count as usize + 2);
    for i in 0..count {
        mutations.push(StorageMutation::Delete(seg_key(HIST, peer, i)));
    }
    mutations.push(StorageMutation::Delete(meta_key(HIST, peer)));
    mutations.push(StorageMutation::Put(
        PEER_INDEX.to_vec(),
        wire::encode(&names),
    ));
    store.apply_batch(&mutations)?;
    Ok(())
}

/// Edit a stored 1:1 message by id — but only one authored by the same side as
/// the edit (`by_me`), so a peer can't rewrite *your* messages and vice versa.
/// No-op if not found. Rewrites only the segment holding the message.
pub fn edit<S>(
    store: &mut S,
    peer: &str,
    id: &str,
    new_text: &str,
    by_me: bool,
) -> anyhow::Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let count = seg_count(store, HIST, peer)?;
    for i in 0..count {
        let mut seg: Vec<StoredMessage> =
            crate::decode_state(store.get(&seg_key(HIST, peer, i))?, "1:1 transcript")?;
        let mut changed = false;
        for m in &mut seg {
            if m.id == id && m.from_me == by_me {
                m.text = format!("{new_text} (edited)");
                changed = true;
            }
        }
        if changed {
            store.put(&seg_key(HIST, peer, i), &wire::encode(&seg))?;
        }
    }
    Ok(())
}

/// Delete a stored 1:1 message by id — only if authored by the same side as the
/// delete (`by_me`). No-op if not found or authored by the other side. Rewrites
/// only the segment holding the message.
pub fn delete<S>(store: &mut S, peer: &str, id: &str, by_me: bool) -> anyhow::Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    delete_segments(store, HIST, peer, "1:1 transcript", |m: &StoredMessage| {
        m.id == id && m.from_me == by_me
    })
}

/// Edit a stored group message by id — only one whose recorded `sender` matches,
/// so a member can't rewrite another member's message. Rewrites only the segment
/// holding the message.
pub fn group_edit<S>(
    store: &mut S,
    group_id: &str,
    id: &str,
    new_text: &str,
    sender: &str,
) -> anyhow::Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let count = seg_count(store, GHIST, group_id)?;
    for i in 0..count {
        let mut seg: Vec<GroupStoredMessage> =
            crate::decode_state(store.get(&seg_key(GHIST, group_id, i))?, "group transcript")?;
        let mut changed = false;
        for m in &mut seg {
            if m.id == id && m.sender == sender {
                m.text = format!("{new_text} (edited)");
                changed = true;
            }
        }
        if changed {
            store.put(&seg_key(GHIST, group_id, i), &wire::encode(&seg))?;
        }
    }
    Ok(())
}

/// Delete a stored group message by id — only if its recorded `sender` matches.
/// Rewrites only the segment holding the message.
pub fn group_delete<S>(store: &mut S, group_id: &str, id: &str, sender: &str) -> anyhow::Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    delete_segments(
        store,
        GHIST,
        group_id,
        "group transcript",
        |m: &GroupStoredMessage| m.id == id && m.sender == sender,
    )
}

/// Load a group's transcript, pruning expired messages as of `now`.
pub fn group_load_active<S>(
    store: &mut S,
    group_id: &str,
    now: u64,
) -> anyhow::Result<Vec<GroupStoredMessage>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    load_active_segments(
        store,
        GHIST,
        group_id,
        "group transcript",
        |m: &GroupStoredMessage| matches!(m.expires_at, Some(at) if now >= at),
    )
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
        StoredMessage {
            id: String::new(),
            from_me,
            text: text.into(),
            timestamp: 0,
            expires_at: None,
        }
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
    fn corrupt_history_metadata_blocks_append_without_partial_state() {
        let mut store = MemStore::default();
        let metadata_key = meta_key(HIST, "bob");
        store
            .put(&metadata_key, b"corrupt history metadata")
            .unwrap();

        assert!(load(&store, "bob").is_err());
        assert!(append(&mut store, "bob", msg(true, "do not overwrite")).is_err());
        assert_eq!(
            store.get(&metadata_key).unwrap().as_deref(),
            Some(&b"corrupt history metadata"[..])
        );
        assert!(store.get(&seg_key(HIST, "bob", 0)).unwrap().is_none());
    }

    #[test]
    fn expired_messages_are_pruned_on_load() {
        let mut store = MemStore::default();
        append(
            &mut store,
            "bob",
            StoredMessage {
                id: String::new(),
                from_me: true,
                text: "keep".into(),
                timestamp: 0,
                expires_at: None,
            },
        )
        .unwrap();
        append(
            &mut store,
            "bob",
            StoredMessage {
                id: String::new(),
                from_me: true,
                text: "gone".into(),
                timestamp: 0,
                expires_at: Some(100),
            },
        )
        .unwrap();

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
        append(
            &mut store,
            "bob",
            StoredMessage {
                id: "m1".into(),
                from_me: false,
                text: "theirs".into(),
                timestamp: 0,
                expires_at: None,
            },
        )
        .unwrap();

        // A "mine"-scoped edit/delete (by_me: true) must NOT touch the peer's message.
        edit(&mut store, "bob", "m1", "hacked", true).unwrap();
        assert_eq!(
            load(&store, "bob").unwrap()[0].text,
            "theirs",
            "a peer can't edit as if it were mine"
        );
        delete(&mut store, "bob", "m1", true).unwrap();
        assert_eq!(
            load(&store, "bob").unwrap().len(),
            1,
            "a peer can't delete my-scoped"
        );

        // The correctly-scoped delete (by_me: false) does remove it.
        delete(&mut store, "bob", "m1", false).unwrap();
        assert!(load(&store, "bob").unwrap().is_empty());
    }

    #[test]
    fn group_edit_delete_are_sender_scoped() {
        let mut store = MemStore::default();
        let gm = |id: &str, sender: &str, text: &str| GroupStoredMessage {
            id: id.into(),
            sender: sender.into(),
            text: text.into(),
            timestamp: 0,
            expires_at: None,
        };
        group_append(&mut store, "g1", gm("m1", "alice", "alice's")).unwrap();

        // Bob can't edit or delete Alice's message.
        group_edit(&mut store, "g1", "m1", "hacked", "bob").unwrap();
        assert_eq!(
            group_load(&store, "g1").unwrap()[0].text,
            "alice's",
            "another member can't rewrite it"
        );
        group_delete(&mut store, "g1", "m1", "bob").unwrap();
        assert_eq!(
            group_load(&store, "g1").unwrap().len(),
            1,
            "another member can't delete it"
        );

        // Alice (the author) can.
        group_delete(&mut store, "g1", "m1", "alice").unwrap();
        assert!(group_load(&store, "g1").unwrap().is_empty());
    }

    #[test]
    fn corrupt_transcript_fails_closed_without_overwriting_it() {
        let mut store = MemStore::default();
        // A thread with one segment whose bytes are garbage.
        store
            .put(
                &meta_key(HIST, "bob"),
                &wire::encode(&SegMeta { segments: 1 }),
            )
            .unwrap();
        store
            .put(&seg_key(HIST, "bob", 0), b"not valid wire bytes")
            .unwrap();
        let original = store.get(&seg_key(HIST, "bob", 0)).unwrap().unwrap();
        assert!(load(&store, "bob").is_err());
        assert_eq!(
            store.get(&seg_key(HIST, "bob", 0)).unwrap().unwrap(),
            original
        );
    }

    /// How many segments a thread currently occupies (test helper).
    fn seg_count_1to1(store: &MemStore, peer: &str) -> u32 {
        seg_count(store, HIST, peer).unwrap()
    }

    #[test]
    fn append_spans_segments_and_loads_in_order() {
        let mut store = MemStore::default();
        let total = SEGMENT * 2 + 5; // spans three segments
        for i in 0..total {
            append(&mut store, "bob", msg(i % 2 == 0, &format!("m{i}"))).unwrap();
        }
        let transcript = load(&store, "bob").unwrap();
        assert_eq!(transcript.len(), total);
        for (i, m) in transcript.iter().enumerate() {
            assert_eq!(m.text, format!("m{i}"), "order preserved across segments");
        }
        assert_eq!(seg_count_1to1(&store, "bob"), 3);
        // Each non-tail segment is exactly full; the tail holds the remainder.
        let s0: Vec<StoredMessage> =
            crate::decode_state(store.get(&seg_key(HIST, "bob", 0)).unwrap(), "t").unwrap();
        assert_eq!(s0.len(), SEGMENT);
        let s2: Vec<StoredMessage> =
            crate::decode_state(store.get(&seg_key(HIST, "bob", 2)).unwrap(), "t").unwrap();
        assert_eq!(s2.len(), 5);
    }

    #[test]
    fn edit_in_old_segment_touches_only_that_segment() {
        let mut store = MemStore::default();
        for i in 0..(SEGMENT * 2 + 5) {
            let mut m = msg(false, &format!("m{i}"));
            m.id = format!("id{i}");
            append(&mut store, "bob", m).unwrap();
        }
        // Snapshot the tail segment (index 2) before the edit.
        let tail_before = store.get(&seg_key(HIST, "bob", 2)).unwrap();

        // Edit a message in the FIRST (non-tail) segment.
        edit(&mut store, "bob", "id3", "edited-3", false).unwrap();

        assert_eq!(load(&store, "bob").unwrap()[3].text, "edited-3 (edited)");
        // The tail segment's bytes are untouched.
        assert_eq!(store.get(&seg_key(HIST, "bob", 2)).unwrap(), tail_before);
    }

    #[test]
    fn delete_in_old_segment_touches_only_that_segment() {
        let mut store = MemStore::default();
        for i in 0..(SEGMENT * 2 + 5) {
            let mut m = msg(true, &format!("m{i}"));
            m.id = format!("id{i}");
            append(&mut store, "bob", m).unwrap();
        }
        let tail_before = store.get(&seg_key(HIST, "bob", 2)).unwrap();
        let mid_before = store.get(&seg_key(HIST, "bob", 1)).unwrap();

        delete(&mut store, "bob", "id2", true).unwrap();

        let transcript = load(&store, "bob").unwrap();
        assert_eq!(transcript.len(), SEGMENT * 2 + 4);
        assert!(!transcript.iter().any(|m| m.id == "id2"));
        // Only segment 0 changed; segments 1 and 2 are byte-identical.
        assert_eq!(store.get(&seg_key(HIST, "bob", 1)).unwrap(), mid_before);
        assert_eq!(store.get(&seg_key(HIST, "bob", 2)).unwrap(), tail_before);
    }

    #[test]
    fn load_active_prunes_from_non_tail_segment_only() {
        let mut store = MemStore::default();
        // Fill segment 0 fully; put an expiring message near its start.
        for i in 0..SEGMENT {
            let expires_at = if i == 3 { Some(100) } else { None };
            append(
                &mut store,
                "bob",
                StoredMessage {
                    id: format!("id{i}"),
                    from_me: true,
                    text: format!("m{i}"),
                    timestamp: 0,
                    expires_at,
                },
            )
            .unwrap();
        }
        // Add a second, tail segment with no expiring messages.
        for i in SEGMENT..(SEGMENT + 10) {
            append(&mut store, "bob", msg(true, &format!("m{i}"))).unwrap();
        }
        let tail_before = store.get(&seg_key(HIST, "bob", 1)).unwrap();

        let active = load_active(&mut store, "bob", 100).unwrap();
        assert_eq!(
            active.len(),
            SEGMENT + 10 - 1,
            "the expired message is gone"
        );
        assert!(!active.iter().any(|m| m.id == "id3"));
        // The tail segment was never rewritten (nothing expired there).
        assert_eq!(store.get(&seg_key(HIST, "bob", 1)).unwrap(), tail_before);
        // Prune persists.
        assert_eq!(load(&store, "bob").unwrap().len(), SEGMENT + 10 - 1);
    }

    #[test]
    fn clear_removes_all_segments_and_meta() {
        let mut store = MemStore::default();
        for i in 0..(SEGMENT * 2 + 5) {
            append(&mut store, "bob", msg(true, &format!("m{i}"))).unwrap();
        }
        assert_eq!(seg_count_1to1(&store, "bob"), 3);

        clear(&mut store, "bob").unwrap();

        assert!(load(&store, "bob").unwrap().is_empty());
        assert_eq!(seg_count_1to1(&store, "bob"), 0);
        // Every segment key and the meta key are gone.
        for i in 0..3 {
            assert!(store.get(&seg_key(HIST, "bob", i)).unwrap().is_none());
        }
        assert!(store.get(&meta_key(HIST, "bob")).unwrap().is_none());
        // Dropped from the peer index too.
        assert!(!peers(&store).unwrap().iter().any(|p| p == "bob"));
    }

    #[test]
    fn group_append_spans_segments_edit_delete_prune() {
        let mut store = MemStore::default();
        let total = SEGMENT + 10; // spans two segments
        for i in 0..total {
            let expires_at = if i == 2 { Some(100) } else { None };
            group_append(
                &mut store,
                "g1",
                GroupStoredMessage {
                    id: format!("id{i}"),
                    sender: "alice".into(),
                    text: format!("m{i}"),
                    timestamp: 0,
                    expires_at,
                },
            )
            .unwrap();
        }
        assert_eq!(seg_count(&store, GHIST, "g1").unwrap(), 2);
        assert_eq!(group_load(&store, "g1").unwrap().len(), total);

        // Edit a message in the first (non-tail) segment; author-scoped.
        group_edit(&mut store, "g1", "id1", "e", "bob").unwrap();
        assert_eq!(
            group_load(&store, "g1").unwrap()[1].text,
            "m1",
            "wrong sender: no-op"
        );
        group_edit(&mut store, "g1", "id1", "e", "alice").unwrap();
        assert_eq!(group_load(&store, "g1").unwrap()[1].text, "e (edited)");

        // Prune the expiring message (id2, in segment 0).
        let active = group_load_active(&mut store, "g1", 100).unwrap();
        assert_eq!(active.len(), total - 1);
        assert!(!active.iter().any(|m| m.id == "id2"));

        // Delete a message from the tail segment; author-scoped.
        let tail_id = format!("id{}", total - 1);
        group_delete(&mut store, "g1", &tail_id, "bob").unwrap();
        assert!(group_load(&store, "g1")
            .unwrap()
            .iter()
            .any(|m| m.id == tail_id));
        group_delete(&mut store, "g1", &tail_id, "alice").unwrap();
        assert!(!group_load(&store, "g1")
            .unwrap()
            .iter()
            .any(|m| m.id == tail_id));
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
