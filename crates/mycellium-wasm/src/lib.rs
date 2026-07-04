//! Mycellium engine in WebAssembly (Tier 1.1, stage 1).
//!
//! Stage 1 proves the toolchain and the core crypto run correctly *in the
//! browser*: the deterministic account-id hash and real device-key generation.
//! Later stages add the pure send/receive step functions and JS-owned I/O
//! (`fetch` + IndexedDB), replacing the local Rust server entirely.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mycellium_core::group::{Group, GroupMessage};
use mycellium_core::http::{HttpResponse, HttpTransport};
use mycellium_core::identity::{Handle, Identity};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::offline::Envelope;
use mycellium_core::platform::Platform;
use mycellium_core::record::SignedRecord;
use mycellium_core::storage::Storage;
use mycellium_core::userid::user_id as core_user_id;
use mycellium_core::wire;
use mycellium_directory_client::DirectoryClient;
use mycellium_engine::groups::{self, GroupInvitePayload, MailItem, StoredGroup};
use mycellium_engine::{history, names, wireops};
use mycellium_queue_client::{wallet_hex, QueueClient};
use wasm_bindgen::prelude::*;

/// The build's version string — a trivial export to confirm JS↔WASM bindings.
#[wasm_bindgen]
pub fn version() -> String {
    concat!("mycellium-wasm ", env!("CARGO_PKG_VERSION")).to_string()
}

/// The public directory id for an email/username. Must byte-for-byte match the
/// native engine's `user_id`, so the browser and servers agree on identities.
#[wasm_bindgen]
pub fn user_id(input: &str) -> String {
    core_user_id(input).as_str().to_string()
}

/// Generate a fresh device identity in the browser and return its wallet public
/// key (hex). Proves real key material is produced from browser entropy.
#[wasm_bindgen]
pub fn generate_wallet() -> Result<String, JsValue> {
    let identity = Identity::generate(&mut BrowserPlatform).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(hex(&identity.wallet_public().0))
}

/// Log into a directory from the browser: generate a device identity, run the
/// challenge → sign → verify handshake over (synchronous) XHR, and return the
/// session token. Proves the *entire* client stack — transport, shared client
/// logic, and crypto — runs in WASM against a real server.
#[wasm_bindgen]
pub fn directory_login(base: &str) -> Result<String, JsValue> {
    let identity = Identity::generate(&mut BrowserPlatform).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let client = DirectoryClient::with_transport(base, Box::new(XhrTransport));
    client.login(&identity).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// An in-memory [`Storage`] for the browser. Engine state lives here during a
/// session; the host snapshots it to IndexedDB for durability (see [`Session`]).
/// This is the wasm counterpart to the native `FileStore`.
#[derive(Default)]
struct MemStore {
    map: HashMap<Vec<u8>, Vec<u8>>,
}

impl Storage for MemStore {
    type Error = core::convert::Infallible;
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.map.get(key).cloned())
    }
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.map.insert(key.to_vec(), value.to_vec());
        Ok(())
    }
    fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        self.map.remove(key);
        Ok(())
    }
}

/// A browser-side engine session: holds the in-memory store and (de)serializes it
/// so the host can persist it to IndexedDB. Later stages give it the identity and
/// the send/receive operations; today it proves state survives a reload.
#[wasm_bindgen]
pub struct Session {
    store: MemStore,
    identity: Identity,
}

/// The device identity's persistable secret (mnemonic + device seed), from which
/// `Identity::restore` rebuilds all keys. Stored in the session's own store so it
/// round-trips through IndexedDB — the browser account survives reloads.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredIdentity {
    mnemonic: String,
    device_seed: [u8; 32],
}

const IDENTITY_KEY: &[u8] = b"myc:identity";

fn store_identity(store: &mut MemStore, identity: &Identity) {
    let secret = StoredIdentity { mnemonic: identity.mnemonic().to_string(), device_seed: identity.device_seed() };
    if let Ok(bytes) = serde_json::to_vec(&secret) {
        let _ = store.put(IDENTITY_KEY, &bytes);
    }
}

#[wasm_bindgen]
impl Session {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Session {
        let identity = Identity::generate(&mut BrowserPlatform).expect("browser CSPRNG must be available");
        let mut store = MemStore::default();
        store_identity(&mut store, &identity);
        Session { store, identity }
    }

    /// Restore a session — **the same device identity** and all state — from a
    /// snapshot previously produced by [`Session::export`].
    pub fn restore(snapshot: &[u8]) -> Result<Session, JsValue> {
        let entries: Vec<(Vec<u8>, Vec<u8>)> =
            mycellium_core::wire::decode(snapshot).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
        let store = MemStore { map: entries.into_iter().collect() };
        let raw = store
            .get(IDENTITY_KEY)
            .ok()
            .flatten()
            .ok_or_else(|| JsValue::from_str("snapshot has no identity"))?;
        let secret: StoredIdentity =
            serde_json::from_slice(&raw).map_err(|e| JsValue::from_str(&format!("corrupt identity: {e}")))?;
        let identity = Identity::restore(secret.mnemonic.trim(), secret.device_seed)
            .map_err(|_| JsValue::from_str("stored identity is invalid"))?;
        Ok(Session { store, identity })
    }

    /// This session's wallet public key (hex) — a stable id for the device.
    pub fn wallet(&self) -> String {
        hex(&self.identity.wallet_public().0)
    }

    /// Build this identity's signed directory record (wire-encoded) so a peer can
    /// seal messages to it. `handle` is the account name, `queue` its endpoint.
    pub fn record(&mut self, handle: &str, name: &str, queue: &str) -> Result<Vec<u8>, JsValue> {
        let me = Handle::new(handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let record = wireops::build_record(&mut BrowserPlatform, &self.identity, &me, name, queue, "");
        Ok(wire::encode(&record))
    }

    /// Seal a text message to `peer_record` (their wire-encoded [`SignedRecord`]),
    /// returning the encrypted envelope (wire-encoded) to hand to the queue.
    pub fn seal(&mut self, my_handle: &str, my_name: &str, my_queue: &str, peer_record: &[u8], text: &str) -> Result<Vec<u8>, JsValue> {
        let me = Handle::new(my_handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let record: SignedRecord = wire::decode(peer_record).map_err(|e| JsValue::from_str(&format!("bad peer record: {e:?}")))?;
        let plaintext = wireops::text_message(&mut BrowserPlatform, text).encode();
        let envelope = wireops::seal_to(
            &mut BrowserPlatform,
            &self.identity,
            &me,
            my_name,
            my_queue,
            record.record.primary(),
            &plaintext,
        );
        Ok(wire::encode(&envelope))
    }

    /// Open an encrypted envelope addressed to this session. Returns
    /// `{"from":"…","text":"…"}` JSON.
    pub fn open(&mut self, envelope: &[u8]) -> Result<String, JsValue> {
        let env: Envelope = wire::decode(envelope).map_err(|e| JsValue::from_str(&format!("bad envelope: {e:?}")))?;
        let (from, plaintext) =
            wireops::open_envelope(&mut BrowserPlatform, &self.identity, &env).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let app = AppMessage::decode(&plaintext).map_err(|e| JsValue::from_str(&format!("bad message: {e:?}")))?;
        let text = match app.body {
            Body::Text(t) => t,
            other => format!("{other:?}"),
        };
        Ok(serde_json::json!({ "from": from.as_str(), "text": text }).to_string())
    }

    /// Publish this identity's record to the directory so peers can find us.
    pub fn register(&mut self, dir_url: &str, queue_url: &str, handle: &str, name: &str) -> Result<(), JsValue> {
        let me = Handle::new(handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let record = wireops::build_record(&mut BrowserPlatform, &self.identity, &me, name, queue_url, "");
        let dir = DirectoryClient::with_transport(dir_url, Box::new(XhrTransport));
        let token = dir.login(&self.identity).map_err(|e| JsValue::from_str(&e.to_string()))?;
        dir.publish(&token, &me, &record).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let _ = self.store.put(b"myc:handle", handle.as_bytes()); // for group processing during sync
        Ok(())
    }

    /// Send a text message to `peer_handle`. Returns the number of recipient
    /// devices delivered to.
    #[allow(clippy::too_many_arguments)]
    pub fn send(&mut self, dir_url: &str, my_handle: &str, my_name: &str, my_queue: &str, peer_handle: &str, text: &str) -> Result<u32, JsValue> {
        let app = wireops::text_message(&mut BrowserPlatform, text);
        self.deliver_app(dir_url, my_handle, my_name, my_queue, peer_handle, app)
    }

    /// Reply to message `reply_to` in the conversation with `peer_handle`.
    #[allow(clippy::too_many_arguments)]
    pub fn reply(&mut self, dir_url: &str, my_handle: &str, my_name: &str, my_queue: &str, peer_handle: &str, reply_to: &str, text: &str) -> Result<u32, JsValue> {
        let body = Body::Reply { to: reply_to.to_string(), text: text.to_string() };
        let app = wireops::app_message(&mut BrowserPlatform, body);
        self.deliver_app(dir_url, my_handle, my_name, my_queue, peer_handle, app)
    }

    /// React to message `target` with an emoji.
    #[allow(clippy::too_many_arguments)]
    pub fn react(&mut self, dir_url: &str, my_handle: &str, my_name: &str, my_queue: &str, peer_handle: &str, target: &str, emoji: &str) -> Result<u32, JsValue> {
        let body = Body::Reaction { to: target.to_string(), emoji: emoji.to_string() };
        let app = wireops::app_message(&mut BrowserPlatform, body);
        self.deliver_app(dir_url, my_handle, my_name, my_queue, peer_handle, app)
    }

    /// Delete message `target` for everyone (a tombstone, applied to history).
    pub fn delete_message(&mut self, dir_url: &str, my_handle: &str, my_name: &str, my_queue: &str, peer_handle: &str, target: &str) -> Result<u32, JsValue> {
        let body = Body::Delete { to: target.to_string() };
        let app = wireops::app_message(&mut BrowserPlatform, body);
        self.deliver_app(dir_url, my_handle, my_name, my_queue, peer_handle, app)
    }

    /// Send a file attachment (`data` is base64). Carried end-to-end like any
    /// other message; the servers never see the bytes in the clear.
    #[allow(clippy::too_many_arguments)]
    pub fn send_file(&mut self, dir_url: &str, my_handle: &str, my_name: &str, my_queue: &str, peer_handle: &str, name: &str, mime: &str, data_b64: &str) -> Result<u32, JsValue> {
        let data = B64.decode(data_b64).map_err(|e| JsValue::from_str(&format!("bad base64: {e}")))?;
        let body = Body::File { mime: mime.to_string(), name: name.to_string(), data };
        let app = wireops::app_message(&mut BrowserPlatform, body);
        self.deliver_app(dir_url, my_handle, my_name, my_queue, peer_handle, app)
    }

    /// The learned display name for a peer handle, if we've seen their record.
    pub fn name_of(&self, handle: &str) -> Option<String> {
        names::get(&self.store, handle).ok().flatten()
    }

    /// The attachment for message `id` as a `data:` URL, if any.
    pub fn file(&self, id: &str) -> Option<String> {
        self.store
            .get(format!("file:{id}").as_bytes())
            .ok()
            .flatten()
            .map(|v| String::from_utf8_lossy(&v).into_owned())
    }

    /// The queue's VAPID public key, for the browser's `applicationServerKey`.
    pub fn push_key(&self, queue_url: &str) -> Result<String, JsValue> {
        let queue = QueueClient::with_transport(queue_url, Box::new(XhrTransport));
        queue.push_key().map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Register a browser push `endpoint` so the queue can wake us when closed.
    pub fn push_subscribe(&self, queue_url: &str, endpoint: &str) -> Result<(), JsValue> {
        let queue = QueueClient::with_transport(queue_url, Box::new(XhrTransport));
        let token = queue.login(&self.identity).map_err(|e| JsValue::from_str(&e.to_string()))?;
        queue.push_subscribe(&token, endpoint).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Drain our queue, decrypt direct messages, and store them. Returns the
    /// number of new messages received.
    pub fn sync(&mut self, queue_url: &str) -> Result<u32, JsValue> {
        let queue = QueueClient::with_transport(queue_url, Box::new(XhrTransport));
        let qtoken = queue.login(&self.identity).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let my_hex = wallet_hex(&self.identity.wallet_public());
        let my_slot = wireops::device_slot(&self.identity.device_public());
        let mut blobs = queue.collect(&qtoken, &my_hex, &my_slot).unwrap_or_default();
        blobs.extend(queue.collect(&qtoken, &my_hex, "account").unwrap_or_default());
        let mut received = 0u32;
        for blob in blobs {
            let Ok(item) = serde_json::from_str::<MailItem>(&blob) else { continue };
            match item {
                MailItem::Direct(env) => {
                    let Ok((from, plaintext)) = wireops::open_envelope(&mut BrowserPlatform, &self.identity, &env) else { continue };
                    let Ok(app) = AppMessage::decode(&plaintext) else { continue };
                    // Learn the sender's self-set display name (carried in their record).
                    let _ = names::note(&mut self.store, from.as_str(), &env.sender_record.record.name);
                    apply_to_history(&mut self.store, from.as_str(), &app, false);
                    received += 1;
                }
                MailItem::GroupInvite(env) => {
                    self.handle_group_invite(&env);
                    received += 1;
                }
                MailItem::GroupText { group_id, message } => {
                    self.handle_group_text(&group_id, &message);
                    received += 1;
                }
                // GroupSync / GroupRemove / SelfSync aren't handled in the browser yet.
                _ => {}
            }
        }
        Ok(received)
    }

    /// Create a group with `members` (a JSON array of handles) and distribute our
    /// sender key to them. Returns the new group id.
    #[allow(clippy::too_many_arguments)]
    pub fn group_create(&mut self, dir_url: &str, my_handle: &str, my_name: &str, my_queue: &str, name: &str, members_json: &str) -> Result<String, JsValue> {
        let me = Handle::new(my_handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let members: Vec<String> = serde_json::from_str(members_json).map_err(|e| JsValue::from_str(&format!("bad members: {e}")))?;
        let mut id_bytes = [0u8; 8];
        getrandom::getrandom(&mut id_bytes).map_err(|e| JsValue::from_str(&format!("{e}")))?;
        let group_id = wireops::hex(&id_bytes);
        let mut all = members;
        if !all.iter().any(|m| m == me.as_str()) {
            all.push(me.as_str().to_string());
        }
        let my_gid = wireops::my_group_id(&self.identity);
        let group = Group::new(&mut BrowserPlatform, my_gid.clone());
        let mut stored = StoredGroup {
            id: group_id.clone(),
            name: name.to_string(),
            members: all,
            me: me.as_str().to_string(),
            sender_handles: Vec::new(),
            state: group.export(),
        };
        stored.note_sender(my_gid, me.as_str());
        groups::save(&mut self.store, &stored).map_err(|_| JsValue::from_str("store error"))?;
        self.distribute_key(dir_url, my_name, my_queue, &me, &stored, &group)?;
        Ok(group_id)
    }

    /// Send a text message to a group. Returns devices delivered to.
    #[allow(clippy::too_many_arguments)]
    pub fn group_send(&mut self, dir_url: &str, my_handle: &str, my_name: &str, my_queue: &str, group_id: &str, text: &str) -> Result<u32, JsValue> {
        let _ = (my_name, my_queue); // group messages use the group key, not a per-peer seal
        let me = Handle::new(my_handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let mut stored =
            groups::load(&self.store, group_id).map_err(|_| JsValue::from_str("store error"))?.ok_or_else(|| JsValue::from_str("no such group"))?;
        let mut group = Group::import(stored.state.clone()).map_err(|_| JsValue::from_str("bad group state"))?;
        let app = wireops::text_message(&mut BrowserPlatform, text);
        let gm = group.encrypt(&app.encode(), &wireops::group_ad(&stored.id));
        stored.state = group.export();
        groups::save(&mut self.store, &stored).map_err(|_| JsValue::from_str("store error"))?;

        let item = MailItem::GroupText { group_id: stored.id.clone(), message: gm };
        let blob = serde_json::to_string(&item).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let dir = DirectoryClient::with_transport(dir_url, Box::new(XhrTransport));
        let mut delivered = 0u32;
        for member in &stored.members {
            if member == me.as_str() {
                continue;
            }
            let Ok(handle) = Handle::new(member.clone()) else { continue };
            let Ok(record) = dir.lookup(&handle) else { continue };
            let queue = QueueClient::with_transport(&record.record.queue, Box::new(XhrTransport));
            let Ok(qtoken) = queue.login(&self.identity) else { continue };
            let peer_hex = wallet_hex(&record.record.wallet);
            for device in &record.record.devices {
                if queue.deposit(&qtoken, &peer_hex, &wireops::device_slot(&device.device_key), &blob).is_ok() {
                    delivered += 1;
                }
            }
        }
        let entry = history::GroupStoredMessage {
            id: app.id.clone(),
            sender: me.as_str().to_string(),
            text: app.summary(),
            timestamp: app.timestamp,
            expires_at: app.expires_at,
        };
        let _ = history::group_append(&mut self.store, &stored.id, entry);
        Ok(delivered)
    }

    /// The groups we're in, as JSON: `[{id, name, members}]`.
    pub fn groups(&self) -> Result<String, JsValue> {
        let ids = groups::list(&self.store).map_err(|_| JsValue::from_str("store error"))?;
        let mut out = Vec::new();
        for id in ids {
            if let Ok(Some(g)) = groups::load(&self.store, &id) {
                out.push(serde_json::json!({ "id": g.id, "name": g.name, "members": g.members }));
            }
        }
        serde_json::to_string(&out).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// A group's messages as JSON: `[{id, sender, text, timestamp}]`.
    pub fn group_thread(&self, group_id: &str) -> Result<String, JsValue> {
        let msgs = history::group_load(&self.store, group_id).map_err(|_| JsValue::from_str("store error"))?;
        serde_json::to_string(&msgs).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Store a value (UTF-8) under `key`.
    pub fn put(&mut self, key: &str, value: &str) {
        let _ = self.store.put(key.as_bytes(), value.as_bytes());
    }

    /// Read a value, or `undefined` if absent.
    pub fn get(&self, key: &str) -> Option<String> {
        self.store.get(key.as_bytes()).ok().flatten().map(|v| String::from_utf8_lossy(&v).into_owned())
    }

    /// Remove a key.
    pub fn del(&mut self, key: &str) {
        let _ = self.store.delete(key.as_bytes());
    }

    /// Append a message to a peer's conversation, using the **engine's own**
    /// generic history module against the browser store. Returns the message id.
    pub fn add_message(&mut self, peer: &str, text: &str, from_me: bool) -> Result<String, JsValue> {
        let mut id_bytes = [0u8; 8];
        getrandom::getrandom(&mut id_bytes).map_err(|e| JsValue::from_str(&format!("{e}")))?;
        let id = hex(&id_bytes);
        let message = mycellium_engine::history::StoredMessage {
            id: id.clone(),
            from_me,
            text: text.to_string(),
            timestamp: BrowserPlatform.now_unix_secs(),
            expires_at: None,
        };
        mycellium_engine::history::append(&mut self.store, peer, message)
            .map_err(|_| JsValue::from_str("store error"))?;
        Ok(id)
    }

    /// Load a peer's conversation as JSON (via the engine's history module).
    pub fn thread(&self, peer: &str) -> Result<String, JsValue> {
        let messages =
            mycellium_engine::history::load(&self.store, peer).map_err(|_| JsValue::from_str("store error"))?;
        serde_json::to_string(&messages).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// The conversation list as JSON: `[{peer, last, timestamp, mine}]`, newest
    /// first — for rendering the threads screen.
    pub fn peers(&self) -> Result<String, JsValue> {
        let peers = mycellium_engine::history::peers(&self.store).map_err(|_| JsValue::from_str("store error"))?;
        let mut out = Vec::new();
        for peer in peers {
            let msgs =
                mycellium_engine::history::load(&self.store, &peer).map_err(|_| JsValue::from_str("store error"))?;
            let last = msgs.last();
            let name = names::get(&self.store, &peer).ok().flatten().unwrap_or_default();
            out.push(serde_json::json!({
                "peer": peer,
                "name": name,
                "last": last.map(|m| m.text.clone()).unwrap_or_default(),
                "timestamp": last.map(|m| m.timestamp).unwrap_or(0),
                "mine": last.map(|m| m.from_me).unwrap_or(false),
            }));
        }
        out.sort_by(|a, b| b["timestamp"].as_u64().cmp(&a["timestamp"].as_u64()));
        serde_json::to_string(&out).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Serialize the whole store for the host to persist (→ IndexedDB).
    pub fn export(&self) -> Vec<u8> {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = self.store.map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        mycellium_core::wire::encode(&entries)
    }

    /// Restore a previously exported snapshot (from IndexedDB).
    pub fn import(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
        let entries: Vec<(Vec<u8>, Vec<u8>)> =
            mycellium_core::wire::decode(bytes).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
        self.store.map = entries.into_iter().collect();
        Ok(())
    }
}

impl Session {
    /// Shared delivery path: look up the peer, X3DH-seal `app` to each of their
    /// devices, deposit to their queue, and record our own copy.
    #[allow(clippy::too_many_arguments)]
    fn deliver_app(&mut self, dir_url: &str, my_handle: &str, my_name: &str, my_queue: &str, peer_handle: &str, app: AppMessage) -> Result<u32, JsValue> {
        let me = Handle::new(my_handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let peer = Handle::new(peer_handle).map_err(|_| JsValue::from_str("invalid peer handle"))?;
        let dir = DirectoryClient::with_transport(dir_url, Box::new(XhrTransport));
        let precord = dir.lookup(&peer).map_err(|e| JsValue::from_str(&format!("lookup: {e}")))?;
        // Learn the peer's chosen display name from their record.
        let _ = names::note(&mut self.store, peer_handle, &precord.record.name);
        let plaintext = app.encode();
        let queue = QueueClient::with_transport(&precord.record.queue, Box::new(XhrTransport));
        let qtoken = queue.login(&self.identity).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let peer_hex = wallet_hex(&precord.record.wallet);
        let mut delivered = 0u32;
        for device in &precord.record.devices {
            let env = wireops::seal_to(&mut BrowserPlatform, &self.identity, &me, my_name, my_queue, device, &plaintext);
            let blob = serde_json::to_string(&MailItem::Direct(env)).map_err(|e| JsValue::from_str(&e.to_string()))?;
            if queue.deposit(&qtoken, &peer_hex, &wireops::device_slot(&device.device_key), &blob).is_ok() {
                delivered += 1;
            }
        }
        apply_to_history(&mut self.store, peer_handle, &app, true);
        Ok(delivered)
    }

    fn my_handle(&self) -> String {
        self.store
            .get(b"myc:handle")
            .ok()
            .flatten()
            .map(|v| String::from_utf8_lossy(&v).into_owned())
            .unwrap_or_default()
    }

    /// Seal our group sender-key (a `GroupInvitePayload`) to every member device.
    fn distribute_key(&self, dir_url: &str, my_name: &str, my_queue: &str, me: &Handle, stored: &StoredGroup, group: &Group) -> Result<(), JsValue> {
        let payload = GroupInvitePayload {
            group_id: stored.id.clone(),
            name: stored.name.clone(),
            members: stored.members.clone(),
            sender_id: wireops::my_group_id(&self.identity),
            distribution: group.distribution(),
        };
        let plaintext = serde_json::to_vec(&payload).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let dir = DirectoryClient::with_transport(dir_url, Box::new(XhrTransport));
        for member in &stored.members {
            let Ok(handle) = Handle::new(member.clone()) else { continue };
            let Ok(record) = dir.lookup(&handle) else { continue };
            let queue = QueueClient::with_transport(&record.record.queue, Box::new(XhrTransport));
            let Ok(qtoken) = queue.login(&self.identity) else { continue };
            let peer_hex = wallet_hex(&record.record.wallet);
            for device in &record.record.devices {
                if device.device_key == self.identity.device_public() {
                    continue; // never this exact device
                }
                let env = wireops::seal_to(&mut BrowserPlatform, &self.identity, me, my_name, my_queue, device, &plaintext);
                let Ok(blob) = serde_json::to_string(&MailItem::GroupInvite(env)) else { continue };
                let _ = queue.deposit(&qtoken, &peer_hex, &wireops::device_slot(&device.device_key), &blob);
            }
        }
        Ok(())
    }

    /// Process a received group invite: join the group (or learn a member's key)
    /// and record the sender key so we can decrypt their messages.
    fn handle_group_invite(&mut self, env: &Envelope) {
        let Ok((from, bytes)) = wireops::open_envelope(&mut BrowserPlatform, &self.identity, env) else { return };
        let Ok(payload) = serde_json::from_slice::<GroupInvitePayload>(&bytes) else { return };
        let sender_id = payload.sender_id.clone();
        match groups::load(&self.store, &payload.group_id).ok().flatten() {
            Some(mut stored) => {
                let Ok(mut group) = Group::import(stored.state.clone()) else { return };
                let _ = group.add_member(sender_id.clone(), &payload.distribution);
                stored.note_sender(sender_id, from.as_str());
                stored.state = group.export();
                let _ = groups::save(&mut self.store, &stored);
            }
            None => {
                let mut group = Group::new(&mut BrowserPlatform, wireops::my_group_id(&self.identity));
                let _ = group.add_member(sender_id.clone(), &payload.distribution);
                let mine = self.my_handle();
                let mut stored = StoredGroup {
                    id: payload.group_id.clone(),
                    name: payload.name.clone(),
                    members: payload.members.clone(),
                    me: mine.clone(),
                    sender_handles: Vec::new(),
                    state: group.export(),
                };
                stored.note_sender(sender_id, from.as_str());
                stored.note_sender(wireops::my_group_id(&self.identity), &mine);
                let _ = groups::save(&mut self.store, &stored);
            }
        }
    }

    /// Decrypt a received group message and store it.
    fn handle_group_text(&mut self, group_id: &str, message: &GroupMessage) {
        let Some(mut stored) = groups::load(&self.store, group_id).ok().flatten() else { return };
        let sender = stored
            .handle_of(&message.sender)
            .map(str::to_string)
            .unwrap_or_else(|| String::from_utf8_lossy(&message.sender).into_owned());
        let Ok(mut group) = Group::import(stored.state.clone()) else { return };
        if let Ok(plaintext) = group.decrypt(message, &wireops::group_ad(group_id)) {
            stored.state = group.export();
            let _ = groups::save(&mut self.store, &stored);
            if let Ok(app) = AppMessage::decode(&plaintext) {
                match &app.body {
                    Body::Edit { to, text } => {
                        let _ = history::group_edit(&mut self.store, group_id, to, text);
                    }
                    Body::Delete { to } => {
                        let _ = history::group_delete(&mut self.store, group_id, to);
                    }
                    Body::Receipt { .. } => {}
                    _ => {
                        let entry = history::GroupStoredMessage {
                            id: app.id.clone(),
                            sender,
                            text: app.summary(),
                            timestamp: app.timestamp,
                            expires_at: app.expires_at,
                        };
                        let _ = history::group_append(&mut self.store, group_id, entry);
                    }
                }
            }
        }
    }
}

/// Apply a sent/received message to a conversation: edits/deletes mutate the
/// referenced message, everything else appends. `from_me` marks the direction.
fn apply_to_history(store: &mut MemStore, peer: &str, app: &AppMessage, from_me: bool) {
    match &app.body {
        Body::Edit { to, text } => {
            let _ = history::edit(store, peer, to, text);
        }
        Body::Delete { to } => {
            let _ = history::delete(store, peer, to);
        }
        Body::Receipt { .. } => {
            // A delivery/read acknowledgment — not a visible message.
        }
        _ => {
            // Stash attachment bytes as a data: URL, keyed by message id, so the
            // UI can render it (history itself keeps just the "📎 name" summary).
            if let Body::File { mime, data, .. } = &app.body {
                let url = format!("data:{mime};base64,{}", B64.encode(data));
                let _ = store.put(format!("file:{}", app.id).as_bytes(), url.as_bytes());
            }
            let msg = history::StoredMessage {
                id: app.id.clone(),
                from_me,
                text: app.summary(),
                timestamp: app.timestamp,
                expires_at: app.expires_at,
            };
            let _ = history::append(store, peer, msg);
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

/// A synchronous `XMLHttpRequest`-backed [`HttpTransport`]. Synchronous so the
/// shared (blocking) client logic runs unchanged; a later stage moves this into
/// a Web Worker so it never blocks the UI thread.
struct XhrTransport;

impl HttpTransport for XhrTransport {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, String> {
        let xhr = web_sys::XmlHttpRequest::new().map_err(|_| "XHR unavailable".to_string())?;
        xhr.open_with_async(method, url, false).map_err(|e| format!("open: {e:?}"))?;
        for (k, v) in headers {
            let _ = xhr.set_request_header(k, v);
        }
        let sent = match body {
            Some(b) => xhr.send_with_opt_str(Some(&String::from_utf8_lossy(b))),
            None => xhr.send(),
        };
        sent.map_err(|e| format!("send: {e:?}"))?;
        let status = xhr.status().map_err(|e| format!("status: {e:?}"))?;
        let text = xhr.response_text().ok().flatten().unwrap_or_default();
        Ok(HttpResponse { status, body: text.into_bytes() })
    }
}

/// Platform backed by browser APIs: entropy from the Web Crypto RNG (via
/// getrandom's `js` backend) and the clock from `Date.now()`.
struct BrowserPlatform;

impl Platform for BrowserPlatform {
    fn fill_random(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("browser CSPRNG must be available");
    }
    fn now_unix_secs(&self) -> u64 {
        (js_sys::Date::now() / 1000.0) as u64
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
