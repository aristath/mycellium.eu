//! Mycellium engine in WebAssembly (Tier 1.1, stage 1).
//!
//! Stage 1 proves the toolchain and the core crypto run correctly *in the
//! browser*: the deterministic account-id hash and real device-key generation.
//! Later stages add the pure send/receive step functions and JS-owned I/O
//! (`fetch` + IndexedDB), replacing the local Rust server entirely.

use std::collections::HashMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
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
use mycellium_engine::groups::MailItem;
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
            let Ok(MailItem::Direct(env)) = serde_json::from_str::<MailItem>(&blob) else { continue };
            let Ok((from, plaintext)) = wireops::open_envelope(&mut BrowserPlatform, &self.identity, &env) else { continue };
            let Ok(app) = AppMessage::decode(&plaintext) else { continue };
            // Learn the sender's self-set display name (carried in their record).
            let _ = names::note(&mut self.store, from.as_str(), &env.sender_record.record.name);
            apply_to_history(&mut self.store, from.as_str(), &app, false);
            received += 1;
        }
        Ok(received)
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
