//! Mycellium engine in WebAssembly (Tier 1.1, stage 1).
//!
//! Stage 1 proves the toolchain and the core crypto run correctly *in the
//! browser*: the deterministic account-id hash and real device-key generation.
//! Later stages add the pure send/receive step functions and JS-owned I/O
//! (`fetch` + IndexedDB), replacing the local Rust server entirely.

use std::collections::HashMap;

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
use mycellium_engine::{history, wireops};
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

#[wasm_bindgen]
impl Session {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Session {
        let identity = Identity::generate(&mut BrowserPlatform).expect("browser CSPRNG must be available");
        Session { store: MemStore::default(), identity }
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

    /// Send a text message to `peer_handle` via the directory + queue. Returns the
    /// number of recipient devices delivered to.
    #[allow(clippy::too_many_arguments)]
    pub fn send(&mut self, dir_url: &str, my_handle: &str, my_name: &str, my_queue: &str, peer_handle: &str, text: &str) -> Result<u32, JsValue> {
        let me = Handle::new(my_handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let peer = Handle::new(peer_handle).map_err(|_| JsValue::from_str("invalid peer handle"))?;
        let dir = DirectoryClient::with_transport(dir_url, Box::new(XhrTransport));
        let precord = dir.lookup(&peer).map_err(|e| JsValue::from_str(&format!("lookup: {e}")))?;
        let plaintext = wireops::text_message(&mut BrowserPlatform, text).encode();
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
        // Record our own copy of the message in local history.
        let sent = history::StoredMessage {
            id: wireops::random_id(&mut BrowserPlatform),
            from_me: true,
            text: text.to_string(),
            timestamp: BrowserPlatform.now_unix_secs(),
            expires_at: None,
        };
        let _ = history::append(&mut self.store, peer_handle, sent);
        Ok(delivered)
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
            let text = match app.body {
                Body::Text(t) => t,
                other => format!("{other:?}"),
            };
            let msg = history::StoredMessage {
                id: app.id,
                from_me: false,
                text,
                timestamp: app.timestamp,
                expires_at: app.expires_at,
            };
            let _ = history::append(&mut self.store, from.as_str(), msg);
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
