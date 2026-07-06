//! Mycellium engine in WebAssembly (Tier 1.1, stage 1).
//!
//! Stage 1 proves the toolchain and the core crypto run correctly *in the
//! browser*: the deterministic account-id hash and real device-key generation.
//! Later stages add the pure send/receive step functions and JS-owned I/O
//! (`fetch` + IndexedDB), replacing the local Rust server entirely.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

/// Maximum attachment size, matching the native engine (attachments ride inline
/// inside the sealed envelope, so this stays well under the queue's body cap).
const MAX_ATTACHMENT: usize = 256 * 1024;
use mycellium_core::group::{Group, GroupMessage};
use mycellium_core::http::{HttpResponse, HttpTransport};
use mycellium_core::identity::{Handle, Identity};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::offline::Envelope;
use mycellium_core::pairing::{self, PairingMessage, PairingResponder, PairingResponderPublic};
use mycellium_core::platform::Platform;
use mycellium_core::record::{Record, SignedRecord};
use mycellium_core::storage::Storage;
use mycellium_core::userid::user_id as core_user_id;
use mycellium_core::wire;
use mycellium_directory_client::DirectoryClient;
use mycellium_engine::groups::{self, GroupInvitePayload, MailItem, StoredGroup};
use mycellium_engine::{antirollback, history, names, verified, wireops};
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
    let identity = Identity::generate(&mut BrowserPlatform)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(hex(&identity.wallet_public().0))
}

/// Log into a directory from the browser: generate a device identity, run the
/// challenge → sign → verify handshake over (synchronous) XHR, and return the
/// session token. Proves the *entire* client stack — transport, shared client
/// logic, and crypto — runs in WASM against a real server.
#[wasm_bindgen]
pub fn directory_login(base: &str) -> Result<String, JsValue> {
    let identity = Identity::generate(&mut BrowserPlatform)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let client = DirectoryClient::with_transport(base, Box::new(XhrTransport));
    client
        .login(&identity)
        .map_err(|e| JsValue::from_str(&e.to_string()))
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
    /// Pending device-pairing (new-device side): the ephemeral responder and its
    /// rendezvous id, kept in memory between `pair_offer` and `pair_poll`.
    pairing: Option<(mycellium_core::pairing::PairingResponder, String)>,
}

/// The device identity's persistable secret (mnemonic + device seed), from which
/// `Identity::restore` rebuilds all keys. Stored in the session's own store so it
/// round-trips through IndexedDB — the browser account survives reloads.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredIdentity {
    wallet_secret: [u8; 32],
    device_seed: [u8; 32],
}

const IDENTITY_KEY: &[u8] = b"myc:identity";

fn store_identity(store: &mut MemStore, identity: &Identity) {
    let secret = StoredIdentity {
        wallet_secret: identity.wallet_secret(),
        device_seed: identity.device_seed(),
    };
    if let Ok(bytes) = serde_json::to_vec(&secret) {
        let _ = store.put(IDENTITY_KEY, &bytes);
    }
}

#[wasm_bindgen]
impl Session {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Session {
        let identity =
            Identity::generate(&mut BrowserPlatform).expect("browser CSPRNG must be available");
        let mut store = MemStore::default();
        store_identity(&mut store, &identity);
        Session {
            store,
            identity,
            pairing: None,
        }
    }

    /// Restore a session — **the same device identity** and all state — from a
    /// snapshot previously produced by [`Session::export`].
    pub fn restore(snapshot: &[u8]) -> Result<Session, JsValue> {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = mycellium_core::wire::decode(snapshot)
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
        let store = MemStore {
            map: entries.into_iter().collect(),
        };
        let raw = store
            .get(IDENTITY_KEY)
            .ok()
            .flatten()
            .ok_or_else(|| JsValue::from_str("snapshot has no identity"))?;
        let secret: StoredIdentity = serde_json::from_slice(&raw)
            .map_err(|e| JsValue::from_str(&format!("corrupt identity: {e}")))?;
        let identity = Identity::from_wallet_secret(secret.wallet_secret, secret.device_seed)
            .map_err(|_| JsValue::from_str("stored identity is invalid"))?;
        Ok(Session {
            store,
            identity,
            pairing: None,
        })
    }

    /// This session's wallet public key (hex) — a stable id for the device.
    pub fn wallet(&self) -> String {
        hex(&self.identity.wallet_public().0)
    }

    /// Build this identity's signed directory record (wire-encoded) so a peer can
    /// seal messages to it. `handle` is the account name, `queue` its endpoint.
    pub fn record(&mut self, handle: &str, name: &str, queue: &str) -> Result<Vec<u8>, JsValue> {
        let me = Handle::new(handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let record =
            wireops::build_record(&mut BrowserPlatform, &self.identity, &me, name, queue, "");
        Ok(wire::encode(&record))
    }

    /// Seal a text message to `peer_record` (their wire-encoded [`SignedRecord`]),
    /// returning the encrypted envelope (wire-encoded) to hand to the queue.
    pub fn seal(
        &mut self,
        my_handle: &str,
        my_name: &str,
        my_queue: &str,
        peer_record: &[u8],
        text: &str,
    ) -> Result<Vec<u8>, JsValue> {
        let me = Handle::new(my_handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let record: SignedRecord = wire::decode(peer_record)
            .map_err(|e| JsValue::from_str(&format!("bad peer record: {e:?}")))?;
        let plaintext = wireops::text_message(&mut BrowserPlatform, text).encode();
        let envelope = wireops::seal_to(
            &mut BrowserPlatform,
            &self.identity,
            &me,
            my_name,
            my_queue,
            record.record.primary(),
            &plaintext,
        )
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(wire::encode(&envelope))
    }

    /// Open an encrypted envelope addressed to this session. Returns
    /// `{"from":"…","text":"…"}` JSON.
    pub fn open(&mut self, envelope: &[u8]) -> Result<String, JsValue> {
        let env: Envelope = wire::decode(envelope)
            .map_err(|e| JsValue::from_str(&format!("bad envelope: {e:?}")))?;
        let (from, plaintext) = wireops::open_envelope(&mut BrowserPlatform, &self.identity, &env)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let app = AppMessage::decode(&plaintext)
            .map_err(|e| JsValue::from_str(&format!("bad message: {e:?}")))?;
        let text = match app.body {
            Body::Text(t) => t,
            other => format!("{other:?}"),
        };
        Ok(serde_json::json!({ "from": from.as_str(), "text": text }).to_string())
    }

    /// Publish this identity's record to the directory so peers can find us.
    pub fn register(
        &mut self,
        dir_url: &str,
        queue_url: &str,
        handle: &str,
        name: &str,
    ) -> Result<(), JsValue> {
        // Merge into any existing record so renaming/re-registering never drops
        // a device that a prior link_device added to the account.
        self.publish_merged(dir_url, handle, name, queue_url)?;
        // Remember our config so group-invite processing during sync() can
        // distribute our own sender key back to members.
        let _ = self.store.put(b"myc:handle", handle.as_bytes());
        let _ = self.store.put(b"myc:name", name.as_bytes());
        let _ = self.store.put(b"myc:dir", dir_url.as_bytes());
        let _ = self.store.put(b"myc:queue", queue_url.as_bytes());
        Ok(())
    }

    /// Send a text message to `peer_handle`. Returns the number of recipient
    /// devices delivered to.
    #[allow(clippy::too_many_arguments)]
    pub fn send(
        &mut self,
        dir_url: &str,
        my_handle: &str,
        my_name: &str,
        my_queue: &str,
        peer_handle: &str,
        text: &str,
    ) -> Result<u32, JsValue> {
        let app = wireops::text_message(&mut BrowserPlatform, text);
        self.deliver_app(dir_url, my_handle, my_name, my_queue, peer_handle, app)
    }

    /// Reply to message `reply_to` in the conversation with `peer_handle`.
    #[allow(clippy::too_many_arguments)]
    pub fn reply(
        &mut self,
        dir_url: &str,
        my_handle: &str,
        my_name: &str,
        my_queue: &str,
        peer_handle: &str,
        reply_to: &str,
        text: &str,
    ) -> Result<u32, JsValue> {
        let body = Body::Reply {
            to: reply_to.to_string(),
            text: text.to_string(),
        };
        let app = wireops::app_message(&mut BrowserPlatform, body);
        self.deliver_app(dir_url, my_handle, my_name, my_queue, peer_handle, app)
    }

    /// React to message `target` with an emoji.
    #[allow(clippy::too_many_arguments)]
    pub fn react(
        &mut self,
        dir_url: &str,
        my_handle: &str,
        my_name: &str,
        my_queue: &str,
        peer_handle: &str,
        target: &str,
        emoji: &str,
    ) -> Result<u32, JsValue> {
        let body = Body::Reaction {
            to: target.to_string(),
            emoji: emoji.to_string(),
        };
        let app = wireops::app_message(&mut BrowserPlatform, body);
        self.deliver_app(dir_url, my_handle, my_name, my_queue, peer_handle, app)
    }

    /// Delete message `target` for everyone (a tombstone, applied to history).
    pub fn delete_message(
        &mut self,
        dir_url: &str,
        my_handle: &str,
        my_name: &str,
        my_queue: &str,
        peer_handle: &str,
        target: &str,
    ) -> Result<u32, JsValue> {
        let body = Body::Delete {
            to: target.to_string(),
        };
        let app = wireops::app_message(&mut BrowserPlatform, body);
        self.deliver_app(dir_url, my_handle, my_name, my_queue, peer_handle, app)
    }

    /// Send a file attachment (`data` is base64). Carried end-to-end like any
    /// other message; the servers never see the bytes in the clear.
    #[allow(clippy::too_many_arguments)]
    pub fn send_file(
        &mut self,
        dir_url: &str,
        my_handle: &str,
        my_name: &str,
        my_queue: &str,
        peer_handle: &str,
        name: &str,
        mime: &str,
        data_b64: &str,
    ) -> Result<u32, JsValue> {
        let data = B64
            .decode(data_b64)
            .map_err(|e| JsValue::from_str(&format!("bad base64: {e}")))?;
        if data.len() > MAX_ATTACHMENT {
            return Err(JsValue::from_str("attachment too large (max 256 KiB)"));
        }
        let body = Body::File {
            mime: mime.to_string(),
            name: name.to_string(),
            data,
        };
        let app = wireops::app_message(&mut BrowserPlatform, body);
        self.deliver_app(dir_url, my_handle, my_name, my_queue, peer_handle, app)
    }

    /// A scannable QR (SVG string) encoding `text` — e.g. a pairing offer.
    pub fn qr_svg(&self, text: &str) -> Result<String, JsValue> {
        let code = qrcode::QrCode::new(text.as_bytes())
            .map_err(|e| JsValue::from_str(&format!("qr: {e}")))?;
        Ok(code
            .render::<qrcode::render::svg::Color>()
            .min_dimensions(240, 240)
            .dark_color(qrcode::render::svg::Color("#0b0f0c"))
            .light_color(qrcode::render::svg::Color("#ffffff"))
            .build())
    }

    /// New device: create a one-time pairing **offer** (show it / render a QR for
    /// an existing device to scan). Keeps the ephemeral secret in the session so
    /// [`pair_poll`](Self::pair_poll) can complete it. `queue` is the rendezvous.
    pub fn pair_offer(&mut self, queue: &str) -> Result<String, JsValue> {
        let responder = PairingResponder::new(&mut BrowserPlatform);
        let mut rid = [0u8; 16];
        getrandom::getrandom(&mut rid).map_err(|e| JsValue::from_str(&format!("{e}")))?;
        let rid = hex(&rid);
        let offer = hex(
            serde_json::json!({ "r": rid, "k": hex(&responder.public().0), "q": queue })
                .to_string()
                .as_bytes(),
        );
        self.pairing = Some((responder, rid));
        Ok(offer)
    }

    /// New device: poll the rendezvous once. On success, adopt the account, join
    /// its record, and return `{dir,queue,handle,name}` JSON; otherwise
    /// `undefined` (keep polling).
    pub fn pair_poll(&mut self, queue: &str) -> Result<Option<String>, JsValue> {
        let rid = match &self.pairing {
            Some((_, rid)) => rid.clone(),
            None => return Err(JsValue::from_str("call pair_offer first")),
        };
        let qclient = QueueClient::with_transport(queue, Box::new(XhrTransport));
        let msgs = qclient
            .pair_fetch(&rid)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        for m in msgs {
            let Ok(raw) = from_hex(&m) else { continue };
            let Ok(pm) = wire::decode::<PairingMessage>(&raw) else {
                continue;
            };
            let opened = self.pairing.as_ref().and_then(|(r, _)| r.open(&pm).ok());
            if let Some(payload) = opened {
                return self.adopt_from_payload(&payload).map(Some);
            }
        }
        Ok(None)
    }

    /// Existing device: seal our account key to a pairing `offer` and relay it, so
    /// the new device can adopt the account. Shares the account key — confirm the
    /// user really means to add a device before calling this.
    pub fn pair_approve(&mut self, offer: &str, handle: &str, dir: &str) -> Result<(), JsValue> {
        let bytes = from_hex(offer.trim())?;
        let v: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| JsValue::from_str("invalid pairing offer"))?;
        let rid = v["r"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("bad offer"))?;
        let k = from_hex(
            v["k"]
                .as_str()
                .ok_or_else(|| JsValue::from_str("bad offer"))?,
        )?;
        let k: [u8; 32] = k
            .as_slice()
            .try_into()
            .map_err(|_| JsValue::from_str("bad ephemeral key"))?;
        let queue = v["q"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("bad offer"))?;
        let payload = serde_json::json!({
            "ws": hex(&self.identity.wallet_secret()),
            "h": handle,
            "n": self.cfg(b"myc:name"),
            "d": dir,
            "q": self.cfg(b"myc:queue"),
        })
        .to_string();
        let msg = pairing::seal_provisioning(
            &mut BrowserPlatform,
            &PairingResponderPublic(k),
            payload.as_bytes(),
        )
        .map_err(|e| JsValue::from_str(&format!("{e}")))?;
        QueueClient::with_transport(queue, Box::new(XhrTransport))
            .pair_post(rid, &hex(&wire::encode(&msg)))
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(())
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
        queue
            .push_key()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Register a browser push `endpoint` so the queue can wake us when closed.
    pub fn push_subscribe(&self, queue_url: &str, endpoint: &str) -> Result<(), JsValue> {
        let queue = QueueClient::with_transport(queue_url, Box::new(XhrTransport));
        let token = queue
            .login(&self.identity)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        queue
            .push_subscribe(&token, endpoint)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Drain our queue, decrypt direct messages, and store them. Returns the
    /// number of new messages received.
    /// Collect + process in one call (direct callers/tests). The worker instead
    /// calls [`sync_collect`](Self::sync_collect) then [`sync_process`](Self::sync_process)
    /// with a durable snapshot in between, so a crash after the server-side drain
    /// can't lose mail (issue #43).
    pub fn sync(&mut self, queue_url: &str) -> Result<u32, JsValue> {
        self.sync_collect(queue_url)?;
        self.sync_process()
    }

    /// **Phase 1** — drain the queue into the durable inbound store, *before* any
    /// local handling. Collecting removes the items server-side, so persisting them
    /// here (the worker snapshots after this returns) is the checkpoint that lets a
    /// later `sync_process` retry them instead of losing them on a crash. Returns
    /// how many blobs were collected.
    pub fn sync_collect(&mut self, queue_url: &str) -> Result<u32, JsValue> {
        let queue = QueueClient::with_transport(queue_url, Box::new(XhrTransport));
        let qtoken = queue
            .login(&self.identity)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let my_hex = wallet_hex(&self.identity.wallet_public());
        let my_slot = wireops::device_slot(&self.identity.device_public());
        let mut blobs = queue
            .collect(&qtoken, &my_hex, &my_slot)
            .unwrap_or_default();
        blobs.extend(
            queue
                .collect(&qtoken, &my_hex, "account")
                .unwrap_or_default(),
        );

        let now = BrowserPlatform.now_unix_secs();
        let mut pending = mycellium_engine::inbound::load(&self.store).unwrap_or_default();
        let collected = blobs.len() as u32;
        for blob in blobs {
            pending.push(mycellium_engine::inbound::PendingItem {
                blob,
                created_at: now,
                attempts: 0,
            });
        }
        let _ = mycellium_engine::inbound::save(&mut self.store, &pending);
        Ok(collected)
    }

    /// **Phase 2** — process the durable inbound store, keeping only failures for
    /// retry (e.g. a group message that arrived before its sender key); bounded by
    /// attempts/TTL so a permanently-bad item dead-letters. Returns how many items
    /// were successfully handled.
    pub fn sync_process(&mut self) -> Result<u32, JsValue> {
        let now = BrowserPlatform.now_unix_secs();
        let pending = mycellium_engine::inbound::load(&self.store).unwrap_or_default();
        let mut received = 0u32;
        let mut survivors = Vec::new();
        for mut entry in pending {
            if entry.is_expired(now) {
                continue; // dead-letter: give up
            }
            if self.process_blob(&entry.blob) {
                received += 1;
            } else {
                entry.attempts += 1;
                survivors.push(entry);
            }
        }
        let _ = mycellium_engine::inbound::save(&mut self.store, &survivors);
        Ok(received)
    }

    /// Process one collected blob; returns whether it was handled (false ⇒ keep
    /// it in the retry store for a later sync — e.g. its group key hasn't arrived).
    fn process_blob(&mut self, blob: &str) -> bool {
        let Ok(item) = serde_json::from_str::<MailItem>(blob) else {
            return false;
        };
        match item {
            MailItem::Direct(env) => {
                let Ok((from, plaintext)) =
                    wireops::open_envelope(&mut BrowserPlatform, &self.identity, &env)
                else {
                    return false;
                };
                let Ok(app) = AppMessage::decode(&plaintext) else {
                    return false;
                };
                // Learn the sender's self-set display name (carried in their record).
                let _ = names::note(
                    &mut self.store,
                    from.as_str(),
                    &env.sender_record.record.name,
                );
                apply_to_history(&mut self.store, from.as_str(), &app, false);
                true
            }
            MailItem::GroupInvite(env) => self.handle_group_invite(&env),
            MailItem::GroupText { group_id, message } => {
                self.handle_group_text(&group_id, &message)
            }
            // GroupSync / GroupLeave / SelfSync aren't handled in the browser yet
            // (a leave still safely no-ops here rather than applying a removal);
            // treat as processed so they don't retry forever.
            _ => true,
        }
    }

    /// Create a group with `members` (a JSON array of handles) and distribute our
    /// sender key to them. Returns the new group id.
    #[allow(clippy::too_many_arguments)]
    pub fn group_create(
        &mut self,
        dir_url: &str,
        my_handle: &str,
        my_name: &str,
        my_queue: &str,
        name: &str,
        members_json: &str,
    ) -> Result<String, JsValue> {
        let me = Handle::new(my_handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let members: Vec<String> = serde_json::from_str(members_json)
            .map_err(|e| JsValue::from_str(&format!("bad members: {e}")))?;
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
        let targets = stored.members.clone();
        self.distribute_key(dir_url, my_name, my_queue, &me, &stored, &group, &targets)?;
        Ok(group_id)
    }

    /// Add `new_member` to a group and re-distribute keys with the updated
    /// roster (the newcomer joins; existing members learn them and reciprocate).
    #[allow(clippy::too_many_arguments)]
    pub fn group_add(
        &mut self,
        dir_url: &str,
        my_handle: &str,
        my_name: &str,
        my_queue: &str,
        group_id: &str,
        new_member: &str,
    ) -> Result<(), JsValue> {
        let me = Handle::new(my_handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let mut stored = groups::load(&self.store, group_id)
            .map_err(|_| JsValue::from_str("store error"))?
            .ok_or_else(|| JsValue::from_str("no such group"))?;
        if stored.members.iter().any(|m| m == new_member) {
            return Err(JsValue::from_str("already a member"));
        }
        stored.members.push(new_member.to_string());
        groups::save(&mut self.store, &stored).map_err(|_| JsValue::from_str("store error"))?;
        let group = Group::import(stored.state.clone())
            .map_err(|_| JsValue::from_str("bad group state"))?;
        let targets = stored.members.clone();
        self.distribute_key(dir_url, my_name, my_queue, &me, &stored, &group, &targets)?;
        Ok(())
    }

    /// Send a text message to a group. Returns devices delivered to.
    #[allow(clippy::too_many_arguments)]
    pub fn group_send(
        &mut self,
        dir_url: &str,
        my_handle: &str,
        my_name: &str,
        my_queue: &str,
        group_id: &str,
        text: &str,
    ) -> Result<u32, JsValue> {
        let _ = (my_name, my_queue); // group messages use the group key, not a per-peer seal
        let me = Handle::new(my_handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let mut stored = groups::load(&self.store, group_id)
            .map_err(|_| JsValue::from_str("store error"))?
            .ok_or_else(|| JsValue::from_str("no such group"))?;
        let mut group = Group::import(stored.state.clone())
            .map_err(|_| JsValue::from_str("bad group state"))?;
        let app = wireops::text_message(&mut BrowserPlatform, text);
        let gm = group.encrypt(&app.encode(), &wireops::group_ad(&stored.id));
        stored.state = group.export();
        groups::save(&mut self.store, &stored).map_err(|_| JsValue::from_str("store error"))?;

        let item = MailItem::GroupText {
            group_id: stored.id.clone(),
            message: gm,
        };
        let blob = serde_json::to_string(&item).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let dir = DirectoryClient::with_transport(dir_url, Box::new(XhrTransport));
        let mut delivered = 0u32;
        for member in &stored.members {
            if member == me.as_str() {
                continue;
            }
            let Ok(handle) = Handle::new(member.clone()) else {
                continue;
            };
            let Ok(record) = dir.lookup(&handle) else {
                continue;
            };
            // Never seal to an unverifiable member record (core review).
            if record.verify().is_err() {
                continue;
            }
            let queue = QueueClient::with_transport(&record.record.queue, Box::new(XhrTransport));
            let Ok(qtoken) = queue.login(&self.identity) else {
                continue;
            };
            let peer_hex = wallet_hex(&record.record.wallet);
            for device in &record.record.devices {
                if queue
                    .deposit(
                        &qtoken,
                        &peer_hex,
                        &wireops::device_slot(&device.device_key),
                        &blob,
                    )
                    .is_ok()
                {
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

    /// Leave a group locally (stop participating; drops its keys + state).
    pub fn group_leave(&mut self, group_id: &str) -> Result<(), JsValue> {
        groups::remove(&mut self.store, group_id).map_err(|_| JsValue::from_str("store error"))?;
        Ok(())
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
    pub fn group_thread(&mut self, group_id: &str) -> Result<String, JsValue> {
        let now = BrowserPlatform.now_unix_secs();
        let msgs = history::group_load_active(&mut self.store, group_id, now)
            .map_err(|_| JsValue::from_str("store error"))?;
        serde_json::to_string(&msgs).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Store a value (UTF-8) under `key`.
    pub fn put(&mut self, key: &str, value: &str) {
        let _ = self.store.put(key.as_bytes(), value.as_bytes());
    }

    /// Read a value, or `undefined` if absent.
    pub fn get(&self, key: &str) -> Option<String> {
        self.store
            .get(key.as_bytes())
            .ok()
            .flatten()
            .map(|v| String::from_utf8_lossy(&v).into_owned())
    }

    /// Remove a key.
    pub fn del(&mut self, key: &str) {
        let _ = self.store.delete(key.as_bytes());
    }

    /// Append a message to a peer's conversation, using the **engine's own**
    /// generic history module against the browser store. Returns the message id.
    pub fn add_message(
        &mut self,
        peer: &str,
        text: &str,
        from_me: bool,
        expires_at: Option<u64>,
    ) -> Result<String, JsValue> {
        let mut id_bytes = [0u8; 8];
        getrandom::getrandom(&mut id_bytes).map_err(|e| JsValue::from_str(&format!("{e}")))?;
        let id = hex(&id_bytes);
        let message = mycellium_engine::history::StoredMessage {
            id: id.clone(),
            from_me,
            text: text.to_string(),
            timestamp: BrowserPlatform.now_unix_secs(),
            expires_at,
        };
        mycellium_engine::history::append(&mut self.store, peer, message)
            .map_err(|_| JsValue::from_str("store error"))?;
        Ok(id)
    }

    /// Load a peer's conversation as JSON (via the engine's history module).
    pub fn thread(&mut self, peer: &str) -> Result<String, JsValue> {
        // load_active prunes disappearing messages that have expired, so they
        // drop out of the view (and, on the next write, the snapshot).
        let now = BrowserPlatform.now_unix_secs();
        let messages = mycellium_engine::history::load_active(&mut self.store, peer, now)
            .map_err(|_| JsValue::from_str("store error"))?;
        serde_json::to_string(&messages).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// The conversation list as JSON: `[{peer, last, timestamp, mine}]`, newest
    /// first — for rendering the threads screen.
    pub fn peers(&mut self) -> Result<String, JsValue> {
        let now = BrowserPlatform.now_unix_secs();
        let peers = mycellium_engine::history::peers(&self.store)
            .map_err(|_| JsValue::from_str("store error"))?;
        let mut out = Vec::new();
        for peer in peers {
            let msgs = mycellium_engine::history::load_active(&mut self.store, &peer, now)
                .map_err(|_| JsValue::from_str("store error"))?;
            let last = msgs.last();
            let name = names::get(&self.store, &peer)
                .ok()
                .flatten()
                .unwrap_or_default();
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
        let entries: Vec<(Vec<u8>, Vec<u8>)> = self
            .store
            .map
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        mycellium_core::wire::encode(&entries)
    }

    /// Restore a previously exported snapshot (from IndexedDB).
    pub fn import(&mut self, bytes: &[u8]) -> Result<(), JsValue> {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = mycellium_core::wire::decode(bytes)
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
        self.store.map = entries.into_iter().collect();
        Ok(())
    }
}

impl Session {
    /// Adopt the account carried in a decrypted pairing payload: replace this
    /// device's identity with the received account (fresh device keys), join its
    /// record, persist config, and return `{dir,queue,handle,name}` JSON.
    fn adopt_from_payload(&mut self, payload: &[u8]) -> Result<String, JsValue> {
        let v: serde_json::Value =
            serde_json::from_slice(payload).map_err(|_| JsValue::from_str("bad provisioning"))?;
        let ws = from_hex(
            v["ws"]
                .as_str()
                .ok_or_else(|| JsValue::from_str("bad provisioning"))?,
        )?;
        let ws: [u8; 32] = ws
            .as_slice()
            .try_into()
            .map_err(|_| JsValue::from_str("bad account key"))?;
        let handle = v["h"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("bad provisioning"))?;
        let name = v["n"].as_str().filter(|s| !s.is_empty()).unwrap_or(handle);
        let dir = v["d"].as_str().unwrap_or("");
        let queue = v["q"].as_str().unwrap_or("");

        self.identity = Identity::adopt(&mut BrowserPlatform, ws)
            .map_err(|_| JsValue::from_str("invalid account key"))?;
        store_identity(&mut self.store, &self.identity);
        self.publish_merged(dir, handle, name, queue)?;
        let _ = self.store.put(b"myc:handle", handle.as_bytes());
        let _ = self.store.put(b"myc:name", name.as_bytes());
        let _ = self.store.put(b"myc:dir", dir.as_bytes());
        let _ = self.store.put(b"myc:queue", queue.as_bytes());
        let _ = self.store.put(
            b"myc:me",
            serde_json::json!({ "handle": handle, "name": name })
                .to_string()
                .as_bytes(),
        );
        self.pairing = None;
        Ok(
            serde_json::json!({ "dir": dir, "queue": queue, "handle": handle, "name": name })
                .to_string(),
        )
    }

    /// Publish our record, **merging** this device into any record that already
    /// exists for the handle, so re-registering or linking never drops sibling
    /// devices. Bumps `seq` past the existing one.
    fn publish_merged(
        &self,
        dir_url: &str,
        handle: &str,
        name: &str,
        queue_url: &str,
    ) -> Result<(), JsValue> {
        let me = Handle::new(handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let dir = DirectoryClient::with_transport(dir_url, Box::new(XhrTransport));
        let existing = dir.lookup(&me).ok();
        let mut devices = existing
            .as_ref()
            .map(|r| r.record.devices.clone())
            .unwrap_or_default();
        let mine = wireops::this_device(&self.identity, "");
        if !devices.iter().any(|d| d.device_key == mine.device_key) {
            devices.push(mine);
        }
        let now = BrowserPlatform.now_unix_secs();
        let seq = existing
            .as_ref()
            .map(|r| r.record.seq + 1)
            .unwrap_or(now)
            .max(now);
        let record = Record {
            handle: core_user_id(handle),
            name: name.to_string(),
            wallet: self.identity.wallet_public(),
            queue: queue_url.to_string(),
            queues: vec![],
            devices,
            seq,
        };
        let signed = SignedRecord::sign(record, &self.identity);
        let token = dir
            .login(&self.identity)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        dir.publish(&token, &me, &signed)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(())
    }

    /// Shared delivery path: look up the peer, X3DH-seal `app` to each of their
    /// devices, deposit to their queue, and record our own copy.
    #[allow(clippy::too_many_arguments)]
    fn deliver_app(
        &mut self,
        dir_url: &str,
        my_handle: &str,
        my_name: &str,
        my_queue: &str,
        peer_handle: &str,
        app: AppMessage,
    ) -> Result<u32, JsValue> {
        let me = Handle::new(my_handle).map_err(|_| JsValue::from_str("invalid handle"))?;
        let peer =
            Handle::new(peer_handle).map_err(|_| JsValue::from_str("invalid peer handle"))?;
        let dir = DirectoryClient::with_transport(dir_url, Box::new(XhrTransport));
        let precord = dir
            .lookup(&peer)
            .map_err(|e| JsValue::from_str(&format!("lookup: {e}")))?;
        // The directory does not verify records; check the self-signature before we
        // trust its device keys / queue (core review).
        precord
            .verify()
            .map_err(|_| JsValue::from_str("peer record failed verification"))?;
        // Fail closed if the peer's wallet no longer matches the pinned/verified one
        // (impersonation) or the directory served an older record than we've seen
        // (rollback) — the browser send path must not silently trust a swapped or
        // stale record (core review, HIGH).
        if matches!(
            verified::level(&self.store, peer.as_str(), &precord.record.wallet),
            verified::TrustLevel::Changed
        ) {
            return Err(JsValue::from_str(
                "identity changed for this peer — refusing to send",
            ));
        }
        if let Ok(false) =
            antirollback::check_and_pin(&mut self.store, peer.as_str(), precord.record.seq)
        {
            return Err(JsValue::from_str(
                "stale record for this peer — refusing to send",
            ));
        }
        // Learn the peer's chosen display name from their record.
        let _ = names::note(&mut self.store, peer_handle, &precord.record.name);
        let plaintext = app.encode();
        let queue = QueueClient::with_transport(&precord.record.queue, Box::new(XhrTransport));
        let qtoken = queue
            .login(&self.identity)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let peer_hex = wallet_hex(&precord.record.wallet);
        let mut delivered = 0u32;
        for device in &precord.record.devices {
            let Ok(env) = wireops::seal_to(
                &mut BrowserPlatform,
                &self.identity,
                &me,
                my_name,
                my_queue,
                device,
                &plaintext,
            ) else {
                continue;
            };
            let blob = serde_json::to_string(&MailItem::Direct(env))
                .map_err(|e| JsValue::from_str(&e.to_string()))?;
            if queue
                .deposit(
                    &qtoken,
                    &peer_hex,
                    &wireops::device_slot(&device.device_key),
                    &blob,
                )
                .is_ok()
            {
                delivered += 1;
            }
        }
        apply_to_history(&mut self.store, peer_handle, &app, true);
        Ok(delivered)
    }

    /// Read a stored config value (empty if unset).
    fn cfg(&self, key: &[u8]) -> String {
        self.store
            .get(key)
            .ok()
            .flatten()
            .map(|v| String::from_utf8_lossy(&v).into_owned())
            .unwrap_or_default()
    }

    /// Seal our group sender-key (a `GroupInvitePayload`) to `targets`' devices.
    #[allow(clippy::too_many_arguments)]
    fn distribute_key(
        &self,
        dir_url: &str,
        my_name: &str,
        my_queue: &str,
        me: &Handle,
        stored: &StoredGroup,
        group: &Group,
        targets: &[String],
    ) -> Result<(), JsValue> {
        let payload = GroupInvitePayload {
            group_id: stored.id.clone(),
            name: stored.name.clone(),
            members: stored.members.clone(),
            sender_id: wireops::my_group_id(&self.identity),
            distribution: group.distribution(),
        };
        let plaintext =
            serde_json::to_vec(&payload).map_err(|e| JsValue::from_str(&e.to_string()))?;
        let dir = DirectoryClient::with_transport(dir_url, Box::new(XhrTransport));
        for member in targets {
            let Ok(handle) = Handle::new(member.clone()) else {
                continue;
            };
            let Ok(record) = dir.lookup(&handle) else {
                continue;
            };
            // Never seal to an unverifiable member record (core review).
            if record.verify().is_err() {
                continue;
            }
            let queue = QueueClient::with_transport(&record.record.queue, Box::new(XhrTransport));
            let Ok(qtoken) = queue.login(&self.identity) else {
                continue;
            };
            let peer_hex = wallet_hex(&record.record.wallet);
            for device in &record.record.devices {
                if device.device_key == self.identity.device_public() {
                    continue; // never this exact device
                }
                let Ok(env) = wireops::seal_to(
                    &mut BrowserPlatform,
                    &self.identity,
                    me,
                    my_name,
                    my_queue,
                    device,
                    &plaintext,
                ) else {
                    continue;
                };
                let Ok(blob) = serde_json::to_string(&MailItem::GroupInvite(env)) else {
                    continue;
                };
                let _ = queue.deposit(
                    &qtoken,
                    &peer_hex,
                    &wireops::device_slot(&device.device_key),
                    &blob,
                );
            }
        }
        Ok(())
    }

    /// Process a received group invite: join the group (or learn a member's key)
    /// and record the sender key so we can decrypt their messages.
    /// Returns whether the invite was processed (false ⇒ keep it for retry).
    fn handle_group_invite(&mut self, env: &Envelope) -> bool {
        let Ok((from, bytes)) = wireops::open_envelope(&mut BrowserPlatform, &self.identity, env)
        else {
            return false;
        };
        let Ok(payload) = serde_json::from_slice::<GroupInvitePayload>(&bytes) else {
            return false;
        };
        let sender_id = payload.sender_id.clone();
        let (dir, name, queue, mine) = (
            self.cfg(b"myc:dir"),
            self.cfg(b"myc:name"),
            self.cfg(b"myc:queue"),
            self.cfg(b"myc:handle"),
        );
        let Ok(me) = Handle::new(mine.clone()) else {
            return false;
        };
        match groups::load(&self.store, &payload.group_id).ok().flatten() {
            Some(mut stored) => {
                // An invite for a group we're already in is only trustworthy from
                // an existing member (the group id is cleartext in every group
                // MailItem) — ignore non-members (core review, MEDIUM).
                if !stored.members.iter().any(|m| m == from.as_str()) {
                    return true;
                }
                let Ok(mut group) = Group::import(stored.state.clone()) else {
                    return false;
                };
                let _ = group.add_member(sender_id.clone(), &payload.distribution);
                stored.note_sender(sender_id, from.as_str());
                // Learn any members we didn't know about, and send them our key.
                let newcomers: Vec<String> = payload
                    .members
                    .iter()
                    .filter(|m| !stored.members.iter().any(|x| x == *m))
                    .cloned()
                    .collect();
                stored.members.extend(newcomers.iter().cloned());
                stored.state = group.export();
                let _ = groups::save(&mut self.store, &stored);
                if !newcomers.is_empty() {
                    let _ =
                        self.distribute_key(&dir, &name, &queue, &me, &stored, &group, &newcomers);
                }
            }
            None => {
                let mut group =
                    Group::new(&mut BrowserPlatform, wireops::my_group_id(&self.identity));
                let _ = group.add_member(sender_id.clone(), &payload.distribution);
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
                // Reply with our own sender key so everyone can read us too.
                let targets = stored.members.clone();
                let _ = self.distribute_key(&dir, &name, &queue, &me, &stored, &group, &targets);
            }
        }
        true
    }

    /// Decrypt a received group message and store it. Returns whether it was
    /// processed (false ⇒ we don't have the group/sender key yet — keep for retry).
    fn handle_group_text(&mut self, group_id: &str, message: &GroupMessage) -> bool {
        let Some(mut stored) = groups::load(&self.store, group_id).ok().flatten() else {
            return false;
        };
        let sender = stored
            .handle_of(&message.sender)
            .map(str::to_string)
            .unwrap_or_else(|| String::from_utf8_lossy(&message.sender).into_owned());
        let Ok(mut group) = Group::import(stored.state.clone()) else {
            return false;
        };
        let Ok(plaintext) = group.decrypt(message, &wireops::group_ad(group_id)) else {
            return false;
        };
        {
            stored.state = group.export();
            let _ = groups::save(&mut self.store, &stored);
            if let Ok(app) = AppMessage::decode(&plaintext) {
                match &app.body {
                    Body::Edit { to, text } => {
                        let _ = history::group_edit(&mut self.store, group_id, to, text, &sender);
                    }
                    Body::Delete { to } => {
                        let _ = history::group_delete(&mut self.store, group_id, to, &sender);
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
        true
    }
}

/// Apply a sent/received message to a conversation: edits/deletes mutate the
/// referenced message, everything else appends. `from_me` marks the direction.
fn apply_to_history(store: &mut MemStore, peer: &str, app: &AppMessage, from_me: bool) {
    match &app.body {
        Body::Edit { to, text } => {
            let _ = history::edit(store, peer, to, text, from_me);
        }
        Body::Delete { to } => {
            let _ = history::delete(store, peer, to, from_me);
            // Drop the attachment blob too, so a deleted image doesn't linger.
            let _ = store.delete(format!("file:{to}").as_bytes());
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
        xhr.open_with_async(method, url, false)
            .map_err(|e| format!("open: {e:?}"))?;
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
        Ok(HttpResponse {
            status,
            body: text.into_bytes(),
        })
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

fn from_hex(s: &str) -> Result<Vec<u8>, JsValue> {
    if !s.len().is_multiple_of(2) {
        return Err(JsValue::from_str("odd-length hex"));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| JsValue::from_str("bad hex"))
        })
        .collect()
}
