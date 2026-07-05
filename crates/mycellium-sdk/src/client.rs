//! The stateful native client object bound across UniFFI.
//!
//! [`MyceliumClient`] mirrors the proven wasm `Session` façade over the engine,
//! but (a) over the native encrypted [`FileStore`] instead of the browser's
//! in-memory store, (b) over the native `ureq` [`UreqTransport`] instead of the
//! browser XHR transport, and (c) holding config (directory/queue URLs, handle,
//! name) as client state rather than passing it on every call.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use mycellium_core::group::Group as CoreGroup;
use mycellium_core::identity::{Handle, Identity};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::pairing::{self, PairingMessage, PairingResponder, PairingResponderPublic};
use mycellium_core::record::{Record, SignedRecord};
use mycellium_core::storage::Storage;
use mycellium_core::userid::user_id;
use mycellium_core::{safety, wire};
use mycellium_directory_client::DirectoryClient;
use mycellium_engine::groups::{
    self, GroupInvitePayload, GroupLeavePayload, GroupSyncPayload, MailItem, StoredGroup,
};
use mycellium_engine::platform::OsPlatform;
use mycellium_engine::{contacts, history, inbound, names, verified, wireops};
use mycellium_http::UreqTransport;
use mycellium_queue_client::{wallet_hex, QueueClient};

use mycellium_core::platform::Platform;
use mycellium_storage::filestore::FileStore;

use crate::types::{
    Account, Contact, Conversation, DeliveryState, EventListener, Group, Message, SdkError,
    TrustLevel,
};

/// Maximum inline attachment size, matching the engine/wasm cap. Attachments
/// ride inside the sealed envelope, so this stays well under the queue's body cap.
const MAX_ATTACHMENT: usize = 256 * 1024;

// TODO(#64 follow-up): the C-ABI desktop surface (a `cdylib`/`staticlib` shim
// for desktop clients) and smoke tests that load the *generated* Kotlin/Swift
// bindings. The Rust messaging/contacts/verification/pairing/groups/backup
// surface below is complete and covered by `tests/sdk.rs`.

/// The mailbox slot for account-wide items (matches the engine's `ACCOUNT_SLOT`).
const ACCOUNT_SLOT: &str = "account";

// Config keys, matching the wasm Session's `myc:*` layout so a future shared
// snapshot format stays compatible.
const K_DIR: &[u8] = b"myc:dir";
const K_QUEUE: &[u8] = b"myc:queue";
const K_HANDLE: &[u8] = b"myc:handle";
const K_NAME: &[u8] = b"myc:name";

/// The device identity's persistable secret. Lives in a sidecar file under
/// `data_dir` (NOT inside the [`FileStore`], which is itself keyed by the
/// identity, so it can't hold its own key). #65 replaces this with an
/// OS-secure-storage adapter behind the same API.
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    wallet_secret: [u8; 32],
    device_seed: [u8; 32],
}

/// Client configuration, persisted in the store and cached in memory.
#[derive(Default, Clone)]
struct Config {
    dir_url: String,
    queue_url: String,
    handle: String,
    name: String,
}

/// The locked interior: everything one client instance owns.
struct Inner {
    /// The data-dir root (holds the identity sidecar + the `store/` directory).
    /// Kept so pairing can re-key the store and backup can snapshot it.
    root: PathBuf,
    store: FileStore,
    identity: Identity,
    config: Config,
    listener: Option<Arc<dyn EventListener>>,
    /// Pending device-pairing (new-device side): the ephemeral responder and its
    /// rendezvous id, held between `pair_offer` and `pair_poll`.
    pairing: Option<(PairingResponder, String)>,
}

/// A stable, stateful handle to one Mycellium account on one device. All methods
/// are `&self`; interior state is guarded by a `Mutex`, so the object is `Send +
/// Sync` and safe to share across the foreign runtime.
#[derive(uniffi::Object)]
pub struct MyceliumClient {
    inner: Mutex<Inner>,
}

#[uniffi::export]
impl MyceliumClient {
    /// Open (or create) a client rooted at `data_dir`: load-or-create the device
    /// identity, open its encrypted store, and load any persisted config.
    #[uniffi::constructor]
    pub fn new(data_dir: String) -> Result<Arc<Self>, SdkError> {
        let root = PathBuf::from(&data_dir);
        std::fs::create_dir_all(&root).map_err(SdkError::storage)?;

        let identity = load_or_create_identity(&root)?;
        let store = FileStore::open(root.join("store"), identity.storage_key())
            .map_err(SdkError::storage)?;
        let config = Config {
            dir_url: cfg_get(&store, K_DIR),
            queue_url: cfg_get(&store, K_QUEUE),
            handle: cfg_get(&store, K_HANDLE),
            name: cfg_get(&store, K_NAME),
        };

        Ok(Arc::new(MyceliumClient {
            inner: Mutex::new(Inner {
                root,
                store,
                identity,
                config,
                listener: None,
                pairing: None,
            }),
        }))
    }

    /// This device's account (handle/name empty until `register`).
    pub fn account(&self) -> Account {
        let inner = self.lock();
        Account {
            handle: inner.config.handle.clone(),
            name: inner.config.name.clone(),
            wallet_address: wireops::hex(&inner.identity.wallet_public().0),
        }
    }

    /// This account's wallet public key as lowercase hex — a stable account id.
    pub fn wallet_address(&self) -> String {
        wireops::hex(&self.lock().identity.wallet_public().0)
    }

    /// Publish this identity's directory record (merging into any existing record
    /// so sibling devices are never dropped) and persist the config.
    pub fn register(
        &self,
        dir_url: String,
        queue_url: String,
        handle: String,
        name: String,
    ) -> Result<(), SdkError> {
        let mut inner = self.lock();
        publish_merged(&inner.identity, &dir_url, &handle, &name, &queue_url)?;

        inner
            .store
            .put(K_DIR, dir_url.as_bytes())
            .map_err(SdkError::storage)?;
        inner
            .store
            .put(K_QUEUE, queue_url.as_bytes())
            .map_err(SdkError::storage)?;
        inner
            .store
            .put(K_HANDLE, handle.as_bytes())
            .map_err(SdkError::storage)?;
        inner
            .store
            .put(K_NAME, name.as_bytes())
            .map_err(SdkError::storage)?;
        inner.config = Config {
            dir_url,
            queue_url,
            handle,
            name,
        };
        Ok(())
    }

    /// Send a text message to `peer_handle` using the stored config: look the peer
    /// up, seal one copy per device, deposit to their queue, and record our own
    /// copy. Returns the stored [`Message`].
    pub fn send_text(&self, peer_handle: String, text: String) -> Result<Message, SdkError> {
        let app = wireops::text_message(&mut OsPlatform, &text);
        self.deliver_app(peer_handle, app)
    }

    /// Reply to message `reply_to` in the conversation with `peer_handle`.
    pub fn reply(
        &self,
        peer_handle: String,
        reply_to: String,
        text: String,
    ) -> Result<Message, SdkError> {
        let body = Body::Reply { to: reply_to, text };
        let app = wireops::app_message(&mut OsPlatform, body);
        self.deliver_app(peer_handle, app)
    }

    /// React to message `target` (in the conversation with `peer_handle`) with an
    /// emoji.
    pub fn react(
        &self,
        peer_handle: String,
        target: String,
        emoji: String,
    ) -> Result<Message, SdkError> {
        let body = Body::Reaction { to: target, emoji };
        let app = wireops::app_message(&mut OsPlatform, body);
        self.deliver_app(peer_handle, app)
    }

    /// Delete message `target` for everyone (a tombstone applied to the
    /// transcript on both sides).
    pub fn delete_message(&self, peer_handle: String, target: String) -> Result<(), SdkError> {
        let body = Body::Delete { to: target };
        let app = wireops::app_message(&mut OsPlatform, body);
        self.deliver_app(peer_handle, app)?;
        Ok(())
    }

    /// Send a file attachment to `peer_handle`. Carried end-to-end inside the
    /// sealed envelope like any other message; the servers never see the bytes.
    pub fn send_file(
        &self,
        peer_handle: String,
        name: String,
        mime: String,
        data: Vec<u8>,
    ) -> Result<Message, SdkError> {
        if data.len() > MAX_ATTACHMENT {
            return Err(SdkError::invalid("attachment too large (max 256 KiB)"));
        }
        let body = Body::File { mime, name, data };
        let app = wireops::app_message(&mut OsPlatform, body);
        self.deliver_app(peer_handle, app)
    }

    /// Drain our queue, decrypt direct messages, apply them to history, and return
    /// the new inbound messages. Also fires `on_message` for each via the stored
    /// listener, if one is set.
    pub fn sync(&self) -> Result<Vec<Message>, SdkError> {
        // Collect + process under the lock, then fire callbacks after releasing it
        // (so foreign listener code can't deadlock on our mutex).
        let (messages, listener) = {
            let mut inner = self.lock();
            if inner.config.queue_url.is_empty() {
                return Err(SdkError::NotRegistered);
            }

            let queue =
                QueueClient::with_transport(&inner.config.queue_url, Box::new(UreqTransport));
            let qtoken = queue.login(&inner.identity).map_err(SdkError::network)?;
            let my_hex = wallet_hex(&inner.identity.wallet_public());
            let my_slot = wireops::device_slot(&inner.identity.device_public());

            let mut blobs = queue
                .collect(&qtoken, &my_hex, &my_slot)
                .unwrap_or_default();
            blobs.extend(
                queue
                    .collect(&qtoken, &my_hex, ACCOUNT_SLOT)
                    .unwrap_or_default(),
            );

            // Durability (issue #64/#43): collecting drains the mailbox
            // server-side, so persist every blob to the inbound retry store
            // BEFORE processing. A blob that can't be decrypted/processed yet
            // (e.g. a group message whose sender key hasn't arrived) or that hits
            // a transient error is then retried on the next sync instead of being
            // silently lost — bounded by attempts/TTL so a bad item dead-letters.
            let now = OsPlatform.now_unix_secs();
            let mut pending = inbound::load(&inner.store).unwrap_or_default();
            for blob in blobs {
                pending.push(inbound::PendingItem {
                    blob,
                    created_at: now,
                    attempts: 0,
                });
            }
            inbound::save(&mut inner.store, &pending).map_err(SdkError::storage)?;

            let mut received = Vec::new();
            let mut survivors = Vec::new();
            for mut entry in pending {
                if entry.is_expired(now) {
                    continue; // dead-letter: give up
                }
                match process_blob(&mut inner, &entry.blob) {
                    Processed::Done(Some(msg)) => received.push(msg),
                    Processed::Done(None) => {}
                    Processed::Retry => {
                        entry.attempts += 1;
                        survivors.push(entry);
                    }
                }
            }
            inbound::save(&mut inner.store, &survivors).map_err(SdkError::storage)?;
            (received, inner.listener.clone())
        };

        if let Some(l) = listener {
            for m in &messages {
                l.on_message(m.clone());
            }
        }
        Ok(messages)
    }

    /// Register (or replace) the listener the SDK pushes incoming events to.
    pub fn set_listener(&self, listener: Box<dyn EventListener>) {
        self.lock().listener = Some(Arc::from(listener));
    }

    /// The conversation list, newest first.
    pub fn conversations(&self) -> Result<Vec<Conversation>, SdkError> {
        let mut inner = self.lock();
        let now = OsPlatform.now_unix_secs();
        let peers = history::peers(&inner.store).map_err(SdkError::storage)?;
        let mut out = Vec::new();
        for peer in peers {
            let msgs =
                history::load_active(&mut inner.store, &peer, now).map_err(SdkError::storage)?;
            let last = msgs.last();
            let display_name = names::get(&inner.store, &peer)
                .map_err(SdkError::storage)?
                .unwrap_or_default();
            out.push(Conversation {
                peer,
                display_name,
                last_preview: last.map(|m| m.text.clone()).unwrap_or_default(),
                last_at: last.map(|m| m.timestamp).unwrap_or(0),
            });
        }
        out.sort_by_key(|c| std::cmp::Reverse(c.last_at));
        Ok(out)
    }

    /// The transcript with `peer_handle` (expired messages pruned), oldest first.
    pub fn thread(&self, peer_handle: String) -> Result<Vec<Message>, SdkError> {
        let mut inner = self.lock();
        let now = OsPlatform.now_unix_secs();
        let my_handle = inner.config.handle.clone();
        let msgs =
            history::load_active(&mut inner.store, &peer_handle, now).map_err(SdkError::storage)?;
        Ok(msgs
            .into_iter()
            .map(|m| to_message(m, &peer_handle, &my_handle))
            .collect())
    }

    /// Read a free-form setting value, or `None` if unset.
    pub fn get_setting(&self, key: String) -> Option<String> {
        let inner = self.lock();
        inner
            .store
            .get(&setting_key(&key))
            .ok()
            .flatten()
            .map(|v| String::from_utf8_lossy(&v).into_owned())
    }

    /// Store a free-form setting value.
    pub fn set_setting(&self, key: String, value: String) {
        let mut inner = self.lock();
        let _ = inner.store.put(&setting_key(&key), value.as_bytes());
    }

    // ---- contacts (address book, TOFU-pinned) -------------------------------

    /// Add an address-book contact: look up `handle` in the directory, verify its
    /// record, and **pin** its wallet (trust-on-first-use). A later lookup whose
    /// wallet differs from the pin surfaces as an identity change.
    pub fn add_contact(&self, nickname: String, handle: String) -> Result<(), SdkError> {
        let mut inner = self.lock();
        let h = Handle::new(handle).map_err(SdkError::invalid)?;
        let dir = DirectoryClient::with_transport(&inner.config.dir_url, Box::new(UreqTransport));
        let record = dir.lookup(&h).map_err(SdkError::network)?;
        record
            .verify()
            .map_err(|_| SdkError::crypto("that handle's record failed verification"))?;
        let contact = contacts::Contact {
            nickname,
            handle: h.as_str().to_string(),
            wallet: record.record.wallet,
        };
        contacts::save(&mut inner.store, &contact).map_err(SdkError::storage)?;
        Ok(())
    }

    /// The saved contacts, each with its current trust level against the pinned
    /// wallet.
    pub fn contacts(&self) -> Vec<Contact> {
        let inner = self.lock();
        contacts::list(&inner.store)
            .unwrap_or_default()
            .into_iter()
            .map(|c| {
                let trust: TrustLevel = verified::level(&inner.store, &c.handle, &c.wallet).into();
                Contact {
                    nickname: c.nickname,
                    handle: c.handle,
                    trust,
                }
            })
            .collect()
    }

    /// Remove a contact by nickname.
    pub fn remove_contact(&self, nickname: String) -> Result<(), SdkError> {
        let mut inner = self.lock();
        contacts::remove(&mut inner.store, &nickname).map_err(SdkError::storage)
    }

    // ---- out-of-band verification -------------------------------------------

    /// The safety number to compare out of band with `peer_handle` — a short code
    /// derived from both parties' wallet identity keys. Equal on both devices;
    /// changes entirely if either identity differs from what's expected.
    pub fn safety_number(&self, peer_handle: String) -> Result<String, SdkError> {
        let inner = self.lock();
        let peer = Handle::new(peer_handle).map_err(SdkError::invalid)?;
        let dir = DirectoryClient::with_transport(&inner.config.dir_url, Box::new(UreqTransport));
        let record = dir.lookup(&peer).map_err(SdkError::network)?;
        record
            .verify()
            .map_err(|_| SdkError::crypto("peer record failed verification"))?;
        Ok(safety::safety_number(
            &inner.identity.wallet_public(),
            &record.record.wallet,
        ))
    }

    /// Mark `peer_handle` verified out of band: pin the wallet the directory
    /// currently serves as confirmed. A later change to it will then be flagged.
    pub fn mark_verified(&self, peer_handle: String) -> Result<(), SdkError> {
        let mut inner = self.lock();
        let peer = Handle::new(peer_handle).map_err(SdkError::invalid)?;
        let dir = DirectoryClient::with_transport(&inner.config.dir_url, Box::new(UreqTransport));
        let record = dir.lookup(&peer).map_err(SdkError::network)?;
        record
            .verify()
            .map_err(|_| SdkError::crypto("peer record failed verification"))?;
        verified::mark(&mut inner.store, peer.as_str(), &record.record.wallet)
            .map_err(SdkError::storage)?;
        Ok(())
    }

    /// How much the wallet the directory currently serves for `peer_handle` is
    /// trusted, given any TOFU pin / out-of-band verification.
    pub fn trust_level(&self, peer_handle: String) -> Result<TrustLevel, SdkError> {
        let inner = self.lock();
        let peer = Handle::new(peer_handle).map_err(SdkError::invalid)?;
        let dir = DirectoryClient::with_transport(&inner.config.dir_url, Box::new(UreqTransport));
        let record = dir.lookup(&peer).map_err(SdkError::network)?;
        record
            .verify()
            .map_err(|_| SdkError::crypto("peer record failed verification"))?;
        Ok(verified::level(&inner.store, peer.as_str(), &record.record.wallet).into())
    }

    /// Emit **this account's** contact card — a compact hex-encoded `{handle,
    /// wallet}` to show out of band so a peer can verify us without reading a long
    /// safety number aloud. The wallet is public, so the card carries no secret.
    pub fn contact_card(&self) -> Result<String, SdkError> {
        let inner = self.lock();
        if inner.config.handle.is_empty() {
            return Err(SdkError::NotRegistered);
        }
        let card = serde_json::json!({
            "v": 1,
            "h": inner.config.handle,
            "w": wireops::hex(&inner.identity.wallet_public().0),
        })
        .to_string();
        Ok(wireops::hex(card.as_bytes()))
    }

    /// Verify a peer's contact `card`: parse it, look its handle up in the
    /// directory, and compare the card's wallet (which reached us out of band)
    /// against the record served. A match marks the handle verified and returns
    /// it; a mismatch means the directory served a different identity (a possible
    /// MITM) and maps to [`SdkError::IdentityChanged`].
    pub fn verify_card(&self, card: String) -> Result<String, SdkError> {
        let mut inner = self.lock();
        let bytes = from_hex(card.trim())?;
        let v: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| SdkError::invalid("invalid contact card"))?;
        let handle = v["h"]
            .as_str()
            .ok_or_else(|| SdkError::invalid("malformed card"))?;
        let card_wallet = v["w"]
            .as_str()
            .ok_or_else(|| SdkError::invalid("malformed card"))?;
        let h = Handle::new(handle).map_err(SdkError::invalid)?;
        let dir = DirectoryClient::with_transport(&inner.config.dir_url, Box::new(UreqTransport));
        let record = dir.lookup(&h).map_err(SdkError::network)?;
        record
            .verify()
            .map_err(|_| SdkError::crypto("that handle's record failed verification"))?;
        if wireops::hex(&record.record.wallet.0) != card_wallet {
            return Err(SdkError::IdentityChanged {
                handle: handle.to_string(),
            });
        }
        verified::mark(&mut inner.store, handle, &record.record.wallet)
            .map_err(SdkError::storage)?;
        Ok(handle.to_string())
    }

    // ---- seedless device pairing --------------------------------------------

    /// **New device**: mint a one-time pairing offer (hex — render it as a QR for
    /// an existing device to scan). Keeps the ephemeral secret in memory so
    /// [`pair_poll`](Self::pair_poll) can complete it. `queue_url` is the
    /// rendezvous both devices meet on.
    pub fn pair_offer(&self, queue_url: String) -> Result<String, SdkError> {
        let (offer, listener) = {
            let mut inner = self.lock();
            let responder = PairingResponder::new(&mut OsPlatform);
            let mut rid = [0u8; 16];
            OsPlatform.fill_random(&mut rid);
            let rid = wireops::hex(&rid);
            let offer = wireops::hex(
                serde_json::json!({
                    "r": rid,
                    "k": wireops::hex(&responder.public().0),
                    "q": queue_url,
                })
                .to_string()
                .as_bytes(),
            );
            inner.pairing = Some((responder, rid));
            (offer, inner.listener.clone())
        };
        if let Some(l) = listener {
            l.on_pairing("offered".to_string());
        }
        Ok(offer)
    }

    /// **New device**: poll the rendezvous once. On success, adopt the account
    /// (re-key the local store to it), join its directory record, persist config,
    /// and return the adopted [`Account`]; otherwise `None` (keep polling).
    pub fn pair_poll(&self, queue_url: String) -> Result<Option<Account>, SdkError> {
        let (account, listener) = {
            let mut inner = self.lock();
            let rid = match &inner.pairing {
                Some((_, rid)) => rid.clone(),
                None => return Err(SdkError::invalid("call pair_offer first")),
            };
            let queue = QueueClient::with_transport(&queue_url, Box::new(UreqTransport));
            let msgs = queue.pair_fetch(&rid).map_err(SdkError::network)?;
            let mut adopted = None;
            for m in msgs {
                let Ok(raw) = from_hex(&m) else { continue };
                let Ok(pm) = wire::decode::<PairingMessage>(&raw) else {
                    continue;
                };
                let opened = inner.pairing.as_ref().and_then(|(r, _)| r.open(&pm).ok());
                if let Some(payload) = opened {
                    adopted = Some(self.adopt_from_payload(&mut inner, &payload)?);
                    break;
                }
            }
            (adopted, inner.listener.clone())
        };
        if account.is_some() {
            if let Some(l) = listener {
                l.on_pairing("paired".to_string());
            }
        }
        Ok(account)
    }

    /// **Existing device**: seal this account's key to a pairing `offer` and relay
    /// it through the rendezvous, so the new device can adopt the account. Shares
    /// the account key — confirm the user really means to add a device first.
    pub fn pair_approve(&self, offer: String, queue_url: String) -> Result<(), SdkError> {
        let listener = {
            let inner = self.lock();
            if inner.config.handle.is_empty() {
                return Err(SdkError::NotRegistered);
            }
            let bytes = from_hex(offer.trim())?;
            let v: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|_| SdkError::invalid("invalid pairing offer"))?;
            let rid = v["r"]
                .as_str()
                .ok_or_else(|| SdkError::invalid("bad offer"))?;
            let k = from_hex(
                v["k"]
                    .as_str()
                    .ok_or_else(|| SdkError::invalid("bad offer"))?,
            )?;
            let k: [u8; 32] = k
                .as_slice()
                .try_into()
                .map_err(|_| SdkError::invalid("bad ephemeral key"))?;
            let payload = serde_json::json!({
                "ws": wireops::hex(&inner.identity.wallet_secret()),
                "h": inner.config.handle,
                "n": inner.config.name,
                "d": inner.config.dir_url,
                "q": inner.config.queue_url,
            })
            .to_string();
            let msg = pairing::seal_provisioning(
                &mut OsPlatform,
                &PairingResponderPublic(k),
                payload.as_bytes(),
            )
            .map_err(|e| SdkError::crypto(format!("{e:?}")))?;
            QueueClient::with_transport(&queue_url, Box::new(UreqTransport))
                .pair_post(rid, &wireops::hex(&wire::encode(&msg)))
                .map_err(SdkError::network)?;
            inner.listener.clone()
        };
        if let Some(l) = listener {
            l.on_pairing("approved".to_string());
        }
        Ok(())
    }

    // ---- groups -------------------------------------------------------------

    /// Create a group with `members` (handles) and distribute our sender key to
    /// them over the pairwise E2E channel. Returns the new group id.
    pub fn group_create(&self, name: String, members: Vec<String>) -> Result<String, SdkError> {
        let mut inner = self.lock();
        let me = require_handle(&inner)?;
        let (dir_url, my_name, my_queue) = cfg_triple(&inner);

        let mut id_bytes = [0u8; 8];
        OsPlatform.fill_random(&mut id_bytes);
        let group_id = wireops::hex(&id_bytes);

        let mut all = members;
        if !all.iter().any(|m| m == me.as_str()) {
            all.push(me.as_str().to_string());
        }
        let my_gid = wireops::my_group_id(&inner.identity);
        let group = CoreGroup::new(&mut OsPlatform, my_gid.clone());
        let mut stored = StoredGroup {
            id: group_id.clone(),
            name,
            members: all,
            me: me.as_str().to_string(),
            sender_handles: Vec::new(),
            state: group.export(),
        };
        stored.note_sender(my_gid, me.as_str());
        groups::save(&mut inner.store, &stored).map_err(SdkError::storage)?;

        let targets = stored.members.clone();
        distribute_key(
            &inner.identity,
            &dir_url,
            &my_name,
            &my_queue,
            &me,
            &stored,
            &group,
            &targets,
        );
        Ok(group_id)
    }

    /// Add `member` to a group and re-distribute keys with the updated roster.
    pub fn group_add(&self, group_id: String, member: String) -> Result<(), SdkError> {
        let mut inner = self.lock();
        let me = require_handle(&inner)?;
        let (dir_url, my_name, my_queue) = cfg_triple(&inner);

        let mut stored = groups::load(&inner.store, &group_id)
            .map_err(SdkError::storage)?
            .ok_or_else(|| SdkError::invalid("no such group"))?;
        if stored.members.iter().any(|m| m == &member) {
            return Err(SdkError::invalid("already a member"));
        }
        stored.members.push(member);
        groups::save(&mut inner.store, &stored).map_err(SdkError::storage)?;
        let group = CoreGroup::import(stored.state.clone())
            .map_err(|e| SdkError::crypto(format!("{e:?}")))?;
        let targets = stored.members.clone();
        distribute_key(
            &inner.identity,
            &dir_url,
            &my_name,
            &my_queue,
            &me,
            &stored,
            &group,
            &targets,
        );
        Ok(())
    }

    /// Send a text message to a group. Returns the stored [`Message`].
    pub fn group_send(&self, group_id: String, text: String) -> Result<Message, SdkError> {
        let mut inner = self.lock();
        let me = require_handle(&inner)?;
        let dir_url = inner.config.dir_url.clone();

        let mut stored = groups::load(&inner.store, &group_id)
            .map_err(SdkError::storage)?
            .ok_or_else(|| SdkError::invalid("no such group"))?;
        let mut group = CoreGroup::import(stored.state.clone())
            .map_err(|e| SdkError::crypto(format!("{e:?}")))?;
        let app = wireops::text_message(&mut OsPlatform, &text);
        let gm = group.encrypt(&app.encode(), &wireops::group_ad(&stored.id));
        stored.state = group.export();
        groups::save(&mut inner.store, &stored).map_err(SdkError::storage)?;

        let item = MailItem::GroupText {
            group_id: stored.id.clone(),
            message: gm,
        };
        let blob = serde_json::to_string(&item).map_err(SdkError::crypto)?;
        let dir = DirectoryClient::with_transport(&dir_url, Box::new(UreqTransport));
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
            let queue = QueueClient::with_transport(&record.record.queue, Box::new(UreqTransport));
            let Ok(qtoken) = queue.login(&inner.identity) else {
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
        history::group_append(&mut inner.store, &stored.id, entry).map_err(SdkError::storage)?;

        let delivery = if delivered > 0 {
            DeliveryState::Sent
        } else {
            DeliveryState::Queued
        };
        Ok(Message {
            id: app.id.clone(),
            thread: group_id,
            from_me: true,
            sender: me.as_str().to_string(),
            text: app.summary(),
            sent_at: app.timestamp,
            delivery,
        })
    }

    /// Leave a group locally (stop participating; drops its keys + state).
    pub fn group_leave(&self, group_id: String) -> Result<(), SdkError> {
        let mut inner = self.lock();
        groups::remove(&mut inner.store, &group_id).map_err(SdkError::storage)
    }

    /// The groups this account belongs to.
    pub fn groups(&self) -> Vec<Group> {
        let inner = self.lock();
        let ids = groups::list(&inner.store).unwrap_or_default();
        ids.into_iter()
            .filter_map(|id| groups::load(&inner.store, &id).ok().flatten())
            .map(|g| Group {
                id: g.id,
                name: g.name,
                members: g.members,
            })
            .collect()
    }

    /// A group's transcript (expired messages pruned), oldest first.
    pub fn group_thread(&self, group_id: String) -> Result<Vec<Message>, SdkError> {
        let mut inner = self.lock();
        let now = OsPlatform.now_unix_secs();
        let my_handle = inner.config.handle.clone();
        let msgs = history::group_load_active(&mut inner.store, &group_id, now)
            .map_err(SdkError::storage)?;
        Ok(msgs
            .into_iter()
            .map(|m| {
                let from_me = m.sender == my_handle;
                Message {
                    id: m.id,
                    thread: group_id.clone(),
                    from_me,
                    sender: m.sender,
                    text: m.text,
                    sent_at: m.timestamp,
                    delivery: if from_me {
                        DeliveryState::Sent
                    } else {
                        DeliveryState::Delivered
                    },
                }
            })
            .collect())
    }

    // ---- backup / restore ---------------------------------------------------

    /// A portable snapshot of the encrypted store (every entry, still encrypted at
    /// rest under this account's storage key). Restore it into a client opened on
    /// the **same** account with [`import_backup`](Self::import_backup).
    pub fn export_backup(&self) -> Vec<u8> {
        let inner = self.lock();
        let dir = inner.root.join("store");
        let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
        if let Ok(read) = std::fs::read_dir(&dir) {
            for entry in read.flatten() {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    if let (Some(name), Ok(bytes)) = (
                        entry.file_name().to_str().map(str::to_string),
                        std::fs::read(entry.path()),
                    ) {
                        entries.push((name, bytes));
                    }
                }
            }
        }
        wire::encode(&entries)
    }

    /// Restore a store snapshot produced by [`export_backup`](Self::export_backup)
    /// into this client's store, then reload the config from it. The snapshot's
    /// entries are encrypted under the account's storage key, so it only decrypts
    /// under the same account.
    pub fn import_backup(&self, bytes: Vec<u8>) -> Result<(), SdkError> {
        let mut inner = self.lock();
        let entries: Vec<(String, Vec<u8>)> =
            wire::decode(&bytes).map_err(|e| SdkError::storage(format!("{e:?}")))?;
        let dir = inner.root.join("store");
        std::fs::create_dir_all(&dir).map_err(SdkError::storage)?;
        for (name, data) in &entries {
            // Only ever write a basename inside the store dir.
            if let Some(safe) = Path::new(name).file_name().and_then(|n| n.to_str()) {
                std::fs::write(dir.join(safe), data).map_err(SdkError::storage)?;
            }
        }
        // Re-open the store so any cached handles see the restored files, then
        // reload the config snapshot the backup carried.
        inner.store =
            FileStore::open(dir, inner.identity.storage_key()).map_err(SdkError::storage)?;
        inner.config = Config {
            dir_url: cfg_get(&inner.store, K_DIR),
            queue_url: cfg_get(&inner.store, K_QUEUE),
            handle: cfg_get(&inner.store, K_HANDLE),
            name: cfg_get(&inner.store, K_NAME),
        };
        Ok(())
    }
}

impl MyceliumClient {
    /// Lock the interior; the mutex is only poisoned if a prior holder panicked,
    /// in which case recovering the guard is still correct for our data.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Shared 1:1 delivery path: look up the peer, refuse a changed identity, seal
    /// `app` to each of their devices, deposit to their queue, and record our own
    /// copy (edits/deletes mutate the referenced message; everything else appends).
    fn deliver_app(&self, peer_handle: String, app: AppMessage) -> Result<Message, SdkError> {
        let mut inner = self.lock();
        if inner.config.handle.is_empty() {
            return Err(SdkError::NotRegistered);
        }
        let me = Handle::new(inner.config.handle.clone()).map_err(SdkError::invalid)?;
        let peer = Handle::new(peer_handle.clone()).map_err(SdkError::invalid)?;

        let dir = DirectoryClient::with_transport(&inner.config.dir_url, Box::new(UreqTransport));
        let precord = dir.lookup(&peer).map_err(SdkError::network)?;

        // A previously pinned/verified peer whose wallet has changed is a possible
        // impersonation — refuse and surface it (and notify the listener).
        if matches!(
            verified::level(&inner.store, peer.as_str(), &precord.record.wallet),
            verified::TrustLevel::Changed
        ) {
            if let Some(l) = inner.listener.clone() {
                l.on_key_change(peer_handle.clone());
            }
            return Err(SdkError::IdentityChanged {
                handle: peer_handle,
            });
        }

        // Learn the peer's chosen display name from their record.
        let _ = names::note(&mut inner.store, peer.as_str(), &precord.record.name);

        let encoded = app.encode();
        // Log in to each of the peer's queue endpoints in preference order
        // (primary `queue` then `queues`), so a deposit can fail over from a
        // down primary to a backup (#54). Unreachable endpoints are skipped; we
        // only surface the error if *none* of them are reachable.
        let mut sessions: Vec<(QueueClient, String)> = Vec::new();
        let mut last_err: Option<SdkError> = None;
        for url in precord.record.endpoints() {
            let q = QueueClient::with_transport(url, Box::new(UreqTransport));
            match q.login(&inner.identity) {
                Ok(t) => sessions.push((q, t)),
                Err(e) => last_err = Some(SdkError::network(e)),
            }
        }
        if sessions.is_empty() {
            return Err(last_err
                .unwrap_or_else(|| SdkError::network("recipient advertises no queue endpoint")));
        }
        let peer_hex = wallet_hex(&precord.record.wallet);
        let my_name = inner.config.name.clone();
        let my_queue = inner.config.queue_url.clone();

        let mut delivered = 0u32;
        for device in &precord.record.devices {
            let Ok(env) = wireops::seal_to(
                &mut OsPlatform,
                &inner.identity,
                &me,
                &my_name,
                &my_queue,
                device,
                &encoded,
            ) else {
                continue;
            };
            let blob = serde_json::to_string(&MailItem::Direct(env)).map_err(SdkError::crypto)?;
            let slot = wireops::device_slot(&device.device_key);
            // Try each endpoint until one accepts this device's copy (#54).
            if sessions
                .iter()
                .any(|(q, t)| q.deposit(t, &peer_hex, &slot, &blob).is_ok())
            {
                delivered += 1;
            }
        }

        let delivery = if delivered > 0 {
            DeliveryState::Sent
        } else {
            DeliveryState::Queued
        };

        // Record our own copy in this peer's transcript (mirrors the native `send`).
        match &app.body {
            Body::Edit { to, text } => {
                history::edit(&mut inner.store, peer.as_str(), to, text, true)
                    .map_err(SdkError::storage)?;
            }
            Body::Delete { to } => {
                history::delete(&mut inner.store, peer.as_str(), to, true)
                    .map_err(SdkError::storage)?;
            }
            Body::Receipt { .. } => {}
            _ => {
                let stored = history::StoredMessage {
                    id: app.id.clone(),
                    from_me: true,
                    text: app.summary(),
                    timestamp: app.timestamp,
                    expires_at: app.expires_at,
                };
                history::append(&mut inner.store, peer.as_str(), stored)
                    .map_err(SdkError::storage)?;
            }
        }

        Ok(Message {
            id: app.id.clone(),
            thread: peer_handle,
            from_me: true,
            sender: inner.config.handle.clone(),
            text: app.summary(),
            sent_at: app.timestamp,
            delivery,
        })
    }

    /// Adopt the account carried in a decrypted pairing payload: replace this
    /// device's identity with the received account (fresh device keys), **re-key
    /// the local store** to it, join its directory record, persist config, and
    /// return the adopted [`Account`].
    fn adopt_from_payload(&self, inner: &mut Inner, payload: &[u8]) -> Result<Account, SdkError> {
        let v: serde_json::Value =
            serde_json::from_slice(payload).map_err(|_| SdkError::crypto("bad provisioning"))?;
        let ws = from_hex(
            v["ws"]
                .as_str()
                .ok_or_else(|| SdkError::crypto("bad provisioning"))?,
        )?;
        let ws: [u8; 32] = ws
            .as_slice()
            .try_into()
            .map_err(|_| SdkError::crypto("bad account key"))?;
        let handle = v["h"]
            .as_str()
            .ok_or_else(|| SdkError::crypto("bad provisioning"))?
            .to_string();
        let name = v["n"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or(&handle)
            .to_string();
        let dir = v["d"].as_str().unwrap_or_default().to_string();
        let queue = v["q"].as_str().unwrap_or_default().to_string();

        let new_identity =
            Identity::adopt(&mut OsPlatform, ws).map_err(|e| SdkError::crypto(format!("{e:?}")))?;
        persist_identity(&inner.root, &new_identity)?;
        // The store is keyed by the identity, so re-open it under the adopted
        // account's storage key (this device was fresh, so nothing is lost).
        let store = FileStore::open(inner.root.join("store"), new_identity.storage_key())
            .map_err(SdkError::storage)?;
        inner.identity = new_identity;
        inner.store = store;

        publish_merged(&inner.identity, &dir, &handle, &name, &queue)?;
        inner
            .store
            .put(K_DIR, dir.as_bytes())
            .map_err(SdkError::storage)?;
        inner
            .store
            .put(K_QUEUE, queue.as_bytes())
            .map_err(SdkError::storage)?;
        inner
            .store
            .put(K_HANDLE, handle.as_bytes())
            .map_err(SdkError::storage)?;
        inner
            .store
            .put(K_NAME, name.as_bytes())
            .map_err(SdkError::storage)?;
        let wallet_address = wireops::hex(&inner.identity.wallet_public().0);
        inner.config = Config {
            dir_url: dir,
            queue_url: queue,
            handle: handle.clone(),
            name: name.clone(),
        };
        inner.pairing = None;
        Ok(Account {
            handle,
            name,
            wallet_address,
        })
    }
}

/// Load the persisted identity from `data_dir/identity.json`, or generate and
/// persist a fresh one.
fn load_or_create_identity(root: &std::path::Path) -> Result<Identity, SdkError> {
    let path = root.join("identity.json");
    if let Ok(bytes) = std::fs::read(&path) {
        let stored: StoredIdentity = serde_json::from_slice(&bytes).map_err(SdkError::storage)?;
        return Identity::from_wallet_secret(stored.wallet_secret, stored.device_seed)
            .map_err(|e| SdkError::crypto(format!("{e:?}")));
    }
    let identity =
        Identity::generate(&mut OsPlatform).map_err(|e| SdkError::crypto(format!("{e:?}")))?;
    persist_identity(root, &identity)?;
    Ok(identity)
}

/// Write `identity`'s persistable secret to `root/identity.json` (owner-only where
/// supported). Used at first-run and when device pairing adopts a new account.
fn persist_identity(root: &std::path::Path, identity: &Identity) -> Result<(), SdkError> {
    let path = root.join("identity.json");
    let stored = StoredIdentity {
        wallet_secret: identity.wallet_secret(),
        device_seed: identity.device_seed(),
    };
    std::fs::write(
        &path,
        serde_json::to_vec(&stored).map_err(SdkError::storage)?,
    )
    .map_err(SdkError::storage)?;
    restrict_secret_file(&path);
    Ok(())
}

/// Best-effort tighten the sidecar identity file to owner-only (0600) on Unix,
/// so the device secret isn't world-readable. (#65 replaces this sidecar with
/// OS-secure storage.)
fn restrict_secret_file(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Publish our record, merging this device into any record that already exists
/// for the handle (so re-registering or a prior pairing never drops siblings).
fn publish_merged(
    identity: &Identity,
    dir_url: &str,
    handle: &str,
    name: &str,
    queue_url: &str,
) -> Result<(), SdkError> {
    let me = Handle::new(handle).map_err(SdkError::invalid)?;
    let dir = DirectoryClient::with_transport(dir_url, Box::new(UreqTransport));
    let existing = dir.lookup(&me).ok();
    let mut devices = existing
        .as_ref()
        .map(|r| r.record.devices.clone())
        .unwrap_or_default();
    let mine = wireops::this_device(identity, "");
    if !devices.iter().any(|d| d.device_key == mine.device_key) {
        devices.push(mine);
    }
    let now = OsPlatform.now_unix_secs();
    let seq = existing
        .as_ref()
        .map(|r| r.record.seq + 1)
        .unwrap_or(now)
        .max(now);
    let record = Record {
        handle: user_id(handle),
        name: name.to_string(),
        wallet: identity.wallet_public(),
        queue: queue_url.to_string(),
        queues: vec![],
        devices,
        seq,
    };
    let signed = SignedRecord::sign(record, identity);
    let token = dir.login(identity).map_err(SdkError::network)?;
    dir.publish(&token, &me, &signed)
        .map_err(SdkError::network)?;
    Ok(())
}

/// The outcome of processing one inbound blob.
enum Processed {
    /// Handled — optionally surfacing a new visible [`Message`] to the caller.
    Done(Option<Message>),
    /// Not handled yet (couldn't decrypt / its group key hasn't arrived / a
    /// transient error) — keep it in the retry store for a later sync.
    Retry,
}

/// Process one collected blob, mirroring the engine's `process_item`: direct
/// 1:1 messages, self-sync mirrors of our own sends, and the group lifecycle
/// (invite, text, sync, leave).
fn process_blob(inner: &mut Inner, blob: &str) -> Processed {
    let Ok(item) = serde_json::from_str::<MailItem>(blob) else {
        return Processed::Retry; // unparseable — keep until it dead-letters
    };
    match item {
        MailItem::Direct(env) => process_direct(inner, &env),
        MailItem::SelfSync { peer, envelope } => process_self_sync(inner, &peer, &envelope),
        MailItem::GroupInvite(env) => process_group_invite(inner, &env),
        MailItem::GroupText { group_id, message } => process_group_text(inner, &group_id, &message),
        MailItem::GroupSync(env) => process_group_sync(inner, &env),
        // A leave we can't authenticate/decrypt safely no-ops (as in the engine);
        // treat it as handled so it doesn't retry forever.
        MailItem::GroupLeave(env) => {
            let _ = process_group_leave(inner, &env);
            Processed::Done(None)
        }
    }
}

/// Decrypt and apply a one-to-one offline message.
fn process_direct(inner: &mut Inner, env: &mycellium_core::offline::Envelope) -> Processed {
    let Ok((from, plaintext)) = wireops::open_envelope(&mut OsPlatform, &inner.identity, env)
    else {
        return Processed::Retry;
    };
    let Ok(app) = AppMessage::decode(&plaintext) else {
        return Processed::Retry;
    };
    // Learn the sender's self-set display name (from their signed record).
    let _ = names::note(
        &mut inner.store,
        from.as_str(),
        &env.sender_record.record.name,
    );

    match &app.body {
        // Edits/deletes/receipts mutate or acknowledge — not new visible messages.
        Body::Edit { to, text } => {
            let _ = history::edit(&mut inner.store, from.as_str(), to, text, false);
            Processed::Done(None)
        }
        Body::Delete { to } => {
            let _ = history::delete(&mut inner.store, from.as_str(), to, false);
            Processed::Done(None)
        }
        Body::Receipt { .. } => Processed::Done(None),
        _ => {
            let stored = history::StoredMessage {
                id: app.id.clone(),
                from_me: false,
                text: app.summary(),
                timestamp: app.timestamp,
                expires_at: app.expires_at,
            };
            if history::append(&mut inner.store, from.as_str(), stored.clone()).is_err() {
                return Processed::Retry;
            }
            Processed::Done(Some(Message {
                id: stored.id,
                thread: from.as_str().to_string(),
                from_me: false,
                sender: from.as_str().to_string(),
                text: stored.text,
                sent_at: stored.timestamp,
                delivery: DeliveryState::Delivered,
            }))
        }
    }
}

/// Apply a mirror of a message *this account* sent from another device (Layer 11
/// self-sync): record it in the peer's transcript as our own outgoing message.
/// Not surfaced as inbound (it isn't a new message *to* us).
fn process_self_sync(
    inner: &mut Inner,
    peer: &str,
    env: &mycellium_core::offline::Envelope,
) -> Processed {
    let Ok((_from, bytes)) = wireops::open_envelope(&mut OsPlatform, &inner.identity, env) else {
        return Processed::Retry;
    };
    let Ok(app) = AppMessage::decode(&bytes) else {
        return Processed::Done(None); // unusable mirror — nothing to keep
    };
    match &app.body {
        Body::Edit { to, text } => {
            let _ = history::edit(&mut inner.store, peer, to, text, true);
        }
        Body::Delete { to } => {
            let _ = history::delete(&mut inner.store, peer, to, true);
        }
        Body::Receipt { .. } => {}
        _ => {
            let entry = history::StoredMessage {
                id: app.id.clone(),
                from_me: true,
                text: app.summary(),
                timestamp: app.timestamp,
                expires_at: app.expires_at,
            };
            let _ = history::append(&mut inner.store, peer, entry);
        }
    }
    Processed::Done(None)
}

/// Process a received group invite: join the group (or learn a member's key) and
/// reply with our own sender key so members can decrypt us too.
fn process_group_invite(inner: &mut Inner, env: &mycellium_core::offline::Envelope) -> Processed {
    let Ok((from, bytes)) = wireops::open_envelope(&mut OsPlatform, &inner.identity, env) else {
        return Processed::Retry;
    };
    let Ok(payload) = serde_json::from_slice::<GroupInvitePayload>(&bytes) else {
        return Processed::Retry;
    };
    let (dir_url, my_name, my_queue) = cfg_triple(inner);
    let mine = inner.config.handle.clone();
    let Ok(me) = Handle::new(mine.clone()) else {
        return Processed::Retry;
    };
    let sender_id = payload.sender_id.clone();

    match groups::load(&inner.store, &payload.group_id).ok().flatten() {
        Some(mut stored) => {
            let Ok(mut group) = CoreGroup::import(stored.state.clone()) else {
                return Processed::Retry;
            };
            let _ = group.add_member(sender_id.clone(), &payload.distribution);
            stored.note_sender(sender_id, from.as_str());
            let newcomers: Vec<String> = payload
                .members
                .iter()
                .filter(|m| !stored.members.iter().any(|x| x == *m))
                .cloned()
                .collect();
            stored.members.extend(newcomers.iter().cloned());
            stored.state = group.export();
            let _ = groups::save(&mut inner.store, &stored);
            if !newcomers.is_empty() {
                distribute_key(
                    &inner.identity,
                    &dir_url,
                    &my_name,
                    &my_queue,
                    &me,
                    &stored,
                    &group,
                    &newcomers,
                );
            }
        }
        None => {
            let mut group = CoreGroup::new(&mut OsPlatform, wireops::my_group_id(&inner.identity));
            let _ = group.add_member(sender_id.clone(), &payload.distribution);
            let mut stored = StoredGroup {
                id: payload.group_id.clone(),
                name: payload.name.clone(),
                members: payload.members.clone(),
                me: mine,
                sender_handles: Vec::new(),
                state: group.export(),
            };
            stored.note_sender(sender_id, from.as_str());
            stored.note_sender(wireops::my_group_id(&inner.identity), me.as_str());
            let _ = groups::save(&mut inner.store, &stored);
            let targets = stored.members.clone();
            distribute_key(
                &inner.identity,
                &dir_url,
                &my_name,
                &my_queue,
                &me,
                &stored,
                &group,
                &targets,
            );
        }
    }
    Processed::Done(None)
}

/// Decrypt a received group message and store it. Returns [`Processed::Retry`] if
/// we don't have the group / sender key yet (the invite hasn't arrived).
fn process_group_text(
    inner: &mut Inner,
    group_id: &str,
    message: &mycellium_core::group::GroupMessage,
) -> Processed {
    let Some(mut stored) = groups::load(&inner.store, group_id).ok().flatten() else {
        return Processed::Retry;
    };
    let sender = stored
        .handle_of(&message.sender)
        .map(str::to_string)
        .unwrap_or_else(|| String::from_utf8_lossy(&message.sender).into_owned());
    let Ok(mut group) = CoreGroup::import(stored.state.clone()) else {
        return Processed::Retry;
    };
    let Ok(plaintext) = group.decrypt(message, &wireops::group_ad(group_id)) else {
        return Processed::Retry; // missing that sender's key yet
    };
    stored.state = group.export();
    let _ = groups::save(&mut inner.store, &stored);

    let Ok(app) = AppMessage::decode(&plaintext) else {
        return Processed::Done(None);
    };
    match &app.body {
        Body::Edit { to, text } => {
            let _ = history::group_edit(&mut inner.store, group_id, to, text, &sender);
            Processed::Done(None)
        }
        Body::Delete { to } => {
            let _ = history::group_delete(&mut inner.store, group_id, to, &sender);
            Processed::Done(None)
        }
        Body::Receipt { .. } => Processed::Done(None),
        _ => {
            let entry = history::GroupStoredMessage {
                id: app.id.clone(),
                sender: sender.clone(),
                text: app.summary(),
                timestamp: app.timestamp,
                expires_at: app.expires_at,
            };
            let _ = history::group_append(&mut inner.store, group_id, entry);
            Processed::Done(Some(Message {
                id: app.id.clone(),
                thread: group_id.to_string(),
                from_me: false,
                sender,
                text: app.summary(),
                sent_at: app.timestamp,
                delivery: DeliveryState::Delivered,
            }))
        }
    }
}

/// Bootstrap this device into a group from a sibling's [`GroupSyncPayload`].
fn process_group_sync(inner: &mut Inner, env: &mycellium_core::offline::Envelope) -> Processed {
    let Ok((_from, bytes)) = wireops::open_envelope(&mut OsPlatform, &inner.identity, env) else {
        return Processed::Retry;
    };
    let Ok(payload) = serde_json::from_slice::<GroupSyncPayload>(&bytes) else {
        return Processed::Retry;
    };
    if groups::load(&inner.store, &payload.group_id)
        .ok()
        .flatten()
        .is_some()
    {
        return Processed::Done(None); // already have this group
    }
    let (dir_url, my_name, my_queue) = cfg_triple(inner);
    let Ok(me) = Handle::new(inner.config.handle.clone()) else {
        return Processed::Retry;
    };
    let mut group = CoreGroup::new(&mut OsPlatform, wireops::my_group_id(&inner.identity));
    for (id, dist) in &payload.keys {
        let _ = group.add_member(id.clone(), dist);
    }
    let mut stored = StoredGroup {
        id: payload.group_id.clone(),
        name: payload.name.clone(),
        members: payload.members.clone(),
        me: me.as_str().to_string(),
        sender_handles: payload.sender_handles.clone(),
        state: group.export(),
    };
    stored.note_sender(wireops::my_group_id(&inner.identity), me.as_str());
    let _ = groups::save(&mut inner.store, &stored);
    let targets = stored.members.clone();
    distribute_key(
        &inner.identity,
        &dir_url,
        &my_name,
        &my_queue,
        &me,
        &stored,
        &group,
        &targets,
    );
    Processed::Done(None)
}

/// React to a member's **authenticated** departure: drop their sender key, re-key
/// so they can't read future messages, and redistribute our fresh key. The leaver
/// is the envelope's authenticated sender, so this can only remove who actually
/// left.
fn process_group_leave(
    inner: &mut Inner,
    env: &mycellium_core::offline::Envelope,
) -> Result<(), SdkError> {
    let (from, bytes) = wireops::open_envelope(&mut OsPlatform, &inner.identity, env)
        .map_err(|e| SdkError::crypto(format!("{e:?}")))?;
    let payload: GroupLeavePayload = serde_json::from_slice(&bytes).map_err(SdkError::crypto)?;
    let member = from.as_str().to_string();
    let me = inner.config.handle.clone();
    if member == me {
        return Ok(());
    }
    let Some(mut stored) = groups::load(&inner.store, &payload.group_id).ok().flatten() else {
        return Ok(());
    };
    if !stored.members.iter().any(|m| m == &member) {
        return Ok(());
    }
    let (dir_url, my_name, my_queue) = cfg_triple(inner);
    let me_handle = Handle::new(me).map_err(SdkError::invalid)?;
    stored.members.retain(|m| m != &member);
    let mut session =
        CoreGroup::import(stored.state.clone()).map_err(|e| SdkError::crypto(format!("{e:?}")))?;
    for (id, handle) in &stored.sender_handles {
        if handle == &member {
            session.remove_member(id);
        }
    }
    stored.sender_handles.retain(|(_, h)| h != &member);
    session.rotate(&mut OsPlatform);
    stored.state = session.export();
    let _ = groups::save(&mut inner.store, &stored);
    let targets = stored.members.clone();
    distribute_key(
        &inner.identity,
        &dir_url,
        &my_name,
        &my_queue,
        &me_handle,
        &stored,
        &session,
        &targets,
    );
    Ok(())
}

/// Seal our group sender-key (a [`GroupInvitePayload`]) to every device of each
/// `targets` handle over the pairwise E2E channel (never this exact device).
/// Best-effort: unreachable members are skipped (the engine's outbox retry isn't
/// wired into the SDK yet; a re-invite re-distributes).
#[allow(clippy::too_many_arguments)]
fn distribute_key(
    identity: &Identity,
    dir_url: &str,
    my_name: &str,
    my_queue: &str,
    me: &Handle,
    stored: &StoredGroup,
    group: &CoreGroup,
    targets: &[String],
) {
    let payload = GroupInvitePayload {
        group_id: stored.id.clone(),
        name: stored.name.clone(),
        members: stored.members.clone(),
        sender_id: wireops::my_group_id(identity),
        distribution: group.distribution(),
    };
    let Ok(plaintext) = serde_json::to_vec(&payload) else {
        return;
    };
    let dir = DirectoryClient::with_transport(dir_url, Box::new(UreqTransport));
    for member in targets {
        let Ok(handle) = Handle::new(member.clone()) else {
            continue;
        };
        let Ok(record) = dir.lookup(&handle) else {
            continue;
        };
        let queue = QueueClient::with_transport(&record.record.queue, Box::new(UreqTransport));
        let Ok(qtoken) = queue.login(identity) else {
            continue;
        };
        let peer_hex = wallet_hex(&record.record.wallet);
        for device in &record.record.devices {
            if device.device_key == identity.device_public() {
                continue; // never this exact device
            }
            let Ok(env) = wireops::seal_to(
                &mut OsPlatform,
                identity,
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
}

/// The registered handle, or [`SdkError::NotRegistered`] if `register` hasn't run.
fn require_handle(inner: &Inner) -> Result<Handle, SdkError> {
    if inner.config.handle.is_empty() {
        return Err(SdkError::NotRegistered);
    }
    Handle::new(inner.config.handle.clone()).map_err(SdkError::invalid)
}

/// The `(dir_url, name, queue_url)` config triple, cloned for network use.
fn cfg_triple(inner: &Inner) -> (String, String, String) {
    (
        inner.config.dir_url.clone(),
        inner.config.name.clone(),
        inner.config.queue_url.clone(),
    )
}

/// Decode lowercase hex, mapping malformed input to [`SdkError::InvalidInput`].
fn from_hex(s: &str) -> Result<Vec<u8>, SdkError> {
    if !s.len().is_multiple_of(2) {
        return Err(SdkError::invalid("odd-length hex"));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| SdkError::invalid("bad hex"))
        })
        .collect()
}

/// Build a boundary [`Message`] from a stored transcript entry.
fn to_message(m: history::StoredMessage, peer: &str, my_handle: &str) -> Message {
    let delivery = if m.from_me {
        DeliveryState::Sent
    } else {
        DeliveryState::Delivered
    };
    let sender = if m.from_me { my_handle } else { peer };
    Message {
        id: m.id,
        thread: peer.to_string(),
        from_me: m.from_me,
        sender: sender.to_string(),
        text: m.text,
        sent_at: m.timestamp,
        delivery,
    }
}

/// The storage key for a free-form setting (namespaced away from config/history).
fn setting_key(key: &str) -> Vec<u8> {
    let mut k = b"setting:".to_vec();
    k.extend_from_slice(key.as_bytes());
    k
}

/// Read a config value from the store (empty string if unset/unreadable).
fn cfg_get(store: &FileStore, key: &[u8]) -> String {
    store
        .get(key)
        .ok()
        .flatten()
        .map(|v| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_default()
}
