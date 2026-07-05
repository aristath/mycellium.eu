//! The stateful native client object bound across UniFFI.
//!
//! [`MyceliumClient`] mirrors the proven wasm `Session` façade over the engine,
//! but (a) over the native encrypted [`FileStore`] instead of the browser's
//! in-memory store, (b) over the native `ureq` [`UreqTransport`] instead of the
//! browser XHR transport, and (c) holding config (directory/queue URLs, handle,
//! name) as client state rather than passing it on every call.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use mycellium_core::identity::{Handle, Identity};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::record::{Record, SignedRecord};
use mycellium_core::storage::Storage;
use mycellium_core::userid::user_id;
use mycellium_directory_client::DirectoryClient;
use mycellium_engine::groups::MailItem;
use mycellium_engine::platform::OsPlatform;
use mycellium_engine::{history, names, wireops};
use mycellium_http::UreqTransport;
use mycellium_queue_client::{wallet_hex, QueueClient};

use mycellium_core::platform::Platform;
use mycellium_storage::filestore::FileStore;

use crate::types::{Account, Conversation, DeliveryState, EventListener, Message, SdkError};

// TODO(#64 follow-up): groups, pairing, contacts, verification, backup,
// reactions/replies/files, and the C-ABI surface. This increment ships the
// identity → register → send → sync → read core over native storage.

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
    store: FileStore,
    identity: Identity,
    config: Config,
    listener: Option<Arc<dyn EventListener>>,
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
                store,
                identity,
                config,
                listener: None,
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
            mycellium_engine::verified::level(&inner.store, peer.as_str(), &precord.record.wallet),
            mycellium_engine::verified::TrustLevel::Changed
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

        let app = wireops::text_message(&mut OsPlatform, &text);
        let encoded = app.encode();

        let queue = QueueClient::with_transport(&precord.record.queue, Box::new(UreqTransport));
        let qtoken = queue.login(&inner.identity).map_err(SdkError::network)?;
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

        let delivery = if delivered > 0 {
            DeliveryState::Sent
        } else {
            DeliveryState::Queued
        };

        // Record our own copy in this peer's transcript.
        let stored = history::StoredMessage {
            id: app.id.clone(),
            from_me: true,
            text: app.summary(),
            timestamp: app.timestamp,
            expires_at: app.expires_at,
        };
        history::append(&mut inner.store, peer.as_str(), stored.clone())
            .map_err(SdkError::storage)?;

        Ok(Message {
            id: stored.id,
            thread: peer_handle,
            from_me: true,
            sender: inner.config.handle.clone(),
            text: stored.text,
            sent_at: stored.timestamp,
            delivery,
        })
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

            let mut received = Vec::new();
            for blob in blobs {
                if let Some(msg) = process_blob(&mut inner, &blob) {
                    received.push(msg);
                }
            }
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
}

impl MyceliumClient {
    /// Lock the interior; the mutex is only poisoned if a prior holder panicked,
    /// in which case recovering the guard is still correct for our data.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
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
    Ok(identity)
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
        devices,
        seq,
    };
    let signed = SignedRecord::sign(record, identity);
    let token = dir.login(identity).map_err(SdkError::network)?;
    dir.publish(&token, &me, &signed)
        .map_err(SdkError::network)?;
    Ok(())
}

/// Process one collected blob. Only direct 1:1 messages are handled this
/// increment; other mail kinds (self-sync, groups) are ignored for now. Returns
/// the stored inbound [`Message`] on success.
fn process_blob(inner: &mut Inner, blob: &str) -> Option<Message> {
    let item = serde_json::from_str::<MailItem>(blob).ok()?;
    let MailItem::Direct(env) = item else {
        // TODO(#64 follow-up): handle SelfSync / Group* mail here.
        return None;
    };
    let (from, plaintext) = wireops::open_envelope(&mut OsPlatform, &inner.identity, &env).ok()?;
    let app = AppMessage::decode(&plaintext).ok()?;

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
            None
        }
        Body::Delete { to } => {
            let _ = history::delete(&mut inner.store, from.as_str(), to, false);
            None
        }
        Body::Receipt { .. } => None,
        _ => {
            let stored = history::StoredMessage {
                id: app.id.clone(),
                from_me: false,
                text: app.summary(),
                timestamp: app.timestamp,
                expires_at: app.expires_at,
            };
            history::append(&mut inner.store, from.as_str(), stored.clone()).ok()?;
            Some(Message {
                id: stored.id,
                thread: from.as_str().to_string(),
                from_me: false,
                sender: from.as_str().to_string(),
                text: stored.text,
                sent_at: stored.timestamp,
                delivery: DeliveryState::Delivered,
            })
        }
    }
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
