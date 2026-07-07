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
use mycellium_core::identity::{Handle, Identity, WalletPublicKey};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::pairing::{self, PairingMessage, PairingResponder, PairingResponderPublic};
use mycellium_core::record::{Device, SignedRecord};
use mycellium_core::storage::Storage;
use mycellium_core::{safety, wire};
use mycellium_directory_client::DirectoryClient;
use mycellium_engine::flow;
use mycellium_engine::groups::{self, MailItem, StoredGroup};
use mycellium_engine::platform::OsPlatform;
use mycellium_engine::{
    contacts, history, inbound, names, reachability::DeliveryPath, verified, wireops,
};
use mycellium_http::UreqTransport;
use mycellium_queue_client::{wallet_hex, PushSub, QueueClient};

use mycellium_core::platform::Platform;
use mycellium_storage::filestore::FileStore;

use crate::secrets::{PlaintextFileSecretStore, SecretStore};
use crate::types::{
    Account, Contact, Conversation, DeliveryState, EmailVerification, EventListener, Group,
    Message, PushPlatform, SdkError, TrustLevel,
};

/// Maximum inline attachment size, matching the engine/wasm cap. Attachments
/// ride inside the sealed envelope, so this stays well under the queue's body cap.
const MAX_ATTACHMENT: usize = 256 * 1024;

// TODO(#64 follow-up): the C-ABI desktop surface (a `cdylib`/`staticlib` shim
// for desktop clients) and smoke tests that load the *generated* Kotlin/Swift
// bindings. The Rust messaging/contacts/verification/pairing/groups/backup and
// email-verified onboarding surface below is complete and covered by
// `tests/sdk.rs`.
//
// #65 is addressed: the identity secret is now held behind a `SecretStore`
// (see `secrets.rs`), which platform apps back with the OS keystore. The
// remaining follow-up is shipping the per-OS `SecretStore` adapters described in
// `docs/research/SECURE-STORAGE.md`.

/// The mailbox slot for account-wide items (matches the engine's `ACCOUNT_SLOT`).
const ACCOUNT_SLOT: &str = "account";

// Config keys, matching the wasm Session's `myc:*` layout so a future shared
// snapshot format stays compatible.
const K_DIR: &[u8] = b"myc:dir";
const K_QUEUE: &[u8] = b"myc:queue";
const K_HANDLE: &[u8] = b"myc:handle";
const K_NAME: &[u8] = b"myc:name";

/// The device identity's persistable secret. Held behind a [`SecretStore`] (NOT
/// inside the [`FileStore`], which is itself keyed by the identity, so it can't
/// hold its own key). The platform app chooses where it physically lives —
/// OS keystore in production, a passphrase/plaintext file for dev (#65).
///
/// The wire form (JSON of this struct) is unchanged from the legacy
/// `identity.json` sidecar, so a sidecar migrates into the store byte-for-byte.
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    wallet_secret: [u8; 32],
    device_seed: [u8; 32],
}

/// The [`SecretStore`] key under which the identity secret is held.
const IDENTITY_KEY: &str = "identity";

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
    /// The data-dir root (holds the `store/` directory). Kept so pairing can
    /// re-key the store and backup can snapshot it.
    root: PathBuf,
    store: FileStore,
    /// Where the identity secret is held. Pairing re-stores the adopted account
    /// key here.
    secrets: Box<dyn SecretStore>,
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
    /// Open (or create) a client rooted at `data_dir`, holding the identity secret
    /// through the app-supplied [`SecretStore`].
    ///
    /// This is the constructor **production apps use**: pass a [`SecretStore`]
    /// backed by the OS keystore (Keychain / Keystore / DPAPI / libsecret — see
    /// `docs/research/SECURE-STORAGE.md`), so the account's root key never sits in
    /// plaintext on disk.
    ///
    /// Loads the identity from `store.load("identity")` if present; otherwise, if a
    /// legacy plaintext `data_dir/identity.json` sidecar exists it is imported into
    /// the store and removed (clean upgrade); otherwise a fresh identity is
    /// generated and stored. The encrypted `data_dir/store` (history, config) is
    /// then opened under that identity.
    #[uniffi::constructor]
    pub fn new_with_secret_store(
        data_dir: String,
        secrets: Box<dyn SecretStore>,
    ) -> Result<Arc<Self>, SdkError> {
        let root = PathBuf::from(&data_dir);
        std::fs::create_dir_all(&root).map_err(SdkError::storage)?;

        let identity = load_or_create_identity(&root, secrets.as_ref())?;
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
                secrets,
                identity,
                config,
                listener: None,
                pairing: None,
            }),
        }))
    }

    /// Open (or create) a client rooted at `data_dir` using the **dev-only**
    /// plaintext-file secret store (`data_dir/secrets/`, best-effort `0600`).
    ///
    /// **Production apps MUST NOT use this.** It provides no at-rest
    /// confidentiality for the account's root key — anyone who can read the file
    /// reads the key. Real apps call
    /// [`new_with_secret_store`](Self::new_with_secret_store) with a [`SecretStore`]
    /// backed by the OS keystore; headless/server deployments can use
    /// [`PassphraseFileSecretStore`](crate::PassphraseFileSecretStore) instead.
    /// This convenience exists only for tests, local development, and the migration
    /// path off the historical `identity.json` sidecar (#65).
    #[uniffi::constructor]
    pub fn new(data_dir: String) -> Result<Arc<Self>, SdkError> {
        let secrets = Box::new(PlaintextFileSecretStore::new(
            PathBuf::from(&data_dir).join("secrets"),
        ));
        Self::new_with_secret_store(data_dir, secrets)
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

    /// **Onboarding step 1.** Begin an email-verified claim of `handle` for this
    /// wallet: log into `dir_url` with this identity, then ask the directory to
    /// start a verification for `email`. Returns an [`EmailVerification`] carrying
    /// the `pending` token to complete the flow, and a `dev_code` **only** when the
    /// directory runs in dev mode (no SMTP) — in production the code is emailed and
    /// `dev_code` is `None`.
    ///
    /// Intended onboarding order:
    /// [`start_email_verification`](Self::start_email_verification) → user enters
    /// the code they were emailed →
    /// [`confirm_email_verification`](Self::confirm_email_verification) →
    /// [`register`](Self::register) (publish the record). This is also the
    /// account-recovery path: confirming re-binds the handle to this wallet.
    pub fn start_email_verification(
        &self,
        dir_url: String,
        handle: String,
        email: String,
    ) -> Result<EmailVerification, SdkError> {
        if handle.trim().is_empty() {
            return Err(SdkError::invalid("handle must not be empty"));
        }
        if email.trim().is_empty() {
            return Err(SdkError::invalid("email must not be empty"));
        }
        let inner = self.lock();
        let dir = DirectoryClient::with_transport(&dir_url, Box::new(UreqTransport));
        let token = dir.login(&inner.identity).map_err(SdkError::network)?;
        let (pending, dev_code) = dir
            .auth_start(&token, &handle, &email)
            .map_err(SdkError::network)?;
        Ok(EmailVerification { pending, dev_code })
    }

    /// **Onboarding step 2.** Confirm the emailed (or dev-mode) `code` for the
    /// `pending` claim returned by
    /// [`start_email_verification`](Self::start_email_verification). On success the
    /// directory binds (or re-binds, for recovery) the handle to this wallet; the
    /// caller then proceeds to [`register`](Self::register) to publish the record.
    pub fn confirm_email_verification(
        &self,
        dir_url: String,
        pending: String,
        code: String,
    ) -> Result<(), SdkError> {
        if pending.trim().is_empty() {
            return Err(SdkError::invalid("pending token must not be empty"));
        }
        if code.trim().is_empty() {
            return Err(SdkError::invalid("code must not be empty"));
        }
        let dir = DirectoryClient::with_transport(&dir_url, Box::new(UreqTransport));
        dir.auth_confirm(&pending, &code)
            .map_err(SdkError::network)?;
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

            let mut sink = SdkSink {
                messages: Vec::new(),
                my_handle: inner.config.handle.clone(),
                now,
            };
            let mut survivors = Vec::new();
            for mut entry in pending {
                if entry.is_expired(now) {
                    continue; // dead-letter: give up
                }
                let outcome = match serde_json::from_str::<MailItem>(&entry.blob) {
                    Ok(item) => process_inbound(&mut inner, item, &mut sink),
                    // Unparseable — keep it until it dead-letters.
                    Err(_) => flow::ItemOutcome::Retry,
                };
                if outcome == flow::ItemOutcome::Retry {
                    entry.attempts += 1;
                    survivors.push(entry);
                }
            }
            inbound::save(&mut inner.store, &survivors).map_err(SdkError::storage)?;
            (sink.messages, inner.listener.clone())
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

    /// Register this device's native/web push token with the account's queue, so
    /// the queue can wake this device **contentlessly** on deposit. `platform`
    /// selects the transport (Web Push / APNs / FCM / UnifiedPush) and `token` is
    /// the OS-issued token (or, for Web Push / UnifiedPush, the endpoint URL).
    /// Idempotent server-side: re-registering the same token is a no-op. Logs the
    /// queue in with this device identity, like `sync`. Returns
    /// [`SdkError::NotRegistered`] if no queue is configured yet.
    ///
    /// The wake carries no sender or content; messages are decrypted on this
    /// device by `sync()` (decrypt-then-display). The push provider only learns
    /// that a device was woken and when.
    pub fn register_push(&self, platform: PushPlatform, token: String) -> Result<(), SdkError> {
        let inner = self.lock();
        if inner.config.queue_url.is_empty() {
            return Err(SdkError::NotRegistered);
        }
        let sub = platform_to_sub(platform, token);
        let queue = QueueClient::with_transport(&inner.config.queue_url, Box::new(UreqTransport));
        let qtoken = queue.login(&inner.identity).map_err(SdkError::network)?;
        queue
            .push_subscribe_sub(&qtoken, &sub)
            .map_err(SdkError::network)?;
        Ok(())
    }

    /// Remove this device's push registration from the queue (user disabled
    /// notifications, or the device is being removed). Safe to call when none
    /// exists. Mail still queues and arrives on the next `sync()` — disabling
    /// notifications never drops messages.
    pub fn unregister_push(&self, platform: PushPlatform, token: String) -> Result<(), SdkError> {
        let inner = self.lock();
        if inner.config.queue_url.is_empty() {
            return Err(SdkError::NotRegistered);
        }
        let sub = platform_to_sub(platform, token);
        let queue = QueueClient::with_transport(&inner.config.queue_url, Box::new(UreqTransport));
        let qtoken = queue.login(&inner.identity).map_err(SdkError::network)?;
        queue
            .push_unsubscribe_sub(&qtoken, &sub)
            .map_err(SdkError::network)?;
        Ok(())
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
        distribute_key(&mut inner, &me, &stored, &group, &targets);
        Ok(group_id)
    }

    /// Add `member` to a group and re-distribute keys with the updated roster.
    pub fn group_add(&self, group_id: String, member: String) -> Result<(), SdkError> {
        let mut inner = self.lock();
        let me = require_handle(&inner)?;

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
        distribute_key(&mut inner, &me, &stored, &group, &targets);
        Ok(())
    }

    /// Send a text message to a group. Returns the stored [`Message`].
    ///
    /// Runs the shared fan-out ([`flow::group_send`]): it advances the group
    /// ratchet, fans the one ciphertext to every member's cluster (our own
    /// siblings included, so the group reads consistently across our devices), and
    /// records our transcript copy. The closure below deposits each copy into the
    /// recipient's queue.
    pub fn group_send(&self, group_id: String, text: String) -> Result<Message, SdkError> {
        let mut inner = self.lock();
        let me = require_handle(&inner)?;
        let dir_url = inner.config.dir_url.clone();

        let mut stored = groups::load(&inner.store, &group_id)
            .map_err(SdkError::storage)?
            .ok_or_else(|| SdkError::invalid("no such group"))?;
        let app = wireops::text_message(&mut OsPlatform, &text);
        let net = SdkNet {
            dir: DirectoryClient::with_transport(&dir_url, Box::new(UreqTransport)),
        };

        // Disjoint field borrows: `group_send` writes `store`; the closure logs in
        // with `identity` (the store is threaded through as its first argument).
        let inner = &mut *inner;
        let identity = &inner.identity;
        let store = &mut inner.store;

        // The recipient's queue session is per-member but `deliver` is per-device;
        // cache it so we log in once per member, re-logging when the record changes.
        let mut queue_cache: Option<(WalletPublicKey, Option<(QueueClient, String)>)> = None;
        let mut deliver = |_store: &mut FileStore,
                           _handle: &Handle,
                           record: &SignedRecord,
                           device: &Device,
                           item: MailItem|
         -> DeliveryPath {
            if queue_cache.as_ref().map(|(w, _)| *w) != Some(record.record.wallet) {
                let queue =
                    QueueClient::with_transport(&record.record.queue, Box::new(UreqTransport));
                let session = queue.login(identity).ok().map(|t| (queue, t));
                queue_cache = Some((record.record.wallet, session));
            }
            if let Some((_, Some((queue, qtoken)))) = queue_cache.as_ref() {
                if let Ok(blob) = serde_json::to_string(&item) {
                    if queue
                        .deposit(
                            qtoken,
                            &wallet_hex(&record.record.wallet),
                            &wireops::device_slot(&device.device_key),
                            &blob,
                        )
                        .is_ok()
                    {
                        return DeliveryPath::Queue;
                    }
                }
            }
            DeliveryPath::Failed
        };

        let out = flow::group_send(identity, store, &net, &me, &mut stored, &app, &mut deliver);

        let delivery = if out.delivered > 0 {
            DeliveryState::Sent
        } else {
            DeliveryState::Queued
        };
        Ok(Message {
            id: out.id,
            thread: group_id,
            from_me: true,
            sender: me.as_str().to_string(),
            text: app.summary(),
            sent_at: app.timestamp,
            delivery,
        })
    }

    /// Leave a group: announce our authenticated departure to every other member
    /// so they drop us and re-key ([`flow::group_leave`]), then drop the local
    /// state. Previously this was a bare local remove that never told the group —
    /// so a departed SDK user kept working keys and no member rekeyed.
    pub fn group_leave(&self, group_id: String) -> Result<(), SdkError> {
        let mut inner = self.lock();
        let me = require_handle(&inner)?;
        let stored = groups::load(&inner.store, &group_id)
            .map_err(SdkError::storage)?
            .ok_or_else(|| SdkError::invalid("no such group"))?;
        let dir_url = inner.config.dir_url.clone();
        let my_name = inner.config.name.clone();
        let my_queue = inner.config.queue_url.clone();
        let net = SdkNet {
            dir: DirectoryClient::with_transport(&dir_url, Box::new(UreqTransport)),
        };

        // Disjoint field borrows: `group_leave` writes `store`; the closure logs in
        // with `identity` (the store is threaded through as its first argument).
        let inner = &mut *inner;
        let identity = &inner.identity;
        let store = &mut inner.store;

        let mut queue_cache: Option<(WalletPublicKey, Option<(QueueClient, String)>)> = None;
        let mut deliver = |_store: &mut FileStore,
                           _handle: &Handle,
                           record: &SignedRecord,
                           device: &Device,
                           item: MailItem| {
            if queue_cache.as_ref().map(|(w, _)| *w) != Some(record.record.wallet) {
                let queue =
                    QueueClient::with_transport(&record.record.queue, Box::new(UreqTransport));
                let session = queue.login(identity).ok().map(|t| (queue, t));
                queue_cache = Some((record.record.wallet, session));
            }
            if let Some((_, Some((queue, qtoken)))) = queue_cache.as_ref() {
                if let Ok(blob) = serde_json::to_string(&item) {
                    let _ = queue.deposit(
                        qtoken,
                        &wallet_hex(&record.record.wallet),
                        &wireops::device_slot(&device.device_key),
                        &blob,
                    );
                }
            }
        };
        flow::group_leave(
            identity,
            store,
            &mut OsPlatform,
            &net,
            &me,
            &my_name,
            &my_queue,
            &stored,
            &mut deliver,
        );
        Ok(())
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

    /// Shared 1:1 delivery path: run the shared trust chokepoint
    /// ([`flow::lookup_verified`]), then the shared fan-out ([`flow::send_app`]).
    /// The SDK's closures deposit each sealed copy into the recipient's queue
    /// (with endpoint failover, #54); the self-sync closure mirrors the send to
    /// our own other devices' slots in our own queue — the unification that gives
    /// the SDK the self-sync it previously lacked. `send_app` records our own
    /// transcript copy and returns the tally we map to a [`DeliveryState`].
    fn deliver_app(&self, peer_handle: String, app: AppMessage) -> Result<Message, SdkError> {
        let mut inner = self.lock();
        if inner.config.handle.is_empty() {
            return Err(SdkError::NotRegistered);
        }
        let me = Handle::new(inner.config.handle.clone()).map_err(SdkError::invalid)?;
        let my_handle = inner.config.handle.clone();
        let my_name = inner.config.name.clone();
        let my_queue_url = inner.config.queue_url.clone();
        let dir_url = inner.config.dir_url.clone();
        let net = SdkNet {
            dir: DirectoryClient::with_transport(&dir_url, Box::new(UreqTransport)),
        };

        // The shared trust chokepoint: resolve + verify + fail closed on a changed
        // pinned wallet or a rolled-back record. A refusal is surfaced as
        // `IdentityChanged` (and fires the listener) exactly as before.
        let (peer, precord) = match flow::lookup_verified(&mut inner.store, &net, &peer_handle) {
            Ok(pair) => pair,
            Err(flow::TrustError::IdentityChanged) | Err(flow::TrustError::StaleRecord) => {
                if let Some(l) = inner.listener.clone() {
                    l.on_key_change(peer_handle.clone());
                }
                return Err(SdkError::IdentityChanged {
                    handle: peer_handle,
                });
            }
            Err(flow::TrustError::Unverified) => {
                return Err(SdkError::crypto("peer record failed verification"));
            }
            Err(flow::TrustError::BadHandle) => {
                return Err(SdkError::network("could not look up peer record"));
            }
        };

        // Learn the peer's chosen display name from their record.
        let _ = names::note(&mut inner.store, peer.as_str(), &precord.record.name);

        // Log in to each of the peer's queue endpoints in preference order
        // (primary `queue` then `queues`), so a deposit can fail over from a down
        // primary to a backup (#54). We surface an error only if *none* of them are
        // reachable — otherwise a queue deposit is the guaranteed floor.
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
        let my_hex = wallet_hex(&inner.identity.wallet_public());
        // A session to our own queue for the self-sync mirror (best-effort — a
        // single-device account has no siblings, so this is often unused).
        let my_session: Option<(QueueClient, String)> = {
            let q = QueueClient::with_transport(&my_queue_url, Box::new(UreqTransport));
            q.login(&inner.identity).ok().map(|t| (q, t))
        };

        // Disjoint field borrows: `send_app` writes `store`; the closures don't
        // touch it (the store is threaded through as their first argument).
        let inner = &mut *inner;
        let identity = &inner.identity;
        let store = &mut inner.store;

        let mut deliver = |_store: &mut FileStore,
                           _handle: &Handle,
                           _record: &SignedRecord,
                           device: &Device,
                           item: MailItem|
         -> DeliveryPath {
            let Ok(blob) = serde_json::to_string(&item) else {
                return DeliveryPath::Failed;
            };
            let slot = wireops::device_slot(&device.device_key);
            if sessions
                .iter()
                .any(|(q, t)| q.deposit(t, &peer_hex, &slot, &blob).is_ok())
            {
                DeliveryPath::Queue
            } else {
                DeliveryPath::Failed
            }
        };
        let mut self_deliver =
            |_store: &mut FileStore, _handle: &Handle, device: &Device, item: MailItem| {
                if let Some((q, t)) = &my_session {
                    if let Ok(blob) = serde_json::to_string(&item) {
                        let slot = wireops::device_slot(&device.device_key);
                        let _ = q.deposit(t, &my_hex, &slot, &blob);
                    }
                }
            };

        let out = flow::send_app(
            identity,
            store,
            &mut OsPlatform,
            &net,
            &me,
            &my_name,
            &my_queue_url,
            &peer,
            &precord,
            &app,
            &mut deliver,
            &mut self_deliver,
        );

        let delivery = if out.delivered > 0 {
            DeliveryState::Sent
        } else {
            DeliveryState::Queued
        };
        Ok(Message {
            id: out.id,
            thread: peer_handle,
            from_me: true,
            sender: my_handle,
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
        store_identity(inner.secrets.as_ref(), &new_identity)?;
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

/// Load the identity from the [`SecretStore`], migrating a legacy plaintext
/// `data_dir/identity.json` sidecar into the store if present, or generating and
/// storing a fresh one.
///
/// Order: (1) the store already holds `"identity"` → decode it; (2) else a legacy
/// sidecar exists → import it into the store, delete the sidecar, use it (clean
/// upgrade for pre-#65 SDK data); (3) else generate a fresh identity and store it.
fn load_or_create_identity(
    root: &std::path::Path,
    secrets: &dyn SecretStore,
) -> Result<Identity, SdkError> {
    if let Some(bytes) = secrets.load(IDENTITY_KEY.to_string())? {
        return decode_identity(&bytes);
    }

    // Migration: a legacy plaintext sidecar upgrades into the store, then the
    // plaintext copy is removed. Its bytes are the same JSON form we store, so it
    // imports verbatim (and is validated by `decode_identity`).
    let legacy = root.join("identity.json");
    if let Ok(bytes) = std::fs::read(&legacy) {
        let identity = decode_identity(&bytes)?;
        secrets.store(IDENTITY_KEY.to_string(), bytes)?;
        let _ = std::fs::remove_file(&legacy);
        return Ok(identity);
    }

    let identity =
        Identity::generate(&mut OsPlatform).map_err(|e| SdkError::crypto(format!("{e:?}")))?;
    store_identity(secrets, &identity)?;
    Ok(identity)
}

/// Persist `identity`'s secret through the [`SecretStore`]. Used at first-run and
/// when device pairing adopts a new account.
fn store_identity(secrets: &dyn SecretStore, identity: &Identity) -> Result<(), SdkError> {
    secrets.store(IDENTITY_KEY.to_string(), encode_identity(identity)?)
}

/// Serialize `identity`'s persistable secret to the stored JSON form.
fn encode_identity(identity: &Identity) -> Result<Vec<u8>, SdkError> {
    let stored = StoredIdentity {
        wallet_secret: identity.wallet_secret(),
        device_seed: identity.device_seed(),
    };
    serde_json::to_vec(&stored).map_err(SdkError::storage)
}

/// Reconstruct an [`Identity`] from its stored JSON secret form.
fn decode_identity(bytes: &[u8]) -> Result<Identity, SdkError> {
    let stored: StoredIdentity = serde_json::from_slice(bytes).map_err(SdkError::storage)?;
    Identity::from_wallet_secret(stored.wallet_secret, stored.device_seed)
        .map_err(|e| SdkError::crypto(format!("{e:?}")))
}

/// Publish our record, merging this device into any record that already exists
/// for the handle (so re-registering or a prior pairing never drops siblings).
/// The merge+bump+sign+publish is the shared [`flow::publish_merged`]; this only
/// binds the SDK's `ureq` transport (the SDK has no advertised address, so `""`).
fn publish_merged(
    identity: &Identity,
    dir_url: &str,
    handle: &str,
    name: &str,
    queue_url: &str,
) -> Result<(), SdkError> {
    let me = Handle::new(handle).map_err(SdkError::invalid)?;
    let net = SdkNet {
        dir: DirectoryClient::with_transport(dir_url, Box::new(UreqTransport)),
    };
    flow::publish_merged(identity, &mut OsPlatform, &net, &me, name, queue_url, "")
        .map_err(SdkError::network)?;
    Ok(())
}

/// Map a [`PushPlatform`] + OS token into the queue's tagged subscription. For
/// Web Push / UnifiedPush the `token` is the endpoint URL; for APNs / FCM it's
/// the device/registration token (APNs also carries the app bundle `topic`).
fn platform_to_sub(platform: PushPlatform, token: String) -> PushSub {
    match platform {
        PushPlatform::WebPush => PushSub::WebPush { endpoint: token },
        PushPlatform::UnifiedPush => PushSub::UnifiedPush { endpoint: token },
        PushPlatform::Fcm => PushSub::Fcm { token },
        PushPlatform::Apns { topic } => PushSub::Apns { token, topic },
    }
}

/// The SDK [`flow::FlowSink`]: turn the message-bearing inbound events into
/// boundary [`Message`] DTOs the caller collects and the listener is fired with.
/// Edits/deletes are already applied to history by the flow (no DTO); receipts
/// stay unsurfaced; attachments the SDK doesn't persist.
struct SdkSink {
    messages: Vec<Message>,
    my_handle: String,
    now: u64,
}

impl flow::FlowSink for SdkSink {
    fn emit(&mut self, event: flow::FlowEvent) {
        use flow::FlowEvent::*;
        match event {
            DirectMessage { from, id, text, .. } => self.messages.push(Message {
                id,
                thread: from.clone(),
                from_me: false,
                sender: from,
                text,
                sent_at: self.now,
                delivery: DeliveryState::Delivered,
            }),
            GroupMessage {
                group_id,
                sender,
                id,
                text,
                ..
            } => self.messages.push(Message {
                id,
                thread: group_id,
                from_me: false,
                sender,
                text,
                sent_at: self.now,
                delivery: DeliveryState::Delivered,
            }),
            SelfMirror { peer, id, text } => self.messages.push(Message {
                id,
                thread: peer,
                from_me: true,
                sender: self.my_handle.clone(),
                text,
                sent_at: self.now,
                delivery: DeliveryState::Sent,
            }),
            // Receipts/edits/deletes/attachments carry no new visible message.
            _ => {}
        }
    }
}

/// Process one inbound [`MailItem`] through the shared [`flow::process_item`]: the
/// flow applies all state (history, groups, keys) and emits DTO-bearing events to
/// `sink`; the SDK closures below deposit any follow-up send (a read receipt, a
/// group key (re)distribution) into the recipient's queue, matching the SDK's
/// queue-only delivery.
fn process_inbound(inner: &mut Inner, item: MailItem, sink: &mut SdkSink) -> flow::ItemOutcome {
    let me = match Handle::new(inner.config.handle.clone()) {
        Ok(h) => h,
        Err(_) => return flow::ItemOutcome::Retry,
    };
    let my_name = inner.config.name.clone();
    let my_queue_url = inner.config.queue_url.clone();
    let dir_url = inner.config.dir_url.clone();
    let my_hex = wallet_hex(&inner.identity.wallet_public());
    let net = SdkNet {
        dir: DirectoryClient::with_transport(&dir_url, Box::new(UreqTransport)),
    };
    // Our own queue session for the read-receipt self-sync mirror (best-effort).
    let my_session: Option<(QueueClient, String)> = {
        let q = QueueClient::with_transport(&my_queue_url, Box::new(UreqTransport));
        q.login(&inner.identity).ok().map(|t| (q, t))
    };

    // Disjoint field borrows: the flow writes `store`; the closures don't touch it
    // (the store is threaded through as their first argument).
    let inner = &mut *inner;
    let identity = &inner.identity;
    let store = &mut inner.store;

    // The recipient's queue session is per-member but `deliver` is called
    // per-device; cache the login so we only open it once per recipient.
    let mut queue_cache: Option<(WalletPublicKey, Option<(QueueClient, String)>)> = None;
    let mut deliver = |_store: &mut FileStore,
                       _handle: &Handle,
                       record: &SignedRecord,
                       device: &Device,
                       item: MailItem|
     -> DeliveryPath {
        if queue_cache.as_ref().map(|(w, _)| *w) != Some(record.record.wallet) {
            let queue = QueueClient::with_transport(&record.record.queue, Box::new(UreqTransport));
            let session = queue.login(identity).ok().map(|t| (queue, t));
            queue_cache = Some((record.record.wallet, session));
        }
        if let Some((_, Some((queue, qtoken)))) = queue_cache.as_ref() {
            if let Ok(blob) = serde_json::to_string(&item) {
                let slot = wireops::device_slot(&device.device_key);
                if queue
                    .deposit(qtoken, &wallet_hex(&record.record.wallet), &slot, &blob)
                    .is_ok()
                {
                    return DeliveryPath::Queue;
                }
            }
        }
        DeliveryPath::Failed
    };
    let mut self_deliver =
        |_store: &mut FileStore, _handle: &Handle, device: &Device, item: MailItem| {
            if let Some((q, t)) = &my_session {
                if let Ok(blob) = serde_json::to_string(&item) {
                    let slot = wireops::device_slot(&device.device_key);
                    let _ = q.deposit(t, &my_hex, &slot, &blob);
                }
            }
        };

    flow::process_item(
        identity,
        store,
        &mut OsPlatform,
        &net,
        &me,
        &my_name,
        &my_queue_url,
        &[],
        item,
        sink,
        &mut deliver,
        &mut self_deliver,
    )
}

/// The SDK's [`flow::FlowNet`]: directory lookups over the native `ureq`
/// [`UreqTransport`].
struct SdkNet {
    dir: DirectoryClient,
}

impl flow::FlowNet for SdkNet {
    fn lookup(&self, handle: &Handle) -> anyhow::Result<SignedRecord> {
        self.dir.lookup(handle)
    }
    fn publish(&self, identity: &Identity, record: &SignedRecord) -> anyhow::Result<()> {
        let token = self.dir.login(identity)?;
        self.dir.publish(&token, record)
    }
}

/// Seal our group sender-key (a [`GroupInvitePayload`]) to every device of each
/// `targets` handle over the pairwise E2E channel (never this exact device).
///
/// The shared lookup/verify/**pin-check**/seal loop lives in
/// [`flow::distribute_key`]; this only supplies the SDK's per-device delivery
/// (deposit into the recipient's queue). Best-effort: unreachable members are
/// skipped (a re-invite re-distributes). Routing the pin check through the shared
/// flow is what gives the SDK the fail-closed-on-changed-wallet guard.
fn distribute_key(
    inner: &mut Inner,
    me: &Handle,
    stored: &StoredGroup,
    group: &CoreGroup,
    targets: &[String],
) {
    let dir_url = inner.config.dir_url.clone();
    let my_name = inner.config.name.clone();
    let my_queue = inner.config.queue_url.clone();
    let net = SdkNet {
        dir: DirectoryClient::with_transport(&dir_url, Box::new(UreqTransport)),
    };
    // Disjoint field borrows: the pin check reads `store`; the deliver closure
    // logs in with `identity`.
    let identity = &inner.identity;
    let store = &mut inner.store;

    // The recipient's queue session is per-member, but `deliver` is called
    // per-device; cache it so we only log in once per member (records arrive
    // grouped by member), re-logging when the record changes.
    let mut queue_cache: Option<(WalletPublicKey, Option<(QueueClient, String)>)> = None;
    let mut deliver = |_store: &mut FileStore,
                       _handle: &Handle,
                       record: &SignedRecord,
                       device: &Device,
                       item: MailItem| {
        if queue_cache.as_ref().map(|(w, _)| *w) != Some(record.record.wallet) {
            let queue = QueueClient::with_transport(&record.record.queue, Box::new(UreqTransport));
            let session = queue.login(identity).ok().map(|t| (queue, t));
            queue_cache = Some((record.record.wallet, session));
        }
        if let Some((_, Some((queue, qtoken)))) = queue_cache.as_ref() {
            if let Ok(blob) = serde_json::to_string(&item) {
                let _ = queue.deposit(
                    qtoken,
                    &wallet_hex(&record.record.wallet),
                    &wireops::device_slot(&device.device_key),
                    &blob,
                );
            }
        }
    };
    flow::distribute_key(
        identity,
        store,
        &mut OsPlatform,
        &net,
        me,
        &my_name,
        &my_queue,
        &stored.id,
        &stored.name,
        &group.distribution(),
        &stored.members,
        targets,
        &mut deliver,
    );
}

/// The registered handle, or [`SdkError::NotRegistered`] if `register` hasn't run.
fn require_handle(inner: &Inner) -> Result<Handle, SdkError> {
    if inner.config.handle.is_empty() {
        return Err(SdkError::NotRegistered);
    }
    Handle::new(inner.config.handle.clone()).map_err(SdkError::invalid)
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
