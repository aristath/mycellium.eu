//! **The app engine** — a headless messenger core over MLS-over-Nostr (Marmot).
//!
//! This crate is the layer that turns the three proven primitives into an actual
//! messenger:
//!
//! ```text
//!   mycellium-app          App / Account   (this crate: messenger engine)
//!     │  setup · contacts+trust · conversations · receive loop · history
//!     ▼
//!   mycellium-multidevice  DeviceAccount   (one account, many device-leaves)
//!     ▼
//!   mycellium-mls          MlsEngine       (MLS crypto + Marmot events)  ── MDK
//!     ▼
//!   mycellium-nostr        NostrTransport  (relay I/O)
//!     ▼
//!        relay
//! ```
//!
//! # What it provides
//!
//! - **Setup** — create/load an account (an account key + this device key),
//!   publish this device's KeyPackage + the account device list, connect to
//!   relays, subscribe to the incoming stream. See [`App::open_solo`] /
//!   [`App::open_manager`] / [`App::open_member`].
//! - **Contacts + trust hardening** — add a contact by npub (+ optional NIP-05),
//!   pinned trust-on-first-use, plus **key/identity-change detection**: an
//!   account key that differs from the pin surfaces as
//!   [`TrustStatus::IdentityChanged`] and is never silently trusted (Nostr has no
//!   built-in key-change protection — this is our hardening). Plus an
//!   out-of-band [`safety_number`] verification helper.
//! - **Conversations** — a 1:1 conversation is an MLS group containing exactly
//!   the two accounts' devices; groups are >2 accounts. [`App::start_conversation`],
//!   [`App::send_text`].
//! - **Receive loop** — [`App::next_message`] drains the relay subscription,
//!   routes each event through [`DeviceAccount::process_incoming`], decrypts, and
//!   persists to a per-conversation transcript.
//! - **History** — transcripts persist (SQLCipher-encrypted SQLite) and survive
//!   restart.
//!
//! # Storage
//!
//! Two encrypted SQLite databases per device, both keyed from the device seed:
//! the **MLS state** (`mdk-sqlite-storage`, so leaf/epoch state is durable) and
//! the **app data** ([`store::AppStore`] — contacts, trust pins, transcripts).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mdk_sqlite_storage::{EncryptionConfig, MdkSqliteStorage};
use mycellium_mls::{GroupId, Keys, Kind, MlsEngine};
use mycellium_multidevice::{DeviceAccount, DeviceEntry, DeviceList, Incoming, KIND_GROUP_MESSAGE};
use mycellium_nostr::{NostrTransport, Notification};
use nostr::{PublicKey, RelayUrl};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

pub mod contacts;
pub mod store;

pub use contacts::{safety_number, Contact, TrustStatus};
pub use store::{AppStore, StoredMessage};

// Re-export the identity types a caller touches so downstream code depends on
// this crate rather than reaching into the layers below it.
pub use mycellium_multidevice::DeviceEntry as Device;
pub use nostr::{Keys as AccountKeys, PublicKey as AccountId, RelayUrl as Relay};

/// Errors surfaced by the app engine.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the multi-device account layer (enrolment, send, routing).
    #[error(transparent)]
    Account(#[from] mycellium_multidevice::Error),
    /// An error from the relay transport.
    #[error(transparent)]
    Transport(#[from] mycellium_nostr::Error),
    /// An error from the app-data store (contacts / transcripts).
    #[error(transparent)]
    Store(#[from] store::Error),
    /// An error opening the durable MLS state database.
    #[error("MLS storage error: {0}")]
    MlsStorage(String),
    /// A store path could not be prepared.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The receive loop was used before [`App::subscribe`] ran.
    #[error("not subscribed: call subscribe() before receiving")]
    NotSubscribed,
    /// No contact is known under this local handle.
    #[error("no contact known under handle '{0}'")]
    UnknownContact(String),
    /// A conversation id was not valid hex.
    #[error("invalid conversation id '{0}'")]
    BadConversationId(String),
}

/// Convenience result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A stable conversation identifier: the hex of the MLS group id (which never
/// changes for the life of the group), so it round-trips to a [`GroupId`] and
/// survives restart without any extra mapping.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConversationId(String);

impl ConversationId {
    fn from_group(group: &GroupId) -> Self {
        Self(hex_encode(group.as_slice()))
    }

    /// The underlying MLS group id.
    fn group_id(&self) -> Result<GroupId> {
        let bytes = hex_decode(&self.0).ok_or_else(|| Error::BadConversationId(self.0.clone()))?;
        Ok(GroupId::from_slice(&bytes))
    }

    /// The id as a string slice (its persisted key).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ConversationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A newly received, decrypted, and persisted message surfaced by the receive
/// loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedMessage {
    /// The conversation it belongs to.
    pub conversation: ConversationId,
    /// The author's device pubkey (the MLS-leaf that sent it).
    pub author: PublicKey,
    /// The decrypted plaintext.
    pub text: String,
    /// Unix seconds when it was received.
    pub timestamp: u64,
}

/// A headless messenger account bound to **one device**.
///
/// Owns this device's persistent MLS state (via [`DeviceAccount`] over
/// `mdk-sqlite-storage`) and the app-data store (contacts, trust, transcripts).
/// A multi-device account is several `App`s — one per device — sharing an
/// account key; the account key holder is the *manager* that publishes the
/// device list.
pub struct App {
    device: DeviceAccount<MdkSqliteStorage>,
    store: AppStore,
    account: PublicKey,
    incoming: Option<broadcast::Receiver<Notification>>,
}

impl App {
    // -- Setup --------------------------------------------------------------

    /// Open a **solo** account (the common single-device case): the account key
    /// *is* the device key. Opens the durable stores under `data_dir` and builds
    /// the device over persistent MLS storage.
    pub fn open_solo(keys: Keys, relays: Vec<RelayUrl>, data_dir: &Path) -> Result<Self> {
        let account = keys.public_key();
        let (mls, store) = Self::open_stores(&keys, data_dir)?;
        let device = DeviceAccount::solo_with(keys, relays, mls);
        Ok(Self::assemble(device, store, account))
    }

    /// Open a **manager** device: it holds the account key and can publish /
    /// update the account's device list.
    pub fn open_manager(
        account_keys: Keys,
        device_keys: Keys,
        relays: Vec<RelayUrl>,
        data_dir: &Path,
    ) -> Result<Self> {
        let account = account_keys.public_key();
        let (mls, store) = Self::open_stores(&device_keys, data_dir)?;
        let device = DeviceAccount::manager_with(account_keys, device_keys, relays, mls);
        Ok(Self::assemble(device, store, account))
    }

    /// Open an ordinary **member** device of `account`: it can join groups and
    /// message, but does not hold the account key and cannot alter the list.
    pub fn open_member(
        account: PublicKey,
        device_keys: Keys,
        relays: Vec<RelayUrl>,
        data_dir: &Path,
    ) -> Result<Self> {
        let (mls, store) = Self::open_stores(&device_keys, data_dir)?;
        let device = DeviceAccount::member_with(account, device_keys, relays, mls);
        Ok(Self::assemble(device, store, account))
    }

    /// Open both durable databases under `data_dir`, each SQLCipher-encrypted
    /// with a distinct key derived from this device's seed.
    fn open_stores(
        device_keys: &Keys,
        data_dir: &Path,
    ) -> Result<(MlsEngine<MdkSqliteStorage>, AppStore)> {
        std::fs::create_dir_all(data_dir)?;
        let seed = device_keys.secret_key().to_secret_bytes();

        let mls_key = derive_db_key(&seed, b"mycellium-mls-db-v1");
        let mls_storage = MdkSqliteStorage::new_with_key(
            data_dir.join("mls.sqlite"),
            EncryptionConfig::new(mls_key),
        )
        .map_err(|e| Error::MlsStorage(e.to_string()))?;
        let mls = MlsEngine::new(mls_storage);

        let app_key = derive_db_key(&seed, b"mycellium-app-db-v1");
        let store = AppStore::open(&data_dir.join("app.sqlite"), app_key)?;
        Ok((mls, store))
    }

    fn assemble(
        device: DeviceAccount<MdkSqliteStorage>,
        store: AppStore,
        account: PublicKey,
    ) -> Self {
        Self {
            device,
            store,
            account,
            incoming: None,
        }
    }

    /// This account's stable identity (npub).
    #[must_use]
    pub fn account(&self) -> PublicKey {
        self.account
    }

    /// This device's own pubkey (its MLS-leaf identity).
    #[must_use]
    pub fn device_pubkey(&self) -> PublicKey {
        self.device.device_pubkey()
    }

    /// Connect this device's transport to its relays.
    pub async fn connect(&self) -> Result<()> {
        self.device.connect().await?;
        Ok(())
    }

    /// Publish this device's KeyPackage (kind:30443) so it can be enrolled.
    pub async fn publish_key_package(&self) -> Result<()> {
        self.device.publish_key_package().await?;
        Ok(())
    }

    /// Publish (or replace) the account device list. Only a manager (or solo)
    /// device holds the account key needed to do this.
    pub async fn publish_device_list(&self, devices: Vec<DeviceEntry>) -> Result<()> {
        self.device.publish_device_list(devices).await?;
        Ok(())
    }

    /// Subscribe to the incoming stream (gift-wrapped Welcomes to this device and
    /// every group message/commit) and capture the notification receiver used by
    /// [`App::next_message`]. Call this **before** anything you expect to receive.
    pub async fn subscribe(&mut self) -> Result<()> {
        // Grab the receiver first so nothing published after subscribe is missed.
        self.incoming = Some(self.device.transport().notifications());
        self.device.subscribe_incoming().await?;
        Ok(())
    }

    /// Fetch an account's published device list off the relays (or `None`).
    /// Used both to enrol contacts and, for the trust layer, to observe the key
    /// a claimed identity is currently presenting.
    pub async fn fetch_device_list(&self, account: PublicKey) -> Result<Option<DeviceList>> {
        Ok(self.device.fetch_device_list(account).await?)
    }

    /// Disconnect from relays and shut the transport down.
    pub async fn shutdown(&self) {
        self.device.transport().shutdown().await;
    }

    // -- Contacts & trust ---------------------------------------------------

    /// Add a contact under local handle `id`, **pinning** `account` (TOFU).
    ///
    /// - New handle → pinned, returns [`TrustStatus::Pinned`].
    /// - Same handle, same key → returns the existing status (`Pinned`/`Verified`).
    /// - Same handle, **different** key → returns [`TrustStatus::IdentityChanged`]
    ///   and **does not** overwrite the pin: the engine refuses to silently accept
    ///   a changed identity.
    pub fn add_contact(
        &self,
        id: &str,
        account: PublicKey,
        nip05: Option<String>,
        name: Option<String>,
    ) -> Result<TrustStatus> {
        let existing = self.store.get_contact(id)?;
        let status = contacts::classify(existing.as_ref(), &account);
        if status == TrustStatus::Unverified {
            self.store.put_contact(&Contact {
                id: id.to_string(),
                account,
                nip05,
                name,
                verified: false,
                added_at: now(),
            })?;
            return Ok(TrustStatus::Pinned);
        }
        // Known handle: never silently re-pin. Return the classification as-is
        // (matching key → Pinned/Verified; different key → IdentityChanged).
        Ok(status)
    }

    /// Classify a **freshly observed** account key for a known contact against
    /// its pin — the passive key-change signal. A key that differs from the pin
    /// yields [`TrustStatus::IdentityChanged`]; the pin is left untouched.
    pub fn observe_identity(&self, id: &str, observed: PublicKey) -> Result<TrustStatus> {
        let contact = self.store.get_contact(id)?;
        Ok(contacts::classify(contact.as_ref(), &observed))
    }

    /// Look up a contact by local handle.
    pub fn contact(&self, id: &str) -> Result<Option<Contact>> {
        Ok(self.store.get_contact(id)?)
    }

    /// Every known contact.
    pub fn contacts(&self) -> Result<Vec<Contact>> {
        Ok(self.store.list_contacts()?)
    }

    /// The out-of-band safety number for a contact (this account vs. theirs).
    pub fn safety_number(&self, id: &str) -> Result<String> {
        let c = self
            .store
            .get_contact(id)?
            .ok_or_else(|| Error::UnknownContact(id.to_string()))?;
        Ok(safety_number(&self.account, &c.account))
    }

    /// Mark a contact as out-of-band **verified** (after comparing safety
    /// numbers). Strengthens its trust to [`TrustStatus::Verified`].
    pub fn mark_verified(&self, id: &str) -> Result<()> {
        if self.store.get_contact(id)?.is_none() {
            return Err(Error::UnknownContact(id.to_string()));
        }
        self.store.set_verified(id, true)?;
        Ok(())
    }

    // -- Conversations ------------------------------------------------------

    /// Start a 1:1 conversation with a known contact: create an MLS group that
    /// enrols **every device of both accounts** (resolved via the contact's
    /// device list) and record it locally. Returns its conversation id.
    pub async fn start_conversation(&self, contact_id: &str) -> Result<ConversationId> {
        let contact = self
            .store
            .get_contact(contact_id)?
            .ok_or_else(|| Error::UnknownContact(contact_id.to_string()))?;

        let title = contact.name.clone().unwrap_or_else(|| contact.id.clone());
        let group = self
            .device
            .create_group_with(&[contact.account], &title, "1:1 conversation")
            .await?;
        let conv = ConversationId::from_group(&group);
        self.store
            .ensure_conversation(conv.as_str(), &title, now())?;
        Ok(conv)
    }

    /// Start a group conversation with several known contacts.
    pub async fn start_group(&self, title: &str, contact_ids: &[&str]) -> Result<ConversationId> {
        let mut accounts = Vec::with_capacity(contact_ids.len());
        for id in contact_ids {
            let c = self
                .store
                .get_contact(id)?
                .ok_or_else(|| Error::UnknownContact((*id).to_string()))?;
            accounts.push(c.account);
        }
        let group = self
            .device
            .create_group_with(&accounts, title, "group")
            .await?;
        let conv = ConversationId::from_group(&group);
        self.store
            .ensure_conversation(conv.as_str(), title, now())?;
        Ok(conv)
    }

    /// Encrypt + publish a text message to a conversation, and record it in the
    /// local transcript (`from_me`).
    pub async fn send_text(&self, conversation: &ConversationId, text: &str) -> Result<()> {
        let gid = conversation.group_id()?;
        let event_id = self.device.send_message(&gid, text).await?;
        self.store.append_message(
            conversation.as_str(),
            &StoredMessage {
                from_me: true,
                author: None,
                text: text.to_string(),
                timestamp: now(),
            },
            &event_id.to_hex(),
        )?;
        Ok(())
    }

    /// Every conversation this device knows: `(id, title)`.
    pub fn conversations(&self) -> Result<Vec<(ConversationId, String)>> {
        Ok(self
            .store
            .list_conversations()?
            .into_iter()
            .map(|(id, title)| (ConversationId(id), title))
            .collect())
    }

    /// A conversation's full persisted transcript (sent + received, in order).
    pub fn transcript(&self, conversation: &ConversationId) -> Result<Vec<StoredMessage>> {
        Ok(self.store.transcript(conversation.as_str())?)
    }

    // -- Receive loop -------------------------------------------------------

    /// Wait up to `timeout` for the **next decrypted application message**,
    /// persist it to its conversation transcript, and return it.
    ///
    /// Intervening events are handled transparently: a gift-wrapped Welcome joins
    /// the group (and records the conversation), a commit advances the epoch, a
    /// duplicate re-delivery is dropped. Returns `Ok(None)` if no message arrives
    /// before the timeout (or the stream closes).
    pub async fn next_message(&mut self, timeout: Duration) -> Result<Option<ReceivedMessage>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            // Scope the receiver borrow so `ingest` can take &mut self after.
            let event = {
                let recv = self.incoming.as_mut().ok_or(Error::NotSubscribed)?;
                NostrTransport::next_event(recv, remaining, |e| {
                    e.kind == Kind::GiftWrap || e.kind == Kind::Custom(KIND_GROUP_MESSAGE)
                })
                .await
            };
            let Some(event) = event else {
                return Ok(None);
            };
            if let Some(message) = self.ingest(&event).await? {
                return Ok(Some(message));
            }
        }
    }

    /// Drain and apply every incoming event currently available within a short
    /// idle window (joins + commits + messages), persisting any messages. Returns
    /// all messages seen. Useful to settle enrolment/epoch state before sending.
    pub async fn pump(&mut self, idle: Duration) -> Result<Vec<ReceivedMessage>> {
        let mut out = Vec::new();
        while let Some(m) = self.next_message(idle).await? {
            out.push(m);
        }
        Ok(out)
    }

    /// Route one relay event through the engine and persist any message.
    async fn ingest(&mut self, event: &nostr::Event) -> Result<Option<ReceivedMessage>> {
        match self.device.process_incoming(event).await? {
            Incoming::Joined { group } => {
                self.record_conversation(&group)?;
                Ok(None)
            }
            Incoming::CommitApplied { group } => {
                self.record_conversation(&group)?;
                Ok(None)
            }
            Incoming::Message {
                group,
                content,
                author,
            } => {
                self.record_conversation(&group)?;
                let conv = ConversationId::from_group(&group);
                let ts = now();
                let inserted = self.store.append_message(
                    conv.as_str(),
                    &StoredMessage {
                        from_me: false,
                        author: Some(author),
                        text: content.clone(),
                        timestamp: ts,
                    },
                    &event.id.to_hex(),
                )?;
                if inserted {
                    Ok(Some(ReceivedMessage {
                        conversation: conv,
                        author,
                        text: content,
                        timestamp: ts,
                    }))
                } else {
                    // A duplicate re-delivery — already in the transcript.
                    Ok(None)
                }
            }
            Incoming::DeviceListUpdate(_) | Incoming::Ignored => Ok(None),
        }
    }

    /// Ensure a conversation record exists for `group`, titling it from the MLS
    /// group's own name when this device didn't create it (e.g. a joiner).
    fn record_conversation(&self, group: &GroupId) -> Result<()> {
        let conv = ConversationId::from_group(group);
        if self.store.conversation_title(conv.as_str())?.is_some() {
            return Ok(());
        }
        let title = self
            .device
            .groups()?
            .into_iter()
            .find(|g| &g.mls_group_id == group)
            .map(|g| g.name)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "conversation".to_string());
        self.store
            .ensure_conversation(conv.as_str(), &title, now())?;
        Ok(())
    }
}

/// Derive a 32-byte at-rest database key from a device seed and a domain label,
/// so the MLS-state db and the app-data db get distinct keys from the one seed.
fn derive_db_key(seed: &[u8], domain: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(b":");
    hasher.update(seed);
    hasher.finalize().into()
}

/// Current unix time in whole seconds.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercase-hex encode.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Decode lowercase/uppercase hex; `None` if malformed.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi << 4 | lo) as u8);
        i += 2;
    }
    Some(out)
}
