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
use mycellium_multidevice::{
    verify_migration, DeviceAccount, DeviceEntry, DeviceList, Incoming, KIND_GROUP_MESSAGE,
};
use mycellium_nostr::{NostrTransport, Notification};
use nostr::{PublicKey, RelayUrl};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

pub mod contacts;
pub mod pairing;
pub mod store;

pub use contacts::{safety_number, Contact, TrustStatus};
pub use pairing::{sas_for, PairingOffer, ParseOfferError};
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
    /// Device pairing was attempted on a device that does not hold the account
    /// key, so it cannot authorize (sign into the device list) a new device.
    #[error("this device is not the account manager; it cannot approve a new device")]
    NotManager,
    /// No device list exists yet for this account, so there is nothing to add the
    /// new device to. Publish this device's identity first.
    #[error("no device list published for this account yet; publish before pairing")]
    NoDeviceList,
    /// A manager tried to remove the very device it is operating from. A device
    /// cannot evict its own leaf (MLS forbids committing your own removal) — do it
    /// from another device of the account.
    #[error("cannot remove the current device from its own account; do it from another device")]
    CannotRemoveCurrentDevice,
    /// Removing this device would leave the account with no devices at all.
    #[error("cannot remove the account's last remaining device")]
    LastDevice,
    /// The named device is not in the account's device list, so there is nothing
    /// to remove.
    #[error("device {0} is not in the account's device list")]
    UnknownDevice(PublicKey),
    /// No account-key migration attestation was found on the relays for a contact
    /// whose migration was expected (e.g. during [`App::accept_key_migration`]).
    #[error("no key-migration published for account {0}")]
    NoMigration(PublicKey),
    /// A purported migration attestation failed mutual-signature verification.
    #[error("migration attestation is invalid: {0}")]
    BadMigration(String),
    /// A migration attestation is well-formed but does not link the expected
    /// old→new identities (e.g. the confirmed new key does not match the one the
    /// old key actually signed a migration to).
    #[error("migration does not match the expected old and new identity")]
    MigrationMismatch,
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

/// The result of probing a pinned contact for a published **account-key
/// migration** — the deliberately non-automatic signal at the heart of the trust
/// model.
///
/// A migration is **never** auto-accepted: even the [`Self::PendingReverification`]
/// case (a fully, mutually valid attestation) requires the user to compare the new
/// safety number out of band before [`App::accept_key_migration`] re-pins, because
/// a compromised old key can sign a valid-but-fraudulent migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationSignal {
    /// No migration attestation is published under the contact's pinned key.
    None,
    /// A migration signed by **both** the pinned old key and the claimed new key
    /// exists. It is *not* trusted yet: surface it to the user, who must compare
    /// `new_safety_number` out of band with the contact before accepting.
    PendingReverification {
        /// The contact's currently pinned (old) account key.
        old_pubkey: PublicKey,
        /// The new account key the migration points to.
        new_pubkey: PublicKey,
        /// The safety number for *this* account vs. the **new** key, to compare
        /// out of band before accepting.
        new_safety_number: String,
    },
    /// A migration-shaped event exists but failed verification — it is not signed
    /// by the contact's pinned old key, or the new-key attestation is missing or
    /// invalid. A forgery: never acceptable, never surfaced as trustworthy.
    Forged {
        /// Why verification failed (for logging/UX; not a trust decision input).
        reason: String,
    },
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

    // -- Account-key rotation (self) ----------------------------------------

    /// **Rotate this account's identity key** (manager/solo only).
    ///
    /// Generates a fresh account keypair, publishes a mutual old→new migration
    /// attestation (signed by the old key and embedding the new key's continuation
    /// attestation), and re-signs + republishes the device list under the new key.
    /// Because MLS leaves bind to **device** keys — untouched here — every existing
    /// group and conversation keeps working with no re-keying: only the Nostr
    /// identity and the device-list signer change. Returns the **new account
    /// keypair**, which the caller must persist (it is now this account's identity).
    ///
    /// Errors with [`Error::NotManager`] if this device does not hold the account
    /// key (a member device cannot rotate the account identity).
    pub async fn rotate_account_key(&mut self) -> Result<Keys> {
        if !self.device.is_manager() {
            return Err(Error::NotManager);
        }
        let new_keys = Keys::generate();
        self.device.rotate_account_key(&new_keys).await?;
        self.account = new_keys.public_key();
        Ok(new_keys)
    }

    // -- Contact key-migration (the security-sensitive side) ----------------

    /// Fetch the raw (unverified) migration attestation a `account` key has
    /// published, if any. Prefer [`App::detect_migration`], which verifies it.
    pub async fn fetch_migration(&self, account: PublicKey) -> Result<Option<nostr::Event>> {
        Ok(self.device.fetch_migration(account).await?)
    }

    /// **Detect a published account-key migration for a pinned contact** — the
    /// safe, non-automatic transition signal. Fetches the migration attestation
    /// authored by the contact's **pinned** key off the relays and classifies it
    /// with [`App::classify_migration`].
    ///
    /// The result is *never* an automatic re-pin: a [`MigrationSignal::Forged`]
    /// event is rejected, and even a valid [`MigrationSignal::PendingReverification`]
    /// must be confirmed out of band (compare the new safety number) before
    /// [`App::accept_key_migration`].
    pub async fn detect_migration(&self, contact_id: &str) -> Result<MigrationSignal> {
        let contact = self
            .store
            .get_contact(contact_id)?
            .ok_or_else(|| Error::UnknownContact(contact_id.to_string()))?;
        match self.device.fetch_migration(contact.account).await? {
            None => Ok(MigrationSignal::None),
            Some(event) => self.classify_migration(contact_id, &event),
        }
    }

    /// Classify an already-fetched migration `event` against a pinned contact,
    /// **without** re-pinning anything. The two trust checks that matter:
    ///
    /// - The event must pass full mutual-signature verification (signed by the key
    ///   it names as the old identity *and* carrying a valid new-key attestation).
    ///   Any failure → [`MigrationSignal::Forged`].
    /// - That old identity must equal the key we actually **pinned** for this
    ///   contact. A migration signed by some other key — however well-formed — does
    ///   not speak for this contact → [`MigrationSignal::Forged`].
    ///
    /// A migration that clears both is surfaced as
    /// [`MigrationSignal::PendingReverification`] carrying the new safety number to
    /// compare out of band. It is deliberately **not** trusted here.
    pub fn classify_migration(
        &self,
        contact_id: &str,
        event: &nostr::Event,
    ) -> Result<MigrationSignal> {
        let contact = self
            .store
            .get_contact(contact_id)?
            .ok_or_else(|| Error::UnknownContact(contact_id.to_string()))?;
        match verify_migration(event) {
            Err(e) => Ok(MigrationSignal::Forged {
                reason: e.to_string(),
            }),
            Ok(v) if v.old_pubkey != contact.account => Ok(MigrationSignal::Forged {
                reason: "migration is not signed by this contact's pinned key".to_string(),
            }),
            Ok(v) => Ok(MigrationSignal::PendingReverification {
                old_pubkey: v.old_pubkey,
                new_pubkey: v.new_pubkey,
                new_safety_number: safety_number(&self.account, &v.new_pubkey),
            }),
        }
    }

    /// **Accept a contact's key migration** and re-pin to the new key — the final,
    /// user-driven step, called only **after** the user has compared the new safety
    /// number out of band. Re-verifies that a mutually-signed migration from the
    /// contact's pinned old key to exactly `new_pubkey` is published (so the app
    /// never re-pins to an unattested key), then moves the pin to `new_pubkey` and
    /// marks it verified (acceptance *is* the out-of-band confirmation).
    ///
    /// After this, messaging the contact continues over the **same** MLS groups
    /// (device keys never changed); only the trust pin and future device-list
    /// resolution follow the new identity.
    ///
    /// Errors: [`Error::UnknownContact`], [`Error::NoMigration`] if none is
    /// published, [`Error::BadMigration`] if the published one fails verification,
    /// and [`Error::MigrationMismatch`] if it does not link the pinned old key to
    /// the confirmed `new_pubkey`.
    pub async fn accept_key_migration(
        &self,
        contact_id: &str,
        new_pubkey: PublicKey,
    ) -> Result<()> {
        let contact = self
            .store
            .get_contact(contact_id)?
            .ok_or_else(|| Error::UnknownContact(contact_id.to_string()))?;
        let event = self
            .device
            .fetch_migration(contact.account)
            .await?
            .ok_or(Error::NoMigration(contact.account))?;
        let verified = verify_migration(&event).map_err(|e| Error::BadMigration(e.to_string()))?;
        if verified.old_pubkey != contact.account || verified.new_pubkey != new_pubkey {
            return Err(Error::MigrationMismatch);
        }
        // Move the pin to the new identity. The caller only reaches here after an
        // out-of-band re-verification, so the new pin is recorded as verified.
        self.store.put_contact(&Contact {
            id: contact.id,
            account: new_pubkey,
            nip05: contact.nip05,
            name: contact.name,
            verified: true,
            added_at: contact.added_at,
        })?;
        Ok(())
    }

    // -- Secure device pairing ----------------------------------------------

    /// Mint this device's [`PairingOffer`] (used by a **new device**): the offer
    /// carries this device's own pubkey and, via [`PairingOffer::sas`], a short
    /// code the user compares against the manager's screen. The new device shows
    /// the offer string / SAS, publishes its KeyPackage, subscribes, and waits to
    /// be approved (after which it receives the fan-out Welcomes over the relay).
    #[must_use]
    pub fn pairing_offer(&self) -> PairingOffer {
        PairingOffer::new(self.device_pubkey())
    }

    /// **Manager side of pairing.** After the user has confirmed out of band that
    /// this offer's [`PairingOffer::sas`] matches the new device's screen, pin the
    /// new device into the account: add it to the signed device list (the
    /// authorization) and fan it into **every existing group** (an `add_members`
    /// commit + a gift-wrapped Welcome per group), so the new device securely joins
    /// every conversation.
    ///
    /// The SAS confirmation is the caller's responsibility — this method assumes it
    /// has happened. Errors with [`Error::NotManager`] if this device does not hold
    /// the account key, and [`Error::NoDeviceList`] if the account has never
    /// published a device list to add to.
    pub async fn approve_device(&self, offer: &PairingOffer) -> Result<()> {
        // Only the account-key holder can sign a device into the list.
        if !self.device.is_manager() {
            return Err(Error::NotManager);
        }
        let new_device = offer.device_pubkey;

        // Add the device to the account's signed list (idempotent: a re-approval
        // of an already-listed device just republishes the same set).
        let mut list = self
            .device
            .fetch_device_list(self.account)
            .await?
            .ok_or(Error::NoDeviceList)?;
        if !list.contains(&new_device) {
            list.devices.push(DeviceEntry::new(new_device));
        }
        self.publish_device_list(list.devices).await?;

        // Fan the new device into every group this device is already in, so it
        // joins each existing conversation over the relay.
        self.device.add_device_to_all_groups(new_device).await?;
        Ok(())
    }

    // -- Device removal (Post-Compromise Security) --------------------------

    /// The account's current devices, as named in its published device list (or an
    /// empty list if none has been published). Lets the user see what to remove.
    pub async fn devices(&self) -> Result<Vec<DeviceEntry>> {
        match self.device.fetch_device_list(self.account).await? {
            Some(list) => Ok(list.devices),
            None => Ok(Vec::new()),
        }
    }

    /// **Remove a lost / compromised device from the account** (manager only — the
    /// counterpart to [`App::approve_device`]). Two steps, in this order:
    ///
    /// 1. **Drop it from the account's signed device list and republish** — the
    ///    authorization revocation, so no future group ever re-enrolls it.
    /// 2. **Evict its leaf from every group** ([`DeviceAccount::remove_device_from_all_groups`]):
    ///    each `remove_members` commit advances the group to a new MLS epoch whose
    ///    keys the removed device never had. This is the Post-Compromise Security
    ///    property — the removed device **cannot decrypt any message sent after
    ///    removal**.
    ///
    /// Guards: [`Error::NotManager`] if this device does not hold the account key;
    /// [`Error::CannotRemoveCurrentDevice`] if you try to remove the device you are
    /// operating from (MLS forbids committing your own removal — do it from another
    /// device); [`Error::LastDevice`] if it would empty the account; and
    /// [`Error::UnknownDevice`] if the target is not in the list. Requires the
    /// account to have a published device list ([`Error::NoDeviceList`]).
    pub async fn remove_device(&self, device_pubkey: PublicKey) -> Result<()> {
        // Only the account-key holder can sign a device out of the list.
        if !self.device.is_manager() {
            return Err(Error::NotManager);
        }
        // A device cannot author the commit that evicts its own leaf.
        if device_pubkey == self.device_pubkey() {
            return Err(Error::CannotRemoveCurrentDevice);
        }

        let mut list = self
            .device
            .fetch_device_list(self.account)
            .await?
            .ok_or(Error::NoDeviceList)?;
        if !list.contains(&device_pubkey) {
            return Err(Error::UnknownDevice(device_pubkey));
        }
        if list.devices.len() <= 1 {
            return Err(Error::LastDevice);
        }

        // 1. Revoke authorization: drop from the signed list and republish.
        list.devices.retain(|d| d.pubkey != device_pubkey);
        self.publish_device_list(list.devices).await?;

        // 2. Evict the leaf from every group (PCS epoch advance).
        self.device
            .remove_device_from_all_groups(device_pubkey)
            .await?;
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
