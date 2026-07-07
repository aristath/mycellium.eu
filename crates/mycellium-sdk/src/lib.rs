//! **The Mycellium UniFFI SDK** — a stable, foreign-language-bindable surface over
//! [`mycellium_app`], so mobile/desktop UIs (Kotlin/Android, Swift/iOS, …) can be
//! built on the MLS-over-Nostr messenger engine without touching Rust, nostr, or
//! MLS types.
//!
//! # Shape
//!
//! One UniFFI [`Object`](MycelliumClient) owns the async [`App`] engine plus a
//! shared multi-thread tokio runtime. Every exported method is **blocking-facing**:
//! it drives the async engine with `runtime.block_on(...)` and returns a plain
//! value or a [`SdkError`]. This is deliberate — a blocking API is the simplest,
//! most robust thing to consume from Kotlin/Swift (no foreign async runtime, no
//! `Future` bridging), and mobile UIs already call it off their main thread.
//!
//! Incoming traffic is the one thing that cannot be blocking: it is pushed to a
//! foreign [`MycelliumObserver`] callback. [`MycelliumClient::start_receiving`]
//! spawns the engine's receive loop on the runtime and pumps every decrypted
//! message / trust signal to the observer until
//! [`MycelliumClient::stop_receiving`].
//!
//! # Boundary types
//!
//! Nothing nostr/MLS crosses the FFI: keys are `npub`/`nsec`/hex strings, and the
//! engine's rich types are flattened to UniFFI [records](ContactInfo) and
//! [enums](TrustStatusFfi). All engine errors collapse to one [`SdkError`] — no
//! panic ever crosses the boundary.
//!
//! # Threading model (honest limits)
//!
//! The `App` is guarded by a single async mutex. The spawned receive loop polls in
//! short (~400 ms) windows and **releases the lock between polls**, so a foreign
//! `send_text` / `add_contact` call interleaves within a poll gap rather than
//! waiting a whole timeout. It is safe to call any method concurrently from
//! multiple foreign threads; they serialize on that mutex. There is no
//! backgrounding/reconnect logic — see the crate README notes in the phase report.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use mycellium_app::{
    App, AppEvent, Contact, Device, HttpsResolver, Nip05Address, Nip05Status, PairingOffer,
    TrustEvent, TrustStatus,
};
use nostr::nips::nip19::{FromBech32, ToBech32};
use nostr::{Keys, PublicKey, RelayUrl};
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;

uniffi::setup_scaffolding!();

/// Lock the `App` and drive an async body on the runtime, blocking until it
/// completes. Inlining the async block (rather than passing the guard into a
/// closure) sidesteps the higher-ranked-lifetime limit on closures that return a
/// future borrowing their argument. `$app` is bound `mut` for the methods that
/// need `&mut App`; `#[allow(unused_mut)]` keeps the `&self` ones warning-free.
macro_rules! on_app {
    ($self:expr, $app:ident, $($body:tt)*) => {
        $self.rt.block_on(async {
            #[allow(unused_mut)]
            let mut $app = $self.app.lock().await;
            $($body)*
        })
    };
}

// ===========================================================================
// Errors
// ===========================================================================

/// The single error type every fallible SDK call can return. Engine errors are
/// bucketed into a small set of semantic variants a UI can branch on; the exact
/// message is always carried for logging. No panic crosses the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SdkError {
    /// An npub/nsec/hex key string could not be parsed.
    #[error("invalid key: {msg}")]
    InvalidKey { msg: String },
    /// A relay URL could not be parsed.
    #[error("invalid relay url: {msg}")]
    InvalidRelay { msg: String },
    /// A malformed argument (e.g. a bad conversation id or pairing offer).
    #[error("invalid input: {msg}")]
    InvalidInput { msg: String },
    /// No contact is known under the given local handle.
    #[error("unknown contact: {handle}")]
    UnknownContact { handle: String },
    /// An operation that requires the account key was attempted on a member device.
    #[error("this device is not the account manager")]
    NotManager,
    /// A device-lifecycle guard fired (last device, self-removal, unknown device,
    /// no published device list).
    #[error("device error: {msg}")]
    Device { msg: String },
    /// A key-migration attestation was missing, invalid, or did not match.
    #[error("key-migration error: {msg}")]
    Migration { msg: String },
    /// A NIP-05 parse/resolve failure, or a contact with no recorded address.
    #[error("nip05 error: {msg}")]
    Nip05 { msg: String },
    /// A receive-loop method was used out of order (not subscribed / not receiving).
    #[error("receive error: {msg}")]
    Receive { msg: String },
    /// Any other engine/transport/store error, message preserved.
    #[error("engine error: {msg}")]
    Engine { msg: String },
}

impl From<mycellium_app::Error> for SdkError {
    fn from(e: mycellium_app::Error) -> Self {
        use mycellium_app::Error as E;
        let msg = e.to_string();
        match e {
            E::UnknownContact(handle) => SdkError::UnknownContact { handle },
            E::NotManager => SdkError::NotManager,
            E::BadConversationId(_) => SdkError::InvalidInput { msg },
            E::NotSubscribed => SdkError::Receive { msg },
            E::CannotRemoveCurrentDevice
            | E::LastDevice
            | E::UnknownDevice(_)
            | E::NoDeviceList => SdkError::Device { msg },
            E::NoMigration(_) | E::BadMigration(_) | E::MigrationMismatch => {
                SdkError::Migration { msg }
            }
            E::Nip05Parse(_) | E::Nip05Resolve(_) | E::NoNip05(_) => SdkError::Nip05 { msg },
            E::Account(_) | E::Transport(_) | E::Store(_) | E::MlsStorage(_) | E::Io(_) => {
                SdkError::Engine { msg }
            }
        }
    }
}

// ===========================================================================
// Records & enums (the flattened boundary types)
// ===========================================================================

/// How much the engine trusts an observed account key for a known contact.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum TrustStatusFfi {
    /// Confirmed out of band and the key matches.
    Verified,
    /// Pinned on first use (TOFU) and the key matches.
    Pinned,
    /// A key was pinned before but the observed key differs — never auto-trusted.
    IdentityChanged,
    /// No pin exists for this handle yet.
    Unverified,
}

impl From<TrustStatus> for TrustStatusFfi {
    fn from(s: TrustStatus) -> Self {
        match s {
            TrustStatus::Verified => TrustStatusFfi::Verified,
            TrustStatus::Pinned => TrustStatusFfi::Pinned,
            TrustStatus::IdentityChanged => TrustStatusFfi::IdentityChanged,
            TrustStatus::Unverified => TrustStatusFfi::Unverified,
        }
    }
}

/// The outcome of checking a contact's recorded NIP-05 address against its pin.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum Nip05StatusFfi {
    /// The address still resolves to the pinned key.
    Verified,
    /// The address now resolves to a **different** key (a rebinding red flag).
    Mismatch {
        /// The key the name resolves to now (npub) — not pinned, not trusted.
        resolved_npub: String,
    },
    /// The address could not be resolved (network / malformed / name absent).
    Unreachable,
}

/// A contact address-book entry, flattened for the FFI.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ContactInfo {
    /// The local handle / petname (stable key used by every contact method).
    pub handle: String,
    /// The pinned account key as an `npub`.
    pub account_npub: String,
    /// The pinned account key as hex (for callers that prefer it).
    pub account_hex: String,
    /// Recorded NIP-05 address (`name@domain`), if any.
    pub nip05: Option<String>,
    /// Whether the recorded NIP-05 address was verified against the pinned key.
    pub nip05_verified: bool,
    /// Optional display name.
    pub name: Option<String>,
    /// Whether the identity was confirmed out of band (safety-number compare).
    pub verified: bool,
    /// Unix seconds when the contact was added.
    pub added_at: u64,
}

impl From<Contact> for ContactInfo {
    fn from(c: Contact) -> Self {
        ContactInfo {
            handle: c.id,
            account_npub: npub(&c.account),
            account_hex: c.account.to_hex(),
            nip05: c.nip05,
            nip05_verified: c.nip05_verified,
            name: c.name,
            verified: c.verified,
            added_at: c.added_at,
        }
    }
}

/// A conversation the device knows: its stable id and title.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ConversationInfo {
    /// The stable conversation id (the MLS group id hex) — pass it to
    /// [`MycelliumClient::send_text`] / [`MycelliumClient::transcript`].
    pub id: String,
    /// The conversation title.
    pub title: String,
}

/// One message in a persisted transcript (sent or received).
#[derive(Debug, Clone, uniffi::Record)]
pub struct MessageInfo {
    /// Whether this device sent it (vs. received it).
    pub from_me: bool,
    /// The author's device pubkey (npub); absent for this device's own sends.
    pub author_npub: Option<String>,
    /// The plaintext.
    pub text: String,
    /// Unix seconds when it was stored.
    pub timestamp: u64,
}

impl From<mycellium_app::StoredMessage> for MessageInfo {
    fn from(m: mycellium_app::StoredMessage) -> Self {
        MessageInfo {
            from_me: m.from_me,
            author_npub: m.author.as_ref().map(npub),
            text: m.text,
            timestamp: m.timestamp,
        }
    }
}

/// A device named in the account's published device list.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceInfo {
    /// The device pubkey as an `npub`.
    pub npub: String,
    /// The device pubkey as hex.
    pub hex: String,
    /// The device's optional label.
    pub name: Option<String>,
}

impl From<Device> for DeviceInfo {
    fn from(d: Device) -> Self {
        DeviceInfo {
            npub: npub(&d.pubkey),
            hex: d.pubkey.to_hex(),
            name: d.name,
        }
    }
}

/// A decrypted application message pushed to the observer.
#[derive(Debug, Clone, uniffi::Record)]
pub struct ReceivedMessageInfo {
    /// The conversation it belongs to (its stable id).
    pub conversation_id: String,
    /// The author's device pubkey as an `npub`.
    pub from_npub: String,
    /// The decrypted plaintext.
    pub text: String,
    /// Unix seconds when it was received.
    pub timestamp: u64,
}

/// The kind of a passive trust signal for a pinned contact.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum TrustEventKind {
    /// A valid account-key migration for the contact is pending re-verification.
    KeyMigrationPending,
    /// The contact's device set changed.
    ContactDevicesChanged,
    /// A migration-shaped event authored by the contact failed verification.
    ForgedMigration,
    /// The contact's NIP-05 name now resolves to a different key.
    Nip05Mismatch,
}

/// A passive trust signal pushed to the observer. Never an action — a
/// `KeyMigrationPending` still requires out-of-band re-verification followed by
/// [`MycelliumClient::accept_key_migration`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct TrustEventInfo {
    /// Which kind of signal this is.
    pub kind: TrustEventKind,
    /// The local handle of the pinned contact it concerns.
    pub contact: String,
    /// A human-readable detail (new key + safety number, device count, reason, …).
    pub detail: String,
}

impl From<TrustEvent> for TrustEventInfo {
    fn from(e: TrustEvent) -> Self {
        match e {
            TrustEvent::KeyMigrationPending {
                contact,
                new_pubkey,
                new_safety_number,
                ..
            } => TrustEventInfo {
                kind: TrustEventKind::KeyMigrationPending,
                contact,
                detail: format!(
                    "new key {} — compare safety number out of band: {new_safety_number}",
                    npub(&new_pubkey)
                ),
            },
            TrustEvent::ContactDevicesChanged { contact, devices } => TrustEventInfo {
                kind: TrustEventKind::ContactDevicesChanged,
                contact,
                detail: format!("device set changed ({} device(s))", devices.len()),
            },
            TrustEvent::ForgedMigration { contact, reason } => TrustEventInfo {
                kind: TrustEventKind::ForgedMigration,
                contact,
                detail: reason,
            },
            TrustEvent::Nip05Mismatch {
                contact,
                address,
                resolved_pubkey,
            } => TrustEventInfo {
                kind: TrustEventKind::Nip05Mismatch,
                contact,
                detail: format!("{address} now resolves to {}", npub(&resolved_pubkey)),
            },
        }
    }
}

// ===========================================================================
// Observer callback (foreign trait)
// ===========================================================================

/// The **foreign-implemented** sink for live incoming events. A UI implements this
/// (in Kotlin/Swift) and hands it to [`MycelliumClient::start_receiving`]; the SDK
/// then calls it from the runtime's receive loop. Implementations must be
/// thread-safe (`Send + Sync`) and should not block for long — hand work to the
/// UI thread and return.
#[uniffi::export(with_foreign)]
pub trait MycelliumObserver: Send + Sync {
    /// A decrypted application message arrived and was persisted.
    fn on_message(&self, message: ReceivedMessageInfo);
    /// A passive trust signal arrived for a pinned contact (no pin changed).
    fn on_trust_event(&self, event: TrustEventInfo);
    /// The receive loop hit a (non-fatal) error; it keeps running.
    fn on_error(&self, message: String);
}

// ===========================================================================
// The client object
// ===========================================================================

/// Handle to the running receive loop, so [`MycelliumClient::stop_receiving`] can
/// signal it and wait for it to unwind (freeing the App mutex).
struct ReceiveHandle {
    stop: Arc<AtomicBool>,
    join: tokio::task::JoinHandle<()>,
}

/// The one FFI object: owns the [`App`] engine and the runtime it is driven on.
/// Construct with one of the `open_*` constructors, then `connect`, `subscribe`,
/// `publish`, and `start_receiving`.
#[derive(uniffi::Object)]
pub struct MycelliumClient {
    rt: Arc<Runtime>,
    app: Arc<AsyncMutex<App>>,
    /// Whether [`App::subscribe`] has run (it must, once, before receiving).
    subscribed: AtomicBool,
    /// The live receive loop, if any.
    receiver: StdMutex<Option<ReceiveHandle>>,
}

#[uniffi::export]
impl MycelliumClient {
    // -- Constructors -------------------------------------------------------

    /// Open a **solo** account (single device: the account key *is* the device
    /// key). `nsec` is this identity's bech32 secret key (see
    /// [`generate_identity`]); `relays` are `wss://…` URLs; `data_dir` is the
    /// on-disk directory for the encrypted state.
    #[uniffi::constructor]
    pub fn open_solo(
        nsec: String,
        relays: Vec<String>,
        data_dir: String,
    ) -> Result<Arc<Self>, SdkError> {
        let keys = parse_keys(&nsec)?;
        let relays = parse_relays(&relays)?;
        let app = App::open_solo(keys, relays, std::path::Path::new(&data_dir))?;
        Ok(Self::wrap(app))
    }

    /// Open a **manager** device: it holds the account key (`account_nsec`) and can
    /// publish/update the account device list. `device_nsec` is this device's own
    /// key.
    #[uniffi::constructor]
    pub fn open_manager(
        account_nsec: String,
        device_nsec: String,
        relays: Vec<String>,
        data_dir: String,
    ) -> Result<Arc<Self>, SdkError> {
        let account_keys = parse_keys(&account_nsec)?;
        let device_keys = parse_keys(&device_nsec)?;
        let relays = parse_relays(&relays)?;
        let app = App::open_manager(
            account_keys,
            device_keys,
            relays,
            std::path::Path::new(&data_dir),
        )?;
        Ok(Self::wrap(app))
    }

    /// Open an ordinary **member** device of an existing account. `account_npub` is
    /// the account identity; `device_nsec` is this device's own key. A member can
    /// message but cannot alter the device list.
    #[uniffi::constructor]
    pub fn open_member(
        account_npub: String,
        device_nsec: String,
        relays: Vec<String>,
        data_dir: String,
    ) -> Result<Arc<Self>, SdkError> {
        let account = parse_pubkey(&account_npub)?;
        let device_keys = parse_keys(&device_nsec)?;
        let relays = parse_relays(&relays)?;
        let app = App::open_member(
            account,
            device_keys,
            relays,
            std::path::Path::new(&data_dir),
        )?;
        Ok(Self::wrap(app))
    }

    // -- Identity & lifecycle ----------------------------------------------

    /// This account's stable identity as an `npub`.
    #[must_use]
    pub fn account_npub(&self) -> String {
        on_app!(self, app, npub(&app.account()))
    }

    /// This device's own pubkey (its MLS-leaf identity) as an `npub`.
    #[must_use]
    pub fn device_npub(&self) -> String {
        on_app!(self, app, npub(&app.device_pubkey()))
    }

    /// Connect the transport to the configured relays.
    pub fn connect(&self) -> Result<(), SdkError> {
        on_app!(self, app, app.connect().await.map_err(SdkError::from))
    }

    /// Subscribe to the incoming stream (must run once, after [`Self::connect`] and
    /// before anything you expect to receive). Calling it again is a no-op.
    /// [`Self::start_receiving`] calls this for you if you have not.
    pub fn subscribe(&self) -> Result<(), SdkError> {
        self.ensure_subscribed()
    }

    /// Publish this device's KeyPackage **and** a device list containing just this
    /// device — the single-device bootstrap. Only a solo/manager device (holding
    /// the account key) can publish the list; multi-device growth goes through
    /// [`Self::approve_device`]. `display_name` labels this device in the list.
    pub fn publish(&self, display_name: Option<String>) -> Result<(), SdkError> {
        on_app!(self, app,
            app.publish_key_package().await?;
            let device = match display_name {
                Some(name) => Device::named(app.device_pubkey(), name),
                None => Device::new(app.device_pubkey()),
            };
            app.publish_device_list(vec![device]).await?;
            Ok(())
        )
    }

    /// Publish (or replace) this account's own NIP-05 address (`name@domain`) in its
    /// profile, so contacts can verify the name→key binding. Manager/solo only.
    pub fn set_nip05(&self, address: String) -> Result<(), SdkError> {
        let addr = parse_nip05(&address)?;
        on_app!(
            self,
            app,
            app.set_nip05(&addr).await.map_err(SdkError::from)
        )
    }

    /// Disconnect from relays and stop any running receive loop.
    pub fn shutdown(&self) {
        self.stop_receiving();
        on_app!(self, app, app.shutdown().await);
    }

    // -- Contacts & trust ---------------------------------------------------

    /// Add a contact under local handle derived from `name` (or the key itself),
    /// **pinning** the given `npub_or_hex` account key (TOFU). Returns the resulting
    /// trust status; a different key for an existing handle returns
    /// [`TrustStatusFfi::IdentityChanged`] and does not re-pin.
    pub fn add_contact(
        &self,
        npub_or_hex: String,
        name: Option<String>,
    ) -> Result<TrustStatusFfi, SdkError> {
        let account = parse_pubkey(&npub_or_hex)?;
        let handle = name.clone().unwrap_or_else(|| npub(&account));
        on_app!(
            self,
            app,
            app.add_contact(&handle, account, None, name)
                .await
                .map(TrustStatusFfi::from)
                .map_err(SdkError::from)
        )
    }

    /// Add a contact by NIP-05 address: resolve it, pin the key it maps to (TOFU),
    /// and record the address as a verified binding. `name` sets the local handle
    /// (defaults to the address).
    pub fn add_contact_by_nip05(
        &self,
        address: String,
        name: Option<String>,
    ) -> Result<TrustStatusFfi, SdkError> {
        let addr = parse_nip05(&address)?;
        on_app!(
            self,
            app,
            app.add_contact_by_nip05(&HttpsResolver, &addr, name)
                .await
                .map(TrustStatusFfi::from)
                .map_err(SdkError::from)
        )
    }

    /// Every known contact.
    pub fn list_contacts(&self) -> Result<Vec<ContactInfo>, SdkError> {
        on_app!(
            self,
            app,
            Ok(app.contacts()?.into_iter().map(ContactInfo::from).collect())
        )
    }

    /// Re-verify a contact's recorded NIP-05 binding against its pinned key.
    pub fn verify_nip05(&self, contact: String) -> Result<Nip05StatusFfi, SdkError> {
        on_app!(self, app,
            let status = app.verify_nip05(&HttpsResolver, &contact).await?;
            Ok(match status {
                Nip05Status::Verified => Nip05StatusFfi::Verified,
                Nip05Status::Mismatch { resolved_pubkey } => Nip05StatusFfi::Mismatch {
                    resolved_npub: npub(&resolved_pubkey),
                },
                Nip05Status::Unreachable => Nip05StatusFfi::Unreachable,
            })
        )
    }

    /// The out-of-band safety number for a contact (this account vs. theirs) — read
    /// it aloud to confirm you pinned the same identities.
    pub fn safety_number(&self, contact: String) -> Result<String, SdkError> {
        on_app!(
            self,
            app,
            app.safety_number(&contact).map_err(SdkError::from)
        )
    }

    /// Mark a contact **verified** after comparing safety numbers out of band.
    pub fn mark_verified(&self, contact: String) -> Result<(), SdkError> {
        on_app!(
            self,
            app,
            app.mark_verified(&contact).map_err(SdkError::from)
        )
    }

    // -- Conversations ------------------------------------------------------

    /// Start a 1:1 conversation with a known contact (enrolls every device of both
    /// accounts). Returns the stable conversation id.
    pub fn start_conversation(&self, contact: String) -> Result<String, SdkError> {
        on_app!(
            self,
            app,
            app.start_conversation(&contact)
                .await
                .map(|c| c.as_str().to_string())
                .map_err(SdkError::from)
        )
    }

    /// Start a group conversation with several known contacts.
    pub fn start_group(&self, title: String, contacts: Vec<String>) -> Result<String, SdkError> {
        on_app!(self, app,
            let refs: Vec<&str> = contacts.iter().map(String::as_str).collect();
            app.start_group(&title, &refs)
                .await
                .map(|c| c.as_str().to_string())
                .map_err(SdkError::from)
        )
    }

    /// Encrypt + publish a text message to a conversation and record it locally.
    pub fn send_text(&self, conversation_id: String, text: String) -> Result<(), SdkError> {
        let conv = parse_conversation(&conversation_id)?;
        on_app!(
            self,
            app,
            app.send_text(&conv, &text).await.map_err(SdkError::from)
        )
    }

    /// Every conversation this device knows.
    pub fn list_conversations(&self) -> Result<Vec<ConversationInfo>, SdkError> {
        on_app!(
            self,
            app,
            Ok(app
                .conversations()?
                .into_iter()
                .map(|(id, title)| ConversationInfo {
                    id: id.as_str().to_string(),
                    title,
                })
                .collect())
        )
    }

    /// A conversation's full persisted transcript, in order.
    pub fn transcript(&self, conversation_id: String) -> Result<Vec<MessageInfo>, SdkError> {
        let conv = parse_conversation(&conversation_id)?;
        on_app!(
            self,
            app,
            Ok(app
                .transcript(&conv)?
                .into_iter()
                .map(MessageInfo::from)
                .collect())
        )
    }

    // -- Device lifecycle ---------------------------------------------------

    /// Mint this device's pairing offer string (shown as a QR / copyable code on a
    /// **new** device; the manager confirms its SAS out of band, then approves).
    #[must_use]
    pub fn pairing_offer(&self) -> String {
        on_app!(self, app, app.pairing_offer().to_string())
    }

    /// Manager side of pairing: after confirming the offer's SAS out of band, add
    /// the new device to the signed list and fan it into every existing group.
    pub fn approve_device(&self, offer: String) -> Result<(), SdkError> {
        let offer: PairingOffer =
            offer
                .parse()
                .map_err(|e: mycellium_app::ParseOfferError| SdkError::InvalidInput {
                    msg: e.to_string(),
                })?;
        on_app!(
            self,
            app,
            app.approve_device(&offer).await.map_err(SdkError::from)
        )
    }

    /// The account's current devices (from its published device list).
    pub fn list_devices(&self) -> Result<Vec<DeviceInfo>, SdkError> {
        on_app!(
            self,
            app,
            Ok(app
                .devices()
                .await?
                .into_iter()
                .map(DeviceInfo::from)
                .collect())
        )
    }

    /// Remove a lost/compromised device (manager only): drop it from the signed
    /// list and evict its leaf from every group (Post-Compromise Security).
    pub fn remove_device(&self, npub_or_hex: String) -> Result<(), SdkError> {
        let pk = parse_pubkey(&npub_or_hex)?;
        on_app!(
            self,
            app,
            app.remove_device(pk).await.map_err(SdkError::from)
        )
    }

    /// Rotate this account's identity key (manager/solo). Returns the **new** account
    /// `nsec`, which the caller **must** persist — it is now this account's identity.
    /// Existing conversations keep working (device keys are untouched).
    pub fn rotate_account_key(&self) -> Result<String, SdkError> {
        on_app!(self, app,
            let new_keys = app.rotate_account_key().await?;
            nsec_of(&new_keys)
        )
    }

    /// Accept a contact's key migration and re-pin to `new_key` — call only **after**
    /// comparing the new safety number out of band (see a `KeyMigrationPending`
    /// trust event).
    pub fn accept_key_migration(&self, contact: String, new_key: String) -> Result<(), SdkError> {
        let new_pubkey = parse_pubkey(&new_key)?;
        on_app!(
            self,
            app,
            app.accept_key_migration(&contact, new_pubkey)
                .await
                .map_err(SdkError::from)
        )
    }

    // -- Receive loop -------------------------------------------------------

    /// Spawn the receive loop on the runtime and pump every decrypted message /
    /// trust signal to `observer` until [`Self::stop_receiving`]. Subscribes first
    /// if you have not. Errors with `AlreadyReceiving` if a loop is already running.
    pub fn start_receiving(&self, observer: Arc<dyn MycelliumObserver>) -> Result<(), SdkError> {
        let mut slot = self.receiver.lock().expect("receiver mutex");
        if slot.is_some() {
            return Err(SdkError::Receive {
                msg: "already receiving".to_string(),
            });
        }
        self.ensure_subscribed()?;

        let app = self.app.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_task = stop.clone();
        let join = self.rt.spawn(async move {
            // Poll in short windows, releasing the App lock between polls so
            // foreign calls (send_text, add_contact, …) interleave promptly.
            const POLL: Duration = Duration::from_millis(400);
            while !stop_task.load(Ordering::Relaxed) {
                let next = {
                    let mut app = app.lock().await;
                    app.next_event(POLL).await
                };
                match next {
                    Ok(Some(AppEvent::Message(m))) => observer.on_message(ReceivedMessageInfo {
                        conversation_id: m.conversation.as_str().to_string(),
                        from_npub: npub(&m.author),
                        text: m.text,
                        timestamp: m.timestamp,
                    }),
                    Ok(Some(AppEvent::Trust(t))) => observer.on_trust_event(t.into()),
                    Ok(None) => {} // idle window elapsed — loop and re-check stop
                    Err(e) => {
                        observer.on_error(SdkError::from(e).to_string());
                        // Back off briefly so a persistent error is not a hot loop.
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
        });
        *slot = Some(ReceiveHandle { stop, join });
        Ok(())
    }

    /// Stop the receive loop (if running) and wait for it to unwind. Idempotent.
    pub fn stop_receiving(&self) {
        let handle = self.receiver.lock().expect("receiver mutex").take();
        if let Some(handle) = handle {
            handle.stop.store(true, Ordering::Relaxed);
            // Wait (bounded) for the loop to observe the flag and drop its lock.
            self.rt.block_on(async {
                let _ = tokio::time::timeout(Duration::from_secs(2), handle.join).await;
            });
        }
    }
}

impl MycelliumClient {
    /// Assemble the object around an opened [`App`] and a fresh multi-thread
    /// runtime. Multi-thread so the spawned receive loop and foreign `block_on`
    /// calls make progress concurrently.
    fn wrap(app: App) -> Arc<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime");
        Arc::new(Self {
            rt: Arc::new(rt),
            app: Arc::new(AsyncMutex::new(app)),
            subscribed: AtomicBool::new(false),
            receiver: StdMutex::new(None),
        })
    }

    /// Ensure [`App::subscribe`] has run exactly once.
    fn ensure_subscribed(&self) -> Result<(), SdkError> {
        if self.subscribed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let res = self.rt.block_on(async {
            let mut app = self.app.lock().await;
            app.subscribe().await.map_err(SdkError::from)
        });
        if res.is_err() {
            // Roll back so a later retry can subscribe.
            self.subscribed.store(false, Ordering::SeqCst);
        }
        res
    }
}

// ===========================================================================
// Free functions & helpers
// ===========================================================================

/// Generate a fresh account/device identity and return its bech32 secret key
/// (`nsec1…`). Persist this — it is the only way back into the account. Feed it to
/// [`MycelliumClient::open_solo`] (or as a device key).
#[uniffi::export]
#[must_use]
pub fn generate_identity() -> String {
    // Bech32 encoding of a freshly generated secret key never fails.
    nsec_of(&Keys::generate()).unwrap_or_default()
}

/// Validate an existing secret key the user already holds (from another Nostr
/// client) and return its **`npub`**, so a native client can confirm *which*
/// identity is about to be imported ("Importing aristath — npub1… — correct?")
/// before opening the app with it via [`MycelliumClient::open_solo`].
///
/// Errors ([`SdkError::InvalidKey`]) if `nsec` is not a valid secret — in
/// particular a public `npub1…` is rejected with a clear message, since a
/// public key cannot sign and so cannot back an identity.
#[uniffi::export]
pub fn import_identity(nsec: String) -> Result<String, SdkError> {
    Ok(npub(&parse_keys(&nsec)?.public_key()))
}

/// Render a public key as an `npub`, falling back to hex if bech32 encoding fails.
fn npub(pk: &PublicKey) -> String {
    pk.to_bech32().unwrap_or_else(|_| pk.to_hex())
}

/// A keypair's secret as a bech32 `nsec`.
fn nsec_of(keys: &Keys) -> Result<String, SdkError> {
    keys.secret_key()
        .to_bech32()
        .map_err(|e| SdkError::InvalidKey { msg: e.to_string() })
}

/// Parse an `nsec1…` (or hex) secret key into a keypair. Rejects a public
/// `npub1…` with a clear message — an identity can only be opened/imported from
/// its *secret*, since the app must sign as it; a public key can never sign.
fn parse_keys(secret: &str) -> Result<Keys, SdkError> {
    if secret.starts_with("npub1") {
        return Err(SdkError::InvalidKey {
            msg: "that is a public key (npub) — an identity needs its secret key (nsec1…), \
                  which only you hold; a public key cannot sign"
                .to_string(),
        });
    }
    Keys::parse(secret).map_err(|e| SdkError::InvalidKey { msg: e.to_string() })
}

/// Parse an `npub1…` bech32 key or a raw hex key into a public key.
fn parse_pubkey(s: &str) -> Result<PublicKey, SdkError> {
    let to_err = |e: &dyn std::fmt::Display| SdkError::InvalidKey { msg: e.to_string() };
    if s.starts_with("npub1") {
        PublicKey::from_bech32(s).map_err(|e| to_err(&e))
    } else {
        PublicKey::from_hex(s).map_err(|e| to_err(&e))
    }
}

/// Parse a list of `wss://…` relay URLs.
fn parse_relays(relays: &[String]) -> Result<Vec<RelayUrl>, SdkError> {
    relays
        .iter()
        .map(|r| RelayUrl::parse(r).map_err(|e| SdkError::InvalidRelay { msg: e.to_string() }))
        .collect()
}

/// Parse a NIP-05 `name@domain` address.
fn parse_nip05(address: &str) -> Result<Nip05Address, SdkError> {
    Nip05Address::parse(address).map_err(|e| SdkError::Nip05 { msg: e.to_string() })
}

/// Parse a conversation id (validated group-id hex).
fn parse_conversation(id: &str) -> Result<mycellium_app::ConversationId, SdkError> {
    mycellium_app::ConversationId::parse(id).map_err(SdkError::from)
}
