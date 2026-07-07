//! **Multi-device accounts** over MLS-over-Nostr (Marmot).
//!
//! MDK / Marmot give you secure group messaging where every group member is one
//! MLS *leaf* bound to one keypair. What they leave open is the thing real users
//! actually have: **one identity, many devices.** MLS binds a leaf to a keypair
//! and MDK has no state-sync between a user's devices, so out of the box each of
//! Bob's phones is an unrelated stranger to every group.
//!
//! This crate closes that gap with a deliberate design choice: **do not share
//! MLS state across devices.** Sharing a leaf's secret across devices would throw
//! away MLS's per-leaf Forward Secrecy / Post-Compromise Security and force a
//! bespoke, fragile replication layer. Instead:
//!
//! - An **account** is a stable Nostr identity (the *account key* / npub).
//! - A **device** is its own keypair with its own [`MlsEngine`] leaf and its own
//!   KeyPackage (kind:30443). Every device is a first-class MLS member.
//! - The account is a *higher-level construct* whose only job is to keep **all of
//!   its device-leaves enrolled in every group**. The mapping
//!   `account pubkey -> {device pubkeys}` lives in a signed **device list**
//!   ([`DeviceList`], kind [`KIND_DEVICE_LIST`]), published under the account key.
//!
//! # The invariants this layer maintains
//!
//! 1. **Create/join enrolls every device.** To message "an account" you resolve
//!    its device list, fetch every device's KeyPackage, and add *all* of them as
//!    leaves ([`DeviceAccount::create_group_with`]).
//! 2. **A new device joins every existing group.** When an account adds a device,
//!    an existing device of that account fans it into every group the account is
//!    in via an MLS commit ([`DeviceAccount::add_device_to_all_groups`]).
//! 3. **Every device of the account can decrypt.** Because each is a real leaf,
//!    a message sent to the account decrypts on all of them.
//!
//! # What MLS forces on the design (honest constraints)
//!
//! - **A commit needs an author who is already a member.** A brand-new device
//!   cannot add *itself* — it has no leaf yet. So [`DeviceAccount::add_device_to_all_groups`]
//!   is called on an *existing* device of the account, which authors the commit.
//! - **`add_members` requires the author to be a group admin** (MDK returns
//!   `NotAdmin` otherwise). So [`DeviceAccount::create_group_with`] makes **every
//!   enrolled device an admin**, so any of an account's devices can enroll the
//!   account's next device. (A production policy would be account-scoped rather
//!   than every-leaf-is-admin — see the crate README / design notes.)
//! - **A single MLS Welcome serves everyone added in one commit.** MDK emits one
//!   welcome rumor per invited KeyPackage (same payload, different target `e`
//!   tag), in the same order as the KeyPackages passed in; we gift-wrap rumor
//!   `i` to invitee `i`.
//! - **Ordering matters.** After a device is fanned in, the commit advances the
//!   epoch; every other member (including the far side of the conversation) must
//!   process that commit *before* the next message or it will encrypt at a stale
//!   epoch. The far side does this by processing the kind:445 commit it receives.
//!
//! # Layering
//!
//! ```text
//!   mycellium-multidevice   DeviceAccount + DeviceList   (this crate: account layer)
//!         │  create_group_with / add_device_to_all_groups / process_incoming
//!         ▼
//!   mycellium-mls           MlsEngine + wire             (MLS crypto + Marmot events)
//!         ▼
//!   mycellium-nostr         NostrTransport               (relay I/O)
//!         ▼
//!        relay
//! ```

use std::time::Duration;

use mycellium_mls::{
    wire as mls_wire, EventBuilder, GroupId, Keys, Kind, MdkMemoryStorage, MdkStorageProvider,
    MessageProcessingResult, MlsEngine, NostrGroupConfigData,
};
use mycellium_nostr::NostrTransport;
use nostr::{Event, EventId, PublicKey, RelayUrl};
use nostr_sdk::prelude::Filter;

mod device_list;
pub use device_list::{DeviceEntry, DeviceList};

// Re-export the handful of types a caller touches, so downstream code depends on
// this crate rather than reaching into the layers below it.
pub use mycellium_mls::{Group, KIND_GROUP_MESSAGE, KIND_KEY_PACKAGE};
pub use nostr::{Keys as NostrKeys, PublicKey as NostrPublicKey, RelayUrl as NostrRelayUrl};

/// Nostr `kind` for a Mycellium device list.
///
/// Addressable (NIP-33 / 30000-range) so it is replaceable per
/// `(kind, account_pubkey, d-tag)`: publishing a new revision supersedes the old
/// one on the relay. Chosen adjacent to Marmot's KeyPackage kind (30443) so the
/// account-layer artifact sits beside the leaf-layer one. A NIP-worthy artifact.
pub const KIND_DEVICE_LIST: u16 = 30444;

/// The fixed `d`-tag identifier that makes the device list addressable — one
/// canonical device list per account.
pub const DEVICE_LIST_IDENTIFIER: &str = "mycellium-marmot-devices";

/// Default ceiling for bounded relay fetches (KeyPackages, device lists).
const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Default ceiling for opening relay connections.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Errors surfaced by the multi-device account layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the MLS crypto / Marmot event layer.
    #[error(transparent)]
    Mls(#[from] mycellium_mls::Error),
    /// An error from the relay transport (connect / publish / subscribe).
    #[error(transparent)]
    Transport(#[from] mycellium_nostr::Error),
    /// An error running a raw relay query through the transport's client.
    #[error(transparent)]
    Client(#[from] nostr_sdk::client::Error),
    /// An error building or signing the device-list event.
    #[error(transparent)]
    NostrEvent(#[from] nostr::event::Error),
    /// An error (de)serializing the device-list JSON body.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// This device holds no account signing key, so it cannot author or update
    /// the account's device list.
    #[error("this device holds no account signing key; it cannot manage the device list")]
    NoAccountKey,
    /// No device list could be found on the relays for this account.
    #[error("no device list published for account {0}")]
    NoDeviceList(PublicKey),
    /// A listed device has no KeyPackage (kind:30443) on the relays, so it cannot
    /// be enrolled as a leaf.
    #[error("no KeyPackage published for device {0}")]
    NoKeyPackage(PublicKey),
    /// An event handed to a device-list parser was not a device-list event.
    #[error("event kind {0} is not a Mycellium device list (expected {KIND_DEVICE_LIST})")]
    NotDeviceList(u16),
    /// A device-list event's stated `account` did not match its signer.
    #[error("device-list account does not match the event signer")]
    AccountSignerMismatch,
}

/// Convenience result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// The outcome of routing one incoming relay event through
/// [`DeviceAccount::process_incoming`].
#[derive(Debug, Clone)]
pub enum Incoming {
    /// A gift-wrapped Welcome was unwrapped and accepted: this device joined a
    /// group.
    Joined {
        /// The group this device just joined.
        group: GroupId,
    },
    /// A kind:445 application message was decrypted.
    Message {
        /// The group the message belongs to.
        group: GroupId,
        /// The decrypted plaintext.
        content: String,
        /// The message author's device pubkey.
        author: PublicKey,
    },
    /// A kind:445 commit was applied, advancing this device's epoch.
    CommitApplied {
        /// The group whose epoch advanced.
        group: GroupId,
    },
    /// A device-list revision was observed for some account.
    DeviceListUpdate(DeviceList),
    /// The event was not relevant to this layer (or could not be processed).
    Ignored,
}

/// One **device's** view of a multi-device account.
///
/// Owns this device's [`MlsEngine`] and [`NostrTransport`], remembers the account
/// identity it belongs to, and (if this device holds the account signing key)
/// can publish the account's device list. Every account-layer operation —
/// resolving an account to its device-leaves, enrolling them, fanning a new
/// device into every group — hangs off this type.
pub struct DeviceAccount<S = MdkMemoryStorage>
where
    S: MdkStorageProvider,
{
    /// The stable account identity this device belongs to.
    account: PublicKey,
    /// The account signing key — present only on a device authorized to manage
    /// the device list (publish/update it). `None` on an ordinary device.
    account_keys: Option<Keys>,
    /// This device's own keypair (its MLS-leaf / KeyPackage identity).
    device_keys: Keys,
    /// This device's MLS engine (its leaf state across all groups).
    mls: MlsEngine<S>,
    /// This device's relay transport.
    transport: NostrTransport,
    /// The relays this device publishes to and advertises in KeyPackages.
    relays: Vec<RelayUrl>,
    /// Bounded ceiling for relay fetches.
    fetch_timeout: Duration,
}

impl DeviceAccount<MdkMemoryStorage> {
    /// A device that **can manage the account's device list** (it holds
    /// `account_keys`), backed by volatile in-memory MLS storage. Use this for
    /// the device that publishes / updates the list.
    #[must_use]
    pub fn manager(account_keys: Keys, device_keys: Keys, relays: Vec<RelayUrl>) -> Self {
        let account = account_keys.public_key();
        Self::with_engine(
            account,
            Some(account_keys),
            device_keys,
            relays,
            MlsEngine::in_memory(),
        )
    }

    /// An ordinary device that belongs to `account` but does **not** hold the
    /// account key, backed by volatile in-memory MLS storage (it can join groups
    /// and message, but cannot alter the list).
    #[must_use]
    pub fn member(account: PublicKey, device_keys: Keys, relays: Vec<RelayUrl>) -> Self {
        Self::with_engine(account, None, device_keys, relays, MlsEngine::in_memory())
    }

    /// A single-device account backed by volatile in-memory MLS storage: the
    /// account key *is* the device key. The degenerate (but common) case — a
    /// contact who has not gone multi-device.
    #[must_use]
    pub fn solo(keys: Keys, relays: Vec<RelayUrl>) -> Self {
        Self::manager(keys.clone(), keys, relays)
    }
}

impl<S> DeviceAccount<S>
where
    S: MdkStorageProvider,
{
    /// A **manager** device over a caller-supplied MLS engine (e.g. a persistent
    /// `mdk-sqlite-storage` backend). Same role as [`DeviceAccount::manager`] but
    /// generic over the MLS storage provider.
    #[must_use]
    pub fn manager_with(
        account_keys: Keys,
        device_keys: Keys,
        relays: Vec<RelayUrl>,
        mls: MlsEngine<S>,
    ) -> Self {
        let account = account_keys.public_key();
        Self::with_engine(account, Some(account_keys), device_keys, relays, mls)
    }

    /// A **member** device over a caller-supplied MLS engine. Same role as
    /// [`DeviceAccount::member`] but generic over the MLS storage provider.
    #[must_use]
    pub fn member_with(
        account: PublicKey,
        device_keys: Keys,
        relays: Vec<RelayUrl>,
        mls: MlsEngine<S>,
    ) -> Self {
        Self::with_engine(account, None, device_keys, relays, mls)
    }

    /// A **solo** account over a caller-supplied MLS engine. Same role as
    /// [`DeviceAccount::solo`] but generic over the MLS storage provider.
    #[must_use]
    pub fn solo_with(keys: Keys, relays: Vec<RelayUrl>, mls: MlsEngine<S>) -> Self {
        Self::manager_with(keys.clone(), keys, relays, mls)
    }

    /// Shared constructor body: bind an MLS engine + a fresh transport to this
    /// device's keys.
    fn with_engine(
        account: PublicKey,
        account_keys: Option<Keys>,
        device_keys: Keys,
        relays: Vec<RelayUrl>,
        mls: MlsEngine<S>,
    ) -> Self {
        let transport = NostrTransport::new(&device_keys);
        Self {
            account,
            account_keys,
            device_keys,
            mls,
            transport,
            relays,
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,
        }
    }

    /// This device's own pubkey (its MLS-leaf identity).
    #[must_use]
    pub fn device_pubkey(&self) -> PublicKey {
        self.device_keys.public_key()
    }

    /// The account identity this device belongs to.
    #[must_use]
    pub fn account_pubkey(&self) -> PublicKey {
        self.account
    }

    /// Whether this device holds the account signing key — i.e. it can publish /
    /// update the account's device list (a manager or solo device). An ordinary
    /// member device returns `false`.
    #[must_use]
    pub fn is_manager(&self) -> bool {
        self.account_keys.is_some()
    }

    /// The underlying relay transport (for `notifications` / `next_event` in
    /// tests and advanced callers).
    #[must_use]
    pub fn transport(&self) -> &NostrTransport {
        &self.transport
    }

    /// The groups this device is currently a leaf in.
    pub fn groups(&self) -> Result<Vec<Group>> {
        Ok(self.mls.groups()?)
    }

    /// Connect this device's transport to its relays.
    pub async fn connect(&self) -> Result<()> {
        self.transport
            .connect(&self.relays, DEFAULT_CONNECT_TIMEOUT)
            .await?;
        Ok(())
    }

    /// Subscribe to everything this layer routes: gift-wrapped Welcomes addressed
    /// to this device, and every kind:445 group message / commit. Grab
    /// [`DeviceAccount::transport`]`().notifications()` **before** calling the
    /// producers so nothing is missed.
    pub async fn subscribe_incoming(&self) -> Result<()> {
        self.transport
            .subscribe(
                Filter::new()
                    .kind(Kind::GiftWrap)
                    .pubkey(self.device_keys.public_key()),
            )
            .await?;
        self.transport
            .subscribe(Filter::new().kind(Kind::Custom(KIND_GROUP_MESSAGE)))
            .await?;
        Ok(())
    }

    // -- KeyPackages & device list -----------------------------------------

    /// Publish this device's KeyPackage (kind:30443) so it can be enrolled as a
    /// leaf. Returns the published event id.
    pub async fn publish_key_package(&self) -> Result<EventId> {
        let kp = self
            .mls
            .key_package_for(&self.device_keys.public_key(), self.relays.clone())?;
        let event = mls_wire::key_package_event(&self.device_keys, &kp).await?;
        Ok(self.transport.publish(&event).await?)
    }

    /// Publish (or replace) this account's device list. Requires the account
    /// signing key — only a [`DeviceAccount::manager`] can do this.
    pub async fn publish_device_list(&self, devices: Vec<DeviceEntry>) -> Result<EventId> {
        let account_keys = self.account_keys.as_ref().ok_or(Error::NoAccountKey)?;
        let list = DeviceList::new(self.account, devices);
        let event = wire::device_list_event(account_keys, &list).await?;
        Ok(self.transport.publish(&event).await?)
    }

    /// Fetch the latest device list published under `account`, or `None` if the
    /// account has none on the queried relays.
    pub async fn fetch_device_list(&self, account: PublicKey) -> Result<Option<DeviceList>> {
        let filter = Filter::new()
            .author(account)
            .kind(Kind::Custom(KIND_DEVICE_LIST))
            .identifier(DEVICE_LIST_IDENTIFIER)
            .limit(1);
        let events = self
            .transport
            .client()
            .fetch_events(filter, self.fetch_timeout)
            .await?;
        match events.first_owned() {
            Some(event) => Ok(Some(wire::parse_device_list(&event)?)),
            None => Ok(None),
        }
    }

    /// Resolve an account to its device pubkeys. For **this** account, a missing
    /// list degrades gracefully to "just this device"; for any other account a
    /// missing list is an error (we cannot enroll devices we cannot see).
    async fn devices_of(&self, account: PublicKey) -> Result<Vec<PublicKey>> {
        match self.fetch_device_list(account).await? {
            Some(list) => Ok(list.pubkeys()),
            None if account == self.account => Ok(vec![self.device_keys.public_key()]),
            None => Err(Error::NoDeviceList(account)),
        }
    }

    // -- Group creation (enroll every device of every account) --------------

    /// Create a group that enrolls **every device of every listed account** plus
    /// every device of this account. This device is the creator leaf; all other
    /// devices are added by their KeyPackage and each receives a gift-wrapped
    /// Welcome. Returns the new group id.
    ///
    /// `accounts` are the *other* accounts to include; this device's own account
    /// is always included.
    pub async fn create_group_with(
        &self,
        accounts: &[PublicKey],
        name: &str,
        description: &str,
    ) -> Result<GroupId> {
        let me = self.device_keys.public_key();

        // The full set of member accounts: mine first, then the targets (deduped).
        let mut member_accounts = vec![self.account];
        for a in accounts {
            if !member_accounts.contains(a) {
                member_accounts.push(*a);
            }
        }

        // Resolve every account to its device-leaves (deduped, order-stable), and
        // make sure this creator device is in the set.
        let mut all_devices: Vec<PublicKey> = Vec::new();
        for account in &member_accounts {
            for device in self.devices_of(*account).await? {
                if !all_devices.contains(&device) {
                    all_devices.push(device);
                }
            }
        }
        if !all_devices.contains(&me) {
            all_devices.push(me);
        }

        // Invitees are every enrolled device except the creator leaf.
        let invitees: Vec<PublicKey> = all_devices.iter().copied().filter(|d| *d != me).collect();

        // Fetch each invitee device's KeyPackage.
        let mut invitee_key_packages: Vec<Event> = Vec::with_capacity(invitees.len());
        for device in &invitees {
            let kp = self
                .transport
                .fetch_key_package(*device, self.fetch_timeout)
                .await?
                .ok_or(Error::NoKeyPackage(*device))?;
            invitee_key_packages.push(kp);
        }

        // Every enrolled device is an admin so any device of an account can later
        // enroll that account's next device (MDK requires admin for `add_members`).
        let config = NostrGroupConfigData::new(
            name.to_string(),
            description.to_string(),
            None,
            None,
            None,
            self.relays.clone(),
            all_devices.clone(),
        );

        let created = self.mls.create_group(&me, invitee_key_packages, config)?;
        let group = created.group.mls_group_id.clone();

        // Welcome rumor `i` corresponds to invitee `i` (MDK preserves the order
        // of the KeyPackages we passed). Gift-wrap each to its device.
        for (rumor, device) in created.welcome_rumors.into_iter().zip(invitees.iter()) {
            let gift = mls_wire::gift_wrap_welcome(&self.device_keys, device, rumor).await?;
            self.transport.publish(&gift).await?;
        }

        Ok(group)
    }

    // -- Fan-out (a new device joins every existing group) ------------------

    /// Enroll `new_device` into **every group this device is currently in**: for
    /// each group, author an `add_members` commit adding the new device's
    /// KeyPackage, publish the evolution (kind:445) so existing members converge,
    /// and gift-wrap the resulting Welcome to the new device. Returns the number
    /// of groups the device was fanned into.
    ///
    /// This must be called on a device that is **already a member and an admin**
    /// of those groups — a brand-new device has no leaf and cannot author its own
    /// commit. In a multi-device account, an existing device does this on the new
    /// device's behalf.
    pub async fn add_device_to_all_groups(&self, new_device: PublicKey) -> Result<usize> {
        let kp = self
            .transport
            .fetch_key_package(new_device, self.fetch_timeout)
            .await?
            .ok_or(Error::NoKeyPackage(new_device))?;

        let groups = self.mls.groups()?;
        let mut count = 0;
        for group in groups {
            let gid = group.mls_group_id.clone();
            let update = self.mls.add_members(&gid, std::slice::from_ref(&kp))?;

            // Existing members apply this commit to advance their epoch.
            self.transport.publish(&update.evolution_event).await?;

            // The new device joins via the Welcome (one rumor for the one add).
            if let Some(rumors) = update.welcome_rumors {
                for rumor in rumors {
                    let gift =
                        mls_wire::gift_wrap_welcome(&self.device_keys, &new_device, rumor).await?;
                    self.transport.publish(&gift).await?;
                }
            }
            count += 1;
        }
        Ok(count)
    }

    // -- Messaging ----------------------------------------------------------

    /// Encrypt and publish an application message (kind:445) to `group`. Every
    /// device-leaf in the group decrypts it. Returns the published event id.
    pub async fn send_message(&self, group: &GroupId, text: &str) -> Result<EventId> {
        let rumor = EventBuilder::new(Kind::Custom(9), text).build(self.device_keys.public_key());
        let event = self.mls.encrypt_message(group, rumor)?;
        Ok(self.transport.publish(&event).await?)
    }

    // -- Incoming routing ---------------------------------------------------

    /// Route one incoming relay event into this device's engine: a gift-wrapped
    /// Welcome becomes a join, a kind:445 becomes a decrypted message or an
    /// applied commit, a device-list event is surfaced. Anything else is
    /// [`Incoming::Ignored`].
    pub async fn process_incoming(&self, event: &Event) -> Result<Incoming> {
        if event.kind == Kind::GiftWrap {
            let rumor = mls_wire::unwrap_welcome(&self.device_keys, event).await?;
            let welcome = self.mls.process_welcome(&event.id, &rumor)?;
            self.mls.accept_welcome(&welcome)?;
            return Ok(Incoming::Joined {
                group: welcome.mls_group_id,
            });
        }

        if event.kind == Kind::Custom(KIND_GROUP_MESSAGE) {
            // A device on the shared kind:445 subscription sees traffic for groups
            // it is not (yet) in — most importantly the fan-out commit that adds a
            // freshly paired device arrives before that device joins via its
            // Welcome. Such an event is not actionable, not a fault: drop it.
            let processed = match self.mls.process_incoming(event) {
                Ok(processed) => processed,
                Err(e) if e.is_unactionable_incoming() => return Ok(Incoming::Ignored),
                Err(e) => return Err(e.into()),
            };
            return Ok(match processed {
                MessageProcessingResult::ApplicationMessage(message) => Incoming::Message {
                    group: message.mls_group_id,
                    content: message.content,
                    author: message.pubkey,
                },
                MessageProcessingResult::Commit { mls_group_id } => Incoming::CommitApplied {
                    group: mls_group_id,
                },
                _ => Incoming::Ignored,
            });
        }

        if event.kind == Kind::Custom(KIND_DEVICE_LIST) {
            return Ok(Incoming::DeviceListUpdate(wire::parse_device_list(event)?));
        }

        Ok(Incoming::Ignored)
    }
}

/// Wire helpers for the device-list event: build the signed kind:30444 event and
/// parse/verify one back.
pub mod wire {
    use super::{DeviceList, Error, DEVICE_LIST_IDENTIFIER, KIND_DEVICE_LIST};
    use nostr::{Event, EventBuilder, Keys, Kind, Tag};

    /// Build and sign the account's device-list event (kind:30444, addressable
    /// via the fixed `d` tag). Signing with `account_keys` is the authorization:
    /// the event author *is* the account.
    ///
    /// The device pubkeys are mirrored into `p` tags for relay-side indexing; the
    /// authoritative body is the JSON content.
    pub async fn device_list_event(account_keys: &Keys, list: &DeviceList) -> Result<Event, Error> {
        let content = serde_json::to_string(list)?;
        let mut tags = Vec::with_capacity(list.devices.len() + 1);
        tags.push(Tag::identifier(DEVICE_LIST_IDENTIFIER));
        for device in &list.devices {
            tags.push(Tag::public_key(device.pubkey));
        }
        Ok(EventBuilder::new(Kind::Custom(KIND_DEVICE_LIST), content)
            .tags(tags)
            .build(account_keys.public_key())
            .sign(account_keys)
            .await?)
    }

    /// Parse a device-list event back into a [`DeviceList`], **binding the
    /// account to the signer**: the returned list speaks for `event.pubkey`, and
    /// a body that claims a different account is rejected. (The event signature
    /// itself is verified by the relay / nostr-sdk before it reaches here.)
    pub fn parse_device_list(event: &Event) -> Result<DeviceList, Error> {
        if event.kind != Kind::Custom(KIND_DEVICE_LIST) {
            return Err(Error::NotDeviceList(event.kind.as_u16()));
        }
        let list: DeviceList = serde_json::from_str(&event.content)?;
        if list.account != event.pubkey {
            return Err(Error::AccountSignerMismatch);
        }
        Ok(list)
    }
}
