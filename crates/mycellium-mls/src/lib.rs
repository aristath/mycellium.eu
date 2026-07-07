//! MLS-over-Nostr (Marmot) engine for Mycellium.
//!
//! This crate is a **thin, honest wrapper** over [MDK] (the Marmot Development
//! Kit) — the MLS crypto engine — plus the small amount of Nostr event
//! plumbing that turns MDK's output into publishable events. It exists so the
//! rest of Mycellium can drive secure group messaging without ever touching raw
//! `mdk-core` or hand-rolling the two-phase-commit choreography.
//!
//! # The Marmot flow
//!
//! Marmot layers MLS group messaging on top of Nostr events. The lifecycle:
//!
//! 1. **KeyPackage** — a would-be member publishes a signed KeyPackage event so
//!    others can add them to a group. See [`MlsEngine::key_package_for`] +
//!    [`wire::key_package_event`].
//! 2. **Create group** — a creator consumes invitees' KeyPackage events and
//!    forms the group, producing one Welcome rumor per invitee. See
//!    [`MlsEngine::create_group`].
//! 3. **Welcome** — the creator NIP-59 gift-wraps each Welcome rumor to its
//!    invitee ([`wire::gift_wrap_welcome`]); the invitee unwraps it
//!    ([`wire::unwrap_welcome`]), previews it ([`MlsEngine::pending_welcomes`]),
//!    and joins ([`MlsEngine::process_welcome`] + [`MlsEngine::accept_welcome`]).
//! 4. **Messages** — members encrypt application messages
//!    ([`MlsEngine::encrypt_message`]) and process incoming ones
//!    ([`MlsEngine::process_incoming`] + [`MlsEngine::messages`]).
//! 5. **Group evolution** — add/remove members or rotate keys for
//!    Post-Compromise Security ([`MlsEngine::add_members`],
//!    [`MlsEngine::remove_members`], [`MlsEngine::rotate`]). Each advances the
//!    MLS epoch. The **author's two-phase commit** (perform op → merge the
//!    pending commit locally → publish the evolution event for other members to
//!    apply) is hidden inside these methods.
//!
//! # Event-kind mapping (Nostr)
//!
//! | Marmot object            | Nostr kind | Notes                                    |
//! |--------------------------|-----------:|------------------------------------------|
//! | KeyPackage               |  **30443** | NIP-33 addressable event ([`KIND_KEY_PACKAGE`]) |
//! | Welcome                  |    **444** | rumor, NIP-59 gift-wrapped ([`KIND_WELCOME`])   |
//! | Group message / commit   |    **445** | `h` tag = `nostr_group_id` ([`KIND_GROUP_MESSAGE`]) |
//!
//! # Alpha / version pinning
//!
//! This is **alpha** and deliberately pinned to `nostr 0.44` / `MDK 0.8`. MDK
//! re-exports `nostr`; bumping `nostr` to a `0.45-alpha` breaks against those
//! re-exports. Do not float these versions without re-validating the round-trip.
//!
//! [MDK]: https://crates.io/crates/mdk-core

use mdk_core::prelude::*;
use nostr::{Event, EventId, PublicKey, UnsignedEvent};

pub use mdk_memory_storage::MdkMemoryStorage;

// ---------------------------------------------------------------------------
// Re-exports: the handful of MDK / Nostr types a caller needs, so downstream
// crates depend on `mycellium-mls` rather than reaching into `mdk-core`.
// ---------------------------------------------------------------------------

/// The data MDK produces for a KeyPackage before it is wrapped into a Nostr event.
pub use mdk_core::key_packages::KeyPackageEventData;
/// MDK's stored-group type (epoch, ids, name, …).
pub use mdk_core::prelude::group_types::Group;
/// MDK's decrypted-message type.
pub use mdk_core::prelude::message_types::Message;
/// MDK's pending-Welcome type.
pub use mdk_core::prelude::welcome_types::Welcome;
pub use mdk_core::prelude::{
    GroupId, GroupResult, MdkStorageProvider, MessageProcessingResult, NostrGroupConfigData,
    UpdateGroupResult,
};

// A curated slice of `nostr` so callers can construct rumors and hold identities
// without a direct `nostr` dependency.
pub use nostr::{EventBuilder, Keys, Kind, RelayUrl, Tag, Timestamp};

/// Nostr `kind` for a Marmot KeyPackage event (NIP-33 addressable).
pub const KIND_KEY_PACKAGE: u16 = 30443;
/// Nostr `kind` for a Marmot Welcome rumor (gift-wrapped via NIP-59).
pub const KIND_WELCOME: u16 = 444;
/// Nostr `kind` for a Marmot group message / commit event.
pub const KIND_GROUP_MESSAGE: u16 = 445;

/// Errors surfaced by the MLS engine and its wire helpers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the underlying MDK crypto engine.
    #[error(transparent)]
    Mdk(#[from] mdk_core::Error),
    /// An error building or signing a Nostr event (KeyPackage wire path).
    #[error(transparent)]
    NostrBuilder(#[from] nostr::event::builder::Error),
    /// An error constructing a Nostr event (NIP-59 gift-wrap path).
    #[error(transparent)]
    NostrEvent(#[from] nostr::event::Error),
    /// An error unwrapping a NIP-59 gift-wrap.
    #[error(transparent)]
    NostrGiftWrap(#[from] nostr::nips::nip59::Error),
}

impl Error {
    /// Whether this error, raised while processing an incoming kind:445 event,
    /// means the event is simply **not actionable for this device** rather than a
    /// real fault — so a receive loop on a shared kind:445 subscription should
    /// drop it, not fail.
    ///
    /// A device that subscribes to every group message inevitably sees traffic for
    /// groups it is not a member of (a commit that adds it arrives before it has
    /// joined via the Welcome; groups it will never be in), its own messages
    /// echoed back by the relay, and stale/duplicate re-deliveries. MDK surfaces
    /// these as distinct process-message variants; none is a bug on our side.
    #[must_use]
    pub fn is_unactionable_incoming(&self) -> bool {
        matches!(
            self,
            Error::Mdk(
                mdk_core::Error::GroupNotFound
                    | mdk_core::Error::CannotDecryptOwnMessage
                    | mdk_core::Error::ProcessMessageWrongGroupId
                    | mdk_core::Error::ProcessMessageWrongEpoch(_, _)
                    | mdk_core::Error::ProcessMessageUseAfterEviction
            )
        )
    }
}

/// Convenience result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A single MLS identity's engine: the local MLS state store plus every Marmot
/// lifecycle operation that acts on it.
///
/// One `MlsEngine` corresponds to one participant. It is generic over the MDK
/// storage backend; [`MlsEngine::in_memory`] gives the volatile
/// [`MdkMemoryStorage`] used for tests and as the default until an at-rest
/// sealed provider lands in a later phase.
pub struct MlsEngine<S = MdkMemoryStorage>
where
    S: MdkStorageProvider,
{
    mdk: MDK<S>,
}

impl MlsEngine<MdkMemoryStorage> {
    /// Create an engine backed by volatile in-memory storage.
    #[must_use]
    pub fn in_memory() -> Self {
        Self::new(MdkMemoryStorage::default())
    }
}

impl<S> MlsEngine<S>
where
    S: MdkStorageProvider,
{
    /// Wrap an MDK storage backend in an engine.
    pub fn new(storage: S) -> Self {
        Self {
            mdk: MDK::new(storage),
        }
    }

    /// Escape hatch to the underlying MDK instance for operations this thin
    /// wrapper does not (yet) surface. Prefer the wrapper methods.
    pub fn mdk(&self) -> &MDK<S> {
        &self.mdk
    }

    // -- KeyPackages --------------------------------------------------------

    /// Produce the KeyPackage data for `pubkey`, advertising `relays`.
    ///
    /// The returned [`KeyPackageEventData`] must be signed into a kind:30443
    /// Nostr event before publishing — see [`wire::key_package_event`].
    pub fn key_package_for<I>(&self, pubkey: &PublicKey, relays: I) -> Result<KeyPackageEventData>
    where
        I: IntoIterator<Item = RelayUrl>,
    {
        Ok(self.mdk.create_key_package_for_event(pubkey, relays)?)
    }

    // -- Group creation & Welcomes -----------------------------------------

    /// Create a new group as `creator`, adding the members carried by their
    /// signed KeyPackage events. The result's `welcome_rumors` (one per
    /// invitee) still need to be gift-wrapped and published — see
    /// [`wire::gift_wrap_welcome`].
    pub fn create_group(
        &self,
        creator: &PublicKey,
        invitee_key_packages: Vec<Event>,
        config: NostrGroupConfigData,
    ) -> Result<GroupResult> {
        Ok(self
            .mdk
            .create_group(creator, invitee_key_packages, config)?)
    }

    /// Ingest a received (unwrapped) Welcome rumor so it becomes previewable /
    /// acceptable. `wrapper_event_id` is the id of the NIP-59 gift-wrap the
    /// rumor arrived in.
    pub fn process_welcome(
        &self,
        wrapper_event_id: &EventId,
        welcome_rumor: &UnsignedEvent,
    ) -> Result<Welcome> {
        Ok(self.mdk.process_welcome(wrapper_event_id, welcome_rumor)?)
    }

    /// The Welcomes that have been processed but not yet accepted.
    pub fn pending_welcomes(&self) -> Result<Vec<Welcome>> {
        Ok(self.mdk.get_pending_welcomes(None)?)
    }

    /// Accept a pending Welcome, joining its group.
    pub fn accept_welcome(&self, welcome: &Welcome) -> Result<()> {
        self.mdk.accept_welcome(welcome)?;
        Ok(())
    }

    // -- Messages -----------------------------------------------------------

    /// Encrypt a rumor into a publishable kind:445 group message event.
    pub fn encrypt_message(&self, group: &GroupId, rumor: UnsignedEvent) -> Result<Event> {
        Ok(self.mdk.create_message(group, rumor, None)?)
    }

    /// Process an incoming kind:445 event (application message *or* commit).
    ///
    /// For application messages the decrypted plaintext lands in the group's
    /// message store; read it back with [`MlsEngine::messages`]. Commits advance
    /// the local epoch. The [`MessageProcessingResult`] tells you which happened.
    pub fn process_incoming(&self, event: &Event) -> Result<MessageProcessingResult> {
        Ok(self.mdk.process_message(event)?)
    }

    /// The decrypted messages stored for a group.
    pub fn messages(&self, group: &GroupId) -> Result<Vec<Message>> {
        Ok(self.mdk.get_messages(group, None)?)
    }

    // -- Group evolution (author two-phase commit hidden inside) ------------

    /// Add members (by their signed KeyPackage events). Advances the epoch.
    ///
    /// The author's two-phase commit is handled here: the commit is merged
    /// locally before returning. The caller must still publish the returned
    /// `evolution_event` (kind:445) to the group and gift-wrap the returned
    /// `welcome_rumors` to the new members.
    pub fn add_members(
        &self,
        group: &GroupId,
        invitee_key_packages: &[Event],
    ) -> Result<UpdateGroupResult> {
        let update = self.mdk.add_members(group, invitee_key_packages)?;
        self.mdk.merge_pending_commit(group)?;
        Ok(update)
    }

    /// Remove members by pubkey. Advances the epoch. Two-phase commit handled
    /// here; the caller publishes the returned evolution event.
    pub fn remove_members(&self, group: &GroupId, pubkeys: &[PublicKey]) -> Result<Event> {
        let update = self.mdk.remove_members(group, pubkeys)?;
        self.mdk.merge_pending_commit(group)?;
        Ok(update.evolution_event)
    }

    /// Rotate this member's key material (MLS `self_update`) for Post-Compromise
    /// Security. Advances the epoch. Two-phase commit handled here; the caller
    /// publishes the returned evolution event so other members converge.
    pub fn rotate(&self, group: &GroupId) -> Result<Event> {
        let update = self.mdk.self_update(group)?;
        self.mdk.merge_pending_commit(group)?;
        Ok(update.evolution_event)
    }

    /// Leave a group. Unlike the other evolution ops this does **not** merge a
    /// local commit — MLS forbids committing your own removal — so the returned
    /// event is a proposal for the remaining members to commit.
    pub fn leave(&self, group: &GroupId) -> Result<Event> {
        let update = self.mdk.leave_group(group)?;
        Ok(update.evolution_event)
    }

    // -- State inspection ---------------------------------------------------

    /// All groups this engine is a member of.
    pub fn groups(&self) -> Result<Vec<Group>> {
        Ok(self.mdk.get_groups()?)
    }

    /// The current MLS epoch of `group`, or `None` if this engine isn't in it.
    pub fn epoch(&self, group: &GroupId) -> Result<Option<u64>> {
        Ok(self
            .groups()?
            .into_iter()
            .find(|g| &g.mls_group_id == group)
            .map(|g| g.epoch))
    }
}

/// Nostr wire helpers: turn MDK lifecycle output into signed, publishable
/// events (and back). These encapsulate the event-kind mapping and NIP-59
/// gift-wrapping so callers never hand-roll the Nostr plumbing.
pub mod wire {
    use super::{Error, KeyPackageEventData};
    use nostr::event::builder::EventBuilder;
    use nostr::nips::nip59::UnwrappedGift;
    use nostr::{Event, Keys, Kind, PublicKey, UnsignedEvent};

    /// Sign a [`KeyPackageEventData`] into a publishable kind:30443 KeyPackage
    /// event owned by `keys`.
    pub async fn key_package_event(
        keys: &Keys,
        key_package: &KeyPackageEventData,
    ) -> Result<Event, Error> {
        Ok(EventBuilder::new(
            Kind::Custom(super::KIND_KEY_PACKAGE),
            key_package.content.clone(),
        )
        .tags(key_package.tags_30443.clone())
        .build(keys.public_key())
        .sign(keys)
        .await?)
    }

    /// NIP-59 gift-wrap a Welcome rumor from `sender` to `recipient`, producing
    /// the kind:1059 wrapper event to publish.
    pub async fn gift_wrap_welcome(
        sender: &Keys,
        recipient: &PublicKey,
        welcome_rumor: UnsignedEvent,
    ) -> Result<Event, Error> {
        Ok(EventBuilder::gift_wrap(sender, recipient, welcome_rumor, []).await?)
    }

    /// Unwrap a NIP-59 gift-wrap addressed to `recipient`, recovering the inner
    /// Welcome rumor (feed it to [`super::MlsEngine::process_welcome`] along with
    /// `gift_wrap.id`).
    pub async fn unwrap_welcome(
        recipient: &Keys,
        gift_wrap: &Event,
    ) -> Result<UnsignedEvent, Error> {
        let unwrapped = UnwrappedGift::from_gift_wrap(recipient, gift_wrap).await?;
        Ok(unwrapped.rumor)
    }
}
