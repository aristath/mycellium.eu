//! The stable, versioned contract exposed across the UniFFI boundary.
//!
//! Everything a foreign client (Kotlin/Swift/desktop) can see is defined here as
//! UniFFI `Record`/`Enum`/`Error` types built from simple, binding-friendly
//! primitives. Internal engine errors (`anyhow`, IO, crypto) are mapped into
//! [`SdkError`] at the boundary — `anyhow` never crosses it.

/// How far along a message is in delivery, from the sender's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DeliveryState {
    /// Handed to at least one recipient device (cluster or queue).
    Sent,
    /// Parked locally because no recipient device could be reached.
    Queued,
    /// Confirmed received by the peer (a read/delivery receipt came back).
    Delivered,
    /// Delivery failed outright.
    Failed,
}

/// How much we trust that a peer's current wallet is really theirs. Mirrors
/// [`mycellium_engine::verified::TrustLevel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum TrustLevel {
    /// Never pinned or verified — a first, unverified contact.
    Unverified,
    /// Pinned on first use (TOFU), but not out-of-band verified.
    Pinned,
    /// Confirmed out of band — the safety number matched.
    Verified,
    /// A wallet was pinned/verified before but the current one differs.
    Changed,
}

impl From<mycellium_engine::verified::TrustLevel> for TrustLevel {
    fn from(t: mycellium_engine::verified::TrustLevel) -> Self {
        use mycellium_engine::verified::TrustLevel as T;
        match t {
            T::Unverified => TrustLevel::Unverified,
            T::Pinned => TrustLevel::Pinned,
            T::Verified => TrustLevel::Verified,
            T::Changed => TrustLevel::Changed,
        }
    }
}

/// One message in a conversation transcript.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Message {
    /// The message id (stable for edit/delete/reaction targeting).
    pub id: String,
    /// The peer handle whose thread this message belongs to.
    pub thread: String,
    /// Whether this device's account sent it (vs. received it).
    pub from_me: bool,
    /// The sender's handle (equal to `thread` for inbound, our handle for sent).
    pub sender: String,
    /// The plaintext (or a summary, e.g. "📎 name" for attachments).
    pub text: String,
    /// Unix seconds when it was stored.
    pub sent_at: u64,
    /// Delivery status, from the sender's perspective.
    pub delivery: DeliveryState,
}

/// A conversation summary for the threads list.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Conversation {
    /// The peer handle.
    pub peer: String,
    /// The peer's learned display name (empty if unknown).
    pub display_name: String,
    /// A preview of the most recent message.
    pub last_preview: String,
    /// Unix seconds of the most recent message (0 if none).
    pub last_at: u64,
}

/// A saved address-book contact. (Contacts are a #64 follow-up; this type is part
/// of the stable surface now so the shape doesn't churn later.)
#[derive(Debug, Clone, uniffi::Record)]
pub struct Contact {
    /// The local nickname for the contact.
    pub nickname: String,
    /// The contact's handle.
    pub handle: String,
    /// How much the pinned wallet is trusted.
    pub trust: TrustLevel,
}

/// A group conversation this account belongs to.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Group {
    /// The stable group id.
    pub id: String,
    /// The human-readable group name.
    pub name: String,
    /// The member handles (including this account).
    pub members: Vec<String>,
}

/// This device's own account, for the profile/settings screen.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Account {
    /// The registered handle (empty until `register`).
    pub handle: String,
    /// The chosen display name (empty until `register`).
    pub name: String,
    /// The account's wallet public key, lowercase hex — a stable account id.
    pub wallet_address: String,
}

/// Every error that can cross the boundary. Internal `anyhow`/engine errors are
/// mapped into one of these variants; the underlying error is never leaked.
#[derive(Debug, uniffi::Error)]
pub enum SdkError {
    /// An operation needing a published record was called before `register`.
    NotRegistered,
    /// A network/transport/server failure talking to the directory or queue.
    Network {
        /// A human-readable description (no secrets).
        msg: String,
    },
    /// A local storage (filesystem/serialization) failure.
    Storage {
        /// A human-readable description (no secrets).
        msg: String,
    },
    /// A cryptographic failure (sealing/opening/identity).
    Crypto {
        /// A human-readable description (no secrets).
        msg: String,
    },
    /// A caller-supplied argument was invalid (e.g. a malformed handle).
    InvalidInput {
        /// A human-readable description.
        msg: String,
    },
    /// A peer's wallet no longer matches what we pinned/verified — treat as a
    /// possible impersonation and re-verify out of band.
    IdentityChanged {
        /// The affected peer handle.
        handle: String,
    },
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SdkError::NotRegistered => write!(f, "not registered — call register first"),
            SdkError::Network { msg } => write!(f, "network error: {msg}"),
            SdkError::Storage { msg } => write!(f, "storage error: {msg}"),
            SdkError::Crypto { msg } => write!(f, "crypto error: {msg}"),
            SdkError::InvalidInput { msg } => write!(f, "invalid input: {msg}"),
            SdkError::IdentityChanged { handle } => {
                write!(f, "identity changed for '{handle}' — re-verify out of band")
            }
        }
    }
}

impl std::error::Error for SdkError {}

impl SdkError {
    /// A network/transport failure with a message.
    pub(crate) fn network(e: impl std::fmt::Display) -> Self {
        SdkError::Network { msg: e.to_string() }
    }
    /// A local storage failure with a message.
    pub(crate) fn storage(e: impl std::fmt::Display) -> Self {
        SdkError::Storage { msg: e.to_string() }
    }
    /// A cryptographic failure with a message.
    pub(crate) fn crypto(e: impl std::fmt::Display) -> Self {
        SdkError::Crypto { msg: e.to_string() }
    }
    /// An invalid-argument failure with a message.
    pub(crate) fn invalid(e: impl std::fmt::Display) -> Self {
        SdkError::InvalidInput { msg: e.to_string() }
    }
}

/// Pushed to the foreign UI when incoming events occur. The client implements
/// this; the SDK calls it (e.g. from `sync`) so new mail surfaces without polling
/// the return value.
#[uniffi::export(callback_interface)]
pub trait EventListener: Send + Sync {
    /// A new inbound message was received and stored.
    fn on_message(&self, message: Message);
    /// A message's delivery state changed.
    fn on_delivery(&self, message_id: String, state: DeliveryState);
    /// A peer's key changed (possible impersonation — re-verify).
    fn on_key_change(&self, handle: String);
    /// A device-pairing lifecycle event (opaque string for now).
    fn on_pairing(&self, event: String);
}
