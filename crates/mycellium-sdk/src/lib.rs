//! The Mycellium native SDK: the stable boundary that Android (Kotlin), iOS
//! (Swift), and desktop clients bind to via UniFFI.
//!
//! This crate wraps [`mycellium_engine`] in a small, stateful, foreign-friendly
//! API. Foreign code sees only the types in [`types`] — `Record`/`Enum`/`Error`
//! DTOs built from simple primitives — and the [`client::MyceliumClient`] object.
//! Internal `anyhow`/engine errors are mapped to [`types::SdkError`] and never
//! leak across the boundary.
//!
//! ## Ownership of secrets and storage
//!
//! All persistent state lives under the `data_dir` passed to
//! [`client::MyceliumClient::new`]:
//!
//! - The device **identity secret** (wallet secret + device seed) is written to
//!   `data_dir/identity.json`. The message history, learned names, and config
//!   snapshot live in `data_dir/store`, an encrypted [`mycellium_storage`]
//!   `FileStore` keyed by the identity itself.
//! - The SDK **never logs secrets** and never returns key material across the
//!   boundary except the public wallet address (a stable, shareable account id).
//! - Issue #65 will slot OS-secure-storage adapters (Android Keystore / iOS
//!   Keychain) *underneath this same API*, replacing the sidecar identity file
//!   without changing the foreign contract.
//!
//! Scope of this increment (issue #64): a correct, building, testable
//! identity → register → send → sync → read core over native storage. Groups,
//! pairing, contacts, verification, backup, and the C-ABI are follow-ups.

uniffi::setup_scaffolding!();

pub mod client;
pub mod types;

pub use client::MyceliumClient;
pub use types::{
    Account, Contact, Conversation, DeliveryState, EventListener, Message, SdkError, TrustLevel,
};
