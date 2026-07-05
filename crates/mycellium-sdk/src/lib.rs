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
//! The bulk of persistent state lives under the `data_dir` passed to the
//! constructor; the **identity secret** is held separately behind a
//! [`secrets::SecretStore`]:
//!
//! - The device **identity secret** (wallet secret + device seed) is persisted
//!   through a [`secrets::SecretStore`] the platform app supplies — backed by the
//!   OS keystore (Keychain / Keystore / DPAPI / libsecret). Only that small,
//!   high-value key material goes through the store. See
//!   `docs/research/SECURE-STORAGE.md` and issue #65.
//! - The message history, learned names, and config snapshot live in
//!   `data_dir/store`, an encrypted [`mycellium_storage`] `FileStore` keyed by the
//!   identity itself (so it cannot hold its own key — hence the separate store).
//! - The SDK **never logs secrets** and never returns key material across the
//!   boundary except the public wallet address (a stable, shareable account id).
//! - [`client::MyceliumClient::new`] is a **dev-only** convenience that defaults to
//!   a plaintext-file store; production apps MUST call
//!   [`client::MyceliumClient::new_with_secret_store`] with an OS-backed store.
//!
//! Scope (issue #64): the full messaging surface over native storage —
//! identity → register → send/reply/react/delete/file → sync → read, plus
//! contacts, out-of-band verification, seedless device pairing, groups, and a
//! store backup/restore. Inbound blobs are written to a durable retry store
//! before processing, so a not-yet-decryptable item is retried, not dropped.
//! The C-ABI desktop surface and generated Kotlin/Swift binding smoke tests are
//! the remaining follow-ups.

uniffi::setup_scaffolding!();

pub mod client;
pub mod secrets;
pub mod types;

pub use client::MyceliumClient;
pub use secrets::{PassphraseFileSecretStore, PlaintextFileSecretStore, SecretStore};
pub use types::{
    Account, Contact, Conversation, DeliveryState, EmailVerification, EventListener, Group,
    Message, SdkError, TrustLevel,
};
