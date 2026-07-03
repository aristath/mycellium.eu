//! Storage-port adapters: the durable local state a peer keeps on a rich host.
//!
//! - [`filestore`] — an encrypted, file-backed key-value store implementing
//!   `mycellium_core::storage::Storage` (the engine's transcripts, groups,
//!   contacts, etc. ride on it), keyed from the identity via HKDF.
//! - [`store`] — the identity at rest: the seed phrase + this device's seed,
//!   sealed with Argon2id + ChaCha20-Poly1305 under a user passphrase.
//!
//! A different platform (web, embedded) swaps this crate for its own Storage
//! adapter; the engine depends only on the core `Storage` port.

pub mod filestore;
pub mod store;
