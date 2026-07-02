//! The **Storage** capability: persisting identity, sessions, and messages.
//!
//! A tiny key-value interface — the smallest thing the core needs and the
//! easiest to satisfy everywhere. Rich hosts back it with SQLite or files;
//! embedded hosts with a flash key-value store (Layer 10.3).

use alloc::vec::Vec;

/// A persistent, byte-keyed store.
pub trait Storage {
    /// Host-specific storage error.
    type Error;

    /// Fetch the value for `key`, or `None` if absent.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Insert or overwrite `key` with `value`.
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error>;

    /// Remove `key` if present.
    fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error>;
}
