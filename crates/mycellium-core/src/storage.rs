//! The **Storage** capability: persisting identity, sessions, and messages.
//!
//! A tiny key-value interface — the smallest thing the core needs and the
//! easiest to satisfy everywhere. Rich hosts back it with SQLite or files;
//! embedded hosts with a flash key-value store.

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// One mutation in an atomic storage batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageMutation {
    /// Insert or replace one key and value.
    Put(Vec<u8>, Vec<u8>),
    /// Remove one key if it exists.
    Delete(Vec<u8>),
}

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

    /// Apply related mutations atomically when the backend supports it. Tiny
    /// stores may use the sequential default; durable hosts override this with
    /// a transaction or write-ahead journal.
    fn apply_batch(&mut self, mutations: &[StorageMutation]) -> Result<(), Self::Error> {
        for mutation in mutations {
            match mutation {
                StorageMutation::Put(key, value) => self.put(key, value)?,
                StorageMutation::Delete(key) => self.delete(key)?,
            }
        }
        Ok(())
    }
}
