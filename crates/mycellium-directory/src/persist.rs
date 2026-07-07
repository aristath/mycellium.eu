//! Durable storage for the directory (Tier 0.1).
//!
//! Only the data that *must* survive a restart is persisted: handle→wallet
//! bindings, published records, recovery-email hashes, and the email-hash
//! pepper. Ephemeral state (login challenges, session tokens, presence, pending
//! verification codes, rate counters) stays in memory and is fine to lose.
//!
//! Backed by `redb` — a single-file, pure-Rust embedded store. A multi-node
//! deployment swaps this for Postgres; the [`Directory`](crate::Directory) logic
//! is unchanged.

use std::collections::HashMap;
use std::sync::Mutex;

use mycellium_core::identity::{Handle, WalletPublicKey};
use mycellium_core::record::SignedRecord;
use mycellium_core::wire;
use redb::{Database, ReadableTable, TableDefinition};

const BINDINGS: TableDefinition<&str, &[u8]> = TableDefinition::new("bindings"); // handle → wallet[33]
const RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("records"); // handle → encoded SignedRecord
const EMAILS: TableDefinition<&str, &str> = TableDefinition::new("emails"); // handle → email hash
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta"); // "pepper" → [u8;32]

/// What a fresh process loads back from disk.
#[derive(Default)]
pub struct Loaded {
    pub bindings: HashMap<Handle, WalletPublicKey>,
    pub records: HashMap<Handle, SignedRecord>,
    pub emails: HashMap<Handle, String>,
    pub pepper: Option<[u8; 32]>,
}

/// One durable mutation, captured under the [`Directory`](crate::Directory) lock
/// and committed **off** it (on `spawn_blocking`). Each carries a monotonic `seq`
/// from the directory's write counter so [`Store::apply`] can drop a stale
/// off-lock commit whose handle a newer commit already advanced — keeping the
/// durable record equal to the latest in-memory one even when a `publish`'s
/// commit reaches redb out of the order the memory was mutated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Write {
    /// A published record: its binding **and** record, written atomically.
    Record {
        handle: String,
        wallet: [u8; 33],
        record: Vec<u8>,
        seq: u64,
    },
    /// An email-verified claim: its binding **and** recovery-email hash, atomic.
    Email {
        handle: String,
        wallet: [u8; 33],
        hash: String,
        seq: u64,
    },
}

/// A durable directory store.
pub struct Store {
    db: Database,
    /// Highest committed `seq` per handle-scoped key — the guard that makes
    /// concurrent off-lock commits order-independent (see [`Write`]). Touched only
    /// on the write path (inside `spawn_blocking`), never by a read handler.
    versions: Mutex<HashMap<String, u64>>,
}

impl Store {
    /// Open (or create) the store at `path`.
    pub fn open(path: &str) -> Result<Self, String> {
        let db = Database::create(path).map_err(|e| e.to_string())?;
        // Ensure tables exist so the first read never fails.
        let txn = db.begin_write().map_err(|e| e.to_string())?;
        {
            txn.open_table(BINDINGS).map_err(|e| e.to_string())?;
            txn.open_table(RECORDS).map_err(|e| e.to_string())?;
            txn.open_table(EMAILS).map_err(|e| e.to_string())?;
            txn.open_table(META).map_err(|e| e.to_string())?;
        }
        txn.commit().map_err(|e| e.to_string())?;
        Ok(Store {
            db,
            versions: Mutex::new(HashMap::new()),
        })
    }

    /// Read everything back into memory.
    pub fn load(&self) -> Result<Loaded, String> {
        let mut out = Loaded::default();
        let txn = self.db.begin_read().map_err(|e| e.to_string())?;

        let bindings = txn.open_table(BINDINGS).map_err(|e| e.to_string())?;
        for entry in bindings.iter().map_err(|e| e.to_string())? {
            let (k, v) = entry.map_err(|e| e.to_string())?;
            if let (Ok(handle), Ok(wallet)) = (Handle::new(k.value()), wallet_from(v.value())) {
                out.bindings.insert(handle, wallet);
            }
        }
        let records = txn.open_table(RECORDS).map_err(|e| e.to_string())?;
        for entry in records.iter().map_err(|e| e.to_string())? {
            let (k, v) = entry.map_err(|e| e.to_string())?;
            if let (Ok(handle), Ok(record)) = (
                Handle::new(k.value()),
                wire::decode::<SignedRecord>(v.value()),
            ) {
                out.records.insert(handle, record);
            }
        }
        let emails = txn.open_table(EMAILS).map_err(|e| e.to_string())?;
        for entry in emails.iter().map_err(|e| e.to_string())? {
            let (k, v) = entry.map_err(|e| e.to_string())?;
            if let Ok(handle) = Handle::new(k.value()) {
                out.emails.insert(handle, v.value().to_string());
            }
        }
        let meta = txn.open_table(META).map_err(|e| e.to_string())?;
        if let Some(v) = meta.get("pepper").map_err(|e| e.to_string())? {
            let bytes = v.value();
            if bytes.len() == 32 {
                let mut p = [0u8; 32];
                p.copy_from_slice(bytes);
                out.pepper = Some(p);
            }
        }
        Ok(out)
    }

    /// Durably apply one [`Write`], guarding against stale off-lock commits by its
    /// `seq` (see [`Write`]). Each variant is one atomic multi-table transaction,
    /// so a crash can never leave a binding without its record/email. Returns
    /// `Ok(())` for both a fresh commit and a deliberately-skipped stale one.
    pub fn apply(&self, write: Write) -> Result<(), String> {
        match write {
            Write::Record {
                handle,
                wallet,
                record,
                seq,
            } => self.versioned(&format!("r:{handle}"), seq, |txn| {
                txn.open_table(BINDINGS)
                    .map_err(err)?
                    .insert(handle.as_str(), &wallet[..])
                    .map_err(err)?;
                txn.open_table(RECORDS)
                    .map_err(err)?
                    .insert(handle.as_str(), &record[..])
                    .map_err(err)?;
                Ok(())
            }),
            Write::Email {
                handle,
                wallet,
                hash,
                seq,
            } => self.versioned(&format!("e:{handle}"), seq, |txn| {
                txn.open_table(BINDINGS)
                    .map_err(err)?
                    .insert(handle.as_str(), &wallet[..])
                    .map_err(err)?;
                txn.open_table(EMAILS)
                    .map_err(err)?
                    .insert(handle.as_str(), hash.as_str())
                    .map_err(err)?;
                Ok(())
            }),
        }
    }

    pub fn set_pepper(&self, pepper: &[u8; 32]) -> Result<(), String> {
        let txn = self.db.begin_write().map_err(err)?;
        txn.open_table(META)
            .map_err(err)?
            .insert("pepper", &pepper[..])
            .map_err(err)?;
        txn.commit().map_err(err)
    }

    /// Commit `f` iff `seq` is newer than the last committed `seq` for `vkey`,
    /// else skip it as stale. The `versions` lock spans the commit so a concurrent
    /// apply to the same key can't interleave a stale write — redb already
    /// serializes its single writer, and (unlike the state lock it replaced) this
    /// lock is never held across a read.
    fn versioned(
        &self,
        vkey: &str,
        seq: u64,
        f: impl FnOnce(&redb::WriteTransaction) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut versions = self.versions.lock().unwrap_or_else(|e| e.into_inner());
        if versions.get(vkey).is_some_and(|&last| seq <= last) {
            return Ok(()); // a newer snapshot already committed this handle
        }
        let txn = self.db.begin_write().map_err(err)?;
        f(&txn)?;
        txn.commit().map_err(err)?;
        versions.insert(vkey.to_string(), seq);
        Ok(())
    }
}

/// Stringify any redb error (keeps `Result` `Err` variants small).
fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn wallet_from(bytes: &[u8]) -> Result<WalletPublicKey, ()> {
    if bytes.len() != 33 {
        return Err(());
    }
    let mut w = [0u8; 33];
    w.copy_from_slice(bytes);
    Ok(WalletPublicKey(w))
}
