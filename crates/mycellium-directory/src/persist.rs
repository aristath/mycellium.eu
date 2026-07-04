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

/// A durable directory store.
pub struct Store {
    db: Database,
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
        Ok(Store { db })
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
            if let (Ok(handle), Ok(record)) = (Handle::new(k.value()), wire::decode::<SignedRecord>(v.value())) {
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

    /// Atomically write a handle's binding **and** record in one transaction, so
    /// a crash can never leave a binding without its record (or vice versa).
    pub fn put_binding_and_record(&self, handle: &Handle, wallet: &WalletPublicKey, record: &SignedRecord) -> Result<(), String> {
        let encoded = wire::encode(record);
        self.write(|txn| {
            txn.open_table(BINDINGS).map_err(err)?.insert(handle.as_str(), &wallet.0[..]).map_err(err)?;
            txn.open_table(RECORDS).map_err(err)?.insert(handle.as_str(), &encoded[..]).map_err(err)?;
            Ok(())
        })
    }

    /// Atomically write a handle's binding **and** recovery-email hash in one
    /// transaction (for email-verified claim + recovery).
    pub fn put_binding_and_email(&self, handle: &Handle, wallet: &WalletPublicKey, hash: &str) -> Result<(), String> {
        self.write(|txn| {
            txn.open_table(BINDINGS).map_err(err)?.insert(handle.as_str(), &wallet.0[..]).map_err(err)?;
            txn.open_table(EMAILS).map_err(err)?.insert(handle.as_str(), hash).map_err(err)?;
            Ok(())
        })
    }

    pub fn set_pepper(&self, pepper: &[u8; 32]) -> Result<(), String> {
        self.write(|txn| {
            txn.open_table(META).map_err(err)?.insert("pepper", &pepper[..]).map_err(err)?;
            Ok(())
        })
    }

    fn write(&self, f: impl FnOnce(&redb::WriteTransaction) -> Result<(), String>) -> Result<(), String> {
        let txn = self.db.begin_write().map_err(err)?;
        f(&txn)?;
        txn.commit().map_err(err)
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
