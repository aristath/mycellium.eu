//! Durable storage for the queue (Tier 0.1).
//!
//! Persists what must survive a restart: queued mail (per recipient wallet +
//! slot) and Web Push subscriptions. Ephemeral state (login challenges, session
//! tokens, rate counters) stays in memory. Backed by `redb`.

use std::collections::HashMap;

use redb::{ReadableTable, TableDefinition};

const MAILBOX: TableDefinition<&str, &[u8]> = TableDefinition::new("mailbox"); // "wallet\0slot" → json Vec<String>
const SUBS: TableDefinition<&str, &[u8]> = TableDefinition::new("subs"); // wallet → json Vec<String>

/// The persisted state loaded on startup.
#[derive(Default)]
pub struct Loaded {
    pub mailboxes: HashMap<(String, String), Vec<String>>,
    pub subs: HashMap<String, Vec<String>>,
}

pub struct Store {
    db: redb::Database,
}

impl Store {
    pub fn open(path: &str) -> Result<Self, String> {
        let db = redb::Database::create(path).map_err(err)?;
        let txn = db.begin_write().map_err(err)?;
        {
            txn.open_table(MAILBOX).map_err(err)?;
            txn.open_table(SUBS).map_err(err)?;
        }
        txn.commit().map_err(err)?;
        Ok(Store { db })
    }

    pub fn load(&self) -> Result<Loaded, String> {
        let mut out = Loaded::default();
        let txn = self.db.begin_read().map_err(err)?;

        let mailbox = txn.open_table(MAILBOX).map_err(err)?;
        for entry in mailbox.iter().map_err(err)? {
            let (k, v) = entry.map_err(err)?;
            if let Some((wallet, slot)) = k.value().split_once('\0') {
                if let Ok(blobs) = serde_json::from_slice::<Vec<String>>(v.value()) {
                    out.mailboxes
                        .insert((wallet.to_string(), slot.to_string()), blobs);
                }
            }
        }
        let subs = txn.open_table(SUBS).map_err(err)?;
        for entry in subs.iter().map_err(err)? {
            let (k, v) = entry.map_err(err)?;
            if let Ok(endpoints) = serde_json::from_slice::<Vec<String>>(v.value()) {
                out.subs.insert(k.value().to_string(), endpoints);
            }
        }
        Ok(out)
    }

    /// Write the whole blob list for one `(wallet, slot)` mailbox.
    pub fn put_mailbox(&self, wallet: &str, slot: &str, blobs: &[String]) -> Result<(), String> {
        let key = format!("{wallet}\0{slot}");
        let json = serde_json::to_vec(blobs).map_err(err)?;
        self.write(|txn| {
            txn.open_table(MAILBOX)
                .map_err(err)?
                .insert(key.as_str(), &json[..])
                .map_err(err)?;
            Ok(())
        })
    }

    pub fn del_mailbox(&self, wallet: &str, slot: &str) -> Result<(), String> {
        let key = format!("{wallet}\0{slot}");
        self.write(|txn| {
            txn.open_table(MAILBOX)
                .map_err(err)?
                .remove(key.as_str())
                .map_err(err)?;
            Ok(())
        })
    }

    pub fn put_subs(&self, wallet: &str, endpoints: &[String]) -> Result<(), String> {
        let json = serde_json::to_vec(endpoints).map_err(err)?;
        self.write(|txn| {
            txn.open_table(SUBS)
                .map_err(err)?
                .insert(wallet, &json[..])
                .map_err(err)?;
            Ok(())
        })
    }

    fn write(
        &self,
        f: impl FnOnce(&redb::WriteTransaction) -> Result<(), String>,
    ) -> Result<(), String> {
        let txn = self.db.begin_write().map_err(err)?;
        f(&txn)?;
        txn.commit().map_err(err)
    }
}

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}
