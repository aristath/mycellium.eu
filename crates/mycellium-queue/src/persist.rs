//! Durable storage for the queue (Tier 0.1).
//!
//! Persists what must survive a restart: queued mail (per recipient wallet +
//! slot) and push subscriptions. Ephemeral state (login challenges, session
//! tokens, rate counters) stays in memory. Backed by `redb`.

use std::collections::HashMap;

use redb::{ReadableTable, TableDefinition};

use crate::Subscription;

const MAILBOX: TableDefinition<&str, &[u8]> = TableDefinition::new("mailbox"); // "wallet\0slot" → json Vec<String>
const SUBS: TableDefinition<&str, &[u8]> = TableDefinition::new("subs"); // wallet → json Vec<Subscription>

/// The persisted state loaded on startup.
#[derive(Default)]
pub struct Loaded {
    pub mailboxes: HashMap<(String, String), Vec<String>>,
    pub subs: HashMap<String, Vec<Subscription>>,
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
            out.subs.insert(k.value().to_string(), load_subs(v.value()));
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

    pub fn put_subs(&self, wallet: &str, subs: &[Subscription]) -> Result<(), String> {
        let json = serde_json::to_vec(subs).map_err(err)?;
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

/// Decode a persisted subscription list, upgrading the pre-tagged-union format
/// (a bare `Vec<String>` of web-push endpoints) into `Vec<Subscription>`.
///
/// Current format first; on failure fall back to the old endpoint-string shape
/// (back-compat), exactly like the outbox `load()` upcast. This explicit
/// fallback is load-bearing: `serde_json` will **not** coerce a bare endpoint
/// string into a `#[serde(tag = "kind")]` enum, so a naive type change would
/// fail to decode and silently drop *every* pre-upgrade subscription. Genuinely
/// corrupt bytes decode to an empty list, as before.
fn load_subs(bytes: &[u8]) -> Vec<Subscription> {
    if let Ok(subs) = serde_json::from_slice::<Vec<Subscription>>(bytes) {
        return subs;
    }
    if let Ok(endpoints) = serde_json::from_slice::<Vec<String>>(bytes) {
        return endpoints
            .into_iter()
            .map(|endpoint| Subscription::WebPush { endpoint })
            .collect();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "myc-persist-{tag}-{}-{:?}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
        ))
    }

    #[test]
    fn old_format_web_push_subs_migrate_to_webpush() {
        let path = temp_path("subs-migrate");
        let path_str = path.to_str().unwrap();
        {
            let store = Store::open(path_str).unwrap();
            // Plant an OLD-format blob: a bare `Vec<String>` of endpoints, exactly
            // as a pre-tagged-union build persisted, straight into the SUBS table.
            let old = serde_json::to_vec(&vec![
                "https://push.example/a".to_string(),
                "https://push.example/b".to_string(),
            ])
            .unwrap();
            store
                .write(|txn| {
                    txn.open_table(SUBS)
                        .map_err(err)?
                        .insert("wallethex", &old[..])
                        .map_err(err)?;
                    Ok(())
                })
                .unwrap();
        }
        // Reopening upgrades the bare strings into tagged `WebPush` entries.
        let loaded = Store::open(path_str).unwrap().load().unwrap();
        assert_eq!(
            loaded.subs.get("wallethex").unwrap(),
            &vec![
                Subscription::WebPush {
                    endpoint: "https://push.example/a".into()
                },
                Subscription::WebPush {
                    endpoint: "https://push.example/b".into()
                },
            ],
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tagged_subscriptions_round_trip() {
        let path = temp_path("subs-roundtrip");
        let path_str = path.to_str().unwrap();
        let subs = vec![
            Subscription::WebPush {
                endpoint: "https://push.example/x".into(),
            },
            Subscription::Apns {
                token: "abcdef01".into(),
                topic: "eu.mycellium.app".into(),
            },
            Subscription::Fcm {
                token: "fcm-token".into(),
            },
            Subscription::UnifiedPush {
                endpoint: "https://ntfy.example/up".into(),
            },
        ];
        {
            let store = Store::open(path_str).unwrap();
            store.put_subs("wallethex", &subs).unwrap();
        }
        let loaded = Store::open(path_str).unwrap().load().unwrap();
        assert_eq!(loaded.subs.get("wallethex").unwrap(), &subs);
        let _ = std::fs::remove_file(&path);
    }
}
