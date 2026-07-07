//! The name registry: a durable `name → (pubkey, relays)` table backed by SQLite,
//! fronted by an in-memory map so the hot path (`/.well-known/nostr.json`
//! resolution) is a lock-free-ish read, never a disk hit. Writes go to SQLite
//! first (the authority — its `PRIMARY KEY` arbitrates races) then the cache.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, RwLock};

use nostr::{PublicKey, RelayUrl};
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::policy::{Policy, PolicyError};

/// A resolved binding: the key a name points at, plus the owner's preferred relays.
#[derive(Debug, Clone)]
pub struct NameRecord {
    pub pubkey: PublicKey,
    pub relays: Vec<RelayUrl>,
}

/// Why a registry mutation failed.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("that name is already taken")]
    Taken,
    #[error("this key already holds its maximum of {0} name(s)")]
    KeyLimit(usize),
    #[error("no such name")]
    NotFound,
    #[error("that name is owned by a different key")]
    NotOwner,
    #[error("database error: {0}")]
    Db(String),
}

impl From<rusqlite::Error> for RegistryError {
    fn from(e: rusqlite::Error) -> Self {
        RegistryError::Db(e.to_string())
    }
}

pub struct Registry {
    names: RwLock<HashMap<String, NameRecord>>,
    db: Mutex<Connection>,
    policy: Policy,
}

impl Registry {
    /// Open (creating if absent) the registry at `path` and load it into memory.
    pub fn open(path: impl AsRef<Path>, policy: Policy) -> Result<Self, RegistryError> {
        Self::from_connection(Connection::open(path)?, policy)
    }

    /// An ephemeral in-memory registry — for tests.
    pub fn open_in_memory(policy: Policy) -> Result<Self, RegistryError> {
        Self::from_connection(Connection::open_in_memory()?, policy)
    }

    fn from_connection(db: Connection, policy: Policy) -> Result<Self, RegistryError> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS names (
                 name   TEXT PRIMARY KEY,
                 pubkey TEXT NOT NULL,
                 relays TEXT NOT NULL DEFAULT ''
             );
             CREATE INDEX IF NOT EXISTS idx_names_pubkey ON names(pubkey);",
        )?;

        let mut names = HashMap::new();
        {
            let mut stmt = db.prepare("SELECT name, pubkey, relays FROM names")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (name, pk, relays) = row?;
                let pubkey = PublicKey::from_hex(&pk)
                    .map_err(|e| RegistryError::Db(format!("corrupt pubkey for '{name}': {e}")))?;
                names.insert(
                    name,
                    NameRecord {
                        pubkey,
                        relays: parse_relays(&relays),
                    },
                );
            }
        }
        Ok(Self {
            names: RwLock::new(names),
            db: Mutex::new(db),
            policy,
        })
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Resolve a name to its binding (case-insensitive). The read hot path.
    pub fn resolve(&self, name: &str) -> Option<NameRecord> {
        let name = name.trim().to_ascii_lowercase();
        self.names.read().unwrap().get(&name).cloned()
    }

    /// Build the NIP-05 `/.well-known/nostr.json` document for a single name:
    /// `{"names": {..}, "relays": {..}}`, or `{"names": {}}` if unknown.
    pub fn well_known(&self, name: &str) -> Value {
        let mut out_names = Map::new();
        let mut out_relays = Map::new();
        if let Some(rec) = self.resolve(name) {
            let hex = rec.pubkey.to_hex();
            out_names.insert(name.trim().to_ascii_lowercase(), json!(hex));
            if !rec.relays.is_empty() {
                let urls: Vec<String> = rec.relays.iter().map(RelayUrl::to_string).collect();
                out_relays.insert(hex, json!(urls));
            }
        }
        let mut obj = Map::new();
        obj.insert("names".to_string(), Value::Object(out_names));
        if !out_relays.is_empty() {
            obj.insert("relays".to_string(), Value::Object(out_relays));
        }
        Value::Object(obj)
    }

    /// Bind a fresh `name` to `pubkey`. Fails if the name is invalid, already
    /// taken, or the key is at its name limit.
    pub fn register(
        &self,
        name: &str,
        pubkey: PublicKey,
        relays: Vec<RelayUrl>,
    ) -> Result<String, RegistryError> {
        let name = self.policy.normalize(name)?;
        // Hold the db lock for the whole op so concurrent writers are serialized;
        // SQLite's PRIMARY KEY is still the final arbiter on the name itself.
        let db = self.db.lock().unwrap();
        if self.names_held_by(&pubkey) >= self.policy.max_names_per_key {
            return Err(RegistryError::KeyLimit(self.policy.max_names_per_key));
        }
        match db.execute(
            "INSERT INTO names (name, pubkey, relays) VALUES (?1, ?2, ?3)",
            (&name, pubkey.to_hex(), encode_relays(&relays)),
        ) {
            Ok(_) => {}
            Err(e) if is_constraint(&e) => return Err(RegistryError::Taken),
            Err(e) => return Err(e.into()),
        }
        self.names
            .write()
            .unwrap()
            .insert(name.clone(), NameRecord { pubkey, relays });
        Ok(name)
    }

    /// Point an existing name at a new key — authorized by its **current** owner
    /// (checked here). This is how a name follows an account-key rotation.
    pub fn reassign(
        &self,
        name: &str,
        current_owner: PublicKey,
        new_pubkey: PublicKey,
        relays: Vec<RelayUrl>,
    ) -> Result<String, RegistryError> {
        let name = name.trim().to_ascii_lowercase();
        let db = self.db.lock().unwrap();
        self.require_owner(&name, &current_owner)?;
        db.execute(
            "UPDATE names SET pubkey = ?1, relays = ?2 WHERE name = ?3",
            (new_pubkey.to_hex(), encode_relays(&relays), &name),
        )?;
        self.names.write().unwrap().insert(
            name.clone(),
            NameRecord {
                pubkey: new_pubkey,
                relays,
            },
        );
        Ok(name)
    }

    /// Release a name, authorized by its owner.
    pub fn release(&self, name: &str, owner: PublicKey) -> Result<String, RegistryError> {
        let name = name.trim().to_ascii_lowercase();
        let db = self.db.lock().unwrap();
        self.require_owner(&name, &owner)?;
        db.execute("DELETE FROM names WHERE name = ?1", (&name,))?;
        self.names.write().unwrap().remove(&name);
        Ok(name)
    }

    fn names_held_by(&self, pubkey: &PublicKey) -> usize {
        self.names
            .read()
            .unwrap()
            .values()
            .filter(|r| &r.pubkey == pubkey)
            .count()
    }

    fn require_owner(&self, name: &str, who: &PublicKey) -> Result<(), RegistryError> {
        match self.names.read().unwrap().get(name) {
            None => Err(RegistryError::NotFound),
            Some(rec) if &rec.pubkey != who => Err(RegistryError::NotOwner),
            Some(_) => Ok(()),
        }
    }
}

fn is_constraint(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

fn encode_relays(relays: &[RelayUrl]) -> String {
    relays
        .iter()
        .map(RelayUrl::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_relays(s: &str) -> Vec<RelayUrl> {
    s.split_whitespace()
        .filter_map(|u| RelayUrl::parse(u).ok())
        .collect()
}
