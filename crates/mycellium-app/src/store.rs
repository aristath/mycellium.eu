//! The app's durable, at-rest state: contacts + trust pins, conversation
//! metadata, and per-conversation transcripts.
//!
//! Backed by a single **SQLCipher-encrypted** SQLite database (via `rusqlite`'s
//! bundled SQLCipher, so no system SQLite is required), separate from the MLS
//! state database that `mdk-sqlite-storage` owns. The encryption key is derived
//! from this device's seed (via the app engine's `derive_db_key`), so the
//! transcript and address book are encrypted with the identity.
//!
//! Transcripts survive restart: reopening the same file against the same key
//! yields the same messages. This is what makes the engine a real messenger core
//! rather than a volatile demo.

use nostr::PublicKey;
use rusqlite::{Connection, OptionalExtension};

use crate::contacts::Contact;

/// One stored message in a conversation transcript (sent or received).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredMessage {
    /// Whether this device sent it (vs. received it).
    pub from_me: bool,
    /// The author's *device* pubkey (the MLS-leaf that sent it); `None` for our
    /// own sends where it is implicitly this device.
    pub author: Option<PublicKey>,
    /// The plaintext.
    pub text: String,
    /// Unix seconds when it was stored.
    pub timestamp: u64,
}

/// Errors from the app store.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A SQLite / SQLCipher error.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// A stored pubkey hex string could not be parsed back.
    #[error("stored public key is not valid: {0}")]
    BadKey(String),
}

type Result<T> = core::result::Result<T, Error>;

/// The encrypted app-data store.
pub struct AppStore {
    conn: Connection,
}

impl AppStore {
    /// Open (creating if needed) the encrypted store at `path`, keyed by the
    /// 32-byte `key`, and ensure the schema exists.
    pub fn open(path: &std::path::Path, key: [u8; 32]) -> Result<Self> {
        let conn = Connection::open(path)?;
        // SQLCipher raw-key form (`x'..64 hex..'`) uses the key material directly,
        // skipping the passphrase KDF — appropriate since `key` is already a
        // high-entropy derived key, not a human passphrase.
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS contacts (
                 id        TEXT PRIMARY KEY,
                 account   TEXT NOT NULL,
                 nip05     TEXT,
                 name      TEXT,
                 verified  INTEGER NOT NULL DEFAULT 0,
                 added_at  INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS conversations (
                 id         TEXT PRIMARY KEY,
                 title      TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS messages (
                 conversation_id TEXT NOT NULL,
                 from_me         INTEGER NOT NULL,
                 author          TEXT,
                 text            TEXT NOT NULL,
                 timestamp       INTEGER NOT NULL,
                 event_id        TEXT UNIQUE,
                 FOREIGN KEY (conversation_id) REFERENCES conversations(id)
             );
             CREATE INDEX IF NOT EXISTS messages_by_conv
                 ON messages(conversation_id);",
        )?;
        Ok(())
    }

    // -- Contacts -----------------------------------------------------------

    /// Insert or replace a contact (pinning its account key).
    pub fn put_contact(&self, c: &Contact) -> Result<()> {
        self.conn.execute(
            "INSERT INTO contacts (id, account, nip05, name, verified, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                 account=?2, nip05=?3, name=?4, verified=?5, added_at=?6",
            rusqlite::params![
                c.id,
                c.account.to_hex(),
                c.nip05,
                c.name,
                c.verified as i64,
                c.added_at as i64,
            ],
        )?;
        Ok(())
    }

    /// Look up a contact by its local handle.
    pub fn get_contact(&self, id: &str) -> Result<Option<Contact>> {
        self.conn
            .query_row(
                "SELECT id, account, nip05, name, verified, added_at
                 FROM contacts WHERE id = ?1",
                [id],
                row_to_contact,
            )
            .optional()?
            .transpose()
    }

    /// Every contact, in insertion order.
    pub fn list_contacts(&self) -> Result<Vec<Contact>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, account, nip05, name, verified, added_at
             FROM contacts ORDER BY added_at, id",
        )?;
        let rows = stmt.query_map([], row_to_contact)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    /// Mark a contact verified (out-of-band safety-number confirmation).
    pub fn set_verified(&self, id: &str, verified: bool) -> Result<()> {
        self.conn.execute(
            "UPDATE contacts SET verified = ?2 WHERE id = ?1",
            rusqlite::params![id, verified as i64],
        )?;
        Ok(())
    }

    // -- Conversations ------------------------------------------------------

    /// Insert a conversation if absent (idempotent); leaves an existing title.
    pub fn ensure_conversation(&self, id: &str, title: &str, created_at: u64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO conversations (id, title, created_at)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![id, title, created_at as i64],
        )?;
        Ok(())
    }

    /// A conversation's title, if it exists.
    pub fn conversation_title(&self, id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT title FROM conversations WHERE id = ?1",
                [id],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    }

    /// Every conversation id + title, oldest first.
    pub fn list_conversations(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, title FROM conversations ORDER BY created_at, id")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // -- Transcripts --------------------------------------------------------

    /// Append a message to a conversation's transcript, de-duplicated by
    /// `event_id` (the Nostr event that carried it). Returns `true` if it was
    /// newly inserted, `false` if it was a duplicate already stored.
    pub fn append_message(
        &self,
        conversation_id: &str,
        msg: &StoredMessage,
        event_id: &str,
    ) -> Result<bool> {
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO messages
                 (conversation_id, from_me, author, text, timestamp, event_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                conversation_id,
                msg.from_me as i64,
                msg.author.map(|a| a.to_hex()),
                msg.text,
                msg.timestamp as i64,
                event_id,
            ],
        )?;
        Ok(changed > 0)
    }

    /// A conversation's full transcript, in insertion (rowid) order.
    pub fn transcript(&self, conversation_id: &str) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT from_me, author, text, timestamp
             FROM messages WHERE conversation_id = ?1 ORDER BY rowid",
        )?;
        let rows = stmt.query_map([conversation_id], |row| {
            let author_hex: Option<String> = row.get(1)?;
            Ok((
                row.get::<_, i64>(0)? != 0,
                author_hex,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)? as u64,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (from_me, author_hex, text, timestamp) = r?;
            let author = match author_hex {
                Some(h) => Some(PublicKey::from_hex(&h).map_err(|_| Error::BadKey(h))?),
                None => None,
            };
            out.push(StoredMessage {
                from_me,
                author,
                text,
                timestamp,
            });
        }
        Ok(out)
    }
}

/// Map a `contacts` row to a [`Contact`] (pubkey parse is fallible → inner Result).
fn row_to_contact(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Contact>> {
    let account_hex: String = row.get(1)?;
    let verified: i64 = row.get(4)?;
    let added_at: i64 = row.get(5)?;
    Ok((|| {
        Ok(Contact {
            id: row.get(0)?,
            account: PublicKey::from_hex(&account_hex).map_err(|_| Error::BadKey(account_hex))?,
            nip05: row.get(2)?,
            name: row.get(3)?,
            verified: verified != 0,
            added_at: added_at as u64,
        })
    })())
}
