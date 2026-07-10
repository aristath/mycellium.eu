//! An encrypted, file-backed implementation of the core [`Storage`] trait.
//!
//! Each key maps to one file whose contents are `nonce || ChaCha20-Poly1305(value)`
//! under a key derived from the identity
//! ([`Identity::storage_key`](mycellium_core::identity::Identity::storage_key)). So local
//! data (message history) is encrypted at rest, consistent with the seed.
//!
//! The logical storage key is bound into the AEAD as **associated data**, so a
//! ciphertext authenticates the key it belongs to (the on-disk filename `hex(key)`
//! is otherwise unauthenticated). This defeats an at-rest attacker with write
//! access relocating one key's blob onto another key's path (record confusion).
//! NOTE: this is a clean format break — entries written before AAD binding will no
//! longer decrypt. That is acceptable because this store holds only locally
//! generated state with no cross-version persisted-data contract to preserve.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

use mycellium_core::storage::Storage;
use serde::{Deserialize, Serialize};

const JOURNAL_FILE: &str = ".transaction-v1";
const JOURNAL_AAD: &[u8] = b"mycellium-storage-transaction-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Mutation {
    Put(Vec<u8>, Vec<u8>),
    Delete(Vec<u8>),
}

/// A directory of encrypted key-value files.
pub struct FileStore {
    dir: PathBuf,
    key: [u8; 32],
}

impl FileStore {
    /// Open (creating if needed) a store in `dir`, encrypting with `key`.
    pub fn open(dir: PathBuf, key: [u8; 32]) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        crate::perms::restrict_dir(&dir);
        let mut store = FileStore { dir, key };
        store.recover_transaction()?;
        Ok(store)
    }

    /// The on-disk path for a key (hex of the raw key bytes — always a safe name).
    fn path(&self, key: &[u8]) -> PathBuf {
        let mut name = String::with_capacity(key.len() * 2);
        for b in key {
            name.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            name.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        self.dir.join(name)
    }

    fn journal_path(&self) -> PathBuf {
        self.dir.join(JOURNAL_FILE)
    }

    fn ensure_ready(&self) -> io::Result<()> {
        if self.journal_path().exists() {
            return Err(io::Error::other(
                "transaction recovery required; reopen the store",
            ));
        }
        Ok(())
    }

    /// Begin an isolated write transaction. Reads observe staged mutations;
    /// dropping without [`FileTransaction::commit`] rolls them back.
    pub fn transaction(&mut self) -> FileTransaction<'_> {
        FileTransaction {
            store: self,
            changes: BTreeMap::new(),
        }
    }

    fn encrypt(&self, aad: &[u8], value: &[u8]) -> io::Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|_| io::Error::other("RNG failure"))?;
        let key_ga: Key = self.key.into();
        let nonce_ga: Nonce = nonce.into();
        let ciphertext = ChaCha20Poly1305::new(&key_ga)
            .encrypt(&nonce_ga, Payload { msg: value, aad })
            .map_err(|_| io::Error::other("encryption failed"))?;

        let mut blob = Vec::with_capacity(12 + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        Ok(blob)
    }

    fn decrypt(&self, aad: &[u8], blob: &[u8]) -> io::Result<Vec<u8>> {
        if blob.len() < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "corrupt store entry",
            ));
        }
        let (nonce, ciphertext) = blob.split_at(12);
        let key_ga: Key = self.key.into();
        let nonce_arr: [u8; 12] = nonce.try_into().unwrap();
        let nonce_ga: Nonce = nonce_arr.into();
        ChaCha20Poly1305::new(&key_ga)
            .decrypt(
                &nonce_ga,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed"))
    }

    fn apply(&mut self, mutations: &[Mutation]) -> io::Result<()> {
        for mutation in mutations {
            match mutation {
                Mutation::Put(key, value) => self.put_raw(key, value)?,
                Mutation::Delete(key) => self.delete_raw(key)?,
            }
        }
        Ok(())
    }

    fn put_raw(&mut self, key: &[u8], value: &[u8]) -> io::Result<()> {
        let blob = self.encrypt(key, value)?;
        crate::atomic_write(&self.path(key), &blob)
    }

    fn delete_raw(&mut self, key: &[u8]) -> io::Result<()> {
        match fs::remove_file(self.path(key)) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn recover_transaction(&mut self) -> io::Result<()> {
        let blob = match fs::read(self.journal_path()) {
            Ok(blob) => blob,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        };
        let plaintext = self.decrypt(JOURNAL_AAD, &blob)?;
        let mutations: Vec<Mutation> = mycellium_core::wire::decode(&plaintext)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "corrupt transaction"))?;
        self.apply(&mutations)?;
        self.finish_transaction()
    }

    fn finish_transaction(&self) -> io::Result<()> {
        match fs::remove_file(self.journal_path()) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        }
        fs::File::open(&self.dir)?.sync_all()
    }
}

/// An in-memory overlay committed through an encrypted, fsynced write-ahead
/// journal. Once the journal is durable, recovery replays every mutation after
/// a crash, so callers observe all-or-eventually-all rather than a torn update.
pub struct FileTransaction<'a> {
    store: &'a mut FileStore,
    changes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl FileTransaction<'_> {
    /// Durably commit every staged mutation as one recoverable unit.
    pub fn commit(self) -> io::Result<()> {
        self.store.ensure_ready()?;
        let mutations: Vec<Mutation> = self
            .changes
            .into_iter()
            .map(|(key, value)| match value {
                Some(value) => Mutation::Put(key, value),
                None => Mutation::Delete(key),
            })
            .collect();
        if mutations.is_empty() {
            return Ok(());
        }
        let plaintext = mycellium_core::wire::encode(&mutations);
        let journal = self.store.encrypt(JOURNAL_AAD, &plaintext)?;
        crate::atomic_write(&self.store.journal_path(), &journal)?;
        self.store.apply(&mutations)?;
        self.store.finish_transaction()
    }
}

impl Storage for FileTransaction<'_> {
    type Error = io::Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        match self.changes.get(key) {
            Some(value) => Ok(value.clone()),
            None => self.store.get(key),
        }
    }

    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.changes.insert(key.to_vec(), Some(value.to_vec()));
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        self.changes.insert(key.to_vec(), None);
        Ok(())
    }
}

impl Storage for FileStore {
    type Error = io::Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, io::Error> {
        self.ensure_ready()?;
        let blob = match fs::read(self.path(key)) {
            Ok(blob) => blob,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        // Bind the logical storage key as associated data so a ciphertext written
        // for key K fails the auth tag if an at-rest attacker relocates it onto a
        // different key K''s file (record confusion / rollback across keys).
        let plaintext = self.decrypt(key, &blob)?;
        Ok(Some(plaintext))
    }

    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), io::Error> {
        self.ensure_ready()?;
        // `put_raw` binds the logical storage key as associated data (see `get`).
        self.put_raw(key, value)
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), io::Error> {
        self.ensure_ready()?;
        self.delete_raw(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "mycellium-store-test-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[cfg(unix)]
    #[test]
    fn dir_is_0700_and_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let mut store = FileStore::open(dir.clone(), [7u8; 32]).unwrap();
        store.put(b"k", b"v").unwrap();
        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        let file_mode = fs::metadata(store.path(b"k")).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "store dir should be 0700");
        assert_eq!(file_mode, 0o600, "store files should be 0600");
    }

    #[test]
    fn round_trips_encrypted() {
        let dir = temp_dir("rt");
        let mut store = FileStore::open(dir.clone(), [3u8; 32]).unwrap();

        assert_eq!(store.get(b"missing").unwrap(), None);
        store.put(b"k", b"secret value").unwrap();
        assert_eq!(
            store.get(b"k").unwrap().as_deref(),
            Some(&b"secret value"[..])
        );

        // The bytes on disk must not be the plaintext.
        let raw = fs::read(store.path(b"k")).unwrap();
        assert!(
            !raw.windows(6).any(|w| w == b"secret"),
            "value stored in the clear"
        );

        store.delete(b"k").unwrap();
        assert_eq!(store.get(b"k").unwrap(), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn transaction_commits_all_changes_and_drop_rolls_back() {
        let dir = temp_dir("transaction");
        let mut store = FileStore::open(dir.clone(), [4u8; 32]).unwrap();
        store.put(b"old", b"before").unwrap();

        {
            let mut tx = store.transaction();
            tx.put(b"new", b"value").unwrap();
            tx.delete(b"old").unwrap();
            assert_eq!(tx.get(b"new").unwrap().as_deref(), Some(&b"value"[..]));
            assert_eq!(tx.get(b"old").unwrap(), None);
        }
        assert_eq!(store.get(b"new").unwrap(), None);
        assert_eq!(store.get(b"old").unwrap().as_deref(), Some(&b"before"[..]));

        let mut tx = store.transaction();
        tx.put(b"new", b"value").unwrap();
        tx.delete(b"old").unwrap();
        tx.commit().unwrap();
        assert_eq!(store.get(b"new").unwrap().as_deref(), Some(&b"value"[..]));
        assert_eq!(store.get(b"old").unwrap(), None);
        assert!(!store.journal_path().exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_replays_a_durable_transaction_journal() {
        let dir = temp_dir("journal-recovery");
        {
            let mut store = FileStore::open(dir.clone(), [5u8; 32]).unwrap();
            store.put(b"old", b"before").unwrap();
            let mutations = vec![
                Mutation::Put(b"new".to_vec(), b"after".to_vec()),
                Mutation::Delete(b"old".to_vec()),
            ];
            let plaintext = mycellium_core::wire::encode(&mutations);
            let journal = store.encrypt(JOURNAL_AAD, &plaintext).unwrap();
            crate::atomic_write(&store.journal_path(), &journal).unwrap();
            assert!(store.get(b"old").is_err());
            // Simulate termination after the commit point but before applying
            // any data files: the next open must finish the committed unit.
        }

        let store = FileStore::open(dir.clone(), [5u8; 32]).unwrap();
        assert_eq!(store.get(b"new").unwrap().as_deref(), Some(&b"after"[..]));
        assert_eq!(store.get(b"old").unwrap(), None);
        assert!(!store.journal_path().exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn abrupt_exit_after_journal_helper() {
        let Some(dir) = std::env::var_os("MYCELLIUM_CRASH_TEST_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let mut store = FileStore::open(dir, [6u8; 32]).unwrap();
        store.put(b"old", b"before").unwrap();
        let mutations = vec![
            Mutation::Put(b"new".to_vec(), b"committed".to_vec()),
            Mutation::Delete(b"old".to_vec()),
        ];
        let plaintext = mycellium_core::wire::encode(&mutations);
        let journal = store.encrypt(JOURNAL_AAD, &plaintext).unwrap();
        crate::atomic_write(&store.journal_path(), &journal).unwrap();
        // No unwinding, Drop, or cleanup: model power loss immediately after
        // the durable write-ahead commit point.
        std::process::exit(91);
    }

    #[test]
    fn committed_transaction_survives_abrupt_process_exit() {
        let dir = temp_dir("process-crash-recovery");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("filestore::tests::abrupt_exit_after_journal_helper")
            .arg("--nocapture")
            .env("MYCELLIUM_CRASH_TEST_DIR", &dir)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(91));

        let store = FileStore::open(dir.clone(), [6u8; 32]).unwrap();
        assert_eq!(
            store.get(b"new").unwrap().as_deref(),
            Some(&b"committed"[..])
        );
        assert_eq!(store.get(b"old").unwrap(), None);
        assert!(!store.journal_path().exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn wrong_key_cannot_read() {
        let dir = temp_dir("wk");
        {
            let mut store = FileStore::open(dir.clone(), [1u8; 32]).unwrap();
            store.put(b"k", b"value").unwrap();
        }
        let other = FileStore::open(dir.clone(), [2u8; 32]).unwrap();
        assert!(other.get(b"k").is_err(), "a different key must not decrypt");
        let _ = fs::remove_dir_all(&dir);
    }

    /// At-rest tampering: an attacker with write access relocates a valid
    /// ciphertext from key `a`'s file onto key `b`'s path. Because the logical
    /// storage key is bound as AEAD associated data, the blob no longer
    /// authenticates under `b` and `get(b)` fails instead of returning `a`'s value
    /// (record confusion). Before the AAD fix this returned `v_a`.
    #[test]
    fn relocated_ciphertext_fails_auth() {
        let dir = temp_dir("confusion");
        let mut store = FileStore::open(dir.clone(), [9u8; 32]).unwrap();

        store.put(b"a", b"value-a").unwrap();
        store.put(b"b", b"value-b").unwrap();

        // Simulate the attack: overwrite b's file with a's ciphertext verbatim,
        // computing the filename exactly as the store does.
        let a_blob = fs::read(store.path(b"a")).unwrap();
        fs::write(store.path(b"b"), &a_blob).unwrap();

        // The relocated blob decrypts under the shared key, but its AAD (key `a`)
        // no longer matches the path's key (`b`), so authentication must fail.
        assert!(
            store.get(b"b").is_err(),
            "relocated ciphertext must not decrypt under a different key"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
