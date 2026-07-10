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

use std::fs;
use std::io;
use std::path::PathBuf;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

use mycellium_core::storage::Storage;

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
        Ok(FileStore { dir, key })
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
}

impl Storage for FileStore {
    type Error = io::Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, io::Error> {
        let blob = match fs::read(self.path(key)) {
            Ok(blob) => blob,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
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
        // Bind the logical storage key as associated data so a ciphertext written
        // for key K fails the auth tag if an at-rest attacker relocates it onto a
        // different key K''s file (record confusion / rollback across keys).
        let plaintext = ChaCha20Poly1305::new(&key_ga)
            .decrypt(
                &nonce_ga,
                Payload {
                    msg: ciphertext,
                    aad: key,
                },
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decryption failed"))?;
        Ok(Some(plaintext))
    }

    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<(), io::Error> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|_| io::Error::other("RNG failure"))?;
        let key_ga: Key = self.key.into();
        let nonce_ga: Nonce = nonce.into();
        // Bind the logical storage key as associated data (see `get`): the on-disk
        // filename is `hex(key)` but is not itself authenticated, so without this an
        // attacker with write access could swap one key's blob onto another's path.
        let ciphertext = ChaCha20Poly1305::new(&key_ga)
            .encrypt(
                &nonce_ga,
                Payload {
                    msg: value,
                    aad: key,
                },
            )
            .map_err(|_| io::Error::other("encryption failed"))?;

        let mut blob = Vec::with_capacity(12 + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        let p = self.path(key);
        crate::atomic_write(&p, &blob)
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), io::Error> {
        match fs::remove_file(self.path(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
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
