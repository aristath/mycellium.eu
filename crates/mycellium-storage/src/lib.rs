//! Storage-port adapters: the durable local state a peer keeps on a rich host.
//!
//! - [`filestore`] — an encrypted, file-backed key-value store implementing
//!   `mycellium_core::storage::Storage` (the engine's transcripts, groups,
//!   contacts, etc. ride on it), keyed from the identity via HKDF.
//! - [`store`] — the identity at rest: the wallet secret + this device's seed,
//!   sealed with Argon2id + ChaCha20-Poly1305 under a user passphrase.
//!
//! A different platform (web, embedded) swaps this crate for its own Storage
//! adapter; the engine depends only on the core `Storage` port.

pub mod filestore;
pub mod seal;
pub mod store;

use std::io::{self, Write};
use std::path::Path;

/// Create a directory and apply the platform's restrictive private-data mode.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    perms::restrict_dir(path);
    Ok(())
}

/// Durably replace one file: restrictive temp creation, full write, file sync,
/// atomic rename, then parent-directory sync.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    create_private_dir(parent)?;

    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce).map_err(|_| io::Error::other("RNG failure"))?;
    let suffix = u64::from_le_bytes(nonce);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid file name"))?;
    let temp = parent.join(format!(".{name}.{suffix:016x}.tmp"));

    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        perms::restrict_file(&temp);
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        perms::restrict_file(path);
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Best-effort restrictive permissions for local storage. On Unix, directories
/// become `0700` and files `0600`; a no-op on platforms without Unix modes.
pub(crate) mod perms {
    use std::path::Path;

    #[cfg(unix)]
    fn set(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }

    #[cfg(unix)]
    pub fn restrict_dir(path: &Path) {
        set(path, 0o700);
    }
    #[cfg(unix)]
    pub fn restrict_file(path: &Path) {
        set(path, 0o600);
    }
    #[cfg(not(unix))]
    pub fn restrict_dir(_path: &Path) {}
    #[cfg(not(unix))]
    pub fn restrict_file(_path: &Path) {}
}
