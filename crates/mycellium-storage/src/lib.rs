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
