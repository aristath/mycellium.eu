//! Secure storage for the account's root secret (issue #65).
//!
//! The device identity secret (`{wallet_secret, device_seed}`) is small,
//! long-lived, high-value key material: it *is* the account. Everything else —
//! the message history, learned names, config — lives in the encrypted
//! [`FileStore`](mycellium_storage::filestore::FileStore), which is keyed *from*
//! the identity and so cannot hold its own key. That root key has to live
//! somewhere, and where it lives is a platform decision.
//!
//! [`SecretStore`] is the seam. A platform app implements it over its OS keystore
//! — iOS/macOS Keychain, Android Keystore, Windows DPAPI/Credential Manager,
//! Linux Secret Service — and hands it to
//! [`MyceliumClient::new_with_secret_store`](crate::MyceliumClient::new_with_secret_store).
//! The SDK stores **only** the identity secret through it (and, later, push
//! tokens — #71), never the bulk store. See `docs/research/SECURE-STORAGE.md` for
//! the per-OS mapping and residual limits.
//!
//! Two honest Rust defaults ship for headless/dev/test use, since without an OS
//! keystore *or* a passphrase there is nothing to encrypt the root key *with*:
//!
//! - [`PassphraseFileSecretStore`] — a genuine at-rest improvement: seals each
//!   secret under an **Argon2id**-derived key with **ChaCha20-Poly1305**, the same
//!   construction the CLI uses ([`mycellium_storage::store`]). Fails **closed** on
//!   the wrong passphrase.
//! - [`PlaintextFileSecretStore`] — the historical `0600`-file behaviour,
//!   explicitly named and documented as **dev/fallback only**. Production apps
//!   MUST pass an OS-backed [`SecretStore`] instead (#65).

use std::path::{Path, PathBuf};

use mycellium_storage::seal::{self, SealError};

use crate::types::SdkError;

/// The at-rest secret store a platform app implements with its OS keystore.
///
/// The SDK persists the identity secret (and only that — small, high-value
/// material) through this seam; the app decides where it physically lives
/// (Keychain / Keystore / DPAPI / libsecret). Implementations MUST **fail closed**:
/// if a secret cannot be stored or a stored secret cannot be read back, return an
/// [`SdkError`] rather than silently losing or exposing key material. `load` of an
/// absent key returns `Ok(None)`; every other failure is an error.
#[uniffi::export(callback_interface)]
pub trait SecretStore: Send + Sync {
    /// Persist `secret` under `key`, replacing any existing value. Errors if it
    /// cannot be durably stored.
    fn store(&self, key: String, secret: Vec<u8>) -> Result<(), SdkError>;

    /// Load the secret stored under `key`, or `None` if there is none. Errors on a
    /// genuine read/decrypt failure (which callers treat as fatal, not as "absent").
    fn load(&self, key: String) -> Result<Option<Vec<u8>>, SdkError>;

    /// Remove the secret stored under `key` (a no-op if absent).
    fn delete(&self, key: String) -> Result<(), SdkError>;
}

/// Reject any key that isn't a single, safe filename component, so a key can never
/// escape the store directory. Keys are SDK-internal (`"identity"`, and later push
/// token ids), so this is a guard, not a general path sanitiser.
fn key_path(dir: &Path, key: &str) -> Result<PathBuf, SdkError> {
    if key.is_empty() || key == "." || key == ".." || key.contains(['/', '\\']) {
        return Err(SdkError::invalid("invalid secret key"));
    }
    Ok(dir.join(key))
}

/// Best-effort tighten a directory to owner-only (`0700`) on Unix; a no-op
/// elsewhere.
fn restrict_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Best-effort tighten a file to owner-only (`0600`) on Unix; a no-op elsewhere.
fn restrict_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// A passphrase-sealed file [`SecretStore`]: each secret is encrypted under an
/// **Argon2id**-derived key with **ChaCha20-Poly1305** and written to a file in
/// `dir` (one file per key). This mirrors the CLI's at-rest identity sealing
/// ([`mycellium_storage::store`]) and is a real at-rest improvement over a
/// plaintext file — suitable for headless/server deployments where no OS keystore
/// exists but a passphrase (or an operator-supplied secret) is available.
///
/// Losing the passphrase means losing this on-disk copy of the account key; the
/// account is then recovered by re-binding the handle from another device (email
/// verification, #6). A wrong passphrase **fails closed** with an [`SdkError`].
pub struct PassphraseFileSecretStore {
    dir: PathBuf,
    passphrase: String,
}

impl PassphraseFileSecretStore {
    /// Seal secrets under `passphrase`, in files under `dir` (created on first
    /// write).
    pub fn new(dir: impl Into<PathBuf>, passphrase: impl Into<String>) -> Self {
        Self {
            dir: dir.into(),
            passphrase: passphrase.into(),
        }
    }
}

impl SecretStore for PassphraseFileSecretStore {
    fn store(&self, key: String, secret: Vec<u8>) -> Result<(), SdkError> {
        let path = key_path(&self.dir, &key)?;
        std::fs::create_dir_all(&self.dir).map_err(SdkError::storage)?;
        restrict_dir(&self.dir);

        let sealed = seal::seal(&self.passphrase, &secret)
            .map_err(|e| SdkError::crypto(format!("failed to seal secret: {e}")))?;
        std::fs::write(&path, sealed).map_err(SdkError::storage)?;
        restrict_file(&path);
        Ok(())
    }

    fn load(&self, key: String) -> Result<Option<Vec<u8>>, SdkError> {
        let path = key_path(&self.dir, &key)?;
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(SdkError::storage(e)),
        };
        // Wrong passphrase (or tampering) fails the AEAD tag — fail closed.
        let plaintext = seal::open(&self.passphrase, &bytes).map_err(|e| match e {
            SealError::Corrupt => SdkError::crypto("secret file is corrupt"),
            SealError::WrongKeyOrCorrupt => SdkError::crypto("wrong passphrase or corrupt secret"),
            other => SdkError::crypto(other.to_string()),
        })?;
        Ok(Some(plaintext))
    }

    fn delete(&self, key: String) -> Result<(), SdkError> {
        let path = key_path(&self.dir, &key)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SdkError::storage(e)),
        }
    }
}

/// A plaintext file [`SecretStore`]: each secret is written **unencrypted** to a
/// file in `dir` (best-effort `0600` on Unix, one file per key).
///
/// **Dev / fallback only.** This is the SDK's historical behaviour and is exposed
/// as an explicit, opt-in choice so it is never a *silent* default. It provides no
/// at-rest confidentiality: anyone who can read the file reads the account key.
/// Production apps MUST pass an OS-backed [`SecretStore`] (Keychain / Keystore /
/// DPAPI / libsecret) — or, for headless use, [`PassphraseFileSecretStore`] —
/// instead (#65).
pub struct PlaintextFileSecretStore {
    dir: PathBuf,
}

impl PlaintextFileSecretStore {
    /// Store secrets as plaintext files under `dir` (created on first write).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

impl SecretStore for PlaintextFileSecretStore {
    fn store(&self, key: String, secret: Vec<u8>) -> Result<(), SdkError> {
        let path = key_path(&self.dir, &key)?;
        std::fs::create_dir_all(&self.dir).map_err(SdkError::storage)?;
        restrict_dir(&self.dir);
        std::fs::write(&path, &secret).map_err(SdkError::storage)?;
        restrict_file(&path);
        Ok(())
    }

    fn load(&self, key: String) -> Result<Option<Vec<u8>>, SdkError> {
        let path = key_path(&self.dir, &key)?;
        match std::fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(SdkError::storage(e)),
        }
    }

    fn delete(&self, key: String) -> Result<(), SdkError> {
        let path = key_path(&self.dir, &key)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(SdkError::storage(e)),
        }
    }
}
