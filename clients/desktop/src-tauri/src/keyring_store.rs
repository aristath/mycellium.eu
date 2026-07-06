//! The desktop `SecretStore` adapter (#65).
//!
//! The account's root identity secret is small, long-lived, high-value key
//! material — it *is* the account. The SDK holds it behind the
//! [`SecretStore`](mycellium_sdk::SecretStore) seam and lets the platform decide
//! where it physically lives. On desktop that place is the OS secret store,
//! reached uniformly through the cross-platform [`keyring`] crate:
//!
//! - **Linux** — the Secret Service (GNOME Keyring / KWallet via libsecret).
//! - **Windows** — the Windows Credential Manager (DPAPI-protected).
//! - **macOS** — the login Keychain.
//!
//! `SecretStore` is `#[uniffi::export(callback_interface)]`, but that only *adds*
//! a foreign-callback adapter — it stays an ordinary Rust trait, so a native Rust
//! type can `impl` it directly (the SDK's own `PlaintextFileSecretStore` /
//! `PassphraseFileSecretStore` do exactly this). `KeyringSecretStore` therefore
//! compiles as a first-class Rust `SecretStore`, no FFI involved.
//!
//! **Fail-closed** (per `docs/research/SECURE-STORAGE.md` §6): `load` returns
//! `None` *only* for a genuinely absent entry (`keyring::Error::NoEntry`); any
//! other keyring error (locked collection, backend unavailable, decode failure)
//! is surfaced as an [`SdkError`], so the SDK never mistakes an unreadable
//! identity for "no identity" and silently mints a fresh one.

use keyring::{Entry, Error as KeyringError};
use mycellium_sdk::{SdkError, SecretStore};

/// A [`SecretStore`] backed by the OS secret store via the `keyring` crate.
///
/// The keyring *service* name is **namespaced** (a base label plus a per-account
/// tag derived from the data dir) so two accounts on the same machine never
/// collide on the same `"identity"` key. Secrets are stored as raw bytes through
/// keyring's `set_secret`/`get_secret` byte API — no base64 round-trip needed.
pub struct KeyringSecretStore {
    /// The namespaced keyring service (collection) these entries live under.
    service: String,
}

impl KeyringSecretStore {
    /// Build a store under `base` service, namespaced by `namespace` (e.g. the
    /// account's data directory) so multiple accounts on one machine don't clash.
    pub fn new(base: impl AsRef<str>, namespace: impl AsRef<str>) -> Self {
        let tag = sanitize(namespace.as_ref());
        Self {
            service: format!("{}::{}", base.as_ref(), tag),
        }
    }

    /// A keyring entry for `key` within this store's namespaced service.
    fn entry(&self, key: &str) -> Result<Entry, SdkError> {
        Entry::new(&self.service, key).map_err(|e| SdkError::Storage {
            msg: format!("keyring: cannot open entry: {e}"),
        })
    }
}

impl SecretStore for KeyringSecretStore {
    fn store(&self, key: String, secret: Vec<u8>) -> Result<(), SdkError> {
        self.entry(&key)?
            .set_secret(&secret)
            .map_err(|e| SdkError::Storage {
                msg: format!("keyring: cannot store secret: {e}"),
            })
    }

    fn load(&self, key: String) -> Result<Option<Vec<u8>>, SdkError> {
        match self.entry(&key)?.get_secret() {
            Ok(bytes) => Ok(Some(bytes)),
            // A genuinely absent entry is the only "None" — everything else fails closed.
            Err(KeyringError::NoEntry) => Ok(None),
            Err(e) => Err(SdkError::Storage {
                msg: format!("keyring: cannot load secret: {e}"),
            }),
        }
    }

    fn delete(&self, key: String) -> Result<(), SdkError> {
        match self.entry(&key)?.delete_credential() {
            Ok(()) => Ok(()),
            Err(KeyringError::NoEntry) => Ok(()),
            Err(e) => Err(SdkError::Storage {
                msg: format!("keyring: cannot delete secret: {e}"),
            }),
        }
    }
}

/// Reduce an arbitrary namespace (a filesystem path) to a compact, keyring-safe
/// tag: keep alphanumerics, collapse everything else to `-`.
fn sanitize(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    // Trim leading/trailing separators for tidiness.
    let trimmed = out.trim_matches('-').to_string();
    out = if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed
    };
    out
}
