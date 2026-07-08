//! On-disk client config and account bootstrap — the `config.json` that a client
//! (CLI, desktop, …) stores next to its encrypted databases, plus the logic to
//! open the [`App`] engine from it. Shared so every client agrees on the format
//! and location and can open the *same* account.
//!
//! ```json
//! { "secret_key": "nsec1…", "account_key": "nsec1…"?, "relays": ["wss://…"] }
//! ```
//!
//! `secret_key` is this **device's** key (also the account key for a solo account);
//! `account_key` appears only once the account key has been rotated to a separate
//! key (a manager device). The file is written `0600` where the OS supports it.

use std::path::{Path, PathBuf};

use nostr::nips::nip19::ToBech32;
use nostr::{Keys, RelayUrl};
use serde::{Deserialize, Serialize};

use crate::App;

/// The relay a freshly created account uses when none is specified.
pub const DEFAULT_RELAY: &str = "wss://relay.damus.io";

/// A failure loading, saving, or opening a client config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("no config at {0}; create an account first")]
    Missing(PathBuf),
    #[error("config already exists at {0}; pass force to overwrite")]
    Exists(PathBuf),
    #[error("config i/o error: {0}")]
    Io(String),
    #[error("config is not valid json: {0}")]
    Parse(String),
    #[error("{0}")]
    Key(String),
    #[error("invalid relay url '{0}': {1}")]
    Relay(String, String),
    #[error("$HOME is not set; specify a data directory")]
    NoHome,
    #[error(transparent)]
    Engine(#[from] crate::Error),
}

/// The on-disk client config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// This **device's** secret key, bech32 (`nsec1…`) — also the account key when
    /// `account_key` is absent (a solo account). Never changes on a key rotation,
    /// so MLS/history stay intact.
    pub secret_key: String,
    /// The separate **account** identity key (`nsec1…`), present once rotated away
    /// from the device key (a manager account). Absent for a solo account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_key: Option<String>,
    /// Relay URLs this device connects to.
    pub relays: Vec<String>,
}

impl Config {
    /// A fresh solo account with a newly generated key.
    #[must_use]
    pub fn generate(relays: Vec<String>) -> Self {
        Self::from_device_key(&Keys::generate(), relays)
    }

    /// A solo account adopting an existing secret key (`nsec1…` or hex). Rejects a
    /// public `npub1…` — an identity needs its secret, which only its holder has.
    pub fn import(secret: &str, relays: Vec<String>) -> Result<Self, ConfigError> {
        if secret.trim().starts_with("npub1") {
            return Err(ConfigError::Key(
                "that is a public key (npub) — importing an identity needs its secret \
                 key (nsec1…), which only you hold; a public key cannot sign"
                    .to_string(),
            ));
        }
        let keys = Keys::parse(secret.trim()).map_err(|e| {
            ConfigError::Key(format!("invalid secret key (expected nsec1… or hex): {e}"))
        })?;
        Ok(Self::from_device_key(&keys, relays))
    }

    fn from_device_key(keys: &Keys, relays: Vec<String>) -> Self {
        let relays = if relays.is_empty() {
            vec![DEFAULT_RELAY.to_string()]
        } else {
            relays
        };
        Self {
            secret_key: keys
                .secret_key()
                .to_bech32()
                .expect("a secret key always bech32-encodes"),
            account_key: None,
            relays,
        }
    }

    /// This device's keypair.
    pub fn keys(&self) -> Result<Keys, ConfigError> {
        Keys::parse(&self.secret_key)
            .map_err(|e| ConfigError::Key(format!("stored device key is invalid: {e}")))
    }

    /// The account identity keypair — the rotated account key if present, else the
    /// device key (solo account).
    pub fn account_keys(&self) -> Result<Keys, ConfigError> {
        match &self.account_key {
            Some(ak) => Keys::parse(ak)
                .map_err(|e| ConfigError::Key(format!("stored account key is invalid: {e}"))),
            None => self.keys(),
        }
    }

    /// The relay URLs, parsed and validated.
    pub fn relay_urls(&self) -> Result<Vec<RelayUrl>, ConfigError> {
        self.relays
            .iter()
            .map(|r| RelayUrl::parse(r).map_err(|e| ConfigError::Relay(r.clone(), e.to_string())))
            .collect()
    }

    /// Whether this config is a manager account (holds a separate account key).
    #[must_use]
    pub fn is_manager(&self) -> bool {
        self.account_key.is_some()
    }

    /// The `config.json` path within `data_dir`.
    #[must_use]
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("config.json")
    }

    /// Whether a config exists in `data_dir`.
    #[must_use]
    pub fn exists(data_dir: &Path) -> bool {
        Self::path(data_dir).exists()
    }

    /// Load the config from `data_dir`.
    pub fn load(data_dir: &Path) -> Result<Self, ConfigError> {
        let path = Self::path(data_dir);
        let raw = std::fs::read_to_string(&path).map_err(|_| ConfigError::Missing(path))?;
        serde_json::from_str(&raw).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Persist the config to `data_dir` (`0600` where supported), creating the dir.
    pub fn save(&self, data_dir: &Path) -> Result<(), ConfigError> {
        std::fs::create_dir_all(data_dir).map_err(|e| ConfigError::Io(e.to_string()))?;
        let path = Self::path(data_dir);
        let json =
            serde_json::to_string_pretty(self).map_err(|e| ConfigError::Parse(e.to_string()))?;
        std::fs::write(&path, json).map_err(|e| ConfigError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Save only if no config exists yet (unless `force`).
    pub fn create(&self, data_dir: &Path, force: bool) -> Result<(), ConfigError> {
        let path = Self::path(data_dir);
        if path.exists() && !force {
            return Err(ConfigError::Exists(path));
        }
        self.save(data_dir)
    }

    /// Open the [`App`] engine from this config — a solo account, or a manager
    /// account once the account key has been rotated to a separate key.
    pub fn open(&self, data_dir: &Path) -> Result<App, ConfigError> {
        let device_keys = self.keys()?;
        let relays = self.relay_urls()?;
        let app = if self.is_manager() {
            App::open_manager(self.account_keys()?, device_keys, relays, data_dir)?
        } else {
            App::open_solo(device_keys, relays, data_dir)?
        };
        Ok(app)
    }
}

/// The default data directory: `$MYCELLIUM_DATA_DIR`, else `$HOME/.mycellium`.
pub fn default_data_dir() -> Result<PathBuf, ConfigError> {
    if let Ok(dir) = std::env::var("MYCELLIUM_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".mycellium"))
        .ok_or(ConfigError::NoHome)
}
