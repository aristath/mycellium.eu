//! The Mycellium engine: the headless peer logic that a front-end drives.
//!
//! It owns platform-neutral messaging behaviour over core capabilities:
//! conversations and history, peer records, active-device delivery, contacts,
//! trust, and blocking.
//! It carries no argument parsing and no terminal UI — those live in a shell
//! crate (e.g. `mycellium-cli`), so the same engine can back a GUI or mobile app.
//!
//! Native command orchestration belongs to the shell crate; this crate exposes
//! domain state and structured [`flow::FlowEvent`] values.

use std::sync::{Mutex, OnceLock};

pub mod antirollback;
pub mod attachments;
pub mod blocklist;
pub mod contacts;
pub mod draft;
pub mod expiry;
pub mod flow;
pub mod groups;
pub mod history;
pub mod inbox;
pub mod names;
pub mod outbox;
pub mod peerbook;
pub mod reachability;
pub mod verified;

/// A structured engine diagnostic for a host surface to render or record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineDiagnostic {
    /// Persisted bytes were present but could not be decoded. They remain in
    /// place until overwritten so a backup may still recover them.
    CorruptLocalState { what: String },
}

static DIAGNOSTICS: OnceLock<Mutex<Vec<EngineDiagnostic>>> = OnceLock::new();

/// Drain diagnostics accumulated since the previous call.
pub fn take_diagnostics() -> Vec<EngineDiagnostic> {
    let diagnostics = DIAGNOSTICS.get_or_init(|| Mutex::new(Vec::new()));
    diagnostics
        .lock()
        .map(|mut diagnostics| core::mem::take(&mut *diagnostics))
        .unwrap_or_default()
}

/// Record corrupt persisted state without coupling the engine to stderr.
pub(crate) fn warn_corrupt(what: &str) {
    if let Ok(mut diagnostics) = DIAGNOSTICS.get_or_init(|| Mutex::new(Vec::new())).lock() {
        diagnostics.push(EngineDiagnostic::CorruptLocalState {
            what: what.to_string(),
        });
    }
}

/// Decode collection-like stored state. An absent key is a valid empty/default
/// value; present-but-invalid bytes are reported and rejected so callers cannot
/// accidentally overwrite recoverable state with an empty collection.
pub(crate) fn decode_state<T>(bytes: Option<Vec<u8>>, what: &str) -> anyhow::Result<T>
where
    T: Default + serde::de::DeserializeOwned,
{
    match bytes {
        None => Ok(T::default()),
        Some(b) => mycellium_core::wire::decode(&b).map_err(|_| {
            warn_corrupt(what);
            anyhow::anyhow!("local {what} is corrupt")
        }),
    }
}

/// Decode optional stored state. Missing is `None`; corrupt is an error.
pub(crate) fn load_state<T>(bytes: Option<Vec<u8>>, what: &str) -> anyhow::Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    let Some(b) = bytes else {
        return Ok(None);
    };
    match mycellium_core::wire::decode(&b) {
        Ok(v) => Ok(Some(v)),
        Err(_) => {
            warn_corrupt(what);
            Err(anyhow::anyhow!("local {what} is corrupt"))
        }
    }
}
pub mod wireops;
