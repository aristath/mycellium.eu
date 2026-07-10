//! The Mycellium engine: the headless peer logic that a front-end drives.
//!
//! It owns platform-neutral messaging behaviour over core capabilities:
//! conversations and history, peer records, multi-device fan-out, contacts,
//! trust, and blocking.
//! It carries no argument parsing and no terminal UI — those live in a shell
//! crate (e.g. `mycellium-cli`), so the same engine can back a GUI or mobile app.
//!
//! Native command orchestration belongs to the shell crate; this crate exposes
//! domain state and structured [`flow::FlowEvent`] values.

use std::sync::{Mutex, OnceLock};

pub mod antirollback;
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

/// Decode stored bytes, distinguishing *absent* (→ default, silently) from
/// *present-but-corrupt* (→ default, with a structured diagnostic). This keeps local-state
/// corruption / partial writes / format-migration failures visible instead of
/// looking like messages/groups/contacts silently vanished. The raw bytes are
/// left in place until the next write, so a backup/export can still recover them.
pub(crate) fn decode_or_warn<T>(bytes: Option<Vec<u8>>, what: &str) -> T
where
    T: Default + serde::de::DeserializeOwned,
{
    match bytes {
        None => T::default(),
        Some(b) => mycellium_core::wire::decode(&b).unwrap_or_else(|_| {
            warn_corrupt(what);
            T::default()
        }),
    }
}

/// The single-value analogue of [`decode_or_warn`]: an *absent* key is `None`
/// silently (no data), while a *present-but-corrupt* blob is `None` with a
/// diagnostic — never a silent drop. Use for optional getters (`get(..) -> Option<T>`)
/// whose value type has no meaningful `Default`.
pub(crate) fn load_opt<T>(bytes: Option<Vec<u8>>, what: &str) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    let b = bytes?;
    match mycellium_core::wire::decode(&b) {
        Ok(v) => Some(v),
        Err(_) => {
            warn_corrupt(what);
            None
        }
    }
}
pub mod wireops;
