//! The Mycellium engine: the headless peer logic that a front-end drives.
//!
//! It composes the core protocol with host-port adapters for transport and
//! storage, then owns the actual messaging behaviour: conversations and
//! history, local peer records, multi-device delivery, contacts, and blocking.
//! It carries no argument parsing and no terminal UI — those live in a shell
//! crate (e.g. `mycellium-cli`), so the same engine can back a GUI or mobile app.
//!
//! [`app`] holds the orchestration (the commands a shell invokes); the other
//! modules are the domain state it operates on, generic over
//! `mycellium_core::storage`.

// `app` (native orchestration) and `platform` (OS clock + RNG) pull in the
// filesystem, env, and P2P transport. They are gated behind the default
// `native` feature; the other modules are pure domain state, generic over
// `mycellium_core::storage`.
pub mod antirollback;
#[cfg(feature = "native")]
pub mod app;
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

/// Log a loud warning that persisted `what` is present but couldn't be decoded.
/// The single place the corruption policy is spelled out, so every store module
/// surfaces corruption identically instead of some silently swallowing it.
pub(crate) fn warn_corrupt(what: &str) {
    // stderr is a native-only reporting channel.
    #[cfg(not(target_arch = "wasm32"))]
    eprintln!("(warning: corrupt {what} in local storage — treated as empty; back up before it is overwritten)");
    let _ = what;
}

/// Decode stored bytes, distinguishing *absent* (→ default, silently) from
/// *present-but-corrupt* (→ default, but logged loudly). This keeps local-state
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
/// silently (no data), while a *present-but-corrupt* blob is `None` but logged
/// loudly — never a silent drop. Use for optional getters (`get(..) -> Option<T>`)
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
#[cfg(feature = "native")]
pub mod platform;
pub mod wireops;
