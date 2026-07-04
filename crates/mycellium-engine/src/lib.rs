//! The Mycellium engine: the headless peer logic that a front-end drives.
//!
//! It composes the core protocol with the host-port adapters (transport,
//! storage, directory-client) and owns the actual messaging behaviour:
//! conversations and history, groups, multi-device delivery, contacts, presence.
//! It carries no argument parsing and no terminal UI — those live in a shell
//! crate (e.g. `mycellium-cli`), so the same engine can back a GUI or mobile app.
//!
//! [`app`] holds the orchestration (the commands a shell invokes); the other
//! modules are the domain state it operates on, generic over
//! `mycellium_core::storage`.

// `app` (native orchestration) and `platform` (OS clock + RNG) pull in the
// filesystem, env, native HTTP clients, and the P2P transport — none of which
// exist on wasm32. They're gated behind the default `native` feature; the other
// modules are pure domain state, generic over `mycellium_core::storage`, and
// compile to wasm so the browser build can drive them.
#[cfg(feature = "native")]
pub mod app;
pub mod blocklist;
pub mod contacts;
pub mod draft;
pub mod expiry;
pub mod groups;
pub mod history;
pub mod names;
pub mod outbox;
#[cfg(feature = "native")]
pub mod platform;
