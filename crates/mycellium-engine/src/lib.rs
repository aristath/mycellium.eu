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

pub mod app;
pub mod blocklist;
pub mod contacts;
pub mod draft;
pub mod expiry;
pub mod groups;
pub mod history;
pub mod outbox;
pub mod platform;
