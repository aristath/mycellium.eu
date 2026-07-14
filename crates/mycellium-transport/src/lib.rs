//! Transport-port adapters: concrete implementations of `mycellium_core`'s
//! `Transport`/`Connection` ports, plus the length-prefixed framing the app
//! layer rides on.
//!
//! - [`link`] — framing (`Wire`, `FrameReader`, `FrameWriter`) over any core
//!   `Connection`.
//! - [`reticulum_net`] — the production Reticulum transport adapter.
//! - `net` — an opt-in raw-TCP diagnostic adapter.
//! - [`libp2p_net`] — optional legacy/DHT adapter code behind the `quic`/`dht`
//!   features.
//!
//! A shell composes whichever adapters its platform supports at build time;
//! the engine above depends only on the core ports, never on these crates.

pub mod link;
#[cfg(feature = "legacy-tcp")]
pub mod net;

#[cfg(feature = "reticulum")]
pub mod reticulum_net;

#[cfg(feature = "quic")]
pub mod libp2p_net;
