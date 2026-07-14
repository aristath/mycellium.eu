//! Transport-port adapters: concrete implementations of `mycellium_core`'s
//! `Transport`/`Connection` ports, plus the length-prefixed framing the app
//! layer rides on.
//!
//! - [`link`] — framing (`Wire`, `FrameReader`, `FrameWriter`) over any core
//!   `Connection`.
//! - `net` — an opt-in raw-TCP diagnostic adapter used only by the CLI.
//! - [`libp2p_net`] — the production direct QUIC transport plus the registry
//!   introduction control stream, behind the `libp2p` feature.
//!
//! A shell composes whichever adapters its platform supports at build time;
//! the engine above depends only on the core ports, never on these crates.

pub mod link;
#[cfg(feature = "legacy-tcp")]
pub mod net;

#[cfg(feature = "quic")]
pub mod libp2p_net;
