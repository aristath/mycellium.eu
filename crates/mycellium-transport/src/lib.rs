//! Transport-port adapters: concrete implementations of `mycellium_core`'s
//! `Transport`/`Connection` ports, plus the length-prefixed framing the app
//! layer rides on.
//!
//! - [`link`] — framing (`Wire`, `FrameReader`, `FrameWriter`) over any core
//!   `Connection`.
//! - [`net`] — a minimal framed TCP transport for local/direct operation.
//! - [`libp2p_net`] — the production transport over rust-libp2p (TCP + Noise +
//!   Yamux + a `/mycellium/1.0` stream protocol), behind the `libp2p` feature.
//!
//! A shell composes whichever adapters its platform supports at build time;
//! the engine above depends only on the core ports, never on these crates.

pub mod link;
pub mod net;

#[cfg(feature = "libp2p")]
pub mod libp2p_net;
