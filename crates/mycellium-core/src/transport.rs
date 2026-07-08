//! The **Transport** capability: opening a direct line to a peer.
//!
//! The core never speaks a wire protocol itself. On rich devices the host
//! implements this with rust-libp2p or direct TCP; on constrained devices with a
//! minimal Noise-over-TCP/UDP. Either way the core only sees "give me a
//! byte-stream connection to this peer".
//!
//! These traits are deliberately synchronous and buffer-oriented so they fit a
//! `no_std` core. A `Full`-tier host wraps its async stack behind them; that
//! adaptation lives in the shell, not here.

use alloc::vec::Vec;

use crate::identity::PeerId;

/// A bidirectional, already-secured, message-framed channel to one peer.
pub trait Connection {
    /// Host-specific transport error.
    type Error;

    /// Send one framed message. Implementations deliver it whole or fail.
    fn send(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Receive the next whole framed message.
    fn recv(&mut self) -> Result<Vec<u8>, Self::Error>;
}

/// Opens connections to peers and accepts incoming ones.
pub trait Transport {
    /// The connection type this transport yields.
    type Conn: Connection;
    /// Host-specific transport error.
    type Error;

    /// Dial `peer`, resolving its current addresses and opening a direct,
    /// secured connection.
    fn dial(&mut self, peer: &PeerId) -> Result<Self::Conn, Self::Error>;

    /// Block until an inbound connection arrives, then return it.
    fn accept(&mut self) -> Result<Self::Conn, Self::Error>;
}
