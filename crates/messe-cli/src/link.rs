//! A transport-agnostic message channel, so the chat/handshake logic doesn't
//! care whether it's running over raw TCP or libp2p.
//!
//! Any core [`Connection`] whose error is `io::Error` (both our transports)
//! becomes a [`Wire`] for free.

use anyhow::Result;

use messe_core::transport::Connection;

/// A framed, send/receive channel to a peer.
pub trait Wire {
    /// Send one framed message.
    fn send(&mut self, bytes: &[u8]) -> Result<()>;
    /// Receive the next framed message.
    fn recv(&mut self) -> Result<Vec<u8>>;
}

impl<C: Connection<Error = std::io::Error>> Wire for C {
    fn send(&mut self, bytes: &[u8]) -> Result<()> {
        Connection::send(self, bytes)?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Vec<u8>> {
        Ok(Connection::recv(self)?)
    }
}

/// The read half of a connection, for full-duplex chat (runs on its own thread).
pub trait FrameReader: Send {
    /// Receive the next framed message.
    fn recv_frame(&mut self) -> Result<Vec<u8>>;
}

/// The write half of a connection, for full-duplex chat.
pub trait FrameWriter: Send {
    /// Send one framed message.
    fn send_frame(&mut self, bytes: &[u8]) -> Result<()>;
}

// A TCP connection (a cloned socket handle) is both a reader and a writer.
impl<C: Connection<Error = std::io::Error> + Send> FrameReader for C {
    fn recv_frame(&mut self) -> Result<Vec<u8>> {
        Ok(Connection::recv(self)?)
    }
}

impl<C: Connection<Error = std::io::Error> + Send> FrameWriter for C {
    fn send_frame(&mut self, bytes: &[u8]) -> Result<()> {
        Connection::send(self, bytes)?;
        Ok(())
    }
}
