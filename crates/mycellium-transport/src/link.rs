//! A transport-agnostic message channel, so the chat/handshake logic doesn't
//! care whether it's running over raw TCP or libp2p.
//!
//! Any core [`Connection`] whose error is `io::Error` (both our transports)
//! becomes a [`Wire`] for free.

use std::io;

use anyhow::Result;

use mycellium_core::transport::Connection;

/// Maximum accepted frame body size — the single definition every framed
/// transport shares (guards against an absurd length prefix). 1 MiB.
pub const MAX_FRAME: usize = 1 << 20;

/// The 4-byte big-endian length prefix for a frame body of `len` bytes. The
/// build half of the length-prefix codec, shared by the sync (`net`) and async
/// (`libp2p_net`) writers.
pub fn frame_header(len: usize) -> [u8; 4] {
    (len as u32).to_be_bytes()
}

/// Parse a 4-byte big-endian length prefix into a body length, rejecting
/// anything over [`MAX_FRAME`] **before** the caller allocates a buffer (the DoS
/// guard). The parse half of the codec — pure and IO-error-agnostic, so every
/// reader (`std::io` or `futures::io`) shares it and maps the `io::Error` as it
/// sees fit.
pub fn frame_len(header: [u8; 4]) -> io::Result<usize> {
    let n = u32::from_be_bytes(header) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    Ok(n)
}

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
