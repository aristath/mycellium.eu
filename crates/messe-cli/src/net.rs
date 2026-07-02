//! A `Transport` implementation over plain TCP — the POC's first transport.
//!
//! It carries the app-layer end-to-end payload (X3DH + Double Ratchet), which
//! is what actually secures messages, so a bare TCP link is a genuine *direct*
//! line for the POC. libp2p (NAT traversal, DHT, relay) is the production
//! Transport to swap in behind this same trait — see `docs/CONCEPT.md` Layer 10.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

use messe_core::identity::PeerId;
use messe_core::transport::{Connection, Transport};

/// Maximum accepted frame size (guards against absurd length prefixes).
const MAX_FRAME: usize = 1 << 20; // 1 MiB

/// A framed connection over one TCP stream.
pub struct TcpConnection(TcpStream);

impl TcpConnection {
    /// Connect to `addr` (`host:port`) as a framed connection.
    pub fn connect(addr: &str) -> io::Result<TcpConnection> {
        Ok(TcpConnection(TcpStream::connect(addr)?))
    }

    /// Split into independent read/write handles (a cloned socket), so a reader
    /// thread and the main thread can use the connection concurrently.
    pub fn split(self) -> io::Result<(TcpConnection, TcpConnection)> {
        let clone = self.0.try_clone()?;
        Ok((TcpConnection(self.0), TcpConnection(clone)))
    }
}

impl Connection for TcpConnection {
    type Error = io::Error;

    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.write_all(&(bytes.len() as u32).to_be_bytes())?;
        self.0.write_all(bytes)?;
        self.0.flush()
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        self.0.read_exact(&mut len)?;
        let n = u32::from_be_bytes(len) as usize;
        if n > MAX_FRAME {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
        }
        let mut buf = vec![0u8; n];
        self.0.read_exact(&mut buf)?;
        Ok(buf)
    }
}

/// A TCP transport: dials peers and (optionally) accepts inbound connections.
pub struct TcpTransport {
    listener: Option<TcpListener>,
}

impl TcpTransport {
    /// A dial-only transport (for the initiator).
    pub fn dialer() -> Self {
        TcpTransport { listener: None }
    }

    /// A transport bound to `addr`, able to accept inbound connections.
    pub fn listening(addr: &str) -> io::Result<Self> {
        Ok(TcpTransport {
            listener: Some(TcpListener::bind(addr)?),
        })
    }
}

impl Transport for TcpTransport {
    type Conn = TcpConnection;
    type Error = io::Error;

    fn dial(&mut self, peer: &PeerId) -> io::Result<TcpConnection> {
        let addr = std::str::from_utf8(&peer.0)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "peer id is not an address"))?;
        Ok(TcpConnection(TcpStream::connect(addr)?))
    }

    fn accept(&mut self) -> io::Result<TcpConnection> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "transport is dial-only"))?;
        let (stream, _peer) = listener.accept()?;
        Ok(TcpConnection(stream))
    }
}
