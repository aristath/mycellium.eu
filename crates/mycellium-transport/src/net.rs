//! A `Transport` implementation over plain TCP.
//!
//! It carries the app-layer end-to-end payload (fresh X3DH + one-shot AEAD), which
//! is what actually secures messages, so a bare TCP link is a genuine *direct*
//! line. libp2p is another direct transport behind this same trait.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

use mycellium_core::identity::PeerId;
use mycellium_core::transport::{Connection, Transport};

use crate::link::{frame_header, frame_len};

/// How long a dial may take before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a single read/write may block before erroring — bounds a peer that
/// connects then stalls mid-frame (it no longer pins the thread forever).
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Dial `addr` with a connect timeout, then apply read/write timeouts.
fn dial_timed(addr: &str) -> io::Result<TcpStream> {
    let sockaddr = addr
        .to_socket_addrs()?
        .find(|candidate| candidate.is_ipv6())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "could not resolve address"))?;
    let stream = TcpStream::connect_timeout(&sockaddr, CONNECT_TIMEOUT)?;
    set_timeouts(&stream)?;
    Ok(stream)
}

/// Apply read/write timeouts to a stream (dialed or accepted).
fn set_timeouts(stream: &TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(())
}

/// A framed connection over one TCP stream.
pub struct TcpConnection(TcpStream);

impl TcpConnection {
    /// Connect to `addr` (`host:port`) as a framed connection.
    pub fn connect(addr: &str) -> io::Result<TcpConnection> {
        Ok(TcpConnection(dial_timed(addr)?))
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
        self.0.write_all(&frame_header(bytes.len())?)?;
        self.0.write_all(bytes)?;
        self.0.flush()
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        let mut header = [0u8; 4];
        self.0.read_exact(&mut header)?;
        let n = frame_len(header)?;
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
        let sockaddr = addr
            .to_socket_addrs()?
            .find(|candidate| candidate.is_ipv6())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv4 is not a Mycellium transport address",
                )
            })?;
        Ok(TcpTransport {
            listener: Some(TcpListener::bind(sockaddr)?),
        })
    }
}

impl Transport for TcpTransport {
    type Conn = TcpConnection;
    type Error = io::Error;

    fn dial(&mut self, peer: &PeerId) -> io::Result<TcpConnection> {
        let addr = std::str::from_utf8(&peer.0).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "peer id is not an address")
        })?;
        Ok(TcpConnection(dial_timed(addr)?))
    }

    fn accept(&mut self) -> io::Result<TcpConnection> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "transport is dial-only"))?;
        let (stream, _peer) = listener.accept()?;
        set_timeouts(&stream)?;
        Ok(TcpConnection(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_times_out_on_a_stalled_peer() {
        let listener = TcpListener::bind("[::1]:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // A peer that sends a partial frame (length says 8, sends 2) then stalls.
        let peer = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(&8u32.to_be_bytes()).unwrap();
            s.write_all(&[1, 2]).unwrap();
            std::thread::sleep(Duration::from_secs(2));
        });
        let (stream, _) = listener.accept().unwrap();
        // Use a short read timeout so the test is fast (the real one is 30s).
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut conn = TcpConnection(stream);
        // recv reads the length, then blocks on the missing body bytes → times out
        // rather than pinning the thread forever.
        let err = conn.recv().unwrap_err();
        assert!(matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        let _ = peer.join();
    }
}
