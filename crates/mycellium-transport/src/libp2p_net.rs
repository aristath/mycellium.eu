//! A libp2p-based transport: the production "direct line" (Layers 7, 10).
//!
//! TCP + Noise + Yamux, with the node's PeerId derived from the **device key**
//! (Layer 8.1), and a `/mycellium/1.0` byte-stream protocol carrying the same
//! app-layer E2E payload. The async libp2p swarm runs on a background Tokio
//! runtime; a small blocking bridge exposes it through the core's synchronous
//! `Connection` trait.
//!
//! NAT traversal (DHT, relay, DCUtR) is the next increment — the swarm is the
//! place to add it, with no change to the app above.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder};
use libp2p_stream as stream;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use mycellium_core::transport::Connection;

const PROTOCOL: StreamProtocol = StreamProtocol::new("/mycellium/1.0");
const MAX_FRAME: usize = 1 << 20;

/// A running libp2p node: owns the runtime and the swarm-driving task.
pub struct Libp2pNode {
    rt: Runtime,
    control: stream::Control,
    incoming: stream::IncomingStreams,
    dial_tx: mpsc::UnboundedSender<Multiaddr>,
    peer_id: PeerId,
}

impl Libp2pNode {
    /// Build a node from the device key, optionally listening on `listen_addr`.
    pub fn new(device_secret: [u8; 32], listen_addr: Option<Multiaddr>) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let mut secret = device_secret;
        let keypair = identity::Keypair::ed25519_from_bytes(&mut secret)
            .map_err(|e| anyhow!("bad device key: {e}"))?;
        let peer_id = keypair.public().to_peer_id();

        let (dial_tx, mut dial_rx) = mpsc::unbounded_channel::<Multiaddr>();

        let (control, incoming) = rt.block_on(async {
            let mut swarm = SwarmBuilder::with_existing_identity(keypair)
                .with_tokio()
                .with_tcp(
                    tcp::Config::default(),
                    noise::Config::new,
                    yamux::Config::default,
                )
                .map_err(|e| anyhow!("tcp/noise setup: {e}"))?
                .with_behaviour(|_| stream::Behaviour::new())
                .map_err(|e| anyhow!("behaviour setup: {e}"))?
                .build();

            let mut control = swarm.behaviour().new_control();
            let incoming = control
                .accept(PROTOCOL)
                .map_err(|e| anyhow!("accept protocol: {e}"))?;

            if let Some(addr) = listen_addr {
                swarm.listen_on(addr).map_err(|e| anyhow!("listen: {e}"))?;
            }

            // Drive the swarm forever; handle dial commands from the bridge.
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        event = swarm.select_next_some() => {
                            if let SwarmEvent::OutgoingConnectionError { error, .. } = event {
                                eprintln!("(libp2p dial error: {error})");
                            }
                        }
                        Some(addr) = dial_rx.recv() => {
                            let _ = swarm.dial(addr);
                        }
                    }
                }
            });

            Ok::<_, anyhow::Error>((control, incoming))
        })?;

        Ok(Libp2pNode {
            rt,
            control,
            incoming,
            dial_tx,
            peer_id,
        })
    }

    /// This node's PeerId (derived from the device key).
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Dial a peer given its multiaddr as a string.
    pub fn dial_str(&mut self, target: &str) -> Result<Libp2pConnection> {
        let addr: Multiaddr = target
            .parse()
            .map_err(|_| anyhow!("'{target}' is not a valid multiaddr"))?;
        self.dial(&addr)
    }

    /// Dial a peer given its full multiaddr (must include `/p2p/<peer-id>`).
    pub fn dial(&mut self, target: &Multiaddr) -> Result<Libp2pConnection> {
        let peer = peer_from_multiaddr(target)
            .ok_or_else(|| anyhow!("multiaddr is missing a /p2p/<peer-id> component"))?;
        self.dial_tx.send(target.clone()).ok();

        let mut control = self.control.clone();
        let stream = self.rt.block_on(async move {
            // The dial is asynchronous; retry opening the stream until the
            // connection is up (or give up after a few seconds).
            for _ in 0..100 {
                match control.open_stream(peer, PROTOCOL).await {
                    Ok(stream) => return Ok(stream),
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
            Err(anyhow!("could not open a stream to {peer}"))
        })?;

        Ok(Libp2pConnection {
            handle: self.rt.handle().clone(),
            stream,
        })
    }

    /// Wait for an inbound `/mycellium/1.0` stream and return it as a connection.
    pub fn accept(&mut self) -> Result<Libp2pConnection> {
        let next = self.rt.block_on(self.incoming.next());
        let (_peer, stream) = next.ok_or_else(|| anyhow!("stream listener closed"))?;
        Ok(Libp2pConnection {
            handle: self.rt.handle().clone(),
            stream,
        })
    }

    /// Let the background swarm run for `millis` so buffered stream data is
    /// actually transmitted before the node (and its runtime) is dropped.
    pub fn drain(&self, millis: u64) {
        self.rt
            .block_on(async move { tokio::time::sleep(Duration::from_millis(millis)).await });
    }
}

/// A framed connection over one libp2p stream.
pub struct Libp2pConnection {
    handle: tokio::runtime::Handle,
    stream: libp2p::swarm::Stream,
}

impl Libp2pConnection {
    /// Split into independent read/write halves for full-duplex chat. Both
    /// halves drive the same background runtime; yamux allows concurrent I/O.
    pub fn split(self) -> (Libp2pReadHalf, Libp2pWriteHalf) {
        let (read, write) = self.stream.split();
        (
            Libp2pReadHalf {
                handle: self.handle.clone(),
                read,
            },
            Libp2pWriteHalf {
                handle: self.handle,
                write,
            },
        )
    }
}

/// The read half of a libp2p stream.
pub struct Libp2pReadHalf {
    handle: tokio::runtime::Handle,
    read: futures::io::ReadHalf<libp2p::swarm::Stream>,
}

/// The write half of a libp2p stream.
pub struct Libp2pWriteHalf {
    handle: tokio::runtime::Handle,
    write: futures::io::WriteHalf<libp2p::swarm::Stream>,
}

impl crate::link::FrameReader for Libp2pReadHalf {
    fn recv_frame(&mut self) -> anyhow::Result<Vec<u8>> {
        let read = &mut self.read;
        let bytes = self.handle.block_on(async move {
            let mut len = [0u8; 4];
            read.read_exact(&mut len).await?;
            let n = u32::from_be_bytes(len) as usize;
            if n > MAX_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame too large",
                ));
            }
            let mut buf = vec![0u8; n];
            read.read_exact(&mut buf).await?;
            Ok::<_, io::Error>(buf)
        })?;
        Ok(bytes)
    }
}

impl crate::link::FrameWriter for Libp2pWriteHalf {
    fn send_frame(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let write = &mut self.write;
        self.handle.block_on(async move {
            write.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
            write.write_all(bytes).await?;
            write.flush().await
        })?;
        Ok(())
    }
}

impl Connection for Libp2pConnection {
    type Error = io::Error;

    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        let stream = &mut self.stream;
        self.handle.block_on(async move {
            stream
                .write_all(&(bytes.len() as u32).to_be_bytes())
                .await?;
            stream.write_all(bytes).await?;
            stream.flush().await
        })
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        let stream = &mut self.stream;
        self.handle.block_on(async move {
            let mut len = [0u8; 4];
            stream.read_exact(&mut len).await?;
            let n = u32::from_be_bytes(len) as usize;
            if n > MAX_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame too large",
                ));
            }
            let mut buf = vec![0u8; n];
            stream.read_exact(&mut buf).await?;
            Ok(buf)
        })
    }
}

/// The libp2p PeerId string for a device key (without starting a node).
pub fn peer_id_string(device_secret: [u8; 32]) -> Result<String> {
    let mut secret = device_secret;
    let keypair = identity::Keypair::ed25519_from_bytes(&mut secret)
        .map_err(|e| anyhow!("bad device key: {e}"))?;
    Ok(keypair.public().to_peer_id().to_string())
}

/// A listen multiaddr (`/ip4/…/tcp/…`) from a `host:port` string.
pub fn listen_multiaddr(addr: &str) -> Result<Multiaddr> {
    let socket: SocketAddr = addr
        .parse()
        .map_err(|_| anyhow!("address must be host:port, e.g. 127.0.0.1:9001"))?;
    Ok(socket_to_multiaddr(socket))
}

/// The dialable multiaddr to publish: `/ip4/…/tcp/…/p2p/<peer-id>`.
pub fn advertised_multiaddr(addr: &str, device_secret: [u8; 32]) -> Result<String> {
    let base = listen_multiaddr(addr)?;
    let peer = peer_id_string(device_secret)?;
    Ok(format!("{base}/p2p/{peer}"))
}

fn socket_to_multiaddr(socket: SocketAddr) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    match socket.ip() {
        IpAddr::V4(ip) => addr.push(Protocol::Ip4(ip)),
        IpAddr::V6(ip) => addr.push(Protocol::Ip6(ip)),
    }
    addr.push(Protocol::Tcp(socket.port()));
    addr
}

/// Extract the PeerId from the `/p2p/...` component of a multiaddr.
fn peer_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listen_addr(port: u16) -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
    }

    #[test]
    fn two_nodes_stream_a_message() {
        // Bob listens; Alice dials Bob's PeerId and sends a framed message.
        let mut bob = Libp2pNode::new([7u8; 32], Some(listen_addr(41001))).unwrap();
        let bob_peer = bob.peer_id();

        let bob_thread = std::thread::spawn(move || {
            let mut conn = bob.accept().unwrap();
            conn.recv().unwrap()
        });

        let mut alice = Libp2pNode::new([9u8; 32], None).unwrap();
        let dial: Multiaddr = format!("/ip4/127.0.0.1/tcp/41001/p2p/{bob_peer}")
            .parse()
            .unwrap();
        let mut conn = alice.dial(&dial).unwrap();
        conn.send(b"hello over libp2p").unwrap();

        let received = bob_thread.join().unwrap();
        assert_eq!(received, b"hello over libp2p");
    }
}
