//! A libp2p-based transport: the production "direct line" (Layers 7, 10).
//!
//! TCP + Noise + Yamux, with the node's PeerId derived from the **device key**
//! (Layer 8.1), and a `/mycellium/1.0` byte-stream protocol carrying the same
//! app-layer E2E payload. The async libp2p swarm runs on a background Tokio
//! runtime; a small blocking bridge exposes it through the core's synchronous
//! `Connection` trait.
//!
//! NAT traversal builds on this: **Circuit Relay v2** (#59) is wired in here —
//! a node can act as a relay for others, obtain a reservation on a public relay,
//! and be reached (or dial) over a `…/p2p-circuit/…` address — all with no
//! change to the app above. DHT/DCUtR are the next increment.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identity, noise, relay, tcp, yamux, Multiaddr, PeerId, StreamProtocol, SwarmBuilder};
use libp2p_stream as stream;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use mycellium_core::transport::Connection;

const PROTOCOL: StreamProtocol = StreamProtocol::new("/mycellium/1.0");

/// How long `reserve`/`listen_addr` wait for the swarm to make progress.
const RESERVE_TIMEOUT: Duration = Duration::from_secs(20);

/// The composite network behaviour driving this node:
/// - `stream`: the `/mycellium/1.0` byte-stream protocol (unchanged app path).
/// - `relay`: lets this node ACT AS a Circuit Relay v2 relay, forwarding
///   traffic for peers that reserve a slot on it.
/// - `relay_client`: lets this node be reached VIA a relay (reservations) and
///   dial peers over `…/p2p-circuit/…` addresses.
#[derive(NetworkBehaviour)]
struct Behaviour {
    stream: stream::Behaviour,
    relay: relay::Behaviour,
    relay_client: relay::client::Behaviour,
}

/// Commands the blocking bridge sends to the background swarm task.
enum Command {
    Dial(Multiaddr),
    Listen(Multiaddr),
}

/// Swarm events the background task surfaces back to the blocking bridge.
enum NodeEvent {
    /// A concrete address this node now listens on (direct or a `p2p-circuit`).
    NewListenAddr(Multiaddr),
    /// A relay accepted our Circuit Relay v2 reservation.
    ReservationAccepted,
}

/// A running libp2p node: owns the runtime and the swarm-driving task.
pub struct Libp2pNode {
    rt: Runtime,
    control: stream::Control,
    incoming: stream::IncomingStreams,
    cmd_tx: mpsc::UnboundedSender<Command>,
    event_rx: mpsc::UnboundedReceiver<NodeEvent>,
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

        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Command>();
        let (event_tx, event_rx) = mpsc::unbounded_channel::<NodeEvent>();

        let (control, incoming) = rt.block_on(async {
            let mut swarm = SwarmBuilder::with_existing_identity(keypair)
                .with_tokio()
                .with_tcp(
                    tcp::Config::default(),
                    noise::Config::new,
                    yamux::Config::default,
                )
                .map_err(|e| anyhow!("tcp/noise setup: {e}"))?
                .with_relay_client(noise::Config::new, yamux::Config::default)
                .map_err(|e| anyhow!("relay-client setup: {e}"))?
                .with_behaviour(|key, relay_client| Behaviour {
                    stream: stream::Behaviour::new(),
                    relay: relay::Behaviour::new(key.public().to_peer_id(), Default::default()),
                    relay_client,
                })
                .map_err(|e| anyhow!("behaviour setup: {e}"))?
                .build();

            let mut control = swarm.behaviour().stream.new_control();
            let incoming = control
                .accept(PROTOCOL)
                .map_err(|e| anyhow!("accept protocol: {e}"))?;

            if let Some(addr) = listen_addr {
                swarm.listen_on(addr).map_err(|e| anyhow!("listen: {e}"))?;
            }

            // Drive the swarm forever; handle commands from the bridge and
            // surface the few events the bridge cares about. Relay + relay-client
            // events are handled here (reservation accepted) or ignored; the
            // stream/`accept` path is unchanged.
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        event = swarm.select_next_some() => match event {
                            SwarmEvent::OutgoingConnectionError { error, .. } => {
                                eprintln!("(libp2p dial error: {error})");
                            }
                            SwarmEvent::NewListenAddr { address, .. } => {
                                // A direct (non-circuit) listen address is one this
                                // node can be reached at, so advertise it as an
                                // external address. This is what lets the relay
                                // server hand it out in reservations it grants
                                // (otherwise the client rejects the reservation
                                // with `NoAddressesInReservation`).
                                if !address.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                                    swarm.add_external_address(address.clone());
                                }
                                let _ = event_tx.send(NodeEvent::NewListenAddr(address));
                            }
                            SwarmEvent::Behaviour(BehaviourEvent::RelayClient(
                                relay::client::Event::ReservationReqAccepted { .. },
                            )) => {
                                let _ = event_tx.send(NodeEvent::ReservationAccepted);
                            }
                            _ => {}
                        },
                        Some(cmd) = cmd_rx.recv() => match cmd {
                            Command::Dial(addr) => { let _ = swarm.dial(addr); }
                            Command::Listen(addr) => { let _ = swarm.listen_on(addr); }
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
            cmd_tx,
            event_rx,
            peer_id,
        })
    }

    /// Block until this node reports a concrete listen address (the OS-assigned
    /// `/ip4/…/tcp/<port>` after a `tcp/0` bind), or time out.
    pub fn listen_addr(&mut self) -> Result<Multiaddr> {
        let handle = self.rt.handle().clone();
        let event_rx = &mut self.event_rx;
        handle.block_on(async {
            let start = Instant::now();
            loop {
                let remaining = RESERVE_TIMEOUT
                    .checked_sub(start.elapsed())
                    .ok_or_else(|| anyhow!("timed out waiting for a listen address"))?;
                match tokio::time::timeout(remaining, event_rx.recv()).await {
                    Ok(Some(NodeEvent::NewListenAddr(addr))) => return Ok(addr),
                    Ok(Some(_)) => continue,
                    Ok(None) => return Err(anyhow!("swarm event channel closed")),
                    Err(_) => return Err(anyhow!("timed out waiting for a listen address")),
                }
            }
        })
    }

    /// Obtain a Circuit Relay v2 reservation on `relay_addr` (which must include
    /// the relay's `/p2p/<relay-peer-id>`), so this node becomes reachable
    /// *through* that relay. Returns this node's dialable circuit address:
    /// `<relay_addr>/p2p-circuit/p2p/<self-peer-id>`.
    pub fn reserve(&mut self, relay_addr: &Multiaddr) -> Result<Multiaddr> {
        let listen = relay_addr.clone().with(Protocol::P2pCircuit);
        self.cmd_tx
            .send(Command::Listen(listen))
            .map_err(|_| anyhow!("swarm task is gone"))?;

        let handle = self.rt.handle().clone();
        let event_rx = &mut self.event_rx;
        handle.block_on(async {
            let start = Instant::now();
            loop {
                let remaining = RESERVE_TIMEOUT
                    .checked_sub(start.elapsed())
                    .ok_or_else(|| anyhow!("timed out waiting for a relay reservation"))?;
                match tokio::time::timeout(remaining, event_rx.recv()).await {
                    Ok(Some(NodeEvent::ReservationAccepted)) => return Ok::<_, anyhow::Error>(()),
                    Ok(Some(_)) => continue,
                    Ok(None) => return Err(anyhow!("swarm event channel closed")),
                    Err(_) => return Err(anyhow!("timed out waiting for a relay reservation")),
                }
            }
        })?;

        Ok(relay_addr
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(self.peer_id)))
    }

    /// Like [`Self::reserve`], but takes the relay address as a string and returns
    /// this node's dialable circuit address as a string — so callers (the engine)
    /// need no `Multiaddr` type in scope, mirroring [`Self::dial_str`].
    pub fn reserve_str(&mut self, relay_addr: &str) -> Result<String> {
        let addr: Multiaddr = relay_addr
            .parse()
            .map_err(|_| anyhow!("'{relay_addr}' is not a valid multiaddr"))?;
        Ok(self.reserve(&addr)?.to_string())
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
        self.cmd_tx.send(Command::Dial(target.clone())).ok();

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
            let mut header = [0u8; 4];
            read.read_exact(&mut header).await?;
            let n = crate::link::frame_len(header)?;
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
            write
                .write_all(&crate::link::frame_header(bytes.len()))
                .await?;
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
                .write_all(&crate::link::frame_header(bytes.len()))
                .await?;
            stream.write_all(bytes).await?;
            stream.flush().await
        })
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        let stream = &mut self.stream;
        self.handle.block_on(async move {
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).await?;
            let n = crate::link::frame_len(header)?;
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

/// Extract the target PeerId from a multiaddr. For a direct address there is a
/// single `/p2p/<peer>`; for a relayed `…/p2p/<relay>/p2p-circuit/p2p/<target>`
/// the *last* `/p2p/` is the destination (the earlier one is the relay), so we
/// take the last one — correct in both cases.
fn peer_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().fold(None, |acc, p| match p {
        Protocol::P2p(peer) => Some(peer),
        _ => acc,
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

    /// Circuit Relay v2 loopback (#59): a recipient with **no direct address**
    /// is reached purely through a public relay.
    ///
    /// Non-vacuity: B never listens on a direct transport address (created with
    /// `None`), so the *only* way A can reach it is the `/p2p-circuit/` path. A
    /// is handed B's circuit address and nothing else — it has no way to learn a
    /// direct route to B — so a delivered frame proves it travelled through R.
    #[test]
    fn relayed_frame_delivery_over_circuit() {
        use crate::link::{FrameReader, FrameWriter};

        // Relay R: a public node that will forward for others.
        let mut relay = Libp2pNode::new([1u8; 32], Some(listen_addr(0))).unwrap();
        let relay_peer = relay.peer_id();
        let relay_addr = relay.listen_addr().unwrap().with(Protocol::P2p(relay_peer));

        // Recipient B: NO direct listen address — reachable only via the relay.
        let mut bob = Libp2pNode::new([2u8; 32], None).unwrap();
        let bob_circuit = bob.reserve(&relay_addr).unwrap();

        // The address A will use is genuinely a relayed one, targeting B.
        assert!(
            bob_circuit
                .iter()
                .any(|p| matches!(p, Protocol::P2pCircuit)),
            "recipient's address must be a p2p-circuit address: {bob_circuit}"
        );
        assert_eq!(
            peer_from_multiaddr(&bob_circuit),
            Some(bob.peer_id()),
            "circuit address must target B (not the relay)"
        );

        // B waits for the inbound relayed stream and reads one frame.
        let bob_thread = std::thread::spawn(move || {
            let conn = bob.accept().unwrap();
            let (mut reader, _writer) = conn.split();
            let frame = reader.recv_frame().unwrap();
            // Keep B alive briefly so the ack/teardown is orderly.
            bob.drain(100);
            frame
        });

        // Sender A: knows only B's circuit address; dials through the relay.
        let mut alice = Libp2pNode::new([3u8; 32], None).unwrap();
        let conn = alice
            .dial_str(&bob_circuit.to_string())
            .expect("dial B over the circuit relay");
        let (_reader, mut writer) = conn.split();
        writer.send_frame(b"hello over relay").unwrap();

        let received = bob_thread.join().unwrap();
        assert_eq!(
            received, b"hello over relay",
            "the frame must arrive intact through the relay"
        );

        // Keep A and R alive until delivery is confirmed (the relayed path needs
        // both ends of the circuit up).
        alice.drain(50);
        relay.drain(50);
    }
}
