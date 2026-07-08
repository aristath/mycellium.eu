//! A libp2p-based transport: the production "direct line" (Layers 7, 10).
//!
//! TCP + Noise + Yamux, with the node's PeerId derived from the **device key**
//! (Layer 8.1), and a `/mycellium/1.0` byte-stream protocol carrying the same
//! app-layer E2E payload. The async libp2p swarm runs on a background Tokio
//! runtime; a small blocking bridge exposes it through the core's synchronous
//! `Connection` trait.
//!
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::kad::{self, store::MemoryStore, GetRecordOk, QueryResult, Quorum, Record, RecordKey};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identity, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder};
use libp2p_stream as stream;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use mycellium_core::transport::Connection;

const PROTOCOL: StreamProtocol = StreamProtocol::new("/mycellium/1.0");
const KAD_PROTOCOL: StreamProtocol = StreamProtocol::new("/mycellium/kad/1.0");

/// Public address type used by the libp2p adapter.
pub type P2pMultiaddr = Multiaddr;

/// How long `listen_addr` waits for the swarm to make progress.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(20);

/// The composite network behaviour driving this node.
#[derive(NetworkBehaviour)]
struct StreamBehaviour {
    stream: stream::Behaviour,
}

/// Kademlia-only behaviour for non-authoritative peer-record discovery.
#[derive(NetworkBehaviour)]
struct DhtBehaviour {
    kad: kad::Behaviour<MemoryStore>,
}

/// Commands the blocking bridge sends to the background swarm task.
enum Command {
    Dial(Multiaddr),
}

/// Swarm events the background task surfaces back to the blocking bridge.
enum NodeEvent {
    /// A concrete address this node now listens on.
    NewListenAddr(Multiaddr),
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
                .with_behaviour(|_| StreamBehaviour {
                    stream: stream::Behaviour::new(),
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
            // surface the few events the bridge cares about.
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        event = swarm.select_next_some() => match event {
                            SwarmEvent::OutgoingConnectionError { error, .. } => {
                                eprintln!("(libp2p dial error: {error})");
                            }
                            SwarmEvent::NewListenAddr { address, .. } => {
                                swarm.add_external_address(address.clone());
                                let _ = event_tx.send(NodeEvent::NewListenAddr(address));
                            }
                            _ => {}
                        },
                        Some(cmd) = cmd_rx.recv() => match cmd {
                            Command::Dial(addr) => { let _ = swarm.dial(addr); }
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
                let remaining = LISTEN_TIMEOUT
                    .checked_sub(start.elapsed())
                    .ok_or_else(|| anyhow!("timed out waiting for a listen address"))?;
                match tokio::time::timeout(remaining, event_rx.recv()).await {
                    Ok(Some(NodeEvent::NewListenAddr(addr))) => return Ok(addr),
                    Ok(None) => return Err(anyhow!("swarm event channel closed")),
                    Err(_) => return Err(anyhow!("timed out waiting for a listen address")),
                }
            }
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

/// Run a Kademlia peer-record discovery node forever.
pub fn dht_serve(
    device_secret: [u8; 32],
    listen_addr: Multiaddr,
    bootstrap: Vec<Multiaddr>,
) -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let mut swarm = new_dht_swarm(device_secret).await?;
        add_bootstrap_peers(&mut swarm, &bootstrap);
        swarm
            .listen_on(listen_addr)
            .map_err(|e| anyhow!("listen: {e:?}"))?;

        loop {
            match swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    swarm.add_external_address(address.clone());
                    println!("dht listening on {address}/p2p/{}", swarm.local_peer_id());
                }
                SwarmEvent::Behaviour(DhtBehaviourEvent::Kad(
                    kad::Event::OutboundQueryProgressed {
                        result: QueryResult::Bootstrap(result),
                        ..
                    },
                )) => {
                    if let Err(err) = result {
                        eprintln!("(dht bootstrap failed: {err})");
                    }
                }
                _ => {}
            }
        }
    })
}

/// Publish one signed-record blob into the DHT under `key`.
pub fn dht_put(
    device_secret: [u8; 32],
    listen_addr: Option<Multiaddr>,
    bootstrap: Vec<Multiaddr>,
    key: Vec<u8>,
    value: Vec<u8>,
) -> Result<()> {
    if bootstrap.is_empty() {
        bail!("dht publish needs at least one bootstrap peer");
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let mut swarm = new_dht_swarm(device_secret).await?;
        if let Some(addr) = listen_addr {
            swarm
                .listen_on(addr)
                .map_err(|e| anyhow!("listen: {e:?}"))?;
        }
        add_bootstrap_peers(&mut swarm, &bootstrap);
        for addr in &bootstrap {
            let _ = swarm.dial(addr.clone());
        }

        let query = swarm
            .behaviour_mut()
            .kad
            .put_record(Record::new(RecordKey::new(&key), value), Quorum::One)
            .map_err(|e| anyhow!("dht put failed to start: {e}"))?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        loop {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .ok_or_else(|| anyhow!("dht put timed out"))?;
            let event = tokio::time::timeout(remaining, swarm.select_next_some())
                .await
                .map_err(|_| anyhow!("dht put timed out"))?;
            if let SwarmEvent::Behaviour(DhtBehaviourEvent::Kad(
                kad::Event::OutboundQueryProgressed {
                    id,
                    result: QueryResult::PutRecord(result),
                    ..
                },
            )) = event
            {
                if id == query {
                    result.map_err(|err| anyhow!("dht put failed: {err}"))?;
                    return Ok(());
                }
            }
        }
    })
}

/// Resolve signed-record blobs from the DHT.
pub fn dht_get_records(
    device_secret: [u8; 32],
    listen_addr: Option<Multiaddr>,
    bootstrap: Vec<Multiaddr>,
    key: Vec<u8>,
) -> Result<Vec<Vec<u8>>> {
    if bootstrap.is_empty() {
        bail!("dht lookup needs at least one bootstrap peer");
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let mut swarm = new_dht_swarm(device_secret).await?;
        if let Some(addr) = listen_addr {
            swarm
                .listen_on(addr)
                .map_err(|e| anyhow!("listen: {e:?}"))?;
        }
        add_bootstrap_peers(&mut swarm, &bootstrap);
        for addr in &bootstrap {
            let _ = swarm.dial(addr.clone());
        }

        let query = swarm.behaviour_mut().kad.get_record(RecordKey::new(&key));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut records = Vec::new();

        loop {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .ok_or_else(|| anyhow!("dht get timed out"))?;
            let event = tokio::time::timeout(remaining, swarm.select_next_some())
                .await
                .map_err(|_| anyhow!("dht get timed out"))?;
            if let SwarmEvent::Behaviour(DhtBehaviourEvent::Kad(
                kad::Event::OutboundQueryProgressed {
                    id,
                    result: QueryResult::GetRecord(result),
                    step,
                    ..
                },
            )) = event
            {
                if id == query {
                    match result {
                        Ok(GetRecordOk::FoundRecord(record)) => {
                            records.push(record.record.value);
                            if step.last {
                                return Ok(records);
                            }
                        }
                        Ok(GetRecordOk::FinishedWithNoAdditionalRecord { .. }) => {
                            return Ok(records);
                        }
                        Err(kad::GetRecordError::NotFound { .. }) => return Ok(records),
                        Err(err) => return Err(anyhow!("dht get failed: {err}")),
                    }
                }
            }
        }
    })
}

async fn new_dht_swarm(device_secret: [u8; 32]) -> Result<Swarm<DhtBehaviour>> {
    let mut secret = device_secret;
    let keypair = identity::Keypair::ed25519_from_bytes(&mut secret)
        .map_err(|e| anyhow!("bad device key: {e}"))?;
    let peer_id = keypair.public().to_peer_id();

    let mut config = kad::Config::new(KAD_PROTOCOL);
    config.set_periodic_bootstrap_interval(Some(Duration::from_secs(60)));
    let store = MemoryStore::new(peer_id);

    SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| anyhow!("tcp/noise setup: {e}"))?
        .with_behaviour(move |_| DhtBehaviour {
            kad: kad::Behaviour::with_config(peer_id, store, config),
        })
        .map_err(|e| anyhow!("behaviour setup: {e}"))
        .map(|builder| builder.build())
}

fn add_bootstrap_peers(swarm: &mut Swarm<DhtBehaviour>, bootstrap: &[Multiaddr]) {
    for addr in bootstrap {
        if let Some((peer, base)) = peer_and_base_multiaddr(addr) {
            swarm.behaviour_mut().kad.add_address(&peer, base);
        }
    }
    if !bootstrap.is_empty() {
        let _ = swarm.behaviour_mut().kad.bootstrap();
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

/// Parse a full libp2p multiaddr.
pub fn parse_multiaddr(addr: &str) -> Result<Multiaddr> {
    addr.parse()
        .map_err(|_| anyhow!("'{addr}' is not a valid multiaddr"))
}

/// Parse a list of full libp2p multiaddrs.
pub fn parse_multiaddrs(addrs: &[String]) -> Result<Vec<Multiaddr>> {
    addrs
        .iter()
        .map(|addr| {
            let parsed = parse_multiaddr(addr)?;
            if peer_and_base_multiaddr(&parsed).is_none() {
                bail!("bootstrap multiaddr must include /p2p/<peer-id>: {addr}");
            }
            Ok(parsed)
        })
        .collect()
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

fn peer_and_base_multiaddr(addr: &Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let mut base = Multiaddr::empty();
    let mut peer = None;
    for protocol in addr.iter() {
        match protocol {
            Protocol::P2p(id) => peer = Some(id),
            other => base.push(other),
        }
    }
    peer.map(|id| (id, base))
}

/// Extract the target PeerId from a direct multiaddr.
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

    #[test]
    fn dht_bootstrap_addrs_must_include_peer_id() {
        let addrs = vec!["/ip4/127.0.0.1/tcp/41001".to_string()];

        assert!(parse_multiaddrs(&addrs).is_err());
    }
}
