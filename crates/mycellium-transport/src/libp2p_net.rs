//! Optional libp2p-based adapter code.
//!
//! This module is retained for explicit legacy diagnostics and DHT peer-record
//! discovery. Native Mycellium delivery uses the Reticulum adapter.
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
#[cfg(feature = "dht")]
use libp2p::kad::{self, store::MemoryStore, GetRecordOk, QueryResult, Quorum, Record, RecordKey};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identity, Multiaddr, PeerId, StreamProtocol, SwarmBuilder};
#[cfg(feature = "dht")]
use libp2p::{noise, tcp, yamux, Swarm};
use libp2p_stream as stream;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use mycellium_core::identity::DevicePublicKey;
use mycellium_core::transport::Connection;

const PROTOCOL: StreamProtocol = StreamProtocol::new("/mycellium/1.0");
#[cfg(feature = "dht")]
const KAD_PROTOCOL: StreamProtocol = StreamProtocol::new("/mycellium/kad/1.0");

/// Public address type used by the libp2p adapter.
pub type P2pMultiaddr = Multiaddr;

/// How long `listen_addr` waits for the swarm to make progress.
const LISTEN_TIMEOUT: Duration = Duration::from_secs(20);
/// Bound one framed stream operation so an idle peer cannot pin a synchronous
/// engine worker forever while it waits for payload bytes or an acceptance ACK.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// The composite network behaviour driving this node.
#[derive(NetworkBehaviour)]
struct StreamBehaviour {
    stream: stream::Behaviour,
}

/// Kademlia-only behaviour for non-authoritative peer-record discovery.
#[cfg(feature = "dht")]
#[derive(NetworkBehaviour)]
struct DhtBehaviour {
    kad: kad::Behaviour<MemoryStore>,
}

/// Commands the blocking bridge sends to the background swarm task.
enum Command {
    Dial(Multiaddr),
    Shutdown,
}

/// Swarm events the background task surfaces back to the blocking bridge.
enum NodeEvent {
    /// A concrete address this node now listens on.
    NewListenAddr(Multiaddr),
}

/// A running libp2p node: owns the runtime and the swarm-driving task.
pub struct Libp2pNode {
    dialer: Libp2pDialer,
    incoming: stream::IncomingStreams,
    event_rx: mpsc::Receiver<NodeEvent>,
    peer_id: PeerId,
}

/// Cloneable outbound handle to one long-lived swarm.
///
/// Clones share the same runtime, peer identity, connections, and stream
/// control. A listener can therefore keep accepting inbound streams while
/// background retry workers open outbound streams through this handle.
#[derive(Clone)]
pub struct Libp2pDialer {
    rt: Arc<Runtime>,
    control: stream::Control,
    cmd_tx: mpsc::Sender<Command>,
}

impl Libp2pNode {
    /// Build a node from the device key, optionally listening on `listen_addr`.
    pub fn new(device_secret: [u8; 32], listen_addr: Option<Multiaddr>) -> Result<Self> {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?,
        );

        let mut secret = device_secret;
        let keypair = identity::Keypair::ed25519_from_bytes(&mut secret)
            .map_err(|e| anyhow!("bad device key: {e}"))?;
        let peer_id = keypair.public().to_peer_id();

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(256);
        let (event_tx, event_rx) = mpsc::channel::<NodeEvent>(8);

        let (control, incoming) = rt.block_on(async {
            let mut swarm = SwarmBuilder::with_existing_identity(keypair)
                .with_tokio()
                .with_quic()
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
                                let _ = event_tx.try_send(NodeEvent::NewListenAddr(address));
                            }
                            _ => {}
                        },
                        Some(cmd) = cmd_rx.recv() => match cmd {
                            Command::Dial(addr) => { let _ = swarm.dial(addr); }
                            Command::Shutdown => break,
                        }
                    }
                }
            });

            Ok::<_, anyhow::Error>((control, incoming))
        })?;

        let dialer = Libp2pDialer {
            rt,
            control,
            cmd_tx,
        };
        Ok(Libp2pNode {
            dialer,
            incoming,
            event_rx,
            peer_id,
        })
    }

    /// Block until this node reports the concrete OS-assigned listen address.
    pub fn listen_addr(&mut self) -> Result<Multiaddr> {
        let handle = self.dialer.rt.handle().clone();
        let event_rx = &mut self.event_rx;
        handle.block_on(async {
            match tokio::time::timeout(LISTEN_TIMEOUT, event_rx.recv()).await {
                Ok(Some(NodeEvent::NewListenAddr(addr))) => Ok(addr),
                Ok(None) => Err(anyhow!("swarm event channel closed")),
                Err(_) => Err(anyhow!("timed out waiting for a listen address")),
            }
        })
    }

    /// This node's PeerId (derived from the device key).
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Clone an outbound handle backed by this node's existing swarm.
    pub fn dialer(&self) -> Libp2pDialer {
        self.dialer.clone()
    }

    /// Dial a peer given its multiaddr as a string.
    pub fn dial_str(&self, target: &str) -> Result<Libp2pConnection> {
        self.dialer.dial_str(target)
    }

    /// Dial a peer given its full multiaddr (must include `/p2p/<peer-id>`).
    pub fn dial(&self, target: &Multiaddr) -> Result<Libp2pConnection> {
        self.dialer.dial(target)
    }

    /// Wait for an inbound `/mycellium/1.0` stream and return it as a connection.
    pub fn accept(&mut self) -> Result<Libp2pConnection> {
        let next = self.dialer.rt.block_on(self.incoming.next());
        let (peer, stream) = next.ok_or_else(|| anyhow!("stream listener closed"))?;
        Ok(Libp2pConnection {
            handle: self.dialer.rt.handle().clone(),
            peer,
            stream,
        })
    }

    /// Wait up to `timeout` for an inbound stream. A timeout returns `Ok(None)`
    /// so native lifecycle loops can observe cancellation without leaking a
    /// permanently blocked listener thread.
    pub fn accept_timeout(&mut self, timeout: Duration) -> Result<Option<Libp2pConnection>> {
        let incoming = &mut self.incoming;
        let next = self
            .dialer
            .rt
            .block_on(async move { tokio::time::timeout(timeout, incoming.next()).await });
        match next {
            Err(_) => Ok(None),
            Ok(Some((peer, stream))) => Ok(Some(Libp2pConnection {
                handle: self.dialer.rt.handle().clone(),
                peer,
                stream,
            })),
            Ok(None) => Err(anyhow!("stream listener closed")),
        }
    }

    /// Let the background swarm run for `millis` so buffered stream data is
    /// actually transmitted before the node (and its runtime) is dropped.
    pub fn drain(&self, millis: u64) {
        self.dialer
            .rt
            .block_on(async move { tokio::time::sleep(Duration::from_millis(millis)).await });
    }
}

impl Libp2pDialer {
    /// Start one outbound-only swarm. Keep this handle and clone it instead of
    /// constructing a node for every delivery.
    pub fn new(device_secret: [u8; 32]) -> Result<Self> {
        Ok(Libp2pNode::new(device_secret, None)?.dialer())
    }

    /// Dial a peer given its multiaddr as a string.
    pub fn dial_str(&self, target: &str) -> Result<Libp2pConnection> {
        let addr: Multiaddr = target
            .parse()
            .map_err(|_| anyhow!("'{target}' is not a valid multiaddr"))?;
        self.dial(&addr)
    }

    /// Dial a peer through the shared swarm.
    pub fn dial(&self, target: &Multiaddr) -> Result<Libp2pConnection> {
        ensure_no_ipv4(target)?;
        let peer = peer_from_multiaddr(target)
            .ok_or_else(|| anyhow!("multiaddr is missing a /p2p/<peer-id> component"))?;
        let mut control = self.control.clone();
        // Reuse an established connection without asking the swarm to dial it
        // again. This is the common retry/multi-message path.
        if let Ok(stream) = self.rt.block_on(control.open_stream(peer, PROTOCOL)) {
            return Ok(Libp2pConnection {
                handle: self.rt.handle().clone(),
                peer,
                stream,
            });
        }
        self.cmd_tx
            .try_send(Command::Dial(target.clone()))
            .map_err(|_| anyhow!("libp2p swarm stopped"))?;

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
            peer,
            stream,
        })
    }

    /// Stop the shared swarm.
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.try_send(Command::Shutdown);
    }
}

/// Run a Kademlia peer-record discovery node forever.
#[cfg(feature = "dht")]
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
                        result: QueryResult::Bootstrap(Err(err)),
                        ..
                    },
                )) => {
                    eprintln!("(dht bootstrap failed: {err})");
                }
                _ => {}
            }
        }
    })
}

/// Publish one signed-record blob into the DHT under `key`.
#[cfg(feature = "dht")]
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
#[cfg(feature = "dht")]
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

#[cfg(feature = "dht")]
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

#[cfg(feature = "dht")]
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
    peer: PeerId,
    stream: libp2p::swarm::Stream,
}

impl Libp2pConnection {
    /// Authenticated remote transport identity.
    pub fn peer_id(&self) -> PeerId {
        self.peer
    }

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
            match tokio::time::timeout(IO_TIMEOUT, async {
                let mut header = [0u8; 4];
                read.read_exact(&mut header).await?;
                let n = crate::link::frame_len(header)?;
                let mut buf = vec![0u8; n];
                read.read_exact(&mut buf).await?;
                Ok::<_, io::Error>(buf)
            })
            .await
            {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stream read timed out",
                )),
            }
        })?;
        Ok(bytes)
    }
}

impl crate::link::FrameWriter for Libp2pWriteHalf {
    fn send_frame(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        let write = &mut self.write;
        self.handle.block_on(async move {
            match tokio::time::timeout(IO_TIMEOUT, async {
                write
                    .write_all(&crate::link::frame_header(bytes.len())?)
                    .await?;
                write.write_all(bytes).await?;
                write.flush().await
            })
            .await
            {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stream write timed out",
                )),
            }
        })?;
        Ok(())
    }
}

impl Connection for Libp2pConnection {
    type Error = io::Error;

    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        let stream = &mut self.stream;
        self.handle.block_on(async move {
            match tokio::time::timeout(IO_TIMEOUT, async {
                stream
                    .write_all(&crate::link::frame_header(bytes.len())?)
                    .await?;
                stream.write_all(bytes).await?;
                stream.flush().await
            })
            .await
            {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stream write timed out",
                )),
            }
        })
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        let stream = &mut self.stream;
        self.handle.block_on(async move {
            match tokio::time::timeout(IO_TIMEOUT, async {
                let mut header = [0u8; 4];
                stream.read_exact(&mut header).await?;
                let n = crate::link::frame_len(header)?;
                let mut buf = vec![0u8; n];
                stream.read_exact(&mut buf).await?;
                Ok(buf)
            })
            .await
            {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stream read timed out",
                )),
            }
        })
    }
}

/// Public Mycellium device key corresponding to a transport secret.
pub fn device_key_for_secret(mut device_secret: [u8; 32]) -> Result<DevicePublicKey> {
    let keypair = identity::Keypair::ed25519_from_bytes(&mut device_secret)
        .map_err(|e| anyhow!("bad device key: {e}"))?;
    let public = keypair
        .public()
        .try_into_ed25519()
        .map_err(|_| anyhow!("device key is not Ed25519"))?;
    Ok(DevicePublicKey(public.to_bytes()))
}

/// Derive the authenticated libp2p PeerId for a public device key.
pub fn peer_id_for_device(device: &DevicePublicKey) -> Result<PeerId> {
    let public = identity::ed25519::PublicKey::try_from_bytes(&device.0)
        .map_err(|e| anyhow!("bad device public key: {e}"))?;
    let public: identity::PublicKey = public.into();
    Ok(public.to_peer_id())
}

/// A listen multiaddr (`/ip6/…/tcp/…`) from an IPv6 `host:port` string.
pub fn listen_multiaddr(addr: &str) -> Result<Multiaddr> {
    let socket: SocketAddr = addr
        .parse()
        .map_err(|_| anyhow!("address must be IPv6 host:port, e.g. [::1]:9001"))?;
    if socket.is_ipv4() {
        bail!("IPv4 is not a Mycellium transport address");
    }
    Ok(socket_to_multiaddr(socket))
}

/// A QUIC listen multiaddr (`/ip6/…/udp/…/quic-v1`) from an IPv6 `host:port`.
pub fn quic_listen_multiaddr(addr: &str) -> Result<Multiaddr> {
    let socket: SocketAddr = addr
        .parse()
        .map_err(|_| anyhow!("address must be IPv6 host:port, e.g. [::]:0"))?;
    let mut address = Multiaddr::empty();
    match socket.ip() {
        IpAddr::V4(_) => bail!("IPv4 is not a Mycellium transport address"),
        IpAddr::V6(ip) => address.push(Protocol::Ip6(ip)),
    }
    address.push(Protocol::Udp(socket.port()));
    address.push(Protocol::QuicV1);
    Ok(address)
}

/// Parse a full libp2p multiaddr.
pub fn parse_multiaddr(addr: &str) -> Result<Multiaddr> {
    let parsed = addr
        .parse()
        .map_err(|_| anyhow!("'{addr}' is not a valid multiaddr"))?;
    ensure_no_ipv4(&parsed)?;
    Ok(parsed)
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

fn socket_to_multiaddr(socket: SocketAddr) -> Multiaddr {
    let mut addr = Multiaddr::empty();
    match socket.ip() {
        IpAddr::V4(_) => unreachable!("IPv4 socket addresses are rejected before conversion"),
        IpAddr::V6(ip) => addr.push(Protocol::Ip6(ip)),
    }
    addr.push(Protocol::Tcp(socket.port()));
    addr
}

fn ensure_no_ipv4(address: &Multiaddr) -> Result<()> {
    for protocol in address.iter() {
        match protocol {
            Protocol::Ip4(_) | Protocol::Dns4(_) => {
                bail!("IPv4 is not a Mycellium transport address")
            }
            _ => {}
        }
    }
    Ok(())
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
        format!("/ip6/::1/udp/{port}/quic-v1").parse().unwrap()
    }

    #[test]
    fn one_outbound_actor_reuses_its_swarm_across_multiple_peers() {
        let mut bob = Libp2pNode::new([7u8; 32], Some(listen_addr(0))).unwrap();
        let bob_peer = bob.peer_id();
        let bob_addr = bob.listen_addr().unwrap();
        let mut carol = Libp2pNode::new([8u8; 32], Some(listen_addr(0))).unwrap();
        let carol_peer = carol.peer_id();
        let carol_addr = carol.listen_addr().unwrap();

        let bob_thread = std::thread::spawn(move || {
            let mut received = Vec::new();
            for _ in 0..2 {
                let mut conn = bob.accept().unwrap();
                received.push(conn.recv().unwrap());
            }
            received
        });
        let carol_thread = std::thread::spawn(move || {
            let mut conn = carol.accept().unwrap();
            conn.recv().unwrap()
        });

        // `Libp2pDialer::new` drops its temporary node shell. The cloneable
        // dialer keeps the one runtime and swarm alive across both deposits.
        let alice = Libp2pDialer::new([9u8; 32]).unwrap();
        let bob_dial: Multiaddr = format!("{bob_addr}/p2p/{bob_peer}").parse().unwrap();
        let carol_dial: Multiaddr = format!("{carol_addr}/p2p/{carol_peer}").parse().unwrap();
        let mut conn = alice.dial(&bob_dial).unwrap();
        conn.send(b"first").unwrap();
        let mut conn = alice.dial(&carol_dial).unwrap();
        conn.send(b"other peer").unwrap();
        let mut conn = alice.dial(&bob_dial).unwrap();
        conn.send(b"second").unwrap();

        let received = bob_thread.join().unwrap();
        assert_eq!(received, [b"first".to_vec(), b"second".to_vec()]);
        assert_eq!(carol_thread.join().unwrap(), b"other peer");
    }

    #[test]
    fn dht_bootstrap_addrs_must_include_peer_id() {
        let addrs = vec!["/ip6/::1/tcp/41001".to_string()];

        assert!(parse_multiaddrs(&addrs).is_err());
    }

    #[test]
    fn ipv4_multiaddrs_are_rejected() {
        assert!(parse_multiaddr("/ip4/127.0.0.1/udp/4001/quic-v1").is_err());
        assert!(quic_listen_multiaddr("0.0.0.0:0").is_err());
        assert!(listen_multiaddr("127.0.0.1:9001").is_err());
    }

    #[test]
    fn accept_timeout_creates_its_timer_inside_the_owned_runtime() {
        let mut node = Libp2pNode::new([10u8; 32], Some(listen_addr(0))).unwrap();
        node.listen_addr().unwrap();

        assert!(node
            .accept_timeout(Duration::from_millis(10))
            .unwrap()
            .is_none());
    }
}
