//! Live device introduction over authenticated QUIC.
//!
//! This service retains only a process-local map of currently connected
//! devices and their observed UDP mappings. It cannot accept application
//! message streams and stores no presence, introduction, or payload data.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::core::ConnectedPoint;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{identity, Multiaddr, PeerId, StreamProtocol, SwarmBuilder};
use libp2p_stream as stream;
use tokio::sync::mpsc;

use mycellium_core::identity::DevicePublicKey;
use mycellium_core::rendezvous::{self as protocol, ClientMessage, PunchRole, ServerMessage};
use mycellium_core::userid::UserId;
use mycellium_core::wire;

const STREAM_PROTOCOL: StreamProtocol = StreamProtocol::new(protocol::PROTOCOL);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Registry account lookup needed to authenticate a live device.
pub trait DeviceAuthorizer: Clone + Send + Sync + 'static {
    /// Return true only when `user_id`'s current signed public record names
    /// `device` as its active device. The QUIC peer separately proves possession
    /// of that device key.
    fn authorize_device(
        &self,
        user_id: &UserId,
        device: &DevicePublicKey,
    ) -> futures::future::BoxFuture<'static, bool>;
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    stream: stream::Behaviour,
}

#[derive(Clone)]
struct LiveDevice {
    observed_address: Multiaddr,
    generation: u64,
    user_id: UserId,
    tx: mpsc::Sender<ServerMessage>,
}

type LiveDevices = Arc<Mutex<HashMap<DevicePublicKey, LiveDevice>>>;
type ObservedAddresses = Arc<Mutex<HashMap<PeerId, Multiaddr>>>;

/// Run the QUIC introduction service until it fails or is shut down.
pub async fn serve<A>(
    authorizer: A,
    device_secret: [u8; 32],
    listen_address: Multiaddr,
) -> Result<()>
where
    A: DeviceAuthorizer,
{
    let mut secret = device_secret;
    let keypair = identity::Keypair::ed25519_from_bytes(&mut secret)
        .map_err(|error| anyhow!("invalid rendezvous identity: {error}"))?;
    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_quic()
        .with_behaviour(|_| Behaviour {
            stream: stream::Behaviour::new(),
        })
        .map_err(|error| anyhow!("rendezvous behaviour setup failed: {error}"))?
        .build();
    let mut control = swarm.behaviour().stream.new_control();
    let mut incoming = control
        .accept(STREAM_PROTOCOL)
        .map_err(|error| anyhow!("rendezvous protocol setup failed: {error}"))?;
    swarm
        .listen_on(listen_address)
        .map_err(|error| anyhow!("rendezvous listen failed: {error:?}"))?;

    let devices: LiveDevices = Arc::new(Mutex::new(HashMap::new()));
    let observed: ObservedAddresses = Arc::new(Mutex::new(HashMap::new()));
    let generations = Arc::new(AtomicU64::new(0));

    loop {
        tokio::select! {
            stream = incoming.next() => {
                let Some((peer, stream)) = stream else {
                    bail!("rendezvous stream listener closed");
                };
                tokio::spawn(handle_device(
                    authorizer.clone(),
                    peer,
                    stream,
                    Arc::clone(&observed),
                    Arc::clone(&devices),
                    Arc::clone(&generations),
                ));
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    endpoint: ConnectedPoint::Listener { send_back_addr, .. },
                    ..
                } => {
                    if is_quic_address(&send_back_addr) {
                        observed
                            .lock()
                            .map_err(|_| anyhow!("observed-address state is unavailable"))?
                            .insert(peer_id, send_back_addr);
                    }
                }
                SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => {
                    observed
                        .lock()
                        .map_err(|_| anyhow!("observed-address state is unavailable"))?
                        .remove(&peer_id);
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    eprintln!("mycellium-registry rendezvous listening on {address}/p2p/{}", swarm.local_peer_id());
                }
                _ => {}
            }
        }
    }
}

async fn handle_device<A>(
    authorizer: A,
    peer: PeerId,
    mut transport: libp2p::swarm::Stream,
    observed: ObservedAddresses,
    devices: LiveDevices,
    generations: Arc<AtomicU64>,
) where
    A: DeviceAuthorizer,
{
    let registration = tokio::time::timeout(IO_TIMEOUT, read_client_message(&mut transport)).await;
    let Ok(Ok(ClientMessage::Register { user_id, device })) = registration else {
        let _ = write_server_message(&mut transport, &ServerMessage::Rejected).await;
        return;
    };

    let Ok(expected_peer) = peer_id_for_device(&device) else {
        let _ = write_server_message(&mut transport, &ServerMessage::Rejected).await;
        return;
    };
    if expected_peer != peer || !authorizer.authorize_device(&user_id, &device).await {
        let _ = write_server_message(&mut transport, &ServerMessage::Rejected).await;
        return;
    }
    let observed_address = match observed.lock() {
        Ok(observed) => observed.get(&peer).cloned(),
        Err(_) => None,
    };
    let Some(observed_address) = observed_address else {
        let _ = write_server_message(&mut transport, &ServerMessage::Rejected).await;
        return;
    };

    let generation = generations.fetch_add(1, Ordering::Relaxed) + 1;
    let (mut read, mut write) = transport.split();
    // One slow or malicious device must not grow registry memory without bound.
    // Sixty-four control instructions already represents far more concurrent
    // introductions than one client can usefully process.
    let (tx, mut rx) = mpsc::channel(64);
    let registered = match devices.lock() {
        Ok(mut live_devices) => {
            live_devices.insert(
                device,
                LiveDevice {
                    observed_address: observed_address.clone(),
                    generation,
                    user_id: user_id.clone(),
                    tx: tx.clone(),
                },
            );
            true
        }
        Err(_) => false,
    };
    if !registered {
        let _ = write_server_message(&mut write, &ServerMessage::Rejected).await;
        return;
    }
    let _ = tx.try_send(ServerMessage::Registered);

    let writer = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if write_server_message(&mut write, &message).await.is_err() {
                break;
            }
        }
    });

    while let Ok(message) = read_client_message(&mut read).await {
        let ClientMessage::Introduce { device: target } = message else {
            break;
        };
        if !authorizer.authorize_device(&user_id, &device).await {
            let _ = tx.try_send(ServerMessage::Rejected);
            break;
        }
        if target == device {
            let _ = tx.try_send(ServerMessage::Unavailable { device: target });
            continue;
        }
        let target_live = match devices.lock() {
            Ok(devices) => devices.get(&target).cloned(),
            Err(_) => {
                let _ = tx.try_send(ServerMessage::Rejected);
                break;
            }
        };
        let Some(target_live) = target_live else {
            let _ = tx.try_send(ServerMessage::Unavailable { device: target });
            continue;
        };
        if !authorizer
            .authorize_device(&target_live.user_id, &target)
            .await
        {
            remove_if_generation(&devices, &target, target_live.generation);
            let _ = tx.try_send(ServerMessage::Unavailable { device: target });
            continue;
        }

        // Tell the receiving peer first so it begins the listener-role dial
        // before the initiating peer starts its normal dial.
        if target_live
            .tx
            .try_send(ServerMessage::Connect {
                device,
                address: observed_address.to_vec(),
                role: PunchRole::Listener,
            })
            .is_err()
        {
            remove_if_generation(&devices, &target, target_live.generation);
            let _ = tx.try_send(ServerMessage::Unavailable { device: target });
            continue;
        }
        let _ = tx.try_send(ServerMessage::Connect {
            device: target,
            address: target_live.observed_address.to_vec(),
            role: PunchRole::Dialer,
        });
    }

    remove_if_generation(&devices, &device, generation);
    writer.abort();
}

fn remove_if_generation(devices: &LiveDevices, device: &DevicePublicKey, generation: u64) {
    let Ok(mut devices) = devices.lock() else {
        return;
    };
    if devices
        .get(device)
        .is_some_and(|live| live.generation == generation)
    {
        devices.remove(device);
    }
}

async fn read_client_message<R>(reader: &mut R) -> Result<ClientMessage>
where
    R: futures::AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let len = frame_length(header)?;
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes).await?;
    wire::decode(&bytes).map_err(|_| anyhow!("invalid rendezvous control frame"))
}

async fn write_server_message<W>(writer: &mut W, message: &ServerMessage) -> Result<()>
where
    W: futures::AsyncWrite + Unpin,
{
    let bytes = wire::encode(message);
    if bytes.len() > protocol::MAX_FRAME_BYTES {
        bail!("rendezvous control frame is too large");
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

fn frame_length(header: [u8; 4]) -> Result<usize> {
    let len = u32::from_be_bytes(header) as usize;
    if len > protocol::MAX_FRAME_BYTES {
        bail!("rendezvous control frame is too large");
    }
    Ok(len)
}

fn is_quic_address(address: &Multiaddr) -> bool {
    address.iter().any(|part| part == Protocol::QuicV1)
}

/// Derive a libp2p peer identity from a public Mycellium device key.
pub fn peer_id_for_device(device: &DevicePublicKey) -> Result<PeerId> {
    let public = identity::ed25519::PublicKey::try_from_bytes(&device.0)
        .map_err(|error| anyhow!("invalid device public key: {error}"))?;
    let public: identity::PublicKey = public.into();
    Ok(public.to_peer_id())
}

/// Load the registry's stable rendezvous identity, creating it on first run.
pub fn load_or_create_identity(path: &Path) -> Result<[u8; 32]> {
    match OpenOptions::new().read(true).open(path) {
        Ok(mut file) => {
            let mut secret = [0u8; 32];
            file.read_exact(&mut secret)
                .context("could not read rendezvous identity")?;
            let mut extra = [0u8; 1];
            if file.read(&mut extra)? != 0 {
                bail!("rendezvous identity has an invalid length");
            }
            Ok(secret)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut secret = [0u8; 32];
            getrandom::getrandom(&mut secret).context("could not create rendezvous identity")?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(path)
                .context("could not store rendezvous identity")?;
            file.write_all(&secret)?;
            file.sync_all()?;
            Ok(secret)
        }
        Err(error) => Err(error).context("could not open rendezvous identity"),
    }
}

/// PeerId string for the rendezvous identity.
pub fn peer_id_for_secret(mut secret: [u8; 32]) -> Result<PeerId> {
    let keypair = identity::Keypair::ed25519_from_bytes(&mut secret)
        .map_err(|error| anyhow!("invalid rendezvous identity: {error}"))?;
    Ok(keypair.public().to_peer_id())
}

/// Convert a socket address into a QUIC libp2p listen address.
pub fn quic_listen_address(socket: SocketAddr) -> Multiaddr {
    let mut address = Multiaddr::empty();
    match socket.ip() {
        IpAddr::V4(ip) => address.push(Protocol::Ip4(ip)),
        IpAddr::V6(ip) => address.push(Protocol::Ip6(ip)),
    }
    address.push(Protocol::Udp(socket.port()));
    address.push(Protocol::QuicV1);
    address
}

/// Append and validate the registry PeerId on a public QUIC base address.
pub fn public_address(base: &str, peer: PeerId) -> Result<String> {
    let mut address: Multiaddr = base
        .parse()
        .map_err(|_| anyhow!("invalid public rendezvous multiaddr"))?;
    if !is_quic_address(&address) {
        bail!("public rendezvous address must use QUIC");
    }
    if address.iter().any(|part| matches!(part, Protocol::P2p(_))) {
        bail!("public rendezvous base address must not include /p2p");
    }
    address.push(Protocol::P2p(peer));
    Ok(address.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycellium_core::transport::Connection;
    use mycellium_transport::libp2p_net::{self, Libp2pNode};

    fn test_user_id(byte: u8) -> UserId {
        UserId::new(format!("{byte:02x}").repeat(32)).unwrap()
    }

    #[derive(Clone)]
    struct AllowCurrentDevice;

    impl DeviceAuthorizer for AllowCurrentDevice {
        fn authorize_device(
            &self,
            _user_id: &UserId,
            _device: &DevicePublicKey,
        ) -> futures::future::BoxFuture<'static, bool> {
            Box::pin(async { true })
        }
    }

    #[derive(Clone, Default)]
    struct RevocableDevice {
        revoked: Arc<Mutex<Option<DevicePublicKey>>>,
    }

    impl DeviceAuthorizer for RevocableDevice {
        fn authorize_device(
            &self,
            _user_id: &UserId,
            device: &DevicePublicKey,
        ) -> futures::future::BoxFuture<'static, bool> {
            let allowed = self
                .revoked
                .lock()
                .expect("revocation lock poisoned")
                .as_ref()
                != Some(device);
            Box::pin(async move { allowed })
        }
    }

    #[test]
    fn public_address_is_quic_and_self_authenticating() {
        let peer = peer_id_for_secret([7; 32]).unwrap();
        let address = public_address("/ip4/203.0.113.2/udp/8788/quic-v1", peer).unwrap();
        assert!(address.contains("/udp/8788/quic-v1/p2p/"));
        assert!(public_address("/ip4/203.0.113.2/tcp/8788", peer).is_err());
    }

    #[test]
    fn device_key_deterministically_selects_peer_id() {
        let mut secret = [9; 32];
        let keypair = identity::Keypair::ed25519_from_bytes(&mut secret).unwrap();
        let public = keypair.public().try_into_ed25519().unwrap();
        let device = DevicePublicKey(public.to_bytes());
        assert_eq!(
            peer_id_for_device(&device).unwrap(),
            keypair.public().to_peer_id()
        );
    }

    #[test]
    #[ignore = "requires MYCELLIUM_LIVE_RENDEZVOUS"]
    fn live_rendezvous_rejects_an_unauthorized_device_after_quic_handshake() {
        let address = std::env::var("MYCELLIUM_LIVE_RENDEZVOUS")
            .expect("set MYCELLIUM_LIVE_RENDEZVOUS to the public QUIC multiaddr");
        let secret = [11; 32];
        let listen = libp2p_net::quic_listen_multiaddr("0.0.0.0:0").unwrap();
        let mut node = Libp2pNode::new(secret, Some(listen)).unwrap();
        node.listen_addr().unwrap();
        let error = node
            .dialer()
            .register_rendezvous(
                &address,
                &test_user_id(0x11),
                libp2p_net::device_key_for_secret(secret).unwrap(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("rejected this active device"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn introduces_two_devices_without_carrying_their_payload() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);

        let registry_secret = [5; 32];
        let registry_peer = peer_id_for_secret(registry_secret).unwrap();
        let registry_address = format!("/ip4/127.0.0.1/udp/{port}/quic-v1/p2p/{registry_peer}");
        let server = tokio::spawn(serve(
            AllowCurrentDevice,
            registry_secret,
            quic_listen_address(format!("127.0.0.1:{port}").parse().unwrap()),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let bob_address = registry_address.clone();
        let bob = tokio::task::spawn_blocking(move || {
            let secret = [7; 32];
            let listen = libp2p_net::quic_listen_multiaddr("127.0.0.1:0").unwrap();
            let mut node = Libp2pNode::new(secret, Some(listen)).unwrap();
            node.listen_addr().unwrap();
            node.dialer()
                .register_rendezvous(
                    &bob_address,
                    &test_user_id(0x22),
                    libp2p_net::device_key_for_secret(secret).unwrap(),
                )
                .unwrap();
            ready_tx.send(()).unwrap();
            let mut direct = node.accept().unwrap();
            direct.recv().unwrap()
        });
        ready_rx.await.unwrap();

        let alice_address = registry_address;
        let alice = tokio::task::spawn_blocking(move || {
            let secret = [9; 32];
            let listen = libp2p_net::quic_listen_multiaddr("127.0.0.1:0").unwrap();
            let mut node = Libp2pNode::new(secret, Some(listen)).unwrap();
            node.listen_addr().unwrap();
            let dialer = node.dialer();
            dialer
                .register_rendezvous(
                    &alice_address,
                    &test_user_id(0x33),
                    libp2p_net::device_key_for_secret(secret).unwrap(),
                )
                .unwrap();
            let bob_device = libp2p_net::device_key_for_secret([7; 32]).unwrap();
            let mut direct = dialer.introduce_and_dial(&bob_device).unwrap();
            direct.send(b"device-to-device only").unwrap();
        });

        alice.await.unwrap();
        assert_eq!(bob.await.unwrap(), b"device-to-device only");
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retired_active_device_is_not_introduced() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);

        let authorizer = RevocableDevice::default();
        let registry_secret = [13; 32];
        let registry_peer = peer_id_for_secret(registry_secret).unwrap();
        let registry_address = format!("/ip4/127.0.0.1/udp/{port}/quic-v1/p2p/{registry_peer}");
        let server = tokio::spawn(serve(
            authorizer.clone(),
            registry_secret,
            quic_listen_address(format!("127.0.0.1:{port}").parse().unwrap()),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let bob_secret = [15; 32];
        let bob_device = libp2p_net::device_key_for_secret(bob_secret).unwrap();
        let bob_address = registry_address.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let bob = tokio::task::spawn_blocking(move || {
            let listen = libp2p_net::quic_listen_multiaddr("127.0.0.1:0").unwrap();
            let mut node = Libp2pNode::new(bob_secret, Some(listen)).unwrap();
            node.listen_addr().unwrap();
            node.dialer()
                .register_rendezvous(&bob_address, &test_user_id(0x44), bob_device)
                .unwrap();
            ready_tx.send(()).unwrap();
            release_rx.blocking_recv().unwrap();
        });
        ready_rx.await.unwrap();
        *authorizer.revoked.lock().unwrap() = Some(bob_device);

        let alice_address = registry_address;
        let error = tokio::task::spawn_blocking(move || {
            let secret = [17; 32];
            let listen = libp2p_net::quic_listen_multiaddr("127.0.0.1:0").unwrap();
            let mut node = Libp2pNode::new(secret, Some(listen)).unwrap();
            node.listen_addr().unwrap();
            let dialer = node.dialer();
            dialer
                .register_rendezvous(
                    &alice_address,
                    &test_user_id(0x55),
                    libp2p_net::device_key_for_secret(secret).unwrap(),
                )
                .unwrap();
            match dialer.introduce_and_dial(&bob_device) {
                Ok(_) => panic!("retired device was introduced"),
                Err(error) => error,
            }
        })
        .await
        .unwrap();
        assert!(error.to_string().contains("not currently available"));

        release_tx.send(()).unwrap();
        bob.await.unwrap();
        server.abort();
    }
}
