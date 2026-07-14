//! Reticulum transport adapter for Mycellium delivery frames.
//!
//! Mycellium addresses devices by their signed Reticulum destination. Underlay
//! interfaces are only Reticulum connectivity; they are not user/device
//! addresses and are never written into account records.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use mycellium_core::identity::ReticulumPublicIdentity;
use rns_transport::delivery::{await_link_activation, send_on_link};
use rns_transport::destination::{DestinationDesc, DestinationName};
use rns_transport::hash::AddressHash;
use rns_transport::identity::{Identity as RnsIdentity, PrivateIdentity};
use rns_transport::iface::tcp_client::TcpClient;
use rns_transport::iface::tcp_server::TcpServer;
use rns_transport::iface::IfaceRole;
use rns_transport::resource::ResourceEventKind;
use rns_transport::transport::{Transport, TransportConfig};
use tokio::runtime::Runtime;

const APP_NAME: &str = "mycellium";
const APP_ASPECT: &str = "delivery";
const DEFAULT_LINK_TIMEOUT: Duration = Duration::from_secs(30);

/// Reticulum underlay configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReticulumConfig {
    /// TCP Reticulum nodes to connect to, for example `host.example:4242`.
    pub tcp_nodes: Vec<String>,
}

impl ReticulumConfig {
    /// Read Reticulum TCP nodes from `MYCELLIUM_RETICULUM_TCP_NODES`.
    ///
    /// Values may be comma, semicolon, or whitespace separated.
    pub fn from_env() -> Self {
        let nodes = std::env::var("MYCELLIUM_RETICULUM_TCP_NODES")
            .ok()
            .map(|value| {
                value
                    .split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace())
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Self { tcp_nodes: nodes }
    }
}

/// One inbound Mycellium frame received over a Reticulum link.
pub struct InboundFrame {
    bytes: Vec<u8>,
    reply: ReticulumReply,
}

impl InboundFrame {
    /// Borrow the received frame bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Send a response frame over the same Reticulum link.
    pub fn reply(&self, bytes: &[u8]) -> Result<()> {
        self.reply.send(bytes)
    }
}

#[derive(Clone)]
struct ReticulumReply {
    node: ReticulumNode,
    link_id: AddressHash,
}

impl ReticulumReply {
    fn send(&self, bytes: &[u8]) -> Result<()> {
        self.node.send_on_existing_link(self.link_id, bytes)
    }
}

#[derive(Clone)]
pub struct ReticulumNode {
    inner: Arc<Inner>,
}

struct Inner {
    rt: Runtime,
    transport: Arc<Transport>,
    address: [u8; 16],
    inbound_rx: Mutex<mpsc::Receiver<InboundFrame>>,
    running: AtomicBool,
}

/// A minimal local Reticulum TCP node useful for integration tests and local
/// development.
///
/// It carries Reticulum traffic only. It has no Mycellium registry, queue,
/// mailbox, or payload semantics.
#[derive(Clone)]
pub struct ReticulumBackbone {
    _inner: Arc<BackboneInner>,
}

struct BackboneInner {
    _rt: Runtime,
    _transport: Arc<Transport>,
}

impl ReticulumBackbone {
    /// Listen for Reticulum TCP clients on `bind`, for example `[::1]:4242`.
    pub fn tcp(bind: impl Into<String>) -> Result<Self> {
        let private = PrivateIdentity::from_private_key_bytes(&[0x42; 64])
            .map_err(|_| anyhow!("invalid Reticulum backbone identity"))?;
        let rt = Runtime::new().context("could not start Reticulum backbone runtime")?;
        let transport = {
            let _runtime_context = rt.enter();
            Transport::new(TransportConfig::new("mycellium-backbone", &private, true))
        };
        let transport = Arc::new(transport);
        let manager = transport.iface_manager();
        let bind = bind.into();
        rt.block_on(async move {
            let server = TcpServer::new(bind, manager.clone()).with_backbone_client_liveness();
            manager
                .lock()
                .await
                .spawn_as(server, TcpServer::spawn, IfaceRole::Unicast);
        });
        Ok(Self {
            _inner: Arc::new(BackboneInner {
                _rt: rt,
                _transport: transport,
            }),
        })
    }
}

impl ReticulumNode {
    /// Start a Reticulum node from `[x25519 secret][ed25519 signing seed]`.
    pub fn new(private_bytes: [u8; 64], config: ReticulumConfig) -> Result<Self> {
        let private = PrivateIdentity::from_private_key_bytes(&private_bytes)
            .map_err(|_| anyhow!("invalid Reticulum private identity"))?;
        let rt = Runtime::new().context("could not start Reticulum runtime")?;
        let mut transport_config = TransportConfig::new("mycellium", &private, true);
        transport_config.set_retransmit(false);
        let mut transport = {
            let _runtime_context = rt.enter();
            Transport::new(transport_config)
        };
        let destination = rt.block_on(async {
            let destination = transport
                .add_destination(private, DestinationName::new(APP_NAME, APP_ASPECT))
                .await;
            destination
        });
        let address = rt.block_on(async { destination.lock().await.desc.address_hash });

        for node in &config.tcp_nodes {
            let manager = transport.iface_manager();
            let node = node.clone();
            rt.block_on(async move {
                manager.lock().await.spawn_as(
                    TcpClient::new(node).with_backbone_liveness(),
                    TcpClient::spawn,
                    IfaceRole::Unicast,
                );
            });
        }
        rt.block_on(async {
            transport.send_announce(&destination, None).await;
        });

        let (inbound_tx, inbound_rx) = mpsc::channel();
        let node = Self {
            inner: Arc::new(Inner {
                rt,
                transport: Arc::new(transport),
                address: address_bytes(address),
                inbound_rx: Mutex::new(inbound_rx),
                running: AtomicBool::new(true),
            }),
        };
        node.start_forwarders(inbound_tx, address);
        Ok(node)
    }

    /// This node's Reticulum destination address.
    pub fn address(&self) -> [u8; 16] {
        self.inner.address
    }

    /// Receive one inbound frame from any Reticulum link.
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Option<InboundFrame>> {
        if !self.inner.running.load(Ordering::Acquire) {
            return Ok(None);
        }
        match self
            .inner
            .inbound_rx
            .lock()
            .map_err(|_| anyhow!("Reticulum inbound queue is unavailable"))?
            .recv_timeout(timeout)
        {
            Ok(frame) => Ok(Some(frame)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(None),
        }
    }

    /// Send a frame to a signed Reticulum destination and wait for its reply.
    pub fn send_and_wait(
        &self,
        destination: &ReticulumPublicIdentity,
        frame: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let timeout = if timeout.is_zero() {
            DEFAULT_LINK_TIMEOUT
        } else {
            timeout
        };
        let desc = destination_desc(destination)?;
        let transport = self.inner.transport.clone();
        self.inner
            .rt
            .block_on(async move {
                let link = transport.link(desc).await;
                let link_id = *link.lock().await.id();
                let mut data_rx = transport.received_data_events();
                let mut resource_rx = transport.resource_events();

                await_link_activation(&transport, &link, timeout).await?;
                send_on_link(&transport, &link, frame).await?;

                let deadline = Instant::now() + timeout;
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "Reticulum reply timed out",
                        ));
                    }
                    tokio::select! {
                        data = data_rx.recv() => {
                            let Ok(data) = data else { continue };
                            if data.destination == link_id {
                                return Ok(data.data.as_slice().to_vec());
                            }
                        }
                        event = resource_rx.recv() => {
                            let Ok(event) = event else { continue };
                            if event.link_id != link_id {
                                continue;
                            }
                            if let ResourceEventKind::Complete(complete) = event.kind {
                                return Ok(complete.data);
                            }
                        }
                        _ = tokio::time::sleep(remaining.min(Duration::from_millis(250))) => {}
                    }
                }
            })
            .map_err(Into::into)
    }

    /// Stop accepting inbound frames.
    pub fn shutdown(&self) {
        self.inner.running.store(false, Ordering::Release);
    }

    fn start_forwarders(&self, inbound_tx: mpsc::Sender<InboundFrame>, local_address: AddressHash) {
        let node = self.clone();
        let transport = self.inner.transport.clone();
        let mut data_rx = transport.received_data_events();
        let data_tx = inbound_tx.clone();
        self.inner.rt.spawn(async move {
            while let Ok(data) = data_rx.recv().await {
                if data.destination == local_address {
                    continue;
                }
                let _ = data_tx.send(InboundFrame {
                    bytes: data.data.as_slice().to_vec(),
                    reply: ReticulumReply {
                        node: node.clone(),
                        link_id: data.destination,
                    },
                });
            }
        });

        let node = self.clone();
        let transport = self.inner.transport.clone();
        let mut resource_rx = transport.resource_events();
        self.inner.rt.spawn(async move {
            while let Ok(event) = resource_rx.recv().await {
                let ResourceEventKind::Complete(complete) = event.kind else {
                    continue;
                };
                let _ = inbound_tx.send(InboundFrame {
                    bytes: complete.data,
                    reply: ReticulumReply {
                        node: node.clone(),
                        link_id: event.link_id,
                    },
                });
            }
        });
    }

    fn send_on_existing_link(&self, link_id: AddressHash, bytes: &[u8]) -> Result<()> {
        let transport = self.inner.transport.clone();
        self.inner
            .rt
            .block_on(async move {
                let link = match transport.find_in_link(&link_id).await {
                    Some(link) => link,
                    None => transport.find_out_link(&link_id).await.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotConnected, "Reticulum link is gone")
                    })?,
                };
                send_on_link(&transport, &link, bytes).await.map(|_| ())
            })
            .map_err(Into::into)
    }
}

fn destination_desc(destination: &ReticulumPublicIdentity) -> Result<DestinationDesc> {
    if !destination.verify() {
        anyhow::bail!("invalid Reticulum destination identity");
    }
    let identity =
        RnsIdentity::new_from_slices(&destination.encryption_key, &destination.signing_key);
    let desc = rns_transport::destination::SingleOutputDestination::new(
        identity,
        DestinationName::new(APP_NAME, APP_ASPECT),
    )
    .desc;
    if desc.address_hash.as_slice() != destination.address.0.as_slice() {
        anyhow::bail!("Reticulum destination address mismatch");
    }
    Ok(desc)
}

fn address_bytes(address: AddressHash) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(address.as_slice());
    bytes
}
