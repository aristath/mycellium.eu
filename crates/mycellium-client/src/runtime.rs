//! Shared direct-delivery runtime primitives.
//!
//! This is intentionally small: it knows how to push one already-sealed item to
//! a peer-published active device, verify the device ACK, and update local
//! sender-owned outbox state. Shells still own UI, config, discovery policy, and
//! whether they run this once or on a background loop.

use std::sync::{Arc, Mutex};

use anyhow::Result;

use mycellium_core::identity::{DevicePublicKey, Handle};
use mycellium_core::record::Device;
use mycellium_core::storage::Storage;
use mycellium_core::wire;
use mycellium_engine::groups::{MailItem, PeerFrame};
use mycellium_engine::outbox;
use mycellium_engine::peerbook;
use mycellium_engine::reachability::{self, DeliveryPath};
use mycellium_engine::wireops::device_slot;
use mycellium_transport::libp2p_net;
use mycellium_transport::link::{FrameReader, FrameWriter};
use mycellium_transport::net;

use crate::{mark_outbox_delivered, park_outbox};

/// Process-local direct-network actor.
///
/// TCP dials directly. libp2p lazily starts one dialer and reuses it for every
/// direct delivery made by this process.
#[derive(Clone)]
pub struct DirectNetwork {
    device_secret: [u8; 32],
    libp2p: Arc<Mutex<Option<libp2p_net::Libp2pDialer>>>,
}

impl DirectNetwork {
    pub fn new(device_secret: [u8; 32]) -> Self {
        Self {
            device_secret,
            libp2p: Arc::new(Mutex::new(None)),
        }
    }

    pub fn with_libp2p(device_secret: [u8; 32], dialer: libp2p_net::Libp2pDialer) -> Self {
        Self {
            device_secret,
            libp2p: Arc::new(Mutex::new(Some(dialer))),
        }
    }

    pub fn libp2p(&self) -> Option<libp2p_net::Libp2pDialer> {
        let mut dialer = self.libp2p.lock().ok()?;
        if dialer.is_none() {
            *dialer = libp2p_net::Libp2pDialer::new(self.device_secret).ok();
        }
        dialer.clone()
    }
}

/// Directly push one already-sealed mail item to a recipient active device.
pub fn direct_push(
    network: &DirectNetwork,
    device: &Device,
    delivery_id: &str,
    item: &MailItem,
) -> bool {
    let payload = wire::encode(item);
    let frame = PeerFrame::Delivery {
        delivery_id: delivery_id.to_string(),
        item: Box::new(item.clone()),
    };
    let frame = wire::encode(&frame);
    match direct_transport(&device.peer_id().0) {
        DirectTransport::None => false,
        DirectTransport::Tcp => {
            let addr = String::from_utf8_lossy(&device.peer_id().0);
            let Ok(mut conn) = net::TcpConnection::connect(&addr) else {
                return false;
            };
            exchange_delivery(&mut conn, &frame, delivery_id, &payload, &device.device_key)
        }
        DirectTransport::Libp2p => {
            let addr = String::from_utf8_lossy(&device.peer_id().0);
            let Some(dialer) = network.libp2p() else {
                return false;
            };
            match dialer.dial_str(&addr) {
                Ok(mut conn) => {
                    exchange_delivery(&mut conn, &frame, delivery_id, &payload, &device.device_key)
                }
                Err(_) => false,
            }
        }
    }
}

/// Send a delivery frame and accept only an ACK signed by the target device for
/// the exact delivery id and payload bytes.
pub fn exchange_delivery<C>(
    conn: &mut C,
    frame: &[u8],
    delivery_id: &str,
    payload: &[u8],
    recipient: &DevicePublicKey,
) -> bool
where
    C: FrameReader + FrameWriter,
{
    if conn.send_frame(frame).is_err() {
        return false;
    }
    let Ok(bytes) = conn.recv_frame() else {
        return false;
    };
    let Ok(PeerFrame::Ack(ack)) = wire::decode::<PeerFrame>(&bytes) else {
        return false;
    };
    ack.verify(delivery_id, payload, recipient).is_ok()
}

/// Try live direct delivery and record reachability evidence locally.
pub fn deliver_direct<S: Storage>(
    store: &mut S,
    network: &DirectNetwork,
    device: &Device,
    delivery_id: &str,
    item: &MailItem,
    now: u64,
) -> DeliveryPath
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let key = device_slot(&device.device_key);
    let ok = direct_push(network, device, delivery_id, item);
    let _ = reachability::record(store, &key, DeliveryPath::Direct, ok, now);
    if ok {
        DeliveryPath::Direct
    } else {
        DeliveryPath::Failed
    }
}

/// Persist before networking, then mark delivered only after a recipient-device
/// ACK. If live delivery fails, the item remains pending in the local outbox.
pub fn deliver_or_park<S: Storage>(
    store: &mut S,
    network: &DirectNetwork,
    recipient: &Handle,
    device: &Device,
    delivery_id: String,
    item: MailItem,
    now: u64,
) -> DeliveryPath
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    if park_outbox(
        store,
        delivery_id.clone(),
        recipient,
        device,
        item.clone(),
        now,
    )
    .is_err()
    {
        return DeliveryPath::Failed;
    }

    if deliver_direct(store, network, device, &delivery_id, &item, now).is_delivered() {
        // Acceptance is already proven. If cleanup fails, leaving the entry is
        // safe: the recipient deduplicates the retry and returns the ACK again.
        let _ = mark_outbox_delivered(store, &delivery_id);
        DeliveryPath::Direct
    } else {
        DeliveryPath::Outbox
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutboxFlush {
    pub delivered: usize,
    pub waiting: usize,
}

/// Run one local outbox flush using known signed peer records only.
///
/// Discovery policy is deliberately outside this helper. Callers that want DHT
/// refresh can import records before calling this, or keep their richer loop.
pub fn flush_due_outbox<S: Storage>(
    store: &mut S,
    network: &DirectNetwork,
    now: u64,
) -> Result<OutboxFlush>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let entries = outbox::load(store)?;
    if entries.is_empty() {
        return Ok(OutboxFlush::default());
    }

    let (delivered, remaining) = outbox::flush_pass(entries, now, |entry| {
        let Ok(handle) = Handle::new(entry.recipient.clone()) else {
            return outbox::Attempt::Drop;
        };
        let record = match peerbook::get(store, &handle) {
            Ok(Some(record)) => record,
            Ok(None) | Err(_) => return outbox::Attempt::Retry,
        };
        if record.verify().is_err() {
            return outbox::Attempt::Retry;
        }
        let device = &record.record.device;
        if device_slot(&device.device_key) != entry.slot {
            return outbox::Attempt::Drop;
        }
        if deliver_direct(store, network, device, &entry.id, &entry.item, now).is_delivered() {
            outbox::Attempt::Delivered
        } else {
            outbox::Attempt::Retry
        }
    });
    let waiting = remaining.iter().filter(|entry| entry.is_pending()).count();
    outbox::save(store, &remaining)?;
    Ok(OutboxFlush { delivered, waiting })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectTransport {
    Tcp,
    Libp2p,
    None,
}

fn direct_transport(peer_id: &[u8]) -> DirectTransport {
    match core::str::from_utf8(peer_id) {
        Ok("") => DirectTransport::None,
        Ok(addr) if addr.starts_with('/') => DirectTransport::Libp2p,
        Ok(_) => DirectTransport::Tcp,
        Err(_) => DirectTransport::None,
    }
}
