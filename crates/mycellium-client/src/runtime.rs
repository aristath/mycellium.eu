//! Shared direct-delivery runtime primitives.
//!
//! This is intentionally small: it knows how to push one already-sealed item to
//! a peer-published active device, verify the device ACK, and update local
//! sender-owned outbox state. Shells still own UI, config, discovery policy, and
//! whether they run this once or on a background loop.

use std::sync::{Arc, Mutex};

use anyhow::Result;

use mycellium_core::delivery::{payload_digest, DeliveryAck, MAX_DELIVERY_ID_LEN};
use mycellium_core::identity::{DevicePublicKey, Handle, Identity};
use mycellium_core::offline::Envelope;
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, SignedRecord};
use mycellium_core::storage::Storage;
use mycellium_core::wire;
use mycellium_engine::flow;
use mycellium_engine::groups::{MailItem, PeerFrame};
use mycellium_engine::inbox;
use mycellium_engine::outbox;
use mycellium_engine::peerbook;
use mycellium_engine::reachability::{self, DeliveryPath};
use mycellium_engine::verified;
use mycellium_engine::wireops::device_slot;
use mycellium_storage::filestore::FileStore;
use mycellium_transport::libp2p_net;
use mycellium_transport::link::{FrameReader, FrameWriter};
use mycellium_transport::net;

use crate::{mark_outbox_delivered, park_outbox};

/// Stable delivery id for the exact sealed item bytes.
pub fn delivery_id_for_item(item: &MailItem) -> String {
    hex(&mycellium_core::delivery::payload_digest(&wire::encode(
        item,
    )))
}

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

/// Accept one inbound delivery frame atomically, then ACK only after commit.
#[allow(clippy::too_many_arguments)]
pub fn accept_delivery<W, P>(
    identity: &Identity,
    me: &Handle,
    my_record: &SignedRecord,
    blocked: &[String],
    platform: &mut P,
    store: &mut FileStore,
    writer: &mut W,
    delivery_id: String,
    item: MailItem,
    sink: &mut dyn flow::FlowSink,
) -> bool
where
    W: FrameWriter,
    P: Platform,
{
    if delivery_id.is_empty()
        || delivery_id.len() > MAX_DELIVERY_ID_LEN
        || delivery_id != delivery_id_for_item(&item)
    {
        return false;
    }
    let payload = wire::encode(&item);
    let digest = payload_digest(&payload);
    match inbox::seen(store, &delivery_id, &digest) {
        Ok(inbox::Seen::Duplicate) => {
            send_delivery_ack(identity, writer, delivery_id, &payload);
            return true;
        }
        Ok(inbox::Seen::Collision) | Err(_) => return false,
        Ok(inbox::Seen::New) => {}
    }
    if sender_identity_changed(store, &item) {
        return false;
    }

    let mut tx = store.transaction();
    if !remember_sender(&mut tx, &item) {
        return false;
    }
    let now = platform.now_unix_secs();
    let mut deliver = |store: &mut mycellium_storage::filestore::FileTransaction<'_>,
                       handle: &Handle,
                       _record: &SignedRecord,
                       device: &Device,
                       item: MailItem|
     -> DeliveryPath {
        let delivery_id = delivery_id_for_item(&item);
        match park_outbox(store, delivery_id, handle, device, item, now) {
            Ok(()) => DeliveryPath::Outbox,
            Err(_) => DeliveryPath::Failed,
        }
    };
    let mut buffered = BufferedSink::default();
    if crate::process_item(
        identity,
        &mut tx,
        platform,
        me,
        my_record,
        blocked,
        item,
        &mut buffered,
        &mut deliver,
    ) != flow::ItemOutcome::Accepted
    {
        return false;
    }
    if inbox::record(&mut tx, delivery_id.clone(), digest, now).is_err() {
        return false;
    }
    if tx.commit().is_err() {
        return false;
    }
    for event in buffered.0 {
        sink.emit(event);
    }
    send_delivery_ack(identity, writer, delivery_id, &payload);
    true
}

fn send_delivery_ack<W: FrameWriter>(
    identity: &Identity,
    writer: &mut W,
    delivery_id: String,
    payload: &[u8],
) {
    let frame = PeerFrame::Ack(DeliveryAck::accepted(identity, delivery_id, payload));
    let _ = writer.send_frame(&wire::encode(&frame));
}

fn sender_identity_changed<S: Storage>(store: &S, item: &MailItem) -> bool {
    let Some(env) = envelope_sender(item) else {
        return false;
    };
    verified::level(
        store,
        env.sender_record.record.user_id.as_str(),
        &env.sender_record.record.wallet,
    ) == verified::TrustLevel::Changed
}

fn remember_sender<S: Storage>(store: &mut S, item: &MailItem) -> bool
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    match envelope_sender(item) {
        Some(env) => peerbook::put(store, &env.from, env.sender_record.clone()).is_ok(),
        None => true,
    }
}

fn envelope_sender(item: &MailItem) -> Option<&Envelope> {
    match item {
        MailItem::Direct(env) | MailItem::GroupInvite(env) | MailItem::GroupLeave(env) => Some(env),
        MailItem::GroupText { .. } => None,
    }
}

#[derive(Default)]
struct BufferedSink(Vec<flow::FlowEvent>);

impl flow::FlowSink for BufferedSink {
    fn emit(&mut self, event: flow::FlowEvent) {
        self.0.push(event);
    }
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
    item: MailItem,
    now: u64,
) -> DeliveryPath
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let delivery_id = delivery_id_for_item(&item);
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
