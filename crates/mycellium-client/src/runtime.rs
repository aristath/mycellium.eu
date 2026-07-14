//! Shared direct-delivery runtime primitives.
//!
//! This is intentionally small: it knows how to push one already-sealed item to
//! the stable active Reticulum destination, verify the device ACK, and update
//! local sender-owned outbox state. Shells still own UI, discovery policy, and
//! scheduling.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;

use mycellium_core::delivery::{payload_digest, DeliveryAck, MAX_DELIVERY_ID_LEN};
use mycellium_core::identity::{DevicePublicKey, Handle, Identity};
use mycellium_core::offline::Envelope;
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, SignedRecord};
use mycellium_core::storage::Storage;
use mycellium_core::userid::UserId;
use mycellium_core::wire;
use mycellium_engine::blocklist;
use mycellium_engine::flow;
use mycellium_engine::groups::{MailItem, PeerFrame};
use mycellium_engine::inbox;
use mycellium_engine::outbox;
use mycellium_engine::peerbook;
use mycellium_engine::reachability::{self, DeliveryPath};
use mycellium_engine::verified;
use mycellium_engine::wireops::{device_slot, seal_to_with_record};
use mycellium_storage::filestore::FileStore;
use mycellium_transport::link::{FrameReader, FrameWriter};
use mycellium_transport::reticulum_net::{ReticulumConfig, ReticulumNode};

use crate::registry::RegistryClient;
use crate::{mark_outbox_delivered, park_outbox, park_pairwise_outbox};

/// Stable delivery id for the exact sealed item bytes.
pub fn delivery_id_for_item(item: &MailItem) -> String {
    hex(&mycellium_core::delivery::payload_digest(&wire::encode(
        item,
    )))
}

/// Process-local direct-network actor.
///
/// One Reticulum node is reused for every direct device delivery made by this
/// process. The registry is only used to refresh signed identity records.
#[derive(Clone)]
pub struct DirectNetwork {
    reticulum_private: [u8; 64],
    reticulum: Arc<Mutex<Option<ReticulumNode>>>,
    registry: Arc<Mutex<Option<RegistryPresence>>>,
    running: Arc<AtomicBool>,
}

#[derive(Clone)]
struct RegistryPresence {
    registry_url: String,
}

impl DirectNetwork {
    pub fn new(reticulum_private: [u8; 64]) -> Self {
        Self {
            reticulum_private,
            reticulum: Arc::new(Mutex::new(None)),
            registry: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn with_reticulum(reticulum_private: [u8; 64], node: ReticulumNode) -> Self {
        Self {
            reticulum_private,
            reticulum: Arc::new(Mutex::new(Some(node))),
            registry: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn set_reticulum(&self, node: ReticulumNode) {
        if !self.running.load(Ordering::Acquire) {
            node.shutdown();
            return;
        }
        if let Ok(mut current) = self.reticulum.lock() {
            *current = Some(node);
        }
    }

    pub fn reticulum(&self) -> Option<ReticulumNode> {
        if !self.running.load(Ordering::Acquire) {
            return None;
        }
        let mut node = self.reticulum.lock().ok()?;
        if node.is_none() {
            *node = ReticulumNode::new(self.reticulum_private, ReticulumConfig::from_env()).ok();
        }
        node.clone()
    }

    /// Remember the registry used for signed-record refreshes.
    pub fn use_registry(&self, registry_url: impl Into<String>, _user_id: UserId) {
        if let Ok(mut current) = self.registry.lock() {
            *current = Some(RegistryPresence {
                registry_url: registry_url.into(),
            });
        }
    }

    /// Ensure the Reticulum node exists.
    pub fn ensure_reticulum(&self) -> Result<()> {
        if !self.running.load(Ordering::Acquire) {
            anyhow::bail!("direct network is stopped");
        }
        self.reticulum()
            .ok_or_else(|| anyhow::anyhow!("Reticulum network is unavailable"))
            .map(|_| ())
    }

    /// Fetch the registry's current self-signed record for a user. The record
    /// still has to pass the local peerbook and anti-rollback checks before use.
    fn current_registry_record(&self, user_id: &UserId) -> Result<Option<SignedRecord>> {
        let presence = self
            .registry
            .lock()
            .map_err(|_| anyhow::anyhow!("registry state is unavailable"))?
            .clone();
        let Some(presence) = presence else {
            return Ok(None);
        };
        RegistryClient::new(&presence.registry_url)?.get_record_for_user(user_id.as_str())
    }

    /// Whether this process-local direct network is still active.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Stop the shared Reticulum node.
    pub fn shutdown(&self) {
        if !self.running.swap(false, Ordering::AcqRel) {
            return;
        }
        if let Some(node) = self.reticulum.lock().ok().and_then(|node| node.clone()) {
            node.shutdown();
        }
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
    let Some(node) = network.reticulum() else {
        return false;
    };
    let bytes = match node.send_and_wait(device.reticulum(), &frame, Duration::from_secs(30)) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    verify_delivery_ack(&bytes, delivery_id, &payload, &device.device_key)
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

pub fn verify_delivery_ack(
    bytes: &[u8],
    delivery_id: &str,
    payload: &[u8],
    recipient: &DevicePublicKey,
) -> bool {
    let Ok(PeerFrame::Ack(ack)) = wire::decode::<PeerFrame>(bytes) else {
        return false;
    };
    ack.verify(delivery_id, payload, recipient).is_ok()
}

/// Accept one inbound delivery frame atomically, then ACK only after commit.
#[allow(clippy::too_many_arguments)]
pub fn accept_delivery<P>(
    identity: &Identity,
    me: &Handle,
    my_record: &SignedRecord,
    platform: &mut P,
    store: &mut FileStore,
    delivery_id: String,
    item: MailItem,
    sink: &mut dyn flow::FlowSink,
) -> Option<Vec<u8>>
where
    P: Platform,
{
    if delivery_id.is_empty()
        || delivery_id.len() > MAX_DELIVERY_ID_LEN
        || delivery_id != delivery_id_for_item(&item)
    {
        return None;
    }
    let payload = wire::encode(&item);
    let digest = payload_digest(&payload);
    match inbox::seen(store, &delivery_id, &digest) {
        Ok(inbox::Seen::Duplicate) => {
            return Some(delivery_ack(identity, delivery_id, &payload));
        }
        Ok(inbox::Seen::Collision) | Err(_) => return None,
        Ok(inbox::Seen::New) => {}
    }
    if sender_identity_changed(store, &item) {
        return None;
    }
    let blocked = match blocklist::load(store) {
        Ok(blocked) => blocked,
        // Never turn a corrupt block list into "nobody is blocked".
        Err(_) => return None,
    };

    let mut tx = store.transaction();
    if !remember_sender(&mut tx, &item) {
        return None;
    }
    let now = platform.now_unix_secs();
    let mut deliver = |store: &mut mycellium_storage::filestore::FileTransaction<'_>,
                       handle: &Handle,
                       record: &SignedRecord,
                       device: &Device,
                       item: MailItem,
                       pairwise_plaintext: Option<Vec<u8>>|
     -> DeliveryPath {
        let delivery_id = delivery_id_for_item(&item);
        let parked = match pairwise_plaintext {
            Some(plaintext) => park_pairwise_outbox(
                store,
                delivery_id,
                handle,
                record,
                device,
                item,
                plaintext,
                now,
            ),
            None => park_outbox(store, delivery_id, handle, record, device, item, now),
        };
        match parked {
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
        &blocked,
        item,
        &mut buffered,
        &mut deliver,
    ) != flow::ItemOutcome::Accepted
    {
        return None;
    }
    if inbox::record(&mut tx, delivery_id.clone(), digest, now).is_err() {
        return None;
    }
    if tx.commit().is_err() {
        return None;
    }
    for event in buffered.0 {
        sink.emit(event);
    }
    Some(delivery_ack(identity, delivery_id, &payload))
}

fn delivery_ack(identity: &Identity, delivery_id: String, payload: &[u8]) -> Vec<u8> {
    let frame = PeerFrame::Ack(DeliveryAck::accepted(identity, delivery_id, payload));
    wire::encode(&frame)
}

fn sender_identity_changed<S: Storage>(store: &S, item: &MailItem) -> bool
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
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

/// Device identity authenticated by the application envelope or group sender
/// key.
pub fn mail_item_sender_device(item: &MailItem) -> Option<DevicePublicKey> {
    match item {
        MailItem::Direct(env) | MailItem::GroupInvite(env) | MailItem::GroupLeave(env) => {
            Some(env.sender_record.record.device.device_key)
        }
        MailItem::GroupText { message, .. } => message
            .sender
            .as_slice()
            .try_into()
            .ok()
            .map(DevicePublicKey),
    }
}

#[derive(Default)]
struct BufferedSink(Vec<flow::FlowEvent>);

impl flow::FlowSink for BufferedSink {
    fn emit(&mut self, event: flow::FlowEvent) {
        self.0.push(event);
    }
}

/// Try live direct delivery and return the observed outcome.
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

/// Try one delivery that was already committed to a shared local outbox.
///
/// The network exchange happens without holding the store mutex. The recipient
/// ACK is then recorded locally; if that write fails, the pending entry remains
/// and a later duplicate delivery is safe because recipients deduplicate it.
pub fn attempt_parked_delivery(
    store: &Arc<Mutex<FileStore>>,
    network: &DirectNetwork,
    device: &Device,
    delivery_id: &str,
    item: &MailItem,
    now: u64,
) -> Result<bool> {
    let accepted = direct_push(network, device, delivery_id, item);
    let mut store = store
        .lock()
        .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
    let slot = device_slot(&device.device_key);
    reachability::record(&mut *store, &slot, DeliveryPath::Direct, accepted, now)?;
    outbox::record_attempt(&mut *store, delivery_id, now, accepted)?;
    Ok(accepted)
}

/// Persist before networking, then mark delivered only after a recipient-device
/// ACK. If live delivery fails, the item remains pending in the local outbox.
pub fn deliver_or_park<S: Storage>(
    store: &mut S,
    network: &DirectNetwork,
    recipient: &Handle,
    recipient_record: &SignedRecord,
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
        recipient_record,
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

/// Pairwise form of [`deliver_or_park`]. The plaintext never leaves the
/// encrypted local outbox; it exists solely so a pending envelope can follow
/// the same user to their replacement active device.
#[allow(clippy::too_many_arguments)]
pub fn deliver_pairwise_or_park<S: Storage>(
    store: &mut S,
    network: &DirectNetwork,
    recipient: &Handle,
    recipient_record: &SignedRecord,
    device: &Device,
    item: MailItem,
    plaintext: Vec<u8>,
    now: u64,
) -> DeliveryPath
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let delivery_id = delivery_id_for_item(&item);
    if park_pairwise_outbox(
        store,
        delivery_id.clone(),
        recipient,
        recipient_record,
        device,
        item.clone(),
        plaintext,
        now,
    )
    .is_err()
    {
        return DeliveryPath::Failed;
    }

    if deliver_direct(store, network, device, &delivery_id, &item, now).is_delivered() {
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
pub fn flush_shared_outbox<P: Platform>(
    identity: &Identity,
    platform: &mut P,
    store: &Arc<Mutex<FileStore>>,
    network: &DirectNetwork,
    now: u64,
) -> Result<OutboxFlush> {
    let entries: Vec<_> = {
        let store = store
            .lock()
            .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
        outbox::load(&*store)?
            .into_iter()
            .filter(|entry| entry.is_due(now))
            .collect()
    };
    if entries.is_empty() {
        let waiting = {
            let store = store
                .lock()
                .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
            outbox::len(&*store)?
        };
        return Ok(OutboxFlush {
            delivered: 0,
            waiting,
        });
    }

    let mut delivered = 0;
    for entry in entries {
        let user_id = match UserId::new(entry.recipient_user_id.clone()) {
            Ok(user_id) => user_id,
            Err(_) => {
                let mut store = store
                    .lock()
                    .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
                outbox::mark_failed(&mut *store, &entry.id)?;
                continue;
            }
        };
        if let Ok(Some(record)) = network.current_registry_record(&user_id) {
            let mut store = store
                .lock()
                .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
            // A hostile or stale registry response is ignored; the last locally
            // authenticated record remains the safe fallback.
            let _ = crate::apply_registry_record(&mut *store, user_id.as_str(), record);
        }
        let record = {
            let store = store
                .lock()
                .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
            peerbook::get_by_user_id(&*store, &user_id)?
        };
        let Some(record) = record else {
            let mut store = store
                .lock()
                .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
            outbox::record_attempt(&mut *store, &entry.id, now, false)?;
            continue;
        };
        if record.verify().is_err() {
            let mut store = store
                .lock()
                .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
            outbox::record_attempt(&mut *store, &entry.id, now, false)?;
            continue;
        }
        let device = record.record.device;
        let Some(original_item) = entry.item.as_ref() else {
            let mut store = store
                .lock()
                .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
            outbox::mark_failed(&mut *store, &entry.id)?;
            continue;
        };
        let current_slot = device_slot(&device.device_key);
        let (delivery_id, item) = if current_slot != entry.slot {
            let Some(plaintext) = entry.pairwise_plaintext.as_deref() else {
                // Old entries and group ciphertext cannot be safely transformed
                // into a pairwise envelope for a different device.
                let mut store = store
                    .lock()
                    .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
                outbox::mark_failed(&mut *store, &entry.id)?;
                continue;
            };
            let new_item =
                match readdress_pairwise(identity, platform, original_item, &device, plaintext) {
                    Ok(item) => item,
                    Err(_) => {
                        let mut store = store
                            .lock()
                            .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
                        outbox::mark_failed(&mut *store, &entry.id)?;
                        continue;
                    }
                };
            let new_id = delivery_id_for_item(&new_item);
            let replaced = {
                let mut store = store
                    .lock()
                    .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
                outbox::readdress_pending(
                    &mut *store,
                    &entry.id,
                    new_id.clone(),
                    current_slot,
                    new_item.clone(),
                )?
            };
            if !replaced {
                continue;
            }
            (new_id, new_item)
        } else {
            (entry.id.clone(), original_item.clone())
        };
        if attempt_parked_delivery(store, network, &device, &delivery_id, &item, now)? {
            delivered += 1;
        }
    }

    let waiting = {
        let store = store
            .lock()
            .map_err(|_| anyhow::anyhow!("local store is unavailable"))?;
        outbox::len(&*store)?
    };
    Ok(OutboxFlush { delivered, waiting })
}

fn readdress_pairwise<P: Platform>(
    identity: &Identity,
    platform: &mut P,
    item: &MailItem,
    device: &Device,
    plaintext: &[u8],
) -> Result<MailItem> {
    let (envelope, wrap): (&Envelope, fn(Envelope) -> MailItem) = match item {
        MailItem::Direct(envelope) => (envelope, MailItem::Direct),
        MailItem::GroupInvite(envelope) => (envelope, MailItem::GroupInvite),
        MailItem::GroupLeave(envelope) => (envelope, MailItem::GroupLeave),
        MailItem::GroupText { .. } => anyhow::bail!("group ciphertext is not pairwise"),
    };
    if envelope.sender_record.verify().is_err()
        || envelope.sender_record.record.wallet != identity.wallet_public()
        || envelope.sender_record.record.device.device_key != identity.device_public()
    {
        anyhow::bail!("outbox sender identity does not match this device");
    }
    let sealed = seal_to_with_record(
        platform,
        identity,
        &envelope.from,
        &envelope.sender_record,
        device,
        plaintext,
    )?;
    Ok(wrap(sealed))
}

/// Prepare one pending delivery for the recipient's currently signed active
/// device, atomically replacing its ciphertext and delivery id when needed.
/// `None` means the entry was completed concurrently or cannot be safely
/// readdressed (for example, an old entry without retry material).
pub fn readdress_parked_delivery<S, P>(
    identity: &Identity,
    platform: &mut P,
    store: &mut S,
    entry: &outbox::OutboxEntry,
    device: &Device,
) -> Result<Option<(String, MailItem)>>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
    P: Platform,
{
    let item = entry
        .item
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("pending outbox entry has no ciphertext"))?;
    let slot = device_slot(&device.device_key);
    if slot == entry.slot {
        return Ok(Some((entry.id.clone(), item.clone())));
    }
    let Some(plaintext) = entry.pairwise_plaintext.as_deref() else {
        return Ok(None);
    };
    let item = readdress_pairwise(identity, platform, item, device, plaintext)?;
    let id = delivery_id_for_item(&item);
    if !outbox::readdress_pending(store, &entry.id, id.clone(), slot, item.clone())? {
        return Ok(None);
    }
    Ok(Some((id, item)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{anyhow, Result};
    use std::collections::HashMap;
    use std::convert::Infallible;

    #[derive(Default)]
    struct MemStore(HashMap<Vec<u8>, Vec<u8>>);

    impl Storage for MemStore {
        type Error = Infallible;

        fn get(&self, key: &[u8]) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.0.get(key).cloned())
        }

        fn put(&mut self, key: &[u8], value: &[u8]) -> std::result::Result<(), Self::Error> {
            self.0.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> std::result::Result<(), Self::Error> {
            self.0.remove(key);
            Ok(())
        }
    }

    struct SeededPlatform(u8);

    impl Platform for SeededPlatform {
        fn fill_random(&mut self, bytes: &mut [u8]) {
            for byte in bytes {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }

        fn now_unix_secs(&self) -> u64 {
            1
        }
    }

    struct ScriptedConnection {
        response: Option<Vec<u8>>,
        sent: Vec<Vec<u8>>,
        fail_send: bool,
    }

    impl FrameReader for ScriptedConnection {
        fn recv_frame(&mut self) -> Result<Vec<u8>> {
            self.response
                .take()
                .ok_or_else(|| anyhow!("no scripted response"))
        }
    }

    impl FrameWriter for ScriptedConnection {
        fn send_frame(&mut self, bytes: &[u8]) -> Result<()> {
            if self.fail_send {
                return Err(anyhow!("scripted send failure"));
            }
            self.sent.push(bytes.to_vec());
            Ok(())
        }
    }

    fn connection(response: Vec<u8>) -> ScriptedConnection {
        ScriptedConnection {
            response: Some(response),
            sent: Vec::new(),
            fail_send: false,
        }
    }

    #[test]
    fn delivery_exchange_accepts_only_the_target_devices_exact_ack() {
        let recipient = Identity::generate(&mut SeededPlatform(1)).unwrap();
        let payload = b"sealed-mail-item";
        let delivery_id = "delivery-id";
        let frame = b"delivery-frame";
        let ack = DeliveryAck::accepted(&recipient, delivery_id.into(), payload);
        let mut conn = connection(wire::encode(&PeerFrame::Ack(ack)));

        assert!(exchange_delivery(
            &mut conn,
            frame,
            delivery_id,
            payload,
            &recipient.device_public(),
        ));
        assert_eq!(conn.sent, vec![frame.to_vec()]);
    }

    #[test]
    fn delivery_exchange_rejects_wrong_device_payload_id_and_malformed_frames() {
        let recipient = Identity::generate(&mut SeededPlatform(1)).unwrap();
        let other = Identity::generate(&mut SeededPlatform(99)).unwrap();
        let payload = b"sealed-mail-item";
        let delivery_id = "delivery-id";
        let valid_ack = || {
            wire::encode(&PeerFrame::Ack(DeliveryAck::accepted(
                &recipient,
                delivery_id.into(),
                payload,
            )))
        };

        assert!(!exchange_delivery(
            &mut connection(valid_ack()),
            b"frame",
            delivery_id,
            payload,
            &other.device_public(),
        ));
        assert!(!exchange_delivery(
            &mut connection(valid_ack()),
            b"frame",
            delivery_id,
            b"different-payload",
            &recipient.device_public(),
        ));
        assert!(!exchange_delivery(
            &mut connection(valid_ack()),
            b"frame",
            "different-delivery-id",
            payload,
            &recipient.device_public(),
        ));
        assert!(!exchange_delivery(
            &mut connection(vec![0xff, 0x00]),
            b"frame",
            delivery_id,
            payload,
            &recipient.device_public(),
        ));
    }

    #[test]
    fn delivery_exchange_fails_when_frame_cannot_be_sent_or_ack_is_missing() {
        let recipient = Identity::generate(&mut SeededPlatform(1)).unwrap();
        let mut send_failure = ScriptedConnection {
            response: None,
            sent: Vec::new(),
            fail_send: true,
        };
        let mut missing_ack = ScriptedConnection {
            response: None,
            sent: Vec::new(),
            fail_send: false,
        };

        assert!(!exchange_delivery(
            &mut send_failure,
            b"frame",
            "delivery-id",
            b"payload",
            &recipient.device_public(),
        ));
        assert!(!exchange_delivery(
            &mut missing_ack,
            b"frame",
            "delivery-id",
            b"payload",
            &recipient.device_public(),
        ));
    }

    #[test]
    fn pending_pairwise_delivery_follows_the_same_user_to_a_new_device() {
        let mut platform = SeededPlatform(1);
        let sender = Identity::generate(&mut platform).unwrap();
        let old_recipient = Identity::generate(&mut platform).unwrap();
        let replacement = Identity::adopt(&mut platform, old_recipient.wallet_secret()).unwrap();
        let sender_handle = Handle::new("alice").unwrap();
        let recipient_handle = Handle::new("bob").unwrap();
        let sender_record = peerbook::build_record(&mut platform, &sender, &sender_handle, "Alice");
        let old_record =
            peerbook::build_record(&mut platform, &old_recipient, &recipient_handle, "Bob");
        let replacement_record =
            peerbook::build_record(&mut platform, &replacement, &recipient_handle, "Bob");
        assert_eq!(old_record.record.user_id, replacement_record.record.user_id);
        assert_ne!(
            old_record.record.device.device_key,
            replacement_record.record.device.device_key
        );

        let plaintext = b"message survives device replacement".to_vec();
        let envelope = seal_to_with_record(
            &mut platform,
            &sender,
            &sender_handle,
            &sender_record,
            &old_record.record.device,
            &plaintext,
        )
        .unwrap();
        let item = MailItem::Direct(envelope);
        let old_id = delivery_id_for_item(&item);
        let mut store = MemStore::default();
        crate::park_pairwise_outbox(
            &mut store,
            old_id.clone(),
            &recipient_handle,
            &old_record,
            &old_record.record.device,
            item,
            plaintext.clone(),
            1,
        )
        .unwrap();

        let entry = outbox::load(&store).unwrap().remove(0);
        let (new_id, new_item) = readdress_parked_delivery(
            &sender,
            &mut platform,
            &mut store,
            &entry,
            &replacement_record.record.device,
        )
        .unwrap()
        .unwrap();
        assert_ne!(new_id, old_id);
        let MailItem::Direct(new_envelope) = &new_item else {
            panic!("readdressing changed the mail kind");
        };
        let (_, opened) = mycellium_engine::wireops::open_envelope(&replacement, new_envelope)
            .expect("replacement device decrypts the resealed message");
        assert_eq!(opened, plaintext);
        assert!(mycellium_engine::wireops::open_envelope(&old_recipient, new_envelope).is_err());

        let saved = outbox::load(&store).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].id, new_id);
        assert_eq!(
            saved[0].slot,
            device_slot(&replacement_record.record.device.device_key)
        );
        assert_eq!(
            saved[0].pairwise_plaintext.as_deref(),
            Some(plaintext.as_slice())
        );

        outbox::mark_delivered(&mut store, &new_id).unwrap();
        let final_entry = outbox::load(&store).unwrap().remove(0);
        assert!(final_entry.item.is_none());
        assert!(final_entry.pairwise_plaintext.is_none());
    }
}
