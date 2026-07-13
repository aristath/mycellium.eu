//! Native hard-serverless CLI orchestration.
//!
//! This app layer has no directory, queue, relay, mailbox, push, or hosted
//! rendezvous dependency. It keeps signed peer records locally, sends only over
//! direct peer-to-peer transports, and parks undelivered messages in the local
//! outbox.
#![allow(clippy::too_many_arguments)]

use std::sync::{mpsc, Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};

use mycellium_client as client;
use mycellium_core::delivery::{payload_digest, DeliveryAck, MAX_DELIVERY_ID_LEN};
use mycellium_core::group::Group;
use mycellium_core::identity::{DevicePublicKey, Handle, Identity, WalletPublicKey};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::offline::Envelope;
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, SignedRecord};
use mycellium_core::safety;
use mycellium_core::storage::Storage;
use mycellium_core::transport::Transport;
use mycellium_core::userid::user_id;
use mycellium_core::wire;

use mycellium_storage::filestore::FileStore;
use mycellium_storage::store;
use mycellium_transport::libp2p_net::{self};
use mycellium_transport::link::{FrameReader, FrameWriter};
use mycellium_transport::net::{self, TcpTransport};

use crate::platform::OsPlatform;
use mycellium_engine::contacts::{self, Contact};
use mycellium_engine::groups::{self, MailItem, PeerFrame, StoredGroup};
use mycellium_engine::peerbook;
use mycellium_engine::reachability::{self, DeliveryPath};
#[cfg(test)]
use mycellium_engine::wireops;
use mycellium_engine::{blocklist, draft, expiry, flow, history, inbox, outbox, verified};

mod backup;
mod util;

pub use backup::*;
pub use util::*;

// ---- identity / records -----------------------------------------------------

pub fn identity_new() -> Result<()> {
    if store::exists() {
        bail!("an identity already exists at {}", store::path().display());
    }
    let identity = client::create_identity(&mut OsPlatform)?;
    store::save_identity(&identity)?;
    println!("New identity created.");
    println!("wallet: {}", hex(&identity.wallet_public().0));
    println!("device: {}", hex(&identity.device_public().0));
    Ok(())
}

pub fn identity_show() -> Result<()> {
    let identity = store::load_identity()?;
    println!("wallet:    {}", hex(&identity.wallet_public().0));
    println!("device:    {}", hex(&identity.device_public().0));
    println!("device-id: {}", short_device_id(&identity.device_public()));
    println!("messaging: {}", hex(&identity.messaging_public().0));
    Ok(())
}

pub fn identity_export_wallet(yes: bool) -> Result<()> {
    if !yes {
        bail!("refusing to print the wallet secret without --yes");
    }
    let identity = store::load_identity()?;
    println!("{}", hex(&identity.wallet_secret()));
    Ok(())
}

pub fn identity_adopt(wallet_secret: &str) -> Result<()> {
    if store::exists() {
        bail!("an identity already exists at {}", store::path().display());
    }
    let wallet_secret = hex_32(wallet_secret)?;
    let identity = client::adopt_identity(&mut OsPlatform, wallet_secret)?;
    store::save_identity(&identity)?;
    println!("Adopted wallet on a fresh device.");
    println!("wallet: {}", hex(&identity.wallet_public().0));
    println!("device: {}", hex(&identity.device_public().0));
    Ok(())
}

pub fn register(handle: &str, addr: &str, libp2p: bool) -> Result<()> {
    let identity = store::load_identity()?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let location = if libp2p {
        libp2p_net::advertised_multiaddr(addr, identity.device_secret())?
    } else {
        addr.to_string()
    };

    let mut fs = open_history(&identity)?;
    let name = display_name_for(&handle);
    let signed = client::publish_active_device_record(
        &mut fs,
        &mut OsPlatform,
        &identity,
        &handle,
        &name,
        &location,
    )?;
    println!("registered '{}' locally at {}", handle.as_str(), location);
    println!("record: {}", peerbook::encode(&signed));
    report_configured_dht_publish(&identity, &handle, &signed);
    Ok(())
}

pub fn record_export(handle: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let record = client::require_record(&fs, &handle).map_err(|_| {
        anyhow!(
            "no local record for '{}' — run `register` or `record import`",
            handle.as_str()
        )
    })?;
    println!("{}", peerbook::encode(&record));
    Ok(())
}

pub fn record_import(handle: &str, encoded: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let record = peerbook::decode(encoded)?;
    client::import_record(&mut fs, &handle, record)?;
    println!("imported signed record for '{}'", handle.as_str());
    Ok(())
}

pub fn records_list() -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let records = client::list_records(&fs)?;
    if records.is_empty() {
        println!("no local peer records");
        return Ok(());
    }
    for entry in records {
        println!(
            "{}  wallet={}  active_device={}",
            entry.handle,
            hex(&entry.record.record.wallet.0),
            short_device_id(&entry.record.record.device.device_key)
        );
    }
    Ok(())
}

pub fn list_device(handle: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let record = client::require_record(&fs, &handle)?;
    let d = &record.record.device;
    println!("active device for '{}':", handle.as_str());
    println!(
        "  {}  {}",
        short_device_id(&d.device_key),
        String::from_utf8_lossy(&d.peer_id().0)
    );
    Ok(())
}

pub fn remove_record(handle: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    if client::remove_record(&mut fs, &handle)? {
        println!("removed local record for '{}'", handle.as_str());
    } else {
        println!("no local record for '{}'", handle.as_str());
    }
    Ok(())
}

pub fn discover(peer: &str, want: &[String]) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let (peer_handle, peer_record) = resolve_record(&mut fs, peer)?;
    let network = DirectNetwork::new(identity.device_secret());
    let device = &peer_record.record.device;
    let detail = match request_discovery_from_device(&network, device, want) {
        Ok(records) => {
            let report = peerbook::import_records(&mut fs, records);
            println!(
                "discovered through '{}' — imported {} record(s), skipped {}",
                peer_handle.as_str(),
                report.imported,
                report.skipped.len()
            );
            for (handle, reason) in report.skipped {
                eprintln!("skipped {handle}: {reason}");
            }
            return Ok(());
        }
        Err(err) => err.to_string(),
    };
    bail!(
        "could not discover through '{}': {detail}",
        peer_handle.as_str()
    )
}

pub fn dht_serve(addr: &str, bootstrap: &[String]) -> Result<()> {
    let identity = store::load_identity()?;
    let listen_addr = libp2p_net::listen_multiaddr(addr).context("bad DHT listen address")?;
    let bootstrap = effective_bootstrap(bootstrap)?;
    println!("starting DHT discovery node on {addr}");
    libp2p_net::dht_serve(identity.device_secret(), listen_addr, bootstrap)
}

pub fn dht_publish(handle: &str, listen: Option<&str>, bootstrap: &[String]) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let record = own_record(&fs, &handle)?;
    let listen_addr = listen
        .map(libp2p_net::listen_multiaddr)
        .transpose()
        .context("bad DHT listen address")?;
    let bootstrap = effective_bootstrap(bootstrap)?;
    libp2p_net::dht_put(
        identity.device_secret(),
        listen_addr,
        bootstrap,
        dht_record_key(&handle),
        wire::encode(&record),
    )?;
    println!(
        "published signed record for '{}' to the DHT",
        handle.as_str()
    );
    Ok(())
}

pub fn dht_lookup(handle: &str, listen: Option<&str>, bootstrap: &[String]) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let listen_addr = listen
        .map(libp2p_net::listen_multiaddr)
        .transpose()
        .context("bad DHT listen address")?;
    let bootstrap = effective_bootstrap(bootstrap)?;
    let candidates = libp2p_net::dht_get_records(
        identity.device_secret(),
        listen_addr,
        bootstrap,
        dht_record_key(&handle),
    )?;
    let wallet = trusted_wallet(&fs, &handle)?;
    let (best, skipped) = best_dht_record_candidate(&handle, candidates, wallet)?;
    let Some(record) = best else {
        bail!("no DHT record found for '{}'", handle.as_str());
    };
    peerbook::put(&mut fs, &handle, record)?;
    if skipped > 0 {
        println!(
            "imported signed DHT record for '{}' (skipped {skipped} invalid candidate(s))",
            handle.as_str()
        );
    } else {
        println!("imported signed DHT record for '{}'", handle.as_str());
    }
    Ok(())
}

// ---- direct delivery --------------------------------------------------------

/// Process-local direct-network actor. TCP deposits open ordinary sockets;
/// libp2p deposits lazily start one swarm and reuse it for every device copy,
/// discovery request, and retry made by this process.
#[derive(Clone)]
struct DirectNetwork {
    device_secret: [u8; 32],
    libp2p: Arc<Mutex<Option<libp2p_net::Libp2pDialer>>>,
}

impl DirectNetwork {
    fn new(device_secret: [u8; 32]) -> Self {
        Self {
            device_secret,
            libp2p: Arc::new(Mutex::new(None)),
        }
    }

    fn with_libp2p(device_secret: [u8; 32], dialer: libp2p_net::Libp2pDialer) -> Self {
        Self {
            device_secret,
            libp2p: Arc::new(Mutex::new(Some(dialer))),
        }
    }

    fn libp2p(&self) -> Option<libp2p_net::Libp2pDialer> {
        let mut dialer = self.libp2p.lock().ok()?;
        if dialer.is_none() {
            *dialer = libp2p_net::Libp2pDialer::new(self.device_secret).ok();
        }
        dialer.clone()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn send(
    peer: &str,
    whoami: &str,
    message: Option<&str>,
    reply_to: Option<&str>,
    react: Option<&str>,
    to: Option<&str>,
    file: Option<&str>,
    edit: Option<&str>,
    delete: Option<&str>,
    expire: Option<&str>,
) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let mut fs = open_history(&identity)?;
    let network = DirectNetwork::new(identity.device_secret());
    let _ = flush_outbox_with_network(&identity, &mut fs, &network);
    let (peer_handle, peer_record) = lookup_verified(&mut fs, peer)?;

    let expires_at = resolve_expiry(&fs, peer_handle.as_str(), expire)?;
    let app = build_message(message, reply_to, react, to, file, edit, delete, expires_at)?;
    let now = OsPlatform.now_unix_secs();
    let my_record = own_record(&fs, &me)?;
    let net = client::LocalNet::load(&fs);

    let mut deliver =
        |store: &mut FileStore,
         handle: &Handle,
         _record: &SignedRecord,
         device: &Device,
         item: MailItem|
         -> DeliveryPath { deliver_or_park(store, &network, handle, device, item, now) };
    let mut self_deliver =
        |store: &mut FileStore, handle: &Handle, device: &Device, item: MailItem| {
            let _ = deliver_or_park(store, &network, handle, device, item, now);
        };

    let out = flow::send_app(
        &identity,
        &mut fs,
        &mut OsPlatform,
        &net,
        &me,
        &my_record,
        &peer_handle,
        &peer_record,
        &app,
        &mut deliver,
        &mut self_deliver,
    )?;

    let total = out.delivered + out.outboxed + out.failed;
    print_delivery_summary(
        peer_handle.as_str(),
        &out.id,
        out.delivered,
        out.outboxed,
        out.failed,
        total,
    );
    Ok(())
}

fn print_delivery_summary(
    peer: &str,
    id: &str,
    delivered: u32,
    pending: u32,
    failed: u32,
    total: u32,
) {
    println!(
        "{}",
        delivery_summary(peer, id, delivered, pending, failed, total)
    );
}

fn delivery_summary(
    peer: &str,
    id: &str,
    delivered: u32,
    pending: u32,
    failed: u32,
    total: u32,
) -> String {
    if failed > 0 {
        format!(
            "delivery to '{peer}' incomplete — {delivered} accepted, {pending} pending locally, {failed} not saved (#{id})"
        )
    } else if pending == 0 {
        format!("delivered to '{peer}' — {delivered}/{total} active device (#{id})")
    } else if delivered == 0 {
        format!("saved for '{peer}' — waiting for direct delivery to active device (#{id})")
    } else {
        format!(
            "partially delivered to '{peer}' — {delivered} accepted, {pending} pending locally (#{id})"
        )
    }
}

pub fn serve(addr: &str, whoami: &str, libp2p: bool) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let fs = open_history(&identity)?;
    let blocked = blocklist::load(&fs)?;
    let my_record = own_record(&fs, &me)?;
    let identity = Arc::new(identity);
    let me = Arc::new(me);
    let my_record = Arc::new(my_record);
    let blocked = Arc::new(blocked);
    let fs = Arc::new(Mutex::new(fs));
    crate::print_engine_diagnostics();

    if libp2p {
        let listen_addr = libp2p_net::listen_multiaddr(addr).context("bad serve address")?;
        let mut node = libp2p_net::Libp2pNode::new(identity.device_secret(), Some(listen_addr))
            .context("could not start libp2p node")?;
        let network = DirectNetwork::with_libp2p(identity.device_secret(), node.dialer());
        if let Ok(mut store) = fs.lock() {
            let _ = flush_outbox_with_network(&identity, &mut store, &network);
        }
        start_retry_worker(Arc::clone(&identity), Arc::clone(&fs), network);
        println!(
            "serving (libp2p) on {addr} as {} ({})",
            me.as_str(),
            node.peer_id()
        );
        let workers = connection_workers(
            Arc::clone(&identity),
            Arc::clone(&me),
            Arc::clone(&my_record),
            Arc::clone(&blocked),
            Arc::clone(&fs),
        );
        loop {
            let conn = match node.accept() {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            if workers.send(conn).is_err() {
                bail!("connection workers stopped");
            }
        }
    } else {
        let mut transport = TcpTransport::listening(addr).context("could not bind address")?;
        let network = DirectNetwork::new(identity.device_secret());
        if let Ok(mut store) = fs.lock() {
            let _ = flush_outbox_with_network(&identity, &mut store, &network);
        }
        start_retry_worker(Arc::clone(&identity), Arc::clone(&fs), network);
        println!("serving on {addr} as {}", me.as_str());
        let workers = connection_workers(
            Arc::clone(&identity),
            Arc::clone(&me),
            Arc::clone(&my_record),
            Arc::clone(&blocked),
            Arc::clone(&fs),
        );
        loop {
            let conn = match transport.accept() {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            if workers.send(conn).is_err() {
                bail!("connection workers stopped");
            }
        }
    }
}

fn connection_workers<C>(
    identity: Arc<Identity>,
    me: Arc<Handle>,
    my_record: Arc<SignedRecord>,
    blocked: Arc<Vec<String>>,
    fs: Arc<Mutex<FileStore>>,
) -> mpsc::SyncSender<C>
where
    C: FrameReader + FrameWriter + Send + 'static,
{
    let count = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(2)
        .max(2);
    let (sender, receiver) = mpsc::sync_channel::<C>(count * 2);
    let receiver = Arc::new(Mutex::new(receiver));
    for _ in 0..count {
        let receiver = Arc::clone(&receiver);
        let identity = Arc::clone(&identity);
        let me = Arc::clone(&me);
        let my_record = Arc::clone(&my_record);
        let blocked = Arc::clone(&blocked);
        let fs = Arc::clone(&fs);
        std::thread::spawn(move || loop {
            let conn = {
                let Ok(receiver) = receiver.lock() else {
                    return;
                };
                match receiver.recv() {
                    Ok(conn) => conn,
                    Err(_) => return,
                }
            };
            serve_connection(conn, &identity, &me, &my_record, &blocked, &fs);
        });
    }
    sender
}

fn start_retry_worker(identity: Arc<Identity>, fs: Arc<Mutex<FileStore>>, network: DirectNetwork) {
    std::thread::spawn(move || loop {
        retry_due_deliveries(&identity, &fs, &network);
        std::thread::sleep(std::time::Duration::from_secs(5));
    });
}

fn retry_due_deliveries(identity: &Identity, fs: &Mutex<FileStore>, network: &DirectNetwork) {
    enum Target {
        Device(Handle, Device),
        Retry,
        Drop,
    }

    let now = OsPlatform.now_unix_secs();
    let due: Vec<outbox::OutboxEntry> = {
        let Ok(fs) = fs.lock() else {
            return;
        };
        match outbox::load(&*fs) {
            Ok(entries) => entries
                .into_iter()
                .filter(|entry| entry.is_due(now))
                .collect(),
            Err(_) => return,
        }
    };

    for entry in due {
        let target = {
            let Ok(fs) = fs.lock() else {
                return;
            };
            match Handle::new(entry.recipient.clone()) {
                Err(_) => Target::Drop,
                Ok(handle) => match peerbook::get(&*fs, &handle) {
                    Ok(Some(record)) => {
                        let device = record.record.device;
                        if device_slot(&device.device_key) == entry.slot {
                            Target::Device(handle, device)
                        } else {
                            Target::Drop
                        }
                    }
                    Ok(None) | Err(_) => Target::Retry,
                },
            }
        };

        if matches!(target, Target::Drop) {
            if let Ok(mut fs) = fs.lock() {
                let _ = outbox::mark_failed(&mut *fs, &entry.id);
            }
            continue;
        }

        let mut accepted = match &target {
            Target::Device(_, device) => direct_push(network, device, &entry.id, &entry.item),
            Target::Retry => false,
            Target::Drop => unreachable!(),
        };

        let Ok(mut guard) = fs.lock() else {
            return;
        };
        if let Target::Device(handle, device) = &target {
            let _ = reachability::record(
                &mut *guard,
                &device_slot(&device.device_key),
                DeliveryPath::Direct,
                accepted,
                now,
            );
            if !accepted {
                if let Some(fresh) =
                    refresh_delivery_device(identity, &mut guard, handle, &entry.slot)
                {
                    drop(guard);
                    accepted = direct_push(network, &fresh, &entry.id, &entry.item);
                    let Ok(mut reopened) = fs.lock() else {
                        return;
                    };
                    let _ = reachability::record(
                        &mut *reopened,
                        &device_slot(&fresh.device_key),
                        DeliveryPath::Direct,
                        accepted,
                        now,
                    );
                    let _ = outbox::record_attempt(&mut *reopened, &entry.id, now, accepted);
                    continue;
                }
            }
        }
        let _ = outbox::record_attempt(&mut *guard, &entry.id, now, accepted);
    }
}

fn serve_connection<C>(
    mut conn: C,
    identity: &Identity,
    me: &Handle,
    my_record: &SignedRecord,
    blocked: &[String],
    fs: &Mutex<FileStore>,
) where
    C: FrameReader + FrameWriter,
{
    let mut platform = OsPlatform;
    while let Ok(bytes) = conn.recv_frame() {
        let Ok(frame) = wire::decode::<PeerFrame>(&bytes) else {
            continue;
        };
        let Ok(mut fs) = fs.lock() else {
            return;
        };
        if handle_discovery_frame(&mut fs, &mut conn, &frame) {
            crate::print_engine_diagnostics();
            continue;
        }
        if let PeerFrame::Delivery { delivery_id, item } = frame {
            handle_delivery_frame(
                identity,
                me,
                my_record,
                blocked,
                &mut platform,
                &mut fs,
                &mut conn,
                delivery_id,
                *item,
            );
        }
        crate::print_engine_diagnostics();
    }
}

pub fn outbox_list() -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let entries = outbox::load(&fs)?;
    print_outbox_entries(&entries);
    Ok(())
}

pub fn outbox_retry() -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    outbox::make_all_due(&mut fs)?;
    let (delivered, _) = flush_outbox(&identity, &mut fs)?;
    if delivered > 0 {
        println!(
            "delivered {delivered} pending {}",
            plural(delivered, "message", "messages")
        );
    }
    let entries = outbox::load(&fs)?;
    print_outbox_entries(&entries);
    Ok(())
}

pub fn outbox_cancel(id: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let mut entries = outbox::load(&fs)?;
    if entries.is_empty() {
        println!("outbox empty");
        return Ok(());
    }

    if id == "all" {
        let mut removed = 0usize;
        for entry in entries.iter_mut().filter(|entry| entry.is_pending()) {
            entry.status = outbox::OutboxStatus::Cancelled;
            entry.send_after = 0;
            removed += 1;
        }
        outbox::save(&mut fs, &entries)?;
        println!(
            "cancelled {removed} pending local delivery {}",
            plural(removed, "item", "items")
        );
        return Ok(());
    }

    let matches: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| entry.id.starts_with(id).then_some(index))
        .collect();
    match matches.len() {
        0 => bail!("no pending local delivery item matches '{id}'"),
        1 => {
            let entry = &mut entries[matches[0]];
            if !entry.is_pending() {
                bail!(
                    "local delivery {} is already {:?}",
                    short_outbox_id(&entry.id),
                    entry.status
                );
            }
            entry.status = outbox::OutboxStatus::Cancelled;
            entry.send_after = 0;
            let removed_id = entry.id.clone();
            let removed_recipient = entry.recipient.clone();
            outbox::save(&mut fs, &entries)?;
            println!(
                "cancelled pending local delivery {} for '{}'",
                short_outbox_id(&removed_id),
                removed_recipient
            );
        }
        n => bail!("'{id}' matches {n} pending items; use a longer id prefix"),
    }
    Ok(())
}

fn print_outbox_entries(entries: &[outbox::OutboxEntry]) {
    let pending = entries.iter().filter(|entry| entry.is_pending()).count();
    if pending == 0 {
        println!("outbox empty");
        let delivered = entries
            .iter()
            .filter(|entry| entry.status == outbox::OutboxStatus::Delivered)
            .count();
        let failed = entries
            .iter()
            .filter(|entry| entry.status == outbox::OutboxStatus::Failed)
            .count();
        let cancelled = entries
            .iter()
            .filter(|entry| entry.status == outbox::OutboxStatus::Cancelled)
            .count();
        if delivered + failed + cancelled > 0 {
            println!("recorded: {delivered} delivered, {failed} failed, {cancelled} cancelled");
        }
        return;
    }
    let now = OsPlatform.now_unix_secs();
    println!(
        "{} pending local delivery {}:",
        pending,
        plural(pending, "item", "items")
    );
    for e in entries.iter().filter(|entry| entry.is_pending()) {
        println!(
            "  {} -> {}  (device {}, {}s old, {} {})",
            short_outbox_id(&e.id),
            e.recipient,
            &e.slot[..8.min(e.slot.len())],
            now.saturating_sub(e.created_at),
            e.attempts,
            plural(e.attempts as usize, "attempt", "attempts")
        );
    }
}

fn short_outbox_id(id: &str) -> &str {
    &id[..12.min(id.len())]
}

pub fn flush_outbox(identity: &Identity, fs: &mut FileStore) -> Result<(usize, usize)> {
    let network = DirectNetwork::new(identity.device_secret());
    flush_outbox_with_network(identity, fs, &network)
}

fn flush_outbox_with_network(
    identity: &Identity,
    fs: &mut FileStore,
    network: &DirectNetwork,
) -> Result<(usize, usize)> {
    let entries = outbox::load(fs)?;
    if entries.is_empty() {
        return Ok((0, 0));
    }
    let now = OsPlatform.now_unix_secs();
    let (delivered, remaining) = outbox::flush_pass(entries, now, |entry| {
        let Ok(handle) = Handle::new(entry.recipient.clone()) else {
            return outbox::Attempt::Drop;
        };
        let mut record = match peerbook::get(fs, &handle) {
            Ok(record) => record,
            Err(_) => return outbox::Attempt::Retry,
        };
        if record.is_none() {
            let _ = import_from_configured_dht(identity, fs, &handle);
            record = match peerbook::get(fs, &handle) {
                Ok(record) => record,
                Err(_) => return outbox::Attempt::Retry,
            };
        }
        let Some(record) = record else {
            return outbox::Attempt::Retry;
        };
        if record.verify().is_err() {
            return outbox::Attempt::Retry;
        }
        let device = &record.record.device;
        if device_slot(&device.device_key) != entry.slot {
            return outbox::Attempt::Drop;
        }
        if deliver_direct(fs, network, device, &entry.id, &entry.item, now).is_delivered() {
            outbox::Attempt::Delivered
        } else if let Some(device) = refresh_delivery_device(identity, fs, &handle, &entry.slot) {
            if deliver_direct(fs, network, &device, &entry.id, &entry.item, now).is_delivered() {
                outbox::Attempt::Delivered
            } else {
                outbox::Attempt::Retry
            }
        } else {
            outbox::Attempt::Retry
        }
    });
    let waiting = remaining.iter().filter(|entry| entry.is_pending()).count();
    outbox::save(fs, &remaining)?;
    Ok((delivered, waiting))
}

fn deliver_direct(
    store: &mut FileStore,
    network: &DirectNetwork,
    device: &Device,
    delivery_id: &str,
    item: &MailItem,
    now: u64,
) -> DeliveryPath {
    let key = device_slot(&device.device_key);
    let ok = direct_push(network, device, delivery_id, item);
    let _ = reachability::record(store, &key, DeliveryPath::Direct, ok, now);
    if ok {
        DeliveryPath::Direct
    } else {
        DeliveryPath::Failed
    }
}

fn direct_push(
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

fn exchange_delivery<C>(
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

/// Persist before networking, then remove only after a recipient-device ACK.
fn deliver_or_park(
    store: &mut FileStore,
    network: &DirectNetwork,
    recipient: &Handle,
    device: &Device,
    item: MailItem,
    now: u64,
) -> DeliveryPath {
    let delivery_id = random_id();
    let slot = device_slot(&device.device_key);
    if outbox::enqueue(
        store,
        delivery_id.clone(),
        recipient.as_str(),
        &slot,
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
        let _ = outbox::mark_delivered(store, &delivery_id);
        DeliveryPath::Direct
    } else {
        DeliveryPath::Outbox
    }
}

/// Persist a follow-up generated while accepting inbound mail. The acceptance
/// ACK must not wait on more network I/O; the background retry worker delivers
/// this item after the receive transaction releases local state.
fn park_delivery<S: Storage>(
    store: &mut S,
    recipient: &Handle,
    device: &Device,
    item: MailItem,
    now: u64,
) -> DeliveryPath {
    let delivery_id = random_id();
    let slot = device_slot(&device.device_key);
    match outbox::enqueue(store, delivery_id, recipient.as_str(), &slot, item, now) {
        Ok(()) => DeliveryPath::Outbox,
        Err(_) => DeliveryPath::Failed,
    }
}

fn request_discovery_from_device(
    network: &DirectNetwork,
    device: &Device,
    want: &[String],
) -> Result<Vec<groups::DiscoveryRecord>> {
    let request = PeerFrame::DiscoveryRequest {
        want: want.to_vec(),
    };
    let frame = wire::encode(&request);
    match direct_transport(&device.peer_id().0) {
        DirectTransport::None => bail!("device has no dialable address"),
        DirectTransport::Tcp => {
            let addr = String::from_utf8_lossy(&device.peer_id().0);
            let mut conn = net::TcpConnection::connect(&addr)
                .with_context(|| format!("could not connect to {addr}"))?;
            conn.send_frame(&frame)?;
            decode_discovery_response(&conn.recv_frame()?)
        }
        DirectTransport::Libp2p => {
            let addr = String::from_utf8_lossy(&device.peer_id().0);
            let dialer = network
                .libp2p()
                .ok_or_else(|| anyhow!("could not start libp2p network actor"))?;
            let mut conn = dialer
                .dial_str(&addr)
                .with_context(|| format!("could not connect to {addr}"))?;
            conn.send_frame(&frame)?;
            decode_discovery_response(&conn.recv_frame()?)
        }
    }
}

fn decode_discovery_response(frame: &[u8]) -> Result<Vec<groups::DiscoveryRecord>> {
    match wire::decode::<PeerFrame>(frame)? {
        PeerFrame::DiscoveryResponse { records } => Ok(records),
        _ => bail!("peer returned a non-discovery frame"),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_delivery_frame<W: FrameWriter>(
    identity: &Identity,
    me: &Handle,
    my_record: &SignedRecord,
    blocked: &[String],
    platform: &mut OsPlatform,
    fs: &mut FileStore,
    writer: &mut W,
    delivery_id: String,
    item: MailItem,
) {
    if delivery_id.is_empty() || delivery_id.len() > MAX_DELIVERY_ID_LEN {
        return;
    }
    let payload = wire::encode(&item);
    let digest = payload_digest(&payload);
    match inbox::seen(fs, &delivery_id, &digest) {
        Ok(inbox::Seen::Duplicate) => {
            send_delivery_ack(identity, writer, delivery_id, &payload);
            return;
        }
        Ok(inbox::Seen::Collision) | Err(_) => return,
        Ok(inbox::Seen::New) => {}
    }
    if sender_identity_changed(fs, &item) {
        return;
    }

    let mut tx = fs.transaction();
    remember_sender(&mut tx, &item);
    let mut sink = BufferedSink::default();
    if process_item_with_sink(
        identity, me, my_record, blocked, platform, &mut tx, item, &mut sink,
    ) != flow::ItemOutcome::Accepted
    {
        return;
    }
    if inbox::record(
        &mut tx,
        delivery_id.clone(),
        digest,
        platform.now_unix_secs(),
    )
    .is_err()
    {
        return;
    }
    if tx.commit().is_ok() {
        let mut cli = CliSink;
        for event in sink.0 {
            flow::FlowSink::emit(&mut cli, event);
        }
        send_delivery_ack(identity, writer, delivery_id, &payload);
    }
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

fn sender_identity_changed<S: Storage>(fs: &S, item: &MailItem) -> bool {
    let Some(env) = envelope_sender(item) else {
        return false;
    };
    verified::level(fs, env.from.as_str(), &env.sender_record.record.wallet)
        == verified::TrustLevel::Changed
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

fn handle_discovery_frame<W: FrameWriter>(
    fs: &mut FileStore,
    writer: &mut W,
    frame: &PeerFrame,
) -> bool {
    match frame {
        PeerFrame::DiscoveryRequest { want } => {
            let records = match peerbook::pack(fs, want) {
                Ok(records) => records,
                Err(err) => {
                    eprintln!("(could not build discovery response: {err})");
                    Vec::new()
                }
            };
            let response = PeerFrame::DiscoveryResponse { records };
            let _ = writer.send_frame(&wire::encode(&response));
            true
        }
        PeerFrame::DiscoveryResponse { records } => {
            let report = peerbook::import_records(fs, records.clone());
            if report.imported > 0 || !report.skipped.is_empty() {
                println!(
                    "discovery imported {} record(s), skipped {}",
                    report.imported,
                    report.skipped.len()
                );
            }
            true
        }
        _ => false,
    }
}

fn remember_sender<S: Storage>(fs: &mut S, item: &MailItem)
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let env = envelope_sender(item);
    if let Some(env) = env {
        let _ = peerbook::put(fs, &env.from, env.sender_record.clone());
    }
}

fn envelope_sender(item: &MailItem) -> Option<&Envelope> {
    match item {
        MailItem::Direct(env) | MailItem::GroupInvite(env) | MailItem::GroupLeave(env) => Some(env),
        MailItem::GroupText { .. } => None,
    }
}

// ---- receive processing -----------------------------------------------------

struct CliSink;

impl flow::FlowSink for CliSink {
    fn emit(&mut self, event: flow::FlowEvent) {
        use flow::FlowEvent::*;
        match event {
            DirectMessage { from, id, text, .. } => {
                if id.is_empty() {
                    println!("from {from}: {text}");
                } else {
                    println!("from {from}: {text}  (#{id})");
                }
            }
            GroupMessage {
                name,
                sender,
                id,
                text,
                ..
            } => {
                println!("[{name}] {sender}: {text}  (#{id})")
            }
            Edited {
                thread, id, group, ..
            } => {
                if group {
                    println!("[{thread}] edited #{id}");
                } else {
                    println!("from {thread}: edited #{id}");
                }
            }
            Deleted { thread, id, group } => {
                if group {
                    println!("[{thread}] deleted #{id}");
                } else {
                    println!("from {thread}: deleted #{id}");
                }
            }
            Receipt {
                from,
                message_id,
                read,
            } => {
                let mark = if read { "read" } else { "delivered" };
                println!("ok {from} {mark} your message #{message_id}");
            }
            GroupJoined { name, inviter, .. } => {
                println!("joined group '{name}' (invited by {inviter})")
            }
            GroupLeft { name, member, .. } => println!("'{member}' left '{name}'"),
            Attachment { name, data, .. } => match save_attachment(&name, &data) {
                Ok(path) => println!("(saved attachment to {})", path.display()),
                Err(err) => eprintln!("(could not save attachment: {err})"),
            },
            Warn(msg) => eprintln!("({msg})"),
        }
    }
}

#[derive(Default)]
struct BufferedSink(Vec<flow::FlowEvent>);

impl flow::FlowSink for BufferedSink {
    fn emit(&mut self, event: flow::FlowEvent) {
        self.0.push(event);
    }
}

#[allow(clippy::too_many_arguments)]
fn process_item_with_sink<S: Storage>(
    identity: &Identity,
    me: &Handle,
    my_record: &SignedRecord,
    blocked: &[String],
    platform: &mut OsPlatform,
    fs: &mut S,
    item: MailItem,
    sink: &mut dyn flow::FlowSink,
) -> flow::ItemOutcome
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let now = platform.now_unix_secs();
    let net = client::LocalNet::load(fs);
    let mut deliver = |store: &mut S,
                       handle: &Handle,
                       _record: &SignedRecord,
                       device: &Device,
                       item: MailItem|
     -> DeliveryPath { park_delivery(store, handle, device, item, now) };
    flow::process_item(
        identity,
        fs,
        platform,
        &net,
        me,
        my_record,
        blocked,
        item,
        sink,
        &mut deliver,
    )
}

// ---- groups -----------------------------------------------------------------

pub fn group_create(name: &str, members: &[String], whoami: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let mut fs = open_history(&identity)?;
    let my_record = own_record(&fs, &me)?;

    let mut all = Vec::new();
    for member in members {
        let handle = Handle::new(member.clone()).map_err(|_| anyhow!("invalid member handle"))?;
        if !all.iter().any(|m| m == handle.as_str()) {
            all.push(handle.as_str().to_string());
        }
    }
    if !all.iter().any(|m| m == me.as_str()) {
        all.push(me.as_str().to_string());
    }
    ensure_peer_records(&identity, &mut fs, &all)?;

    let mut platform = OsPlatform;
    let group_id = random_id();
    let group = Group::new(&mut platform, my_group_id(&identity));
    let mut stored = StoredGroup {
        id: group_id.clone(),
        name: name.to_string(),
        members: all.clone(),
        me: me.as_str().to_string(),
        sender_handles: Vec::new(),
        state: group.export(),
    };
    stored.note_sender(my_group_id(&identity), me.as_str());
    groups::save(&mut fs, &stored)?;

    distribute_group_key_direct(&identity, &me, &my_record, &stored, &group, &all, &mut fs);
    println!(
        "created group '{name}' ({group_id}) with {} members",
        all.len()
    );
    Ok(())
}

pub fn group_add(group: &str, member: &str, whoami: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let mut fs = open_history(&identity)?;
    let my_record = own_record(&fs, &me)?;
    let member = Handle::new(member.to_string()).map_err(|_| anyhow!("invalid member handle"))?;

    let mut stored = resolve_group(&fs, group)?;
    if stored.members.iter().any(|m| m == member.as_str()) {
        bail!("'{}' is already in '{}'", member.as_str(), stored.name);
    }
    stored.members.push(member.as_str().to_string());
    ensure_peer_records(&identity, &mut fs, &stored.members)?;
    groups::save(&mut fs, &stored)?;

    let session = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    let targets = stored.members.clone();
    distribute_group_key_direct(
        &identity, &me, &my_record, &stored, &session, &targets, &mut fs,
    );
    println!("invited '{}' to '{}'", member.as_str(), stored.name);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn group_send(
    group: &str,
    whoami: &str,
    message: Option<&str>,
    reply_to: Option<&str>,
    react: Option<&str>,
    to: Option<&str>,
    file: Option<&str>,
    edit: Option<&str>,
    delete: Option<&str>,
    expire: Option<&str>,
) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let mut fs = open_history(&identity)?;
    let network = DirectNetwork::new(identity.device_secret());
    let _ = flush_outbox_with_network(&identity, &mut fs, &network);
    let mut stored = resolve_group(&fs, group)?;
    ensure_peer_records(&identity, &mut fs, &stored.members)?;

    let expires_at = resolve_expiry(&fs, &stored.id, expire)?;
    let app = build_message(message, reply_to, react, to, file, edit, delete, expires_at)?;
    let now = OsPlatform.now_unix_secs();
    let net = client::LocalNet::load(&fs);
    let mut deliver =
        |store: &mut FileStore,
         handle: &Handle,
         _record: &SignedRecord,
         device: &Device,
         item: MailItem|
         -> DeliveryPath { deliver_or_park(store, &network, handle, device, item, now) };

    let out = flow::group_send(
        &identity,
        &mut fs,
        &net,
        &me,
        &mut stored,
        &app,
        &mut deliver,
    )?;
    print_group_delivery_summary(&stored.name, &out.id, out.direct, out.outboxed, out.failed);
    Ok(())
}

fn print_group_delivery_summary(group: &str, id: &str, delivered: u32, pending: u32, failed: u32) {
    println!(
        "{}",
        group_delivery_summary(group, id, delivered, pending, failed)
    );
}

fn group_delivery_summary(
    group: &str,
    id: &str,
    delivered: u32,
    pending: u32,
    failed: u32,
) -> String {
    let delivered_copies = plural(delivered as usize, "copy", "copies");
    let pending_copies = plural(pending as usize, "copy", "copies");
    if failed > 0 {
        format!(
            "delivery to group '{group}' incomplete — {delivered} accepted, {pending} pending locally, {failed} not saved (#{id})"
        )
    } else if pending == 0 {
        format!("delivered to group '{group}' — {delivered} accepted {delivered_copies} (#{id})")
    } else if delivered == 0 {
        format!("saved for group '{group}' — {pending} {pending_copies} pending locally (#{id})")
    } else {
        format!(
            "partially delivered to group '{group}' — {delivered} accepted {delivered_copies}, {pending} pending locally (#{id})"
        )
    }
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 {
        singular
    } else {
        plural
    }
}

pub fn group_history(group: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let stored = resolve_group(&fs, group)?;
    let now = OsPlatform.now_unix_secs();
    let transcript = history::group_load_active(&mut fs, &stored.id, now)?;
    if transcript.is_empty() {
        println!("no messages in '{}'", stored.name);
        return Ok(());
    }
    for m in transcript {
        println!("[{}] {}: {}", stored.name, m.sender, m.text);
    }
    Ok(())
}

pub fn group_info(group: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let stored = resolve_group(&fs, group)?;
    println!("{} ({})", stored.name, stored.id);
    println!("members: {}", stored.members.join(", "));
    Ok(())
}

pub fn group_leave(group: &str, whoami: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let mut fs = open_history(&identity)?;
    let my_record = own_record(&fs, &me)?;
    let stored = resolve_group(&fs, group)?;
    ensure_peer_records(&identity, &mut fs, &stored.members)?;
    let now = OsPlatform.now_unix_secs();
    let network = DirectNetwork::new(identity.device_secret());
    let net = client::LocalNet::load(&fs);
    let mut deliver = |store: &mut FileStore,
                       handle: &Handle,
                       _record: &SignedRecord,
                       device: &Device,
                       item: MailItem| {
        let _ = deliver_or_park(store, &network, handle, device, item, now);
    };
    flow::group_leave(
        &identity,
        &mut fs,
        &mut OsPlatform,
        &net,
        &me,
        &my_record,
        &stored,
        &mut deliver,
    );
    println!("left group '{}'", stored.name);
    Ok(())
}

pub fn group_list() -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let ids = groups::list(&fs)?;
    if ids.is_empty() {
        println!("no groups");
        return Ok(());
    }
    for id in ids {
        if let Some(g) = groups::load(&fs, &id)? {
            println!("{} ({}) — {} members", g.name, g.id, g.members.len());
        }
    }
    Ok(())
}

fn distribute_group_key_direct(
    identity: &Identity,
    me: &Handle,
    my_record: &SignedRecord,
    stored: &StoredGroup,
    group: &Group,
    targets: &[String],
    fs: &mut FileStore,
) {
    let now = OsPlatform.now_unix_secs();
    let network = DirectNetwork::new(identity.device_secret());
    let net = client::LocalNet::load(fs);
    let mut deliver = |store: &mut FileStore,
                       handle: &Handle,
                       _record: &SignedRecord,
                       device: &Device,
                       item: MailItem| {
        let _ = deliver_or_park(store, &network, handle, device, item, now);
    };
    flow::distribute_key(
        identity,
        fs,
        &mut OsPlatform,
        &net,
        me,
        my_record,
        &stored.id,
        &stored.name,
        &group.distribution(),
        &stored.members,
        targets,
        &mut deliver,
    );
}

fn ensure_peer_records(identity: &Identity, fs: &mut FileStore, handles: &[String]) -> Result<()> {
    for handle in handles {
        let handle =
            Handle::new(handle.clone()).map_err(|_| anyhow!("invalid handle '{handle}'"))?;
        if peerbook::get(fs, &handle)?.is_none() {
            let _ = import_from_configured_dht(identity, fs, &handle);
        }
        if peerbook::get(fs, &handle)?.is_none() {
            bail!(
                "no local signed record for '{}' — import their record first",
                handle.as_str()
            );
        }
        let record = peerbook::get(fs, &handle)?.expect("record checked above");
        if record.record.wallet != identity.wallet_public()
            && matches!(
                verified::level(fs, handle.as_str(), &record.record.wallet),
                verified::TrustLevel::Unverified | verified::TrustLevel::Changed
            )
        {
            bail!(
                "group member '{}' is unverified; verify or pin the contact before sharing group keys",
                handle.as_str()
            );
        }
    }
    Ok(())
}

pub fn resolve_group(fs: &FileStore, key: &str) -> Result<StoredGroup> {
    if let Some(g) = groups::load(fs, key)? {
        return Ok(g);
    }
    let mut matches = Vec::new();
    for id in groups::list(fs)? {
        if let Some(g) = groups::load(fs, &id)? {
            if g.name == key {
                matches.push(g);
            }
        }
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => bail!("no such group '{key}'"),
        _ => bail!("group name '{key}' is ambiguous; use the group id"),
    }
}

// ---- trust / contacts -------------------------------------------------------

pub fn resolve_record(fs: &mut FileStore, input: &str) -> Result<(Handle, SignedRecord)> {
    let resolved = client::resolve_name(fs, input)?;
    match client::resolve_local_record(fs, &resolved) {
        Ok(pair) => Ok(pair),
        Err(flow::TrustError::BadHandle) => {
            let handle =
                Handle::new(resolved.clone()).map_err(|_| anyhow!("invalid handle '{resolved}'"))?;
            let identity = store::load_identity()?;
            match import_from_configured_dht(&identity, fs, &handle) {
                Ok(true) => {
                    client::resolve_local_record(fs, &resolved).map_err(|err| match err {
                        flow::TrustError::BadHandle => {
                            anyhow!("no signed record for '{resolved}'")
                        }
                        flow::TrustError::Unverified => anyhow!("peer record failed verification"),
                        flow::TrustError::IdentityChanged => anyhow!(
                            "IDENTITY CHANGED for '{resolved}'. Refusing until you verify the new record out of band."
                        ),
                        flow::TrustError::StaleRecord => {
                            anyhow!("STALE RECORD for '{resolved}'. Refusing rollback.")
                        }
                    })
                }
                Ok(false) => Err(anyhow!("no local signed record for '{resolved}'")),
                Err(err) => Err(anyhow!(
                    "no local signed record for '{resolved}', and DHT lookup failed: {err}"
                )),
            }
        }
        Err(flow::TrustError::Unverified) => Err(anyhow!("peer record failed verification")),
        Err(flow::TrustError::IdentityChanged) => bail!(
            "IDENTITY CHANGED for '{resolved}'. Refusing until you verify the new record out of band."
        ),
        Err(flow::TrustError::StaleRecord) => {
            bail!("STALE RECORD for '{resolved}'. Refusing rollback.")
        }
    }
}

/// Resolve a peer and require an explicit local TOFU pin or out-of-band
/// verification before message or group-secret delivery.
pub fn lookup_verified(fs: &mut FileStore, input: &str) -> Result<(Handle, SignedRecord)> {
    let (handle, record) = resolve_record(fs, input)?;
    match verified::level(fs, handle.as_str(), &record.record.wallet) {
        verified::TrustLevel::Pinned | verified::TrustLevel::Verified => Ok((handle, record)),
        verified::TrustLevel::Changed => bail!(
            "IDENTITY CHANGED for '{}'. Refusing until you verify the new record out of band.",
            handle.as_str()
        ),
        verified::TrustLevel::Unverified => bail!(
            "first contact '{}' is unverified; run `verify {} --confirm` after comparing its safety number, or add it as a contact to pin it",
            handle.as_str(),
            handle.as_str()
        ),
    }
}

fn own_record(fs: &FileStore, me: &Handle) -> Result<SignedRecord> {
    client::require_own_record(fs, me)
}

fn effective_bootstrap(extra: &[String]) -> Result<Vec<libp2p_net::P2pMultiaddr>> {
    let mut addrs = store::config().dht_bootstrap;
    for addr in extra {
        if !addrs.iter().any(|known| known == addr) {
            addrs.push(addr.clone());
        }
    }
    libp2p_net::parse_multiaddrs(&addrs)
}

const MAX_DHT_RECORD_BYTES: usize = 64 * 1024;

fn decode_dht_record_candidate(handle: &Handle, bytes: &[u8]) -> Result<SignedRecord> {
    if bytes.len() > MAX_DHT_RECORD_BYTES {
        bail!("DHT record is too large");
    }
    let record: SignedRecord = wire::decode(bytes).map_err(|_| anyhow!("bad DHT record"))?;
    if record.record.handle != user_id(handle.as_str()) {
        bail!("DHT record belongs to a different handle");
    }
    record
        .verify()
        .map_err(|_| anyhow!("DHT record failed verification"))?;
    Ok(record)
}

fn best_dht_record_candidate(
    handle: &Handle,
    candidates: Vec<Vec<u8>>,
    trusted_wallet: Option<WalletPublicKey>,
) -> Result<(Option<SignedRecord>, usize)> {
    let mut best = None::<SignedRecord>;
    let mut selected_wallet = trusted_wallet;
    let mut skipped = 0usize;
    let mut conflicting_wallet = false;
    for bytes in candidates {
        match decode_dht_record_candidate(handle, &bytes) {
            Ok(record) => {
                match selected_wallet {
                    Some(wallet) if wallet != record.record.wallet => {
                        conflicting_wallet = true;
                        skipped += 1;
                        continue;
                    }
                    None => selected_wallet = Some(record.record.wallet),
                    Some(_) => {}
                }
                let replace = best
                    .as_ref()
                    .map(|known| record.freshness() > known.freshness())
                    .unwrap_or(true);
                if replace {
                    best = Some(record);
                }
            }
            Err(_) => skipped += 1,
        }
    }
    if trusted_wallet.is_none() && conflicting_wallet {
        bail!(
            "conflicting wallets claim '{}'; discovery cannot choose identity authority",
            handle.as_str()
        );
    }
    Ok((best, skipped))
}

fn trusted_wallet(fs: &FileStore, handle: &Handle) -> Result<Option<WalletPublicKey>> {
    let Some(record) = peerbook::get(fs, handle)? else {
        return Ok(None);
    };
    Ok(
        match verified::level(fs, handle.as_str(), &record.record.wallet) {
            verified::TrustLevel::Pinned | verified::TrustLevel::Verified => {
                Some(record.record.wallet)
            }
            verified::TrustLevel::Changed | verified::TrustLevel::Unverified => None,
        },
    )
}

fn import_from_configured_dht(
    identity: &Identity,
    fs: &mut FileStore,
    handle: &Handle,
) -> Result<bool> {
    let bootstrap = effective_bootstrap(&[])?;
    if bootstrap.is_empty() {
        return Ok(false);
    }
    let candidates = libp2p_net::dht_get_records(
        identity.device_secret(),
        None,
        bootstrap,
        dht_record_key(handle),
    )?;
    let wallet = trusted_wallet(fs, handle)?;
    let (best, _skipped) = best_dht_record_candidate(handle, candidates, wallet)?;
    let Some(record) = best else {
        return Ok(false);
    };
    peerbook::put(fs, handle, record)?;
    Ok(true)
}

fn refresh_delivery_device(
    identity: &Identity,
    fs: &mut FileStore,
    handle: &Handle,
    slot: &str,
) -> Option<Device> {
    if !import_from_configured_dht(identity, fs, handle).ok()? {
        return None;
    }
    let device = peerbook::get(fs, handle).ok().flatten()?.record.device;
    (device_slot(&device.device_key) == slot).then_some(device)
}

fn publish_to_configured_dht(
    identity: &Identity,
    handle: &Handle,
    record: &SignedRecord,
) -> Result<bool> {
    let bootstrap = effective_bootstrap(&[])?;
    if bootstrap.is_empty() {
        return Ok(false);
    }
    libp2p_net::dht_put(
        identity.device_secret(),
        None,
        bootstrap,
        dht_record_key(handle),
        wire::encode(record),
    )?;
    Ok(true)
}

fn report_configured_dht_publish(identity: &Identity, handle: &Handle, record: &SignedRecord) {
    match publish_to_configured_dht(identity, handle, record) {
        Ok(true) => println!(
            "published signed record for '{}' to the configured DHT",
            handle.as_str()
        ),
        Ok(false) => {}
        Err(err) => eprintln!(
            "warning: could not publish signed record for '{}' to the configured DHT: {err}",
            handle.as_str()
        ),
    }
}

fn dht_record_key(handle: &Handle) -> Vec<u8> {
    format!("mycellium/record/{}", handle.as_str()).into_bytes()
}

pub fn verify(peer: &str, confirm: bool, accept_change: bool) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let resolved = contacts::resolve(&fs, peer)?;
    let peer_handle =
        Handle::new(resolved.clone()).map_err(|_| anyhow!("invalid handle '{resolved}'"))?;
    if peerbook::get(&fs, &peer_handle)?.is_none() {
        let _ = import_from_configured_dht(&identity, &mut fs, &peer_handle);
    }
    let peer_record = peerbook::get(&fs, &peer_handle)?
        .ok_or_else(|| anyhow!("no signed record for '{}'", peer_handle.as_str()))?;
    peer_record
        .verify()
        .map_err(|_| anyhow!("peer record failed verification"))?;
    let wallet = peer_record.record.wallet;
    let sn = safety::safety_number(&identity.wallet_public(), &wallet);
    let level = verified::level(&fs, peer_handle.as_str(), &wallet);
    println!("'{}' - {}", peer_handle.as_str(), level.label());
    println!("safety number: {sn}");
    if accept_change {
        if level != verified::TrustLevel::Changed {
            bail!(
                "'{}' has no changed identity to accept",
                peer_handle.as_str()
            );
        }
        verified::mark(&mut fs, peer_handle.as_str(), &wallet)?;
        for mut contact in contacts::list(&fs)? {
            if contact.handle == peer_handle.as_str() {
                contact.wallet = wallet;
                contacts::save(&mut fs, &contact)?;
            }
        }
        println!(
            "accepted the new verified identity for '{}'",
            peer_handle.as_str()
        );
    } else if confirm {
        if level == verified::TrustLevel::Changed {
            bail!(
                "identity changed for '{}'; compare the new safety number and use --accept-change explicitly",
                peer_handle.as_str()
            );
        }
        verified::mark(&mut fs, peer_handle.as_str(), &wallet)?;
        println!("marked '{}' as verified", peer_handle.as_str());
    }
    Ok(())
}

pub fn contact_add(nickname: &str, handle: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let record = peerbook::get(&fs, &handle)?
        .ok_or_else(|| anyhow!("import a signed record for '{}' first", handle.as_str()))?;
    let contact = Contact {
        nickname: nickname.to_string(),
        handle: handle.as_str().to_string(),
        wallet: record.record.wallet,
    };
    contacts::save(&mut fs, &contact)?;
    println!("added '{}' -> {}", nickname, handle.as_str());
    Ok(())
}

pub fn contact_list() -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let list = contacts::list(&fs)?;
    if list.is_empty() {
        println!("no contacts");
        return Ok(());
    }
    for c in list {
        let verified_here =
            verified::get(&fs, &c.handle).ok().flatten().as_ref() == Some(&c.wallet);
        let mark = if verified_here { "verified" } else { "pinned" };
        println!("{} -> {}   [{mark}]", c.nickname, c.handle);
    }
    Ok(())
}

pub fn contact_remove(nickname: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    contacts::remove(&mut fs, nickname)?;
    println!("removed '{nickname}'");
    Ok(())
}

// ---- local organization -----------------------------------------------------

pub fn set_blocked(handle: &str, blocked: bool) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    if blocked {
        blocklist::block(&mut fs, handle)?;
        println!("blocked '{handle}'");
    } else {
        blocklist::unblock(&mut fs, handle)?;
        println!("unblocked '{handle}'");
    }
    Ok(())
}

pub fn list_blocked() -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let list = blocklist::load(&fs)?;
    if list.is_empty() {
        println!("no blocked handles");
    } else {
        for h in list {
            println!("{h}");
        }
    }
    Ok(())
}

pub fn clear_history(peer: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = contacts::resolve(&fs, peer)?;
    history::clear(&mut fs, &key)?;
    println!("cleared history with '{key}'");
    Ok(())
}

pub fn show_history(peer: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = contacts::resolve(&fs, peer)?;
    let now = OsPlatform.now_unix_secs();
    let transcript = history::load_active(&mut fs, &key, now)?;
    if transcript.is_empty() {
        println!("no stored history with '{key}'");
        return Ok(());
    }
    for m in transcript {
        let who = if m.from_me { "you" } else { key.as_str() };
        println!("{who}: {}", m.text);
    }
    Ok(())
}

pub fn conversations() -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let now = OsPlatform.now_unix_secs();
    let mut any = false;
    for peer in history::peers(&fs)? {
        let msgs = history::load_active(&mut fs, &peer, now)?;
        if let Some(last) = msgs.last() {
            let who = if last.from_me { "you" } else { peer.as_str() };
            println!("{peer:16} {who}: {}", preview(&last.text));
            any = true;
        }
    }
    if !any {
        println!("no conversations yet");
    }
    Ok(())
}

pub fn search(query: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let now = OsPlatform.now_unix_secs();
    let needle = query.to_lowercase();
    let mut hits = 0usize;
    for peer in history::peers(&fs)? {
        for m in history::load_active(&mut fs, &peer, now)? {
            if m.text.to_lowercase().contains(&needle) {
                let who = if m.from_me { "you" } else { peer.as_str() };
                println!("[{peer}] {who}: {}", m.text);
                hits += 1;
            }
        }
    }
    if hits == 0 {
        println!("no matches for '{query}'");
    } else {
        println!("{hits} match(es)");
    }
    Ok(())
}

pub fn draft_cmd(peer: &str, text: Option<&str>) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = contacts::resolve(&fs, peer)?;
    match text {
        Some(t) => {
            draft::set(&mut fs, &key, t)?;
            println!("draft saved for '{key}'");
        }
        None => match draft::get(&fs, &key)? {
            Some(d) => println!("draft for '{key}': {d}"),
            None => println!("no draft for '{key}'"),
        },
    }
    Ok(())
}

pub fn draft_clear(peer: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = contacts::resolve(&fs, peer)?;
    draft::clear(&mut fs, &key)?;
    println!("cleared draft for '{key}'");
    Ok(())
}

pub fn expire_set(target: &str, duration: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let secs = parse_duration(duration)?;
    let mut fs = open_history(&identity)?;
    let key = contacts::resolve(&fs, target)?;
    expiry::set(&mut fs, &key, secs)?;
    println!("messages to '{key}' now disappear after {duration}");
    Ok(())
}

pub fn expire_clear(target: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = contacts::resolve(&fs, target)?;
    expiry::clear(&mut fs, &key)?;
    println!("cleared disappearing-message timer for '{key}'");
    Ok(())
}

pub fn expire_show(target: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let key = contacts::resolve(&fs, target)?;
    match expiry::get(&fs, &key)? {
        Some(secs) => println!("'{key}': messages disappear after {secs}s"),
        None => println!("'{key}': no disappearing-message timer"),
    }
    Ok(())
}

pub fn short_device_id(key: &DevicePublicKey) -> String {
    hex(&key.0[..4])
}

fn hex_32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex_bytes(s)?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected 32-byte hex string"))
}

fn hex_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        bail!("hex string has an odd length");
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| anyhow!("invalid hex string"))
        })
        .collect()
}

pub use mycellium_engine::wireops::{device_slot, my_group_id};

#[cfg(test)]
mod tests {
    use super::*;
    use mycellium_core::group::GroupMessage;

    struct TestPlatform;

    impl Platform for TestPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(13).wrapping_add(9);
            }
        }

        fn now_unix_secs(&self) -> u64 {
            42
        }
    }

    struct SeededPlatform(u8);

    impl Platform for SeededPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.0.wrapping_add((i as u8).wrapping_mul(31));
            }
            self.0 = self.0.wrapping_add(1);
        }

        fn now_unix_secs(&self) -> u64 {
            42
        }
    }

    fn signed_record(handle: &Handle) -> SignedRecord {
        let mut platform = TestPlatform;
        let identity = Identity::generate(&mut platform).unwrap();
        peerbook::build_record(&mut platform, &identity, handle, "Name", "127.0.0.1:1")
    }

    fn sample_mail() -> MailItem {
        MailItem::GroupText {
            group_id: "group-1".into(),
            message: GroupMessage {
                sender: vec![1],
                iteration: 0,
                ciphertext: vec![2, 3],
                signature: vec![4; 64],
            },
        }
    }

    struct AckWire {
        signer: Identity,
        sent: Option<Vec<u8>>,
    }

    #[derive(Default)]
    struct CaptureWriter(Vec<Vec<u8>>);

    impl FrameWriter for CaptureWriter {
        fn send_frame(&mut self, bytes: &[u8]) -> Result<()> {
            self.0.push(bytes.to_vec());
            Ok(())
        }
    }

    impl FrameWriter for AckWire {
        fn send_frame(&mut self, bytes: &[u8]) -> Result<()> {
            self.sent = Some(bytes.to_vec());
            Ok(())
        }
    }

    impl FrameReader for AckWire {
        fn recv_frame(&mut self) -> Result<Vec<u8>> {
            let frame = self.sent.as_ref().unwrap();
            let PeerFrame::Delivery { delivery_id, item } =
                wire::decode::<PeerFrame>(frame).unwrap()
            else {
                panic!("expected delivery frame");
            };
            let payload = wire::encode(&*item);
            Ok(wire::encode(&PeerFrame::Ack(DeliveryAck::accepted(
                &self.signer,
                delivery_id,
                &payload,
            ))))
        }
    }

    #[test]
    fn direct_delivery_requires_the_recipient_active_device_acceptance_ack() {
        let mut platform = SeededPlatform(30);
        let bob = Identity::generate(&mut platform).unwrap();
        let device = wireops::this_device(&bob, "127.0.0.1:1", 1);
        let item = sample_mail();
        let payload = wire::encode(&item);
        let frame = wire::encode(&PeerFrame::Delivery {
            delivery_id: "delivery-1".into(),
            item: Box::new(item),
        });
        let mut conn = AckWire {
            signer: bob,
            sent: None,
        };

        assert!(exchange_delivery(
            &mut conn,
            &frame,
            "delivery-1",
            &payload,
            &device.device_key,
        ));
    }

    #[test]
    fn direct_delivery_rejects_an_ack_signed_by_the_wrong_device() {
        let mut platform = SeededPlatform(30);
        let bob = Identity::generate(&mut platform).unwrap();
        let mallory = Identity::generate(&mut SeededPlatform(130)).unwrap();
        let device = wireops::this_device(&bob, "127.0.0.1:1", 1);
        let item = sample_mail();
        let payload = wire::encode(&item);
        let frame = wire::encode(&PeerFrame::Delivery {
            delivery_id: "delivery-1".into(),
            item: Box::new(item),
        });
        let mut conn = AckWire {
            signer: mallory,
            sent: None,
        };

        assert!(!exchange_delivery(
            &mut conn,
            &frame,
            "delivery-1",
            &payload,
            &device.device_key,
        ));
    }

    #[test]
    fn recipient_commits_message_and_dedup_record_before_ack() {
        let mut platform = SeededPlatform(20);
        let alice = Identity::generate(&mut platform).unwrap();
        let bob = Identity::generate(&mut platform).unwrap();
        let alice_handle = Handle::new("alice").unwrap();
        let bob_handle = Handle::new("bob").unwrap();
        let alice_record =
            wireops::build_record(&mut platform, &alice, &alice_handle, "Alice", "127.0.0.1:1");
        let bob_record =
            wireops::build_record(&mut platform, &bob, &bob_handle, "Bob", "127.0.0.1:2");
        let app = wireops::text_message(&mut platform, "hello");
        let envelope = wireops::seal_to_with_record(
            &mut platform,
            &alice,
            &alice_handle,
            &alice_record,
            bob_record.record.primary(),
            &app.encode(),
        )
        .unwrap();
        let item = MailItem::Direct(envelope);
        let payload = wire::encode(&item);
        let digest = payload_digest(&payload);
        let dir = std::env::temp_dir().join(format!(
            "mycellium-acceptance-transaction-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = FileStore::open(dir.clone(), [7; 32]).unwrap();
        let mut writer = CaptureWriter::default();

        handle_delivery_frame(
            &bob,
            &bob_handle,
            &bob_record,
            &[],
            &mut OsPlatform,
            &mut store,
            &mut writer,
            "delivery-atomic".into(),
            item.clone(),
        );

        assert_eq!(writer.0.len(), 1, "ACK is emitted after commit");
        assert_eq!(history::load(&store, "alice").unwrap().len(), 1);
        assert_eq!(
            inbox::seen(&store, "delivery-atomic", &digest).unwrap(),
            inbox::Seen::Duplicate
        );
        // Model a lost first ACK: the sender retries the exact delivery. The
        // recipient must not reapply it, but must return the signed ACK again.
        handle_delivery_frame(
            &bob,
            &bob_handle,
            &bob_record,
            &[],
            &mut OsPlatform,
            &mut store,
            &mut writer,
            "delivery-atomic".into(),
            item,
        );
        assert_eq!(writer.0.len(), 2);
        assert_eq!(history::load(&store, "alice").unwrap().len(), 1);
        drop(store);
        let reopened = FileStore::open(dir.clone(), [7; 32]).unwrap();
        assert_eq!(history::load(&reopened, "alice").unwrap().len(), 1);
        assert_eq!(
            inbox::seen(&reopened, "delivery-atomic", &digest).unwrap(),
            inbox::Seen::Duplicate
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn recipient_rejects_changed_sender_wallet_before_ack_or_storage() {
        let mut platform = SeededPlatform(80);
        let alice = Identity::generate(&mut platform).unwrap();
        let mallory = Identity::generate(&mut platform).unwrap();
        let bob = Identity::generate(&mut platform).unwrap();
        let alice_handle = Handle::new("alice").unwrap();
        let bob_handle = Handle::new("bob").unwrap();
        let alice_record =
            wireops::build_record(&mut platform, &alice, &alice_handle, "Alice", "127.0.0.1:1");
        let mallory_record = wireops::build_record(
            &mut platform,
            &mallory,
            &alice_handle,
            "Fake Alice",
            "127.0.0.1:9",
        );
        let bob_record =
            wireops::build_record(&mut platform, &bob, &bob_handle, "Bob", "127.0.0.1:2");
        let app = wireops::text_message(&mut platform, "not alice");
        let envelope = wireops::seal_to_with_record(
            &mut platform,
            &mallory,
            &alice_handle,
            &mallory_record,
            bob_record.record.primary(),
            &app.encode(),
        )
        .unwrap();
        let item = MailItem::Direct(envelope);
        let payload = wire::encode(&item);
        let digest = payload_digest(&payload);
        let dir =
            std::env::temp_dir().join(format!("mycellium-changed-sender-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = FileStore::open(dir.clone(), [8; 32]).unwrap();
        contacts::save(
            &mut store,
            &Contact {
                nickname: "alice".into(),
                handle: "alice".into(),
                wallet: alice_record.record.wallet,
            },
        )
        .unwrap();
        let mut writer = CaptureWriter::default();

        handle_delivery_frame(
            &bob,
            &bob_handle,
            &bob_record,
            &[],
            &mut OsPlatform,
            &mut store,
            &mut writer,
            "delivery-changed".into(),
            item,
        );

        assert!(writer.0.is_empty(), "changed identity is not ACKed");
        assert!(history::load(&store, "alice").unwrap().is_empty());
        assert_eq!(
            inbox::seen(&store, "delivery-changed", &digest).unwrap(),
            inbox::Seen::New
        );
        assert!(peerbook::get(&store, &alice_handle).unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn dht_candidate_accepts_matching_signed_record() {
        let handle = Handle::new("alice").unwrap();
        let record = signed_record(&handle);
        let decoded = decode_dht_record_candidate(&handle, &wire::encode(&record)).unwrap();

        assert_eq!(decoded.record.handle, user_id("alice"));
    }

    #[test]
    fn dht_candidate_rejects_wrong_handle() {
        let alice = Handle::new("alice").unwrap();
        let bob = Handle::new("bob").unwrap();
        let record = signed_record(&alice);

        assert!(decode_dht_record_candidate(&bob, &wire::encode(&record)).is_err());
    }

    #[test]
    fn dht_candidate_rejects_oversized_values() {
        let handle = Handle::new("alice").unwrap();
        let bytes = vec![0u8; MAX_DHT_RECORD_BYTES + 1];

        assert!(decode_dht_record_candidate(&handle, &bytes).is_err());
    }

    #[test]
    fn dht_cannot_choose_between_competing_unpinned_wallets() {
        let handle = Handle::new("alice").unwrap();
        let first = signed_record(&handle);
        let mut other_platform = SeededPlatform(180);
        let other_identity = Identity::generate(&mut other_platform).unwrap();
        let other = peerbook::build_record(
            &mut other_platform,
            &other_identity,
            &handle,
            "Other Alice",
            "127.0.0.1:2",
        );

        let err = best_dht_record_candidate(
            &handle,
            vec![wire::encode(&first), wire::encode(&other)],
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("conflicting wallets"));
    }

    #[test]
    fn dht_freshness_is_selected_only_within_the_trusted_wallet() {
        let handle = Handle::new("alice").unwrap();
        let trusted = signed_record(&handle);
        let wallet = trusted.record.wallet;
        let mut other_platform = SeededPlatform(180);
        let other_identity = Identity::generate(&mut other_platform).unwrap();
        let other = peerbook::build_record(
            &mut other_platform,
            &other_identity,
            &handle,
            "Other Alice",
            "127.0.0.1:2",
        );

        let (selected, skipped) = best_dht_record_candidate(
            &handle,
            vec![wire::encode(&other), wire::encode(&trusted)],
            Some(wallet),
        )
        .unwrap();
        assert_eq!(selected.unwrap().record.wallet, wallet);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn register_reuses_only_same_wallet_records() {
        let handle = Handle::new("alice").unwrap();
        let mut platform = SeededPlatform(1);
        let identity = Identity::generate(&mut platform).unwrap();
        let record =
            peerbook::build_record(&mut platform, &identity, &handle, "Alice", "127.0.0.1:1");

        let reusable = client::reusable_own_record(&identity, &handle, Some(record)).unwrap();

        assert!(reusable.is_some());
    }

    #[test]
    fn register_rejects_foreign_wallet_records() {
        let handle = Handle::new("alice").unwrap();
        let mut mine_platform = SeededPlatform(1);
        let mut foreign_platform = SeededPlatform(99);
        let identity = Identity::generate(&mut mine_platform).unwrap();
        let foreign = Identity::generate(&mut foreign_platform).unwrap();
        let foreign_record = peerbook::build_record(
            &mut foreign_platform,
            &foreign,
            &handle,
            "Alice",
            "127.0.0.1:1",
        );

        let err =
            client::reusable_own_record(&identity, &handle, Some(foreign_record)).unwrap_err();

        assert!(err.to_string().contains("different wallet"));
    }

    #[test]
    fn delivery_summaries_do_not_fake_sent_state() {
        assert_eq!(
            delivery_summary("bob", "abc123", 1, 0, 0, 1),
            "delivered to 'bob' — 1/1 active device (#abc123)"
        );
        assert_eq!(
            delivery_summary("bob", "abc123", 0, 1, 0, 1),
            "saved for 'bob' — waiting for direct delivery to active device (#abc123)"
        );
        assert_eq!(
            delivery_summary("bob", "abc123", 1, 1, 0, 2),
            "partially delivered to 'bob' — 1 accepted, 1 pending locally (#abc123)"
        );
        assert_eq!(
            delivery_summary("bob", "abc123", 0, 1, 1, 2),
            "delivery to 'bob' incomplete — 0 accepted, 1 pending locally, 1 not saved (#abc123)"
        );
    }

    #[test]
    fn group_delivery_summaries_do_not_fake_sent_state() {
        assert_eq!(
            group_delivery_summary("team", "abc123", 3, 0, 0),
            "delivered to group 'team' — 3 accepted copies (#abc123)"
        );
        assert_eq!(
            group_delivery_summary("team", "abc123", 0, 3, 0),
            "saved for group 'team' — 3 copies pending locally (#abc123)"
        );
        assert_eq!(
            group_delivery_summary("team", "abc123", 2, 1, 0),
            "partially delivered to group 'team' — 2 accepted copies, 1 pending locally (#abc123)"
        );
    }
}
