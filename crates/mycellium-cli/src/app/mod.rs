//! Native hard-serverless CLI orchestration.
//!
//! This app layer has no directory, queue, relay, mailbox, or push dependency.
//! It keeps signed peer records locally, sends only over peer-to-peer
//! transports, and parks undelivered messages in the local outbox.
#![allow(clippy::too_many_arguments)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};

use mycellium_client::{self as client, DirectNetwork};
#[cfg(test)]
use mycellium_core::delivery::{payload_digest, DeliveryAck};
use mycellium_core::identity::{DevicePublicKey, Handle, Identity, WalletPublicKey};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, SignedRecord};
use mycellium_core::userid::UserId;
use mycellium_core::wire;

use mycellium_storage::filestore::FileStore;
use mycellium_storage::store;
use mycellium_transport::libp2p_net::{self};
#[cfg(test)]
use mycellium_transport::link::{FrameReader, FrameWriter};
use mycellium_transport::reticulum_net::InboundFrame;

use crate::platform::OsPlatform;
#[cfg(test)]
use mycellium_engine::contacts;
use mycellium_engine::groups::{DiscoveryRecord, GroupMember, MailItem, PeerFrame, StoredGroup};
#[cfg(test)]
use mycellium_engine::history;
#[cfg(test)]
use mycellium_engine::inbox;
use mycellium_engine::peerbook;
use mycellium_engine::reachability::{self, DeliveryPath};
#[cfg(test)]
use mycellium_engine::wireops;
use mycellium_engine::{expiry, flow, outbox, verified};

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

pub fn register(handle: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let mut fs = open_history(&identity)?;
    let name = display_name_for(&handle);
    let signed =
        client::publish_active_device_record(&mut fs, &mut OsPlatform, &identity, &handle, &name)?;
    println!("registered '{}' locally", handle.as_str());
    println!("record: {}", client::encode_record(&signed));
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
    println!("{}", client::encode_record(&record));
    Ok(())
}

pub fn record_import(handle: &str, encoded: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let record = client::decode_record(encoded)?;
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
        "  {}  reticulum={}",
        short_device_id(&d.device_key),
        hex(&d.reticulum().address.0)
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
    let network = DirectNetwork::new(identity.reticulum_private_bytes());
    let device = &peer_record.record.device;
    let detail = match request_discovery_from_device(&network, device, want) {
        Ok(records) => {
            let report = client::import_discovery_records(&mut fs, records);
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
    let record = own_record(&fs, &identity, &handle)?;
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
    client::import_record(&mut fs, &handle, record)?;
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
    let network = DirectNetwork::new(identity.reticulum_private_bytes());
    let _ = flush_outbox_with_network(&identity, &mut fs, &network);
    let (peer_handle, peer_record) = lookup_verified(&mut fs, peer)?;

    let expires_at = resolve_expiry(&fs, peer_handle.as_str(), expire)?;
    let app = build_message(message, reply_to, react, to, file, edit, delete, expires_at)?;
    let now = OsPlatform.now_unix_secs();
    let mut deliver = |store: &mut FileStore,
                       handle: &Handle,
                       record: &SignedRecord,
                       device: &Device,
                       item: MailItem,
                       pairwise_plaintext: Option<Vec<u8>>|
     -> DeliveryPath {
        deliver_or_park(
            store,
            &network,
            handle,
            record,
            device,
            item,
            pairwise_plaintext,
            now,
        )
    };

    let out = client::send_direct(
        &identity,
        &mut fs,
        &mut OsPlatform,
        &me,
        &peer_handle,
        &peer_record,
        &app,
        &mut deliver,
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

pub fn serve(whoami: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let fs = open_history(&identity)?;
    let my_record = own_record(&fs, &identity, &me)?;
    let identity = Arc::new(identity);
    let me = Arc::new(me);
    let my_record = Arc::new(my_record);
    let fs = Arc::new(Mutex::new(fs));
    crate::print_engine_diagnostics();

    let network = DirectNetwork::new(identity.reticulum_private_bytes());
    let node = network
        .reticulum()
        .ok_or_else(|| anyhow!("could not start Reticulum node"))?;
    if let Ok(mut store) = fs.lock() {
        let _ = flush_outbox_with_network(&identity, &mut store, &network);
    }
    start_retry_worker(Arc::clone(&identity), Arc::clone(&fs), network);
    println!(
        "serving on Reticulum as {} ({})",
        me.as_str(),
        hex(&my_record.record.device.reticulum().address.0)
    );
    loop {
        match node.recv_timeout(Duration::from_secs(1)) {
            Ok(Some(frame)) => serve_reticulum_frame(frame, &identity, &me, &my_record, &fs),
            Ok(None) => {}
            Err(_) => {}
        }
    }
}

fn start_retry_worker(identity: Arc<Identity>, fs: Arc<Mutex<FileStore>>, network: DirectNetwork) {
    std::thread::spawn(move || loop {
        retry_due_deliveries(&identity, &fs, &network);
        std::thread::sleep(std::time::Duration::from_secs(5));
    });
}

fn retry_due_deliveries(identity: &Identity, fs: &Mutex<FileStore>, network: &DirectNetwork) {
    enum Target {
        Device(Box<Device>),
        Retry,
        Drop,
    }

    let now = OsPlatform.now_unix_secs();
    let due: Vec<outbox::OutboxEntry> = {
        let Ok(fs) = fs.lock() else {
            return;
        };
        match client::due_outbox_entries(&*fs, now) {
            Ok(entries) => entries,
            Err(_) => return,
        }
    };

    for entry in due {
        let target = {
            let Ok(fs) = fs.lock() else {
                return;
            };
            match UserId::new(entry.recipient_user_id.clone()) {
                Ok(user_id) => match peerbook::get_by_user_id(&*fs, &user_id) {
                    Ok(Some(record)) if record.verify().is_ok() => {
                        Target::Device(Box::new(record.record.device))
                    }
                    Ok(None) | Err(_) => Target::Retry,
                    Ok(Some(_)) => Target::Drop,
                },
                _ => Target::Drop,
            }
        };

        if matches!(target, Target::Drop) {
            if let Ok(mut fs) = fs.lock() {
                let _ = client::mark_outbox_failed(&mut *fs, &entry.id);
            }
            continue;
        }

        let Target::Device(device) = target else {
            if let Ok(mut guard) = fs.lock() {
                let _ = client::record_outbox_attempt(&mut *guard, &entry.id, now, false);
            }
            continue;
        };
        let prepared = {
            let Ok(mut guard) = fs.lock() else {
                return;
            };
            client::readdress_parked_delivery(
                identity,
                &mut OsPlatform,
                &mut *guard,
                &entry,
                &device,
            )
        };
        let Ok(Some((delivery_id, item))) = prepared else {
            if let Ok(mut guard) = fs.lock() {
                let _ = client::mark_outbox_failed(&mut *guard, &entry.id);
            }
            continue;
        };
        let accepted = client::direct_push(network, &device, &delivery_id, &item);
        let Ok(mut guard) = fs.lock() else {
            return;
        };
        let _ = reachability::record(
            &mut *guard,
            &device_slot(&device.device_key),
            DeliveryPath::Direct,
            accepted,
            now,
        );
        let _ = client::record_outbox_attempt(&mut *guard, &delivery_id, now, accepted);
    }
}

fn serve_reticulum_frame(
    inbound: InboundFrame,
    identity: &Identity,
    me: &Handle,
    my_record: &SignedRecord,
    fs: &Mutex<FileStore>,
) {
    let mut platform = OsPlatform;
    let Ok(frame) = wire::decode::<PeerFrame>(inbound.bytes()) else {
        return;
    };
    let Ok(mut fs) = fs.lock() else {
        return;
    };
    match frame {
        PeerFrame::DiscoveryRequest { want } => {
            let records = client::discovery_records(&*fs, &want).unwrap_or_default();
            let response = PeerFrame::DiscoveryResponse { records };
            let _ = inbound.reply(&wire::encode(&response));
        }
        PeerFrame::DiscoveryResponse { records } => {
            let _ = client::import_discovery_records(&mut *fs, records);
        }
        PeerFrame::Delivery { delivery_id, item } => {
            let acknowledgement = handle_delivery_frame(
                identity,
                me,
                my_record,
                &mut platform,
                &mut fs,
                delivery_id,
                *item,
            );
            drop(fs);
            if let Some(frame) = acknowledgement {
                let _ = inbound.reply(&frame);
            }
        }
        _ => {}
    }
    crate::print_engine_diagnostics();
}

pub fn outbox_list() -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let entries = client::list_outbox(&fs)?;
    print_outbox_entries(&entries);
    Ok(())
}

pub fn outbox_retry() -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    client::make_outbox_due(&mut fs)?;
    let (delivered, _) = flush_outbox(&identity, &mut fs)?;
    if delivered > 0 {
        println!(
            "delivered {delivered} pending {}",
            plural(delivered, "message", "messages")
        );
    }
    let entries = client::list_outbox(&fs)?;
    print_outbox_entries(&entries);
    Ok(())
}

pub fn outbox_cancel(id: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    match client::cancel_outbox(&mut fs, id)? {
        client::OutboxCancel::Empty => println!("outbox empty"),
        client::OutboxCancel::All { removed } => println!(
            "cancelled {removed} pending local delivery {}",
            plural(removed, "item", "items")
        ),
        client::OutboxCancel::One { id, recipient } => {
            println!(
                "cancelled pending local delivery {} for '{}'",
                short_outbox_id(&id),
                recipient
            );
        }
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
    let network = DirectNetwork::new(identity.reticulum_private_bytes());
    flush_outbox_with_network(identity, fs, &network)
}

fn flush_outbox_with_network(
    identity: &Identity,
    fs: &mut FileStore,
    network: &DirectNetwork,
) -> Result<(usize, usize)> {
    let now = OsPlatform.now_unix_secs();
    let entries = client::due_outbox_entries(fs, now)?;
    let mut delivered = 0;
    for entry in entries {
        let user_id = match UserId::new(entry.recipient_user_id.clone()) {
            Ok(user_id) => user_id,
            Err(_) => {
                client::mark_outbox_failed(fs, &entry.id)?;
                continue;
            }
        };
        let handle = match Handle::new(entry.recipient.clone()) {
            Ok(handle) => handle,
            Err(_) => {
                client::mark_outbox_failed(fs, &entry.id)?;
                continue;
            }
        };
        // Refresh discovery before choosing the active device. Imported records
        // remain self-signed and anti-rollback checked by the peerbook.
        let _ = import_from_configured_dht(identity, fs, &handle);
        let Some(record) = peerbook::get_by_user_id(fs, &user_id)? else {
            client::record_outbox_attempt(fs, &entry.id, now, false)?;
            continue;
        };
        if record.verify().is_err() {
            client::mark_outbox_failed(fs, &entry.id)?;
            continue;
        }
        let device = record.record.device;
        let Some((delivery_id, item)) =
            client::readdress_parked_delivery(identity, &mut OsPlatform, fs, &entry, &device)?
        else {
            client::mark_outbox_failed(fs, &entry.id)?;
            continue;
        };
        let accepted =
            client::deliver_direct(fs, network, &device, &delivery_id, &item, now).is_delivered();
        client::record_outbox_attempt(fs, &delivery_id, now, accepted)?;
        if accepted {
            delivered += 1;
        }
    }
    let waiting = outbox::len(fs)?;
    Ok((delivered, waiting))
}

/// Persist before networking, then remove only after a recipient-device ACK.
fn deliver_or_park(
    store: &mut FileStore,
    network: &DirectNetwork,
    recipient: &Handle,
    recipient_record: &SignedRecord,
    device: &Device,
    item: MailItem,
    pairwise_plaintext: Option<Vec<u8>>,
    now: u64,
) -> DeliveryPath {
    match pairwise_plaintext {
        Some(plaintext) => client::deliver_pairwise_or_park(
            store,
            network,
            recipient,
            recipient_record,
            device,
            item,
            plaintext,
            now,
        ),
        None => client::deliver_or_park(
            store,
            network,
            recipient,
            recipient_record,
            device,
            item,
            now,
        ),
    }
}

fn request_discovery_from_device(
    network: &DirectNetwork,
    device: &Device,
    want: &[String],
) -> Result<Vec<DiscoveryRecord>> {
    let request = PeerFrame::DiscoveryRequest {
        want: want.to_vec(),
    };
    let frame = wire::encode(&request);
    let node = network
        .reticulum()
        .ok_or_else(|| anyhow!("could not start Reticulum node"))?;
    let response = node.send_and_wait(device.reticulum(), &frame, Duration::from_secs(30))?;
    decode_discovery_response(&response)
}

fn decode_discovery_response(frame: &[u8]) -> Result<Vec<DiscoveryRecord>> {
    match wire::decode::<PeerFrame>(frame)? {
        PeerFrame::DiscoveryResponse { records } => Ok(records),
        _ => bail!("peer returned a non-discovery frame"),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_delivery_frame(
    identity: &Identity,
    me: &Handle,
    my_record: &SignedRecord,
    platform: &mut OsPlatform,
    fs: &mut FileStore,
    delivery_id: String,
    item: MailItem,
) -> Option<Vec<u8>> {
    let mut sink = CliSink;
    client::accept_delivery(
        identity,
        me,
        my_record,
        platform,
        fs,
        delivery_id,
        item,
        &mut sink,
    )
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
                ..
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

// ---- groups -----------------------------------------------------------------

pub fn group_create(name: &str, members: &[String], whoami: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let mut fs = open_history(&identity)?;
    let my_record = own_record(&fs, &identity, &me)?;

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
    let mut stored =
        client::create_group(&identity, &mut fs, &mut platform, &me, name, all.clone())?;

    let targets = stored.members.clone();
    distribute_group_key_direct(&identity, &me, &my_record, &mut stored, &targets, &mut fs);
    println!(
        "created group '{name}' ({}) with {} members",
        stored.id,
        all.len()
    );
    Ok(())
}

pub fn group_add(group: &str, member: &str, whoami: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let mut fs = open_history(&identity)?;
    let my_record = own_record(&fs, &identity, &me)?;
    let member = Handle::new(member.to_string()).map_err(|_| anyhow!("invalid member handle"))?;

    ensure_peer_records(&identity, &mut fs, &[member.as_str().to_string()])?;
    let mut stored = client::group_with_added_member(&fs, group, &member)?;
    client::save_group(&mut fs, &stored)?;

    let targets = stored.members.clone();
    distribute_group_key_direct(&identity, &me, &my_record, &mut stored, &targets, &mut fs);
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
    let network = DirectNetwork::new(identity.reticulum_private_bytes());
    let _ = flush_outbox_with_network(&identity, &mut fs, &network);
    let mut stored = client::resolve_group(&fs, group)?;

    let expires_at = resolve_expiry(&fs, &stored.id, expire)?;
    let app = build_message(message, reply_to, react, to, file, edit, delete, expires_at)?;
    let now = OsPlatform.now_unix_secs();
    let mut deliver = |store: &mut FileStore,
                       handle: &Handle,
                       record: &SignedRecord,
                       device: &Device,
                       item: MailItem,
                       pairwise_plaintext: Option<Vec<u8>>|
     -> DeliveryPath {
        deliver_or_park(
            store,
            &network,
            handle,
            record,
            device,
            item,
            pairwise_plaintext,
            now,
        )
    };

    let out = client::send_group(
        &identity,
        &mut fs,
        &mut OsPlatform,
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
    let now = OsPlatform.now_unix_secs();
    let (stored, transcript) = client::group_history(&mut fs, group, now)?;
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
    let stored = client::resolve_group(&fs, group)?;
    println!("{} ({})", stored.name, stored.id);
    let members = stored
        .members
        .iter()
        .map(|member| format!("{} ({})", member.handle, member.user_id))
        .collect::<Vec<_>>()
        .join(", ");
    println!("members: {members}");
    Ok(())
}

pub fn group_leave(group: &str, whoami: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let mut fs = open_history(&identity)?;
    let my_record = own_record(&fs, &identity, &me)?;
    let stored = client::resolve_group(&fs, group)?;
    let now = OsPlatform.now_unix_secs();
    let network = DirectNetwork::new(identity.reticulum_private_bytes());
    let mut deliver = |store: &mut FileStore,
                       handle: &Handle,
                       record: &SignedRecord,
                       device: &Device,
                       item: MailItem,
                       pairwise_plaintext: Vec<u8>| {
        deliver_or_park(
            store,
            &network,
            handle,
            record,
            device,
            item,
            Some(pairwise_plaintext),
            now,
        )
    };
    client::leave_group(
        &identity,
        &mut fs,
        &mut OsPlatform,
        &me,
        &my_record,
        &stored,
        &mut deliver,
    )?;
    println!("left group '{}'", stored.name);
    Ok(())
}

pub fn group_list() -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let groups = client::list_groups(&fs)?;
    if groups.is_empty() {
        println!("no groups");
        return Ok(());
    }
    for group in groups {
        println!(
            "{} ({}) — {} members",
            group.name, group.id, group.member_count
        );
    }
    Ok(())
}

fn distribute_group_key_direct(
    identity: &Identity,
    me: &Handle,
    my_record: &SignedRecord,
    stored: &mut StoredGroup,
    targets: &[GroupMember],
    fs: &mut FileStore,
) {
    let now = OsPlatform.now_unix_secs();
    let network = DirectNetwork::new(identity.reticulum_private_bytes());
    let mut deliver = |store: &mut FileStore,
                       handle: &Handle,
                       record: &SignedRecord,
                       device: &Device,
                       item: MailItem,
                       pairwise_plaintext: Vec<u8>| {
        deliver_or_park(
            store,
            &network,
            handle,
            record,
            device,
            item,
            Some(pairwise_plaintext),
            now,
        )
    };
    let _ = client::distribute_group_key(
        identity,
        fs,
        &mut OsPlatform,
        me,
        my_record,
        stored,
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
                verified::level(fs, record.record.user_id.as_str(), &record.record.wallet),
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

// ---- trust / contacts -------------------------------------------------------

pub fn resolve_record(fs: &mut FileStore, input: &str) -> Result<(Handle, SignedRecord)> {
    match client::resolve_local_record(fs, input) {
        Ok(pair) => Ok(pair),
        Err(flow::TrustError::BadHandle) => {
            let resolved = client::resolve_name(fs, input)?;
            let handle = Handle::new(resolved.clone())
                .map_err(|_| anyhow!("invalid handle '{resolved}'"))?;
            let identity = store::load_identity()?;
            match import_from_configured_dht(&identity, fs, &handle) {
                Ok(true) => {
                    client::resolve_local_record(fs, input).map_err(|err| match err {
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
            "IDENTITY CHANGED for '{input}'. Refusing until you verify the new record out of band."
        ),
        Err(flow::TrustError::StaleRecord) => {
            bail!("STALE RECORD for '{input}'. Refusing rollback.")
        }
    }
}

/// Resolve a peer and require an explicit local TOFU pin or out-of-band
/// verification before message or group-secret delivery.
pub fn lookup_verified(fs: &mut FileStore, input: &str) -> Result<(Handle, SignedRecord)> {
    let (handle, record) = resolve_record(fs, input)?;
    match verified::level(fs, record.record.user_id.as_str(), &record.record.wallet) {
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

fn own_record(fs: &FileStore, identity: &Identity, me: &Handle) -> Result<SignedRecord> {
    client::require_own_record_for_identity(fs, identity, me)
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
    if record.record.handle != *handle {
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
        match verified::level(fs, record.record.user_id.as_str(), &record.record.wallet) {
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
    let (peer_handle, record) = resolve_record(&mut fs, peer)?;
    let info = client::verification_info_for_record(&fs, &identity, &peer_handle, &record)?;
    println!("'{}' - {}", info.handle, info.level.label());
    println!("safety number: {}", info.safety_number);
    if accept_change {
        client::accept_identity_change(&mut fs, &info)?;
        println!("accepted the new verified identity for '{}'", info.handle);
    } else if confirm {
        client::mark_verified(&mut fs, &info)?;
        println!("marked '{}' as verified", info.handle);
    }
    Ok(())
}

pub fn contact_add(nickname: &str, handle: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    client::add_contact(&mut fs, nickname, &handle)?;
    println!("added '{}' -> {}", nickname, handle.as_str());
    Ok(())
}

pub fn contact_list() -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let list = client::list_contacts(&fs)?;
    if list.is_empty() {
        println!("no contacts");
        return Ok(());
    }
    for c in list {
        let mark = if c.verified { "verified" } else { "pinned" };
        println!("{} -> {}   [{mark}]", c.nickname, c.handle);
    }
    Ok(())
}

pub fn contact_remove(nickname: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    client::remove_contact(&mut fs, nickname)?;
    println!("removed '{nickname}'");
    Ok(())
}

// ---- local organization -----------------------------------------------------

pub fn set_blocked(person: &str, blocked: bool) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let user_id = match UserId::new(person.to_string()) {
        Ok(user_id) => user_id.as_str().to_string(),
        Err(_) => client::resolve_local_record(&mut fs, person)
            .map_err(|_| anyhow!("unknown or ambiguous person '{person}'"))?
            .1
            .record
            .user_id
            .as_str()
            .to_string(),
    };
    client::set_blocked(&mut fs, &user_id, blocked)?;
    if blocked {
        println!("blocked '{person}' ({user_id})");
    } else {
        println!("unblocked '{person}' ({user_id})");
    }
    Ok(())
}

pub fn list_blocked() -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let list = client::list_blocked(&fs)?;
    if list.is_empty() {
        println!("no blocked users");
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
    let key = client::clear_history(&mut fs, peer)?;
    println!("cleared history with '{key}'");
    Ok(())
}

pub fn show_history(peer: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let now = OsPlatform.now_unix_secs();
    let (key, transcript) = client::history_with(&mut fs, peer, now)?;
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
    let conversations = client::conversations(&mut fs, now)?;
    if conversations.is_empty() {
        println!("no conversations yet");
        return Ok(());
    }
    for conversation in conversations {
        let who = if conversation.from_me {
            "you"
        } else {
            conversation.peer.as_str()
        };
        println!(
            "{:16} {who}: {}",
            conversation.peer,
            preview(&conversation.text)
        );
    }
    Ok(())
}

pub fn search(query: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let now = OsPlatform.now_unix_secs();
    let hits = client::search_history(&mut fs, query, now)?;
    if hits.is_empty() {
        println!("no matches for '{query}'");
        return Ok(());
    }
    for hit in &hits {
        let who = if hit.from_me {
            "you"
        } else {
            hit.peer.as_str()
        };
        println!("[{}] {who}: {}", hit.peer, hit.text);
    }
    println!("{} match(es)", hits.len());
    Ok(())
}

pub fn draft_cmd(peer: &str, text: Option<&str>) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    match text {
        Some(t) => {
            let key = client::set_draft(&mut fs, peer, t)?;
            println!("draft saved for '{key}'");
        }
        None => match client::get_draft(&fs, peer)? {
            (key, Some(d)) => println!("draft for '{key}': {d}"),
            (key, None) => println!("no draft for '{key}'"),
        },
    }
    Ok(())
}

pub fn draft_clear(peer: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = client::clear_draft(&mut fs, peer)?;
    println!("cleared draft for '{key}'");
    Ok(())
}

pub fn expire_set(target: &str, duration: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let secs = parse_duration(duration)?;
    let mut fs = open_history(&identity)?;
    let key = client::set_expiry(&mut fs, target, secs)?;
    println!("messages to '{key}' now disappear after {duration}");
    Ok(())
}

pub fn expire_clear(target: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = client::clear_expiry(&mut fs, target)?;
    println!("cleared disappearing-message timer for '{key}'");
    Ok(())
}

pub fn expire_show(target: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    match client::get_expiry(&fs, target)? {
        (key, Some(secs)) => println!("'{key}': messages disappear after {secs}s"),
        (key, None) => println!("'{key}': no disappearing-message timer"),
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

pub use mycellium_engine::wireops::device_slot;

#[cfg(test)]
mod tests {
    use super::*;
    use mycellium_core::group::GroupMessage;
    use mycellium_engine::contacts::Contact;

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
        peerbook::build_record(&mut platform, &identity, handle, "Name")
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
        let device = wireops::this_device(&bob, 1);
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

        assert!(client::exchange_delivery(
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
        let device = wireops::this_device(&bob, 1);
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

        assert!(!client::exchange_delivery(
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
        let alice_record = wireops::build_record(&mut platform, &alice, &alice_handle, "Alice");
        let bob_record = wireops::build_record(&mut platform, &bob, &bob_handle, "Bob");
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
        let delivery_id = client::delivery_id_for_item(&item);
        let payload = wire::encode(&item);
        let digest = payload_digest(&payload);
        let dir = std::env::temp_dir().join(format!(
            "mycellium-acceptance-transaction-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = FileStore::open(dir.clone(), [7; 32]).unwrap();
        let mut writer = CaptureWriter::default();
        let acknowledgement = handle_delivery_frame(
            &bob,
            &bob_handle,
            &bob_record,
            &mut OsPlatform,
            &mut store,
            delivery_id.clone(),
            item.clone(),
        );
        writer.send_frame(&acknowledgement.unwrap()).unwrap();

        assert_eq!(writer.0.len(), 1, "ACK is emitted after commit");
        let alice_user_id = alice_record.record.user_id.as_str();
        assert_eq!(history::load(&store, alice_user_id).unwrap().len(), 1);
        assert_eq!(
            inbox::seen(&store, &delivery_id, &digest).unwrap(),
            inbox::Seen::Duplicate
        );
        // Model a lost first ACK: the sender retries the exact delivery. The
        // recipient must not reapply it, but must return the signed ACK again.
        let acknowledgement = handle_delivery_frame(
            &bob,
            &bob_handle,
            &bob_record,
            &mut OsPlatform,
            &mut store,
            delivery_id.clone(),
            item,
        );
        writer.send_frame(&acknowledgement.unwrap()).unwrap();
        assert_eq!(writer.0.len(), 2);
        assert_eq!(history::load(&store, alice_user_id).unwrap().len(), 1);
        drop(store);
        let reopened = FileStore::open(dir.clone(), [7; 32]).unwrap();
        assert_eq!(history::load(&reopened, alice_user_id).unwrap().len(), 1);
        assert_eq!(
            inbox::seen(&reopened, &delivery_id, &digest).unwrap(),
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
        let alice_record = wireops::build_record(&mut platform, &alice, &alice_handle, "Alice");
        let mallory_record =
            wireops::build_record(&mut platform, &mallory, &alice_handle, "Fake Alice");
        let bob_record = wireops::build_record(&mut platform, &bob, &bob_handle, "Bob");
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
                user_id: alice_record.record.user_id.as_str().to_string(),
                wallet: alice_record.record.wallet,
            },
        )
        .unwrap();
        let acknowledgement = handle_delivery_frame(
            &bob,
            &bob_handle,
            &bob_record,
            &mut OsPlatform,
            &mut store,
            "delivery-changed".into(),
            item,
        );

        assert!(acknowledgement.is_none());
        assert!(
            history::load(&store, mallory_record.record.user_id.as_str())
                .unwrap()
                .is_empty()
        );
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

        assert_eq!(decoded.record.handle, handle);
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
        let other =
            peerbook::build_record(&mut other_platform, &other_identity, &handle, "Other Alice");

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
        let other =
            peerbook::build_record(&mut other_platform, &other_identity, &handle, "Other Alice");

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
        let record = peerbook::build_record(&mut platform, &identity, &handle, "Alice");

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
        let foreign_record =
            peerbook::build_record(&mut foreign_platform, &foreign, &handle, "Alice");

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
