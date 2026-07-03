#![allow(clippy::too_many_arguments)]
use super::*;

pub fn forward(message_id: &str, from: &str, to: &str, whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let fs = open_history(&identity)?;

    // Find the source message's text in the transcript with `from`.
    let from_key = contacts::resolve(&fs, from)?;
    let text = history::load(&fs, &from_key)?
        .into_iter()
        .find(|m| m.id == message_id)
        .map(|m| m.text)
        .ok_or_else(|| anyhow!("no message #{message_id} in history with '{from_key}'"))?;
    let forwarded = format!("Fwd from {from_key}: {text}");

    // Send it to the recipient.
    let client = DirectoryClient::new(directory);
    let (to_handle, to_record) = lookup_verified(&client, &fs, to)?;
    let app = text_message(&forwarded);
    let envelope = seal_to(&identity, &me, to_record.record.primary(), &app.encode());
    let queue = QueueTarget::open(&identity, &to_record.record);
    deliver(&client, &to_handle, queue.as_ref(), to_record.record.primary(), &MailItem::Direct(envelope));
    println!("forwarded #{message_id} to '{}'", to_handle.as_str());
    Ok(())
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
    directory: &str,
) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;

    let client = DirectoryClient::new(directory);
    let mut fs = open_history(&identity)?;
    // First, retry anything that got stuck on an earlier attempt.
    let _ = flush_outbox(&identity, &client, &mut fs);
    let (peer_handle, peer_record) = lookup_verified(&client, &fs, peer)?;

    let expires_at = resolve_expiry(&fs, peer_handle.as_str(), expire)?;
    let app = build_message(message, reply_to, react, to, file, edit, delete, expires_at)?;
    let encoded = app.encode();

    // Fan out one sealed copy per recipient device (Layer 11) — each device has
    // its own keys, so every device in the cluster receives it. A device we
    // can't reach (offline, no reachable queue) is parked in the outbox.
    let queue = QueueTarget::open(&identity, &peer_record.record);
    let now = OsPlatform.now_unix_secs();
    let mut delivered = 0;
    for device in &peer_record.record.devices {
        let envelope = seal_to(&identity, &me, device, &encoded);
        let slot = device_slot(&device.device_key);
        let item = MailItem::Direct(envelope);
        if deliver(&client, &peer_handle, queue.as_ref(), device, &item) {
            delivered += 1;
        } else {
            let _ = outbox::enqueue(&mut fs, random_id(), peer_handle.as_str(), &slot, item, now);
        }
    }
    let total = peer_record.record.devices.len();
    let queued = total - delivered;
    let note = if queued > 0 { format!(" — {queued} queued for retry") } else { String::new() };
    println!("sent to '{}' — {delivered}/{total} device(s) (#{}){note}", peer_handle.as_str(), app.id);

    // Self-sync: mirror this message to my own other devices (Layer 11).
    if let Ok(my_record) = client.lookup(&me) {
        let my_queue = QueueTarget::open(&identity, &my_record.record);
        let my_key = identity.device_public();
        for device in &my_record.record.devices {
            if device.device_key == my_key {
                continue;
            }
            let envelope = seal_to(&identity, &me, device, &encoded);
            let sync = MailItem::SelfSync { peer: peer_handle.as_str().to_string(), envelope };
            deliver(&client, &me, my_queue.as_ref(), device, &sync);
        }
    }
    Ok(())
}



pub fn broadcast(recipients: &[String], whoami: &str, message: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let fs = open_history(&identity)?;

    let mut sent = 0;
    for recipient in recipients {
        match lookup_verified(&client, &fs, recipient) {
            Ok((handle, record)) => {
                let app = text_message(message);
                let envelope = seal_to(&identity, &me, record.record.primary(), &app.encode());
                let queue = QueueTarget::open(&identity, &record.record);
                if deliver(&client, &handle, queue.as_ref(), record.record.primary(), &MailItem::Direct(envelope)) {
                    sent += 1;
                }
            }
            Err(err) => eprintln!("(skipping '{recipient}': {err})"),
        }
    }
    println!("broadcast to {sent} peer(s)");
    Ok(())
}



/// Asynchronously X3DH-seal `plaintext` for `peer` (offline, one-shot session).
pub fn seal_to(identity: &Identity, me: &Handle, device: &Device, plaintext: &[u8]) -> Envelope {
    let mut platform = OsPlatform;
    let responder_ik = device.id_key;
    let responder_spk = device.signed_pre_key.public;
    let initiated = x3dh::initiate(&mut platform, identity, &responder_ik, &responder_spk);
    let mut ratchet = Ratchet::new_initiator(&mut platform, &initiated.shared_secret, &responder_spk);
    let ad = associated_data(&identity.messaging_public(), &responder_ik);
    let sealed = ratchet.encrypt(plaintext, &ad);
    Envelope {
        from: me.clone(),
        sender_record: build_record(identity, me, ""),
        init: initiated.init,
        message: sealed,
        timestamp: platform.now_unix_secs(),
    }
}



/// A logged-in deposit target: a recipient's queue plus their wallet key. Built
/// from the recipient's record (the queue lives at the endpoint *they* publish,
/// keyed by *their* wallet) — decoupled from the directory.
pub struct QueueTarget {
    client: QueueClient,
    token: String,
    wallet_hex: String,
}

impl QueueTarget {
    /// Open a session to the queue named in `record` (None if it lists no queue
    /// or login fails).
    pub fn open(identity: &Identity, record: &Record) -> Option<QueueTarget> {
        if record.queue.is_empty() {
            return None;
        }
        let client = QueueClient::new(&record.queue);
        let token = client.login(identity).ok()?;
        Some(QueueTarget { client, token, wallet_hex: wallet_hex(&record.wallet) })
    }

    /// Deposit `item` into `slot` of this recipient's mailbox.
    pub fn deposit(&self, slot: &str, item: &MailItem) -> bool {
        match serde_json::to_string(item) {
            Ok(json) => self.client.deposit(&self.token, &self.wallet_hex, slot, &json).is_ok(),
            Err(_) => false,
        }
    }
}

/// Deliver `item` to one peer device: push it live over a direct connection if
/// the peer is online (runs `serve`), else deposit into their queue (if any).
pub fn deliver(
    dir: &DirectoryClient,
    handle: &Handle,
    queue: Option<&QueueTarget>,
    device: &Device,
    item: &MailItem,
) -> bool {
    if dir.presence(handle).unwrap_or(false) {
        if let Ok(addr) = String::from_utf8(device.peer_id.0.clone()) {
            if !addr.is_empty() && !addr.starts_with('/') {
                if let Ok(frame) = serde_json::to_vec(item) {
                    if let Ok(mut conn) = net::TcpConnection::connect(&addr) {
                        if conn.send_frame(&frame).is_ok() {
                            return true; // delivered live
                        }
                    }
                }
            }
        }
    }
    match queue {
        Some(q) => q.deposit(&device_slot(&device.device_key), item),
        None => false,
    }
}

/// Deliver the *same* item to every device in a handle's cluster (Layer 11),
/// via their queue for the offline devices.
pub fn deliver_to_cluster(dir: &DirectoryClient, identity: &Identity, handle: &Handle, item: &MailItem) {
    if let Ok(rec) = dir.lookup(handle) {
        if rec.verify().is_ok() {
            let queue = QueueTarget::open(identity, &rec.record);
            for device in &rec.record.devices {
                deliver(dir, handle, queue.as_ref(), device, item);
            }
        }
    }
}



/// Retry every parked outbox item once: re-resolve the recipient, re-attempt
/// live/queue delivery, drop the delivered and the expired, bump the rest.
/// Returns `(delivered, still_waiting)`.
pub fn flush_outbox(
    identity: &Identity,
    client: &DirectoryClient,
    fs: &mut FileStore,
) -> Result<(usize, usize)> {
    let entries = outbox::load(fs)?;
    if entries.is_empty() {
        return Ok((0, 0));
    }
    let now = OsPlatform.now_unix_secs();
    let mut delivered = 0;
    let mut remaining: Vec<outbox::OutboxEntry> = Vec::new();
    for mut entry in entries {
        let handle = match Handle::new(entry.recipient.clone()) {
            Ok(h) => h,
            Err(_) => continue, // unparseable recipient — drop it
        };
        // Re-resolve the recipient's current record (queue/devices may have moved).
        let record = match client.lookup(&handle) {
            Ok(r) if r.verify().is_ok() => Some(r),
            _ => None,
        };
        let delivered_now = record.as_ref().and_then(|record| {
            // The device this copy was sealed for; if it's gone, we drop the entry.
            let device = record.record.devices.iter().find(|d| device_slot(&d.device_key) == entry.slot)?;
            let queue = QueueTarget::open(identity, &record.record);
            Some(deliver(client, &handle, queue.as_ref(), device, &entry.item))
        });
        match delivered_now {
            Some(true) => delivered += 1,
            // The target device is gone — nothing to retry; drop the entry.
            None if record.is_some() => {}
            // Still undeliverable (or couldn't resolve): bump and keep unless spent.
            _ => {
                entry.attempts += 1;
                if !entry.is_expired(now) {
                    remaining.push(entry);
                }
            }
        }
    }
    let waiting = remaining.len();
    outbox::save(fs, &remaining)?;
    Ok((delivered, waiting))
}

/// Show the outbox: retry what we can, then report what's still waiting.
pub fn outbox_show(directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let client = DirectoryClient::new(directory);
    let mut fs = open_history(&identity)?;
    let (delivered, waiting) = flush_outbox(&identity, &client, &mut fs)?;
    if delivered > 0 {
        println!("delivered {delivered} previously-stuck message(s)");
    }
    let entries = outbox::load(&fs)?;
    if entries.is_empty() {
        println!("outbox empty ({waiting} waiting)");
        return Ok(());
    }
    let now = OsPlatform.now_unix_secs();
    println!("{} message(s) waiting to send:", entries.len());
    for e in &entries {
        let age = now.saturating_sub(e.created_at);
        println!("  → {}  (device {}, {}s old, {} attempt(s))", e.recipient, &e.slot[..8.min(e.slot.len())], age, e.attempts);
    }
    Ok(())
}

/// Accept live-pushed items from peers and process them (the `serve` receiver).
pub fn serve(addr: &str, whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let _ = client.announce(&token, &me); // mark ourselves online for delivery
    let mut fs = open_history(&identity)?;
    let blocked = blocklist::load(&fs)?;

    let mut transport = TcpTransport::listening(addr).context("could not bind address")?;
    println!("serving on {addr} as {} — receiving live messages", me.as_str());
    let mut platform = OsPlatform;
    loop {
        let mut conn = match transport.accept() {
            Ok(conn) => conn,
            Err(_) => continue,
        };
        while let Ok(frame) = conn.recv_frame() {
            if let Ok(item) = serde_json::from_slice::<MailItem>(&frame) {
                let _ = process_item(&identity, &me, &client, &blocked, &mut platform, &mut fs, item);
            }
        }
    }
}



pub fn inbox(whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;

    let client = DirectoryClient::new(directory);
    // Drain from *my* queue, keyed by my wallet: this device's slot + the
    // cluster-wide account slot.
    let my_hex = wallet_hex(&identity.wallet_public());
    let my_slot = device_slot(&identity.device_public());
    let mut blobs = Vec::new();
    let queue_url = own_queue();
    if !queue_url.is_empty() {
        let queue = QueueClient::new(&queue_url);
        if let Ok(qtoken) = queue.login(&identity) {
            blobs = queue.collect(&qtoken, &my_hex, &my_slot).unwrap_or_default();
            blobs.extend(queue.collect(&qtoken, &my_hex, ACCOUNT_SLOT).unwrap_or_default());
        }
    }
    let mut fs = open_history(&identity)?;
    let blocked = blocklist::load(&fs)?;
    // Opportunistically retry anything stuck in our outbox while we're online.
    let _ = flush_outbox(&identity, &client, &mut fs);

    if blobs.is_empty() {
        println!("no new messages");
        return Ok(());
    }
    let mut platform = OsPlatform;
    for blob in blobs {
        let item: MailItem = match serde_json::from_str(&blob) {
            Ok(item) => item,
            Err(_) => {
                eprintln!("(skipping an unrecognized item)");
                continue;
            }
        };
        if let Err(err) = process_item(&identity, &me, &client, &blocked, &mut platform, &mut fs, item) {
            eprintln!("(skipping an item: {err})");
        }
    }
    Ok(())
}



/// Handle one mailbox/pushed item (shared by `inbox` and `serve`).
#[allow(clippy::too_many_arguments)]
pub fn process_item(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    blocked: &[String],
    platform: &mut OsPlatform,
    fs: &mut FileStore,
    item: MailItem,
) -> Result<()> {
    match item {
        MailItem::Direct(env) => handle_direct(identity, me, client, blocked, platform, fs, &env),
        MailItem::SelfSync { peer, envelope } => handle_self_sync(identity, platform, fs, &peer, &envelope),
        MailItem::GroupSync(env) => handle_group_sync(identity, me, client, platform, fs, &env),
        MailItem::GroupInvite(env) => handle_group_invite(identity, me, client, fs, platform, &env),
        MailItem::GroupText { group_id, message } => handle_group_text(blocked, fs, &group_id, &message),
        MailItem::GroupRemove { group_id, member } => {
            handle_group_remove(identity, me, client, fs, &group_id, &member)
        }
    }
}



/// Process a mirror of a message *this account* sent from another device: record
/// it in the peer's transcript as our own outgoing message (Layer 11 self-sync).
pub fn handle_self_sync(
    identity: &Identity,
    platform: &mut OsPlatform,
    fs: &mut FileStore,
    peer: &str,
    env: &Envelope,
) -> Result<()> {
    let (_from, bytes) = open_envelope(identity, platform, env)?;
    let app = match AppMessage::decode(&bytes) {
        Ok(app) => app,
        Err(_) => return Ok(()),
    };
    match &app.body {
        Body::Edit { to, text } => history::edit(fs, peer, to, text)?,
        Body::Delete { to } => history::delete(fs, peer, to)?,
        Body::Receipt { .. } => {} // receipts aren't mirrored
        _ => {
            println!("→ {peer}: {}  (#{})", app.summary(), app.id);
            let entry = StoredMessage {
                id: app.id.clone(),
                from_me: true,
                text: app.summary(),
                timestamp: OsPlatform.now_unix_secs(),
                expires_at: app.expires_at,
            };
            history::append(fs, peer, entry)?;
        }
    }
    Ok(())
}



/// Decrypt and act on a one-to-one offline message: display + persist real
/// messages (and reply with a read receipt), or show an incoming receipt.
#[allow(clippy::too_many_arguments)]
pub fn handle_direct(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    blocked: &[String],
    platform: &mut OsPlatform,
    fs: &mut FileStore,
    env: &Envelope,
) -> Result<()> {
    let (from, bytes) = open_envelope(identity, platform, env)?;
    if blocklist::is_blocked(blocked, from.as_str()) {
        return Ok(()); // silently drop — no display, storage, or receipt
    }

    match AppMessage::decode(&bytes) {
        Ok(app) => match &app.body {
            // A receipt: show the status; never receipt a receipt (no loops).
            Body::Receipt { message_id, read } => {
                let mark = if *read { "read" } else { "delivered" };
                println!("✓ {} {mark} your message #{message_id}", from.as_str());
            }
            // An edit or deletion of an earlier message: apply to the transcript.
            Body::Edit { to, text } => {
                history::edit(fs, from.as_str(), to, text)?;
                println!("from {}: edited #{to}", from.as_str());
            }
            Body::Delete { to } => {
                history::delete(fs, from.as_str(), to)?;
                println!("from {}: deleted #{to}", from.as_str());
            }
            // Already expired in transit? drop it entirely.
            _ if app.is_expired(OsPlatform.now_unix_secs()) => {}
            // A real message: display, persist, and send a read receipt back.
            _ => {
                if let Some(path) = maybe_save_attachment(&app) {
                    println!("(saved attachment to {})", path.display());
                }
                println!("from {}: {}  (#{})", from.as_str(), app.summary(), app.id);
                let entry = StoredMessage {
                    id: app.id.clone(),
                    from_me: false,
                    text: app.summary(),
                    timestamp: OsPlatform.now_unix_secs(),
                    expires_at: app.expires_at,
                };
                history::append(fs, from.as_str(), entry)?;
                send_receipt(identity, me, client, &from, &app.id);
            }
        },
        Err(_) => {
            // Older/raw payloads: best-effort display.
            let text = String::from_utf8_lossy(&bytes).into_owned();
            println!("from {}: {text}", from.as_str());
            let entry = StoredMessage { id: String::new(), from_me: false, text, timestamp: OsPlatform.now_unix_secs(), expires_at: None };
            history::append(fs, from.as_str(), entry)?;
        }
    }
    Ok(())
}



/// Send a read receipt for `message_id` back to `to` (best-effort).
pub fn send_receipt(identity: &Identity, me: &Handle, client: &DirectoryClient, to: &Handle, message_id: &str) {
    let record = match client.lookup(to) {
        Ok(r) if r.verify().is_ok() => r,
        _ => return,
    };
    let receipt = AppMessage {
        id: random_id(),
        timestamp: OsPlatform.now_unix_secs(),
        expires_at: None,
        body: Body::Receipt { message_id: message_id.to_string(), read: true },
    };
    // Fan the receipt out to every device of the original sender (Layer 11), so
    // whichever device they sent from sees the read status.
    let encoded = receipt.encode();
    let queue = QueueTarget::open(identity, &record.record);
    for device in &record.record.devices {
        let env = seal_to(identity, me, device, &encoded);
        deliver(client, to, queue.as_ref(), device, &MailItem::Direct(env));
    }
}



/// Authenticate the sender and decrypt one offline envelope to raw bytes.
pub fn open_envelope(
    identity: &Identity,
    platform: &mut OsPlatform,
    env: &Envelope,
) -> Result<(Handle, Vec<u8>)> {
    env.sender_record
        .verify()
        .map_err(|_| anyhow!("sender record failed verification"))?;
    if env.sender_record.record.handle != env.from {
        bail!("sender handle does not match its record");
    }
    if env.init.initiator_ik != env.sender_record.record.primary().id_key {
        bail!("handshake is not bound to the sender's identity");
    }

    let shared = x3dh::respond(identity, &env.init);
    let mut ratchet = Ratchet::new_responder(&shared, identity);
    let ad = associated_data(&env.init.initiator_ik, &identity.messaging_public());
    let plaintext = ratchet
        .decrypt(platform, &env.message, &ad)
        .map_err(|_| anyhow!("could not decrypt message"))?;
    Ok((env.from.clone(), plaintext))
}
