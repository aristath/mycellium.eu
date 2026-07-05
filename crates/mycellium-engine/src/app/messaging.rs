#![allow(clippy::too_many_arguments)]
use super::*;

pub fn forward(
    message_id: &str,
    from: &str,
    to: &str,
    whoami: &str,
    directory: &str,
) -> Result<()> {
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
    let envelope = seal_to(&identity, &me, to_record.record.primary(), &app.encode())?;
    let queue = QueueTarget::open(&identity, &to_record.record);
    let _ = deliver(
        identity.device_secret(),
        &client,
        &to_handle,
        queue.as_ref(),
        to_record.record.primary(),
        &MailItem::Direct(envelope),
    );
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
    // Per-path tally for observability (#59): how many went out live vs queued.
    let mut direct = 0;
    let mut queued_live = 0;
    for device in &peer_record.record.devices {
        let Ok(envelope) = seal_to(&identity, &me, device, &encoded) else {
            continue;
        };
        let slot = device_slot(&device.device_key);
        let item = MailItem::Direct(envelope);
        let path = deliver_scored(
            &mut fs,
            identity.device_secret(),
            &client,
            &peer_handle,
            queue.as_ref(),
            device,
            &item,
            now,
        );
        match path {
            DeliveryPath::Direct | DeliveryPath::Relay => {
                direct += 1;
                delivered += 1;
            }
            DeliveryPath::Queue => {
                queued_live += 1;
                delivered += 1;
            }
            DeliveryPath::Outbox | DeliveryPath::Failed => {
                let _ =
                    outbox::enqueue(&mut fs, random_id(), peer_handle.as_str(), &slot, item, now);
            }
        }
    }
    let total = peer_record.record.devices.len();
    let outboxed = total - delivered;
    // Keep the "queued for retry" wording (the outbox); append the live-path
    // breakdown so the delivery path is observable (#59).
    let note = if outboxed > 0 {
        format!(" — {outboxed} queued for retry")
    } else {
        String::new()
    };
    let breakdown = if direct > 0 || queued_live > 0 {
        format!(" [{direct} direct, {queued_live} queued]")
    } else {
        String::new()
    };
    println!(
        "sent to '{}' — {delivered}/{total} device(s) (#{}){note}{breakdown}",
        peer_handle.as_str(),
        app.id
    );

    // Record our own copy in this device's transcript, so the conversation shows
    // what we sent (edits/deletes apply to it; other kinds append).
    match &app.body {
        Body::Edit { to, text } => history::edit(&mut fs, peer_handle.as_str(), to, text, true)?,
        Body::Delete { to } => history::delete(&mut fs, peer_handle.as_str(), to, true)?,
        Body::Receipt { .. } => {}
        _ => history::append(
            &mut fs,
            peer_handle.as_str(),
            StoredMessage {
                id: app.id.clone(),
                from_me: true,
                text: app.summary(),
                timestamp: now,
                expires_at: app.expires_at,
            },
        )?,
    }

    // Self-sync: mirror this message to my own other devices (Layer 11).
    if let Ok(my_record) = client.lookup(&me) {
        let my_queue = QueueTarget::open(&identity, &my_record.record);
        let my_key = identity.device_public();
        for device in &my_record.record.devices {
            if device.device_key == my_key {
                continue;
            }
            let Ok(envelope) = seal_to(&identity, &me, device, &encoded) else {
                continue;
            };
            let sync = MailItem::SelfSync {
                peer: peer_handle.as_str().to_string(),
                envelope,
            };
            if !deliver_scored(
                &mut fs,
                identity.device_secret(),
                &client,
                &me,
                my_queue.as_ref(),
                device,
                &sync,
                now,
            )
            .is_delivered()
            {
                let slot = device_slot(&device.device_key);
                let _ = outbox::enqueue(&mut fs, random_id(), me.as_str(), &slot, sync, now);
            }
        }
    }
    Ok(())
}

pub fn broadcast(
    recipients: &[String],
    whoami: &str,
    message: &str,
    directory: &str,
) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let fs = open_history(&identity)?;

    let mut sent = 0;
    for recipient in recipients {
        match lookup_verified(&client, &fs, recipient) {
            Ok((handle, record)) => {
                let app = text_message(message);
                let envelope = seal_to(&identity, &me, record.record.primary(), &app.encode())?;
                let queue = QueueTarget::open(&identity, &record.record);
                if deliver(
                    identity.device_secret(),
                    &client,
                    &handle,
                    queue.as_ref(),
                    record.record.primary(),
                    &MailItem::Direct(envelope),
                )
                .is_delivered()
                {
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
/// Fails if the recipient device published a low-order key.
pub fn seal_to(
    identity: &Identity,
    me: &Handle,
    device: &Device,
    plaintext: &[u8],
) -> Result<Envelope> {
    crate::wireops::seal_to(
        &mut OsPlatform,
        identity,
        me,
        &display_name_for(me),
        &own_queue(),
        device,
        plaintext,
    )
}

/// A recipient's queue endpoints in preference order (#54): the primary
/// `record.queue` first, then each `record.queues` entry, skipping empties and
/// duplicates. Senders deposit to the first endpoint that accepts and fail over
/// to the next on error — the recipient owns and rotates this set. Thin wrapper
/// over [`Record::endpoints`] so the sender-side deposit loop reads naturally.
pub fn endpoints(record: &Record) -> impl Iterator<Item = &str> {
    record.endpoints()
}

/// One logged-in queue session: a live client plus its auth token.
struct QueueSession {
    client: QueueClient,
    token: String,
}

/// A logged-in deposit target: a recipient's reachable queue endpoints plus
/// their wallet key. Built from the recipient's record (the queues live at the
/// endpoints *they* publish, keyed by *their* wallet) — decoupled from the
/// directory. Holds one session per reachable endpoint so a deposit can fail
/// over from a down primary to a backup (#54).
pub struct QueueTarget {
    /// Logged-in sessions in preference order (primary first, then failovers).
    sessions: Vec<QueueSession>,
    wallet_hex: String,
}

impl QueueTarget {
    /// Open a session to each endpoint named in `record`, in preference order
    /// (`queue` then `queues`). Unreachable endpoints (login fails) are skipped;
    /// returns None only if the record lists no endpoint we could log in to.
    pub fn open(identity: &Identity, record: &Record) -> Option<QueueTarget> {
        let mut sessions = Vec::new();
        for url in endpoints(record) {
            let client = QueueClient::new(url);
            if let Ok(token) = client.login(identity) {
                sessions.push(QueueSession { client, token });
            }
        }
        if sessions.is_empty() {
            return None;
        }
        Some(QueueTarget {
            sessions,
            wallet_hex: wallet_hex(&record.wallet),
        })
    }

    /// Deposit `item` into `slot` of this recipient's mailbox, trying each
    /// endpoint in order until one accepts. Returns true on the first success;
    /// only if *every* endpoint fails does the caller fall back to the outbox.
    pub fn deposit(&self, slot: &str, item: &MailItem) -> bool {
        let Ok(json) = serde_json::to_string(item) else {
            return false;
        };
        self.sessions.iter().any(|s| {
            s.client
                .deposit(&s.token, &self.wallet_hex, slot, &json)
                .is_ok()
        })
    }
}

/// Which direct-line transport a device's advertised `peer_id` selects.
///
/// A record advertises either a raw `host:port` (TCP) or a libp2p multiaddr
/// (`/ip4/.../tcp/.../p2p/<peer-id>`, marked by its leading `/`); an empty or
/// non-UTF-8 `peer_id` is unusable for a live push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectTransport {
    /// Raw `host:port` — dial over plain framed TCP.
    Tcp,
    /// A libp2p multiaddr — dial over `libp2p_net` (Noise + Yamux).
    Libp2p,
    /// No usable direct address (empty or non-UTF-8).
    None,
}

/// Classify a device's advertised address into the transport a live push uses.
/// Pure and total, so the send-side transport selection is unit-testable.
fn direct_transport(peer_id: &[u8]) -> DirectTransport {
    match core::str::from_utf8(peer_id) {
        Ok("") => DirectTransport::None,
        // A leading '/' marks a libp2p multiaddr (same rule `chat`/`register` use).
        Ok(addr) if addr.starts_with('/') => DirectTransport::Libp2p,
        Ok(_) => DirectTransport::Tcp,
        Err(_) => DirectTransport::None,
    }
}

/// The live direct-push seam: push `item` over a direct connection to `device`,
/// returning whether it was accepted. Factored out of the ladder so the ordering
/// logic is unit-testable without a real network.
///
/// A raw `host:port` `peer_id` is dialed over framed TCP; a libp2p multiaddr is
/// dialed over `libp2p_net` (Noise authenticates the peer's device key against
/// the `/p2p/<peer-id>` embedded in the record). Either way the receiver is a
/// `serve` loop reading `MailItem` frames. `device_secret` is *our* device key,
/// used only to build the dialing libp2p node.
fn direct_push(device_secret: [u8; 32], device: &Device, item: &MailItem) -> bool {
    let Ok(frame) = serde_json::to_vec(item) else {
        return false;
    };
    match direct_transport(&device.peer_id.0) {
        DirectTransport::None => false,
        DirectTransport::Tcp => {
            let addr = String::from_utf8_lossy(&device.peer_id.0);
            match net::TcpConnection::connect(&addr) {
                Ok(mut conn) => conn.send_frame(&frame).is_ok(),
                Err(_) => false,
            }
        }
        DirectTransport::Libp2p => {
            let addr = String::from_utf8_lossy(&device.peer_id.0);
            push_libp2p(device_secret, &addr, &frame)
        }
    }
}

/// Dial `multiaddr` over libp2p (a fresh dial-only node keyed by our device
/// secret) and push one framed `MailItem`. Returns whether the frame was written.
///
/// The Noise handshake authenticates the responder against the `/p2p/<peer-id>`
/// in the multiaddr — which is derived from the recipient device's key in the
/// signed record — so a successful push reached the pinned identity, not an
/// impostor (the same end-to-end guarantee the TCP path relies on the sealed
/// envelope for, plus transport-level peer authentication).
fn push_libp2p(device_secret: [u8; 32], multiaddr: &str, frame: &[u8]) -> bool {
    let mut node = match libp2p_net::Libp2pNode::new(device_secret, None) {
        Ok(node) => node,
        Err(_) => return false,
    };
    let ok = match node.dial_str(multiaddr) {
        Ok(mut conn) => conn.send_frame(frame).is_ok(),
        Err(_) => false,
    };
    // Let the background swarm flush the buffered frame before the node (and its
    // runtime) drop — mirrors `chat`/`listen`'s drain before exit.
    node.drain(300);
    ok
}

/// The pure delivery ladder: consult `score` (if any) for the order of the
/// direct band, attempt each candidate via the `attempt` seam, record every
/// outcome, and stop at the first success. The queue is the guaranteed floor;
/// if nothing succeeds the result is [`DeliveryPath::Failed`] and the caller
/// parks the item in the outbox — exactly as today.
///
/// `online` gates the live/direct rungs: a peer whose presence is false is only
/// offered the queue, preserving today's "offline → queue" behavior. With
/// `score == None` no memory is consulted or recorded and the order is
/// [`reachability::default_order`], so an unscored caller behaves exactly as
/// before this module existed.
fn deliver_ladder<S, F>(
    mut score: Option<&mut S>,
    online: bool,
    key: &str,
    now: u64,
    mut attempt: F,
) -> DeliveryPath
where
    S: Storage,
    F: FnMut(DeliveryPath) -> bool,
{
    let order = match score.as_deref() {
        Some(s) => reachability::best_paths(s, key, now),
        None => reachability::default_order(),
    };
    for path in order {
        // Live rungs are only worth attempting when the peer is online; the
        // queue floor is always available.
        if path.is_live_direct() && !online {
            continue;
        }
        let ok = attempt(path);
        if let Some(s) = score.as_deref_mut() {
            let _ = reachability::record(s, key, path, ok, now);
        }
        if ok {
            return path;
        }
    }
    DeliveryPath::Failed
}

/// Shared body of [`deliver`] / [`deliver_scored`]: resolve presence, then walk
/// the ladder with the real network seams (direct push, queue deposit).
fn deliver_recording<S: Storage>(
    score: Option<&mut S>,
    device_secret: [u8; 32],
    dir: &DirectoryClient,
    handle: &Handle,
    queue: Option<&QueueTarget>,
    device: &Device,
    item: &MailItem,
    now: u64,
) -> DeliveryPath {
    let online = dir.presence(handle).unwrap_or(false);
    let key = device_slot(&device.device_key);
    deliver_ladder(score, online, &key, now, |path| match path {
        DeliveryPath::Direct => direct_push(device_secret, device, item),
        DeliveryPath::Queue => queue.map(|q| q.deposit(&key, item)).unwrap_or(false),
        // The direct band never emits Relay yet, and Queue/Outbox/Failed aren't
        // attempted as live rungs — nothing else to try.
        _ => false,
    })
}

/// Deliver `item` to one peer device: push it live over a direct connection if
/// the peer is online (runs `serve`), else deposit into their queue (if any).
/// Returns which [`DeliveryPath`] handled it — [`DeliveryPath::is_delivered`]
/// recovers the old `bool`. Best-effort callers use this store-less form (no
/// reachability memory consulted or recorded); the primary send/retry paths use
/// [`deliver_scored`].
pub fn deliver(
    device_secret: [u8; 32],
    dir: &DirectoryClient,
    handle: &Handle,
    queue: Option<&QueueTarget>,
    device: &Device,
    item: &MailItem,
) -> DeliveryPath {
    deliver_recording::<FileStore>(None, device_secret, dir, handle, queue, device, item, 0)
}

/// Like [`deliver`], but consults and updates the local, per-device
/// [`reachability`] score so a device known-unreachable-direct isn't made to pay
/// a full direct-dial timeout first, and each outcome is remembered. The queue +
/// outbox remain the guaranteed fallback.
pub fn deliver_scored(
    store: &mut FileStore,
    device_secret: [u8; 32],
    dir: &DirectoryClient,
    handle: &Handle,
    queue: Option<&QueueTarget>,
    device: &Device,
    item: &MailItem,
    now: u64,
) -> DeliveryPath {
    deliver_recording(
        Some(store),
        device_secret,
        dir,
        handle,
        queue,
        device,
        item,
        now,
    )
}

/// Deliver the *same* item to every device in a handle's cluster (Layer 11),
/// via their queue for the offline devices.
pub fn deliver_to_cluster(
    dir: &DirectoryClient,
    identity: &Identity,
    handle: &Handle,
    item: &MailItem,
) {
    if let Ok(rec) = dir.lookup(handle) {
        if rec.verify().is_ok() {
            let queue = QueueTarget::open(identity, &rec.record);
            for device in &rec.record.devices {
                let _ = deliver(
                    identity.device_secret(),
                    dir,
                    handle,
                    queue.as_ref(),
                    device,
                    item,
                );
            }
        }
    }
}

/// Like [`deliver_to_cluster`], but parks any device we couldn't reach in the
/// outbox for retry — so group messages aren't silently lost on a transient
/// failure (Tier 2.3). `flush_outbox` re-attempts them on the next send.
pub fn deliver_to_cluster_or_queue(
    dir: &DirectoryClient,
    identity: &Identity,
    handle: &Handle,
    item: &MailItem,
    fs: &mut FileStore,
    now: u64,
) {
    if let Ok(rec) = dir.lookup(handle) {
        if rec.verify().is_ok() {
            let queue = QueueTarget::open(identity, &rec.record);
            for device in &rec.record.devices {
                if !deliver_scored(
                    fs,
                    identity.device_secret(),
                    dir,
                    handle,
                    queue.as_ref(),
                    device,
                    item,
                    now,
                )
                .is_delivered()
                {
                    let slot = device_slot(&device.device_key);
                    let _ =
                        outbox::enqueue(fs, random_id(), handle.as_str(), &slot, item.clone(), now);
                }
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
    // Deposit every entry whose delay has elapsed; not-yet-due entries are left
    // for a later flush by `flush_pass` (never counted as an attempt). Batching
    // is implicit: all currently-due entries go out in this one pass.
    let (delivered, remaining) = outbox::flush_pass(entries, now, |entry| {
        let handle = match Handle::new(entry.recipient.clone()) {
            Ok(h) => h,
            Err(_) => return outbox::Attempt::Drop, // unparseable recipient — drop it
        };
        // Re-resolve the recipient's current record (queue/devices may have
        // moved). This is the safe-rotation path (#53): a stale endpoint that
        // failed is never reused from a cache — every retry does a fresh
        // directory lookup, so once the recipient re-publishes a rotated
        // `queue`/`queues` set, senders pick it up automatically. The grace
        // period is implicit: a rotating recipient keeps draining its old
        // endpoint until in-flight senders have re-resolved to the new one.
        let record = match client.lookup(&handle) {
            Ok(r) if r.verify().is_ok() => r,
            // Couldn't resolve/verify: bump and keep unless spent.
            _ => return outbox::Attempt::Retry,
        };
        // The device this copy was sealed for; if it's gone, drop the entry.
        let Some(device) = record
            .record
            .devices
            .iter()
            .find(|d| device_slot(&d.device_key) == entry.slot)
        else {
            return outbox::Attempt::Drop;
        };
        let queue = QueueTarget::open(identity, &record.record);
        if deliver_scored(
            fs,
            identity.device_secret(),
            client,
            &handle,
            queue.as_ref(),
            device,
            &entry.item,
            now,
        )
        .is_delivered()
        {
            outbox::Attempt::Delivered
        } else {
            outbox::Attempt::Retry
        }
    });
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
        println!(
            "  → {}  (device {}, {}s old, {} attempt(s))",
            e.recipient,
            &e.slot[..8.min(e.slot.len())],
            age,
            e.attempts
        );
    }
    Ok(())
}

/// Accept live-pushed items from peers and process them (the `serve` receiver).
///
/// `libp2p` selects the receive transport, matching how the account registered:
/// a libp2p multiaddr recipient listens on a `libp2p_net` node for the
/// `/mycellium/1.0` stream protocol; a raw `host:port` recipient listens on
/// framed TCP. Both feed received `MailItem` frames into the same `process_item`
/// path, so senders reach an online recipient live over whichever transport its
/// record advertises (#59).
pub fn serve(addr: &str, whoami: &str, libp2p: bool, directory: &str) -> Result<()> {
    let identity = std::sync::Arc::new(store::load_identity()?);
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let _ = client.announce(&token, &me); // mark ourselves online for delivery

    // Keep presence fresh: it expires after the directory's PRESENCE_TTL (60s),
    // so re-announce well inside that window while we're serving. Re-logging in
    // each cycle also transparently handles a session-token expiry.
    {
        let identity = std::sync::Arc::clone(&identity);
        let directory = directory.to_string();
        let me = me.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            let client = DirectoryClient::new(&directory);
            if let Ok(token) = client.login(&identity) {
                let _ = client.announce(&token, &me);
            }
        });
    }

    let mut fs = open_history(&identity)?;
    let blocked = blocklist::load(&fs)?;

    let mut platform = OsPlatform;
    if libp2p {
        // libp2p receive path: bind a node and accept `/mycellium/1.0` streams.
        // Each inbound stream carries `MailItem` frames pushed by a sender's
        // `direct_push`; feed them into the SAME `process_item` path as TCP.
        let listen_addr = libp2p_net::listen_multiaddr(addr).context("bad serve address")?;
        let mut node = libp2p_net::Libp2pNode::new(identity.device_secret(), Some(listen_addr))
            .context("could not start libp2p node")?;
        println!(
            "serving (libp2p) on {addr} as {} ({}) — receiving live messages",
            me.as_str(),
            node.peer_id()
        );
        loop {
            let mut conn = match node.accept() {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            while let Ok(frame) = conn.recv_frame() {
                if let Ok(item) = serde_json::from_slice::<MailItem>(&frame) {
                    let _ = process_item(
                        &identity,
                        &me,
                        &client,
                        &blocked,
                        &mut platform,
                        &mut fs,
                        item,
                    );
                }
            }
        }
    } else {
        let mut transport = TcpTransport::listening(addr).context("could not bind address")?;
        println!(
            "serving on {addr} as {} — receiving live messages",
            me.as_str()
        );
        loop {
            let mut conn = match transport.accept() {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            while let Ok(frame) = conn.recv_frame() {
                if let Ok(item) = serde_json::from_slice::<MailItem>(&frame) {
                    let _ = process_item(
                        &identity,
                        &me,
                        &client,
                        &blocked,
                        &mut platform,
                        &mut fs,
                        item,
                    );
                }
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
            blobs = queue
                .collect(&qtoken, &my_hex, &my_slot)
                .unwrap_or_default();
            blobs.extend(
                queue
                    .collect(&qtoken, &my_hex, ACCOUNT_SLOT)
                    .unwrap_or_default(),
            );
        }
    }
    let mut fs = open_history(&identity)?;
    let blocked = blocklist::load(&fs)?;
    // Opportunistically retry anything stuck in our outbox while we're online.
    let _ = flush_outbox(&identity, &client, &mut fs);

    let now = OsPlatform.now_unix_secs();
    // Write-ahead: collecting drained these from the queue, so persist them (plus
    // anything still pending from a previous run) to the retry store BEFORE
    // processing. A crash, a not-yet-decryptable group message, or a transient
    // error can then be retried next time instead of being lost.
    let mut pending = inbound::load(&fs).unwrap_or_default();
    for blob in blobs {
        pending.push(inbound::PendingItem {
            blob,
            created_at: now,
            attempts: 0,
        });
    }
    let _ = inbound::save(&mut fs, &pending);

    if pending.is_empty() {
        println!("no new messages");
        return Ok(());
    }

    let mut platform = OsPlatform;
    let mut survivors = Vec::new();
    for mut entry in pending {
        if entry.is_expired(now) {
            eprintln!("(giving up on an item after {} tries)", entry.attempts);
            continue; // dead-letter: drop
        }
        let processed = match serde_json::from_str::<MailItem>(&entry.blob) {
            Ok(item) => process_item(
                &identity,
                &me,
                &client,
                &blocked,
                &mut platform,
                &mut fs,
                item,
            )
            .is_ok(),
            Err(_) => false, // unparseable — keep retrying until it dead-letters
        };
        if !processed {
            entry.attempts += 1;
            survivors.push(entry); // retry next inbox
        }
    }
    // Only failures remain in the retry store.
    let _ = inbound::save(&mut fs, &survivors);
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
        MailItem::SelfSync { peer, envelope } => {
            handle_self_sync(identity, platform, fs, &peer, &envelope)
        }
        MailItem::GroupSync(env) => handle_group_sync(identity, me, client, platform, fs, &env),
        MailItem::GroupInvite(env) => handle_group_invite(identity, me, client, fs, platform, &env),
        MailItem::GroupText { group_id, message } => {
            handle_group_text(blocked, fs, &group_id, &message)
        }
        MailItem::GroupLeave(env) => handle_group_leave(identity, me, client, fs, &env),
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
        Body::Edit { to, text } => history::edit(fs, peer, to, text, true)?,
        Body::Delete { to } => history::delete(fs, peer, to, true)?,
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
    // Learn the sender's self-set name (from their signed record), so an unsaved
    // sender shows "Mary" rather than a raw id. A saved contact still wins.
    let _ = names::note(fs, from.as_str(), &env.sender_record.record.name);

    match AppMessage::decode(&bytes) {
        Ok(app) => match &app.body {
            // A receipt: show the status; never receipt a receipt (no loops).
            Body::Receipt { message_id, read } => {
                let mark = if *read { "read" } else { "delivered" };
                println!("✓ {} {mark} your message #{message_id}", from.as_str());
            }
            // An edit or deletion of an earlier message: apply to the transcript.
            Body::Edit { to, text } => {
                history::edit(fs, from.as_str(), to, text, false)?;
                println!("from {}: edited #{to}", from.as_str());
            }
            Body::Delete { to } => {
                history::delete(fs, from.as_str(), to, false)?;
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
            let entry = StoredMessage {
                id: String::new(),
                from_me: false,
                text,
                timestamp: OsPlatform.now_unix_secs(),
                expires_at: None,
            };
            history::append(fs, from.as_str(), entry)?;
        }
    }
    Ok(())
}

/// Send a read receipt for `message_id` back to `to` (best-effort).
pub fn send_receipt(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    to: &Handle,
    message_id: &str,
) {
    let record = match client.lookup(to) {
        Ok(r) if r.verify().is_ok() => r,
        _ => return,
    };
    let receipt = AppMessage {
        id: random_id(),
        timestamp: OsPlatform.now_unix_secs(),
        expires_at: None,
        body: Body::Receipt {
            message_id: message_id.to_string(),
            read: true,
        },
    };
    // Fan the receipt out to every device of the original sender (Layer 11), so
    // whichever device they sent from sees the read status.
    let encoded = receipt.encode();
    let queue = QueueTarget::open(identity, &record.record);
    for device in &record.record.devices {
        let Ok(env) = seal_to(identity, me, device, &encoded) else {
            continue;
        };
        let _ = deliver(
            identity.device_secret(),
            client,
            to,
            queue.as_ref(),
            device,
            &MailItem::Direct(env),
        );
    }
}

/// Authenticate the sender and decrypt one offline envelope to raw bytes.
pub fn open_envelope(
    identity: &Identity,
    platform: &mut OsPlatform,
    env: &Envelope,
) -> Result<(Handle, Vec<u8>)> {
    crate::wireops::open_envelope(platform, identity, env)
}

#[cfg(test)]
mod ladder_tests {
    //! The delivery-ladder ordering logic, exercised through the network seam
    //! (`attempt`) with an in-memory score store — no real network. The live
    //! push (`direct_push`) and queue deposit are the *only* network parts, and
    //! they are provided by the mock closure here, so these assert purely on the
    //! order the ladder tries paths and the outcome it reports.

    use super::*;
    use crate::reachability::{self, DeliveryPath};
    use mycellium_core::storage::Storage;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::convert::Infallible;

    #[derive(Default)]
    struct MemStore(HashMap<Vec<u8>, Vec<u8>>);
    impl Storage for MemStore {
        type Error = Infallible;
        fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, Infallible> {
            Ok(self.0.get(k).cloned())
        }
        fn put(&mut self, k: &[u8], v: &[u8]) -> Result<(), Infallible> {
            self.0.insert(k.to_vec(), v.to_vec());
            Ok(())
        }
        fn delete(&mut self, k: &[u8]) -> Result<(), Infallible> {
            self.0.remove(k);
            Ok(())
        }
    }

    #[test]
    fn cold_start_tries_direct_then_queue() {
        let mut store = MemStore::default();
        let tried = RefCell::new(Vec::new());
        // Direct fails, queue succeeds → the ladder escalates to the queue.
        let path = deliver_ladder(Some(&mut store), true, "dev", 1_000, |p| {
            tried.borrow_mut().push(p);
            matches!(p, DeliveryPath::Queue)
        });
        assert_eq!(path, DeliveryPath::Queue);
        assert_eq!(
            *tried.borrow(),
            vec![DeliveryPath::Direct, DeliveryPath::Queue],
            "an unknown device is tried direct-first, queue as the floor"
        );
    }

    #[test]
    fn direct_success_stops_before_the_queue() {
        let mut store = MemStore::default();
        let tried = RefCell::new(Vec::new());
        let path = deliver_ladder(Some(&mut store), true, "dev", 1_000, |p| {
            tried.borrow_mut().push(p);
            true
        });
        assert_eq!(path, DeliveryPath::Direct);
        assert_eq!(*tried.borrow(), vec![DeliveryPath::Direct]);
    }

    #[test]
    fn offline_skips_direct_and_uses_the_queue() {
        let mut store = MemStore::default();
        let tried = RefCell::new(Vec::new());
        let path = deliver_ladder(Some(&mut store), false, "dev", 1_000, |p| {
            tried.borrow_mut().push(p);
            true
        });
        assert_eq!(path, DeliveryPath::Queue);
        assert_eq!(
            *tried.borrow(),
            vec![DeliveryPath::Queue],
            "an offline peer must not be direct-dialed"
        );
    }

    #[test]
    fn seeded_dead_direct_tries_the_queue_first() {
        let mut store = MemStore::default();
        // Seed a demonstrably-dead direct path (several failures, no success).
        for t in [100u64, 160, 220] {
            reachability::record(&mut store, "dev", DeliveryPath::Direct, false, t).unwrap();
        }
        let tried = RefCell::new(Vec::new());
        let path = deliver_ladder(Some(&mut store), true, "dev", 260, |p| {
            tried.borrow_mut().push(p);
            matches!(p, DeliveryPath::Queue)
        });
        assert_eq!(path, DeliveryPath::Queue);
        assert_eq!(
            tried.borrow()[0],
            DeliveryPath::Queue,
            "a device known-unreachable-direct must not pay the direct-dial first"
        );
    }

    #[test]
    fn seeded_dead_direct_still_records_and_reprobes_later() {
        let mut store = MemStore::default();
        for t in [100u64, 160, 220] {
            reachability::record(&mut store, "dev", DeliveryPath::Direct, false, t).unwrap();
        }
        // After the re-probe interval, direct is offered first again.
        let tried = RefCell::new(Vec::new());
        let _ = deliver_ladder(
            Some(&mut store),
            true,
            "dev",
            220 + reachability::REPROBE_SECS + 1,
            |p| {
                tried.borrow_mut().push(p);
                matches!(p, DeliveryPath::Direct)
            },
        );
        assert_eq!(
            tried.borrow()[0],
            DeliveryPath::Direct,
            "direct is never permanently abandoned — it is periodically re-probed"
        );
    }

    #[test]
    fn unscored_ladder_matches_the_default_order() {
        // No score store: behaves exactly as before this module existed.
        let tried = RefCell::new(Vec::new());
        let path = deliver_ladder::<MemStore, _>(None, true, "dev", 0, |p| {
            tried.borrow_mut().push(p);
            matches!(p, DeliveryPath::Queue)
        });
        assert_eq!(path, DeliveryPath::Queue);
        assert_eq!(
            *tried.borrow(),
            vec![DeliveryPath::Direct, DeliveryPath::Queue]
        );
    }

    #[test]
    fn nothing_works_reports_failed() {
        let mut store = MemStore::default();
        let path = deliver_ladder(Some(&mut store), true, "dev", 0, |_p| false);
        assert_eq!(path, DeliveryPath::Failed);
    }

    #[test]
    fn outcomes_are_recorded_into_the_score() {
        let mut store = MemStore::default();
        // A direct success is remembered, keeping direct first next time.
        let _ = deliver_ladder(Some(&mut store), true, "dev", 1_000, |p| {
            matches!(p, DeliveryPath::Direct)
        });
        assert_eq!(
            reachability::best_paths(&store, "dev", 1_050),
            reachability::default_order(),
            "a recorded direct success keeps direct ahead of the queue"
        );
    }
}

#[cfg(test)]
mod transport_tests {
    //! The send-side transport selection: which live-push transport a device's
    //! advertised `peer_id` maps to. Pure classification — no network.

    use super::{direct_transport, DirectTransport};

    #[test]
    fn raw_host_port_selects_tcp() {
        assert_eq!(direct_transport(b"127.0.0.1:9001"), DirectTransport::Tcp);
        assert_eq!(
            direct_transport(b"example.com:443"),
            DirectTransport::Tcp,
            "a hostname:port is still a TCP address"
        );
    }

    #[test]
    fn leading_slash_selects_libp2p() {
        // A full dialable multiaddr (with the /p2p/<peer-id> component).
        assert_eq!(
            direct_transport(b"/ip4/127.0.0.1/tcp/9001/p2p/12D3KooWabc"),
            DirectTransport::Libp2p,
        );
        // Even a bare multiaddr prefix classifies as libp2p (the dial fails later,
        // falling through to the queue — the classifier only picks the transport).
        assert_eq!(
            direct_transport(b"/ip4/10.0.0.2/tcp/1"),
            DirectTransport::Libp2p,
        );
    }

    #[test]
    fn empty_or_non_utf8_is_unusable() {
        assert_eq!(direct_transport(b""), DirectTransport::None);
        assert_eq!(
            direct_transport(&[0xff, 0xfe, 0x00]),
            DirectTransport::None,
            "a non-UTF-8 peer_id has no usable direct address"
        );
    }
}
