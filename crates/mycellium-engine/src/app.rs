//! The engine's orchestration (headless): create/restore an identity, register,
//! open a direct line (X3DH + Double Ratchet), deliver live or via the mailbox,
//! run groups and multi-device — everything a shell drives, minus presentation.
#![allow(clippy::too_many_arguments)]

use anyhow::{anyhow, bail, Context, Result};

use mycellium_core::group::{Group, GroupMessage};
use mycellium_core::identity::{DevicePublicKey, Handle, Identity, MessagingPublicKey, PeerId};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::offline::Envelope;
use mycellium_core::platform::Platform;
use mycellium_core::ratchet::Ratchet;
use mycellium_core::record::{Device, Record, SignedPreKey, SignedRecord};
use mycellium_core::safety;
use mycellium_core::shamir::{self, Share};
use mycellium_core::transport::Transport;
use mycellium_core::wire;
use mycellium_core::x3dh::{self, HandshakeInit};

use mycellium_directory_client::DirectoryClient;
use mycellium_storage::filestore::FileStore;
use mycellium_storage::store;
use crate::blocklist;
use crate::contacts::{self, Contact};
use crate::draft;
use crate::expiry;
use crate::groups::{self, GroupInvitePayload, GroupSyncPayload, MailItem, StoredGroup};
use crate::history::{self, GroupStoredMessage, StoredMessage};
use crate::platform::OsPlatform;
use mycellium_transport::libp2p_net::{self};
use mycellium_transport::link::{FrameReader, FrameWriter, Wire};
use mycellium_transport::net::{self, TcpTransport};



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


pub fn wipe(yes: bool) -> Result<()> {
    if !yes {
        bail!("this erases ALL local data (identity + messages); re-run with --yes to confirm");
    }
    let dir = store::data_dir();
    if dir.exists() {
        std::fs::remove_dir_all(&dir).context("could not wipe data directory")?;
    }
    println!("wiped all local data");
    Ok(())
}


/// A portable backup: the encrypted identity plus every store entry (already
/// encrypted at rest, so the bundle needs no extra protection).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Backup {
    identity: Vec<u8>,
    store: Vec<(String, Vec<u8>)>,
}


pub fn export_backup(path: &str) -> Result<()> {
    // Require unlocking the identity to authorize the export.
    let _ = store::load_identity()?;
    let identity = std::fs::read(store::path()).context("could not read identity")?;

    let store_dir = store::data_dir().join("history");
    let mut entries = Vec::new();
    if store_dir.exists() {
        for entry in std::fs::read_dir(&store_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let name = entry.file_name().to_string_lossy().into_owned();
                entries.push((name, std::fs::read(entry.path())?));
            }
        }
    }

    let backup = Backup { identity, store: entries };
    std::fs::write(path, wire::encode(&backup)).context("could not write backup")?;
    println!("exported identity + {} store entries to {path}", backup.store.len());
    Ok(())
}


pub fn import_backup(path: &str) -> Result<()> {
    if store::exists() {
        bail!(
            "an identity already exists at {} — import into a fresh MYCELLIUM_HOME",
            store::path().display()
        );
    }
    let bytes = std::fs::read(path).context("could not read backup")?;
    let backup: Backup = wire::decode(&bytes).map_err(|_| anyhow!("not a valid backup file"))?;

    std::fs::create_dir_all(store::data_dir())?;
    std::fs::write(store::path(), &backup.identity)?;

    let store_dir = store::data_dir().join("history");
    std::fs::create_dir_all(&store_dir)?;
    for (name, data) in &backup.store {
        // Only ever write a basename inside the store dir.
        if let Some(safe) = std::path::Path::new(name).file_name().and_then(|n| n.to_str()) {
            std::fs::write(store_dir.join(safe), data)?;
        }
    }
    println!("imported identity + {} store entries", backup.store.len());
    Ok(())
}


/// Resolve an expiry target (a peer nickname/handle, or a group id) to its store key.
pub fn expire_key(fs: &FileStore, target: &str) -> Result<String> {
    // A group id resolves to itself; otherwise treat as a peer handle/nickname.
    if groups::load(fs, target)?.is_some() {
        Ok(target.to_string())
    } else {
        Ok(contacts::resolve(fs, target)?)
    }
}


pub fn expire_set(target: &str, duration: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let secs = parse_duration(duration)?;
    let mut fs = open_history(&identity)?;
    let key = expire_key(&fs, target)?;
    expiry::set(&mut fs, &key, secs)?;
    println!("messages to '{key}' now disappear after {duration}");
    Ok(())
}


pub fn expire_clear(target: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = expire_key(&fs, target)?;
    expiry::clear(&mut fs, &key)?;
    println!("cleared disappearing-message timer for '{key}'");
    Ok(())
}


pub fn expire_show(target: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let key = expire_key(&fs, target)?;
    match expiry::get(&fs, &key)? {
        Some(secs) => println!("'{key}': messages disappear after {secs}s"),
        None => println!("'{key}': no disappearing-message timer"),
    }
    Ok(())
}


pub fn announce(whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    client.announce(&token, &me)?;
    println!("announced '{}' online", me.as_str());
    Ok(())
}


pub fn verify(peer: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let client = DirectoryClient::new(directory);
    let (peer_handle, peer_record) = lookup_verified(&client, &fs, peer)?;
    let sn = safety::safety_number(&identity.wallet_public(), &peer_record.record.wallet);
    println!("safety number with '{}': {sn}", peer_handle.as_str());
    println!("compare it with them out of band — if it matches, no one is impersonating either of you.");
    Ok(())
}


pub fn presence(peer: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let handle_str = contacts::resolve(&fs, peer)?;
    let handle = Handle::new(handle_str).map_err(|_| anyhow!("invalid handle or nickname"))?;
    let client = DirectoryClient::new(directory);
    let online = client.presence(&handle)?;
    println!("{} is {}", handle.as_str(), if online { "online" } else { "offline" });
    Ok(())
}


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
        return Ok(());
    }
    for h in list {
        println!("{h}");
    }
    Ok(())
}


pub fn contact_add(nickname: &str, handle: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let client = DirectoryClient::new(directory);
    let record = client.lookup(&handle)?;
    record
        .verify()
        .map_err(|_| anyhow!("that handle's record failed verification"))?;

    let mut fs = open_history(&identity)?;
    let contact = Contact {
        nickname: nickname.to_string(),
        handle: handle.as_str().to_string(),
        wallet: record.record.wallet,
    };
    contacts::save(&mut fs, &contact)?;
    println!("added '{}' → {}", nickname, handle.as_str());
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
        println!("{} → {}", c.nickname, c.handle);
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


/// Resolve a nickname to a handle (or pass a raw handle through), then verify
/// the record matches any pinned wallet for that contact (TOFU).
pub fn lookup_verified(
    client: &DirectoryClient,
    fs: &FileStore,
    input: &str,
) -> Result<(Handle, SignedRecord)> {
    let resolved = contacts::resolve(fs, input)?;
    let handle = Handle::new(resolved).map_err(|_| anyhow!("invalid handle or nickname"))?;
    let record = client.lookup(&handle)?;
    record
        .verify()
        .map_err(|_| anyhow!("peer's record failed verification"))?;

    if let Some(contact) = contacts::by_handle(fs, handle.as_str())? {
        if contact.wallet != record.record.wallet {
            bail!(
                "'{}' identity CHANGED since you added it — refusing (possible impersonation)",
                handle.as_str()
            );
        }
    }
    Ok((handle, record))
}


/// Open the encrypted local history store for this identity.
pub fn open_history(identity: &Identity) -> Result<FileStore> {
    FileStore::open(store::data_dir().join("history"), identity.storage_key())
        .context("could not open local history store")
}


pub fn clear_history(peer: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = contacts::resolve(&fs, peer)?;
    history::clear(&mut fs, &key)?;
    println!("cleared history with '{key}'");
    Ok(())
}


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
    let token = client.login(&identity)?;
    let (to_handle, to_record) = lookup_verified(&client, &fs, to)?;
    let app = text_message(&forwarded);
    let envelope = seal_to(&identity, &me, to_record.record.primary(), &app.encode());
    deliver(&client, &token, &to_handle, to_record.record.primary(), &MailItem::Direct(envelope));
    println!("forwarded #{message_id} to '{}'", to_handle.as_str());
    Ok(())
}


/// Truncate a preview string to a readable length.
pub fn preview(text: &str) -> String {
    let text: String = text.chars().take(48).collect();
    text
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
    for id in groups::list(&fs)? {
        if let Some(g) = groups::load(&fs, &id)? {
            let msgs = history::group_load_active(&mut fs, &id, now)?;
            let last = msgs
                .last()
                .map(|m| format!("{}: {}", m.sender, preview(&m.text)))
                .unwrap_or_else(|| "(no messages)".to_string());
            println!("[group {}] {last}", g.name);
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

    // One-to-one transcripts.
    for peer in history::peers(&fs)? {
        for m in history::load_active(&mut fs, &peer, now)? {
            if m.text.to_lowercase().contains(&needle) {
                let who = if m.from_me { "you" } else { peer.as_str() };
                println!("[{peer}] {who}: {}", m.text);
                hits += 1;
            }
        }
    }

    // Group transcripts.
    for id in groups::list(&fs)? {
        let name = groups::load(&fs, &id)?.map(|g| g.name).unwrap_or_else(|| id.clone());
        for m in history::group_load_active(&mut fs, &id, now)? {
            if m.text.to_lowercase().contains(&needle) {
                println!("[group {name}] {}: {}", m.sender, m.text);
                hits += 1;
            }
        }
    }

    if hits == 0 {
        println!("no matches for '{query}'");
    } else {
        println!("\n{hits} match(es)");
    }
    Ok(())
}


pub fn show_history(peer: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let peer_handle = Handle::new(peer).map_err(|_| anyhow!("invalid peer handle"))?;
    let mut fs = open_history(&identity)?;
    let now = OsPlatform.now_unix_secs();
    let transcript = history::load_active(&mut fs, peer_handle.as_str(), now)
        .map_err(|e| anyhow!("read history: {e}"))?;
    if transcript.is_empty() {
        println!("no stored history with '{peer}'");
        return Ok(());
    }
    for m in transcript {
        let who = if m.from_me { "you" } else { peer };
        println!("{who}: {}", m.text);
    }
    Ok(())
}


// ---- commands ---------------------------------------------------------------

pub fn identity_new() -> Result<()> {
    if store::exists() {
        bail!("an identity already exists at {}", store::path().display());
    }
    let identity = Identity::generate(&mut OsPlatform)?;
    store::save_identity(&identity)?;
    println!("New identity created. Write down these 24 words and keep them safe:\n");
    println!("    {}\n", identity.mnemonic());
    println!("wallet: {}", hex(&identity.wallet_public().0));
    Ok(())
}


pub fn identity_show() -> Result<()> {
    let identity = store::load_identity()?;
    println!("wallet:      {}", hex(&identity.wallet_public().0));
    println!("device:      {}", hex(&identity.device_public().0));
    println!("device-id:   {}  (this device, as shown by `devices`)", short_device_id(&identity.device_public()));
    println!("messaging:   {}", hex(&identity.messaging_public().0));
    println!("signed-pk:   {}", hex(&identity.signed_pre_key_public().0));
    Ok(())
}


pub fn register(handle: &str, addr: &str, libp2p: bool, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;

    // The record's location is a raw `host:port` for TCP, or a full multiaddr
    // (with the PeerId) for libp2p. `chat` auto-detects which by its leading `/`.
    let location = if libp2p {
        libp2p_net::advertised_multiaddr(addr, identity.device_secret())?
    } else {
        addr.to_string()
    };
    let record = build_record(&identity, &handle, &location);

    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    client.publish(&token, &handle, &record)?;
    println!("registered '{}' reachable at {}", handle.as_str(), location);
    Ok(())
}


/// An established, ready-to-use session: the ratchet, the AEAD associated data,
/// and the peer's display name.
pub struct Session {
    pub ratchet: Ratchet,
    pub ad: Vec<u8>,
    pub peer_name: String,
}


/// Initiator handshake: send our record + X3DH init, build the session.
pub fn handshake_initiator(
    conn: &mut dyn Wire,
    identity: &Identity,
    me: &Handle,
    peer_handle: &Handle,
    peer_record: &SignedRecord,
    location: &str,
) -> Result<Session> {
    let my_record = build_record(identity, me, "");
    conn.send(&wire::encode(&my_record))?;

    let mut platform = OsPlatform;
    let responder_ik = peer_record.record.primary().id_key;
    let responder_spk = peer_record.record.primary().signed_pre_key.public;
    let initiated = x3dh::initiate(&mut platform, identity, &responder_ik, &responder_spk);
    conn.send(&wire::encode(&initiated.init))?;

    let ratchet = Ratchet::new_initiator(&mut platform, &initiated.shared_secret, &responder_spk);
    let ad = associated_data(&identity.messaging_public(), &responder_ik);

    let sn = safety::safety_number(&identity.wallet_public(), &peer_record.record.wallet);
    println!("connected to '{}' at {} — end-to-end encrypted.", peer_handle.as_str(), location);
    println!("safety number (verify with '{}' out of band): {sn}", peer_handle.as_str());
    println!("Type messages (Ctrl-D to quit):");

    Ok(Session { ratchet, ad, peer_name: peer_handle.as_str().to_string() })
}


/// Responder handshake: read the peer's record + X3DH init, build the session.
pub fn handshake_responder(conn: &mut dyn Wire, identity: &Identity) -> Result<Session> {
    let peer_record: SignedRecord = wire::decode(&conn.recv()?)?;
    peer_record
        .verify()
        .map_err(|_| anyhow!("peer's record failed verification"))?;
    let init: HandshakeInit = wire::decode(&conn.recv()?)?;

    let shared = x3dh::respond(identity, &init);
    let ratchet = Ratchet::new_responder(&shared, identity);
    let ad = associated_data(&init.initiator_ik, &identity.messaging_public());
    let who = peer_record.record.handle.as_str().to_string();

    let sn = safety::safety_number(&identity.wallet_public(), &peer_record.record.wallet);
    println!("connected with '{who}' — end-to-end encrypted.");
    println!("safety number (verify with '{who}' out of band): {sn}");
    println!("Type messages (Ctrl-D to quit):");

    Ok(Session { ratchet, ad, peer_name: who })
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
    let token = client.login(&identity)?;
    let fs = open_history(&identity)?;
    let (peer_handle, peer_record) = lookup_verified(&client, &fs, peer)?;

    let expires_at = resolve_expiry(&fs, peer_handle.as_str(), expire)?;
    let app = build_message(message, reply_to, react, to, file, edit, delete, expires_at)?;
    let encoded = app.encode();

    // Fan out one sealed copy per recipient device (Layer 11) — each device has
    // its own keys, so every device in the cluster receives it.
    let mut delivered = 0;
    for device in &peer_record.record.devices {
        let envelope = seal_to(&identity, &me, device, &encoded);
        if deliver(&client, &token, &peer_handle, device, &MailItem::Direct(envelope)) {
            delivered += 1;
        }
    }
    let total = peer_record.record.devices.len();
    println!("sent to '{}' — {delivered}/{total} device(s) (#{})", peer_handle.as_str(), app.id);

    // Self-sync: mirror this message to my own other devices (Layer 11).
    if let Ok(my_record) = client.lookup(&me) {
        let my_key = identity.device_public();
        for device in &my_record.record.devices {
            if device.device_key == my_key {
                continue;
            }
            let envelope = seal_to(&identity, &me, device, &encoded);
            let sync = MailItem::SelfSync { peer: peer_handle.as_str().to_string(), envelope };
            deliver(&client, &token, &me, device, &sync);
        }
    }
    Ok(())
}


pub fn broadcast(recipients: &[String], whoami: &str, message: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let fs = open_history(&identity)?;

    let mut sent = 0;
    for recipient in recipients {
        match lookup_verified(&client, &fs, recipient) {
            Ok((handle, record)) => {
                let app = text_message(message);
                let envelope = seal_to(&identity, &me, record.record.primary(), &app.encode());
                if deliver(&client, &token, &handle, record.record.primary(), &MailItem::Direct(envelope)) {
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


pub fn deposit_item(client: &DirectoryClient, token: &str, to: &Handle, slot: &str, item: &MailItem) -> Result<()> {
    client.deposit(token, to, slot, &serde_json::to_string(item)?)
}


/// Deliver `item` to a peer: push it live over a direct connection if they are
/// online and reachable (they run `serve`), otherwise queue it in their mailbox.
pub fn deliver(
    client: &DirectoryClient,
    token: &str,
    handle: &Handle,
    device: &Device,
    item: &MailItem,
) -> bool {
    let slot = device_slot(&device.device_key);
    let online = client.presence(handle).unwrap_or(false);
    if online {
        if let Ok(addr) = String::from_utf8(device.peer_id.0.clone()) {
            // Push over a plain TCP `serve` endpoint (a raw host:port).
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
    deposit_item(client, token, handle, &slot, item).is_ok()
}


/// Deliver the *same* item to every device in a handle's cluster (Layer 11).
/// Used for cluster-uniform items (group text/control); falls back to the
/// account slot if the record can't be fetched.
pub fn deliver_to_cluster(client: &DirectoryClient, token: &str, handle: &Handle, item: &MailItem) {
    match client.lookup(handle) {
        Ok(rec) if rec.verify().is_ok() => {
            for device in &rec.record.devices {
                deliver(client, token, handle, device, item);
            }
        }
        _ => {
            let _ = deposit_item(client, token, handle, ACCOUNT_SLOT, item);
        }
    }
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
                let _ = process_item(&identity, &me, &client, &token, &blocked, &mut platform, &mut fs, item);
            }
        }
    }
}


pub fn inbox(whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;

    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    // Drain this device's own slot plus the cluster-wide account slot.
    let my_slot = device_slot(&identity.device_public());
    let mut blobs = client.collect(&token, &me, &my_slot)?;
    blobs.extend(client.collect(&token, &me, ACCOUNT_SLOT)?);
    let mut fs = open_history(&identity)?;
    let blocked = blocklist::load(&fs)?;

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
        if let Err(err) = process_item(&identity, &me, &client, &token, &blocked, &mut platform, &mut fs, item) {
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
    token: &str,
    blocked: &[String],
    platform: &mut OsPlatform,
    fs: &mut FileStore,
    item: MailItem,
) -> Result<()> {
    match item {
        MailItem::Direct(env) => handle_direct(identity, me, client, token, blocked, platform, fs, &env),
        MailItem::SelfSync { peer, envelope } => handle_self_sync(identity, platform, fs, &peer, &envelope),
        MailItem::GroupSync(env) => handle_group_sync(identity, me, client, token, platform, fs, &env),
        MailItem::GroupInvite(env) => handle_group_invite(identity, me, client, token, fs, platform, &env),
        MailItem::GroupText { group_id, message } => handle_group_text(blocked, fs, &group_id, &message),
        MailItem::GroupRemove { group_id, member } => {
            handle_group_remove(identity, me, client, token, fs, &group_id, &member)
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
    token: &str,
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
                send_receipt(identity, me, client, token, &from, &app.id);
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
pub fn send_receipt(identity: &Identity, me: &Handle, client: &DirectoryClient, token: &str, to: &Handle, message_id: &str) {
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
    for device in &record.record.devices {
        let env = seal_to(identity, me, device, &encoded);
        deliver(client, token, to, device, &MailItem::Direct(env));
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


// ---- groups -----------------------------------------------------------------

/// Associated data binding a group message to its group.
pub fn group_ad(group_id: &str) -> Vec<u8> {
    let mut ad = b"group:".to_vec();
    ad.extend_from_slice(group_id.as_bytes());
    ad
}


pub fn group_create(name: &str, members: &[String], whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let mut fs = open_history(&identity)?;

    let mut id_bytes = [0u8; 8];
    getrandom::getrandom(&mut id_bytes).map_err(|_| anyhow!("RNG failure"))?;
    let group_id = hex(&id_bytes);

    // Membership is the given members plus ourselves.
    let mut all: Vec<String> = members.to_vec();
    if !all.iter().any(|m| m == me.as_str()) {
        all.push(me.as_str().to_string());
    }

    let mut platform = OsPlatform;
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
    distribute_key(&identity, &me, &client, &token, &stored, &group);

    println!("created group '{name}' ({group_id}) with {} members", all.len());
    Ok(())
}


/// Send our sender-key distribution to every other member (over pairwise E2E).
pub fn distribute_key(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    token: &str,
    stored: &StoredGroup,
    group: &Group,
) {
    // Every member, including our own handle — `distribute_key_to` skips only
    // this exact device, so our sibling devices still get our key (Layer 11).
    distribute_key_to(identity, me, client, token, stored, group, &stored.members);
}


/// Send our sender-key distribution to a specific set of members.
pub fn distribute_key_to(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    token: &str,
    stored: &StoredGroup,
    group: &Group,
    targets: &[String],
) {
    let payload = GroupInvitePayload {
        group_id: stored.id.clone(),
        name: stored.name.clone(),
        members: stored.members.clone(),
        sender_id: my_group_id(identity),
        distribution: group.distribution(),
    };
    let plaintext = match serde_json::to_vec(&payload) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };
    for member in targets {
        let handle = match Handle::new(member.clone()) {
            Ok(h) => h,
            Err(_) => continue,
        };
        let record = match client.lookup(&handle) {
            Ok(r) if r.verify().is_ok() => r,
            _ => {
                eprintln!("(could not reach '{member}')");
                continue;
            }
        };
        // Seal the sender key to every device in the member's cluster (Layer 11) —
        // including our *own* siblings, but never this device itself.
        for device in &record.record.devices {
            if device.device_key == identity.device_public() {
                continue;
            }
            let env = seal_to(identity, me, device, &plaintext);
            deliver(client, token, &handle, device, &MailItem::GroupInvite(env));
        }
    }
}


pub fn handle_group_invite(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    token: &str,
    fs: &mut FileStore,
    platform: &mut OsPlatform,
    env: &Envelope,
) -> Result<()> {
    let (from, bytes) = open_envelope(identity, platform, env)?;
    let payload: GroupInvitePayload =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("malformed group invite"))?;
    // Senders are keyed by their device id (Layer 11), carried in the payload;
    // we remember which handle is behind it for display and block checks.
    let sender_id = payload.sender_id.clone();

    match groups::load(fs, &payload.group_id)? {
        Some(mut stored) => {
            // Already in the group — learn this member's sender key.
            let mut group = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
            group.add_member(sender_id.clone(), &payload.distribution).map_err(|_| anyhow!("bad sender key"))?;
            stored.note_sender(sender_id, from.as_str());

            // Learn any members we didn't know about, and send them our key.
            let newcomers: Vec<String> = payload
                .members
                .iter()
                .filter(|m| !stored.members.iter().any(|x| x == *m))
                .cloned()
                .collect();
            for m in &newcomers {
                stored.members.push(m.clone());
            }
            stored.state = group.export();
            groups::save(fs, &stored)?;
            if !newcomers.is_empty() {
                distribute_key_to(identity, me, client, token, &stored, &group, &newcomers);
            }
        }
        None => {
            // First time we hear of this group: join, and reply with our key.
            let mut own_platform = OsPlatform;
            let mut group = Group::new(&mut own_platform, my_group_id(identity));
            group.add_member(sender_id.clone(), &payload.distribution).map_err(|_| anyhow!("bad sender key"))?;
            let mut stored = StoredGroup {
                id: payload.group_id.clone(),
                name: payload.name.clone(),
                members: payload.members.clone(),
                me: me.as_str().to_string(),
                sender_handles: Vec::new(),
                state: group.export(),
            };
            stored.note_sender(sender_id, from.as_str());
            stored.note_sender(my_group_id(identity), me.as_str());
            groups::save(fs, &stored)?;
            println!("joined group '{}' (invited by {})", stored.name, from.as_str());
            distribute_key(identity, me, client, token, &stored, &group);
        }
    }
    Ok(())
}


pub fn handle_group_text(
    blocked: &[String],
    fs: &mut FileStore,
    group_id: &str,
    message: &GroupMessage,
) -> Result<()> {
    let mut stored = match groups::load(fs, group_id)? {
        Some(stored) => stored,
        None => {
            eprintln!("(group message for an unknown group)");
            return Ok(());
        }
    };
    // Map the device-keyed sender id back to a handle for display/block checks.
    let sender = stored
        .handle_of(&message.sender)
        .map(str::to_string)
        .unwrap_or_else(|| String::from_utf8_lossy(&message.sender).into_owned());
    if blocklist::is_blocked(blocked, &sender) {
        return Ok(()); // drop group messages from blocked members
    }
    let mut group = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    match group.decrypt(message, &group_ad(group_id)) {
        Ok(plaintext) => {
            // Advance/persist the ratchet state regardless.
            stored.state = group.export();
            groups::save(fs, &stored)?;

            let (id, display, expires_at) = match AppMessage::decode(&plaintext) {
                Ok(app) => {
                    match &app.body {
                        Body::Edit { to, text } => {
                            history::group_edit(fs, group_id, to, text)?;
                            println!("[{}] {sender}: edited #{to}", stored.name);
                            return Ok(());
                        }
                        Body::Delete { to } => {
                            history::group_delete(fs, group_id, to)?;
                            println!("[{}] {sender}: deleted #{to}", stored.name);
                            return Ok(());
                        }
                        _ => {}
                    }
                    if app.is_expired(OsPlatform.now_unix_secs()) {
                        return Ok(()); // already expired — drop
                    }
                    if let Some(path) = maybe_save_attachment(&app) {
                        println!("(saved attachment to {})", path.display());
                    }
                    (app.id.clone(), app.summary(), app.expires_at)
                }
                Err(_) => (String::new(), String::from_utf8_lossy(&plaintext).into_owned(), None),
            };
            println!("[{}] {sender}: {display}  (#{id})", stored.name);
            let entry = GroupStoredMessage {
                id: id.clone(),
                sender,
                text: display,
                timestamp: OsPlatform.now_unix_secs(),
                expires_at,
            };
            let _ = history::group_append(fs, group_id, entry);
        }
        Err(_) => eprintln!("(a group message could not be decrypted yet — missing that sender's key)"),
    }
    Ok(())
}


pub fn group_add(group: &str, member: &str, whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let mut fs = open_history(&identity)?;

    let mut stored = resolve_group(&fs, group)?;
    if stored.members.iter().any(|m| m == member) {
        bail!("'{member}' is already in '{}'", stored.name);
    }
    stored.members.push(member.to_string());
    groups::save(&mut fs, &stored)?;

    // Distribute our key with the updated roster: the newcomer joins, and
    // existing members learn the newcomer and send it their keys.
    let session = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    distribute_key(&identity, &me, &client, &token, &stored, &session);
    println!("invited '{member}' to '{}'", stored.name);
    Ok(())
}


pub fn group_remove(group: &str, member: &str, whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let mut fs = open_history(&identity)?;

    let mut stored = resolve_group(&fs, group)?;
    if !stored.members.iter().any(|m| m == member) {
        bail!("'{member}' is not in '{}'", stored.name);
    }
    stored.members.retain(|m| m != member);

    // Drop every device-sender of the removed handle, and re-key ourselves.
    let mut session = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    for (id, handle) in &stored.sender_handles {
        if handle == member {
            session.remove_member(id);
        }
    }
    stored.sender_handles.retain(|(_, h)| h != member);
    session.rotate(&mut OsPlatform);
    stored.state = session.export();
    groups::save(&mut fs, &stored)?;

    // Give the remaining members our fresh key, and tell them to re-key too.
    distribute_key(&identity, &me, &client, &token, &stored, &session);
    let control = MailItem::GroupRemove {
        group_id: stored.id.clone(),
        member: member.to_string(),
    };
    for m in &stored.members {
        if m == me.as_str() {
            continue;
        }
        if let Ok(handle) = Handle::new(m.clone()) {
            deliver_to_cluster(&client, &token, &handle, &control);
        }
    }
    println!("removed '{member}' from '{}' (re-keyed)", stored.name);
    Ok(())
}


/// React to a removal: drop the member, re-key, and redistribute our new key.
pub fn handle_group_remove(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    token: &str,
    fs: &mut FileStore,
    group_id: &str,
    member: &str,
) -> Result<()> {
    let mut stored = match groups::load(fs, group_id)? {
        Some(stored) => stored,
        None => return Ok(()),
    };
    if member == me.as_str() {
        return Ok(()); // we were removed; nothing to re-key
    }
    stored.members.retain(|m| m != member);
    let mut session = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    for (id, handle) in &stored.sender_handles {
        if handle == member {
            session.remove_member(id);
        }
    }
    stored.sender_handles.retain(|(_, h)| h != member);
    session.rotate(&mut OsPlatform);
    stored.state = session.export();
    groups::save(fs, &stored)?;
    distribute_key(identity, me, client, token, &stored, &session);
    println!("'{member}' was removed from '{}' — re-keyed", stored.name);
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
    directory: &str,
) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let mut fs = open_history(&identity)?;

    let mut stored = resolve_group(&fs, group)?;
    let mut session = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    let expires_at = resolve_expiry(&fs, &stored.id, expire)?;
    let app = build_message(message, reply_to, react, to, file, edit, delete, expires_at)?;

    // Apply an edit/delete to our own copy of the transcript too.
    match &app.body {
        Body::Edit { to, text } => history::group_edit(&mut fs, &stored.id, to, text)?,
        Body::Delete { to } => history::group_delete(&mut fs, &stored.id, to)?,
        _ => {}
    }
    let gm = session.encrypt(&app.encode(), &group_ad(&stored.id));
    stored.state = session.export();
    groups::save(&mut fs, &stored)?;

    let item = MailItem::GroupText { group_id: stored.id.clone(), message: gm };
    for member in &stored.members {
        let handle = match Handle::new(member.clone()) {
            Ok(h) => h,
            Err(_) => continue,
        };
        if member == me.as_str() {
            // Mirror to my *own* other devices (they hold my key from `group
            // sync`), so the group reads consistently across my cluster.
            if let Ok(my_rec) = client.lookup(&me) {
                for device in &my_rec.record.devices {
                    if device.device_key != identity.device_public() {
                        deliver(&client, &token, &me, device, &item);
                    }
                }
            }
            continue;
        }
        // Fan the one ciphertext out to every device in the member's cluster.
        deliver_to_cluster(&client, &token, &handle, &item);
    }

    // Record our own message in the group transcript (edits/deletes already
    // applied above, so don't add them as new lines).
    if !matches!(app.body, Body::Edit { .. } | Body::Delete { .. }) {
        let entry = GroupStoredMessage {
            id: app.id.clone(),
            sender: me.as_str().to_string(),
            text: app.summary(),
            timestamp: OsPlatform.now_unix_secs(),
            expires_at: app.expires_at,
        };
        let _ = history::group_append(&mut fs, &stored.id, entry);
    }
    println!("sent to group '{}' (#{})", stored.name, app.id);
    Ok(())
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


pub fn group_sync(whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let fs = open_history(&identity)?;

    // My sibling devices (everything in my cluster except this one).
    let my_record = client.lookup(&me)?;
    let my_key = identity.device_public();
    let siblings: Vec<Device> = my_record
        .record
        .devices
        .iter()
        .filter(|d| d.device_key != my_key)
        .cloned()
        .collect();
    if siblings.is_empty() {
        println!("no other devices to sync to");
        return Ok(());
    }

    let mut synced = 0;
    for id in groups::list(&fs)? {
        let stored = match groups::load(&fs, &id)? {
            Some(s) => s,
            None => continue,
        };
        let group = match Group::import(stored.state.clone()) {
            Ok(g) => g,
            Err(_) => continue,
        };
        // Every key this device holds: the others' receiver keys, plus our own
        // distribution (so a sibling can decrypt what this device sends).
        let mut keys = group.known_keys();
        keys.push((my_group_id(&identity), group.distribution()));

        let payload = GroupSyncPayload {
            group_id: stored.id.clone(),
            name: stored.name.clone(),
            members: stored.members.clone(),
            keys,
            sender_handles: stored.sender_handles.clone(),
        };
        let plaintext = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(_) => continue,
        };
        for device in &siblings {
            let env = seal_to(&identity, &me, device, &plaintext);
            deliver(&client, &token, &me, device, &MailItem::GroupSync(env));
        }
        synced += 1;
    }
    println!("synced {synced} group(s) to {} other device(s)", siblings.len());
    Ok(())
}


/// Bootstrap this device into a group from a sibling's [`GroupSyncPayload`].
pub fn handle_group_sync(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    token: &str,
    platform: &mut OsPlatform,
    fs: &mut FileStore,
    env: &Envelope,
) -> Result<()> {
    let (_from, bytes) = open_envelope(identity, platform, env)?;
    let payload: GroupSyncPayload =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("malformed group sync"))?;

    if groups::load(fs, &payload.group_id)?.is_some() {
        return Ok(()); // already have this group
    }
    // A fresh own sender key (this device signs under its device id); import
    // every sender key the cluster shared so we can decrypt current members.
    let mut group = Group::new(platform, my_group_id(identity));
    for (id, dist) in &payload.keys {
        let _ = group.add_member(id.clone(), dist);
    }
    let mut stored = StoredGroup {
        id: payload.group_id.clone(),
        name: payload.name.clone(),
        members: payload.members.clone(),
        me: me.as_str().to_string(),
        sender_handles: payload.sender_handles.clone(),
        state: group.export(),
    };
    stored.note_sender(my_group_id(identity), me.as_str());
    groups::save(fs, &stored)?;
    // Announce our own key to the members so this device can also *send*.
    distribute_key(identity, me, client, token, &stored, &group);
    println!("bootstrapped into group '{}'", stored.name);
    Ok(())
}


pub fn group_leave(group: &str, whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let mut fs = open_history(&identity)?;
    let stored = resolve_group(&fs, group)?;

    // Tell the remaining members we left so they drop us and re-key.
    let control = MailItem::GroupRemove {
        group_id: stored.id.clone(),
        member: me.as_str().to_string(),
    };
    for member in &stored.members {
        if member == me.as_str() {
            continue;
        }
        if let Ok(handle) = Handle::new(member.clone()) {
            deliver_to_cluster(&client, &token, &handle, &control);
        }
    }
    groups::remove(&mut fs, &stored.id)?;
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


/// Resolve a group by id, or by name if no id matches.
pub fn resolve_group(fs: &FileStore, key: &str) -> Result<StoredGroup> {
    if let Some(g) = groups::load(fs, key)? {
        return Ok(g);
    }
    for id in groups::list(fs)? {
        if let Some(g) = groups::load(fs, &id)? {
            if g.name == key {
                return Ok(g);
            }
        }
    }
    bail!("no such group '{key}'")
}


pub fn guardian_split(shares: u8, threshold: u8) -> Result<()> {
    let identity = store::load_identity()?;
    let mut platform = OsPlatform;
    let parts = shamir::split(identity.mnemonic().as_bytes(), threshold, shares, &mut platform)
        .map_err(|_| anyhow!("invalid --shares/--threshold (need 1 <= threshold <= shares)"))?;

    println!("{threshold}-of-{shares} social recovery. Give one share to each guardian:\n");
    for part in &parts {
        let mut encoded = Vec::with_capacity(1 + part.body.len());
        encoded.push(part.index);
        encoded.extend_from_slice(&part.body);
        println!("  share {}: {}", part.index, hex(&encoded));
    }
    println!("\nAny {threshold} of these can restore your identity with `guardian-recover`.");
    Ok(())
}


pub fn guardian_recover(share_strs: &[String]) -> Result<()> {
    if store::exists() {
        bail!("an identity already exists at {}", store::path().display());
    }
    let mut shares = Vec::with_capacity(share_strs.len());
    for s in share_strs {
        let bytes = from_hex(s)?;
        if bytes.len() < 2 {
            bail!("a share is too short");
        }
        shares.push(Share { index: bytes[0], body: bytes[1..].to_vec() });
    }

    let secret = shamir::combine(&shares).map_err(|_| anyhow!("could not combine shares"))?;
    let phrase = String::from_utf8(secret).map_err(|_| anyhow!("recovered data is not text"))?;
    let identity = Identity::from_phrase(phrase.trim(), &mut OsPlatform)
        .map_err(|_| anyhow!("recovered phrase is invalid — wrong shares, or fewer than the threshold"))?;

    store::save_identity(&identity)?;
    println!("identity recovered on this device (a fresh device in your cluster).");
    println!("wallet: {}", hex(&identity.wallet_public().0));
    Ok(())
}


// ---- helpers ----------------------------------------------------------------

/// A short, human-usable id for a device: the first 4 bytes of its key, in hex.
pub fn short_device_id(key: &DevicePublicKey) -> String {
    hex(&key.0[..4])
}


/// The mailbox slot a device drains: the full hex of its key. Account-wide
/// items (group, control, receipts) instead use [`ACCOUNT_SLOT`].
pub fn device_slot(key: &DevicePublicKey) -> String {
    hex(&key.0)
}


/// The cluster-wide mailbox slot, read by every device of an account.
const ACCOUNT_SLOT: &str = "account";

/// Read the account's seed phrase from `MYCELLIUM_PHRASE` or stdin.
pub fn read_phrase() -> Result<String> {
    if let Ok(p) = std::env::var("MYCELLIUM_PHRASE") {
        return Ok(p);
    }
    eprint!("Enter your 24-word seed phrase: ");
    std::io::Write::flush(&mut std::io::stderr()).ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}


/// Re-sign and publish a record with a new device set (seq bumped past `prev`).
pub fn update_devices(
    client: &DirectoryClient,
    token: &str,
    identity: &Identity,
    handle: &Handle,
    devices: Vec<Device>,
    prev_seq: u64,
) -> Result<()> {
    let seq = prev_seq.saturating_add(1).max(OsPlatform.now_unix_secs());
    let record = Record { handle: handle.clone(), wallet: identity.wallet_public(), devices, seq };
    let signed = SignedRecord::sign(record, identity);
    client.publish(token, handle, &signed)
}


pub fn link_device(handle: &str, addr: &str, libp2p: bool, directory: &str) -> Result<()> {
    if store::exists() {
        bail!("an identity already exists here — link-device runs on a fresh device (a new MYCELLIUM_HOME)");
    }
    let phrase = read_phrase()?;
    let identity =
        Identity::from_phrase(phrase.trim(), &mut OsPlatform).map_err(|_| anyhow!("invalid seed phrase"))?;
    store::save_identity(&identity)?;

    let me = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let location = if libp2p {
        libp2p_net::advertised_multiaddr(addr, identity.device_secret())?
    } else {
        addr.to_string()
    };
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let current = client
        .lookup(&me)
        .map_err(|_| anyhow!("no record for '{handle}' — register it on your first device first"))?;
    current.verify().map_err(|_| anyhow!("existing record failed verification"))?;
    if current.record.wallet != identity.wallet_public() {
        bail!("'{handle}' belongs to a different account (wallet mismatch)");
    }

    let mut devices = current.record.devices.clone();
    let mine = this_device(&identity, &location);
    if devices.iter().any(|d| d.device_key == mine.device_key) {
        println!("this device is already linked to '{handle}'");
        return Ok(());
    }
    devices.push(mine);
    let count = devices.len();
    update_devices(&client, &token, &identity, &me, devices, current.record.seq)?;
    println!("linked this device to '{handle}' — cluster now has {count} device(s)");
    Ok(())
}


pub fn list_devices(handle: &str, directory: &str) -> Result<()> {
    let me = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let client = DirectoryClient::new(directory);
    let record = client.lookup(&me)?;
    record.verify().map_err(|_| anyhow!("record failed verification"))?;
    println!("devices for '{handle}':");
    for d in &record.record.devices {
        println!("  {}  {}", short_device_id(&d.device_key), String::from_utf8_lossy(&d.peer_id.0));
    }
    Ok(())
}


pub fn revoke_device(handle: &str, device_id: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let current = client.lookup(&me)?;
    current.verify().map_err(|_| anyhow!("record failed verification"))?;
    if current.record.wallet != identity.wallet_public() {
        bail!("'{handle}' is not your account");
    }

    let wanted = device_id.to_lowercase();
    let before = current.record.devices.len();
    let devices: Vec<Device> = current
        .record
        .devices
        .iter()
        .filter(|d| !short_device_id(&d.device_key).starts_with(&wanted))
        .cloned()
        .collect();
    if devices.len() == before {
        bail!("no device matching '{device_id}'");
    }
    if devices.is_empty() {
        bail!("cannot revoke the last device in the cluster");
    }
    let removed = before - devices.len();
    update_devices(&client, &token, &identity, &me, devices, current.record.seq)?;
    println!("revoked {removed} device(s) from '{handle}'");
    Ok(())
}


pub fn build_record(identity: &Identity, handle: &Handle, addr: &str) -> SignedRecord {
    let record = Record {
        handle: handle.clone(),
        wallet: identity.wallet_public(),
        devices: vec![this_device(identity, addr)],
        seq: OsPlatform.now_unix_secs(),
    };
    SignedRecord::sign(record, identity)
}


/// This device's unique sender id inside any group (Layer 11): its device key,
/// so two devices of one account are distinct senders and don't collide.
pub fn my_group_id(identity: &Identity) -> Vec<u8> {
    identity.device_public().0.to_vec()
}


/// This device's entry for a record: its transport address plus its own
/// (currently seed-derived) messaging keys, signed by the account wallet.
pub fn this_device(identity: &Identity, addr: &str) -> Device {
    Device {
        device_key: identity.device_public(),
        peer_id: PeerId(addr.as_bytes().to_vec()),
        id_key: identity.messaging_public(),
        signed_pre_key: SignedPreKey::create(identity.signed_pre_key_public(), identity),
    }
}


/// Bind both peers' messaging identities into the AEAD associated data, so a
/// ciphertext is cryptographically tied to *this* pair. Initiator's key first.
pub fn associated_data(initiator_ik: &MessagingPublicKey, responder_ik: &MessagingPublicKey) -> Vec<u8> {
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(&initiator_ik.0);
    ad.extend_from_slice(&responder_ik.0);
    ad
}


pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}


/// A short random message id.
pub fn random_id() -> String {
    let mut bytes = [0u8; 6];
    let _ = getrandom::getrandom(&mut bytes);
    hex(&bytes)
}


/// A plain-text application message (no expiry).
pub fn text_message(text: &str) -> AppMessage {
    AppMessage {
        id: random_id(),
        timestamp: OsPlatform.now_unix_secs(),
        expires_at: None,
        body: Body::Text(text.to_string()),
    }
}


/// Parse a duration like `30s`, `10m`, `1h`, `7d` into seconds.
pub fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('s') {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86400)
    } else {
        (s, 1)
    };
    let value: u64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid duration '{s}' (use e.g. 30s, 10m, 1h, 7d)"))?;
    Ok(value * mult)
}


/// Maximum attachment size (kept small since attachments ride inline).
const MAX_ATTACHMENT: usize = 256 * 1024;

/// Build a message from the `send`/`group send` flags.
#[allow(clippy::too_many_arguments)]
pub fn build_message(
    message: Option<&str>,
    reply_to: Option<&str>,
    react: Option<&str>,
    to: Option<&str>,
    file: Option<&str>,
    edit: Option<&str>,
    delete: Option<&str>,
    expires_at: Option<u64>,
) -> Result<AppMessage> {
    let body = if let Some(target) = delete {
        Body::Delete { to: target.to_string() }
    } else if let Some(target) = edit {
        let text = message.ok_or_else(|| anyhow!("--edit requires --message"))?;
        Body::Edit { to: target.to_string(), text: text.to_string() }
    } else if let Some(path) = file {
        let data = std::fs::read(path).with_context(|| format!("could not read '{path}'"))?;
        if data.len() > MAX_ATTACHMENT {
            bail!("file too large (max {} KiB)", MAX_ATTACHMENT / 1024);
        }
        let name = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        Body::File { mime: guess_mime(&name), name, data }
    } else if let Some(emoji) = react {
        let to = to.ok_or_else(|| anyhow!("--react requires --to <message-id>"))?;
        Body::Reaction { to: to.to_string(), emoji: emoji.to_string() }
    } else if let Some(target) = reply_to {
        let text = message.ok_or_else(|| anyhow!("--reply-to requires --message"))?;
        Body::Reply { to: target.to_string(), text: text.to_string() }
    } else {
        Body::Text(message.ok_or_else(|| anyhow!("--message is required"))?.to_string())
    };
    Ok(AppMessage { id: random_id(), timestamp: OsPlatform.now_unix_secs(), expires_at, body })
}


/// Resolve an expiry timestamp for a conversation `key`: an explicit `--expire`
/// duration, else the stored per-conversation default, else none.
pub fn resolve_expiry(fs: &FileStore, key: &str, expire: Option<&str>) -> Result<Option<u64>> {
    let ttl = match expire {
        Some(dur) => Some(parse_duration(dur)?),
        None => expiry::get(fs, key)?,
    };
    Ok(ttl.map(|secs| OsPlatform.now_unix_secs() + secs))
}


/// A best-effort MIME type from a file name's extension.
pub fn guess_mime(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let mime = match ext.as_str() {
        "txt" | "md" => "text/plain",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        "json" => "application/json",
        _ => "application/octet-stream",
    };
    mime.to_string()
}


/// Save an attachment to `MYCELLIUM_HOME/downloads` (name sanitized to a basename).
pub fn save_attachment(name: &str, data: &[u8]) -> Result<std::path::PathBuf> {
    let safe = std::path::Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("file");
    let dir = store::data_dir().join("downloads");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(safe);
    std::fs::write(&path, data)?;
    Ok(path)
}


/// If the message is a file, save it and return where.
pub fn maybe_save_attachment(app: &AppMessage) -> Option<std::path::PathBuf> {
    if let Body::File { name, data, .. } = &app.body {
        match save_attachment(name, data) {
            Ok(path) => return Some(path),
            Err(err) => eprintln!("(could not save attachment: {err})"),
        }
    }
    None
}


pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("hex string has an odd length");
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| anyhow!("invalid hex")))
        .collect()
}
