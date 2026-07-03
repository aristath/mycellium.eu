//! `mycellium` — the Full-tier client shell.
//!
//! Wires the portable core to real host capabilities (OS entropy/clock, TCP
//! transport, a directory HTTP client) and drives the whole flow end to end:
//! create/restore an identity, register a handle, look a peer up, open a direct
//! line, run X3DH + Double Ratchet, and exchange end-to-end-encrypted messages.

mod tui;

use std::io::BufRead;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use mycellium_core::identity::Handle;
use mycellium_core::message::AppMessage;
use mycellium_core::platform::Platform;
use mycellium_core::ratchet::RatchetMessage;
use mycellium_core::transport::Transport;
use mycellium_core::wire;

use mycellium_directory_client::DirectoryClient;
use mycellium_storage::filestore::FileStore;
use mycellium_storage::store;
use mycellium_engine::blocklist;
use mycellium_engine::history::{self, StoredMessage};
use mycellium_engine::platform::OsPlatform;
use mycellium_transport::libp2p_net::{self, Libp2pNode};
use mycellium_transport::link::{FrameReader, FrameWriter};
use mycellium_transport::net::TcpTransport;

// The engine owns the orchestration; the shell drives it.
use mycellium_engine::app::*;

const DEFAULT_DIRECTORY: &str = "http://127.0.0.1:8080";


#[derive(Parser)]
#[command(name = "mycellium", about = "Mycellium peer-to-peer messenger (POC client)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}


#[derive(Subcommand)]
enum Command {
    /// Create a new identity (24-word seed) and store it locally.
    IdentityNew,
    /// Show this device's public identity.
    IdentityShow,
    /// Register a handle with the directory and publish your record.
    Register {
        /// The handle to claim, e.g. `ari`.
        handle: String,
        /// Address other peers dial to reach you, e.g. `127.0.0.1:9001`.
        #[arg(long)]
        addr: String,
        /// Advertise a libp2p multiaddr instead of a raw TCP address.
        #[arg(long)]
        libp2p: bool,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Link this (fresh) device to an existing account (Layer 11).
    ///
    /// Reads your 24-word phrase from `MYCELLIUM_PHRASE` or stdin, adopts the
    /// account with fresh device keys, and adds this device to your record.
    LinkDevice {
        /// Your handle.
        handle: String,
        /// Address other peers dial to reach this device.
        #[arg(long)]
        addr: String,
        /// Advertise a libp2p multiaddr instead of a raw TCP address.
        #[arg(long)]
        libp2p: bool,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// List the devices in an account's cluster.
    Devices {
        /// The handle to inspect.
        handle: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Remove a device from your cluster (by short id).
    RevokeDevice {
        /// Your handle.
        handle: String,
        /// The short device id (from `devices`).
        device_id: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Wait for a peer to connect and chat with them.
    Listen {
        /// Address to bind, matching the one you registered.
        #[arg(long)]
        addr: String,
        /// Listen with the libp2p transport instead of raw TCP.
        #[arg(long)]
        libp2p: bool,
        /// Use the full-screen terminal UI instead of line mode.
        #[arg(long)]
        tui: bool,
    },
    /// Look up a peer, open a direct line, and chat.
    Chat {
        /// The peer's handle.
        peer: String,
        /// Your own handle (used to authenticate you to the peer).
        #[arg(long = "as")]
        whoami: String,
        /// Use the full-screen terminal UI instead of line mode.
        #[arg(long)]
        tui: bool,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Queue an offline message in a peer's mailbox (no live connection).
    Send {
        /// The recipient's handle.
        peer: String,
        /// Your own handle.
        #[arg(long = "as")]
        whoami: String,
        /// The message text.
        #[arg(long)]
        message: Option<String>,
        /// Reply to an earlier message id (with --message).
        #[arg(long)]
        reply_to: Option<String>,
        /// React with an emoji (needs --to).
        #[arg(long)]
        react: Option<String>,
        /// The message id to react to.
        #[arg(long)]
        to: Option<String>,
        /// Attach a file at this path.
        #[arg(long)]
        file: Option<String>,
        /// Edit an earlier message id (with --message).
        #[arg(long)]
        edit: Option<String>,
        /// Delete (unsend) an earlier message id.
        #[arg(long)]
        delete: Option<String>,
        /// Make the message disappear after this long (e.g. 30s, 10m, 1h, 7d).
        #[arg(long)]
        expire: Option<String>,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Send the same message to several peers at once.
    Broadcast {
        /// Comma-separated recipient handles/nicknames.
        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,
        /// Your own handle.
        #[arg(long = "as")]
        whoami: String,
        /// The message text.
        #[arg(long)]
        message: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Fetch and decrypt queued offline messages.
    Inbox {
        /// Your own handle.
        #[arg(long = "as")]
        whoami: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Stay online and receive live-pushed messages (announces presence).
    Serve {
        /// Address to bind (matching the one you registered).
        #[arg(long)]
        addr: String,
        /// Your own handle.
        #[arg(long = "as")]
        whoami: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Split your identity into guardian shares (t-of-n social recovery).
    GuardianSplit {
        /// Total number of shares to hand out.
        #[arg(long)]
        shares: u8,
        /// How many shares are needed to recover.
        #[arg(long)]
        threshold: u8,
    },
    /// Recover an identity on a new device from guardian shares.
    GuardianRecover {
        /// A guardian share (repeat `--share` for each).
        #[arg(long = "share", required = true)]
        shares: Vec<String>,
    },
    /// Show the stored message history with a peer.
    History {
        /// The peer's handle.
        peer: String,
    },
    /// Delete the stored history with a peer.
    ClearHistory {
        /// The peer's handle or nickname.
        peer: String,
    },
    /// List all conversations (peers and groups) with a last-message preview.
    Conversations,
    /// Search all local transcripts (1:1 and groups) for text.
    Search {
        /// The text to search for (case-insensitive).
        query: String,
    },
    /// Forward a stored message to another peer.
    Forward {
        /// The message id to forward.
        message_id: String,
        /// The peer you received it from (handle or nickname).
        #[arg(long)]
        from: String,
        /// The recipient (handle or nickname).
        #[arg(long)]
        to: String,
        /// Your own handle.
        #[arg(long = "as")]
        whoami: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Group messaging (async, via the offline mailbox).
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
    /// Manage your local address book of nicknames.
    Contact {
        #[command(subcommand)]
        action: ContactAction,
    },
    /// Announce that you're online (heartbeat the directory).
    Announce {
        /// Your own handle.
        #[arg(long = "as")]
        whoami: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Check whether a handle is currently online.
    Presence {
        /// The handle (or a contact nickname) to check.
        peer: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Show the safety number to verify a peer's identity out of band.
    Verify {
        /// The peer (handle or nickname).
        peer: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Block a handle (its messages are dropped).
    Block {
        /// The handle to block.
        handle: String,
    },
    /// Unblock a handle.
    Unblock {
        /// The handle to unblock.
        handle: String,
    },
    /// List blocked handles.
    Blocked,
    /// Set a per-conversation default disappearing-message timer.
    Expire {
        #[command(subcommand)]
        action: ExpireAction,
    },
    /// Export identity + local data to a single backup file.
    Export {
        /// Destination path.
        path: String,
    },
    /// Import a backup into a fresh MYCELLIUM_HOME.
    Import {
        /// Backup file path.
        path: String,
    },
    /// Save/show/clear a draft message for a peer.
    Draft {
        #[command(subcommand)]
        action: DraftAction,
    },
    /// Erase ALL local data (identity + messages). Irreversible.
    Wipe {
        /// Confirm the wipe.
        #[arg(long)]
        yes: bool,
    },
}


#[derive(Subcommand)]
enum DraftAction {
    /// Save a draft for a peer.
    Set {
        /// Peer handle or nickname.
        peer: String,
        /// The draft text.
        text: String,
    },
    /// Show a peer's draft.
    Show {
        /// Peer handle or nickname.
        peer: String,
    },
    /// Clear a peer's draft.
    Clear {
        /// Peer handle or nickname.
        peer: String,
    },
}


#[derive(Subcommand)]
enum ExpireAction {
    /// Set the default TTL for a peer or group id (e.g. 1h).
    Set {
        /// Peer handle/nickname, or group id.
        target: String,
        /// Duration, e.g. 30s, 10m, 1h, 7d.
        duration: String,
    },
    /// Clear a target's default TTL.
    Clear {
        /// Peer handle/nickname, or group id.
        target: String,
    },
    /// Show a target's default TTL.
    Show {
        /// Peer handle/nickname, or group id.
        target: String,
    },
}


#[derive(Subcommand)]
enum ContactAction {
    /// Add a contact, pinning their current identity (trust-on-first-use).
    Add {
        /// Local nickname.
        nickname: String,
        /// The peer's handle.
        handle: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// List your contacts.
    List,
    /// Remove a contact.
    Remove {
        /// Local nickname.
        nickname: String,
    },
}


#[derive(Subcommand)]
enum GroupAction {
    /// Create a group and invite members (sends each your sender key).
    Create {
        /// Group name.
        name: String,
        /// Comma-separated member handles.
        #[arg(long, value_delimiter = ',')]
        members: Vec<String>,
        /// Your own handle.
        #[arg(long = "as")]
        whoami: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Send a message to a group (fans out to every member).
    Send {
        /// Group id or name.
        group: String,
        /// Your own handle.
        #[arg(long = "as")]
        whoami: String,
        /// The message text.
        #[arg(long)]
        message: Option<String>,
        /// Reply to an earlier message id (with --message).
        #[arg(long)]
        reply_to: Option<String>,
        /// React with an emoji (needs --to).
        #[arg(long)]
        react: Option<String>,
        /// The message id to react to.
        #[arg(long)]
        to: Option<String>,
        /// Attach a file at this path.
        #[arg(long)]
        file: Option<String>,
        /// Edit an earlier message id (with --message).
        #[arg(long)]
        edit: Option<String>,
        /// Delete (unsend) an earlier message id.
        #[arg(long)]
        delete: Option<String>,
        /// Make the message disappear after this long (e.g. 30s, 10m, 1h, 7d).
        #[arg(long)]
        expire: Option<String>,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Invite another member to an existing group.
    Add {
        /// Group id or name.
        group: String,
        /// The handle to invite.
        #[arg(long)]
        member: String,
        /// Your own handle.
        #[arg(long = "as")]
        whoami: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Remove a member from a group (re-keys the remaining members).
    Remove {
        /// Group id or name.
        group: String,
        /// The handle to remove.
        #[arg(long)]
        member: String,
        /// Your own handle.
        #[arg(long = "as")]
        whoami: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Show the stored transcript of a group.
    History {
        /// Group id or name.
        group: String,
    },
    /// Show a group's name, id, and members.
    Info {
        /// Group id or name.
        group: String,
    },
    /// Leave a group (notifies the others to re-key).
    Leave {
        /// Group id or name.
        group: String,
        /// Your own handle.
        #[arg(long = "as")]
        whoami: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// Bootstrap your other devices into your groups (Layer 11, receive-only).
    Sync {
        /// Your own handle.
        #[arg(long = "as")]
        whoami: String,
        #[arg(long, default_value = DEFAULT_DIRECTORY)]
        directory: String,
    },
    /// List the groups this device knows about.
    List,
}


fn main() -> Result<()> {
    match Cli::parse().command {
        Command::IdentityNew => identity_new(),
        Command::LinkDevice { handle, addr, libp2p, directory } => {
            link_device(&handle, &addr, libp2p, &directory)
        }
        Command::Devices { handle, directory } => list_devices(&handle, &directory),
        Command::RevokeDevice { handle, device_id, directory } => {
            revoke_device(&handle, &device_id, &directory)
        }
        Command::IdentityShow => identity_show(),
        Command::Register { handle, addr, libp2p, directory } => {
            register(&handle, &addr, libp2p, &directory)
        }
        Command::Listen { addr, libp2p, tui } => listen(&addr, libp2p, tui),
        Command::Chat { peer, whoami, tui, directory } => chat(&peer, &whoami, tui, &directory),
        Command::Send { peer, whoami, message, reply_to, react, to, file, edit, delete, expire, directory } => {
            send(
                &peer,
                &whoami,
                message.as_deref(),
                reply_to.as_deref(),
                react.as_deref(),
                to.as_deref(),
                file.as_deref(),
                edit.as_deref(),
                delete.as_deref(),
                expire.as_deref(),
                &directory,
            )
        }
        Command::Broadcast { to, whoami, message, directory } => {
            broadcast(&to, &whoami, &message, &directory)
        }
        Command::Inbox { whoami, directory } => inbox(&whoami, &directory),
        Command::Serve { addr, whoami, directory } => serve(&addr, &whoami, &directory),
        Command::GuardianSplit { shares, threshold } => guardian_split(shares, threshold),
        Command::GuardianRecover { shares } => guardian_recover(&shares),
        Command::History { peer } => show_history(&peer),
        Command::ClearHistory { peer } => clear_history(&peer),
        Command::Conversations => conversations(),
        Command::Search { query } => search(&query),
        Command::Forward { message_id, from, to, whoami, directory } => {
            forward(&message_id, &from, &to, &whoami, &directory)
        }
        Command::Group { action } => match action {
            GroupAction::Create { name, members, whoami, directory } => {
                group_create(&name, &members, &whoami, &directory)
            }
            GroupAction::Send { group, whoami, message, reply_to, react, to, file, edit, delete, expire, directory } => {
                group_send(
                    &group,
                    &whoami,
                    message.as_deref(),
                    reply_to.as_deref(),
                    react.as_deref(),
                    to.as_deref(),
                    file.as_deref(),
                    edit.as_deref(),
                    delete.as_deref(),
                    expire.as_deref(),
                    &directory,
                )
            }
            GroupAction::Add { group, member, whoami, directory } => {
                group_add(&group, &member, &whoami, &directory)
            }
            GroupAction::Remove { group, member, whoami, directory } => {
                group_remove(&group, &member, &whoami, &directory)
            }
            GroupAction::History { group } => group_history(&group),
            GroupAction::Info { group } => group_info(&group),
            GroupAction::Leave { group, whoami, directory } => group_leave(&group, &whoami, &directory),
            GroupAction::Sync { whoami, directory } => group_sync(&whoami, &directory),
            GroupAction::List => group_list(),
        },
        Command::Contact { action } => match action {
            ContactAction::Add { nickname, handle, directory } => {
                contact_add(&nickname, &handle, &directory)
            }
            ContactAction::List => contact_list(),
            ContactAction::Remove { nickname } => contact_remove(&nickname),
        },
        Command::Block { handle } => set_blocked(&handle, true),
        Command::Unblock { handle } => set_blocked(&handle, false),
        Command::Blocked => list_blocked(),
        Command::Announce { whoami, directory } => announce(&whoami, &directory),
        Command::Presence { peer, directory } => presence(&peer, &directory),
        Command::Verify { peer, directory } => verify(&peer, &directory),
        Command::Expire { action } => match action {
            ExpireAction::Set { target, duration } => expire_set(&target, &duration),
            ExpireAction::Clear { target } => expire_clear(&target),
            ExpireAction::Show { target } => expire_show(&target),
        },
        Command::Export { path } => export_backup(&path),
        Command::Import { path } => import_backup(&path),
        Command::Draft { action } => match action {
            DraftAction::Set { peer, text } => draft_cmd(&peer, Some(&text)),
            DraftAction::Show { peer } => draft_cmd(&peer, None),
            DraftAction::Clear { peer } => draft_clear(&peer),
        },
        Command::Wipe { yes } => wipe(yes),
    }
}


fn listen(addr: &str, libp2p: bool, tui: bool) -> Result<()> {
    let identity = store::load_identity()?;
    let history = Arc::new(Mutex::new(open_history(&identity)?));
    let blocked = blocklist::load(&*history.lock().unwrap())?;

    // Accept connections until one completes a handshake; failed handshakes
    // (health probes, scanners) and blocked peers are skipped. The accepted
    // peer runs full-duplex.
    if libp2p {
        let listen_addr = libp2p_net::listen_multiaddr(addr)?;
        let mut node = Libp2pNode::new(identity.device_secret(), Some(listen_addr))?;
        println!("listening (libp2p) on {addr} as {}", node.peer_id());
        loop {
            let mut conn = node.accept()?;
            match handshake_responder(&mut conn, &identity) {
                Ok(session) if blocklist::is_blocked(&blocked, &session.peer_name) => {
                    eprintln!("(refused blocked peer '{}')", session.peer_name);
                }
                Ok(session) => {
                    let (reader, writer) = conn.split();
                    run_session(Box::new(reader), Box::new(writer), session, tui, Arc::clone(&history));
                    node.drain(300);
                    std::process::exit(0);
                }
                Err(err) => eprintln!("(ignoring connection: {err})"),
            }
        }
    } else {
        let mut transport = TcpTransport::listening(addr).context("could not bind address")?;
        println!("listening on {addr}; waiting for a peer to connect...");
        loop {
            let mut conn = transport.accept()?;
            match handshake_responder(&mut conn, &identity) {
                Ok(session) if blocklist::is_blocked(&blocked, &session.peer_name) => {
                    eprintln!("(refused blocked peer '{}')", session.peer_name);
                }
                Ok(session) => {
                    let (reader, writer) = conn.split()?;
                    run_session(Box::new(reader), Box::new(writer), session, tui, Arc::clone(&history));
                    std::process::exit(0);
                }
                Err(err) => eprintln!("(ignoring connection: {err})"),
            }
        }
    }
}


fn chat(peer: &str, whoami: &str, tui: bool, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let history = Arc::new(Mutex::new(open_history(&identity)?));

    let client = DirectoryClient::new(directory);
    let (peer_handle, peer_record) = {
        let fs = history.lock().unwrap();
        lookup_verified(&client, &fs, peer)?
    };

    let location = String::from_utf8(peer_record.record.primary().peer_id.0.clone())
        .context("peer record has no dialable address")?;

    // A leading '/' marks a libp2p multiaddr; anything else is a TCP host:port.
    if location.starts_with('/') {
        let mut node = Libp2pNode::new(identity.device_secret(), None)?;
        let mut conn = node
            .dial_str(&location)
            .with_context(|| format!("could not connect to {location}"))?;
        let session = handshake_initiator(&mut conn, &identity, &me, &peer_handle, &peer_record, &location)?;
        let (reader, writer) = conn.split();
        run_session(Box::new(reader), Box::new(writer), session, tui, Arc::clone(&history));
        node.drain(300);
        std::process::exit(0);
    } else {
        let mut transport = TcpTransport::dialer();
        let mut conn = transport
            .dial(&peer_record.record.primary().peer_id)
            .with_context(|| format!("could not connect to {location}"))?;
        let session = handshake_initiator(&mut conn, &identity, &me, &peer_handle, &peer_record, &location)?;
        let (reader, writer) = conn.split()?;
        run_session(Box::new(reader), Box::new(writer), session, tui, Arc::clone(&history));
        std::process::exit(0);
    }
}


/// Run a session in either the terminal UI or line mode.
fn run_session(
    reader: Box<dyn FrameReader>,
    writer: Box<dyn FrameWriter>,
    session: Session,
    tui: bool,
    history: Arc<Mutex<FileStore>>,
) {
    if tui {
        if let Err(err) = tui::run(reader, writer, session, history) {
            eprintln!("tui error: {err}");
        }
    } else {
        run_duplex(reader, writer, session, history);
    }
}


/// Run a full-duplex chat: a reader thread decrypts and prints incoming
/// messages while the main thread encrypts stdin lines and sends them. The
/// ratchet is shared under a mutex since both directions advance it. Every
/// message (both directions) is persisted to the encrypted history store.
fn run_duplex(
    mut reader: Box<dyn FrameReader>,
    mut writer: Box<dyn FrameWriter>,
    session: Session,
    history: Arc<Mutex<FileStore>>,
) {
    let Session { ratchet, ad, peer_name } = session;
    let ratchet = Arc::new(Mutex::new(ratchet));
    let ad = Arc::new(ad);
    let peer_name = Arc::new(peer_name);

    // Replay any earlier conversation (pruning expired).
    let now = OsPlatform.now_unix_secs();
    if let Ok(past) = history::load_active(&mut *history.lock().unwrap(), &peer_name, now) {
        if !past.is_empty() {
            println!("--- earlier messages with {peer_name} ---");
            for m in &past {
                let who = if m.from_me { "you" } else { peer_name.as_str() };
                println!("{who}: {}", m.text);
            }
            println!("---");
        }
    }

    // Reader thread: incoming frames -> decrypt -> print + persist.
    let reader_ratchet = Arc::clone(&ratchet);
    let reader_ad = Arc::clone(&ad);
    let reader_history = Arc::clone(&history);
    let reader_peer = Arc::clone(&peer_name);
    std::thread::spawn(move || {
        let mut platform = OsPlatform;
        loop {
            let frame = match reader.recv_frame() {
                Ok(frame) => frame,
                Err(_) => break, // peer disconnected
            };
            let msg: RatchetMessage = match wire::decode(&frame) {
                Ok(msg) => msg,
                Err(_) => continue,
            };
            let decrypted = reader_ratchet.lock().unwrap().decrypt(&mut platform, &msg, &reader_ad);
            match decrypted {
                Ok(plaintext) => {
                    let (id, display) = render_incoming(&plaintext);
                    println!("{reader_peer}: {display}  (#{id})");
                    record(&reader_history, &reader_peer, false, display);
                }
                Err(_) => eprintln!("(received an undecryptable message)"),
            }
        }
    });

    // Main thread: stdin lines -> encrypt -> send + persist. Ends on Ctrl-D.
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        // A responder cannot send until it has received the peer's first
        // message; wait for the reader thread to establish the sending chain.
        while !ratchet.lock().unwrap().can_send() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let app = text_message(&line);
        let msg = ratchet.lock().unwrap().encrypt(&app.encode(), &ad);
        if writer.send_frame(&wire::encode(&msg)).is_err() {
            break;
        }
        record(&history, &peer_name, true, line);
    }
}


/// Persist one message to the encrypted history store (best-effort).
fn record(history: &Arc<Mutex<FileStore>>, peer: &str, from_me: bool, text: String) {
    let message = StoredMessage { id: String::new(), from_me, text, timestamp: OsPlatform.now_unix_secs(), expires_at: None };
    let _ = history::append(&mut *history.lock().unwrap(), peer, message);
}


/// Decode a decrypted payload into `(id, display)`, tolerating older raw text.
fn render_incoming(bytes: &[u8]) -> (String, String) {
    match AppMessage::decode(bytes) {
        Ok(msg) => {
            let summary = msg.summary();
            (msg.id, summary)
        }
        Err(_) => (String::new(), String::from_utf8_lossy(bytes).into_owned()),
    }
}
