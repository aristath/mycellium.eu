//! `mycellium` hard-serverless client shell.
//!
//! The shell has no directory, queue, relay, mailbox, or push-service dependency.
//! Peers exchange/import self-authenticating records, then messages travel over
//! direct transports or wait in the sender's local outbox.

mod tui;

use std::io::BufRead;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;

use mycellium_core::identity::Handle;
use mycellium_core::message::AppMessage;
use mycellium_core::platform::Platform;
use mycellium_core::ratchet::RatchetMessage;
use mycellium_core::transport::Transport;
use mycellium_core::wire;
use mycellium_engine::app::*;
use mycellium_engine::blocklist;
use mycellium_engine::history::{self, StoredMessage};
use mycellium_engine::peerbook;
use mycellium_engine::platform::OsPlatform;
use mycellium_storage::filestore::FileStore;
use mycellium_storage::store;
use mycellium_transport::libp2p_net::{self, Libp2pNode};
use mycellium_transport::link::{FrameReader, FrameWriter};
use mycellium_transport::net::TcpTransport;

#[derive(Parser)]
#[command(name = "mycellium", about = "Hard-serverless peer-to-peer messenger")]
struct Cli {
    /// JSON client config. If omitted, `.mycellium` is used.
    #[arg(long, global = true)]
    config: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    IdentityNew,
    /// Adopt an existing wallet secret on this fresh device.
    IdentityAdopt {
        wallet_secret: String,
    },
    IdentityShow,
    /// Print the account wallet secret for explicit user-controlled transfer.
    IdentityExportWallet {
        #[arg(long)]
        yes: bool,
    },
    /// Create/update your local signed record and print it for sharing.
    Register {
        handle: String,
        #[arg(long)]
        addr: String,
        #[arg(long)]
        libp2p: bool,
    },
    /// Import/export local signed peer records.
    Record {
        #[command(subcommand)]
        action: RecordAction,
    },
    /// Ask a directly reachable known peer for signed peer records.
    Discover {
        peer: String,
        #[arg(long, value_delimiter = ',')]
        want: Vec<String>,
    },
    /// Non-authoritative DHT discovery for signed peer records.
    Dht {
        #[command(subcommand)]
        action: DhtAction,
    },
    Devices {
        handle: String,
    },
    RevokeDevice {
        handle: String,
        device_id: String,
    },
    Listen {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        libp2p: bool,
        #[arg(long)]
        tui: bool,
    },
    Chat {
        peer: String,
        #[arg(long = "as")]
        whoami: String,
        #[arg(long)]
        tui: bool,
    },
    Send {
        peer: String,
        #[arg(long = "as")]
        whoami: String,
        #[arg(long)]
        message: Option<String>,
        #[arg(long)]
        reply_to: Option<String>,
        #[arg(long)]
        react: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        edit: Option<String>,
        #[arg(long)]
        delete: Option<String>,
        #[arg(long)]
        expire: Option<String>,
    },
    Outbox {
        #[command(subcommand)]
        action: OutboxAction,
    },
    Serve {
        #[arg(long)]
        addr: String,
        #[arg(long = "as")]
        whoami: String,
        #[arg(long)]
        libp2p: bool,
    },
    History {
        peer: String,
    },
    ClearHistory {
        peer: String,
    },
    Conversations,
    Search {
        query: String,
    },
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
    Contact {
        #[command(subcommand)]
        action: ContactAction,
    },
    Verify {
        peer: String,
        #[arg(long)]
        confirm: bool,
        /// Explicitly replace a previously pinned/verified wallet after
        /// comparing the new safety number out of band.
        #[arg(long)]
        accept_change: bool,
    },
    Block {
        handle: String,
    },
    Unblock {
        handle: String,
    },
    Blocked,
    Expire {
        #[command(subcommand)]
        action: ExpireAction,
    },
    Export {
        path: String,
    },
    Import {
        path: String,
    },
    Draft {
        #[command(subcommand)]
        action: DraftAction,
    },
    Wipe {
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum RecordAction {
    Export { handle: String },
    Import { handle: String, record: String },
    List,
    Remove { handle: String },
}

#[derive(Subcommand)]
enum DhtAction {
    /// Run a DHT discovery peer. It stores signed records, never messages.
    Serve {
        #[arg(long)]
        addr: String,
        #[arg(long)]
        bootstrap: Vec<String>,
    },
    /// Publish one of this profile's local signed records to the DHT.
    Publish {
        handle: String,
        #[arg(long)]
        bootstrap: Vec<String>,
        #[arg(long)]
        listen: Option<String>,
    },
    /// Lookup and import a signed peer record from the DHT.
    Lookup {
        handle: String,
        #[arg(long)]
        bootstrap: Vec<String>,
        #[arg(long)]
        listen: Option<String>,
    },
}

#[derive(Subcommand)]
enum OutboxAction {
    List,
    Retry,
    Cancel { id: String },
}

#[derive(Subcommand)]
enum ContactAction {
    Add { nickname: String, handle: String },
    List,
    Remove { nickname: String },
}

#[derive(Subcommand)]
enum GroupAction {
    Create {
        name: String,
        #[arg(long, value_delimiter = ',')]
        members: Vec<String>,
        #[arg(long = "as")]
        whoami: String,
    },
    Send {
        group: String,
        #[arg(long = "as")]
        whoami: String,
        #[arg(long)]
        message: Option<String>,
        #[arg(long)]
        reply_to: Option<String>,
        #[arg(long)]
        react: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        edit: Option<String>,
        #[arg(long)]
        delete: Option<String>,
        #[arg(long)]
        expire: Option<String>,
    },
    Add {
        group: String,
        #[arg(long)]
        member: String,
        #[arg(long = "as")]
        whoami: String,
    },
    History {
        group: String,
    },
    Info {
        group: String,
    },
    Leave {
        group: String,
        #[arg(long = "as")]
        whoami: String,
    },
    Sync {
        #[arg(long = "as")]
        whoami: String,
    },
    List,
}

#[derive(Subcommand)]
enum ExpireAction {
    Set { target: String, duration: String },
    Clear { target: String },
    Show { target: String },
}

#[derive(Subcommand)]
enum DraftAction {
    Set { peer: String, text: String },
    Show { peer: String },
    Clear { peer: String },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_client_config(cli.config.as_deref())?;
    match cli.command {
        Command::IdentityNew => identity_new(),
        Command::IdentityAdopt { wallet_secret } => identity_adopt(&wallet_secret),
        Command::IdentityShow => identity_show(),
        Command::IdentityExportWallet { yes } => identity_export_wallet(yes),
        Command::Register {
            handle,
            addr,
            libp2p,
        } => register(&handle, &addr, libp2p),
        Command::Record { action } => match action {
            RecordAction::Export { handle } => record_export(&handle),
            RecordAction::Import { handle, record } => record_import(&handle, &record),
            RecordAction::List => records_list(),
            RecordAction::Remove { handle } => remove_record(&handle),
        },
        Command::Discover { peer, want } => discover(&peer, &want),
        Command::Dht { action } => match action {
            DhtAction::Serve { addr, bootstrap } => dht_serve(&addr, &bootstrap),
            DhtAction::Publish {
                handle,
                bootstrap,
                listen,
            } => dht_publish(&handle, listen.as_deref(), &bootstrap),
            DhtAction::Lookup {
                handle,
                bootstrap,
                listen,
            } => dht_lookup(&handle, listen.as_deref(), &bootstrap),
        },
        Command::Devices { handle } => list_devices(&handle),
        Command::RevokeDevice { handle, device_id } => revoke_device(&handle, &device_id),
        Command::Listen { addr, libp2p, tui } => listen(&addr, libp2p, tui),
        Command::Chat { peer, whoami, tui } => chat(&peer, &whoami, tui),
        Command::Send {
            peer,
            whoami,
            message,
            reply_to,
            react,
            to,
            file,
            edit,
            delete,
            expire,
        } => send(
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
        ),
        Command::Outbox { action } => match action {
            OutboxAction::List => outbox_list(),
            OutboxAction::Retry => outbox_retry(),
            OutboxAction::Cancel { id } => outbox_cancel(&id),
        },
        Command::Serve {
            addr,
            whoami,
            libp2p,
        } => serve(&addr, &whoami, libp2p),
        Command::History { peer } => show_history(&peer),
        Command::ClearHistory { peer } => clear_history(&peer),
        Command::Conversations => conversations(),
        Command::Search { query } => search(&query),
        Command::Group { action } => match action {
            GroupAction::Create {
                name,
                members,
                whoami,
            } => group_create(&name, &members, &whoami),
            GroupAction::Send {
                group,
                whoami,
                message,
                reply_to,
                react,
                to,
                file,
                edit,
                delete,
                expire,
            } => group_send(
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
            ),
            GroupAction::Add {
                group,
                member,
                whoami,
            } => group_add(&group, &member, &whoami),
            GroupAction::History { group } => group_history(&group),
            GroupAction::Info { group } => group_info(&group),
            GroupAction::Leave { group, whoami } => group_leave(&group, &whoami),
            GroupAction::Sync { whoami } => group_sync(&whoami),
            GroupAction::List => group_list(),
        },
        Command::Contact { action } => match action {
            ContactAction::Add { nickname, handle } => contact_add(&nickname, &handle),
            ContactAction::List => contact_list(),
            ContactAction::Remove { nickname } => contact_remove(&nickname),
        },
        Command::Verify {
            peer,
            confirm,
            accept_change,
        } => verify(&peer, confirm, accept_change),
        Command::Block { handle } => set_blocked(&handle, true),
        Command::Unblock { handle } => set_blocked(&handle, false),
        Command::Blocked => list_blocked(),
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

#[derive(Default, Deserialize)]
struct ClientConfigFile {
    data_dir: Option<String>,
    passphrase: Option<String>,
    display_name: Option<String>,
    #[serde(default)]
    dht_bootstrap: Vec<String>,
}

fn init_client_config(path: Option<&str>) -> Result<()> {
    let file = match path {
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("could not read client config '{path}'"))?;
            serde_json::from_str::<ClientConfigFile>(&raw)
                .with_context(|| format!("could not parse client config '{path}'"))?
        }
        None => ClientConfigFile::default(),
    };
    store::configure(store::ClientConfig {
        data_dir: file
            .data_dir
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(".mycellium")),
        passphrase: file.passphrase,
        display_name: file.display_name.unwrap_or_default(),
        dht_bootstrap: file.dht_bootstrap,
    });
    Ok(())
}

fn listen(addr: &str, libp2p: bool, tui: bool) -> Result<()> {
    let identity = store::load_identity()?;
    let history = Arc::new(Mutex::new(open_history(&identity)?));
    let blocked = blocklist::load(&*history.lock().unwrap())?;

    if libp2p {
        let listen_addr = libp2p_net::listen_multiaddr(addr)?;
        let mut node = Libp2pNode::new(identity.device_secret(), Some(listen_addr))?;
        println!("listening (libp2p) on {addr} as {}", node.peer_id());
        loop {
            let mut conn = node.accept()?;
            let session = {
                let mut fs = history.lock().unwrap();
                handshake_responder(&mut conn, &identity, &mut fs)
            };
            match session {
                Ok(session) if blocklist::is_blocked(&blocked, &session.peer_name) => {
                    eprintln!("(refused blocked peer '{}')", session.peer_name);
                }
                Ok(session) => {
                    let (reader, writer) = conn.split();
                    run_session(
                        Box::new(reader),
                        Box::new(writer),
                        session,
                        tui,
                        Arc::clone(&history),
                    );
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
            let session = {
                let mut fs = history.lock().unwrap();
                handshake_responder(&mut conn, &identity, &mut fs)
            };
            match session {
                Ok(session) if blocklist::is_blocked(&blocked, &session.peer_name) => {
                    eprintln!("(refused blocked peer '{}')", session.peer_name);
                }
                Ok(session) => {
                    let (reader, writer) = conn.split()?;
                    run_session(
                        Box::new(reader),
                        Box::new(writer),
                        session,
                        tui,
                        Arc::clone(&history),
                    );
                    std::process::exit(0);
                }
                Err(err) => eprintln!("(ignoring connection: {err})"),
            }
        }
    }
}

fn chat(peer: &str, whoami: &str, tui: bool) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let history = Arc::new(Mutex::new(open_history(&identity)?));
    let (peer_handle, peer_record, my_record) = {
        let mut fs = history.lock().unwrap();
        let (peer_handle, peer_record) = lookup_verified(&mut fs, peer)?;
        let my_record = peerbook::get(&*fs, &me)?.ok_or_else(|| {
            anyhow!(
                "no local signed record for '{}' — run `register {}` first",
                me.as_str(),
                me.as_str()
            )
        })?;
        (peer_handle, peer_record, my_record)
    };
    let location = String::from_utf8(peer_record.record.primary().peer_id.0.clone())
        .context("peer record has no dialable address")?;

    if location.starts_with('/') {
        let mut node = Libp2pNode::new(identity.device_secret(), None)?;
        let mut conn = node
            .dial_str(&location)
            .with_context(|| format!("could not connect to {location}"))?;
        let session = handshake_initiator(
            &mut conn,
            &identity,
            &me,
            &my_record,
            &peer_handle,
            &peer_record,
            &location,
        )?;
        let (reader, writer) = conn.split();
        run_session(
            Box::new(reader),
            Box::new(writer),
            session,
            tui,
            Arc::clone(&history),
        );
        node.drain(300);
        std::process::exit(0);
    } else {
        let mut transport = TcpTransport::dialer();
        let mut conn = transport
            .dial(&peer_record.record.primary().peer_id)
            .with_context(|| format!("could not connect to {location}"))?;
        let session = handshake_initiator(
            &mut conn,
            &identity,
            &me,
            &my_record,
            &peer_handle,
            &peer_record,
            &location,
        )?;
        let (reader, writer) = conn.split()?;
        run_session(
            Box::new(reader),
            Box::new(writer),
            session,
            tui,
            Arc::clone(&history),
        );
        std::process::exit(0);
    }
}

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

fn run_duplex(
    mut reader: Box<dyn FrameReader>,
    mut writer: Box<dyn FrameWriter>,
    session: Session,
    history: Arc<Mutex<FileStore>>,
) {
    let Session {
        ratchet,
        ad,
        peer_name,
    } = session;
    let ratchet = Arc::new(Mutex::new(ratchet));
    let ad = Arc::new(ad);
    let peer_name = Arc::new(peer_name);

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

    let reader_ratchet = Arc::clone(&ratchet);
    let reader_ad = Arc::clone(&ad);
    let reader_history = Arc::clone(&history);
    let reader_peer = Arc::clone(&peer_name);
    std::thread::spawn(move || {
        let mut platform = OsPlatform;
        loop {
            let frame = match reader.recv_frame() {
                Ok(frame) => frame,
                Err(_) => break,
            };
            let msg: RatchetMessage = match wire::decode(&frame) {
                Ok(msg) => msg,
                Err(_) => continue,
            };
            match reader_ratchet
                .lock()
                .unwrap()
                .decrypt(&mut platform, &msg, &reader_ad)
            {
                Ok(plaintext) => {
                    let (id, expires_at, display) = render_incoming(&plaintext);
                    println!("{reader_peer}: {display}  (#{id})");
                    record(
                        &reader_history,
                        &reader_peer,
                        false,
                        id,
                        display,
                        expires_at,
                    );
                }
                Err(_) => eprintln!("(received an undecryptable message)"),
            }
        }
    });

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        while !ratchet.lock().unwrap().can_send() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let app = text_message(&line);
        let msg = ratchet.lock().unwrap().encrypt(&app.encode(), &ad);
        if writer.send_frame(&wire::encode(&msg)).is_err() {
            break;
        }
        record(
            &history,
            &peer_name,
            true,
            app.id.clone(),
            line,
            app.expires_at,
        );
    }
}

fn record(
    history: &Arc<Mutex<FileStore>>,
    peer: &str,
    from_me: bool,
    id: String,
    text: String,
    expires_at: Option<u64>,
) {
    let message = StoredMessage {
        id,
        from_me,
        text,
        timestamp: OsPlatform.now_unix_secs(),
        expires_at,
    };
    let _ = history::append(&mut *history.lock().unwrap(), peer, message);
}

fn render_incoming(bytes: &[u8]) -> (String, Option<u64>, String) {
    match AppMessage::decode(bytes) {
        Ok(msg) => {
            let summary = msg.summary();
            (msg.id, msg.expires_at, summary)
        }
        Err(_) => (
            String::new(),
            None,
            String::from_utf8_lossy(bytes).into_owned(),
        ),
    }
}
