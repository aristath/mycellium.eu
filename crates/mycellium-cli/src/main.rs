//! `mycellium` hard-serverless client shell.
//!
//! The shell has no directory, queue, relay, mailbox, or push-service dependency.
//! Peers exchange/import self-authenticating records, then messages travel over
//! direct transports or wait in the sender's local outbox.

mod app;
mod platform;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;

use app::*;
use mycellium_storage::store;

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
    Device {
        handle: String,
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
    let result = match cli.command {
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
        Command::Device { handle } => list_device(&handle),
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
    };
    print_engine_diagnostics();
    result
}

fn print_engine_diagnostics() {
    for diagnostic in mycellium_engine::take_diagnostics() {
        match diagnostic {
            mycellium_engine::EngineDiagnostic::CorruptLocalState { what } => eprintln!(
                "(warning: corrupt {what} in local storage — treated as empty; back up before it is overwritten)"
            ),
        }
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
    })?;
    Ok(())
}
