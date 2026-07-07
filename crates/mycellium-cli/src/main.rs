//! **`mycellium`** — a thin, runnable messenger CLI over [`mycellium_app`].
//!
//! This binary is a shell: every real operation (accounts, contacts + trust,
//! conversations, the relay send/receive loop, persisted history) lives in
//! `mycellium-app`; the CLI only parses arguments, holds the on-disk config
//! (this device's key + relay URLs), and drives the engine.
//!
//! ```text
//!   mycellium account new                 # generate an identity + config
//!   mycellium publish                      # KeyPackage + device list → relays
//!   mycellium contact add <npub|nip05> [name]
//!   mycellium contacts                     # list known contacts + trust state
//!   mycellium chat <contact>               # interactive 1:1 conversation
//!   mycellium inbox [--seconds N]          # drain + print incoming messages
//!   mycellium relays                       # configured relay URLs
//! ```
//!
//! Data lives under `--data-dir` (default `$HOME/.mycellium`): `config.json`
//! next to the two SQLCipher databases `mycellium-app` maintains.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use mycellium_app::{App, Device};
use nostr::nips::nip05::{Nip05Address, Nip05Profile};
use nostr::nips::nip19::{FromBech32, ToBech32};
use nostr::{Keys, PublicKey, RelayUrl};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

/// A thin messenger client over MLS-over-Nostr (Marmot).
#[derive(Parser)]
#[command(name = "mycellium", version, about, long_about = None)]
struct Cli {
    /// Directory holding config.json and the encrypted databases.
    #[arg(long, short = 'd', global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Account identity: create one or show the current one.
    #[command(subcommand)]
    Account(AccountCmd),

    /// Add a contact by npub / hex pubkey / nip05 handle.
    Contact {
        #[command(subcommand)]
        cmd: ContactCmd,
    },

    /// List known contacts and their trust state.
    Contacts,

    /// Publish this device's KeyPackage and account device list to the relays.
    Publish,

    /// Open an interactive 1:1 conversation with a contact.
    Chat {
        /// The contact handle (its name, or npub if unnamed).
        contact: String,
    },

    /// Connect, drain, and print incoming messages for a few seconds.
    Inbox {
        /// How long to listen before exiting.
        #[arg(long, default_value_t = 5)]
        seconds: u64,
    },

    /// Pair THIS (new) device to an existing account: print an offer + SAS, then
    /// wait to be approved by the manager and join every conversation.
    Pair {
        /// How long to wait for approval (fan-out Welcomes) before exiting.
        #[arg(long, default_value_t = 120)]
        seconds: u64,
    },

    /// Manager: approve a new device from its offer string, after confirming the
    /// SAS matches the new device's screen.
    PairApprove {
        /// The offer string printed by `mycellium pair` on the new device.
        offer: String,
        /// Skip the interactive SAS confirmation (assume already verified).
        #[arg(long)]
        yes: bool,
    },

    /// Show the configured relay URLs.
    Relays,
}

#[derive(Subcommand)]
enum AccountCmd {
    /// Generate a new identity and write config.json.
    New {
        /// A relay URL to use (repeatable). Defaults to a public relay.
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Overwrite an existing config in this data dir.
        #[arg(long)]
        force: bool,
    },
    /// Print this account's npub, device pubkey, and relays.
    Show,
}

#[derive(Subcommand)]
enum ContactCmd {
    /// Add a contact, pinning its key (trust-on-first-use).
    Add {
        /// npub, hex pubkey, or a nip05 handle (`name@domain`).
        handle: String,
        /// A local name to reference the contact by.
        name: Option<String>,
    },
}

/// On-disk client config: this device's secret key plus its relay URLs.
#[derive(Serialize, Deserialize)]
struct Config {
    /// The device/account secret key, bech32 (`nsec1…`).
    secret_key: String,
    /// Relay URLs this device connects to.
    relays: Vec<String>,
}

impl Config {
    fn keys(&self) -> Result<Keys> {
        Keys::parse(&self.secret_key).context("parsing the stored secret key")
    }

    fn relay_urls(&self) -> Result<Vec<RelayUrl>> {
        self.relays
            .iter()
            .map(|r| RelayUrl::parse(r).with_context(|| format!("parsing relay url '{r}'")))
            .collect()
    }
}

const DEFAULT_RELAY: &str = "wss://relay.damus.io";

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = resolve_data_dir(cli.data_dir.as_deref())?;

    match cli.command {
        Command::Account(AccountCmd::New { relays, force }) => {
            account_new(&data_dir, relays, force)
        }
        Command::Account(AccountCmd::Show) => account_show(&data_dir),
        Command::Contact {
            cmd: ContactCmd::Add { handle, name },
        } => contact_add(&data_dir, &handle, name),
        Command::Contacts => contacts_list(&data_dir),
        Command::Publish => publish(&data_dir).await,
        Command::Chat { contact } => chat(&data_dir, &contact).await,
        Command::Inbox { seconds } => inbox(&data_dir, seconds).await,
        Command::Pair { seconds } => pair(&data_dir, seconds).await,
        Command::PairApprove { offer, yes } => pair_approve(&data_dir, &offer, yes).await,
        Command::Relays => relays(&data_dir),
    }
}

// -- config plumbing --------------------------------------------------------

fn resolve_data_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Ok(env) = std::env::var("MYCELLIUM_DATA_DIR") {
        return Ok(PathBuf::from(env));
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("$HOME is not set; pass --data-dir"))?;
    Ok(home.join(".mycellium"))
}

fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join("config.json")
}

fn load_config(data_dir: &Path) -> Result<Config> {
    let path = config_path(data_dir);
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        anyhow!(
            "no config at {} ({e}); run `mycellium account new` first",
            path.display()
        )
    })?;
    serde_json::from_str(&raw).context("parsing config.json")
}

/// Open the engine from the on-disk config as a solo (single-device) account.
fn open_app(data_dir: &Path) -> Result<(App, Config)> {
    let config = load_config(data_dir)?;
    let keys = config.keys()?;
    let relays = config.relay_urls()?;
    let app = App::open_solo(keys, relays, data_dir).context("opening the app engine")?;
    Ok((app, config))
}

// -- commands ---------------------------------------------------------------

fn account_new(data_dir: &Path, relays: Vec<String>, force: bool) -> Result<()> {
    let path = config_path(data_dir);
    if path.exists() && !force {
        bail!(
            "config already exists at {}; pass --force to overwrite",
            path.display()
        );
    }
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("creating data dir {}", data_dir.display()))?;

    let relays = if relays.is_empty() {
        vec![DEFAULT_RELAY.to_string()]
    } else {
        relays
    };
    // Validate the relay URLs up front so a bad one fails now, not at connect.
    for r in &relays {
        RelayUrl::parse(r).with_context(|| format!("invalid relay url '{r}'"))?;
    }

    let keys = Keys::generate();
    let config = Config {
        secret_key: keys.secret_key().to_bech32().context("encoding nsec")?,
        relays,
    };
    write_config(&path, &config)?;

    println!("account created");
    println!("  npub:     {}", keys.public_key().to_bech32()?);
    println!("  data dir: {}", data_dir.display());
    println!("  relays:   {}", config.relays.join(", "));
    println!("\nnext: `mycellium publish` to announce this device to the relays.");
    Ok(())
}

fn write_config(path: &Path, config: &Config) -> Result<()> {
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    // The config holds a secret key — make it owner-only where the OS supports it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn account_show(data_dir: &Path) -> Result<()> {
    let config = load_config(data_dir)?;
    let keys = config.keys()?;
    println!("npub:     {}", keys.public_key().to_bech32()?);
    println!("pubkey:   {}", keys.public_key().to_hex());
    println!("data dir: {}", data_dir.display());
    println!("relays:   {}", config.relays.join(", "));
    Ok(())
}

fn contact_add(data_dir: &Path, handle: &str, name: Option<String>) -> Result<()> {
    let (account, nip05) = resolve_identity(handle)?;
    let (app, _config) = open_app(data_dir)?;

    // The local handle used to reference the contact later: the given name, else
    // its npub.
    let local_id = name
        .clone()
        .unwrap_or_else(|| account.to_bech32().unwrap_or_else(|_| account.to_hex()));

    let status = app
        .add_contact(&local_id, account, nip05, name)
        .context("adding the contact")?;
    println!("contact '{local_id}' — {}", status.label());
    println!("  npub: {}", account.to_bech32()?);
    if status.label().contains("changed") {
        println!("  WARNING: this handle was already pinned to a DIFFERENT key.");
    }
    Ok(())
}

fn contacts_list(data_dir: &Path) -> Result<()> {
    let (app, _config) = open_app(data_dir)?;
    let contacts = app.contacts()?;
    if contacts.is_empty() {
        println!("(no contacts yet — add one with `mycellium contact add <npub|nip05>`)");
        return Ok(());
    }
    for c in contacts {
        let verified = if c.verified { "verified" } else { "pinned" };
        let npub = c.account.to_bech32().unwrap_or_else(|_| c.account.to_hex());
        match &c.nip05 {
            Some(n) => println!("{}  [{verified}]  {npub}  ({n})", c.id),
            None => println!("{}  [{verified}]  {npub}", c.id),
        }
    }
    Ok(())
}

fn relays(data_dir: &Path) -> Result<()> {
    let config = load_config(data_dir)?;
    for r in &config.relays {
        println!("{r}");
    }
    Ok(())
}

async fn publish(data_dir: &Path) -> Result<()> {
    let (app, _config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;

    app.publish_key_package()
        .await
        .context("publishing KeyPackage")?;
    // Announce this single device as the account's device list.
    let device = Device::new(app.device_pubkey());
    app.publish_device_list(vec![device])
        .await
        .context("publishing device list")?;

    app.shutdown().await;
    println!(
        "published KeyPackage + device list for {}",
        app.account().to_bech32()?
    );
    Ok(())
}

async fn chat(data_dir: &Path, contact: &str) -> Result<()> {
    let (mut app, _config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;
    app.subscribe().await.context("subscribing to the relays")?;

    // Settle any pending joins/commits so an existing conversation is discovered.
    app.pump(Duration::from_millis(600)).await?;

    let conversation = resolve_conversation(&app, contact).await?;
    println!("conversation {conversation} with '{contact}' — type a line to send, Ctrl-D to quit.");

    // Replay the recent transcript so the session has context on open.
    for m in app
        .transcript(&conversation)?
        .into_iter()
        .rev()
        .take(20)
        .rev()
    {
        let who = if m.from_me { "me" } else { "them" };
        println!("  [{who}] {}", m.text);
    }

    // Read stdin lines off-thread and feed them in over a channel, so the main
    // loop can both send and drain incoming messages without blocking on I/O.
    let (line_tx, mut line_rx) = mpsc::channel::<String>(16);
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line_tx.send(line).await.is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            maybe_line = line_rx.recv() => {
                match maybe_line {
                    Some(line) if !line.trim().is_empty() => {
                        if let Err(e) = app.send_text(&conversation, &line).await {
                            eprintln!("send failed: {e}");
                        }
                    }
                    Some(_) => {} // blank line: ignore
                    None => break, // stdin closed (Ctrl-D)
                }
            }
            // Only this future borrows `app` while the select waits, so sending
            // in the branch above stays a distinct, non-overlapping borrow.
            received = app.next_message(Duration::from_millis(500)) => {
                if let Some(msg) = received? {
                    if msg.conversation == conversation {
                        print!("  [them] {}\n> ", msg.text);
                        let _ = std::io::stdout().flush();
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    app.shutdown().await;
    println!("\nbye.");
    Ok(())
}

async fn inbox(data_dir: &Path, seconds: u64) -> Result<()> {
    let (mut app, _config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;
    app.subscribe().await.context("subscribing to the relays")?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let mut count = 0usize;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if let Some(msg) = app
            .next_message(remaining.min(Duration::from_millis(500)))
            .await?
        {
            count += 1;
            let convs = app.conversations()?;
            let title = convs
                .iter()
                .find(|(id, _)| *id == msg.conversation)
                .map(|(_, t)| t.as_str())
                .unwrap_or("conversation");
            println!("[{title}] {}", msg.text);
        }
    }
    app.shutdown().await;
    if count == 0 {
        println!("(no messages in {seconds}s)");
    }
    Ok(())
}

/// **New device**: print a pairing offer + its SAS, publish this device's
/// KeyPackage, then wait to be approved — receiving the fan-out Welcomes and any
/// messages that arrive once the manager pins this device into the account.
async fn pair(data_dir: &Path, seconds: u64) -> Result<()> {
    let (mut app, _config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;
    app.subscribe().await.context("subscribing to the relays")?;
    // Advertise this device's KeyPackage so the manager can enrol it.
    app.publish_key_package()
        .await
        .context("publishing KeyPackage")?;

    let offer = app.pairing_offer();
    println!("New device pairing. Give the manager this offer:\n");
    println!("  {offer}\n");
    println!("Then confirm the SAS below MATCHES the manager's screen:\n");
    println!("      SAS:  {}\n", offer.sas());
    println!("Waiting up to {seconds}s to be approved and join conversations...");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let mut joined = 0usize;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if let Some(msg) = app
            .next_message(remaining.min(Duration::from_millis(500)))
            .await?
        {
            println!("  [received] {}", msg.text);
        }
        let convos = app.conversations()?.len();
        if convos > joined {
            joined = convos;
            println!("  joined {joined} conversation(s)");
        }
    }
    app.shutdown().await;
    if joined == 0 {
        println!("(not approved within {seconds}s — no conversations joined)");
    } else {
        println!("paired: joined {joined} conversation(s).");
    }
    Ok(())
}

/// **Manager**: approve a new device from its offer string. Prints the SAS the
/// manager must confirm matches the new device's screen (the out-of-band check),
/// then pins the device into the account and fans it into every conversation.
async fn pair_approve(data_dir: &Path, offer_str: &str, yes: bool) -> Result<()> {
    let offer: mycellium_app::PairingOffer = offer_str
        .parse()
        .context("parsing the pairing offer string")?;

    println!("Pairing a new device: {}", offer.device_pubkey.to_hex());
    println!("\n      SAS:  {}\n", offer.sas());
    println!("Confirm this SAS is IDENTICAL to the one shown on the new device.");
    if !yes {
        print!("Type 'yes' to approve (anything else aborts): ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading confirmation")?;
        if line.trim() != "yes" {
            bail!("aborted: SAS not confirmed — the new device was NOT approved");
        }
    }

    let (mut app, _config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;
    app.subscribe().await.context("subscribing to the relays")?;
    // Settle existing joins/commits so every current conversation is enrolled.
    app.pump(Duration::from_millis(600)).await?;

    app.approve_device(&offer)
        .await
        .context("approving the new device")?;

    app.shutdown().await;
    println!("approved: the device was added to the account and fanned into every conversation.");
    Ok(())
}

// -- helpers ----------------------------------------------------------------

/// Find the existing 1:1 conversation for a contact, or start one.
async fn resolve_conversation(app: &App, contact: &str) -> Result<mycellium_app::ConversationId> {
    let c = app
        .contact(contact)?
        .ok_or_else(|| anyhow!("no contact known under handle '{contact}'"))?;
    // `start_conversation` titles a 1:1 by the contact's name, else its handle —
    // match on that to reopen rather than create a second group.
    let title = c.name.clone().unwrap_or_else(|| c.id.clone());
    for (id, t) in app.conversations()? {
        if t == title {
            return Ok(id);
        }
    }
    let conv = app
        .start_conversation(contact)
        .await
        .context("starting the conversation")?;
    Ok(conv)
}

/// Resolve a contact handle (`npub…`, hex, or `name@domain` nip05) to a pubkey,
/// returning the pubkey and the nip05 string if that was the input form.
fn resolve_identity(handle: &str) -> Result<(PublicKey, Option<String>)> {
    if handle.starts_with("npub1") {
        let pk = PublicKey::from_bech32(handle).context("parsing npub")?;
        return Ok((pk, None));
    }
    if handle.contains('@') {
        let pk = resolve_nip05(handle)?;
        return Ok((pk, Some(handle.to_string())));
    }
    if let Ok(pk) = PublicKey::from_hex(handle) {
        return Ok((pk, None));
    }
    bail!("'{handle}' is not a valid npub, hex pubkey, or nip05 handle")
}

/// Resolve a nip05 handle by fetching its `.well-known/nostr.json` (one blocking
/// HTTPS GET) and extracting the pubkey.
fn resolve_nip05(handle: &str) -> Result<PublicKey> {
    let address = Nip05Address::parse(handle).context("parsing the nip05 handle")?;
    let body = ureq::get(address.url().as_str())
        .call()
        .with_context(|| format!("fetching {}", address.url()))?
        .into_string()
        .context("reading the nip05 response")?;
    let profile = Nip05Profile::from_raw_json(&address, &body)
        .with_context(|| format!("no pubkey for '{handle}' in the nostr.json"))?;
    Ok(profile.public_key)
}
