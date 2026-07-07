//! **`mycellium`** — a thin, runnable messenger CLI over [`mycellium_app`].
//!
//! This binary is a shell: every real operation (accounts, contacts + trust,
//! conversations, the relay send/receive loop, persisted history) lives in
//! `mycellium-app`; the CLI only parses arguments, holds the on-disk config
//! (this device's key + relay URLs), and drives the engine.
//!
//! ```text
//!   mycellium account new                 # generate an identity + config
//!   mycellium account import <nsec>        # adopt an existing key you already hold
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

    /// Claim or release this account's NIP-05 name at its domain's name service.
    Name {
        #[command(subcommand)]
        cmd: NameCmd,
    },

    /// List the devices in this account's device list.
    Devices,

    /// Manage this account's devices (manager only).
    Device {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },

    /// Show the configured relay URLs.
    Relays,
}

#[derive(Subcommand)]
enum NameCmd {
    /// Register `name@domain` at the domain's name service (proving control of
    /// this account's key via NIP-98) and set it in your profile.
    Register {
        /// The address to claim, e.g. `alice@mycellium.eu`.
        address: String,
    },
    /// Release a `name@domain` you previously registered, freeing it for reuse.
    Release {
        /// The address to release, e.g. `alice@mycellium.eu`.
        address: String,
    },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// Remove a lost/compromised device from the account: drop it from the device
    /// list and evict it from every group (Post-Compromise Security — it can
    /// decrypt nothing sent after removal).
    Remove {
        /// The device pubkey to remove (npub or hex).
        pubkey: String,
    },
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
    /// Import an existing identity from its **secret** key, so a key you already
    /// hold (from another Nostr client) becomes this device's account. Requires
    /// the `nsec1…` — a public `npub1…` cannot be imported, since the app must
    /// sign as you.
    Import {
        /// The secret key to adopt: bech32 `nsec1…` or 64-char hex.
        secret: String,
        /// A relay URL to use (repeatable). Defaults to a public relay.
        #[arg(long = "relay")]
        relays: Vec<String>,
        /// Overwrite an existing config in this data dir.
        #[arg(long)]
        force: bool,
    },
    /// Print this account's npub, device pubkey, and relays.
    Show,
    /// **Publish this account's NIP-05 address** (`name@domain`) in its kind:0
    /// profile so contacts can verify the name→key binding. Hosting the domain's
    /// `.well-known/nostr.json` is the operator's job (server-side, out of scope).
    SetNip05 {
        /// The NIP-05 address to advertise (`name@domain`, or `_@domain` for root).
        address: String,
    },
    /// **Rotate this account's identity key** (hygiene, or recovery after the key
    /// is believed compromised). Publishes a mutual old→new migration attestation
    /// and re-signs the device list under the new key; the device key and every
    /// MLS conversation are untouched. Contacts must re-verify out of band.
    Rotate {
        /// Rotate without the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Show any pending account-key migration a contact has published (fetched from
    /// the relays and verified), including the new safety number to compare out of
    /// band before accepting it.
    Migration {
        /// The contact handle to probe.
        contact: String,
    },
    /// **Accept a contact's key migration** and re-pin to their new key — only
    /// after you have compared the new safety number out of band. Re-verifies the
    /// published mutual attestation before moving the pin.
    AcceptMigration {
        /// The contact handle whose migration to accept.
        contact: String,
        /// The new npub/hex pubkey you confirmed out of band.
        new_key: String,
        /// Accept without the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
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
    /// This **device's** secret key, bech32 (`nsec1…`). It is *also* the account
    /// key when `account_key` is absent (a solo account); it never changes on an
    /// account-key rotation, so MLS/history stay intact.
    secret_key: String,
    /// The separate **account** identity key, bech32 (`nsec1…`), present once the
    /// account key has been rotated away from the device key (making this a manager
    /// account). Absent for a solo account, where `secret_key` serves both roles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_key: Option<String>,
    /// Relay URLs this device connects to.
    relays: Vec<String>,
}

impl Config {
    /// This device's keypair.
    fn keys(&self) -> Result<Keys> {
        Keys::parse(&self.secret_key).context("parsing the stored device secret key")
    }

    /// The account identity keypair — the rotated account key if one is stored,
    /// else the device key (solo account).
    fn account_keys(&self) -> Result<Keys> {
        match &self.account_key {
            Some(ak) => Keys::parse(ak).context("parsing the stored account secret key"),
            None => self.keys(),
        }
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
        Command::Account(AccountCmd::Import {
            secret,
            relays,
            force,
        }) => account_import(&data_dir, &secret, relays, force),
        Command::Account(AccountCmd::Show) => account_show(&data_dir),
        Command::Account(AccountCmd::SetNip05 { address }) => {
            account_set_nip05(&data_dir, &address).await
        }
        Command::Account(AccountCmd::Rotate { yes }) => account_rotate(&data_dir, yes).await,
        Command::Account(AccountCmd::Migration { contact }) => {
            account_migration(&data_dir, &contact).await
        }
        Command::Account(AccountCmd::AcceptMigration {
            contact,
            new_key,
            yes,
        }) => account_accept_migration(&data_dir, &contact, &new_key, yes).await,
        Command::Contact {
            cmd: ContactCmd::Add { handle, name },
        } => contact_add(&data_dir, &handle, name).await,
        Command::Contacts => contacts_list(&data_dir),
        Command::Publish => publish(&data_dir).await,
        Command::Chat { contact } => chat(&data_dir, &contact).await,
        Command::Inbox { seconds } => inbox(&data_dir, seconds).await,
        Command::Pair { seconds } => pair(&data_dir, seconds).await,
        Command::PairApprove { offer, yes } => pair_approve(&data_dir, &offer, yes).await,
        Command::Name {
            cmd: NameCmd::Register { address },
        } => name_register(&data_dir, &address).await,
        Command::Name {
            cmd: NameCmd::Release { address },
        } => name_release(&data_dir, &address).await,
        Command::Devices => devices_list(&data_dir).await,
        Command::Device {
            cmd: DeviceCmd::Remove { pubkey },
        } => device_remove(&data_dir, &pubkey).await,
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

/// Open the engine from the on-disk config: a solo account when the account key
/// equals the device key, or a manager account once the account key has been
/// rotated to a separate key.
fn open_app(data_dir: &Path) -> Result<(App, Config)> {
    let config = load_config(data_dir)?;
    let device_keys = config.keys()?;
    let relays = config.relay_urls()?;
    let app = if config.account_key.is_some() {
        App::open_manager(config.account_keys()?, device_keys, relays, data_dir)
            .context("opening the app engine (manager)")?
    } else {
        App::open_solo(device_keys, relays, data_dir).context("opening the app engine")?
    };
    Ok((app, config))
}

// -- commands ---------------------------------------------------------------

fn account_new(data_dir: &Path, relays: Vec<String>, force: bool) -> Result<()> {
    let keys = Keys::generate();
    let config = create_account(data_dir, &keys, relays, force)?;
    report_account(data_dir, &keys, &config, "account created")
}

fn account_import(data_dir: &Path, secret: &str, relays: Vec<String>, force: bool) -> Result<()> {
    // A public key can't be imported — the app has to sign as this identity, which
    // needs the secret. Catch the common paste-the-npub mistake with a clear message
    // instead of a cryptic parse error.
    if secret.starts_with("npub1") {
        bail!(
            "'{secret}' is a public key (npub) — importing an identity needs its SECRET key \
             (nsec1…), which only you hold. A public key cannot sign, so it can't be imported."
        );
    }
    let keys = Keys::parse(secret).context(
        "parsing the secret key to import (expected an `nsec1…` bech32 or 64-char hex secret)",
    )?;
    let config = create_account(data_dir, &keys, relays, force)?;
    report_account(data_dir, &keys, &config, "account imported")
}

/// Write a fresh solo-account config built from `keys`, guarding an existing
/// config unless `force`. Shared by `account new` and `account import`.
fn create_account(
    data_dir: &Path,
    keys: &Keys,
    relays: Vec<String>,
    force: bool,
) -> Result<Config> {
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

    let config = Config {
        secret_key: keys.secret_key().to_bech32().context("encoding nsec")?,
        account_key: None,
        relays,
    };
    write_config(&path, &config)?;
    Ok(config)
}

fn report_account(data_dir: &Path, keys: &Keys, config: &Config, headline: &str) -> Result<()> {
    println!("{headline}");
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
    let device = config.keys()?;
    let account = config.account_keys()?;
    println!("account npub: {}", account.public_key().to_bech32()?);
    if config.account_key.is_some() {
        println!("  (account key rotated — separate from the device key)");
    }
    println!("device npub:  {}", device.public_key().to_bech32()?);
    println!("device pubkey:{}", device.public_key().to_hex());
    println!("data dir:     {}", data_dir.display());
    println!("relays:       {}", config.relays.join(", "));
    Ok(())
}

/// **Publish this account's NIP-05 address** in its kind:0 profile metadata, so
/// contacts can verify the `name@domain` → this-key binding. Hosting the domain's
/// `.well-known/nostr.json` file is server-side and out of scope.
async fn account_set_nip05(data_dir: &Path, address: &str) -> Result<()> {
    let address = mycellium_app::Nip05Address::parse(address)
        .with_context(|| format!("parsing nip05 address '{address}'"))?;

    let (app, _config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;
    app.set_nip05(&address)
        .await
        .context("publishing the nip05 profile")?;
    app.shutdown().await;

    println!("published NIP-05 '{address}' in this account's profile (kind:0).");
    println!("Ensure your domain serves it too:");
    println!(
        "  https://{}/.well-known/nostr.json?name={}  →  {{\"names\":{{\"{}\":\"{}\"}}}}",
        address.domain(),
        address.name(),
        address.name(),
        app.account().to_hex()
    );
    Ok(())
}

/// **Register this account's NIP-05 name** at its domain's name service: NIP-98-sign
/// a registration, POST it, and set the address in the profile. Unlike `set-nip05`
/// (which only advertises the claim on Nostr), this actually *claims* the name at
/// the domain — the domain must run a compatible name service (e.g. `mycellium-names`).
async fn name_register(data_dir: &Path, address: &str) -> Result<()> {
    let address = mycellium_app::Nip05Address::parse(address)
        .with_context(|| format!("parsing nip05 address '{address}'"))?;

    let (app, _config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;
    let result = app.register_name(&address).await;
    app.shutdown().await;
    result.with_context(|| format!("registering '{address}' at {}", address.domain()))?;

    println!("registered {address} — it now resolves to your account and is set in your profile.");
    println!(
        "  verify: https://{}/.well-known/nostr.json?name={}",
        address.domain(),
        address.name()
    );
    Ok(())
}

/// **Release a NIP-05 name** you registered at its domain's name service.
async fn name_release(data_dir: &Path, address: &str) -> Result<()> {
    let address = mycellium_app::Nip05Address::parse(address)
        .with_context(|| format!("parsing nip05 address '{address}'"))?;

    let (app, _config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;
    let result = app.release_name(&address).await;
    app.shutdown().await;
    result.with_context(|| format!("releasing '{address}' at {}", address.domain()))?;

    println!("released {address} — it is free to register again.");
    Ok(())
}

/// **Rotate this account's identity key.** Publishes the mutual old→new migration
/// attestation and re-signs the device list under the new key, then persists the
/// new account key into config.json. The device key and all MLS conversations are
/// untouched; contacts must re-verify out of band before they follow the new key.
async fn account_rotate(data_dir: &Path, yes: bool) -> Result<()> {
    if !yes {
        println!("Rotating this account's identity key will:");
        println!("  - publish a signed old→new migration (both keys consent),");
        println!("  - re-sign the device list under the new key,");
        println!("  - keep the device key and every conversation intact.");
        println!("Contacts will NOT auto-trust the new key — they must re-verify out of band.");
        print!("Type 'yes' to rotate (anything else aborts): ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading confirmation")?;
        if line.trim() != "yes" {
            bail!("aborted: the account key was NOT rotated");
        }
    }

    let (mut app, mut config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;
    app.subscribe().await.context("subscribing to the relays")?;
    // Settle any pending joins/commits so the current device list is in view.
    app.pump(Duration::from_millis(600)).await?;

    let old_npub = app.account().to_bech32().unwrap_or_default();
    let outcome = app
        .rotate_account_key()
        .await
        .context("rotating the account key")?;
    app.shutdown().await;

    // Persist the new account identity (the device key is unchanged).
    config.account_key = Some(
        outcome
            .new_keys
            .secret_key()
            .to_bech32()
            .context("encoding new nsec")?,
    );
    write_config(&config_path(data_dir), &config)?;

    println!("account key rotated.");
    println!("  old npub: {old_npub}");
    println!("  new npub: {}", outcome.new_keys.public_key().to_bech32()?);
    // Report whether a registered NIP-05 name followed the rotation.
    match outcome.name_carry {
        Some(Ok(addr)) => println!("  name:     {addr} now points at the new key"),
        Some(Err(reason)) => {
            println!("  name:     WARNING — could not carry your name over ({reason});");
            println!("            re-run `mycellium name register <you@domain>` to repair it.");
        }
        None => {}
    }
    println!("\nTell your contacts to run `mycellium account migration <you>` and re-verify");
    println!("the safety number out of band before they accept the new key.");
    Ok(())
}

/// Show any pending account-key migration a contact has published — fetched from
/// the relays and mutual-signature verified. Never re-pins: it prints the new key
/// and the safety number to compare out of band first.
async fn account_migration(data_dir: &Path, contact: &str) -> Result<()> {
    let (app, _config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;
    let signal = app
        .detect_migration(contact)
        .await
        .context("probing for a migration")?;
    app.shutdown().await;

    match signal {
        mycellium_app::MigrationSignal::None => {
            println!("no key migration published for '{contact}'.");
        }
        mycellium_app::MigrationSignal::Forged { reason } => {
            println!("REJECTED an invalid/forged migration for '{contact}': {reason}");
            println!("The pin is unchanged. Do NOT trust this — it is not signed by '{contact}''s pinned key.");
        }
        mycellium_app::MigrationSignal::PendingReverification {
            old_pubkey,
            new_pubkey,
            new_safety_number,
        } => {
            let new_npub = new_pubkey
                .to_bech32()
                .unwrap_or_else(|_| new_pubkey.to_hex());
            println!("PENDING key migration for '{contact}' (NOT yet trusted):");
            println!(
                "  old key: {}",
                old_pubkey
                    .to_bech32()
                    .unwrap_or_else(|_| old_pubkey.to_hex())
            );
            println!("  new key: {new_npub}");
            println!("\nCompare this safety number for the NEW key out of band with '{contact}':");
            println!("    {new_safety_number}");
            println!(
                "\nIf — and only if — it matches, accept it:\n  mycellium account accept-migration {contact} {new_npub}"
            );
        }
    }
    Ok(())
}

/// **Accept a contact's key migration** and re-pin to their new key. Only run this
/// after comparing the new safety number out of band (see `account migration`). The
/// engine re-verifies the published mutual attestation before moving the pin.
async fn account_accept_migration(
    data_dir: &Path,
    contact: &str,
    new_key: &str,
    yes: bool,
) -> Result<()> {
    let new_pubkey = parse_pubkey(new_key)?;

    if !yes {
        println!(
            "Accepting re-pins '{contact}' to {} and marks it verified.",
            new_pubkey
                .to_bech32()
                .unwrap_or_else(|_| new_pubkey.to_hex())
        );
        println!("Only do this if you compared the NEW safety number OUT OF BAND and it matched.");
        print!("Type 'yes' to accept (anything else aborts): ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading confirmation")?;
        if line.trim() != "yes" {
            bail!("aborted: the migration was NOT accepted; the pin is unchanged");
        }
    }

    let (mut app, _config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;
    app.accept_key_migration(contact, new_pubkey)
        .await
        .context("accepting the key migration")?;
    app.shutdown().await;

    println!(
        "accepted: '{contact}' is now pinned (verified) to {}.",
        new_pubkey
            .to_bech32()
            .unwrap_or_else(|_| new_pubkey.to_hex())
    );
    Ok(())
}

async fn contact_add(data_dir: &Path, handle: &str, name: Option<String>) -> Result<()> {
    let (mut app, _config) = open_app(data_dir)?;

    // A `name@domain` handle is resolved + verified via the NIP-05 module (the
    // resolved key is pinned TOFU and the binding recorded verified); an npub/hex
    // is pinned directly. Either way the pin is authoritative — NIP-05 is a
    // binding to verify, never an identity override.
    let (local_id, status) = if handle.contains('@') {
        let address = mycellium_app::Nip05Address::parse(handle)
            .with_context(|| format!("parsing nip05 handle '{handle}'"))?;
        let local_id = name.clone().unwrap_or_else(|| address.to_string());
        app.connect().await.context("connecting to relays")?;
        let status = app
            .add_contact_by_nip05(&mycellium_app::HttpsResolver, &address, name)
            .await
            .context("adding the contact by nip05")?;
        app.shutdown().await;
        println!("  nip05: {address} (verified → pinned key)");
        (local_id, status)
    } else {
        let account = parse_pubkey(handle).with_context(|| {
            format!("'{handle}' is not a valid npub, hex pubkey, or nip05 handle")
        })?;
        let local_id = name
            .clone()
            .unwrap_or_else(|| account.to_bech32().unwrap_or_else(|_| account.to_hex()));
        let status = app
            .add_contact(&local_id, account, None, name)
            .await
            .context("adding the contact")?;
        (local_id, status)
    };

    println!("contact '{local_id}' — {}", status.label());
    if let Some(c) = app.contact(&local_id)? {
        println!("  npub: {}", c.account.to_bech32()?);
    }
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
            Some(n) => {
                let nip05 = if c.nip05_verified {
                    format!("{n} ✓nip05")
                } else {
                    format!("{n} (nip05 unverified)")
                };
                println!("{}  [{verified}]  {npub}  ({nip05})", c.id);
            }
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
            received = app.next_event(Duration::from_millis(500)) => {
                match received? {
                    Some(mycellium_app::AppEvent::Message(msg)) if msg.conversation == conversation => {
                        print!("  [them] {}\n> ", msg.text);
                        let _ = std::io::stdout().flush();
                    }
                    Some(mycellium_app::AppEvent::Trust(trust)) => {
                        println!();
                        print_trust_event(&trust);
                        print!("> ");
                        let _ = std::io::stdout().flush();
                    }
                    _ => {}
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

    // Actively re-verify each contact's recorded NIP-05 binding against its pin and
    // surface any rebinding (a name now pointing at a different key) as a trust
    // warning. This is a pull (an HTTPS resolve), unlike the passive relay events,
    // so it runs once at inbox open. The pin is never changed here.
    for c in app.contacts()?.into_iter().filter(|c| c.nip05.is_some()) {
        match app
            .verify_nip05_signal(&mycellium_app::HttpsResolver, &c.id)
            .await
        {
            Ok(Some(event)) => print_trust_event(&event),
            Ok(None) => {}
            Err(e) => eprintln!("nip05 check for '{}' failed: {e}", c.id),
        }
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let mut count = 0usize;
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if let Some(event) = app
            .next_event(remaining.min(Duration::from_millis(500)))
            .await?
        {
            match event {
                mycellium_app::AppEvent::Message(msg) => {
                    count += 1;
                    let convs = app.conversations()?;
                    let title = convs
                        .iter()
                        .find(|(id, _)| *id == msg.conversation)
                        .map(|(_, t)| t.as_str())
                        .unwrap_or("conversation");
                    println!("[{title}] {}", msg.text);
                }
                mycellium_app::AppEvent::Trust(trust) => print_trust_event(&trust),
            }
        }
    }
    app.shutdown().await;
    if count == 0 {
        println!("(no messages in {seconds}s)");
    }
    Ok(())
}

/// Print a live trust event surfaced by the receive loop. None of these change a
/// pin: a migration prompts the user to re-verify out of band, then explicitly
/// accept; a device-list change is informational + refreshes the cached resolution.
fn print_trust_event(trust: &mycellium_app::TrustEvent) {
    match trust {
        mycellium_app::TrustEvent::KeyMigrationPending {
            contact,
            new_safety_number,
            ..
        } => {
            println!(
                "⚠ IDENTITY MIGRATION for {contact} — verify safety number {new_safety_number} then `account accept-migration`"
            );
        }
        mycellium_app::TrustEvent::ContactDevicesChanged { contact, devices } => {
            println!(
                "contact {contact} devices changed ({} now listed)",
                devices.len()
            );
        }
        mycellium_app::TrustEvent::ForgedMigration { contact, reason } => {
            println!("⚠ dropped a FORGED migration for {contact}: {reason} (pin unchanged)");
        }
        mycellium_app::TrustEvent::Nip05Mismatch {
            contact,
            address,
            resolved_pubkey,
        } => {
            let resolved = resolved_pubkey
                .to_bech32()
                .unwrap_or_else(|_| resolved_pubkey.to_hex());
            println!(
                "⚠ NIP-05 REBINDING for {contact}: '{address}' now resolves to {resolved} \
                 (NOT the pinned key). The pin is unchanged — re-verify out of band."
            );
        }
    }
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

/// List the account's devices from its published device list, flagging the device
/// this config represents.
async fn devices_list(data_dir: &Path) -> Result<()> {
    let (app, _config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;
    let devices = app.devices().await.context("fetching the device list")?;
    let me = app.device_pubkey();
    app.shutdown().await;

    if devices.is_empty() {
        println!("(no device list published yet — run `mycellium publish`)");
        return Ok(());
    }
    for d in devices {
        let npub = d.pubkey.to_bech32().unwrap_or_else(|_| d.pubkey.to_hex());
        let here = if d.pubkey == me {
            "  (this device)"
        } else {
            ""
        };
        match &d.name {
            Some(n) => println!("{npub}  {n}{here}"),
            None => println!("{npub}{here}"),
        }
    }
    Ok(())
}

/// **Manager**: remove a device from the account. Drops it from the signed device
/// list and evicts its leaf from every conversation, advancing each group to an
/// epoch the removed device never had (Post-Compromise Security).
async fn device_remove(data_dir: &Path, pubkey: &str) -> Result<()> {
    let device = parse_pubkey(pubkey)?;

    let (mut app, _config) = open_app(data_dir)?;
    app.connect().await.context("connecting to relays")?;
    app.subscribe().await.context("subscribing to the relays")?;
    // Settle existing joins/commits so this device's group state is current before
    // it authors the eviction commits.
    app.pump(Duration::from_millis(600)).await?;

    app.remove_device(device)
        .await
        .context("removing the device")?;

    app.shutdown().await;
    println!(
        "removed device {} — dropped from the device list and evicted from every group.",
        device.to_bech32().unwrap_or_else(|_| device.to_hex())
    );
    Ok(())
}

// -- helpers ----------------------------------------------------------------

/// Parse a device pubkey argument: an `npub1…` bech32 key or a raw hex key.
fn parse_pubkey(s: &str) -> Result<PublicKey> {
    if s.starts_with("npub1") {
        return PublicKey::from_bech32(s).context("parsing npub");
    }
    PublicKey::from_hex(s).context("parsing hex pubkey")
}

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
