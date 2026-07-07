//! The Mycellium **Circuit Relay v2** server binary.
//!
//! An operator runs this so NAT'd Mycellium peers stay reachable: a recipient
//! behind a firewall reserves a slot here, publishes its `…/p2p-circuit/…`
//! address, and senders reach it *through* this relay (issue #59). The relay
//! only forwards opaque, end-to-end Noise-encrypted circuit bytes — it holds no
//! message keys and can read nothing it forwards; the worst it can do is drop
//! traffic (so peers just fall back to another route or the queue).
//!
//! All the mechanism already lives in `mycellium-transport`: a `Libp2pNode`'s
//! swarm includes `relay::Behaviour` as a server and runs on a background task,
//! granting reservations and forwarding circuits autonomously — so this binary
//! is a thin shell (mirroring `mycellium-server` / `mycellium-queue`): resolve
//! the bind address, load-or-generate a **stable** identity, start the node,
//! print the dialable multiaddr, and stay alive.
//!
//! Kept dependency-lean on purpose (no arg-parsing crate). Runtime
//! configuration comes from `--config PATH`, or from explicit `--dev` mode for
//! local work.

use std::process::exit;

use mycellium_transport::libp2p_net::{listen_multiaddr, Libp2pNode};
use serde::Deserialize;
use tracing::{error, info, warn};

const DEFAULT_ADDR: &str = "0.0.0.0:8700";

fn main() {
    init_tracing();

    let args = match Args::parse() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}\n");
            print_help();
            exit(2);
        }
    };
    let config = match args.config {
        Some(path) => match load_config(&path) {
            Ok(config) => config,
            Err(err) => {
                error!(%err, "invalid relay configuration");
                exit(2);
            }
        },
        None if args.dev => Config::dev(),
        None => {
            eprintln!("mycellium-relay: pass --config PATH or --dev\n");
            print_help();
            exit(2);
        }
    };

    let secret = load_or_generate_secret(config.data_dir.as_deref());

    let listen = match listen_multiaddr(&config.addr) {
        Ok(a) => a,
        Err(err) => {
            error!(addr = %config.addr, %err, "invalid relay bind address");
            exit(2);
        }
    };

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "mycellium-relay — Circuit Relay v2 server"
    );

    // Start the node. Its background swarm task (spawned inside `new`) grants
    // reservations and forwards circuit traffic on its own — no accept()/dial()
    // calls are needed here; we only keep the node alive.
    let mut node = match Libp2pNode::new(secret, Some(listen)) {
        Ok(n) => n,
        Err(err) => {
            error!(%err, "could not start the relay node");
            exit(1);
        }
    };

    // `listen_addr()` blocks until the swarm reports the concrete bound address
    // (resolving a `tcp/0` bind to the OS-assigned port), so what we log is the
    // real, dialable address. It is interpolated into the message (not a field)
    // so it stays a bare, whitespace-delimited token an operator (or tooling)
    // can copy straight out of the log line.
    let bound = match node.listen_addr() {
        Ok(a) => a,
        Err(err) => {
            error!(%err, "never bound a listen address");
            exit(1);
        }
    };
    let dialable = format!("{bound}/p2p/{}", node.peer_id());

    info!("relay listening — advertise this dialable multiaddr to peers: {dialable}");
    info!("recipients run:  serve --libp2p --relay {dialable}");
    info!("forwards opaque Noise-encrypted circuit traffic only; holds no keys, reads nothing");
    info!("press Ctrl-C to stop");

    // Stay alive for the process lifetime, holding `node` (and its background
    // swarm task + runtime) so the relay keeps granting reservations and
    // forwarding circuits. The default SIGINT/SIGTERM handler terminates the
    // process on Ctrl-C; there is no work to do on the main thread until then.
    loop {
        std::thread::park();
    }
}

struct Args {
    config: Option<String>,
    dev: bool,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut config = None;
        let mut dev = false;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--config" => {
                    i += 1;
                    config = Some(
                        args.get(i)
                            .cloned()
                            .ok_or_else(|| "--config requires a path".to_string())?,
                    );
                }
                "--dev" => {
                    dev = true;
                }
                "--help" | "-h" => {
                    print_help();
                    exit(0);
                }
                "--version" | "-V" => {
                    println!("mycellium-relay {}", env!("CARGO_PKG_VERSION"));
                    exit(0);
                }
                other => {
                    return Err(format!("unknown argument: {other}"));
                }
            }
            i += 1;
        }
        if dev && config.is_some() {
            return Err("--dev and --config are mutually exclusive".into());
        }
        Ok(Self { config, dev })
    }
}

struct Config {
    addr: String,
    data_dir: Option<String>,
}

impl Config {
    fn dev() -> Self {
        Self {
            addr: DEFAULT_ADDR.to_string(),
            data_dir: None,
        }
    }
}

#[derive(Deserialize)]
struct FileConfig {
    addr: Option<String>,
    data_dir: Option<String>,
}

fn load_config(path: &str) -> Result<Config, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let file: FileConfig =
        serde_json::from_str(&raw).map_err(|e| format!("cannot parse {path}: {e}"))?;
    Ok(Config {
        addr: file.addr.unwrap_or_else(|| DEFAULT_ADDR.to_string()),
        data_dir: file.data_dir,
    })
}

fn print_help() {
    println!("mycellium-relay — the Mycellium Circuit Relay v2 server\n");
    println!("USAGE:");
    println!("    mycellium-relay --dev");
    println!("    mycellium-relay --config PATH\n");
    println!("Config is JSON. Example:");
    println!(
        r#"{{
  "addr": "0.0.0.0:8700",
  "data_dir": "./data/relay"
}}"#
    );
}

/// Load the relay's 32-byte device secret from `data_dir/relay.key`, or
/// generate one and persist it there (0600) — mirroring the queue's VAPID key.
///
/// A relay's PeerId is derived from this secret and is baked into every client's
/// `--relay <…/p2p/<id>>` address, so it MUST be stable across restarts. Dev
/// mode uses an ephemeral secret and prints a warning.
fn load_or_generate_secret(data_dir: Option<&str>) -> [u8; 32] {
    let dir = match data_dir {
        Some(d) if !d.trim().is_empty() => d,
        _ => {
            warn!(
                "identity: dev mode uses an EPHEMERAL key; the relay's PeerId will CHANGE on \
                 restart and break clients' --relay addresses. Use --config with data_dir to \
                 persist a stable identity."
            );
            return random_secret();
        }
    };
    let _ = std::fs::create_dir_all(dir);
    let path = format!("{}/relay.key", dir.trim_end_matches('/'));
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(secret) = <[u8; 32]>::try_from(bytes.as_slice()) {
            info!(%path, "identity: relay key loaded — PeerId is stable");
            return secret;
        }
        warn!(%path, "identity: relay key unreadable; regenerating");
    }
    let secret = random_secret();
    match std::fs::write(&path, secret) {
        Ok(()) => {
            restrict_perms(&path);
            info!(%path, "identity: relay key generated + persisted — PeerId is stable");
        }
        Err(err) => {
            warn!(%err, "identity: could not persist relay key; the PeerId will change on restart")
        }
    }
    secret
}

/// Install the process-wide structured-logging sink once at startup: a
/// `tracing_subscriber` fmt subscriber filtered by `RUST_LOG` (default `info`).
/// Writes to stdout so the dialable multiaddr stays copy-pastable from the log.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(false)
        .with_writer(std::io::stdout)
        .init();
}

fn random_secret() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS RNG must be available");
    bytes
}

#[cfg(unix)]
fn restrict_perms(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_perms(_path: &str) {}
