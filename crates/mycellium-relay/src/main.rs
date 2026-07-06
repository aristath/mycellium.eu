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
//! Kept dependency-lean on purpose (no arg-parsing crate): the address comes
//! from `--addr`, else `MYCELLIUM_RELAY_ADDR`, else the default.

use std::process::exit;

use mycellium_transport::libp2p_net::{listen_multiaddr, Libp2pNode};

const DEFAULT_ADDR: &str = "0.0.0.0:8700";

fn main() {
    let addr = resolve_addr();
    let secret = load_or_generate_secret();

    let listen = match listen_multiaddr(&addr) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("mycellium-relay: invalid --addr {addr}: {err}");
            exit(2);
        }
    };

    println!(
        "mycellium-relay {} — Circuit Relay v2 server",
        env!("CARGO_PKG_VERSION")
    );

    // Start the node. Its background swarm task (spawned inside `new`) grants
    // reservations and forwards circuit traffic on its own — no accept()/dial()
    // calls are needed here; we only keep the node alive.
    let mut node = match Libp2pNode::new(secret, Some(listen)) {
        Ok(n) => n,
        Err(err) => {
            eprintln!("mycellium-relay: could not start the relay node: {err}");
            exit(1);
        }
    };

    // `listen_addr()` blocks until the swarm reports the concrete bound address
    // (resolving a `tcp/0` bind to the OS-assigned port), so what we print is the
    // real, dialable address.
    let bound = match node.listen_addr() {
        Ok(a) => a,
        Err(err) => {
            eprintln!("mycellium-relay: never bound a listen address: {err}");
            exit(1);
        }
    };
    let dialable = format!("{bound}/p2p/{}", node.peer_id());

    println!("  relay listening — advertise this multiaddr to peers:");
    println!("    {dialable}");
    println!("  recipients:  serve --libp2p --relay {dialable}");
    println!(
        "  forwards opaque Noise-encrypted circuit traffic only; holds no keys, reads nothing"
    );
    println!("  press Ctrl-C to stop");

    // Stay alive for the process lifetime, holding `node` (and its background
    // swarm task + runtime) so the relay keeps granting reservations and
    // forwarding circuits. The default SIGINT/SIGTERM handler terminates the
    // process on Ctrl-C; there is no work to do on the main thread until then.
    loop {
        std::thread::park();
    }
}

/// Resolve the bind address: `--addr HOST:PORT`, then `MYCELLIUM_RELAY_ADDR`,
/// then the default. Also handles `--help`/`--version`.
fn resolve_addr() -> String {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut addr: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                addr = Some(args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("--addr requires a HOST:PORT value");
                    exit(2);
                }));
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
                eprintln!("unknown argument: {other}\n");
                print_help();
                exit(2);
            }
        }
        i += 1;
    }
    addr.or_else(|| std::env::var("MYCELLIUM_RELAY_ADDR").ok())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| DEFAULT_ADDR.into())
}

fn print_help() {
    println!("mycellium-relay — the Mycellium Circuit Relay v2 server\n");
    println!("USAGE:");
    println!("    mycellium-relay [--addr HOST:PORT]\n");
    println!("The bind address may also be set via MYCELLIUM_RELAY_ADDR");
    println!("(default: {DEFAULT_ADDR}).\n");
    println!("Set MYCELLIUM_DATA to a directory so the relay's PeerId (and thus the");
    println!("multiaddr clients pass to `serve --relay`) is STABLE across restarts.");
}

/// Load the relay's 32-byte device secret from `MYCELLIUM_DATA/relay.key`, or
/// generate one and persist it there (0600) — mirroring the queue's VAPID key.
///
/// A relay's PeerId is derived from this secret and is baked into every client's
/// `--relay <…/p2p/<id>>` address, so it MUST be stable across restarts. Without
/// `MYCELLIUM_DATA` we use an ephemeral secret and warn loudly that the PeerId
/// (and every advertised relay address) will change on restart.
fn load_or_generate_secret() -> [u8; 32] {
    let dir = match std::env::var("MYCELLIUM_DATA") {
        Ok(d) if !d.trim().is_empty() => d,
        _ => {
            eprintln!(
                "  identity: MYCELLIUM_DATA is not set — using an EPHEMERAL key; the relay's \
                 PeerId will CHANGE on restart and break clients' --relay addresses. Set \
                 MYCELLIUM_DATA to persist a stable identity."
            );
            return random_secret();
        }
    };
    let _ = std::fs::create_dir_all(&dir);
    let path = format!("{}/relay.key", dir.trim_end_matches('/'));
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(secret) = <[u8; 32]>::try_from(bytes.as_slice()) {
            println!("  identity: relay key loaded ({path}) — PeerId is stable");
            return secret;
        }
        eprintln!("  identity: {path} is unreadable; regenerating");
    }
    let secret = random_secret();
    match std::fs::write(&path, secret) {
        Ok(()) => {
            restrict_perms(&path);
            println!("  identity: relay key generated + persisted ({path}) — PeerId is stable");
        }
        Err(err) => eprintln!(
            "  identity: could not persist relay key ({err}); the PeerId will change on restart"
        ),
    }
    secret
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
