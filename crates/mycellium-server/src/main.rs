//! The Mycellium directory server binary.
//!
//! An **untrusted rendezvous**: it stores wallet-signed records and presence
//! and answers lookups (the queue, a separate service, stores the opaque message
//! blobs). It holds no keys of its own and can read no message content — the
//! worst it can do is withhold or serve a stale record.
//!
//! Kept dependency-lean on purpose (no arg-parsing crate): the address comes
//! from `--addr`, else `MYCELLIUM_DIRECTORY_ADDR`, else the default.

use std::process::exit;

const DEFAULT_ADDR: &str = "127.0.0.1:8080";

fn main() {
    let addr = resolve_addr();
    println!(
        "mycellium-server {} — hosting the directory on http://{addr}",
        env!("CARGO_PKG_VERSION")
    );
    println!("  routes: /health · /login/{{challenge,verify}} · /auth/{{start,confirm,status}} · /records/{{handle}} · /presence/{{handle}} · /metrics");
    println!("  untrusted: stores signed records + presence; holds no keys, reads no content");
    if let Err(err) = mycellium_directory::serve(&addr) {
        eprintln!("mycellium-server failed: {err}");
        exit(1);
    }
}

/// Resolve the bind address: `--addr HOST:PORT`, then the env var, then default.
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
                println!("mycellium-server {}", env!("CARGO_PKG_VERSION"));
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
    addr.or_else(|| std::env::var("MYCELLIUM_DIRECTORY_ADDR").ok())
        .unwrap_or_else(|| DEFAULT_ADDR.into())
}

fn print_help() {
    println!("mycellium-server — the Mycellium rendezvous (directory) server\n");
    println!("USAGE:");
    println!("    mycellium-server [--addr HOST:PORT]\n");
    println!("The bind address may also be set via MYCELLIUM_DIRECTORY_ADDR");
    println!("(default: {DEFAULT_ADDR}).");
}
