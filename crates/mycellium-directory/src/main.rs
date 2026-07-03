//! The Mycellium directory server binary.
//!
//! An **untrusted rendezvous**: it stores wallet-signed records and opaque
//! mailbox blobs and answers lookups. It holds no keys of its own and can read
//! no message content — the worst it can do is withhold or serve a stale record.
//!
//! Kept dependency-lean on purpose (no arg-parsing crate): the address comes
//! from `--addr`, else `MYCELLIUM_DIRECTORY_ADDR`, else the default.

use std::process::exit;

const DEFAULT_ADDR: &str = "127.0.0.1:8080";

fn main() {
    let addr = resolve_addr();
    println!("mycellium-directory {} — listening on http://{addr}", env!("CARGO_PKG_VERSION"));
    println!("  routes: /health · /login/{{challenge,verify}} · /records/{{handle}} · /mailbox/{{handle}}/{{slot}} · /presence/{{handle}}");
    println!("  untrusted: stores signed records + opaque blobs; holds no keys, reads no content");
    if let Err(err) = mycellium_directory::serve(&addr) {
        eprintln!("mycellium-directory failed: {err}");
        exit(1);
    }
}

/// Resolve the bind address: `--addr HOST:PORT`, then the env var, then default.
fn resolve_addr() -> String {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => {
                return args.next().unwrap_or_else(|| {
                    eprintln!("--addr requires a HOST:PORT value");
                    exit(2);
                })
            }
            "--help" | "-h" => {
                print_help();
                exit(0);
            }
            "--version" | "-V" => {
                println!("mycellium-directory {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}\n");
                print_help();
                exit(2);
            }
        }
    }
    std::env::var("MYCELLIUM_DIRECTORY_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.into())
}

fn print_help() {
    println!("mycellium-directory — the Mycellium rendezvous server\n");
    println!("USAGE:");
    println!("    mycellium-directory [--addr HOST:PORT]\n");
    println!("The bind address may also be set via MYCELLIUM_DIRECTORY_ADDR");
    println!("(default: {DEFAULT_ADDR}).");
}
