//! The Mycellium message-queue server binary.
//!
//! A per-recipient store-and-forward mailbox, decoupled from the directory. It
//! holds opaque, end-to-end-encrypted blobs keyed by the recipient's wallet and
//! hands them back only to that wallet. Run one yourself, or point your record
//! at a provider's — it can read nothing either way.

use std::process::exit;

const DEFAULT_ADDR: &str = "127.0.0.1:8090";

#[tokio::main]
async fn main() {
    let addr = resolve_addr();
    println!(
        "mycellium-queue {} — store-and-forward on http://{addr}",
        env!("CARGO_PKG_VERSION")
    );
    println!("  routes: /health · /login/{{challenge,verify}} · /mailbox/{{wallet}}/{{slot}}");
    println!("  holds opaque E2E blobs keyed by wallet; reads nothing");
    if let Err(err) = mycellium_queue::serve(&addr).await {
        eprintln!("mycellium-queue failed: {err}");
        exit(1);
    }
}

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
                println!("mycellium-queue — the Mycellium message queue\n");
                println!("USAGE:\n    mycellium-queue [--addr HOST:PORT]\n");
                println!("Also settable via MYCELLIUM_QUEUE_ADDR (default: {DEFAULT_ADDR}).");
                exit(0);
            }
            "--version" | "-V" => {
                println!("mycellium-queue {}", env!("CARGO_PKG_VERSION"));
                exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                exit(2);
            }
        }
        i += 1;
    }
    addr.or_else(|| std::env::var("MYCELLIUM_QUEUE_ADDR").ok())
        .unwrap_or_else(|| DEFAULT_ADDR.into())
}
