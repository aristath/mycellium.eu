//! The Mycellium message-queue server binary.
//!
//! A per-recipient store-and-forward mailbox, decoupled from the directory. It
//! holds opaque, end-to-end-encrypted blobs keyed by the recipient's wallet and
//! hands them back only to that wallet. Run one yourself, or point your record
//! at a provider's — it can read nothing either way.

use std::process::exit;

use serde::Deserialize;

const DEFAULT_ADDR: &str = "127.0.0.1:8090";

#[tokio::main]
async fn main() {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}\n");
            print_help();
            exit(2);
        }
    };
    let (addr, config) = match args.config {
        Some(path) => match load_config(&path) {
            Ok(v) => v,
            Err(err) => {
                eprintln!("mycellium-queue: {err}");
                exit(2);
            }
        },
        None if args.dev => (
            DEFAULT_ADDR.to_string(),
            mycellium_queue::ServeConfig::dev(),
        ),
        None => {
            eprintln!("mycellium-queue: pass --config PATH or --dev\n");
            print_help();
            exit(2);
        }
    };

    println!(
        "mycellium-queue {} — store-and-forward on http://{addr}",
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "  routes: /health · /login/{{challenge,verify}} · /mailbox/{{wallet}}/{{slot}} · /push/* · /pair/{{rid}}"
    );
    println!("  holds opaque E2E blobs keyed by wallet; reads nothing");
    if let Err(err) = mycellium_queue::serve(&addr, config).await {
        eprintln!("mycellium-queue failed: {err}");
        exit(1);
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
                    println!("mycellium-queue {}", env!("CARGO_PKG_VERSION"));
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

#[derive(Deserialize)]
struct FileConfig {
    addr: Option<String>,
    data_dir: Option<String>,
    tls: Option<TlsFileConfig>,
    access_log: Option<bool>,
    push_allow_hosts: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct TlsFileConfig {
    cert: String,
    key: String,
}

fn load_config(path: &str) -> Result<(String, mycellium_queue::ServeConfig), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let file: FileConfig =
        serde_json::from_str(&raw).map_err(|e| format!("cannot parse {path}: {e}"))?;
    let http = mycellium_serve::HttpConfig {
        tls: file.tls.map(|tls| mycellium_serve::TlsConfig {
            cert_path: tls.cert,
            key_path: tls.key,
        }),
        access_log: file.access_log.unwrap_or(false),
    };
    Ok((
        file.addr.unwrap_or_else(|| DEFAULT_ADDR.to_string()),
        mycellium_queue::ServeConfig {
            data_dir: file.data_dir,
            http,
            push_allow_hosts: file.push_allow_hosts.unwrap_or_default(),
        },
    ))
}

fn print_help() {
    println!("mycellium-queue — the Mycellium message queue\n");
    println!("USAGE:");
    println!("    mycellium-queue --dev");
    println!("    mycellium-queue --config PATH\n");
    println!("Config is JSON. Example:");
    println!(
        r#"{{
  "addr": "127.0.0.1:8090",
  "data_dir": "./data/queue",
  "access_log": false,
  "push_allow_hosts": []
}}"#
    );
}
