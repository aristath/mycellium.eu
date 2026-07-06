//! The Mycellium directory server binary.
//!
//! An **untrusted rendezvous**: it stores wallet-signed records and presence
//! and answers lookups (the queue, a separate service, stores the opaque message
//! blobs). It holds no keys of its own and can read no message content — the
//! worst it can do is withhold or serve a stale record.
//!
//! Kept dependency-lean on purpose (no arg-parsing crate). Runtime configuration
//! comes from `--config PATH`, or from explicit `--dev` mode for local work.

use std::process::exit;

use serde::Deserialize;

const DEFAULT_ADDR: &str = "127.0.0.1:8080";

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
                eprintln!("mycellium-server: {err}");
                exit(2);
            }
        },
        None if args.dev => (
            DEFAULT_ADDR.to_string(),
            mycellium_directory::ServeConfig::dev(),
        ),
        None => {
            eprintln!("mycellium-server: pass --config PATH or --dev\n");
            print_help();
            exit(2);
        }
    };

    println!(
        "mycellium-server {} — hosting the directory on http://{addr}",
        env!("CARGO_PKG_VERSION")
    );
    println!("  routes: /health · /login/{{challenge,verify}} · /auth/{{start,confirm,status}} · /records/{{handle}} · /presence/{{handle}} · /metrics");
    println!("  untrusted: stores signed records + presence; holds no keys, reads no content");
    if let Err(err) = mycellium_directory::serve(&addr, config).await {
        eprintln!("mycellium-server failed: {err}");
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
                    println!("mycellium-server {}", env!("CARGO_PKG_VERSION"));
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
    dev_auth: Option<bool>,
    smtp: Option<SmtpFileConfig>,
    tls: Option<TlsFileConfig>,
    access_log: Option<bool>,
}

#[derive(Deserialize)]
struct SmtpFileConfig {
    host: String,
    port: Option<u16>,
    from: String,
    user: Option<String>,
    pass: Option<String>,
}

#[derive(Deserialize)]
struct TlsFileConfig {
    cert: String,
    key: String,
}

fn load_config(path: &str) -> Result<(String, mycellium_directory::ServeConfig), String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let file: FileConfig =
        serde_json::from_str(&raw).map_err(|e| format!("cannot parse {path}: {e}"))?;
    let auth = match (file.dev_auth.unwrap_or(false), file.smtp) {
        (true, None) => mycellium_directory::AuthConfig::Dev,
        (false, Some(smtp)) => {
            mycellium_directory::AuthConfig::Smtp(mycellium_directory::SmtpConfig {
                host: smtp.host,
                port: smtp.port.unwrap_or(587),
                from: smtp.from,
                user: smtp.user,
                pass: smtp.pass,
            })
        }
        (true, Some(_)) => return Err("choose either dev_auth=true or smtp, not both".into()),
        (false, None) => return Err("directory config needs dev_auth=true or smtp".into()),
    };
    let http = mycellium_serve::HttpConfig {
        tls: file.tls.map(|tls| mycellium_serve::TlsConfig {
            cert_path: tls.cert,
            key_path: tls.key,
        }),
        access_log: file.access_log.unwrap_or(false),
    };
    Ok((
        file.addr.unwrap_or_else(|| DEFAULT_ADDR.to_string()),
        mycellium_directory::ServeConfig {
            data_dir: file.data_dir,
            auth,
            http,
        },
    ))
}

fn print_help() {
    println!("mycellium-server — the Mycellium rendezvous (directory) server\n");
    println!("USAGE:");
    println!("    mycellium-server --dev");
    println!("    mycellium-server --config PATH\n");
    println!("Config is JSON. Example:");
    println!(
        r#"{{
  "addr": "127.0.0.1:8080",
  "data_dir": "./data/directory",
  "dev_auth": true,
  "access_log": false
}}"#
    );
}
