//! The Mycellium local client: a Rust binary that embeds a web server and serves
//! a browser PWA over the headless [`mycellium_engine`].
//!
//! It runs on your machine, binds to `127.0.0.1` only, and is a thin face over
//! the engine: HTTP/JSON in, engine calls out, structured state back. "Login"
//! unlocks your on-disk identity with your passphrase; "register" creates it and
//! claims a handle. All crypto and delivery live in the engine — this is UI.

mod api;
mod web;

use std::sync::Mutex;

use tiny_http::{Header, Method, Request, Response, Server};

/// Shared server state (the client is single-user: one identity per process).
pub struct State {
    /// Directory endpoint (names/records/presence + email-verified claims).
    pub directory: String,
    /// In-flight signups: pending token → the plaintext username. The directory
    /// only ever knows the hashed id, so the client keeps the name to finish.
    pub pending: std::collections::HashMap<String, String>,
}

const DEFAULT_DIRECTORY: &str = "http://127.0.0.1:8080";
const DEFAULT_QUEUE: &str = "http://127.0.0.1:8090";
const DEFAULT_PORT: u16 = 8800;

fn main() {
    let mut port = DEFAULT_PORT;
    let mut directory = env_or("MYCELLIUM_DIRECTORY", DEFAULT_DIRECTORY);
    let mut queue = env_or("MYCELLIUM_QUEUE", DEFAULT_QUEUE);
    let mut data_dir = default_data_dir();

    // Minimal arg parsing: --port, --directory, --queue, --data-dir, --help.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(port);
            }
            "--directory" => {
                i += 1;
                directory = args.get(i).cloned().unwrap_or(directory);
            }
            "--queue" => {
                i += 1;
                queue = args.get(i).cloned().unwrap_or(queue);
            }
            "--data-dir" => {
                i += 1;
                data_dir = args.get(i).cloned().unwrap_or(data_dir);
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    // The engine reads these from the environment; set them once for the process.
    std::env::set_var("MYCELLIUM_HOME", &data_dir);
    std::env::set_var("MYCELLIUM_QUEUE", &queue);
    // Passwordless: the identity is encrypted at rest with a random per-device
    // key kept in the data dir — no user password or seed phrase to manage.
    std::env::set_var("MYCELLIUM_PASSPHRASE", ensure_device_key(&data_dir));
    // The display name (set at signup) is what others see; the engine reads it
    // from MYCELLIUM_NAME when building our record.
    if let Ok(name) = std::fs::read_to_string(std::path::Path::new(&data_dir).join("name")) {
        if !name.trim().is_empty() {
            std::env::set_var("MYCELLIUM_NAME", name.trim());
        }
    }

    let state = Mutex::new(State {
        directory,
        pending: std::collections::HashMap::new(),
    });
    let addr = format!("127.0.0.1:{port}");
    let server = match Server::http(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("could not bind {addr}: {e}");
            std::process::exit(1);
        }
    };

    println!("Mycellium client on  http://{addr}");
    println!("  data:      {data_dir}");
    println!("  directory: {}", state.lock().unwrap().directory);
    println!(
        "  queue:     {}",
        std::env::var("MYCELLIUM_QUEUE").unwrap_or_default()
    );
    println!("Open the URL above in your browser.");

    for request in server.incoming_requests() {
        handle(&state, request);
    }
}

/// Route one request: static PWA assets, or the JSON API under `/api/`.
fn handle(state: &Mutex<State>, mut request: Request) {
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("").to_string();

    if let Some(rest) = path.strip_prefix("/api/") {
        let method = request.method().clone();
        let mut body = String::new();
        let _ = std::io::Read::read_to_string(request.as_reader(), &mut body);
        let (status, json) = api::dispatch(state, &method, rest, &body);
        let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
        let _ = request.respond(
            Response::from_string(json)
                .with_status_code(status)
                .with_header(header),
        );
        return;
    }

    // Static PWA assets (embedded).
    if *request.method() != Method::Get {
        let _ = request.respond(Response::from_string("method not allowed").with_status_code(405));
        return;
    }
    let asset_path = if path == "/" {
        "/index.html"
    } else {
        path.as_str()
    };
    match web::asset(asset_path) {
        Some((bytes, mime)) => {
            let header = Header::from_bytes(&b"Content-Type"[..], mime.as_bytes()).unwrap();
            let _ = request.respond(Response::from_data(bytes).with_header(header));
        }
        None => {
            let _ = request.respond(Response::from_string("not found").with_status_code(404));
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// The per-device secret that encrypts the identity at rest. Generated once and
/// kept in the data dir — the user never sees or types it (no seed/password).
fn ensure_device_key(data_dir: &str) -> String {
    let path = std::path::Path::new(data_dir).join("device.key");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("OS RNG must be available");
    let key: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let _ = std::fs::create_dir_all(data_dir);
    let _ = std::fs::write(&path, &key);
    key
}

fn default_data_dir() -> String {
    if let Ok(home) = std::env::var("MYCELLIUM_HOME") {
        return home;
    }
    let base = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    format!("{base}/.mycellium")
}

fn print_help() {
    println!("mycellium-client — local web/PWA client for Mycellium\n");
    println!("USAGE:\n    mycellium-client [--port N] [--directory URL] [--queue URL] [--data-dir PATH]\n");
    println!(
        "Defaults: port {DEFAULT_PORT}, directory {DEFAULT_DIRECTORY}, queue {DEFAULT_QUEUE}."
    );
}
