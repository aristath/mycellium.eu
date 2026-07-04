//! The JSON API: HTTP in, [`mycellium_engine`] calls out, structured state back.
//!
//! Reads pull straight from the engine's stores (contacts / history / groups);
//! actions call the engine's command functions (which persist into those same
//! stores), and the browser re-fetches. No protocol logic lives here.

use std::sync::Mutex;

use serde_json::{json, Value};
use tiny_http::Method;

use mycellium_core::identity::{Handle, Identity};
use mycellium_core::platform::Platform;
use mycellium_core::userid::user_id;
use mycellium_directory_client::DirectoryClient;
use mycellium_queue_client::QueueClient;
use mycellium_engine::app;
use mycellium_engine::platform::OsPlatform;
use mycellium_engine::{contacts, groups, history, names};
use mycellium_storage::store;

use crate::State;

/// Route an `/api/...` request. Returns `(http_status, json_body)`.
pub fn dispatch(state: &Mutex<State>, method: &Method, path: &str, body: &str) -> (u16, String) {
    // Percent-decode each segment — a browser sends emails as e.g. `a%40b.com`.
    let owned: Vec<String> = path.split('/').filter(|s| !s.is_empty()).map(percent_decode).collect();
    let segs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let req = parse(body);
    let directory = state.lock().unwrap().directory.clone();

    // Status + onboarding are always reachable; everything else needs a claimed
    // handle (a finished account).
    let open = matches!(
        (method, segs.as_slice()),
        (&Method::Get, ["status"])
            | (&Method::Get, ["push", "key"])
            | (&Method::Post, ["signup"])
            | (&Method::Post, ["signup", "confirm"])
            | (&Method::Post, ["signup", "status"])
    );
    if !open && read_handle().is_none() {
        return (401, err("no account yet — sign up first"));
    }

    let result: anyhow::Result<Value> = match (method, segs.as_slice()) {
        (&Method::Get, ["status"]) => status(&directory),
        (&Method::Post, ["signup"]) => signup(state, &req, &directory),
        (&Method::Post, ["signup", "confirm"]) => signup_confirm(state, &req, &directory),
        (&Method::Post, ["signup", "status"]) => signup_status(state, &req, &directory),

        (&Method::Get, ["contacts"]) => contacts_list(),
        (&Method::Post, ["contacts"]) => contacts_add(&req, &directory),
        (&Method::Delete, ["contacts", nick]) => contacts_remove(nick),

        (&Method::Get, ["threads"]) => threads_list(),
        (&Method::Get, ["threads", peer]) => thread_load(peer, &directory),
        (&Method::Post, ["threads", peer]) => thread_send(peer, &req, &directory),

        (&Method::Get, ["groups"]) => groups_list(),
        (&Method::Post, ["groups"]) => group_create(&req, &directory),
        (&Method::Get, ["groups", id]) => group_load(id),
        (&Method::Post, ["groups", id]) => group_send(id, &req, &directory),

        (&Method::Post, ["sync"]) => sync(&directory),

        (&Method::Get, ["push", "key"]) => push_key(),
        (&Method::Post, ["push"]) => push_register(&req),

        _ => return (404, err("no such endpoint")),
    };

    match result {
        Ok(value) => (200, value.to_string()),
        Err(e) => (400, err(&e.to_string())),
    }
}

// ---- session / onboarding ---------------------------------------------------

/// Load the silent device identity, creating it on first use. No password or
/// seed: it's encrypted at rest with the per-device key `main` sets.
fn ensure_identity() -> anyhow::Result<Identity> {
    if store::exists() {
        store::load_identity().map_err(|_| anyhow::anyhow!("could not open the local identity"))
    } else {
        let identity = Identity::generate(&mut OsPlatform)?;
        store::save_identity(&identity)?;
        Ok(identity)
    }
}

fn status(directory: &str) -> anyhow::Result<Value> {
    let queue = std::env::var("MYCELLIUM_QUEUE").unwrap_or_default();
    let wallet = store::load_identity().ok().map(|id| hex(&id.wallet_public().0));
    Ok(json!({
        // The account exists once `handle` (= the id) is set. `name` is the
        // free-form display name; the UI shows the name, routes on the handle.
        "handle": read_handle(),
        "name": read_name(),
        "email": read_email(),
        "wallet": wallet,
        "directory": directory,
        "queue": queue,
        "directory_ok": reachable(directory),
        "queue_ok": reachable(&queue),
    }))
}

/// Step 1: silently ensure an identity, then start an email-verified claim.
/// **Identity = `user_id(email)`**; the display name is stored locally and the
/// directory only ever sees the hashed id + a hashed recovery email.
fn signup(state: &Mutex<State>, req: &Value, directory: &str) -> anyhow::Result<Value> {
    let name = field(req, "name").ok_or_else(|| anyhow::anyhow!("enter a display name"))?;
    let email = field(req, "email").ok_or_else(|| anyhow::anyhow!("enter an email"))?;
    if !email.contains('@') {
        anyhow::bail!("enter a valid email");
    }
    if !reachable(directory) {
        anyhow::bail!(
            "Can't reach the directory at {directory}. Start it first:  cargo run -p mycellium-server -- --addr 127.0.0.1:8080"
        );
    }
    let identity = ensure_identity()?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    // The id we thread everywhere is user_id(email) — the email never enters the
    // engine or envelopes; only the id (a hash) and the code-send do.
    let uid = user_id(email).as_str().to_string();
    let (pending, dev_code) = client.auth_start(&token, &uid, email)?;
    save_name(name)?;
    save_email(email)?; // your own email, so the app can show "add me by …"
    // Remember both the id (to publish) and the name for this pending signup.
    state.lock().unwrap().pending.insert(pending.clone(), uid);
    Ok(json!({ "pending": pending, "dev_code": dev_code }))
}

/// Step 2 (code path): confirm the emailed code and finish setup.
fn signup_confirm(state: &Mutex<State>, req: &Value, directory: &str) -> anyhow::Result<Value> {
    let pending = field(req, "pending").ok_or_else(|| anyhow::anyhow!("missing pending token"))?;
    let code = field(req, "code").ok_or_else(|| anyhow::anyhow!("enter the code"))?;
    let uid = state
        .lock()
        .unwrap()
        .pending
        .get(pending)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("signup expired — start again"))?;
    let client = DirectoryClient::new(directory);
    client.auth_confirm(pending, code)?;
    finalize(&client, &uid)?;
    Ok(json!({ "handle": uid, "name": read_name() }))
}

/// Step 2 (link path): poll whether the one-tap link was clicked; finish if so.
fn signup_status(state: &Mutex<State>, req: &Value, directory: &str) -> anyhow::Result<Value> {
    let pending = field(req, "pending").ok_or_else(|| anyhow::anyhow!("missing pending token"))?;
    let client = DirectoryClient::new(directory);
    let (verified, _) = client.auth_status(pending)?;
    if verified && read_handle().is_none() {
        if let Some(uid) = state.lock().unwrap().pending.get(pending).cloned() {
            finalize(&client, &uid)?;
        }
    }
    Ok(json!({ "verified": verified, "handle": read_handle() }))
}

/// Publish our record under the verified id and remember it locally.
fn finalize(client: &DirectoryClient, uid: &str) -> anyhow::Result<()> {
    let identity = ensure_identity()?;
    let handle = Handle::new(uid).map_err(|_| anyhow::anyhow!("invalid id"))?;
    let token = client.login(&identity)?;
    // Empty addr: a polling client isn't reachable for live push, so mail flows
    // through its queue. The record's name comes from MYCELLIUM_NAME (set above).
    let record = app::build_record(&identity, &handle, "");
    client.publish(&token, &handle, &record)?;
    write_handle(uid)?;
    Ok(())
}

// ---- contacts ---------------------------------------------------------------

fn contacts_list() -> anyhow::Result<Value> {
    let fs = open()?;
    let list: Vec<Value> = contacts::list(&fs)?
        .into_iter()
        .map(|c| json!({ "nickname": c.nickname, "handle": c.handle, "wallet": hex(&c.wallet.0) }))
        .collect();
    Ok(Value::Array(list))
}

/// Add a contact by their **email** — we hash it to their id, pin their record.
fn contacts_add(req: &Value, directory: &str) -> anyhow::Result<Value> {
    let email = field(req, "email").ok_or_else(|| anyhow::anyhow!("enter their email"))?;
    let nickname = field(req, "nickname").unwrap_or(email);
    let uid = to_uid(email);
    app::contact_add(nickname, &uid, directory)?;
    Ok(json!({ "ok": true }))
}

fn contacts_remove(nick: &str) -> anyhow::Result<Value> {
    app::contact_remove(nick)?;
    Ok(json!({ "ok": true }))
}

// ---- threads (1:1) ----------------------------------------------------------

fn threads_list() -> anyhow::Result<Value> {
    let mut fs = open()?;
    let now = OsPlatform.now_unix_secs();
    // Map each peer id to a saved contact nickname (highest-priority display).
    let contact_names: std::collections::HashMap<String, String> = contacts::list(&fs)?
        .into_iter()
        .map(|c| (c.handle, c.nickname))
        .collect();
    let mut threads: Vec<Value> = Vec::new();
    for peer in history::peers(&fs)? {
        let msgs = history::load_active(&mut fs, &peer, now)?;
        let last = msgs.last();
        // Display: saved contact nickname → learned self-set name → short id.
        let display = contact_names
            .get(&peer)
            .cloned()
            .or_else(|| names::get(&fs, &peer).ok().flatten())
            .unwrap_or_else(|| short(&peer));
        threads.push(json!({
            "peer": peer,
            "name": display,
            "last": last.map(|m| m.text.clone()).unwrap_or_default(),
            "timestamp": last.map(|m| m.timestamp).unwrap_or(0),
            "mine": last.map(|m| m.from_me).unwrap_or(false),
            "count": msgs.len(),
        }));
    }
    Ok(Value::Array(threads))
}

fn thread_load(peer: &str, directory: &str) -> anyhow::Result<Value> {
    let uid = to_uid(peer);
    // Draining the queue may need the peer resolvable; harmless if offline.
    let _ = directory;
    let mut fs = open()?;
    let now = OsPlatform.now_unix_secs();
    let msgs: Vec<Value> = history::load_active(&mut fs, &uid, now)?
        .into_iter()
        .map(|m| json!({ "id": m.id, "from_me": m.from_me, "text": m.text, "timestamp": m.timestamp }))
        .collect();
    Ok(Value::Array(msgs))
}

fn thread_send(peer: &str, req: &Value, directory: &str) -> anyhow::Result<Value> {
    let me = read_handle().ok_or_else(|| anyhow::anyhow!("finish signing up first"))?;
    // A plain message, a reply (message + reply_to), a reaction (react + to), or
    // a deletion (delete) — the engine's build_message picks by which are set.
    let message = field(req, "message");
    let reply_to = field(req, "reply_to");
    let react = field(req, "react");
    let target = field(req, "to");
    let delete = field(req, "delete");
    // Optional attachment: base64 bytes written to a temp file the engine reads.
    let attachment = save_upload(req)?;
    let file = attachment.as_ref().map(|p| p.to_string_lossy().to_string());
    let result = app::send(
        &to_uid(peer), &me, message, reply_to, react, target, file.as_deref(), None, delete, None, directory,
    );
    if let Some(path) = &attachment {
        let _ = std::fs::remove_file(path);
    }
    result?;
    Ok(json!({ "ok": true }))
}

// ---- groups -----------------------------------------------------------------

fn groups_list() -> anyhow::Result<Value> {
    let fs = open()?;
    let mut out: Vec<Value> = Vec::new();
    for id in groups::list(&fs)? {
        if let Some(g) = groups::load(&fs, &id)? {
            out.push(json!({ "id": g.id, "name": g.name, "members": g.members }));
        }
    }
    Ok(Value::Array(out))
}

fn group_create(req: &Value, directory: &str) -> anyhow::Result<Value> {
    let name = field(req, "name").ok_or_else(|| anyhow::anyhow!("name required"))?;
    // Members are given by email; hash each to its id.
    let members: Vec<String> = req
        .get("members")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).map(to_uid).collect())
        .unwrap_or_default();
    let me = read_handle().ok_or_else(|| anyhow::anyhow!("register a handle first"))?;
    app::group_create(name, &members, &me, directory)?;
    Ok(json!({ "ok": true }))
}

fn group_load(id: &str) -> anyhow::Result<Value> {
    let mut fs = open()?;
    let me = read_handle().unwrap_or_default();
    let now = OsPlatform.now_unix_secs();
    let msgs: Vec<Value> = history::group_load_active(&mut fs, id, now)?
        .into_iter()
        .map(|m| json!({ "id": m.id, "sender": m.sender, "text": m.text, "timestamp": m.timestamp, "mine": m.sender == me }))
        .collect();
    Ok(Value::Array(msgs))
}

fn group_send(id: &str, req: &Value, directory: &str) -> anyhow::Result<Value> {
    let message = field(req, "message").ok_or_else(|| anyhow::anyhow!("message required"))?;
    let me = read_handle().ok_or_else(|| anyhow::anyhow!("register a handle first"))?;
    app::group_send(id, &me, Some(message), None, None, None, None, None, None, None, directory)?;
    Ok(json!({ "ok": true }))
}

// ---- push -------------------------------------------------------------------

fn queue_url() -> String {
    std::env::var("MYCELLIUM_QUEUE").unwrap_or_default()
}

/// The queue's VAPID public key, for the browser's push subscription.
fn push_key() -> anyhow::Result<Value> {
    let url = queue_url();
    if url.is_empty() {
        return Ok(json!({ "key": Value::Null }));
    }
    let key = QueueClient::new(&url).push_key()?;
    Ok(json!({ "key": key }))
}

/// Register the browser's push endpoint with our queue (keyed by our wallet).
fn push_register(req: &Value) -> anyhow::Result<Value> {
    let endpoint = field(req, "endpoint").ok_or_else(|| anyhow::anyhow!("endpoint required"))?;
    let url = queue_url();
    if url.is_empty() {
        anyhow::bail!("no queue configured");
    }
    let identity = ensure_identity()?;
    let client = QueueClient::new(&url);
    let token = client.login(&identity)?;
    client.push_subscribe(&token, endpoint)?;
    Ok(json!({ "ok": true }))
}

// ---- sync -------------------------------------------------------------------

/// Drain our queue into local history (1:1 and groups). The browser then refetches.
fn sync(directory: &str) -> anyhow::Result<Value> {
    let me = read_handle().ok_or_else(|| anyhow::anyhow!("register a handle first"))?;
    // Best-effort: don't fail the whole sync if one leg errors.
    let _ = app::inbox(&me, directory);
    let _ = app::group_sync(&me, directory);
    Ok(json!({ "ok": true }))
}

// ---- helpers ----------------------------------------------------------------

fn open() -> anyhow::Result<mycellium_storage::filestore::FileStore> {
    let identity = store::load_identity().map_err(|_| anyhow::anyhow!("locked"))?;
    app::open_history(&identity)
}

fn parse(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or(Value::Null)
}

fn field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str()).filter(|s| !s.is_empty())
}

fn err(msg: &str) -> String {
    json!({ "error": msg }).to_string()
}

/// Is a service URL currently accepting connections? A quick TCP probe so the
/// UI can say "the directory isn't running" instead of failing mid-action.
fn reachable(url: &str) -> bool {
    match socket_addr(url) {
        Some(addr) => {
            std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(600)).is_ok()
        }
        None => false,
    }
}

fn socket_addr(url: &str) -> Option<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    let hostport = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()?;
    hostport.to_socket_addrs().ok()?.next()
}

/// Minimal percent-decoding for URL path segments (enough for emails: `%40` etc.).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A short, readable stand-in for an unknown id (no contact name yet).
fn short(id: &str) -> String {
    format!("user-{}", &id[..6.min(id.len())])
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

fn handle_path() -> std::path::PathBuf {
    store::data_dir().join("handle")
}

fn read_handle() -> Option<String> {
    std::fs::read_to_string(handle_path()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn name_path() -> std::path::PathBuf {
    store::data_dir().join("name")
}

fn read_name() -> Option<String> {
    std::fs::read_to_string(name_path()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Persist our display name and make it live immediately (the engine reads it
/// from `MYCELLIUM_NAME` when building our record).
fn save_name(name: &str) -> anyhow::Result<()> {
    let path = name_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, name)?;
    std::env::set_var("MYCELLIUM_NAME", name);
    Ok(())
}

/// If the request carries an attachment (`file_name` + base64 `file_data`),
/// decode it to a temp file and return its path for the engine to inline.
fn save_upload(req: &Value) -> anyhow::Result<Option<std::path::PathBuf>> {
    use base64::Engine;
    let (Some(name), Some(data)) = (field(req, "file_name"), field(req, "file_data")) else {
        return Ok(None);
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|_| anyhow::anyhow!("could not decode the attachment"))?;
    let base = std::path::Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("file");
    let dir = store::data_dir().join("uploads");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(base);
    std::fs::write(&path, &bytes)?;
    Ok(Some(path))
}

fn email_path() -> std::path::PathBuf {
    store::data_dir().join("email")
}

fn read_email() -> Option<String> {
    std::fs::read_to_string(email_path()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn save_email(email: &str) -> anyhow::Result<()> {
    let path = email_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, email)?;
    Ok(())
}

/// Resolve a user-supplied peer reference to an id. An email becomes
/// `user_id(email)`; anything else is assumed to already be an id.
fn to_uid(peer: &str) -> String {
    if peer.contains('@') {
        user_id(peer).as_str().to_string()
    } else {
        peer.to_string()
    }
}

fn write_handle(handle: &str) -> anyhow::Result<()> {
    let path = handle_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, handle)?;
    Ok(())
}
