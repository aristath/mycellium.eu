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
use mycellium_directory_client::DirectoryClient;
use mycellium_engine::app;
use mycellium_engine::platform::OsPlatform;
use mycellium_engine::{contacts, groups, history};
use mycellium_storage::store;

use crate::State;

/// Route an `/api/...` request. Returns `(http_status, json_body)`.
pub fn dispatch(state: &Mutex<State>, method: &Method, path: &str, body: &str) -> (u16, String) {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let req = parse(body);
    let directory = state.lock().unwrap().directory.clone();

    // Status + onboarding are always reachable; everything else needs a claimed
    // handle (a finished account).
    let open = matches!(
        (method, segs.as_slice()),
        (&Method::Get, ["status"])
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
        (&Method::Get, ["threads", peer]) => thread_load(peer),
        (&Method::Post, ["threads", peer]) => thread_send(peer, &req, &directory),

        (&Method::Get, ["groups"]) => groups_list(),
        (&Method::Post, ["groups"]) => group_create(&req, &directory),
        (&Method::Get, ["groups", id]) => group_load(id),
        (&Method::Post, ["groups", id]) => group_send(id, &req, &directory),

        (&Method::Post, ["sync"]) => sync(&directory),

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
        // `handle` is set only once the account is fully claimed (email verified
        // + record published) — the UI routes on it.
        "handle": read_handle(),
        "wallet": wallet,
        "directory": directory,
        "queue": queue,
        "directory_ok": reachable(directory),
        "queue_ok": reachable(&queue),
    }))
}

/// Step 1: silently ensure an identity, then start an email-verified claim.
/// The plaintext username is remembered locally, keyed by the pending token —
/// the directory only ever learns the hashed id.
fn signup(state: &Mutex<State>, req: &Value, directory: &str) -> anyhow::Result<Value> {
    let username = field(req, "username").ok_or_else(|| anyhow::anyhow!("pick a username"))?;
    let email = field(req, "email").ok_or_else(|| anyhow::anyhow!("enter an email"))?;
    Handle::new(username).map_err(|_| anyhow::anyhow!("usernames are lowercase letters, digits, or _"))?;
    if !reachable(directory) {
        anyhow::bail!(
            "Can't reach the directory at {directory}. Start it first:  cargo run -p mycellium-server -- --addr 127.0.0.1:8080"
        );
    }
    let identity = ensure_identity()?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let (pending, dev_code) = client.auth_start(&token, username, email)?;
    state.lock().unwrap().pending.insert(pending.clone(), username.to_string());
    Ok(json!({ "pending": pending, "dev_code": dev_code }))
}

/// Step 2 (code path): confirm the emailed code and finish setup.
fn signup_confirm(state: &Mutex<State>, req: &Value, directory: &str) -> anyhow::Result<Value> {
    let pending = field(req, "pending").ok_or_else(|| anyhow::anyhow!("missing pending token"))?;
    let code = field(req, "code").ok_or_else(|| anyhow::anyhow!("enter the code"))?;
    let username = state
        .lock()
        .unwrap()
        .pending
        .get(pending)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("signup expired — start again"))?;
    let client = DirectoryClient::new(directory);
    client.auth_confirm(pending, code)?;
    finalize(&client, &username)?;
    Ok(json!({ "handle": username }))
}

/// Step 2 (link path): poll whether the one-tap link was clicked; finish if so.
fn signup_status(state: &Mutex<State>, req: &Value, directory: &str) -> anyhow::Result<Value> {
    let pending = field(req, "pending").ok_or_else(|| anyhow::anyhow!("missing pending token"))?;
    let client = DirectoryClient::new(directory);
    let (verified, _) = client.auth_status(pending)?;
    if verified && read_handle().is_none() {
        if let Some(username) = state.lock().unwrap().pending.get(pending).cloned() {
            finalize(&client, &username)?;
        }
    }
    Ok(json!({ "verified": verified, "handle": read_handle() }))
}

/// Publish our record under the verified username and remember it locally.
fn finalize(client: &DirectoryClient, username: &str) -> anyhow::Result<()> {
    let identity = ensure_identity()?;
    let handle = Handle::new(username).map_err(|_| anyhow::anyhow!("invalid username"))?;
    let token = client.login(&identity)?;
    // Empty addr: a polling client isn't reachable for live push, so mail flows
    // through its queue (endpoint baked into the record from MYCELLIUM_QUEUE).
    let record = app::build_record(&identity, &handle, "");
    client.publish(&token, &handle, &record)?;
    write_handle(username)?;
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

fn contacts_add(req: &Value, directory: &str) -> anyhow::Result<Value> {
    let handle = field(req, "handle").ok_or_else(|| anyhow::anyhow!("handle required"))?;
    let nickname = field(req, "nickname").unwrap_or(handle);
    app::contact_add(nickname, handle, directory)?;
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
    let mut threads: Vec<Value> = Vec::new();
    for peer in history::peers(&fs)? {
        let msgs = history::load_active(&mut fs, &peer, now)?;
        let last = msgs.last();
        threads.push(json!({
            "peer": peer,
            "last": last.map(|m| m.text.clone()).unwrap_or_default(),
            "timestamp": last.map(|m| m.timestamp).unwrap_or(0),
            "count": msgs.len(),
        }));
    }
    Ok(Value::Array(threads))
}

fn thread_load(peer: &str) -> anyhow::Result<Value> {
    let mut fs = open()?;
    let now = OsPlatform.now_unix_secs();
    let msgs: Vec<Value> = history::load_active(&mut fs, peer, now)?
        .into_iter()
        .map(|m| json!({ "id": m.id, "from_me": m.from_me, "text": m.text, "timestamp": m.timestamp }))
        .collect();
    Ok(Value::Array(msgs))
}

fn thread_send(peer: &str, req: &Value, directory: &str) -> anyhow::Result<Value> {
    let message = field(req, "message").ok_or_else(|| anyhow::anyhow!("message required"))?;
    let me = read_handle().ok_or_else(|| anyhow::anyhow!("register a handle first"))?;
    app::send(peer, &me, Some(message), None, None, None, None, None, None, None, directory)?;
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
    let members: Vec<String> = req
        .get("members")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
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

fn write_handle(handle: &str) -> anyhow::Result<()> {
    let path = handle_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, handle)?;
    Ok(())
}
