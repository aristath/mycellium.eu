//! The JSON API: HTTP in, [`mycellium_engine`] calls out, structured state back.
//!
//! Reads pull straight from the engine's stores (contacts / history / groups);
//! actions call the engine's command functions (which persist into those same
//! stores), and the browser re-fetches. No protocol logic lives here.

use std::sync::Mutex;

use serde_json::{json, Value};
use tiny_http::Method;

use mycellium_core::identity::Identity;
use mycellium_engine::app;
use mycellium_engine::platform::OsPlatform;
use mycellium_engine::{contacts, groups, history};
use mycellium_core::platform::Platform;
use mycellium_storage::store;

use crate::State;

/// Route an `/api/...` request. Returns `(http_status, json_body)`.
pub fn dispatch(state: &Mutex<State>, method: &Method, path: &str, body: &str) -> (u16, String) {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let req = parse(body);
    let directory = state.lock().unwrap().directory.clone();

    // Session/auth endpoints are always reachable; everything else needs unlock.
    let open = matches!(
        (method, segs.as_slice()),
        (&Method::Get, ["status"])
            | (&Method::Post, ["identity"])
            | (&Method::Post, ["restore"])
            | (&Method::Post, ["unlock"])
    );
    if !open && !state.lock().unwrap().unlocked {
        return (401, err("locked — unlock or register first"));
    }

    let result: anyhow::Result<Value> = match (method, segs.as_slice()) {
        (&Method::Get, ["status"]) => status(state),
        (&Method::Post, ["identity"]) => create_identity(state, &req),
        (&Method::Post, ["restore"]) => restore(state, &req),
        (&Method::Post, ["unlock"]) => unlock(state, &req),
        (&Method::Post, ["lock"]) => lock(state),
        (&Method::Post, ["register"]) => register(&req, &directory),

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

// ---- session ----------------------------------------------------------------

fn status(state: &Mutex<State>) -> anyhow::Result<Value> {
    let unlocked = state.lock().unwrap().unlocked;
    let wallet = if unlocked {
        store::load_identity().ok().map(|id| hex(&id.wallet_public().0))
    } else {
        None
    };
    Ok(json!({
        "registered": store::exists(),
        "unlocked": unlocked,
        "handle": read_handle(),
        "wallet": wallet,
        "directory": state.lock().unwrap().directory,
        "queue": std::env::var("MYCELLIUM_QUEUE").unwrap_or_default(),
    }))
}

fn create_identity(state: &Mutex<State>, req: &Value) -> anyhow::Result<Value> {
    let pass = field(req, "passphrase").ok_or_else(|| anyhow::anyhow!("passphrase required"))?;
    if store::exists() {
        anyhow::bail!("an identity already exists — unlock it instead");
    }
    std::env::set_var("MYCELLIUM_PASSPHRASE", pass);
    let identity = Identity::generate(&mut OsPlatform)?;
    store::save_identity(&identity)?;
    state.lock().unwrap().unlocked = true;
    Ok(json!({ "mnemonic": identity.mnemonic(), "wallet": hex(&identity.wallet_public().0) }))
}

fn restore(state: &Mutex<State>, req: &Value) -> anyhow::Result<Value> {
    let phrase = field(req, "phrase").ok_or_else(|| anyhow::anyhow!("phrase required"))?;
    let pass = field(req, "passphrase").ok_or_else(|| anyhow::anyhow!("passphrase required"))?;
    std::env::set_var("MYCELLIUM_PASSPHRASE", pass);
    let identity = Identity::from_phrase(phrase.trim(), &mut OsPlatform)
        .map_err(|_| anyhow::anyhow!("invalid seed phrase"))?;
    store::save_identity(&identity)?;
    state.lock().unwrap().unlocked = true;
    Ok(json!({ "wallet": hex(&identity.wallet_public().0) }))
}

fn unlock(state: &Mutex<State>, req: &Value) -> anyhow::Result<Value> {
    let pass = field(req, "passphrase").ok_or_else(|| anyhow::anyhow!("passphrase required"))?;
    std::env::set_var("MYCELLIUM_PASSPHRASE", pass);
    let identity = store::load_identity().map_err(|_| anyhow::anyhow!("wrong passphrase or no identity"))?;
    state.lock().unwrap().unlocked = true;
    Ok(json!({ "wallet": hex(&identity.wallet_public().0), "handle": read_handle() }))
}

fn lock(state: &Mutex<State>) -> anyhow::Result<Value> {
    std::env::remove_var("MYCELLIUM_PASSPHRASE");
    state.lock().unwrap().unlocked = false;
    Ok(json!({ "ok": true }))
}

fn register(req: &Value, directory: &str) -> anyhow::Result<Value> {
    let handle = field(req, "handle").ok_or_else(|| anyhow::anyhow!("handle required"))?;
    // A polling client isn't reachable for live push (empty addr) — delivery to
    // it flows through its queue.
    app::register(handle, "", false, directory)?;
    write_handle(handle)?;
    Ok(json!({ "handle": handle }))
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
