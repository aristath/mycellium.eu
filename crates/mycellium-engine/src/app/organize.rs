#![allow(clippy::too_many_arguments)]
use super::*;

pub fn draft_cmd(peer: &str, text: Option<&str>) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = contacts::resolve(&fs, peer)?;
    match text {
        Some(t) => {
            draft::set(&mut fs, &key, t)?;
            println!("draft saved for '{key}'");
        }
        None => match draft::get(&fs, &key)? {
            Some(d) => println!("draft for '{key}': {d}"),
            None => println!("no draft for '{key}'"),
        },
    }
    Ok(())
}

pub fn draft_clear(peer: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = contacts::resolve(&fs, peer)?;
    draft::clear(&mut fs, &key)?;
    println!("cleared draft for '{key}'");
    Ok(())
}

/// Resolve an expiry target (a peer nickname/handle, or a group id) to its store key.
pub fn expire_key(fs: &FileStore, target: &str) -> Result<String> {
    // A group id resolves to itself; otherwise treat as a peer handle/nickname.
    if groups::load(fs, target)?.is_some() {
        Ok(target.to_string())
    } else {
        Ok(contacts::resolve(fs, target)?)
    }
}

pub fn expire_set(target: &str, duration: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let secs = parse_duration(duration)?;
    let mut fs = open_history(&identity)?;
    let key = expire_key(&fs, target)?;
    expiry::set(&mut fs, &key, secs)?;
    println!("messages to '{key}' now disappear after {duration}");
    Ok(())
}

pub fn expire_clear(target: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = expire_key(&fs, target)?;
    expiry::clear(&mut fs, &key)?;
    println!("cleared disappearing-message timer for '{key}'");
    Ok(())
}

pub fn expire_show(target: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let key = expire_key(&fs, target)?;
    match expiry::get(&fs, &key)? {
        Some(secs) => println!("'{key}': messages disappear after {secs}s"),
        None => println!("'{key}': no disappearing-message timer"),
    }
    Ok(())
}

pub fn set_blocked(handle: &str, blocked: bool) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    if blocked {
        blocklist::block(&mut fs, handle)?;
        println!("blocked '{handle}'");
    } else {
        blocklist::unblock(&mut fs, handle)?;
        println!("unblocked '{handle}'");
    }
    Ok(())
}

pub fn list_blocked() -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let list = blocklist::load(&fs)?;
    if list.is_empty() {
        println!("no blocked handles");
        return Ok(());
    }
    for h in list {
        println!("{h}");
    }
    Ok(())
}

pub fn contact_add(nickname: &str, handle: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let client = DirectoryClient::new(directory);
    let record = client.lookup(&handle)?;
    record
        .verify()
        .map_err(|_| anyhow!("that handle's record failed verification"))?;

    let mut fs = open_history(&identity)?;
    let contact = Contact {
        nickname: nickname.to_string(),
        handle: handle.as_str().to_string(),
        wallet: record.record.wallet,
    };
    contacts::save(&mut fs, &contact)?;
    println!("added '{}' → {}", nickname, handle.as_str());
    Ok(())
}

pub fn contact_list() -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let list = contacts::list(&fs)?;
    if list.is_empty() {
        println!("no contacts");
        return Ok(());
    }
    for c in list {
        println!("{} → {}", c.nickname, c.handle);
    }
    Ok(())
}

pub fn contact_remove(nickname: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    contacts::remove(&mut fs, nickname)?;
    println!("removed '{nickname}'");
    Ok(())
}

pub fn clear_history(peer: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let key = contacts::resolve(&fs, peer)?;
    history::clear(&mut fs, &key)?;
    println!("cleared history with '{key}'");
    Ok(())
}

pub fn conversations() -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let now = OsPlatform.now_unix_secs();
    let mut any = false;

    for peer in history::peers(&fs)? {
        let msgs = history::load_active(&mut fs, &peer, now)?;
        if let Some(last) = msgs.last() {
            let who = if last.from_me { "you" } else { peer.as_str() };
            println!("{peer:16} {who}: {}", preview(&last.text));
            any = true;
        }
    }
    for id in groups::list(&fs)? {
        if let Some(g) = groups::load(&fs, &id)? {
            let msgs = history::group_load_active(&mut fs, &id, now)?;
            let last = msgs
                .last()
                .map(|m| format!("{}: {}", m.sender, preview(&m.text)))
                .unwrap_or_else(|| "(no messages)".to_string());
            println!("[group {}] {last}", g.name);
            any = true;
        }
    }
    if !any {
        println!("no conversations yet");
    }
    Ok(())
}

pub fn search(query: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let now = OsPlatform.now_unix_secs();
    let needle = query.to_lowercase();
    let mut hits = 0usize;

    // One-to-one transcripts.
    for peer in history::peers(&fs)? {
        for m in history::load_active(&mut fs, &peer, now)? {
            if m.text.to_lowercase().contains(&needle) {
                let who = if m.from_me { "you" } else { peer.as_str() };
                println!("[{peer}] {who}: {}", m.text);
                hits += 1;
            }
        }
    }

    // Group transcripts.
    for id in groups::list(&fs)? {
        let name = groups::load(&fs, &id)?
            .map(|g| g.name)
            .unwrap_or_else(|| id.clone());
        for m in history::group_load_active(&mut fs, &id, now)? {
            if m.text.to_lowercase().contains(&needle) {
                println!("[group {name}] {}: {}", m.sender, m.text);
                hits += 1;
            }
        }
    }

    if hits == 0 {
        println!("no matches for '{query}'");
    } else {
        println!("\n{hits} match(es)");
    }
    Ok(())
}

pub fn show_history(peer: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let peer_handle = Handle::new(peer).map_err(|_| anyhow!("invalid peer handle"))?;
    let mut fs = open_history(&identity)?;
    let now = OsPlatform.now_unix_secs();
    let transcript = history::load_active(&mut fs, peer_handle.as_str(), now)
        .map_err(|e| anyhow!("read history: {e}"))?;
    if transcript.is_empty() {
        println!("no stored history with '{peer}'");
        return Ok(());
    }
    for m in transcript {
        let who = if m.from_me { "you" } else { peer };
        println!("{who}: {}", m.text);
    }
    Ok(())
}
