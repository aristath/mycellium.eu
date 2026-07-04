#![allow(clippy::too_many_arguments)]
use super::*;

// ---- groups -----------------------------------------------------------------

/// Associated data binding a group message to its group.
pub use crate::wireops::group_ad;



pub fn group_create(name: &str, members: &[String], whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let mut fs = open_history(&identity)?;

    let mut id_bytes = [0u8; 8];
    getrandom::getrandom(&mut id_bytes).map_err(|_| anyhow!("RNG failure"))?;
    let group_id = hex(&id_bytes);

    // Membership is the given members plus ourselves.
    let mut all: Vec<String> = members.to_vec();
    if !all.iter().any(|m| m == me.as_str()) {
        all.push(me.as_str().to_string());
    }

    let mut platform = OsPlatform;
    let group = Group::new(&mut platform, my_group_id(&identity));
    let mut stored = StoredGroup {
        id: group_id.clone(),
        name: name.to_string(),
        members: all.clone(),
        me: me.as_str().to_string(),
        sender_handles: Vec::new(),
        state: group.export(),
    };
    stored.note_sender(my_group_id(&identity), me.as_str());
    groups::save(&mut fs, &stored)?;
    distribute_key(&identity, &me, &client, &stored, &group, &mut fs, OsPlatform.now_unix_secs());

    println!("created group '{name}' ({group_id}) with {} members", all.len());
    Ok(())
}



/// Send our sender-key distribution to every other member (over pairwise E2E).
pub fn distribute_key(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    stored: &StoredGroup,
    group: &Group,
    fs: &mut FileStore,
    now: u64,
) {
    // Every member, including our own handle — `distribute_key_to` skips only
    // this exact device, so our sibling devices still get our key (Layer 11).
    distribute_key_to(identity, me, client, stored, group, &stored.members, fs, now);
}



/// Send our sender-key distribution to a specific set of members. Any device we
/// can't reach live or via its queue is parked in the outbox for retry — so key
/// distribution (like group text) isn't silently lost on a transient failure.
#[allow(clippy::too_many_arguments)]
pub fn distribute_key_to(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    stored: &StoredGroup,
    group: &Group,
    targets: &[String],
    fs: &mut FileStore,
    now: u64,
) {
    let payload = GroupInvitePayload {
        group_id: stored.id.clone(),
        name: stored.name.clone(),
        members: stored.members.clone(),
        sender_id: my_group_id(identity),
        distribution: group.distribution(),
    };
    let plaintext = match serde_json::to_vec(&payload) {
        Ok(bytes) => bytes,
        Err(_) => return,
    };
    for member in targets {
        let handle = match Handle::new(member.clone()) {
            Ok(h) => h,
            Err(_) => continue,
        };
        let record = match client.lookup(&handle) {
            Ok(r) if r.verify().is_ok() => r,
            _ => {
                eprintln!("(could not reach '{member}')");
                continue;
            }
        };
        // Seal the sender key to every device in the member's cluster (Layer 11) —
        // including our *own* siblings, but never this device itself.
        let queue = QueueTarget::open(identity, &record.record);
        for device in &record.record.devices {
            if device.device_key == identity.device_public() {
                continue;
            }
            let env = seal_to(identity, me, device, &plaintext);
            let item = MailItem::GroupInvite(env);
            if !deliver(client, &handle, queue.as_ref(), device, &item) {
                let slot = device_slot(&device.device_key);
                let _ = outbox::enqueue(fs, random_id(), handle.as_str(), &slot, item, now);
            }
        }
    }
}



pub fn handle_group_invite(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    fs: &mut FileStore,
    platform: &mut OsPlatform,
    env: &Envelope,
) -> Result<()> {
    let (from, bytes) = open_envelope(identity, platform, env)?;
    let payload: GroupInvitePayload =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("malformed group invite"))?;
    // Senders are keyed by their device id (Layer 11), carried in the payload;
    // we remember which handle is behind it for display and block checks.
    let sender_id = payload.sender_id.clone();

    match groups::load(fs, &payload.group_id)? {
        Some(mut stored) => {
            // Already in the group — learn this member's sender key.
            let mut group = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
            group.add_member(sender_id.clone(), &payload.distribution).map_err(|_| anyhow!("bad sender key"))?;
            stored.note_sender(sender_id, from.as_str());

            // Learn any members we didn't know about, and send them our key.
            let newcomers: Vec<String> = payload
                .members
                .iter()
                .filter(|m| !stored.members.iter().any(|x| x == *m))
                .cloned()
                .collect();
            for m in &newcomers {
                stored.members.push(m.clone());
            }
            stored.state = group.export();
            groups::save(fs, &stored)?;
            if !newcomers.is_empty() {
                distribute_key_to(identity, me, client, &stored, &group, &newcomers, fs, OsPlatform.now_unix_secs());
            }
        }
        None => {
            // First time we hear of this group: join, and reply with our key.
            let mut own_platform = OsPlatform;
            let mut group = Group::new(&mut own_platform, my_group_id(identity));
            group.add_member(sender_id.clone(), &payload.distribution).map_err(|_| anyhow!("bad sender key"))?;
            let mut stored = StoredGroup {
                id: payload.group_id.clone(),
                name: payload.name.clone(),
                members: payload.members.clone(),
                me: me.as_str().to_string(),
                sender_handles: Vec::new(),
                state: group.export(),
            };
            stored.note_sender(sender_id, from.as_str());
            stored.note_sender(my_group_id(identity), me.as_str());
            groups::save(fs, &stored)?;
            println!("joined group '{}' (invited by {})", stored.name, from.as_str());
            distribute_key(identity, me, client, &stored, &group, fs, OsPlatform.now_unix_secs());
        }
    }
    Ok(())
}



pub fn handle_group_text(
    blocked: &[String],
    fs: &mut FileStore,
    group_id: &str,
    message: &GroupMessage,
) -> Result<()> {
    let mut stored = match groups::load(fs, group_id)? {
        Some(stored) => stored,
        None => {
            eprintln!("(group message for an unknown group)");
            return Ok(());
        }
    };
    // Map the device-keyed sender id back to a handle for display/block checks.
    let sender = stored
        .handle_of(&message.sender)
        .map(str::to_string)
        .unwrap_or_else(|| String::from_utf8_lossy(&message.sender).into_owned());
    if blocklist::is_blocked(blocked, &sender) {
        return Ok(()); // drop group messages from blocked members
    }
    let mut group = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    match group.decrypt(message, &group_ad(group_id)) {
        Ok(plaintext) => {
            // Advance/persist the ratchet state regardless.
            stored.state = group.export();
            groups::save(fs, &stored)?;

            let (id, display, expires_at) = match AppMessage::decode(&plaintext) {
                Ok(app) => {
                    match &app.body {
                        Body::Edit { to, text } => {
                            history::group_edit(fs, group_id, to, text)?;
                            println!("[{}] {sender}: edited #{to}", stored.name);
                            return Ok(());
                        }
                        Body::Delete { to } => {
                            history::group_delete(fs, group_id, to)?;
                            println!("[{}] {sender}: deleted #{to}", stored.name);
                            return Ok(());
                        }
                        _ => {}
                    }
                    if app.is_expired(OsPlatform.now_unix_secs()) {
                        return Ok(()); // already expired — drop
                    }
                    if let Some(path) = maybe_save_attachment(&app) {
                        println!("(saved attachment to {})", path.display());
                    }
                    (app.id.clone(), app.summary(), app.expires_at)
                }
                Err(_) => (String::new(), String::from_utf8_lossy(&plaintext).into_owned(), None),
            };
            println!("[{}] {sender}: {display}  (#{id})", stored.name);
            let entry = GroupStoredMessage {
                id: id.clone(),
                sender,
                text: display,
                timestamp: OsPlatform.now_unix_secs(),
                expires_at,
            };
            let _ = history::group_append(fs, group_id, entry);
        }
        Err(_) => eprintln!("(a group message could not be decrypted yet — missing that sender's key)"),
    }
    Ok(())
}



pub fn group_add(group: &str, member: &str, whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let mut fs = open_history(&identity)?;

    let mut stored = resolve_group(&fs, group)?;
    if stored.members.iter().any(|m| m == member) {
        bail!("'{member}' is already in '{}'", stored.name);
    }
    stored.members.push(member.to_string());
    groups::save(&mut fs, &stored)?;

    // Distribute our key with the updated roster: the newcomer joins, and
    // existing members learn the newcomer and send it their keys.
    let session = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    distribute_key(&identity, &me, &client, &stored, &session, &mut fs, OsPlatform.now_unix_secs());
    println!("invited '{member}' to '{}'", stored.name);
    Ok(())
}



pub fn group_remove(group: &str, member: &str, whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let mut fs = open_history(&identity)?;

    let mut stored = resolve_group(&fs, group)?;
    if !stored.members.iter().any(|m| m == member) {
        bail!("'{member}' is not in '{}'", stored.name);
    }
    stored.members.retain(|m| m != member);

    // Drop every device-sender of the removed handle, and re-key ourselves.
    let mut session = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    for (id, handle) in &stored.sender_handles {
        if handle == member {
            session.remove_member(id);
        }
    }
    stored.sender_handles.retain(|(_, h)| h != member);
    session.rotate(&mut OsPlatform);
    stored.state = session.export();
    groups::save(&mut fs, &stored)?;

    // Give the remaining members our fresh key, and tell them to re-key too.
    distribute_key(&identity, &me, &client, &stored, &session, &mut fs, OsPlatform.now_unix_secs());
    let control = MailItem::GroupRemove {
        group_id: stored.id.clone(),
        member: member.to_string(),
    };
    for m in &stored.members {
        if m == me.as_str() {
            continue;
        }
        if let Ok(handle) = Handle::new(m.clone()) {
            deliver_to_cluster_or_queue(&client, &identity, &handle, &control, &mut fs, OsPlatform.now_unix_secs());
        }
    }
    println!("removed '{member}' from '{}' (re-keyed)", stored.name);
    Ok(())
}



/// React to a removal: drop the member, re-key, and redistribute our new key.
pub fn handle_group_remove(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    fs: &mut FileStore,
    group_id: &str,
    member: &str,
) -> Result<()> {
    let mut stored = match groups::load(fs, group_id)? {
        Some(stored) => stored,
        None => return Ok(()),
    };
    if member == me.as_str() {
        return Ok(()); // we were removed; nothing to re-key
    }
    stored.members.retain(|m| m != member);
    let mut session = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    for (id, handle) in &stored.sender_handles {
        if handle == member {
            session.remove_member(id);
        }
    }
    stored.sender_handles.retain(|(_, h)| h != member);
    session.rotate(&mut OsPlatform);
    stored.state = session.export();
    groups::save(fs, &stored)?;
    distribute_key(identity, me, client, &stored, &session, fs, OsPlatform.now_unix_secs());
    println!("'{member}' was removed from '{}' — re-keyed", stored.name);
    Ok(())
}



#[allow(clippy::too_many_arguments)]
pub fn group_send(
    group: &str,
    whoami: &str,
    message: Option<&str>,
    reply_to: Option<&str>,
    react: Option<&str>,
    to: Option<&str>,
    file: Option<&str>,
    edit: Option<&str>,
    delete: Option<&str>,
    expire: Option<&str>,
    directory: &str,
) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let mut fs = open_history(&identity)?;
    let now = OsPlatform.now_unix_secs();
    // Retry anything parked from an earlier send before adding more.
    let _ = flush_outbox(&identity, &client, &mut fs);

    let mut stored = resolve_group(&fs, group)?;
    let mut session = Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    let expires_at = resolve_expiry(&fs, &stored.id, expire)?;
    let app = build_message(message, reply_to, react, to, file, edit, delete, expires_at)?;

    // Apply an edit/delete to our own copy of the transcript too.
    match &app.body {
        Body::Edit { to, text } => history::group_edit(&mut fs, &stored.id, to, text)?,
        Body::Delete { to } => history::group_delete(&mut fs, &stored.id, to)?,
        _ => {}
    }
    let gm = session.encrypt(&app.encode(), &group_ad(&stored.id));
    stored.state = session.export();
    groups::save(&mut fs, &stored)?;

    let item = MailItem::GroupText { group_id: stored.id.clone(), message: gm };
    for member in &stored.members {
        let handle = match Handle::new(member.clone()) {
            Ok(h) => h,
            Err(_) => continue,
        };
        if member == me.as_str() {
            // Mirror to my *own* other devices (they hold my key from `group
            // sync`), so the group reads consistently across my cluster.
            if let Ok(my_rec) = client.lookup(&me) {
                let my_queue = QueueTarget::open(&identity, &my_rec.record);
                for device in &my_rec.record.devices {
                    if device.device_key != identity.device_public()
                        && !deliver(&client, &me, my_queue.as_ref(), device, &item)
                    {
                        let slot = device_slot(&device.device_key);
                        let _ = outbox::enqueue(&mut fs, random_id(), me.as_str(), &slot, item.clone(), now);
                    }
                }
            }
            continue;
        }
        // Fan the one ciphertext out to every device in the member's cluster,
        // parking any we can't reach in the outbox for retry (Tier 2.3).
        deliver_to_cluster_or_queue(&client, &identity, &handle, &item, &mut fs, now);
    }

    // Record our own message in the group transcript (edits/deletes already
    // applied above, so don't add them as new lines).
    if !matches!(app.body, Body::Edit { .. } | Body::Delete { .. }) {
        let entry = GroupStoredMessage {
            id: app.id.clone(),
            sender: me.as_str().to_string(),
            text: app.summary(),
            timestamp: OsPlatform.now_unix_secs(),
            expires_at: app.expires_at,
        };
        let _ = history::group_append(&mut fs, &stored.id, entry);
    }
    println!("sent to group '{}' (#{})", stored.name, app.id);
    Ok(())
}



pub fn group_history(group: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let stored = resolve_group(&fs, group)?;
    let now = OsPlatform.now_unix_secs();
    let transcript = history::group_load_active(&mut fs, &stored.id, now)?;
    if transcript.is_empty() {
        println!("no messages in '{}'", stored.name);
        return Ok(());
    }
    for m in transcript {
        println!("[{}] {}: {}", stored.name, m.sender, m.text);
    }
    Ok(())
}



pub fn group_info(group: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let stored = resolve_group(&fs, group)?;
    println!("{} ({})", stored.name, stored.id);
    println!("members: {}", stored.members.join(", "));
    Ok(())
}



pub fn group_sync(whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let fs = open_history(&identity)?;

    // My sibling devices (everything in my cluster except this one).
    let my_record = client.lookup(&me)?;
    let my_queue = QueueTarget::open(&identity, &my_record.record);
    let my_key = identity.device_public();
    let siblings: Vec<Device> = my_record
        .record
        .devices
        .iter()
        .filter(|d| d.device_key != my_key)
        .cloned()
        .collect();
    if siblings.is_empty() {
        println!("no other devices to sync to");
        return Ok(());
    }

    let mut synced = 0;
    for id in groups::list(&fs)? {
        let stored = match groups::load(&fs, &id)? {
            Some(s) => s,
            None => continue,
        };
        let group = match Group::import(stored.state.clone()) {
            Ok(g) => g,
            Err(_) => continue,
        };
        // Every key this device holds: the others' receiver keys, plus our own
        // distribution (so a sibling can decrypt what this device sends).
        let mut keys = group.known_keys();
        keys.push((my_group_id(&identity), group.distribution()));

        let payload = GroupSyncPayload {
            group_id: stored.id.clone(),
            name: stored.name.clone(),
            members: stored.members.clone(),
            keys,
            sender_handles: stored.sender_handles.clone(),
        };
        let plaintext = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(_) => continue,
        };
        for device in &siblings {
            let env = seal_to(&identity, &me, device, &plaintext);
            deliver(&client, &me, my_queue.as_ref(), device, &MailItem::GroupSync(env));
        }
        synced += 1;
    }
    println!("synced {synced} group(s) to {} other device(s)", siblings.len());
    Ok(())
}



/// Bootstrap this device into a group from a sibling's [`GroupSyncPayload`].
pub fn handle_group_sync(
    identity: &Identity,
    me: &Handle,
    client: &DirectoryClient,
    platform: &mut OsPlatform,
    fs: &mut FileStore,
    env: &Envelope,
) -> Result<()> {
    let (_from, bytes) = open_envelope(identity, platform, env)?;
    let payload: GroupSyncPayload =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("malformed group sync"))?;

    if groups::load(fs, &payload.group_id)?.is_some() {
        return Ok(()); // already have this group
    }
    // A fresh own sender key (this device signs under its device id); import
    // every sender key the cluster shared so we can decrypt current members.
    let mut group = Group::new(platform, my_group_id(identity));
    for (id, dist) in &payload.keys {
        let _ = group.add_member(id.clone(), dist);
    }
    let mut stored = StoredGroup {
        id: payload.group_id.clone(),
        name: payload.name.clone(),
        members: payload.members.clone(),
        me: me.as_str().to_string(),
        sender_handles: payload.sender_handles.clone(),
        state: group.export(),
    };
    stored.note_sender(my_group_id(identity), me.as_str());
    groups::save(fs, &stored)?;
    // Announce our own key to the members so this device can also *send*.
    distribute_key(identity, me, client, &stored, &group, fs, OsPlatform.now_unix_secs());
    println!("bootstrapped into group '{}'", stored.name);
    Ok(())
}



pub fn group_leave(group: &str, whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let mut fs = open_history(&identity)?;
    let stored = resolve_group(&fs, group)?;

    // Tell the remaining members we left so they drop us and re-key.
    let control = MailItem::GroupRemove {
        group_id: stored.id.clone(),
        member: me.as_str().to_string(),
    };
    for member in &stored.members {
        if member == me.as_str() {
            continue;
        }
        if let Ok(handle) = Handle::new(member.clone()) {
            deliver_to_cluster_or_queue(&client, &identity, &handle, &control, &mut fs, OsPlatform.now_unix_secs());
        }
    }
    groups::remove(&mut fs, &stored.id)?;
    println!("left group '{}'", stored.name);
    Ok(())
}



pub fn group_list() -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let ids = groups::list(&fs)?;
    if ids.is_empty() {
        println!("no groups");
        return Ok(());
    }
    for id in ids {
        if let Some(g) = groups::load(&fs, &id)? {
            println!("{} ({}) — {} members", g.name, g.id, g.members.len());
        }
    }
    Ok(())
}



/// Resolve a group by id, or by name if no id matches.
pub fn resolve_group(fs: &FileStore, key: &str) -> Result<StoredGroup> {
    if let Some(g) = groups::load(fs, key)? {
        return Ok(g);
    }
    for id in groups::list(fs)? {
        if let Some(g) = groups::load(fs, &id)? {
            if g.name == key {
                return Ok(g);
            }
        }
    }
    bail!("no such group '{key}'")
}
