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
    distribute_key(
        &identity,
        &me,
        &client,
        &stored,
        &group,
        &mut fs,
        OsPlatform.now_unix_secs(),
    );

    println!(
        "created group '{name}' ({group_id}) with {} members",
        all.len()
    );
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
    distribute_key_to(
        identity,
        me,
        client,
        stored,
        group,
        &stored.members,
        fs,
        now,
    );
}

/// The engine's [`flow::FlowNet`]: directory lookups over the native blocking
/// `DirectoryClient`.
struct EngineNet<'a> {
    client: &'a DirectoryClient,
}

impl crate::flow::FlowNet for EngineNet<'_> {
    fn lookup(&self, handle: &Handle) -> Result<SignedRecord> {
        self.client.lookup(handle)
    }
}

/// Send our sender-key distribution to a specific set of members. Any device we
/// can't reach live or via its queue is parked in the outbox for retry — so key
/// distribution (like group text) isn't silently lost on a transient failure.
///
/// The shared lookup/verify/pin-check/seal loop lives in [`crate::flow::distribute_key`];
/// this only supplies the engine's per-device delivery (the reachability-scored
/// live ladder, with the outbox as the guaranteed fallback).
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
    let net = EngineNet { client };
    let my_name = display_name_for(me);
    let my_queue = own_queue();
    // The recipient's queue endpoints are per-member, but `deliver` is called
    // per-device; cache the logged-in target so we only open it once per member
    // (records arrive grouped by member), rebuilding when the record changes.
    let mut queue_cache: Option<(WalletPublicKey, Option<QueueTarget>)> = None;
    let mut deliver = |store: &mut FileStore,
                       handle: &Handle,
                       record: &SignedRecord,
                       device: &Device,
                       item: MailItem| {
        if queue_cache.as_ref().map(|(w, _)| *w) != Some(record.record.wallet) {
            queue_cache = Some((
                record.record.wallet,
                QueueTarget::open(identity, &record.record),
            ));
        }
        let queue = queue_cache.as_ref().and_then(|(_, q)| q.as_ref());
        if !deliver_scored(
            store,
            identity.device_secret(),
            client,
            handle,
            queue,
            device,
            &item,
            now,
        )
        .is_delivered()
        {
            let slot = device_slot(&device.device_key);
            let _ = outbox::enqueue(store, random_id(), handle.as_str(), &slot, item, now);
        }
    };
    crate::flow::distribute_key(
        identity,
        fs,
        &mut OsPlatform,
        &net,
        me,
        &my_name,
        &my_queue,
        &stored.id,
        &stored.name,
        &group.distribution(),
        &stored.members,
        targets,
        &mut deliver,
    );
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
    distribute_key(
        &identity,
        &me,
        &client,
        &stored,
        &session,
        &mut fs,
        OsPlatform.now_unix_secs(),
    );
    println!("invited '{member}' to '{}'", stored.name);
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
    let mut session =
        Group::import(stored.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    let expires_at = resolve_expiry(&fs, &stored.id, expire)?;
    let app = build_message(message, reply_to, react, to, file, edit, delete, expires_at)?;

    // Apply an edit/delete to our own copy of the transcript too.
    match &app.body {
        Body::Edit { to, text } => history::group_edit(&mut fs, &stored.id, to, text, me.as_str())?,
        Body::Delete { to } => history::group_delete(&mut fs, &stored.id, to, me.as_str())?,
        _ => {}
    }
    let gm = session.encrypt(&app.encode(), &group_ad(&stored.id));
    stored.state = session.export();
    groups::save(&mut fs, &stored)?;

    let item = MailItem::GroupText {
        group_id: stored.id.clone(),
        message: gm,
    };
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
                        && !deliver_scored(
                            &mut fs,
                            identity.device_secret(),
                            &client,
                            &me,
                            my_queue.as_ref(),
                            device,
                            &item,
                            now,
                        )
                        .is_delivered()
                    {
                        let slot = device_slot(&device.device_key);
                        let _ = outbox::enqueue(
                            &mut fs,
                            random_id(),
                            me.as_str(),
                            &slot,
                            item.clone(),
                            now,
                        );
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
            let Ok(env) = seal_to(&identity, &me, device, &plaintext) else {
                continue;
            };
            let _ = deliver(
                identity.device_secret(),
                &client,
                &me,
                my_queue.as_ref(),
                device,
                &MailItem::GroupSync(env),
            );
        }
        synced += 1;
    }
    println!(
        "synced {synced} group(s) to {} other device(s)",
        siblings.len()
    );
    Ok(())
}

pub fn group_leave(group: &str, whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let mut fs = open_history(&identity)?;
    let stored = resolve_group(&fs, group)?;
    let now = OsPlatform.now_unix_secs();

    // Announce our departure, *sealed* to each member's devices so it's
    // authenticated as ours — no one can forge someone else leaving. They drop
    // us and re-key. (Mirrors how invites/keys are distributed.)
    let payload = GroupLeavePayload {
        group_id: stored.id.clone(),
    };
    let plaintext = serde_json::to_vec(&payload)?;
    for member in &stored.members {
        if member == me.as_str() {
            continue;
        }
        let Ok(handle) = Handle::new(member.clone()) else {
            continue;
        };
        let record = match client.lookup(&handle) {
            Ok(r) if r.verify().is_ok() => r,
            _ => continue,
        };
        let queue = QueueTarget::open(&identity, &record.record);
        for device in &record.record.devices {
            if device.device_key == identity.device_public() {
                continue;
            }
            let Ok(env) = seal_to(&identity, &me, device, &plaintext) else {
                continue;
            };
            let item = MailItem::GroupLeave(env);
            if !deliver_scored(
                &mut fs,
                identity.device_secret(),
                &client,
                &handle,
                queue.as_ref(),
                device,
                &item,
                now,
            )
            .is_delivered()
            {
                let slot = device_slot(&device.device_key);
                let _ = outbox::enqueue(&mut fs, random_id(), handle.as_str(), &slot, item, now);
            }
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
