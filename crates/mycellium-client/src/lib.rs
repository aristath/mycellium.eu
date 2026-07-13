//! Headless Mycellium client API.
//!
//! This crate is the reusable client boundary. It owns account/device record
//! semantics and local peer-record mutations; shells decide only how to prompt,
//! print, and connect transports.

use anyhow::{anyhow, bail, Result};

use mycellium_core::group::Group;
use mycellium_core::identity::{Handle, Identity, PeerId, WalletPublicKey};
use mycellium_core::message::AppMessage;
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, SignedRecord};
use mycellium_core::safety;
use mycellium_core::storage::Storage;
use mycellium_engine::contacts::{self, Contact};
use mycellium_engine::flow::{self, TrustError};
use mycellium_engine::groups::{self, MailItem, StoredGroup};
use mycellium_engine::history::{self, GroupStoredMessage, StoredMessage};
use mycellium_engine::outbox::{self, OutboxEntry};
use mycellium_engine::peerbook::{self, PeerRecord};
use mycellium_engine::reachability::DeliveryPath;
use mycellium_engine::verified;
use mycellium_engine::wireops;
use mycellium_engine::{antirollback, blocklist};
use mycellium_engine::{draft, expiry};

/// Public identity material useful for display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityInfo {
    pub wallet: Vec<u8>,
    pub device: Vec<u8>,
    pub messaging: Vec<u8>,
}

pub fn identity_info(identity: &Identity) -> IdentityInfo {
    IdentityInfo {
        wallet: identity.wallet_public().0.to_vec(),
        device: identity.device_public().0.to_vec(),
        messaging: identity.messaging_public().0.to_vec(),
    }
}

pub fn create_identity(platform: &mut impl Platform) -> Result<Identity> {
    Ok(Identity::generate(platform)?)
}

pub fn adopt_identity(platform: &mut impl Platform, wallet_secret: [u8; 32]) -> Result<Identity> {
    Ok(Identity::adopt(platform, wallet_secret)?)
}

/// Build and store this account's current public record.
///
/// If the existing local record belongs to the same wallet and the same active
/// device, this refreshes only reachability. If it belongs to the same wallet but
/// a different device, this publishes the current device as the new active one.
pub fn publish_active_device_record<S, P>(
    store: &mut S,
    platform: &mut P,
    identity: &Identity,
    handle: &Handle,
    name: &str,
    location: &str,
) -> Result<SignedRecord>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
    P: Platform,
{
    let existing = reusable_own_record(identity, handle, peerbook::get(store, handle)?)?;
    let now = platform.now_unix_secs();
    let active_device = match existing.as_ref() {
        Some(record) if record.record.device.device_key == identity.device_public() => {
            let device = &record.record.device;
            let reachability_seq = now.max(device.reachability.record.seq.saturating_add(1));
            device
                .refresh_reachability(
                    identity,
                    PeerId(location.as_bytes().to_vec()),
                    reachability_seq,
                )
                .map_err(|_| anyhow!("could not sign refreshed reachability"))?
        }
        _ => wireops::this_device(identity, location, now),
    };
    let active_device_changed = existing
        .as_ref()
        .map(|record| record.record.device.device_key != active_device.device_key)
        .unwrap_or(true);
    let signed = match existing {
        Some(mut record) if !active_device_changed && record.record.name == name => {
            // Pure address refresh: preserve wallet-signed identity and stable
            // device records byte-for-byte.
            record.record.device = active_device;
            record
        }
        existing => peerbook::with_device(
            platform,
            identity,
            handle,
            name,
            active_device,
            existing.as_ref().map(|r| r.record.seq).unwrap_or(0),
        ),
    };
    peerbook::put(store, handle, signed.clone())?;
    Ok(signed)
}

pub fn reusable_own_record(
    identity: &Identity,
    handle: &Handle,
    existing: Option<SignedRecord>,
) -> Result<Option<SignedRecord>> {
    let Some(record) = existing else {
        return Ok(None);
    };
    record.verify().map_err(|_| {
        anyhow!(
            "local record for '{}' failed verification; run `record remove {}` before registering it here",
            handle.as_str(),
            handle.as_str()
        )
    })?;
    if record.record.wallet != identity.wallet_public() {
        bail!(
            "local record for '{}' belongs to a different wallet; run `record remove {}` before registering it here",
            handle.as_str(),
            handle.as_str()
        );
    }
    Ok(Some(record))
}

pub fn require_record<S: Storage>(store: &S, handle: &Handle) -> Result<SignedRecord>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    peerbook::get(store, handle)?
        .ok_or_else(|| anyhow!("no local record for '{}'", handle.as_str()))
}

pub fn require_own_record<S: Storage>(store: &S, handle: &Handle) -> Result<SignedRecord>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    peerbook::get(store, handle)?.ok_or_else(|| {
        anyhow!(
            "no local signed record for '{}' — run `register {} --addr <host:port>` first",
            handle.as_str(),
            handle.as_str()
        )
    })
}

pub fn import_record<S: Storage>(store: &mut S, handle: &Handle, record: SignedRecord) -> Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    peerbook::put(store, handle, record)
}

pub fn list_records<S: Storage>(store: &S) -> Result<Vec<PeerRecord>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    Ok(peerbook::load(store)?)
}

pub fn remove_record<S: Storage>(store: &mut S, handle: &Handle) -> Result<bool>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let wallet = peerbook::get(store, handle)?.map(|record| record.record.wallet);
    let removed = peerbook::remove(store, handle)?;
    if removed {
        if let Some(wallet) = wallet {
            antirollback::clear(store, handle.as_str(), &wallet)?;
        }
    }
    Ok(removed)
}

#[derive(Clone)]
pub struct LocalNet {
    records: Vec<PeerRecord>,
}

impl LocalNet {
    pub fn load(store: &impl Storage) -> Self {
        Self {
            records: peerbook::load(store).unwrap_or_default(),
        }
    }
}

impl flow::FlowNet for LocalNet {
    fn lookup(&self, handle: &Handle) -> anyhow::Result<SignedRecord> {
        self.records
            .iter()
            .find(|entry| entry.handle == handle.as_str())
            .map(|entry| entry.record.clone())
            .ok_or_else(|| anyhow!("no local record for '{}'", handle.as_str()))
    }
}

pub fn resolve_name<S: Storage>(store: &S, input: &str) -> Result<String>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    Ok(contacts::resolve(store, input)?)
}

pub fn resolve_local_record<S: Storage>(
    store: &mut S,
    resolved: &str,
) -> std::result::Result<(Handle, SignedRecord), TrustError> {
    let net = LocalNet::load(store);
    flow::resolve_record(store, &net, resolved)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactEntry {
    pub nickname: String,
    pub handle: String,
    pub verified: bool,
}

pub fn add_contact<S: Storage>(store: &mut S, nickname: &str, handle: &Handle) -> Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let record = require_record(store, handle)
        .map_err(|_| anyhow!("import a signed record for '{}' first", handle.as_str()))?;
    let contact = Contact {
        nickname: nickname.to_string(),
        handle: handle.as_str().to_string(),
        wallet: record.record.wallet,
    };
    contacts::save(store, &contact)?;
    Ok(())
}

pub fn list_contacts<S: Storage>(store: &S) -> Result<Vec<ContactEntry>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let contacts = contacts::list(store)?;
    Ok(contacts
        .into_iter()
        .map(|contact| {
            let verified = verified::get(store, &contact.handle)
                .ok()
                .flatten()
                .as_ref()
                == Some(&contact.wallet);
            ContactEntry {
                nickname: contact.nickname,
                handle: contact.handle,
                verified,
            }
        })
        .collect())
}

pub fn remove_contact<S: Storage>(store: &mut S, nickname: &str) -> Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    contacts::remove(store, nickname)?;
    Ok(())
}

pub fn set_blocked<S: Storage>(store: &mut S, handle: &str, blocked: bool) -> Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    if blocked {
        blocklist::block(store, handle)?;
    } else {
        blocklist::unblock(store, handle)?;
    }
    Ok(())
}

pub fn list_blocked<S: Storage>(store: &S) -> Result<Vec<String>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    Ok(blocklist::load(store)?)
}

pub fn set_draft<S: Storage>(store: &mut S, input: &str, text: &str) -> Result<String>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let key = resolve_name(store, input)?;
    draft::set(store, &key, text)?;
    Ok(key)
}

pub fn get_draft<S: Storage>(store: &S, input: &str) -> Result<(String, Option<String>)>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let key = resolve_name(store, input)?;
    let value = draft::get(store, &key)?;
    Ok((key, value))
}

pub fn clear_draft<S: Storage>(store: &mut S, input: &str) -> Result<String>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let key = resolve_name(store, input)?;
    draft::clear(store, &key)?;
    Ok(key)
}

pub fn set_expiry<S: Storage>(store: &mut S, input: &str, ttl_secs: u64) -> Result<String>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let key = resolve_name(store, input)?;
    expiry::set(store, &key, ttl_secs)?;
    Ok(key)
}

pub fn get_expiry<S: Storage>(store: &S, input: &str) -> Result<(String, Option<u64>)>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let key = resolve_name(store, input)?;
    let value = expiry::get(store, &key)?;
    Ok((key, value))
}

pub fn clear_expiry<S: Storage>(store: &mut S, input: &str) -> Result<String>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let key = resolve_name(store, input)?;
    expiry::clear(store, &key)?;
    Ok(key)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConversationPreview {
    pub peer: String,
    pub from_me: bool,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchHit {
    pub peer: String,
    pub from_me: bool,
    pub text: String,
}

pub fn clear_history<S: Storage>(store: &mut S, input: &str) -> Result<String>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let key = resolve_name(store, input)?;
    history::clear(store, &key)?;
    Ok(key)
}

pub fn history_with<S: Storage>(
    store: &mut S,
    input: &str,
    now: u64,
) -> Result<(String, Vec<StoredMessage>)>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let key = resolve_name(store, input)?;
    let messages = history::load_active(store, &key, now)?;
    Ok((key, messages))
}

pub fn conversations<S: Storage>(store: &mut S, now: u64) -> Result<Vec<ConversationPreview>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let mut out = Vec::new();
    for peer in history::peers(store)? {
        if let Some(last) = history::load_active(store, &peer, now)?.last() {
            out.push(ConversationPreview {
                peer,
                from_me: last.from_me,
                text: last.text.clone(),
            });
        }
    }
    Ok(out)
}

pub fn search_history<S: Storage>(store: &mut S, query: &str, now: u64) -> Result<Vec<SearchHit>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let needle = query.to_lowercase();
    let mut hits = Vec::new();
    for peer in history::peers(store)? {
        for message in history::load_active(store, &peer, now)? {
            if message.text.to_lowercase().contains(&needle) {
                hits.push(SearchHit {
                    peer: peer.clone(),
                    from_me: message.from_me,
                    text: message.text,
                });
            }
        }
    }
    Ok(hits)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationInfo {
    pub handle: String,
    pub wallet: WalletPublicKey,
    pub safety_number: String,
    pub level: verified::TrustLevel,
}

pub fn verification_info<S: Storage>(
    store: &S,
    identity: &Identity,
    handle: &Handle,
) -> Result<VerificationInfo>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let record = require_record(store, handle)?;
    record
        .verify()
        .map_err(|_| anyhow!("peer record failed verification"))?;
    let wallet = record.record.wallet;
    Ok(VerificationInfo {
        handle: handle.as_str().to_string(),
        wallet,
        safety_number: safety::safety_number(&identity.wallet_public(), &wallet),
        level: verified::level(store, handle.as_str(), &wallet),
    })
}

pub fn mark_verified<S: Storage>(store: &mut S, info: &VerificationInfo) -> Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    if info.level == verified::TrustLevel::Changed {
        bail!(
            "identity changed for '{}'; compare the new safety number and use --accept-change explicitly",
            info.handle
        );
    }
    verified::mark(store, &info.handle, &info.wallet)?;
    Ok(())
}

pub fn accept_identity_change<S: Storage>(store: &mut S, info: &VerificationInfo) -> Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    if info.level != verified::TrustLevel::Changed {
        bail!("'{}' has no changed identity to accept", info.handle);
    }
    verified::mark(store, &info.handle, &info.wallet)?;
    for mut contact in contacts::list(store)? {
        if contact.handle == info.handle {
            contact.wallet = info.wallet;
            contacts::save(store, &contact)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn send_direct<S, P>(
    identity: &Identity,
    store: &mut S,
    platform: &mut P,
    me: &Handle,
    peer: &Handle,
    peer_record: &SignedRecord,
    app: &AppMessage,
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem) -> DeliveryPath,
) -> Result<flow::SendOutcome>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
    P: Platform,
{
    let my_record = require_own_record(store, me)?;
    let net = LocalNet::load(store);
    let mut self_deliver = |_: &mut S, _: &Handle, _: &Device, _: MailItem| {};
    Ok(flow::send_app(
        identity,
        store,
        platform,
        &net,
        me,
        &my_record,
        peer,
        peer_record,
        app,
        deliver,
        &mut self_deliver,
    )?)
}

pub fn resolve_group<S: Storage>(store: &S, key: &str) -> Result<StoredGroup>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    if let Some(group) = groups::load(store, key)? {
        return Ok(group);
    }

    let mut matches = Vec::new();
    for id in groups::list(store)? {
        if let Some(group) = groups::load(store, &id)? {
            if group.name == key {
                matches.push(group);
            }
        }
    }

    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => bail!("no such group '{key}'"),
        _ => bail!("group name '{key}' is ambiguous; use the group id"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSummary {
    pub id: String,
    pub name: String,
    pub member_count: usize,
}

pub fn list_groups<S: Storage>(store: &S) -> Result<Vec<GroupSummary>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let mut out = Vec::new();
    for id in groups::list(store)? {
        if let Some(group) = groups::load(store, &id)? {
            out.push(GroupSummary {
                id: group.id,
                name: group.name,
                member_count: group.members.len(),
            });
        }
    }
    Ok(out)
}

pub fn group_history<S: Storage>(
    store: &mut S,
    key: &str,
    now: u64,
) -> Result<(StoredGroup, Vec<GroupStoredMessage>)>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let group = resolve_group(store, key)?;
    let messages = history::group_load_active(store, &group.id, now)?;
    Ok((group, messages))
}

pub fn create_group<S, P>(
    identity: &Identity,
    store: &mut S,
    platform: &mut P,
    me: &Handle,
    name: &str,
    members: Vec<String>,
) -> Result<StoredGroup>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
    P: Platform,
{
    let group = Group::new(platform, wireops::my_group_id(identity));
    let mut stored = StoredGroup {
        id: wireops::random_id(platform),
        name: name.to_string(),
        members,
        me: me.as_str().to_string(),
        sender_handles: Vec::new(),
        state: group.export(),
    };
    stored.note_sender(wireops::my_group_id(identity), me.as_str());
    groups::save(store, &stored)?;
    Ok(stored)
}

pub fn group_with_added_member<S: Storage>(
    store: &S,
    group: &str,
    member: &Handle,
) -> Result<StoredGroup>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let mut stored = resolve_group(store, group)?;
    if stored.members.iter().any(|m| m == member.as_str()) {
        bail!("'{}' is already in '{}'", member.as_str(), stored.name);
    }
    stored.members.push(member.as_str().to_string());
    Ok(stored)
}

pub fn save_group<S: Storage>(store: &mut S, group: &StoredGroup) -> Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    groups::save(store, group)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn distribute_group_key<S, P>(
    identity: &Identity,
    store: &mut S,
    platform: &mut P,
    me: &Handle,
    my_record: &SignedRecord,
    group: &StoredGroup,
    targets: &[String],
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem),
) -> Result<()>
where
    S: Storage,
    S::Error: std::error::Error + Send + Sync + 'static,
    P: Platform,
{
    let session = Group::import(group.state.clone()).map_err(|_| anyhow!("bad group state"))?;
    let net = LocalNet::load(store);
    flow::distribute_key(
        identity,
        store,
        platform,
        &net,
        me,
        my_record,
        &group.id,
        &group.name,
        &session.distribution(),
        &group.members,
        targets,
        deliver,
    );
    Ok(())
}

pub fn send_group<S: Storage>(
    identity: &Identity,
    store: &mut S,
    me: &Handle,
    group: &mut StoredGroup,
    app: &AppMessage,
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem) -> DeliveryPath,
) -> Result<flow::SendOutcome>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let net = LocalNet::load(store);
    Ok(flow::group_send(
        identity, store, &net, me, group, app, deliver,
    )?)
}

pub fn leave_group<S, P>(
    identity: &Identity,
    store: &mut S,
    platform: &mut P,
    me: &Handle,
    my_record: &SignedRecord,
    group: &StoredGroup,
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem),
) where
    S: Storage,
    P: Platform,
{
    let net = LocalNet::load(store);
    flow::group_leave(
        identity, store, platform, &net, me, my_record, group, deliver,
    );
}

#[allow(clippy::too_many_arguments)]
pub fn process_item<S, P>(
    identity: &Identity,
    store: &mut S,
    platform: &mut P,
    me: &Handle,
    my_record: &SignedRecord,
    blocked: &[String],
    item: MailItem,
    sink: &mut dyn flow::FlowSink,
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem) -> DeliveryPath,
) -> flow::ItemOutcome
where
    S: Storage,
    P: Platform,
{
    let net = LocalNet::load(store);
    flow::process_item(
        identity, store, platform, &net, me, my_record, blocked, item, sink, deliver,
    )
}

pub fn list_outbox<S: Storage>(store: &S) -> Result<Vec<OutboxEntry>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    Ok(outbox::load(store)?)
}

pub fn make_outbox_due<S: Storage>(store: &mut S) -> Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    outbox::make_all_due(store)?;
    Ok(())
}

pub fn due_outbox_entries<S: Storage>(store: &S, now: u64) -> Result<Vec<OutboxEntry>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    Ok(outbox::load(store)?
        .into_iter()
        .filter(|entry| entry.is_due(now))
        .collect())
}

pub fn park_outbox<S: Storage>(
    store: &mut S,
    delivery_id: String,
    recipient: &Handle,
    device: &Device,
    item: MailItem,
    now: u64,
) -> Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let slot = wireops::device_slot(&device.device_key);
    outbox::enqueue(store, delivery_id, recipient.as_str(), &slot, item, now)?;
    Ok(())
}

pub fn mark_outbox_delivered<S: Storage>(store: &mut S, delivery_id: &str) -> Result<bool>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    Ok(outbox::mark_delivered(store, delivery_id)?)
}

pub fn mark_outbox_failed<S: Storage>(store: &mut S, delivery_id: &str) -> Result<bool>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    Ok(outbox::mark_failed(store, delivery_id)?)
}

pub fn record_outbox_attempt<S: Storage>(
    store: &mut S,
    delivery_id: &str,
    now: u64,
    accepted: bool,
) -> Result<bool>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    Ok(outbox::record_attempt(store, delivery_id, now, accepted)?)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboxCancel {
    Empty,
    All { removed: usize },
    One { id: String, recipient: String },
}

pub fn cancel_outbox<S: Storage>(store: &mut S, id: &str) -> Result<OutboxCancel>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let mut entries = outbox::load(store)?;
    if entries.is_empty() {
        return Ok(OutboxCancel::Empty);
    }

    if id == "all" {
        let mut removed = 0usize;
        for entry in entries.iter_mut().filter(|entry| entry.is_pending()) {
            entry.status = outbox::OutboxStatus::Cancelled;
            entry.send_after = 0;
            removed += 1;
        }
        outbox::save(store, &entries)?;
        return Ok(OutboxCancel::All { removed });
    }

    let matches: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| entry.id.starts_with(id).then_some(index))
        .collect();
    match matches.len() {
        0 => bail!("no pending local delivery item matches '{id}'"),
        1 => {
            let entry = &mut entries[matches[0]];
            if !entry.is_pending() {
                bail!(
                    "local delivery {} is already {:?}",
                    short_outbox_id(&entry.id),
                    entry.status
                );
            }
            entry.status = outbox::OutboxStatus::Cancelled;
            entry.send_after = 0;
            let cancelled = OutboxCancel::One {
                id: entry.id.clone(),
                recipient: entry.recipient.clone(),
            };
            outbox::save(store, &entries)?;
            Ok(cancelled)
        }
        n => bail!("'{id}' matches {n} pending items; use a longer id prefix"),
    }
}

fn short_outbox_id(id: &str) -> &str {
    &id[..12.min(id.len())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::convert::Infallible;

    #[derive(Default)]
    struct MemStore(HashMap<Vec<u8>, Vec<u8>>);

    impl Storage for MemStore {
        type Error = Infallible;

        fn get(&self, key: &[u8]) -> std::result::Result<Option<Vec<u8>>, Infallible> {
            Ok(self.0.get(key).cloned())
        }

        fn put(&mut self, key: &[u8], value: &[u8]) -> std::result::Result<(), Infallible> {
            self.0.insert(key.to_vec(), value.to_vec());
            Ok(())
        }

        fn delete(&mut self, key: &[u8]) -> std::result::Result<(), Infallible> {
            self.0.remove(key);
            Ok(())
        }
    }

    struct SeededPlatform(u8);

    impl Platform for SeededPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self.0.wrapping_add((i as u8).wrapping_mul(31));
            }
            self.0 = self.0.wrapping_add(1);
        }

        fn now_unix_secs(&self) -> u64 {
            42
        }
    }

    #[test]
    fn publishing_switches_to_the_current_active_device() {
        let handle = Handle::new("alice").unwrap();
        let mut first_platform = SeededPlatform(1);
        let mut second_platform = SeededPlatform(80);
        let first = Identity::generate(&mut first_platform).unwrap();
        let second = Identity::adopt(&mut second_platform, first.wallet_secret()).unwrap();
        let mut store = MemStore::default();

        let first_record = publish_active_device_record(
            &mut store,
            &mut first_platform,
            &first,
            &handle,
            "Alice",
            "127.0.0.1:1",
        )
        .unwrap();
        let second_record = publish_active_device_record(
            &mut store,
            &mut second_platform,
            &second,
            &handle,
            "Alice",
            "127.0.0.1:2",
        )
        .unwrap();

        assert_ne!(
            first_record.record.device.device_key,
            second_record.record.device.device_key
        );
        assert_eq!(
            require_record(&store, &handle)
                .unwrap()
                .record
                .device
                .device_key,
            second.device_public()
        );
    }

    #[test]
    fn publishing_rejects_a_foreign_wallet_record() {
        let handle = Handle::new("alice").unwrap();
        let mut mine_platform = SeededPlatform(1);
        let mut foreign_platform = SeededPlatform(99);
        let mine = Identity::generate(&mut mine_platform).unwrap();
        let foreign = Identity::generate(&mut foreign_platform).unwrap();
        let mut store = MemStore::default();
        let foreign_record = peerbook::build_record(
            &mut foreign_platform,
            &foreign,
            &handle,
            "Alice",
            "127.0.0.1:1",
        );
        peerbook::put(&mut store, &handle, foreign_record).unwrap();

        let err = publish_active_device_record(
            &mut store,
            &mut mine_platform,
            &mine,
            &handle,
            "Alice",
            "127.0.0.1:2",
        )
        .unwrap_err();

        assert!(err.to_string().contains("different wallet"));
    }

    #[test]
    fn contacts_pin_an_imported_record_wallet() {
        let handle = Handle::new("alice").unwrap();
        let mut platform = SeededPlatform(7);
        let identity = Identity::generate(&mut platform).unwrap();
        let mut store = MemStore::default();
        let record =
            peerbook::build_record(&mut platform, &identity, &handle, "Alice", "127.0.0.1:1");
        import_record(&mut store, &handle, record).unwrap();

        add_contact(&mut store, "a", &handle).unwrap();
        let list = list_contacts(&store).unwrap();

        assert_eq!(list.len(), 1);
        assert_eq!(list[0].nickname, "a");
        assert_eq!(list[0].handle, "alice");
        assert!(!list[0].verified);

        remove_contact(&mut store, "a").unwrap();
        assert!(list_contacts(&store).unwrap().is_empty());
    }

    #[test]
    fn blocklist_round_trips() {
        let mut store = MemStore::default();

        set_blocked(&mut store, "alice", true).unwrap();
        set_blocked(&mut store, "alice", true).unwrap();
        assert_eq!(list_blocked(&store).unwrap(), vec!["alice".to_string()]);

        set_blocked(&mut store, "alice", false).unwrap();
        assert!(list_blocked(&store).unwrap().is_empty());
    }

    #[test]
    fn outbox_cancel_keeps_cli_policy_out_of_the_shell() {
        let mut platform = SeededPlatform(9);
        let mut group = mycellium_core::group::Group::new(&mut platform, b"me-device".to_vec());
        let item = MailItem::GroupText {
            group_id: "g1".to_string(),
            message: group.encrypt(b"hello", b"group:g1"),
        };
        let mut store = MemStore::default();
        outbox::enqueue(
            &mut store,
            "delivery-123".to_string(),
            "bob",
            "device-slot",
            item,
            1,
        )
        .unwrap();

        assert_eq!(list_outbox(&store).unwrap().len(), 1);
        assert_eq!(
            cancel_outbox(&mut store, "delivery").unwrap(),
            OutboxCancel::One {
                id: "delivery-123".to_string(),
                recipient: "bob".to_string(),
            }
        );
        assert!(!list_outbox(&store).unwrap()[0].is_pending());
    }

    #[test]
    fn draft_and_expiry_resolve_contact_names() {
        let handle = Handle::new("alice").unwrap();
        let mut platform = SeededPlatform(11);
        let identity = Identity::generate(&mut platform).unwrap();
        let mut store = MemStore::default();
        let record =
            peerbook::build_record(&mut platform, &identity, &handle, "Alice", "127.0.0.1:1");
        import_record(&mut store, &handle, record).unwrap();
        add_contact(&mut store, "a", &handle).unwrap();

        assert_eq!(set_draft(&mut store, "a", "hello").unwrap(), "alice");
        assert_eq!(
            get_draft(&store, "alice").unwrap(),
            ("alice".to_string(), Some("hello".to_string()))
        );
        assert_eq!(clear_draft(&mut store, "a").unwrap(), "alice");
        assert_eq!(get_draft(&store, "a").unwrap(), ("alice".to_string(), None));

        assert_eq!(set_expiry(&mut store, "a", 60).unwrap(), "alice");
        assert_eq!(
            get_expiry(&store, "alice").unwrap(),
            ("alice".to_string(), Some(60))
        );
        assert_eq!(clear_expiry(&mut store, "a").unwrap(), "alice");
        assert_eq!(
            get_expiry(&store, "a").unwrap(),
            ("alice".to_string(), None)
        );
    }

    #[test]
    fn history_views_resolve_contacts_and_search() {
        let handle = Handle::new("alice").unwrap();
        let mut platform = SeededPlatform(21);
        let identity = Identity::generate(&mut platform).unwrap();
        let mut store = MemStore::default();
        let record =
            peerbook::build_record(&mut platform, &identity, &handle, "Alice", "127.0.0.1:1");
        import_record(&mut store, &handle, record).unwrap();
        add_contact(&mut store, "a", &handle).unwrap();
        history::append(
            &mut store,
            "alice",
            StoredMessage {
                id: "m1".to_string(),
                from_me: false,
                text: "hello from alice".to_string(),
                timestamp: 1,
                expires_at: None,
            },
        )
        .unwrap();

        let (key, messages) = history_with(&mut store, "a", 2).unwrap();
        assert_eq!(key, "alice");
        assert_eq!(messages.len(), 1);
        assert_eq!(conversations(&mut store, 2).unwrap()[0].peer, "alice");
        assert_eq!(search_history(&mut store, "alice", 2).unwrap().len(), 1);

        assert_eq!(clear_history(&mut store, "a").unwrap(), "alice");
        assert!(history_with(&mut store, "a", 2).unwrap().1.is_empty());
    }

    #[test]
    fn accepting_changed_identity_updates_contact_pin() {
        let handle = Handle::new("alice").unwrap();
        let me = Identity::generate(&mut SeededPlatform(3)).unwrap();
        let mut old_platform = SeededPlatform(31);
        let mut new_platform = SeededPlatform(91);
        let old_identity = Identity::generate(&mut old_platform).unwrap();
        let new_identity = Identity::generate(&mut new_platform).unwrap();
        let mut store = MemStore::default();
        let old_record = peerbook::build_record(
            &mut old_platform,
            &old_identity,
            &handle,
            "Alice",
            "127.0.0.1:1",
        );
        import_record(&mut store, &handle, old_record).unwrap();
        add_contact(&mut store, "a", &handle).unwrap();
        let new_record = peerbook::build_record(
            &mut new_platform,
            &new_identity,
            &handle,
            "Alice",
            "127.0.0.1:2",
        );
        import_record(&mut store, &handle, new_record).unwrap();

        let info = verification_info(&store, &me, &handle).unwrap();
        assert_eq!(info.level, verified::TrustLevel::Changed);

        accept_identity_change(&mut store, &info).unwrap();
        let info = verification_info(&store, &me, &handle).unwrap();
        assert_eq!(info.level, verified::TrustLevel::Verified);
        assert!(list_contacts(&store).unwrap()[0].verified);
    }

    #[test]
    fn send_direct_records_local_transcript_and_uses_delivery_hook() {
        let alice_handle = Handle::new("alice").unwrap();
        let bob_handle = Handle::new("bob").unwrap();
        let mut platform = SeededPlatform(41);
        let alice = Identity::generate(&mut platform).unwrap();
        let bob = Identity::generate(&mut platform).unwrap();
        let mut store = MemStore::default();
        publish_active_device_record(
            &mut store,
            &mut platform,
            &alice,
            &alice_handle,
            "Alice",
            "127.0.0.1:1",
        )
        .unwrap();
        let bob_record =
            peerbook::build_record(&mut platform, &bob, &bob_handle, "Bob", "127.0.0.1:2");
        import_record(&mut store, &bob_handle, bob_record.clone()).unwrap();
        let app = AppMessage {
            id: "m1".to_string(),
            timestamp: 10,
            expires_at: None,
            body: mycellium_core::message::Body::Text("hello".to_string()),
        };
        let mut delivered = 0;
        let mut deliver = |_: &mut MemStore,
                           handle: &Handle,
                           _: &SignedRecord,
                           _: &Device,
                           item: MailItem|
         -> DeliveryPath {
            assert_eq!(handle.as_str(), "bob");
            assert!(matches!(item, MailItem::Direct(_)));
            delivered += 1;
            DeliveryPath::Direct
        };

        let out = send_direct(
            &alice,
            &mut store,
            &mut platform,
            &alice_handle,
            &bob_handle,
            &bob_record,
            &app,
            &mut deliver,
        )
        .unwrap();

        assert_eq!(delivered, 1);
        assert_eq!(out.delivered, 1);
        let transcript = history::load(&store, "bob").unwrap();
        assert_eq!(transcript.len(), 1);
        assert_eq!(transcript[0].text, "hello");
        assert!(transcript[0].from_me);
    }

    #[test]
    fn group_read_views_resolve_by_id_or_name() {
        let mut platform = SeededPlatform(51);
        let group = mycellium_core::group::Group::new(&mut platform, b"me-device".to_vec());
        let stored = StoredGroup {
            id: "g1".to_string(),
            name: "team".to_string(),
            members: vec!["alice".to_string(), "bob".to_string()],
            me: "alice".to_string(),
            sender_handles: Vec::new(),
            state: group.export(),
        };
        let mut store = MemStore::default();
        groups::save(&mut store, &stored).unwrap();
        history::group_append(
            &mut store,
            "g1",
            GroupStoredMessage {
                id: "m1".to_string(),
                sender: "alice".to_string(),
                text: "hello team".to_string(),
                timestamp: 1,
                expires_at: None,
            },
        )
        .unwrap();

        assert_eq!(resolve_group(&store, "g1").unwrap().name, "team");
        assert_eq!(resolve_group(&store, "team").unwrap().id, "g1");
        assert_eq!(list_groups(&store).unwrap()[0].member_count, 2);

        let carol = Handle::new("carol").unwrap();
        let updated = group_with_added_member(&store, "team", &carol).unwrap();
        assert!(updated.members.iter().any(|member| member == "carol"));
        save_group(&mut store, &updated).unwrap();
        assert_eq!(resolve_group(&store, "g1").unwrap().members.len(), 3);

        let (group, messages) = group_history(&mut store, "team", 2).unwrap();
        assert_eq!(group.id, "g1");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].text, "hello team");
    }

    #[test]
    fn send_group_records_local_transcript_and_uses_delivery_hook() {
        let alice_handle = Handle::new("alice").unwrap();
        let bob_handle = Handle::new("bob").unwrap();
        let mut platform = SeededPlatform(61);
        let alice = Identity::generate(&mut platform).unwrap();
        let bob = Identity::generate(&mut platform).unwrap();
        let mut store = MemStore::default();
        publish_active_device_record(
            &mut store,
            &mut platform,
            &alice,
            &alice_handle,
            "Alice",
            "127.0.0.1:1",
        )
        .unwrap();
        let bob_record =
            peerbook::build_record(&mut platform, &bob, &bob_handle, "Bob", "127.0.0.1:2");
        import_record(&mut store, &bob_handle, bob_record.clone()).unwrap();
        verified::mark(&mut store, bob_handle.as_str(), &bob_record.record.wallet).unwrap();

        let group = mycellium_core::group::Group::new(&mut platform, b"alice-device".to_vec());
        let mut stored = StoredGroup {
            id: "g1".to_string(),
            name: "team".to_string(),
            members: vec!["alice".to_string(), "bob".to_string()],
            me: "alice".to_string(),
            sender_handles: Vec::new(),
            state: group.export(),
        };
        groups::save(&mut store, &stored).unwrap();
        let app = AppMessage {
            id: "m1".to_string(),
            timestamp: 10,
            expires_at: None,
            body: mycellium_core::message::Body::Text("hello group".to_string()),
        };
        let mut delivered = 0;
        let mut deliver = |_: &mut MemStore,
                           handle: &Handle,
                           _: &SignedRecord,
                           _: &Device,
                           item: MailItem|
         -> DeliveryPath {
            assert_eq!(handle.as_str(), "bob");
            assert!(matches!(item, MailItem::GroupText { .. }));
            delivered += 1;
            DeliveryPath::Direct
        };

        let out = send_group(
            &alice,
            &mut store,
            &alice_handle,
            &mut stored,
            &app,
            &mut deliver,
        )
        .unwrap();

        assert_eq!(delivered, 1);
        assert_eq!(out.delivered, 1);
        let transcript = history::group_load(&store, "g1").unwrap();
        assert_eq!(transcript.len(), 1);
        assert_eq!(transcript[0].text, "hello group");
        assert_eq!(transcript[0].sender, "alice");
    }
}
