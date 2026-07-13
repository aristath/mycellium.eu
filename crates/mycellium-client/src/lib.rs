//! Headless Mycellium client API.
//!
//! This crate is the reusable client boundary. It owns account/device record
//! semantics and local peer-record mutations; shells decide only how to prompt,
//! print, and connect transports.

use anyhow::{anyhow, bail, Result};

use mycellium_core::identity::{Handle, Identity, PeerId, WalletPublicKey};
use mycellium_core::platform::Platform;
use mycellium_core::record::SignedRecord;
use mycellium_core::safety;
use mycellium_core::storage::Storage;
use mycellium_engine::contacts::{self, Contact};
use mycellium_engine::flow::{self, TrustError};
use mycellium_engine::history::{self, StoredMessage};
use mycellium_engine::peerbook::{self, PeerRecord};
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
}
