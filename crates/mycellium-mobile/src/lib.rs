//! Stable native-client boundary shared by Android and Apple shells.
//!
//! Rust owns protocol state, identity, encrypted history, registry semantics,
//! direct delivery, and sender-held retries. Native shells own presentation,
//! lifecycle integration, and storage of the opaque 64-byte device identity in
//! Android Keystore or Apple Keychain.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use mycellium_client as client;
use mycellium_core::identity::{Handle, Identity};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, SignedRecord};
use mycellium_core::storage::Storage;
use mycellium_core::userid::{user_id, UserId};
use mycellium_core::wire;
use mycellium_engine::flow::{self, FlowEvent};
use mycellium_engine::groups::{MailItem, PeerFrame};
use mycellium_engine::verified::TrustLevel;
use mycellium_storage::filestore::FileStore;
use mycellium_transport::libp2p_net;
use mycellium_transport::link::{FrameReader, FrameWriter};
use zeroize::{Zeroize, Zeroizing};

const REGISTRY_SESSION_KEY: &[u8] = b"mobile:registry-session:v1";
const IDENTITY_SECRET_LEN: usize = 64;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    #[error("{detail}")]
    Failure { detail: String },
}

impl From<anyhow::Error> for MobileError {
    fn from(error: anyhow::Error) -> Self {
        Self::Failure {
            detail: error.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ClientState {
    NeedsLogin,
    NeedsProfile,
    Ready,
    Replaced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum DeliveryState {
    Delivered,
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum EventKind {
    Message,
    Delivered,
    DeviceReplaced,
    Notice,
    Error,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct LoginResult {
    pub created: bool,
    pub state: ClientState,
    /// Present only when this login created this device's identity. The native
    /// shell must immediately place it in its OS secure store.
    pub identity_secret: Option<Vec<u8>>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ProfileInfo {
    pub user_id: String,
    pub handle: String,
    pub display_name: String,
    pub connection_card: String,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ConversationInfo {
    pub user_id: String,
    pub handle: String,
    pub display_name: String,
    pub preview: String,
    pub timestamp: u64,
    pub from_me: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct MessageInfo {
    pub id: String,
    pub text: String,
    pub timestamp: u64,
    pub from_me: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AttachmentInfo {
    pub id: String,
    pub name: String,
    pub mime: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ContactInfo {
    pub nickname: String,
    pub handle: String,
    pub user_id: String,
    pub verified: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ContactSecurityInfo {
    pub user_id: String,
    pub handle: String,
    pub safety_number: String,
    pub trust: String,
    pub identity_changed: bool,
    pub blocked: bool,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ClientEvent {
    pub kind: EventKind,
    pub message: String,
    pub user_id: Option<String>,
}

struct OsPlatform;

impl Platform for OsPlatform {
    fn fill_random(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("OS CSPRNG must be available");
    }

    fn now_unix_secs(&self) -> u64 {
        now()
    }
}

#[derive(Clone)]
struct Session {
    identity: Arc<Identity>,
    store: Arc<Mutex<FileStore>>,
    network: client::DirectNetwork,
    own_record: Arc<Mutex<Option<SignedRecord>>>,
    listener_started: Arc<AtomicBool>,
    device_current: Arc<AtomicBool>,
}

struct Inner {
    account: Option<client::registry::RegistrySession>,
    session: Option<Session>,
}

struct EventSink {
    events: Arc<Mutex<VecDeque<ClientEvent>>>,
}

impl flow::FlowSink for EventSink {
    fn emit(&mut self, event: FlowEvent) {
        let translated = match event {
            FlowEvent::DirectMessage { user_id, from, .. } => Some(ClientEvent {
                kind: EventKind::Message,
                message: format!("New message from {from}"),
                user_id: Some(user_id),
            }),
            FlowEvent::Receipt { from, .. } => Some(ClientEvent {
                kind: EventKind::Delivered,
                message: format!("Delivered to {from}"),
                user_id: None,
            }),
            _ => None,
        };
        if let Some(event) = translated {
            push_event(&self.events, event);
        }
    }
}

/// One process-local native client. Foreign callers may use it from any thread;
/// blocking methods should be dispatched away from the UI thread.
#[derive(uniffi::Object)]
pub struct MobileClient {
    data_dir: PathBuf,
    registry_url: String,
    inner: Mutex<Inner>,
    events: Arc<Mutex<VecDeque<ClientEvent>>>,
    outbox_started: AtomicBool,
    monitor_started: AtomicBool,
}

#[uniffi::export]
impl MobileClient {
    #[uniffi::constructor]
    pub fn open(
        data_dir: String,
        identity_secret: Option<Vec<u8>>,
        registry_url: Option<String>,
    ) -> Result<Arc<Self>, MobileError> {
        Self::open_inner(data_dir, identity_secret, registry_url).map_err(Into::into)
    }

    /// Ask the registry to send a one-time login code.
    pub fn request_email_login(&self, email: String) -> Result<u64, MobileError> {
        let email = email.trim();
        if email.is_empty() {
            return Err(anyhow!("enter your email address").into());
        }
        let expires = client::registry::RegistryClient::new(&self.registry_url)?
            .request_email_login(email)?;
        u64::try_from(expires).map_err(|_| anyhow!("registry returned an invalid expiry").into())
    }

    /// Confirm a login and atomically adopt or create the account identity.
    pub fn confirm_email_login(&self, code: String) -> Result<LoginResult, MobileError> {
        self.confirm_email_login_inner(code).map_err(Into::into)
    }

    pub fn confirm_email_login_link(&self, link: String) -> Result<LoginResult, MobileError> {
        let token = client::registry::login_token_from_link(&link)?;
        self.confirm_email_login_inner(token).map_err(Into::into)
    }

    /// Finish a new account or update the public name of an existing account.
    pub fn save_profile(
        &self,
        handle: String,
        display_name: String,
    ) -> Result<ProfileInfo, MobileError> {
        self.publish_profile(handle, display_name)
            .map_err(Into::into)
    }

    pub fn state(&self) -> ClientState {
        self.current_state()
    }

    pub fn profile(&self) -> Result<Option<ProfileInfo>, MobileError> {
        self.profile_inner().map_err(Into::into)
    }

    pub fn conversations(&self) -> Result<Vec<ConversationInfo>, MobileError> {
        let session = self.require_session()?;
        let mut store = lock(&session.store, "local store")?;
        Ok(client::conversations(&mut *store, now())?
            .into_iter()
            .map(|item| ConversationInfo {
                user_id: item.user_id,
                handle: item.peer,
                display_name: item.display_name,
                preview: item.text,
                timestamp: item.timestamp,
                from_me: item.from_me,
            })
            .collect())
    }

    pub fn messages(&self, user_id: String) -> Result<Vec<MessageInfo>, MobileError> {
        let session = self.require_session()?;
        let mut store = lock(&session.store, "local store")?;
        let (_, messages) = client::history_with(&mut *store, &user_id, now())?;
        Ok(messages
            .into_iter()
            .map(|item| MessageInfo {
                id: item.id,
                text: item.text,
                timestamp: item.timestamp,
                from_me: item.from_me,
            })
            .collect())
    }

    pub fn attachment(&self, message_id: String) -> Result<Option<AttachmentInfo>, MobileError> {
        let session = self.require_session()?;
        let store = lock(&session.store, "local store")?;
        Ok(
            client::attachment(&*store, &message_id)?.map(|attachment| AttachmentInfo {
                id: attachment.id,
                name: attachment.name,
                mime: attachment.mime,
                data: attachment.data,
            }),
        )
    }

    pub fn contacts(&self) -> Result<Vec<ContactInfo>, MobileError> {
        let session = self.require_session()?;
        let store = lock(&session.store, "local store")?;
        let mut contacts: Vec<_> = client::list_contacts(&*store)?
            .into_iter()
            .map(|item| ContactInfo {
                nickname: item.nickname,
                handle: item.handle,
                user_id: item.user_id,
                verified: item.verified,
            })
            .collect();
        contacts.sort_by_key(|item| item.nickname.to_lowercase());
        Ok(contacts)
    }

    pub fn add_contact(
        &self,
        connection_card: String,
        nickname: Option<String>,
    ) -> Result<ContactInfo, MobileError> {
        let record = client::decode_record(connection_card.trim())?;
        let nickname = nickname
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| display_name(&record));
        let info = ContactInfo {
            nickname: nickname.clone(),
            handle: record.record.handle.as_str().to_string(),
            user_id: record.record.user_id.as_str().to_string(),
            verified: false,
        };
        let session = self.require_session()?;
        let mut store = lock(&session.store, "local store")?;
        client::add_contact_from_record(&mut *store, &nickname, record)?;
        Ok(info)
    }

    pub fn remove_contact(&self, nickname: String) -> Result<(), MobileError> {
        let session = self.require_session()?;
        let mut store = lock(&session.store, "local store")?;
        client::remove_contact(&mut *store, nickname.trim())?;
        Ok(())
    }

    pub fn contact_security(&self, user_id: String) -> Result<ContactSecurityInfo, MobileError> {
        let session = self.require_session()?;
        let store = lock(&session.store, "local store")?;
        let record = record_for_user(&store, &user_id)?;
        let info = client::verification_info_for_record(
            &*store,
            &session.identity,
            &record.record.handle,
            &record,
        )?;
        Ok(ContactSecurityInfo {
            user_id: info.user_id,
            handle: info.handle,
            safety_number: info.safety_number,
            trust: trust_label(info.level).to_string(),
            identity_changed: info.level == TrustLevel::Changed,
            blocked: client::list_blocked(&*store)?
                .iter()
                .any(|id| id == &user_id),
        })
    }

    pub fn set_contact_blocked(&self, user_id: String, blocked: bool) -> Result<(), MobileError> {
        UserId::new(user_id.clone()).map_err(|_| anyhow!("invalid protocol user id"))?;
        let session = self.require_session()?;
        let mut store = lock(&session.store, "local store")?;
        client::set_blocked(&mut *store, &user_id, blocked)?;
        Ok(())
    }

    pub fn verify_contact(&self, user_id: String) -> Result<(), MobileError> {
        let session = self.require_session()?;
        let mut store = lock(&session.store, "local store")?;
        let record = record_for_user(&store, &user_id)?;
        let info = client::verification_info_for_record(
            &*store,
            &session.identity,
            &record.record.handle,
            &record,
        )?;
        client::mark_verified(&mut *store, &info)?;
        Ok(())
    }

    pub fn accept_identity_change(&self, user_id: String) -> Result<(), MobileError> {
        let session = self.require_session()?;
        let mut store = lock(&session.store, "local store")?;
        let record = record_for_user(&store, &user_id)?;
        let info = client::verification_info_for_record(
            &*store,
            &session.identity,
            &record.record.handle,
            &record,
        )?;
        client::accept_identity_change(&mut *store, &info)?;
        Ok(())
    }

    pub fn send_text(&self, user_id: String, text: String) -> Result<DeliveryState, MobileError> {
        self.send_text_inner(user_id, text).map_err(Into::into)
    }

    pub fn retry_pending(&self) -> Result<u64, MobileError> {
        let session = self.require_current_session()?;
        {
            let mut store = lock(&session.store, "local store")?;
            client::make_outbox_due(&mut *store)?;
        }
        let result = client::flush_shared_outbox(
            &session.identity,
            &mut OsPlatform,
            &session.store,
            &session.network,
            now(),
        )?;
        Ok(result.waiting as u64)
    }

    pub fn pending_count(&self) -> Result<u64, MobileError> {
        let session = self.require_session()?;
        let store = lock(&session.store, "local store")?;
        Ok(client::list_outbox(&*store)?
            .iter()
            .filter(|entry| entry.is_pending())
            .count() as u64)
    }

    /// Drain events accumulated by listener, retry, and account-monitor workers.
    pub fn poll_events(&self) -> Vec<ClientEvent> {
        let Ok(mut events) = self.events.lock() else {
            return Vec::new();
        };
        events.drain(..).collect()
    }

    /// Re-check whether this remains the registry account's active device.
    pub fn refresh_device_status(&self) -> Result<ClientState, MobileError> {
        self.refresh_device_status_inner().map_err(Into::into)
    }

    /// Restore live registry presence after the OS resumes this app.
    pub fn refresh_connectivity(&self) -> Result<(), MobileError> {
        let session = self.require_session()?;
        session.network.ensure_rendezvous()?;
        Ok(())
    }
}

impl MobileClient {
    fn open_inner(
        data_dir: String,
        identity_secret: Option<Vec<u8>>,
        registry_url: Option<String>,
    ) -> Result<Arc<Self>> {
        let data_dir = PathBuf::from(data_dir);
        std::fs::create_dir_all(&data_dir).context("could not create app storage")?;
        let registry_url = registry_url
            .filter(|url| !url.trim().is_empty())
            .unwrap_or_else(|| client::registry::DEFAULT_REGISTRY_URL.to_string());
        // Validate once before keeping it.
        client::registry::RegistryClient::new(&registry_url)?;

        let session = match identity_secret {
            Some(mut secret) => {
                let identity = decode_identity_secret(&secret)?;
                secret.zeroize();
                Some(open_session(&data_dir, identity)?)
            }
            None => None,
        };
        let account = match session.as_ref() {
            Some(session) => {
                let store = lock(&session.store, "local store")?;
                load_account_session(&store)?
            }
            None => None,
        };
        let client = Arc::new(Self {
            data_dir,
            registry_url,
            inner: Mutex::new(Inner { account, session }),
            events: Arc::new(Mutex::new(VecDeque::new())),
            outbox_started: AtomicBool::new(false),
            monitor_started: AtomicBool::new(false),
        });
        if client.require_session().is_ok() {
            client.start_workers();
            if client.profile_inner()?.is_some() {
                if let Err(error) = client.republish_existing_profile() {
                    push_event(
                        &client.events,
                        ClientEvent {
                            kind: EventKind::Notice,
                            message: format!("Direct reachability will retry: {error}"),
                            user_id: None,
                        },
                    );
                }
            }
        }
        Ok(client)
    }

    fn confirm_email_login_inner(&self, code: String) -> Result<LoginResult> {
        let code = Zeroizing::new(code.trim().to_string());
        if code.is_empty() {
            bail!("enter the code from your email");
        }
        let registry = client::registry::RegistryClient::new(&self.registry_url)?;
        let login = registry.confirm_login(&code)?;
        {
            let inner = self
                .inner
                .lock()
                .map_err(|_| anyhow!("client lock poisoned"))?;
            if inner
                .account
                .as_ref()
                .is_some_and(|account| account.account_id != login.session.account_id)
            {
                bail!("that email belongs to a different Mycellium account");
            }
        }
        let recovery = registry.get_recovery(&login.session)?;
        let remote_record = registry.get_record(&login.session.account_id)?;

        let existing = self.require_session().ok();
        let (session, identity_secret) = if let Some(session) = existing {
            if recovery
                .as_ref()
                .is_some_and(|stored| stored != &session.identity.wallet_secret())
            {
                bail!("that email belongs to a different Mycellium identity");
            }
            if let Some(record) = &remote_record {
                if record.record.user_id != user_id(&session.identity.wallet_public()) {
                    bail!("that email publishes a different Mycellium identity");
                }
            }
            if recovery.is_none() {
                registry.put_recovery(&login.session, &session.identity.wallet_secret())?;
            }
            (session, None)
        } else {
            if recovery.is_none() && remote_record.is_some() {
                bail!("this account has an identity record but no recovery material");
            }
            let identity = match recovery {
                Some(wallet_secret) => client::adopt_identity(&mut OsPlatform, wallet_secret)?,
                None => client::create_identity(&mut OsPlatform)?,
            };
            if remote_record
                .as_ref()
                .is_some_and(|record| record.record.user_id != user_id(&identity.wallet_public()))
            {
                bail!("the recovered identity does not match the account record");
            }
            if recovery.is_none() {
                registry.put_recovery(&login.session, &identity.wallet_secret())?;
            }
            let secret = encode_identity_secret(&identity);
            (open_session(&self.data_dir, identity)?, Some(secret))
        };

        {
            let mut store = lock(&session.store, "local store")?;
            save_account_session(&mut store, &login.session)?;
            if let Some(record) = remote_record.as_ref() {
                let handle = record.record.handle.clone();
                client::import_record(&mut *store, &handle, record.clone())?;
                *lock(&session.own_record, "profile")? = Some(record.clone());
            }
        }
        {
            let mut inner = self
                .inner
                .lock()
                .map_err(|_| anyhow!("client lock poisoned"))?;
            inner.account = Some(login.session);
            inner.session = Some(session);
        }

        self.start_workers();
        if remote_record.is_some() || self.profile_inner()?.is_some() {
            self.republish_existing_profile()?;
        }
        Ok(LoginResult {
            created: login.created,
            state: self.current_state(),
            identity_secret,
        })
    }

    fn publish_profile(&self, handle: String, display_name: String) -> Result<ProfileInfo> {
        let handle = Handle::new(handle.trim().to_lowercase()).map_err(|_| {
            anyhow!("use lowercase letters, numbers, or underscores for the handle")
        })?;
        let name = display_name.trim();
        if name.is_empty() {
            bail!("enter your display name");
        }
        self.publish_profile_values(handle, name.to_string())
    }

    fn republish_existing_profile(&self) -> Result<ProfileInfo> {
        let session = self.require_session()?;
        let record = {
            let own = lock(&session.own_record, "profile")?;
            own.clone()
        }
        .or_else(|| local_own_record(&session).ok().flatten())
        .ok_or_else(|| anyhow!("finish setting up your profile"))?;
        self.publish_profile_values(record.record.handle.clone(), display_name(&record))
    }

    fn publish_profile_values(&self, handle: Handle, name: String) -> Result<ProfileInfo> {
        let session = self.require_session()?;
        let node = self.listener_or_start(&session)?;
        let record = {
            let mut store = lock(&session.store, "local store")?;
            client::publish_active_device_record(
                &mut *store,
                &mut OsPlatform,
                &session.identity,
                &handle,
                &name,
            )?
        };
        *lock(&session.own_record, "profile")? = Some(record.clone());
        if let Some(node) = node {
            self.start_listener(session.clone(), node);
        }
        if let Some(account) = self.account() {
            let registry = client::registry::RegistryClient::new(&account.registry_url)?;
            if account.is_expired(now() as i64) {
                if registry.get_record(&account.account_id)?.as_ref() != Some(&record) {
                    bail!("log in again to publish profile or device changes");
                }
            } else {
                registry.put_record(&account, &record)?;
            }
            session
                .network
                .use_registry(account.registry_url, record.record.user_id.clone());
        }
        session.device_current.store(true, Ordering::Release);
        Ok(profile_info(&record))
    }

    fn listener_or_start(&self, session: &Session) -> Result<Option<libp2p_net::Libp2pNode>> {
        if session.listener_started.load(Ordering::Acquire) {
            return Ok(None);
        }
        let listen_addr = libp2p_net::quic_listen_multiaddr("0.0.0.0:0")
            .map_err(|error| anyhow!("could not create direct listener: {error}"))?;
        let mut node =
            libp2p_net::Libp2pNode::new(session.identity.device_secret(), Some(listen_addr))
                .map_err(|error| anyhow!("could not start direct listener: {error}"))?;
        node.listen_addr()
            .map_err(|error| anyhow!("could not open direct listener: {error}"))?;
        Ok(Some(node))
    }

    fn start_listener(&self, session: Session, mut node: libp2p_net::Libp2pNode) {
        session.network.set_libp2p(node.dialer());
        session.listener_started.store(true, Ordering::Release);
        let events = Arc::clone(&self.events);
        let worker_count = thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(2)
            .max(2);
        let (connections, receiver) = mpsc::sync_channel(worker_count * 4);
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..worker_count {
            let receiver = Arc::clone(&receiver);
            let worker = session.clone();
            let worker_events = Arc::clone(&events);
            thread::spawn(move || {
                while worker.network.is_running() {
                    let connection = {
                        let Ok(receiver) = receiver.lock() else {
                            return;
                        };
                        match receiver.recv_timeout(Duration::from_secs(1)) {
                            Ok(connection) => connection,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Err(mpsc::RecvTimeoutError::Disconnected) => return,
                        }
                    };
                    serve_mobile_connection(connection, &worker, &worker_events);
                }
            });
        }

        thread::spawn(move || {
            while session.network.is_running() {
                let connection = match node.accept_timeout(Duration::from_secs(1)) {
                    Ok(Some(connection)) => connection,
                    Ok(None) => continue,
                    Err(error) => {
                        if !session.network.is_running() {
                            return;
                        }
                        push_event(
                            &events,
                            ClientEvent {
                                kind: EventKind::Error,
                                message: format!("Incoming connection stopped: {error}"),
                                user_id: None,
                            },
                        );
                        return;
                    }
                };
                match connections.try_send(connection) {
                    Ok(()) | Err(mpsc::TrySendError::Full(_)) => {}
                    Err(mpsc::TrySendError::Disconnected(_)) => return,
                }
            }
        });
    }

    fn send_text_inner(&self, user_id: String, text: String) -> Result<DeliveryState> {
        let session = self.require_current_session()?;
        let text = text.trim();
        if text.is_empty() {
            bail!("write a message first");
        }
        let own_record = lock(&session.own_record, "profile")?
            .clone()
            .ok_or_else(|| anyhow!("finish setting up your profile"))?;
        let app = AppMessage {
            id: random_id(),
            timestamp: now(),
            expires_at: None,
            body: Body::Text(text.to_string()),
        };
        // HTTP discovery must not occupy the local-store lock. If it fails, the
        // last authenticated signed record remains the safe fallback.
        let refreshed = client::registry::RegistryClient::new(&self.registry_url)
            .and_then(|registry| registry.get_record_for_user(&user_id))
            .ok()
            .flatten();
        let mut store = lock(&session.store, "local store")?;
        if let Some(record) = refreshed {
            let _ = client::apply_registry_record(&mut *store, &user_id, record);
        }
        let (peer, peer_record) =
            client::resolve_local_record(&mut *store, &user_id).map_err(trust_error)?;
        let info =
            client::verification_info_for_record(&*store, &session.identity, &peer, &peer_record)?;
        if !matches!(info.level, TrustLevel::Pinned | TrustLevel::Verified) {
            bail!("add this person before messaging them");
        }
        let now = now();
        let mut prepared: Vec<(String, Device, MailItem)> = Vec::new();
        let mut deliver = |store: &mut mycellium_storage::filestore::FileTransaction<'_>,
                           handle: &Handle,
                           record: &SignedRecord,
                           device: &Device,
                           item: MailItem,
                           pairwise_plaintext: Option<Vec<u8>>| {
            let delivery_id = client::delivery_id_for_item(&item);
            let parked = match pairwise_plaintext {
                Some(plaintext) => client::park_pairwise_outbox(
                    store,
                    delivery_id.clone(),
                    handle,
                    record,
                    device,
                    item.clone(),
                    plaintext,
                    now,
                ),
                None => client::park_outbox(
                    store,
                    delivery_id.clone(),
                    handle,
                    record,
                    device,
                    item.clone(),
                    now,
                ),
            };
            match parked {
                Ok(()) => {
                    prepared.push((delivery_id, device.clone(), item));
                    mycellium_engine::reachability::DeliveryPath::Outbox
                }
                Err(_) => mycellium_engine::reachability::DeliveryPath::Failed,
            }
        };
        let mut transaction = store.transaction();
        let mut outcome = client::send_direct(
            &session.identity,
            &mut transaction,
            &mut OsPlatform,
            &own_record.record.handle,
            &peer,
            &peer_record,
            &app,
            &mut deliver,
        )?;
        transaction.commit()?;
        drop(store);

        for (delivery_id, device, item) in prepared {
            if client::attempt_parked_delivery(
                &session.store,
                &session.network,
                &device,
                &delivery_id,
                &item,
                now,
            )? {
                outcome.outboxed = outcome.outboxed.saturating_sub(1);
                outcome.direct += 1;
                outcome.delivered += 1;
            }
        }
        if outcome.direct > 0 {
            Ok(DeliveryState::Delivered)
        } else if outcome.outboxed > 0 {
            Ok(DeliveryState::Pending)
        } else {
            bail!("message could not be sent or saved for retry")
        }
    }

    fn start_workers(&self) {
        let Ok(session) = self.require_session() else {
            return;
        };
        if !self.outbox_started.swap(true, Ordering::AcqRel) {
            let events = Arc::clone(&self.events);
            let worker = session.clone();
            thread::spawn(move || {
                while worker.network.is_running() {
                    thread::sleep(Duration::from_secs(5));
                    if !worker.network.is_running() {
                        return;
                    }
                    if !worker.device_current.load(Ordering::Acquire) {
                        continue;
                    }
                    if let Ok(result) = client::flush_shared_outbox(
                        &worker.identity,
                        &mut OsPlatform,
                        &worker.store,
                        &worker.network,
                        now(),
                    ) {
                        if result.delivered > 0 {
                            push_event(
                                &events,
                                ClientEvent {
                                    kind: EventKind::Delivered,
                                    message: format!(
                                        "Delivered {} pending message(s)",
                                        result.delivered
                                    ),
                                    user_id: None,
                                },
                            );
                        }
                    }
                }
            });
        }
        if let Some(account) = self
            .account()
            .filter(|_| !self.monitor_started.swap(true, Ordering::AcqRel))
        {
            let registry_url = account.registry_url.clone();
            let account_id = account.account_id;
            let events = Arc::clone(&self.events);
            let current = Arc::clone(&session.device_current);
            let network = session.network.clone();
            let wallet_user_id = user_id(&session.identity.wallet_public());
            let device_key = session.identity.device_public();
            thread::spawn(move || {
                let Ok(registry) = client::registry::RegistryClient::new(registry_url) else {
                    return;
                };
                while network.is_running() {
                    if let Ok(Some(record)) = registry.get_record(&account_id) {
                        let is_current = record.record.user_id == wallet_user_id
                            && record.record.device.device_key == device_key;
                        let was_current = current.swap(is_current, Ordering::AcqRel);
                        if was_current && !is_current {
                            push_event(
                                &events,
                                ClientEvent {
                                    kind: EventKind::DeviceReplaced,
                                    message: "This device was replaced. Sending is disabled."
                                        .into(),
                                    user_id: None,
                                },
                            );
                        }
                    }
                    for _ in 0..60 {
                        if !network.is_running() {
                            return;
                        }
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            });
        }
    }

    fn refresh_device_status_inner(&self) -> Result<ClientState> {
        let session = self.require_session()?;
        let Some(account) = self.account() else {
            return Ok(self.current_state());
        };
        if let Some(record) = client::registry::RegistryClient::new(&account.registry_url)?
            .get_record(&account.account_id)?
        {
            let current = record.record.user_id == user_id(&session.identity.wallet_public())
                && record.record.device.device_key == session.identity.device_public();
            session.device_current.store(current, Ordering::Release);
        }
        Ok(self.current_state())
    }

    fn profile_inner(&self) -> Result<Option<ProfileInfo>> {
        let session = match self.require_session() {
            Ok(session) => session,
            Err(_) => return Ok(None),
        };
        let record = lock(&session.own_record, "profile")?
            .clone()
            .or(local_own_record(&session)?);
        Ok(record.as_ref().map(profile_info))
    }

    fn current_state(&self) -> ClientState {
        let Ok(inner) = self.inner.lock() else {
            return ClientState::NeedsLogin;
        };
        let Some(session) = inner.session.as_ref() else {
            return ClientState::NeedsLogin;
        };
        if !session.device_current.load(Ordering::Acquire) {
            return ClientState::Replaced;
        }
        let has_profile = session
            .own_record
            .lock()
            .ok()
            .and_then(|record| record.as_ref().map(|_| ()))
            .is_some();
        if has_profile {
            ClientState::Ready
        } else if inner.account.is_some() {
            ClientState::NeedsProfile
        } else {
            ClientState::NeedsLogin
        }
    }

    fn account(&self) -> Option<client::registry::RegistrySession> {
        self.inner.lock().ok()?.account.clone()
    }

    fn require_session(&self) -> Result<Session> {
        self.inner
            .lock()
            .map_err(|_| anyhow!("client lock poisoned"))?
            .session
            .clone()
            .ok_or_else(|| anyhow!("log in first"))
    }

    fn require_current_session(&self) -> Result<Session> {
        let session = self.require_session()?;
        if !session.device_current.load(Ordering::Acquire) {
            bail!("this device was replaced; log in to make it active again");
        }
        Ok(session)
    }
}

impl Drop for MobileClient {
    fn drop(&mut self) {
        if let Ok(inner) = self.inner.lock() {
            if let Some(session) = inner.session.as_ref() {
                session.device_current.store(false, Ordering::Release);
                session.network.shutdown();
            }
        }
    }
}

fn serve_mobile_connection(
    mut connection: libp2p_net::Libp2pConnection,
    session: &Session,
    events: &Arc<Mutex<VecDeque<ClientEvent>>>,
) {
    while session.network.is_running() {
        let Ok(bytes) = connection.recv_frame() else {
            return;
        };
        if !session.device_current.load(Ordering::Acquire) {
            return;
        }
        let Ok(PeerFrame::Delivery { delivery_id, item }) = wire::decode::<PeerFrame>(&bytes)
        else {
            continue;
        };
        let Some(sender_device) = client::mail_item_sender_device(&item) else {
            continue;
        };
        let Ok(sender_peer) = libp2p_net::peer_id_for_device(&sender_device) else {
            continue;
        };
        if sender_peer != connection.peer_id() {
            continue;
        }
        let Some(record) = session
            .own_record
            .lock()
            .ok()
            .and_then(|record| record.clone())
        else {
            continue;
        };
        let me = record.record.handle.clone();
        let acknowledgement = {
            let Ok(mut store) = session.store.lock() else {
                return;
            };
            let mut sink = EventSink {
                events: Arc::clone(events),
            };
            client::accept_delivery(
                &session.identity,
                &me,
                &record,
                &mut OsPlatform,
                &mut store,
                delivery_id,
                *item,
                &mut sink,
            )
        };
        if let Some(frame) = acknowledgement {
            let _ = connection.send_frame(&frame);
        }
    }
}

fn open_session(data_dir: &std::path::Path, identity: Identity) -> Result<Session> {
    let identity = Arc::new(identity);
    let store = FileStore::open(data_dir.join("history"), identity.storage_key())?;
    let own_record = client::list_records(&store)?
        .into_iter()
        .find(|entry| entry.record.record.wallet == identity.wallet_public())
        .map(|entry| entry.record);
    Ok(Session {
        network: client::DirectNetwork::new(identity.device_secret()),
        identity,
        store: Arc::new(Mutex::new(store)),
        own_record: Arc::new(Mutex::new(own_record)),
        listener_started: Arc::new(AtomicBool::new(false)),
        device_current: Arc::new(AtomicBool::new(true)),
    })
}

fn encode_identity_secret(identity: &Identity) -> Vec<u8> {
    let mut secret = Vec::with_capacity(IDENTITY_SECRET_LEN);
    secret.extend_from_slice(&identity.wallet_secret());
    secret.extend_from_slice(&identity.device_seed());
    secret
}

fn decode_identity_secret(secret: &[u8]) -> Result<Identity> {
    if secret.len() != IDENTITY_SECRET_LEN {
        bail!("secure identity is malformed");
    }
    let mut wallet = [0u8; 32];
    let mut device = [0u8; 32];
    wallet.copy_from_slice(&secret[..32]);
    device.copy_from_slice(&secret[32..]);
    Identity::from_wallet_secret(wallet, device).map_err(|_| anyhow!("secure identity is invalid"))
}

fn save_account_session(
    store: &mut FileStore,
    session: &client::registry::RegistrySession,
) -> Result<()> {
    store.put(REGISTRY_SESSION_KEY, &wire::encode(session))?;
    Ok(())
}

fn load_account_session(store: &FileStore) -> Result<Option<client::registry::RegistrySession>> {
    let Some(bytes) = store.get(REGISTRY_SESSION_KEY)? else {
        return Ok(None);
    };
    wire::decode(&bytes)
        .map(Some)
        .map_err(|_| anyhow!("stored registry login is corrupt"))
}

fn local_own_record(session: &Session) -> Result<Option<SignedRecord>> {
    let store = lock(&session.store, "local store")?;
    Ok(client::list_records(&*store)?
        .into_iter()
        .find(|entry| entry.record.record.wallet == session.identity.wallet_public())
        .map(|entry| entry.record))
}

fn profile_info(record: &SignedRecord) -> ProfileInfo {
    ProfileInfo {
        user_id: record.record.user_id.as_str().to_string(),
        handle: record.record.handle.as_str().to_string(),
        display_name: display_name(record),
        connection_card: client::encode_record(record),
    }
}

fn display_name(record: &SignedRecord) -> String {
    if record.record.name.trim().is_empty() {
        record.record.handle.as_str().to_string()
    } else {
        record.record.name.clone()
    }
}

fn record_for_user(store: &FileStore, user_id: &str) -> Result<SignedRecord> {
    let user_id = UserId::new(user_id.to_string()).map_err(|_| anyhow!("invalid user identity"))?;
    client::list_records(store)?
        .into_iter()
        .find(|entry| entry.user_id == user_id.as_str())
        .map(|entry| entry.record)
        .ok_or_else(|| anyhow!("this person's signed record is missing"))
}

fn trust_label(level: TrustLevel) -> &'static str {
    match level {
        TrustLevel::Verified => "Verified",
        TrustLevel::Pinned => "Saved",
        TrustLevel::Changed => "Identity changed",
        TrustLevel::Unverified => "Unverified",
    }
}

fn trust_error(error: flow::TrustError) -> anyhow::Error {
    match error {
        flow::TrustError::IdentityChanged => {
            anyhow!("their identity changed; review it before sending")
        }
        flow::TrustError::StaleRecord => anyhow!("their saved identity record is stale"),
        flow::TrustError::Unverified => anyhow!("their identity record is invalid"),
        flow::TrustError::BadHandle => anyhow!("person not found; add their connection card first"),
    }
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    OsPlatform.fill_random(&mut bytes);
    hex(&bytes)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn push_event(events: &Arc<Mutex<VecDeque<ClientEvent>>>, event: ClientEvent) {
    if let Ok(mut events) = events.lock() {
        const MAX_EVENTS: usize = 256;
        if events.len() == MAX_EVENTS {
            events.pop_front();
        }
        events.push_back(event);
    }
}

fn lock<'a, T>(mutex: &'a Mutex<T>, label: &str) -> Result<std::sync::MutexGuard<'a, T>> {
    mutex.lock().map_err(|_| anyhow!("{label} lock poisoned"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn identity_secret_round_trips_without_exposing_a_passphrase() {
        let identity = client::create_identity(&mut OsPlatform).unwrap();
        let wallet = identity.wallet_public();
        let device = identity.device_public();
        let mut secret = encode_identity_secret(&identity);
        let restored = decode_identity_secret(&secret).unwrap();
        secret.zeroize();
        assert_eq!(restored.wallet_public(), wallet);
        assert_eq!(restored.device_public(), device);
    }

    #[test]
    fn event_queue_is_bounded() {
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        for index in 0..300 {
            push_event(
                &queue,
                ClientEvent {
                    kind: EventKind::Notice,
                    message: index.to_string(),
                    user_id: None,
                },
            );
        }
        let queue = queue.lock().unwrap();
        assert_eq!(queue.len(), 256);
        assert_eq!(queue.front().unwrap().message, "44");
    }

    #[test]
    fn fresh_client_requires_login_and_rejects_local_input_errors() {
        let root = TempDir::new().unwrap();
        let client = MobileClient::open(
            root.path().display().to_string(),
            None,
            Some("http://127.0.0.1:1".into()),
        )
        .unwrap();

        assert_eq!(client.state(), ClientState::NeedsLogin);
        assert!(client.profile().unwrap().is_none());
        assert!(client.request_email_login("  ".into()).is_err());
        assert!(client.confirm_email_login("  ".into()).is_err());
        assert!(client
            .save_profile("valid_handle".into(), "Valid Name".into())
            .is_err());
        assert!(client.add_contact("not-a-card".into(), None).is_err());
        assert!(client
            .send_text("invalid-user".into(), "hello".into())
            .is_err());
        assert!(client.pending_count().is_err());
        assert!(client.refresh_connectivity().is_err());
    }

    #[test]
    fn malformed_secure_identity_lengths_and_values_fail_closed() {
        for secret in [vec![1; 63], vec![1; 65], vec![0; 64]] {
            let root = TempDir::new().unwrap();
            let error = MobileClient::open(
                root.path().display().to_string(),
                Some(secret),
                Some("http://127.0.0.1:1".into()),
            )
            .err()
            .expect("malformed secure identity was accepted");
            assert!(error.to_string().contains("identity"));
        }
    }

    #[test]
    fn invalid_registry_url_is_rejected_before_state_is_kept() {
        let root = TempDir::new().unwrap();
        let error = MobileClient::open(
            root.path().display().to_string(),
            None,
            Some("registry.example.test".into()),
        )
        .err()
        .expect("invalid registry URL was accepted");
        assert!(error.to_string().contains("https:// or http://"));
    }

    #[test]
    fn corrupt_saved_registry_session_prevents_client_startup() {
        let root = TempDir::new().unwrap();
        let identity = client::create_identity(&mut OsPlatform).unwrap();
        let secret = encode_identity_secret(&identity);
        let mut store = FileStore::open(root.path().join("history"), identity.storage_key())
            .expect("open local store");
        store
            .put(REGISTRY_SESSION_KEY, b"not a registry session")
            .expect("write corrupt session");
        drop(store);

        let error = MobileClient::open(
            root.path().display().to_string(),
            Some(secret),
            Some("http://127.0.0.1:1".into()),
        )
        .err()
        .expect("corrupt registry session was accepted");
        assert!(error
            .to_string()
            .contains("stored registry login is corrupt"));
    }
}
