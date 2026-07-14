//! Native Linux Mycellium client.
//!
//! The window owns presentation and local unlock UX. Protocol, trust, storage,
//! and delivery behavior remain in `mycellium-client`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, Sender},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use eframe::egui;

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
use mycellium_storage::store;
use mycellium_transport::reticulum_net::InboundFrame;
use zeroize::{Zeroize, Zeroizing};

const CANVAS: egui::Color32 = egui::Color32::from_rgb(14, 18, 25);
const SIDEBAR: egui::Color32 = egui::Color32::from_rgb(18, 23, 32);
const SURFACE: egui::Color32 = egui::Color32::from_rgb(25, 31, 43);
const SURFACE_RAISED: egui::Color32 = egui::Color32::from_rgb(32, 40, 54);
const BORDER: egui::Color32 = egui::Color32::from_rgb(48, 58, 74);
const TEXT: egui::Color32 = egui::Color32::from_rgb(239, 243, 240);
const MUTED: egui::Color32 = egui::Color32::from_rgb(145, 156, 170);
const MOSS: egui::Color32 = egui::Color32::from_rgb(118, 184, 154);
const SPORE: egui::Color32 = egui::Color32::from_rgb(226, 183, 105);
const DANGER: egui::Color32 = egui::Color32::from_rgb(232, 121, 121);
const REGISTRY_SESSION_KEY: &[u8] = b"linux:registry-session:v1";

fn main() -> eframe::Result {
    let login_link = std::env::args().find(|argument| argument.starts_with("mycellium://"));
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([860.0, 580.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Mycellium",
        options,
        Box::new(move |cc| {
            let mut client = LinuxClient::new(cc);
            if let Some(link) = login_link {
                match client::registry::login_token_from_link(&link) {
                    Ok(token) => {
                        client.login_code = token;
                        client.account_login_open = true;
                        client.login_requested = true;
                        client.confirm_email_login();
                    }
                    Err(error) => client.error = error.to_string(),
                }
            }
            Ok(Box::new(client))
        }),
    )
}

struct OsPlatform;

impl Platform for OsPlatform {
    fn fill_random(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("OS RNG must be available");
    }

    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Messages,
    People,
    Device,
}

struct Session {
    identity: Arc<Identity>,
    store: Arc<Mutex<FileStore>>,
    network: client::DirectNetwork,
    own_record: Arc<Mutex<Option<SignedRecord>>>,
    listener_active: bool,
    device_current: Arc<AtomicBool>,
}

enum RuntimeEvent {
    Flow(FlowEvent),
    Notice(String),
    Error(String),
    LoginRequested(i64),
    AccountAuthenticated(Box<AccountContext>),
    DeviceCurrent(bool),
    MessageFinished {
        user_id: String,
        draft: String,
        result: std::result::Result<String, String>,
    },
}

struct AccountContext {
    login: client::registry::ConfirmedLogin,
    recovery: Option<Zeroizing<[u8; 32]>>,
    record: Option<SignedRecord>,
}

struct EventSink {
    sender: Sender<RuntimeEvent>,
    ctx: egui::Context,
}

impl flow::FlowSink for EventSink {
    fn emit(&mut self, event: FlowEvent) {
        let _ = self.sender.send(RuntimeEvent::Flow(event));
        self.ctx.request_repaint();
    }
}

struct LinuxClient {
    ctx: egui::Context,
    data_dir: PathBuf,
    identity_exists: bool,
    registry_url: String,
    account: Option<client::registry::RegistrySession>,
    email: String,
    login_code: String,
    login_requested: bool,
    account_login_open: bool,
    account_busy: bool,
    pending_recovery: Option<Zeroizing<[u8; 32]>>,
    recovery_record: Option<SignedRecord>,
    device_replaced: bool,
    account_monitor_started: bool,
    passphrase: String,
    passphrase_confirmation: String,
    display_name: String,
    my_handle: String,
    record_blob: String,
    session: Option<Session>,
    events_tx: Sender<RuntimeEvent>,
    events_rx: Receiver<RuntimeEvent>,
    view: View,
    notice: String,
    error: String,

    selected_user_id: String,
    new_recipient: String,
    conversation_filter: String,
    message: String,
    drafts: HashMap<String, String>,
    message_busy: bool,

    adding_person: bool,
    contact_nickname: String,
    contact_card: String,
    selected_contact_user_id: String,
}

impl LinuxClient {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        configure_style(&cc.egui_ctx);
        let data_dir = default_data_dir();
        let identity_exists = store::exists_in(&data_dir);
        let configured_registry = std::env::var("MYCELLIUM_REGISTRY_URL")
            .unwrap_or_else(|_| client::registry::DEFAULT_REGISTRY_URL.to_string());
        let (events_tx, events_rx) = mpsc::channel();
        Self {
            ctx: cc.egui_ctx.clone(),
            data_dir,
            identity_exists,
            registry_url: configured_registry,
            account: None,
            email: String::new(),
            login_code: String::new(),
            login_requested: false,
            account_login_open: false,
            account_busy: false,
            pending_recovery: None,
            recovery_record: None,
            device_replaced: false,
            account_monitor_started: false,
            passphrase: String::new(),
            passphrase_confirmation: String::new(),
            display_name: String::new(),
            my_handle: String::new(),
            record_blob: String::new(),
            session: None,
            events_tx,
            events_rx,
            view: View::Messages,
            notice: String::new(),
            error: String::new(),
            selected_user_id: String::new(),
            new_recipient: String::new(),
            conversation_filter: String::new(),
            message: String::new(),
            drafts: HashMap::new(),
            message_busy: false,
            adding_person: false,
            contact_nickname: String::new(),
            contact_card: String::new(),
            selected_contact_user_id: String::new(),
        }
    }

    fn session_mut(&mut self) -> Result<&mut Session> {
        self.session
            .as_mut()
            .ok_or_else(|| anyhow!("unlock this device first"))
    }

    fn run(&mut self, ok: &str, action: impl FnOnce(&mut Self) -> Result<()>) {
        self.error.clear();
        self.notice.clear();
        match action(self) {
            Ok(()) => self.notice = ok.to_string(),
            Err(error) => self.error = error.to_string(),
        }
    }

    fn request_email_login(&mut self) {
        self.error.clear();
        self.notice.clear();
        if self.email.trim().is_empty() {
            self.error = "enter your email address".into();
            return;
        }
        let registry_url = self.registry_url.clone();
        let email = self.email.trim().to_string();
        let events = self.events_tx.clone();
        let ctx = self.ctx.clone();
        self.account_busy = true;
        thread::spawn(move || {
            let result = client::registry::RegistryClient::new(registry_url)
                .and_then(|registry| registry.request_email_login(&email));
            let event = match result {
                Ok(expires_at) => RuntimeEvent::LoginRequested(expires_at),
                Err(error) => RuntimeEvent::Error(error.to_string()),
            };
            let _ = events.send(event);
            ctx.request_repaint();
        });
    }

    fn confirm_email_login(&mut self) {
        self.error.clear();
        self.notice.clear();
        if self.login_code.trim().is_empty() {
            self.error = "enter the code from your email".into();
            return;
        }
        let registry_url = self.registry_url.clone();
        let token = self.login_code.trim().to_string();
        self.login_code.zeroize();
        let events = self.events_tx.clone();
        let ctx = self.ctx.clone();
        self.account_busy = true;
        thread::spawn(move || {
            let result = (|| {
                let registry = client::registry::RegistryClient::new(registry_url)?;
                let login = registry.confirm_login(&token)?;
                let recovery = registry.get_recovery(&login.session)?;
                let record = registry.get_record(&login.session.account_id)?;
                Ok::<_, anyhow::Error>((login, recovery, record))
            })();
            let event = match result {
                Ok((login, recovery, record)) => {
                    RuntimeEvent::AccountAuthenticated(Box::new(AccountContext {
                        login,
                        recovery: recovery.map(Zeroizing::new),
                        record,
                    }))
                }
                Err(error) => RuntimeEvent::Error(error.to_string()),
            };
            let _ = events.send(event);
            ctx.request_repaint();
        });
    }

    fn accept_account(
        &mut self,
        login: client::registry::ConfirmedLogin,
        recovery: Option<Zeroizing<[u8; 32]>>,
        record: Option<SignedRecord>,
    ) -> Result<()> {
        if self
            .account
            .as_ref()
            .is_some_and(|existing| existing.account_id != login.session.account_id)
        {
            bail!("that email belongs to a different Mycellium account");
        }
        if let Some(local) = self.session.as_ref() {
            let wallet_secret = local.identity.wallet_secret();
            if recovery
                .as_ref()
                .is_some_and(|stored| stored.as_ref() != wallet_secret)
            {
                bail!("this registry account belongs to a different Mycellium identity");
            }
            let local_user_id = user_id(&local.identity.wallet_public());
            if record
                .as_ref()
                .is_some_and(|stored| stored.record.user_id != local_user_id)
            {
                bail!("this registry account publishes a different Mycellium identity");
            }
            let registry = client::registry::RegistryClient::new(&login.session.registry_url)?;
            if recovery.is_none() {
                registry.put_recovery(&login.session, &wallet_secret)?;
            }
            let own_record = {
                let store = local
                    .store
                    .lock()
                    .map_err(|_| anyhow!("local store lock poisoned"))?;
                client::list_records(&*store)?
                    .into_iter()
                    .find(|entry| entry.user_id == local_user_id.as_str())
                    .map(|entry| entry.record)
            };
            if record.is_none() {
                if let Some(own_record) = own_record {
                    registry.put_record(&login.session, &own_record)?;
                }
            }
            if let Some(remote) = &record {
                let current = client::is_current_device(&local.identity, remote);
                local.device_current.store(current, Ordering::Release);
                self.device_replaced = !current;
            }
        } else {
            if recovery.is_none() && record.is_some() {
                bail!("this account has an identity record but no recovery material");
            }
            self.pending_recovery = recovery;
            self.recovery_record = record;
            if let Some(record) = &self.recovery_record {
                self.my_handle = record.record.handle.as_str().to_string();
                self.display_name = record.record.name.clone();
            }
        }

        if let Some(local) = self.session.as_ref() {
            let mut store = local
                .store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            save_account_session(&mut store, &login.session)?;
        }
        self.registry_url = login.session.registry_url.clone();
        self.account = Some(login.session);
        self.email.clear();
        self.login_requested = false;
        self.account_login_open = false;
        self.notice = if login.created {
            "Email verified. Set up this device.".into()
        } else {
            "Email verified".into()
        };
        if self.session.is_some() {
            self.start_account_monitor();
        }
        Ok(())
    }

    fn unlock(&mut self) {
        self.run("Welcome back", |this| {
            let identity =
                store::load_identity_with_passphrase_from(&this.data_dir, &this.passphrase)?;
            this.open_session(identity)?;
            this.passphrase.zeroize();
            this.restore_profile()
        });
    }

    fn create_identity(&mut self) {
        self.run("This device is ready", |this| {
            if this.identity_exists {
                bail!("an identity already exists on this device");
            }
            let account = this
                .account
                .clone()
                .ok_or_else(|| anyhow!("verify your email first"))?;
            if this.passphrase != this.passphrase_confirmation {
                bail!("passphrases do not match");
            }
            if this.passphrase.chars().count() < store::MIN_PASSPHRASE_LEN {
                bail!(
                    "passphrase must be at least {} characters",
                    store::MIN_PASSPHRASE_LEN
                );
            }
            let handle =
                Handle::new(this.my_handle.trim()).map_err(|_| anyhow!("choose a valid handle"))?;
            if this.display_name.trim().is_empty() {
                this.display_name = handle.as_str().to_string();
            }
            let recovery = this.pending_recovery.as_ref().map(|secret| **secret);
            let identity = match recovery {
                Some(wallet_secret) => client::adopt_identity(&mut OsPlatform, wallet_secret)?,
                None => client::create_identity(&mut OsPlatform)?,
            };
            if recovery.is_none() {
                client::registry::RegistryClient::new(&account.registry_url)?
                    .put_recovery(&account, &identity.wallet_secret())?;
                this.pending_recovery = Some(Zeroizing::new(identity.wallet_secret()));
            }
            store::save_identity_with_passphrase_at(&this.data_dir, &identity, &this.passphrase)?;
            this.identity_exists = true;
            this.open_session(identity)?;
            {
                let session = this.session_mut()?;
                let mut store = session
                    .store
                    .lock()
                    .map_err(|_| anyhow!("local store lock poisoned"))?;
                save_account_session(&mut store, &account)?;
            }
            this.passphrase.zeroize();
            this.passphrase_confirmation.zeroize();
            this.pending_recovery = None;
            this.recovery_record = None;
            this.publish_profile()?;
            this.start_account_monitor();
            Ok(())
        });
    }

    fn open_session(&mut self, identity: Identity) -> Result<()> {
        let store = open_history(&self.data_dir, &identity)?;
        if let Some(account) = load_account_session(&store)? {
            self.account_login_open = account.is_expired(OsPlatform.now_unix_secs() as i64);
            self.registry_url = account.registry_url.clone();
            self.account = Some(account);
        }
        let own_record = client::list_records(&store)?
            .into_iter()
            .find(|entry| entry.record.record.wallet == identity.wallet_public())
            .map(|entry| entry.record);
        let identity = Arc::new(identity);
        let network = client::DirectNetwork::new(identity.reticulum_private_bytes());
        let store = Arc::new(Mutex::new(store));
        let current = Arc::new(AtomicBool::new(true));
        self.session = Some(Session {
            identity: Arc::clone(&identity),
            store: Arc::clone(&store),
            network: network.clone(),
            own_record: Arc::new(Mutex::new(own_record)),
            listener_active: false,
            device_current: Arc::clone(&current),
        });
        self.start_outbox_worker(identity, store, network, current);
        Ok(())
    }

    fn start_outbox_worker(
        &self,
        identity: Arc<Identity>,
        store: Arc<Mutex<FileStore>>,
        network: client::DirectNetwork,
        device_current: Arc<AtomicBool>,
    ) {
        let events = self.events_tx.clone();
        let ctx = self.ctx.clone();
        thread::spawn(move || {
            while network.is_running() {
                thread::sleep(Duration::from_secs(5));
                if !network.is_running() {
                    return;
                }
                if !device_current.load(Ordering::Acquire) {
                    continue;
                }
                let now = OsPlatform.now_unix_secs();
                let Ok(result) =
                    client::flush_shared_outbox(&identity, &mut OsPlatform, &store, &network, now)
                else {
                    continue;
                };
                if result.delivered > 0 {
                    let noun = if result.delivered == 1 {
                        "message"
                    } else {
                        "messages"
                    };
                    let _ = events.send(RuntimeEvent::Notice(format!(
                        "Delivered {} pending {noun}",
                        result.delivered
                    )));
                    ctx.request_repaint();
                }
            }
        });
    }

    fn restore_profile(&mut self) -> Result<()> {
        let (identity, store) = {
            let session = self.session_mut()?;
            (Arc::clone(&session.identity), Arc::clone(&session.store))
        };
        let record = {
            let store = store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            client::list_records(&*store)?
                .into_iter()
                .find(|entry| entry.record.record.wallet == identity.wallet_public())
                .map(|entry| entry.record)
        };
        let Some(record) = record else {
            self.view = View::Device;
            self.start_account_monitor();
            return Ok(());
        };
        self.my_handle = record.record.handle.as_str().to_string();
        self.display_name = record.record.name.clone();
        if record.record.device.device_key != identity.device_public() {
            self.record_blob = client::encode_record(&record);
            self.view = View::Device;
        } else {
            self.publish_profile()?;
        }
        self.start_account_monitor();
        Ok(())
    }

    fn publish_profile(&mut self) -> Result<()> {
        let handle =
            Handle::new(self.my_handle.trim()).map_err(|_| anyhow!("choose a valid handle"))?;
        let name = if self.display_name.trim().is_empty() {
            handle.as_str().to_string()
        } else {
            self.display_name.trim().to_string()
        };
        let account = self.account.clone();
        let (identity, store, own_record, device_current) = {
            let session = self.session_mut()?;
            (
                Arc::clone(&session.identity),
                Arc::clone(&session.store),
                Arc::clone(&session.own_record),
                Arc::clone(&session.device_current),
            )
        };
        let start_listener = self.listener_or_start(&identity)?;
        let record = {
            let mut store_guard = store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            client::publish_active_device_record(
                &mut *store_guard,
                &mut OsPlatform,
                &identity,
                &handle,
                &name,
            )?
        };
        if let Some(account) = &account {
            let registry = client::registry::RegistryClient::new(&account.registry_url)?;
            if account.is_expired(OsPlatform.now_unix_secs() as i64) {
                if registry.get_record(&account.account_id)?.as_ref() != Some(&record) {
                    bail!("log in again to publish profile or device changes");
                }
            } else {
                registry.put_record(account, &record)?;
            }
            device_current.store(true, Ordering::Release);
            self.device_replaced = false;
        }
        self.my_handle = handle.as_str().to_string();
        self.display_name = name;
        self.record_blob = client::encode_record(&record);
        let user_id = record.record.user_id.clone();
        *own_record
            .lock()
            .map_err(|_| anyhow!("local profile lock poisoned"))? = Some(record);
        self.start_listener(start_listener)?;
        if let Some(account) = account {
            self.session_mut()?
                .network
                .use_registry(account.registry_url, user_id);
        }
        Ok(())
    }

    fn save_profile(&mut self) {
        self.run("Profile updated", Self::publish_profile);
    }

    fn add_person(&mut self) {
        self.run("Person added", |this| {
            let record = client::decode_record(this.contact_card.trim())?;
            let nickname = if this.contact_nickname.trim().is_empty() {
                if record.record.name.trim().is_empty() {
                    record.record.handle.as_str().to_string()
                } else {
                    record.record.name.clone()
                }
            } else {
                this.contact_nickname.trim().to_string()
            };
            let user_id = record.record.user_id.as_str().to_string();
            let session = this.session_mut()?;
            let mut store = session
                .store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            client::add_contact_from_record(&mut *store, &nickname, record)?;
            drop(store);
            this.selected_contact_user_id = user_id;
            this.contact_nickname.clear();
            this.contact_card.clear();
            this.adding_person = false;
            Ok(())
        });
    }

    fn open_conversation(&mut self) {
        self.error.clear();
        self.notice.clear();
        let input = self.new_recipient.trim().to_string();
        let result = (|| {
            if input.is_empty() {
                bail!("enter a saved name or handle");
            }
            let session = self.session_mut()?;
            let mut store = session
                .store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            let (_, record) =
                client::resolve_local_record(&mut *store, &input).map_err(|error| match error {
                    flow::TrustError::IdentityChanged => {
                        anyhow!("this person's identity changed; review it in People")
                    }
                    flow::TrustError::StaleRecord => anyhow!("the saved identity record is stale"),
                    flow::TrustError::Unverified => anyhow!("the identity record is invalid"),
                    flow::TrustError::BadHandle => {
                        anyhow!("person not found; add their connection card first")
                    }
                })?;
            let trust = client::verification_info_for_record(
                &*store,
                &session.identity,
                &record.record.handle,
                &record,
            )?
            .level;
            if !matches!(trust, TrustLevel::Pinned | TrustLevel::Verified) {
                bail!("add this person before messaging them");
            }
            Ok(record.record.user_id.as_str().to_string())
        })();
        match result {
            Ok(user_id) => {
                self.select_conversation(user_id);
                self.new_recipient.clear();
            }
            Err(error) => self.error = error.to_string(),
        }
    }

    fn select_conversation(&mut self, user_id: String) {
        if !self.selected_user_id.is_empty() && !self.message.is_empty() {
            self.drafts
                .insert(self.selected_user_id.clone(), self.message.clone());
        }
        self.selected_user_id = user_id.clone();
        self.message = self.drafts.remove(&user_id).unwrap_or_default();
        self.view = View::Messages;
    }

    fn send_message(&mut self) {
        self.error.clear();
        self.notice.clear();
        if self.message_busy {
            return;
        }
        if self.device_replaced
            || self
                .session
                .as_ref()
                .is_some_and(|session| !session.device_current.load(Ordering::Acquire))
        {
            self.error =
                "this device was replaced; log in and make it active before sending".into();
            return;
        }
        let me = match Handle::new(self.my_handle.trim()) {
            Ok(me) => me,
            Err(_) => {
                self.error = "finish setting up this device first".into();
                return;
            }
        };
        let selected_user_id = self.selected_user_id.clone();
        if selected_user_id.is_empty() {
            self.error = "choose a conversation first".into();
            return;
        }
        let text = self.message.trim().to_string();
        if text.is_empty() {
            self.error = "write a message first".into();
            return;
        }
        let Some(session) = self.session.as_ref() else {
            self.error = "unlock this device first".into();
            return;
        };
        let identity = Arc::clone(&session.identity);
        let store = Arc::clone(&session.store);
        let network = session.network.clone();
        let registry_url = self.registry_url.clone();
        let events = self.events_tx.clone();
        let ctx = self.ctx.clone();
        self.message_busy = true;
        self.message.clear();
        self.drafts.remove(&selected_user_id);
        thread::spawn(move || {
            let result = send_message_now(
                &identity,
                &store,
                &network,
                &registry_url,
                &me,
                &selected_user_id,
                &text,
            )
            .map_err(|error| error.to_string());
            let _ = events.send(RuntimeEvent::MessageFinished {
                user_id: selected_user_id,
                draft: text,
                result,
            });
            ctx.request_repaint();
        });
    }

    fn retry_outbox(&mut self) {
        self.run("Tried pending messages", |this| {
            if this.device_replaced {
                bail!("this device was replaced; pending messages remain stored locally");
            }
            let now = OsPlatform.now_unix_secs();
            let session = this.session_mut()?;
            let identity = Arc::clone(&session.identity);
            let network = session.network.clone();
            let store = Arc::clone(&session.store);
            {
                let mut guard = store
                    .lock()
                    .map_err(|_| anyhow!("local store lock poisoned"))?;
                client::make_outbox_due(&mut *guard)?;
            }
            let _ = client::flush_shared_outbox(&identity, &mut OsPlatform, &store, &network, now)?;
            Ok(())
        });
    }

    fn mark_verified(&mut self, info: client::VerificationInfo) {
        self.run("Identity verified", |this| {
            let session = this.session_mut()?;
            let mut store = session
                .store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            client::mark_verified(&mut *store, &info)
        });
    }

    fn accept_identity_change(&mut self, info: client::VerificationInfo) {
        self.run("New identity trusted", |this| {
            let session = this.session_mut()?;
            let mut store = session
                .store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            client::accept_identity_change(&mut *store, &info)
        });
    }

    fn remove_contact(&mut self, nickname: String) {
        self.run("Person removed", |this| {
            let session = this.session_mut()?;
            let mut store = session
                .store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            client::remove_contact(&mut *store, &nickname)?;
            drop(store);
            this.selected_contact_user_id.clear();
            Ok(())
        });
    }

    fn set_contact_blocked(&mut self, user_id: String, blocked: bool) {
        let notice = if blocked {
            "Person blocked"
        } else {
            "Person unblocked"
        };
        self.run(notice, |this| {
            let session = this.session_mut()?;
            let mut store = session
                .store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            client::set_blocked(&mut *store, &user_id, blocked)
        });
    }

    fn contact_blocked(&self, user_id: &str) -> Result<bool> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("unlock this device first"))?;
        let store = session
            .store
            .lock()
            .map_err(|_| anyhow!("local store lock poisoned"))?;
        Ok(client::list_blocked(&*store)?
            .iter()
            .any(|known| known == user_id))
    }

    fn verification_for(&self, user_id: &str) -> Result<client::VerificationInfo> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("unlock this device first"))?;
        let store = session
            .store
            .lock()
            .map_err(|_| anyhow!("local store lock poisoned"))?;
        let user_id = UserId::new(user_id.to_string()).map_err(|_| anyhow!("invalid user id"))?;
        let record = client::list_records(&*store)?
            .into_iter()
            .find(|entry| entry.user_id == user_id.as_str())
            .map(|entry| entry.record)
            .ok_or_else(|| anyhow!("this person's signed record is missing"))?;
        client::verification_info_for_record(
            &*store,
            &session.identity,
            &record.record.handle,
            &record,
        )
    }

    fn listener_or_start(&self, _identity: &Identity) -> Result<bool> {
        if self
            .session
            .as_ref()
            .is_some_and(|session| session.listener_active)
        {
            return Ok(false);
        }
        Ok(true)
    }

    fn start_listener(&mut self, start: bool) -> Result<()> {
        let session = self.session_mut()?;
        if session.listener_active || !start {
            return Ok(());
        }
        let node = session
            .network
            .reticulum()
            .ok_or_else(|| anyhow!("could not start Reticulum node"))?;
        session.listener_active = true;
        let identity = Arc::clone(&session.identity);
        let store = Arc::clone(&session.store);
        let own_record = Arc::clone(&session.own_record);
        let device_current = Arc::clone(&session.device_current);
        let network = session.network.clone();
        let events = self.events_tx.clone();
        let ctx = self.ctx.clone();
        thread::spawn(move || {
            while network.is_running() {
                let frame = match node.recv_timeout(Duration::from_secs(1)) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => continue,
                    Err(error) => {
                        if !network.is_running() {
                            return;
                        }
                        let _ = events.send(RuntimeEvent::Error(format!(
                            "incoming connection failed: {error}"
                        )));
                        ctx.request_repaint();
                        return;
                    }
                };
                serve_linux_connection(
                    frame,
                    &identity,
                    &store,
                    &own_record,
                    &device_current,
                    &network,
                    &events,
                    &ctx,
                );
            }
        });
        Ok(())
    }

    fn start_account_monitor(&mut self) {
        if self.account_monitor_started {
            return;
        }
        let Some(account) = self.account.clone() else {
            return;
        };
        let Some(session) = self.session.as_ref() else {
            return;
        };
        let local_user_id = user_id(&session.identity.wallet_public());
        let local_device = session.identity.device_public();
        let device_current = Arc::clone(&session.device_current);
        let network = session.network.clone();
        let events = self.events_tx.clone();
        let ctx = self.ctx.clone();
        self.account_monitor_started = true;
        thread::spawn(move || {
            let registry = match client::registry::RegistryClient::new(&account.registry_url) {
                Ok(registry) => registry,
                Err(_) => return,
            };
            while network.is_running() {
                if let Ok(Some(record)) = registry.get_record(&account.account_id) {
                    let current = record.record.user_id == local_user_id
                        && record.record.device.device_key == local_device;
                    device_current.store(current, Ordering::Release);
                    let _ = events.send(RuntimeEvent::DeviceCurrent(current));
                    ctx.request_repaint();
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

    fn drain_events(&mut self) {
        while let Ok(event) = self.events_rx.try_recv() {
            match event {
                RuntimeEvent::Flow(FlowEvent::DirectMessage { user_id, from, .. }) => {
                    if self.selected_user_id.is_empty() {
                        self.select_conversation(user_id);
                    }
                    self.notice = format!("New message from {from}");
                    self.error.clear();
                }
                RuntimeEvent::Flow(FlowEvent::GroupMessage { name, sender, .. }) => {
                    self.notice = format!("New message in {name} from {sender}");
                    self.error.clear();
                }
                RuntimeEvent::Flow(FlowEvent::GroupJoined { name, inviter, .. }) => {
                    self.notice = format!("Joined {name} from {inviter}");
                    self.error.clear();
                }
                RuntimeEvent::Flow(FlowEvent::Receipt { from, .. }) => {
                    self.notice = format!("Delivered to {from}");
                    self.error.clear();
                }
                RuntimeEvent::Flow(_) => {}
                RuntimeEvent::Notice(message) => {
                    self.notice = message;
                    self.error.clear();
                }
                RuntimeEvent::Error(message) => {
                    self.account_busy = false;
                    self.error = message;
                    self.notice.clear();
                }
                RuntimeEvent::LoginRequested(_expires_at) => {
                    self.account_busy = false;
                    self.login_requested = true;
                    self.notice = "Check your email for the login code".into();
                    self.error.clear();
                }
                RuntimeEvent::AccountAuthenticated(context) => {
                    self.account_busy = false;
                    if let Err(error) =
                        self.accept_account(context.login, context.recovery, context.record)
                    {
                        self.error = error.to_string();
                        self.notice.clear();
                    }
                }
                RuntimeEvent::DeviceCurrent(current) => {
                    self.device_replaced = !current;
                    if !current {
                        self.error = "This device was replaced. Messages are disabled.".into();
                        self.notice.clear();
                    }
                }
                RuntimeEvent::MessageFinished {
                    user_id,
                    draft,
                    result,
                } => {
                    self.message_busy = false;
                    match result {
                        Ok(message) => {
                            self.notice = message;
                            self.error.clear();
                        }
                        Err(error) => {
                            if self.selected_user_id == user_id && self.message.is_empty() {
                                self.message = draft;
                            } else {
                                self.drafts.entry(user_id).or_insert(draft);
                            }
                            self.error = error;
                            self.notice.clear();
                        }
                    }
                }
            }
        }
    }

    fn is_active(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|session| session.listener_active)
            && self
                .session
                .as_ref()
                .is_some_and(|session| session.device_current.load(Ordering::Acquire))
            && !self.my_handle.is_empty()
    }

    fn pending_count(&self) -> usize {
        self.session
            .as_ref()
            .and_then(|session| session.store.lock().ok())
            .and_then(|store| client::list_outbox(&*store).ok())
            .map(|entries| entries.iter().filter(|entry| entry.is_pending()).count())
            .unwrap_or(0)
    }

    fn contacts(&self) -> Vec<client::ContactEntry> {
        let mut contacts = self
            .session
            .as_ref()
            .and_then(|session| session.store.lock().ok())
            .and_then(|store| client::list_contacts(&*store).ok())
            .unwrap_or_default();
        contacts.sort_by_key(|contact| contact.nickname.to_lowercase());
        contacts
    }

    fn conversations(&mut self) -> Vec<client::ConversationPreview> {
        self.session
            .as_mut()
            .and_then(|session| session.store.lock().ok())
            .and_then(|mut store| {
                client::conversations(&mut *store, OsPlatform.now_unix_secs()).ok()
            })
            .unwrap_or_default()
    }

    fn history(&mut self, user_id: &str) -> Vec<mycellium_engine::history::StoredMessage> {
        self.session
            .as_mut()
            .and_then(|session| session.store.lock().ok())
            .and_then(|mut store| {
                client::history_with(&mut *store, user_id, OsPlatform.now_unix_secs())
                    .ok()
                    .map(|(_, messages)| messages)
            })
            .unwrap_or_default()
    }
}

impl eframe::App for LinuxClient {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_events();
        egui::Frame::new().fill(CANVAS).show(ui, |ui| {
            ui.set_min_size(ui.available_size());
            if self.session.is_none() {
                self.auth_view(ui);
            } else {
                self.app_view(ui);
            }
        });
    }
}

impl Drop for LinuxClient {
    fn drop(&mut self) {
        if let Some(session) = self.session.as_ref() {
            session.device_current.store(false, Ordering::Release);
            session.network.shutdown();
        }
    }
}

impl LinuxClient {
    fn auth_view(&mut self, ui: &mut egui::Ui) {
        let size = ui.available_size();
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2((size.x * 0.44).max(340.0), size.y),
                egui::Layout::top_down(egui::Align::Min),
                |ui| self.auth_brand(ui),
            );
            ui.allocate_ui_with_layout(
                ui.available_size(),
                egui::Layout::top_down(egui::Align::Center),
                |ui| self.auth_form(ui),
            );
        });
    }

    fn auth_brand(&self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .fill(SIDEBAR)
            .inner_margin(egui::Margin::same(42))
            .show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                network_mark(ui, 58.0);
                ui.add_space(34.0);
                ui.label(
                    egui::RichText::new("Messages stay\nwith people.")
                        .size(38.0)
                        .strong()
                        .color(TEXT),
                );
                ui.add_space(18.0);
                ui.label(
                    egui::RichText::new(
                        "Mycellium connects devices directly. Your identity, history, and pending messages remain yours.",
                    )
                    .size(16.0)
                    .line_height(Some(24.0))
                    .color(MUTED),
                );
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.label(
                        egui::RichText::new("Private by structure")
                            .monospace()
                            .size(12.0)
                            .color(MOSS),
                    );
                });
            });
    }

    fn auth_form(&mut self, ui: &mut egui::Ui) {
        ui.add_space(62.0);
        ui.set_max_width(410.0);
        if self.identity_exists {
            ui.label(egui::RichText::new("Welcome back").size(30.0).strong());
            ui.label(egui::RichText::new("Unlock this device to continue.").color(MUTED));
            ui.add_space(28.0);
            field_label(ui, "Passphrase");
            let response = ui.add_sized(
                [ui.available_width(), 42.0],
                singleline_input(&mut self.passphrase)
                    .password(true)
                    .hint_text("Your device passphrase"),
            );
            ui.add_space(12.0);
            let unlock = primary_button(ui, "Unlock device", ui.available_width());
            let enter = singleline_submitted(ui, &response);
            if unlock.clicked() || enter {
                self.unlock();
            }
        } else if self.account.is_none() || self.account_login_open {
            ui.label(
                egui::RichText::new(if self.login_requested {
                    "Check your email"
                } else {
                    "Continue with email"
                })
                .size(30.0)
                .strong(),
            );
            ui.label(
                egui::RichText::new("Your email opens your account on this device.").color(MUTED),
            );
            ui.add_space(24.0);
            self.account_login_fields(ui);
        } else if self.account_busy {
            ui.add_space(70.0);
            ui.spinner();
            ui.label(egui::RichText::new("Loading your account…").color(MUTED));
        } else {
            let recovering = self.pending_recovery.is_some();
            ui.label(
                egui::RichText::new(if recovering {
                    "Use your account here"
                } else {
                    "Set up this device"
                })
                .size(30.0)
                .strong(),
            );
            ui.label(
                egui::RichText::new(if recovering {
                    "Your identity will move here. Messages on the old device stay there."
                } else {
                    "Create your identity and start messaging."
                })
                .color(MUTED),
            );
            ui.add_space(22.0);
            ui.columns(2, |columns| {
                field_label(&mut columns[0], "Name");
                columns[0].add_sized(
                    [columns[0].available_width(), 40.0],
                    singleline_input(&mut self.display_name).hint_text("Ada"),
                );
                field_label(&mut columns[1], "Handle");
                columns[1].add_sized(
                    [columns[1].available_width(), 40.0],
                    singleline_input(&mut self.my_handle).hint_text("ada"),
                );
            });
            ui.add_space(10.0);
            ui.columns(2, |columns| {
                field_label(&mut columns[0], "Passphrase");
                columns[0].add_sized(
                    [columns[0].available_width(), 40.0],
                    singleline_input(&mut self.passphrase)
                        .password(true)
                        .hint_text("Protects this device"),
                );
                field_label(&mut columns[1], "Confirm");
                columns[1].add_sized(
                    [columns[1].available_width(), 40.0],
                    singleline_input(&mut self.passphrase_confirmation).password(true),
                );
            });
            ui.label(
                egui::RichText::new(
                    "This passphrase protects local data. It is not a recovery key.",
                )
                .size(12.0)
                .color(MUTED),
            );
            ui.add_space(16.0);
            let label = if recovering {
                "Use this device"
            } else {
                "Create identity"
            };
            if primary_button(ui, label, ui.available_width()).clicked() {
                self.create_identity();
            }
        }
        ui.add_space(14.0);
        self.status_banner(ui);
    }

    fn account_login_fields(&mut self, ui: &mut egui::Ui) {
        if self.login_requested {
            field_label(ui, "Login code");
            let response = ui.add_sized(
                [ui.available_width(), 42.0],
                singleline_input(&mut self.login_code).hint_text("Code from your email"),
            );
            ui.add_space(12.0);
            let clicked = ui
                .add_enabled_ui(!self.account_busy, |ui| {
                    primary_button(ui, "Log in", ui.available_width())
                })
                .inner
                .clicked();
            let enter = !self.account_busy && singleline_submitted(ui, &response);
            if clicked || enter {
                self.confirm_email_login();
            }
            ui.add_space(8.0);
            if ui
                .add_enabled(!self.account_busy, egui::Button::new("Use another email"))
                .clicked()
            {
                self.login_requested = false;
                self.login_code.zeroize();
            }
        } else {
            field_label(ui, "Email address");
            let response = ui.add_sized(
                [ui.available_width(), 42.0],
                singleline_input(&mut self.email).hint_text("you@example.com"),
            );
            ui.add_space(12.0);
            let clicked = ui
                .add_enabled_ui(!self.account_busy, |ui| {
                    primary_button(ui, "Email me a code", ui.available_width())
                })
                .inner
                .clicked();
            let enter = !self.account_busy && singleline_submitted(ui, &response);
            if clicked || enter {
                self.request_email_login();
            }
        }
        if self.account_busy {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(egui::RichText::new("Contacting the registry…").color(MUTED));
            });
        }
    }

    fn app_view(&mut self, ui: &mut egui::Ui) {
        let height = ui.available_height();
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(224.0, height),
                egui::Layout::top_down(egui::Align::Min),
                |ui| self.sidebar(ui),
            );
            ui.allocate_ui_with_layout(
                ui.available_size(),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    egui::Frame::new()
                        .inner_margin(egui::Margin::same(26))
                        .show(ui, |ui| {
                            ui.set_min_size(ui.available_size());
                            self.status_banner(ui);
                            match self.view {
                                View::Messages => self.messages_view(ui),
                                View::People => self.people_view(ui),
                                View::Device => self.device_view(ui),
                            }
                        });
                },
            );
        });
    }

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .fill(SIDEBAR)
            .inner_margin(egui::Margin::same(18))
            .show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                ui.horizontal(|ui| {
                    network_mark(ui, 32.0);
                    ui.label(egui::RichText::new("Mycellium").size(19.0).strong());
                });
                ui.add_space(34.0);
                if nav_button(ui, self.view == View::Messages, "Messages", None).clicked() {
                    self.view = View::Messages;
                }
                ui.add_space(4.0);
                if nav_button(ui, self.view == View::People, "People", None).clicked() {
                    self.view = View::People;
                }
                ui.add_space(4.0);
                let pending = self.pending_count();
                if nav_button(
                    ui,
                    self.view == View::Device,
                    "This device",
                    (pending > 0).then_some(pending),
                )
                .clicked()
                {
                    self.view = View::Device;
                }

                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    egui::Frame::new()
                        .fill(SURFACE)
                        .corner_radius(10)
                        .inner_margin(egui::Margin::same(12))
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.label(
                                egui::RichText::new(if self.display_name.is_empty() {
                                    "This device"
                                } else {
                                    &self.display_name
                                })
                                .strong(),
                            );
                            let (status, color) = if self.device_replaced {
                                ("× Device replaced", DANGER)
                            } else if self.is_active() {
                                ("● Ready for messages", MOSS)
                            } else {
                                ("○ Setup needed", SPORE)
                            };
                            ui.label(egui::RichText::new(status).size(12.0).color(color));
                        });
                });
            });
    }

    fn messages_view(&mut self, ui: &mut egui::Ui) {
        page_heading(ui, "Messages", "Direct conversations stored on this device");
        ui.add_space(18.0);
        if !self.is_active() {
            if self.device_replaced {
                callout(
                    ui,
                    DANGER,
                    "This device was replaced",
                    "History remains available. Sending and receiving are disabled until you make this device active again.",
                );
                ui.add_space(10.0);
            } else {
                callout(
                    ui,
                    SPORE,
                    "Finish device setup",
                    "Publish this device before sending or receiving messages.",
                );
                if ui.button("Open device setup").clicked() {
                    self.view = View::Device;
                }
                return;
            }
        }

        let conversations = self.conversations();
        let contacts = self.contacts();
        let panel_height = ui.available_height();
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(292.0, panel_height),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Conversations").strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if compact_button(ui, "+ New").clicked() {
                                self.selected_user_id.clear();
                                self.new_recipient.clear();
                            }
                        });
                    });
                    ui.add_space(8.0);
                    ui.add_sized(
                        [ui.available_width(), 38.0],
                        singleline_input(&mut self.conversation_filter)
                            .hint_text("Search conversations"),
                    );
                    ui.add_space(10.0);
                    let filter = self.conversation_filter.to_lowercase();
                    let mut selected = None;
                    let list_height = ui.available_height();
                    egui::ScrollArea::vertical()
                        .id_salt("conversation-list")
                        .auto_shrink([false, false])
                        .max_height(list_height)
                        .show(ui, |ui| {
                            for conversation in conversations.iter().filter(|conversation| {
                                filter.is_empty()
                                    || conversation.display_name.to_lowercase().contains(&filter)
                                    || conversation.text.to_lowercase().contains(&filter)
                            }) {
                                if conversation_row(
                                    ui,
                                    conversation,
                                    self.selected_user_id == conversation.user_id,
                                )
                                .clicked()
                                {
                                    selected = Some(conversation.user_id.clone());
                                }
                                ui.add_space(5.0);
                            }
                        });
                    if let Some(user_id) = selected {
                        self.select_conversation(user_id);
                    }
                },
            );
            ui.separator();
            ui.allocate_ui_with_layout(
                ui.available_size(),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    if self.selected_user_id.is_empty() {
                        self.new_conversation_view(ui, &contacts);
                    } else {
                        self.conversation_view(ui, &conversations, &contacts);
                    }
                },
            );
        });
    }

    fn new_conversation_view(&mut self, ui: &mut egui::Ui, contacts: &[client::ContactEntry]) {
        ui.add_space(54.0);
        ui.vertical_centered(|ui| {
            network_mark(ui, 48.0);
            ui.add_space(14.0);
            ui.label(
                egui::RichText::new("Start a conversation")
                    .size(23.0)
                    .strong(),
            );
            ui.label(
                egui::RichText::new("Choose someone you have added and trusted.").color(MUTED),
            );
            ui.add_space(18.0);
            ui.set_max_width(390.0);
            let response = ui.add_sized(
                [ui.available_width(), 42.0],
                singleline_input(&mut self.new_recipient).hint_text("Saved name or handle"),
            );
            let enter = singleline_submitted(ui, &response);
            ui.add_space(10.0);
            if primary_button(ui, "Open conversation", ui.available_width()).clicked() || enter {
                self.open_conversation();
            }
            if contacts.is_empty() {
                ui.add_space(12.0);
                if ui.link("Add someone first").clicked() {
                    self.adding_person = true;
                    self.view = View::People;
                }
            }
        });
    }

    fn conversation_view(
        &mut self,
        ui: &mut egui::Ui,
        conversations: &[client::ConversationPreview],
        contacts: &[client::ContactEntry],
    ) {
        let selected = self.selected_user_id.clone();
        let conversation = conversations
            .iter()
            .find(|conversation| conversation.user_id == selected);
        let contact = contacts.iter().find(|contact| contact.user_id == selected);
        let display_name = conversation
            .map(|conversation| conversation.display_name.as_str())
            .or_else(|| contact.map(|contact| contact.nickname.as_str()))
            .unwrap_or("Conversation");
        let handle = conversation
            .map(|conversation| conversation.peer.as_str())
            .or_else(|| contact.map(|contact| contact.handle.as_str()))
            .unwrap_or("");
        ui.horizontal(|ui| {
            avatar(ui, display_name, &selected, 38.0);
            ui.vertical(|ui| {
                ui.label(egui::RichText::new(display_name).size(18.0).strong());
                ui.label(
                    egui::RichText::new(format!("@{handle}"))
                        .size(12.0)
                        .color(MUTED),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Ok(info) = self.verification_for(&selected) {
                    trust_badge(ui, info.level);
                }
            });
        });
        ui.add_space(10.0);
        ui.separator();
        let messages = self.history(&selected);
        let scroll_height = (ui.available_height() - 86.0).max(180.0);
        egui::ScrollArea::vertical()
            .id_salt(("message-history", selected.as_str()))
            .auto_shrink([false, false])
            .max_height(scroll_height)
            .show(ui, |ui| {
                ui.add_space(12.0);
                if messages.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(70.0);
                        ui.label(
                            egui::RichText::new("No messages yet")
                                .size(18.0)
                                .color(MUTED),
                        );
                    });
                }
                for message in messages {
                    message_bubble(ui, &message);
                    ui.add_space(7.0);
                }
                ui.add_space(8.0);
            });
        ui.separator();
        ui.add_space(8.0);
        let mut send = false;
        ui.horizontal(|ui| {
            let width = (ui.available_width() - 90.0).max(160.0);
            let response = ui.add_enabled(
                !self.device_replaced && !self.message_busy,
                egui::TextEdit::multiline(&mut self.message)
                    .desired_width(width)
                    .desired_rows(2)
                    .hint_text("Write a message"),
            );
            if !self.message_busy
                && response.has_focus()
                && ui.input(|input| input.key_pressed(egui::Key::Enter) && !input.modifiers.shift)
            {
                send = true;
            }
            if ui
                .add_enabled_ui(!self.device_replaced && !self.message_busy, |ui| {
                    primary_button(
                        ui,
                        if self.message_busy {
                            "Sending…"
                        } else {
                            "Send"
                        },
                        76.0,
                    )
                })
                .inner
                .clicked()
            {
                send = true;
            }
        });
        ui.label(
            egui::RichText::new("Enter to send · Shift+Enter for a new line")
                .size(11.0)
                .color(MUTED),
        );
        if send {
            self.send_message();
        }
    }

    fn people_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            page_heading(ui, "People", "Saved identities and safety checks");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if primary_button(ui, "+ Add person", 126.0).clicked() {
                    self.adding_person = !self.adding_person;
                }
            });
        });
        ui.add_space(16.0);
        if self.adding_person {
            self.add_person_view(ui);
            ui.add_space(16.0);
        }
        let contacts = self.contacts();
        if contacts.is_empty() && !self.adding_person {
            empty_people(ui);
            return;
        }
        let height = ui.available_height();
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(300.0, height),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    let mut selected = None;
                    egui::ScrollArea::vertical()
                        .id_salt("people-list")
                        .auto_shrink([false, false])
                        .max_height(ui.available_height())
                        .show(ui, |ui| {
                            for contact in &contacts {
                                if contact_row(
                                    ui,
                                    contact,
                                    self.selected_contact_user_id == contact.user_id,
                                )
                                .clicked()
                                {
                                    selected = Some(contact.user_id.clone());
                                }
                                ui.add_space(6.0);
                            }
                        });
                    if let Some(user_id) = selected {
                        self.selected_contact_user_id = user_id;
                    }
                },
            );
            ui.separator();
            ui.allocate_ui_with_layout(
                ui.available_size(),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("person-detail")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            self.person_detail(ui, &contacts);
                        });
                },
            );
        });
    }

    fn add_person_view(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(egui::Stroke::new(1.0, BORDER))
            .corner_radius(12)
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Add from a connection card").strong());
                ui.label(
                    egui::RichText::new(
                        "Ask the person to send you their card through a channel you already trust.",
                    )
                    .size(12.0)
                    .color(MUTED),
                );
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [210.0, 40.0],
                        singleline_input(&mut self.contact_nickname)
                            .hint_text("Name on this device"),
                    );
                    ui.add_sized(
                        [(ui.available_width() - 112.0).max(220.0), 40.0],
                        singleline_input(&mut self.contact_card).hint_text("Paste connection card"),
                    );
                    if primary_button(ui, "Add", 86.0).clicked() {
                        self.add_person();
                    }
                });
            });
    }

    fn person_detail(&mut self, ui: &mut egui::Ui, contacts: &[client::ContactEntry]) {
        let contact = contacts
            .iter()
            .find(|contact| contact.user_id == self.selected_contact_user_id);
        let Some(contact) = contact else {
            ui.vertical_centered(|ui| {
                ui.add_space(86.0);
                ui.label(
                    egui::RichText::new("Choose a person")
                        .size(20.0)
                        .color(MUTED),
                );
            });
            return;
        };
        let contact = contact.clone();
        let blocked = self.contact_blocked(&contact.user_id);
        let is_blocked = blocked.as_ref().copied().unwrap_or(true);
        ui.horizontal(|ui| {
            avatar(ui, &contact.nickname, &contact.user_id, 52.0);
            ui.vertical(|ui| {
                ui.label(egui::RichText::new(&contact.nickname).size(23.0).strong());
                ui.label(
                    egui::RichText::new(format!("@{}", contact.handle))
                        .size(13.0)
                        .color(MUTED),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if primary_button(ui, if is_blocked { "Blocked" } else { "Message" }, 98.0)
                    .clicked()
                    && !is_blocked
                {
                    self.select_conversation(contact.user_id.clone());
                }
            });
        });
        if let Err(error) = blocked {
            ui.add_space(12.0);
            callout(ui, DANGER, "Block list unavailable", &error.to_string());
        }
        ui.add_space(20.0);
        match self.verification_for(&contact.user_id) {
            Ok(info) => {
                egui::Frame::new()
                    .fill(SURFACE)
                    .stroke(egui::Stroke::new(1.0, BORDER))
                    .corner_radius(12)
                    .inner_margin(egui::Margin::same(18))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Identity safety").strong());
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| trust_badge(ui, info.level),
                            );
                        });
                        ui.add_space(10.0);
                        let explanation = match info.level {
                            TrustLevel::Verified => {
                                "You compared this number and marked the identity as verified."
                            }
                            TrustLevel::Pinned => {
                                "This is the same identity you first added. Compare the number in person or on a trusted call for stronger verification."
                            }
                            TrustLevel::Changed => {
                                "The identity changed. Do not send until you compare the new number with this person."
                            }
                            TrustLevel::Unverified => "This identity has not been trusted yet.",
                        };
                        ui.label(egui::RichText::new(explanation).color(MUTED));
                        ui.add_space(12.0);
                        ui.label(egui::RichText::new("Safety number").size(12.0).color(MUTED));
                        ui.label(
                            egui::RichText::new(group_safety_number(&info.safety_number))
                                .monospace()
                                .size(17.0)
                                .color(TEXT),
                        );
                        ui.add_space(12.0);
                        match info.level {
                            TrustLevel::Pinned | TrustLevel::Unverified => {
                                if ui.button("I compared it — mark verified").clicked() {
                                    self.mark_verified(info.clone());
                                }
                            }
                            TrustLevel::Changed => {
                                if danger_button(ui, "I compared the new number — trust it")
                                    .clicked()
                                {
                                    self.accept_identity_change(info.clone());
                                }
                            }
                            TrustLevel::Verified => {}
                        }
                    });
            }
            Err(error) => callout(ui, DANGER, "Identity unavailable", &error.to_string()),
        }
        ui.add_space(14.0);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new(format!("ID {}", short_id(&contact.user_id)))
                    .monospace()
                    .size(12.0)
                    .color(MUTED),
            );
            if ui.small_button("Copy ID").clicked() {
                ui.ctx().copy_text(contact.user_id.clone());
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Remove person").clicked() {
                    self.remove_contact(contact.nickname.clone());
                }
                let label = if is_blocked {
                    "Unblock person"
                } else {
                    "Block person"
                };
                if ui.small_button(label).clicked() {
                    self.set_contact_blocked(contact.user_id.clone(), !is_blocked);
                }
            });
        });
    }

    fn device_view(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .id_salt("device-page")
            .auto_shrink([false, false])
            .show(ui, |ui| self.device_view_contents(ui));
    }

    fn device_view_contents(&mut self, ui: &mut egui::Ui) {
        page_heading(
            ui,
            "This device",
            "Your local profile, connection, and pending messages",
        );
        ui.add_space(18.0);
        let active = self.is_active();
        if self.device_replaced {
            callout(
                ui,
                DANGER,
                "This device was replaced",
                "Your local messages are still here, but sending and receiving are disabled.",
            );
            ui.add_space(8.0);
            let session_expired = self
                .account
                .as_ref()
                .is_none_or(|account| account.is_expired(OsPlatform.now_unix_secs() as i64));
            if session_expired || self.account_login_open {
                if compact_button(ui, "Log in to use this device again").clicked() {
                    self.account_login_open = true;
                    self.login_requested = false;
                }
            } else if primary_button(ui, "Make this the active device", 218.0).clicked() {
                self.save_profile();
            }
            ui.add_space(12.0);
        } else if !active {
            callout(
                ui,
                SPORE,
                "Activate this device",
                "Set your profile and publish this device so people can reach it directly.",
            );
            ui.add_space(12.0);
        }
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(egui::Stroke::new(1.0, BORDER))
            .corner_radius(12)
            .inner_margin(egui::Margin::same(18))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Profile").size(18.0).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        status_badge(ui, active);
                    });
                });
                ui.add_space(14.0);
                ui.columns(2, |columns| {
                    field_label(&mut columns[0], "Name");
                    columns[0].add_sized(
                        [columns[0].available_width(), 40.0],
                        singleline_input(&mut self.display_name),
                    );
                    field_label(&mut columns[1], "Handle");
                    columns[1].add_sized(
                        [columns[1].available_width(), 40.0],
                        singleline_input(&mut self.my_handle),
                    );
                });
                ui.add_space(14.0);
                let label = if active {
                    "Save profile"
                } else {
                    "Activate device"
                };
                if primary_button(ui, label, 132.0).clicked() {
                    self.save_profile();
                }
            });
        ui.add_space(14.0);
        self.account_panel(ui);
        ui.add_space(14.0);
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(egui::Stroke::new(1.0, BORDER))
            .corner_radius(12)
            .inner_margin(egui::Margin::same(18))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new("Share your connection card")
                        .size(18.0)
                        .strong(),
                );
                ui.label(
                    egui::RichText::new(
                        "Send this card through a channel the other person already trusts.",
                    )
                    .color(MUTED),
                );
                ui.add_space(12.0);
                let enabled = !self.record_blob.is_empty();
                if ui
                    .add_enabled(
                        enabled,
                        egui::Button::new("Copy connection card")
                            .fill(SURFACE_RAISED)
                            .corner_radius(8),
                    )
                    .clicked()
                {
                    ui.ctx().copy_text(self.record_blob.clone());
                    self.notice = "Connection card copied".into();
                    self.error.clear();
                }
            });
        ui.add_space(14.0);
        let pending = self.pending_count();
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(egui::Stroke::new(1.0, BORDER))
            .corner_radius(12)
            .inner_margin(egui::Margin::same(18))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("Pending messages").size(18.0).strong());
                        ui.label(
                            egui::RichText::new(if pending == 0 {
                                "Nothing is waiting on this device.".to_string()
                            } else {
                                format!("{pending} will retry directly from this device.")
                            })
                            .color(MUTED),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(
                                pending > 0 && !self.device_replaced,
                                egui::Button::new("Try now"),
                            )
                            .clicked()
                        {
                            self.retry_outbox();
                        }
                    });
                });
            });
        ui.add_space(10.0);
        ui.collapsing("Device details", |ui| {
            if let Some(session) = &self.session {
                let info = client::identity_info(&session.identity);
                let id = user_id(&session.identity.wallet_public());
                detail_row(ui, "User ID", id.as_str());
                detail_row(ui, "Device", &hex_prefix(&info.device, 8));
                detail_row(ui, "Local data", &self.data_dir.display().to_string());
            }
        });
    }

    fn account_panel(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .fill(SURFACE)
            .stroke(egui::Stroke::new(1.0, BORDER))
            .corner_radius(12)
            .inner_margin(egui::Margin::same(18))
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Account recovery").size(18.0).strong());
                if self.account.is_none() || self.account_login_open {
                    ui.label(
                        egui::RichText::new(if self.account.is_some() {
                            "Log in again to renew access to this account."
                        } else {
                            "Use email to recover this identity on another device."
                        })
                        .color(MUTED),
                    );
                    ui.add_space(12.0);
                    self.account_login_fields(ui);
                    return;
                }

                if let Some(account) = &self.account {
                    ui.label(
                        egui::RichText::new("Your identity can be restored after email login.")
                            .color(MUTED),
                    );
                    ui.add_space(10.0);
                    detail_row(ui, "Account", &short_id(&account.account_id));
                    ui.add_space(10.0);
                    if compact_button(ui, "Log in again").clicked() {
                        self.account_login_open = true;
                        self.login_requested = false;
                        self.email.clear();
                    }
                }
            });
    }

    fn status_banner(&mut self, ui: &mut egui::Ui) {
        let (message, color) = if !self.error.is_empty() {
            (self.error.clone(), DANGER)
        } else if !self.notice.is_empty() {
            (self.notice.clone(), MOSS)
        } else {
            return;
        };
        egui::Frame::new()
            .fill(color.gamma_multiply(0.12))
            .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.45)))
            .corner_radius(8)
            .inner_margin(egui::Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(message).color(color));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("×").clicked() {
                            self.error.clear();
                            self.notice.clear();
                        }
                    });
                });
            });
        ui.add_space(12.0);
    }
}

fn configure_style(ctx: &egui::Context) {
    ctx.set_theme(egui::Theme::Dark);
    let mut style = (*ctx.style_of(egui::Theme::Dark)).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = CANVAS;
    style.visuals.window_fill = SURFACE;
    style.visuals.extreme_bg_color = SIDEBAR;
    style.visuals.faint_bg_color = SURFACE;
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.selection.bg_fill = MOSS.gamma_multiply(0.35);
    style.visuals.selection.stroke = egui::Stroke::new(1.0, MOSS);
    style.visuals.widgets.inactive.bg_fill = SURFACE_RAISED;
    style.visuals.widgets.inactive.weak_bg_fill = SURFACE;
    style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(39, 49, 64);
    style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, MOSS.gamma_multiply(0.7));
    style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(44, 57, 70);
    style.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(13.0, 8.0);
    style.spacing.interact_size.y = 36.0;
    style.text_styles.insert(
        egui::TextStyle::Body,
        egui::FontId::new(15.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        egui::TextStyle::Button,
        egui::FontId::new(14.0, egui::FontFamily::Proportional),
    );
    ctx.set_style_of(egui::Theme::Dark, style);
}

fn page_heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.vertical(|ui| {
        ui.label(egui::RichText::new(title).size(27.0).strong());
        ui.label(egui::RichText::new(subtitle).size(13.0).color(MUTED));
    });
}

fn field_label(ui: &mut egui::Ui, label: &str) {
    ui.label(egui::RichText::new(label).size(12.0).strong().color(MUTED));
}

fn singleline_input(text: &mut String) -> egui::TextEdit<'_> {
    egui::TextEdit::singleline(text).vertical_align(egui::Align::Center)
}

fn singleline_submitted(ui: &egui::Ui, response: &egui::Response) -> bool {
    (response.has_focus() || response.lost_focus())
        && ui.input(|input| input.key_pressed(egui::Key::Enter))
}

fn primary_button(ui: &mut egui::Ui, label: &str, width: f32) -> egui::Response {
    ui.add_sized(
        [width, 40.0],
        egui::Button::new(egui::RichText::new(label).strong().color(CANVAS))
            .fill(MOSS)
            .stroke(egui::Stroke::NONE)
            .corner_radius(8),
    )
}

fn compact_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(label)
            .fill(SURFACE_RAISED)
            .stroke(egui::Stroke::new(1.0, BORDER))
            .corner_radius(8),
    )
}

fn danger_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(egui::RichText::new(label).color(DANGER))
            .fill(DANGER.gamma_multiply(0.1))
            .stroke(egui::Stroke::new(1.0, DANGER.gamma_multiply(0.55)))
            .corner_radius(8),
    )
}

fn nav_button(
    ui: &mut egui::Ui,
    selected: bool,
    label: &str,
    badge: Option<usize>,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 42.0), egui::Sense::click());
    let fill = if selected {
        SURFACE_RAISED
    } else if response.hovered() {
        SURFACE
    } else {
        egui::Color32::TRANSPARENT
    };
    ui.painter().rect_filled(rect, 9.0, fill);
    if selected {
        ui.painter()
            .circle_filled(egui::pos2(rect.left() + 12.0, rect.center().y), 3.0, MOSS);
    }
    ui.painter().text(
        egui::pos2(rect.left() + 24.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(14.0),
        if selected { TEXT } else { MUTED },
    );
    if let Some(count) = badge {
        let center = egui::pos2(rect.right() - 17.0, rect.center().y);
        ui.painter().circle_filled(center, 10.0, SPORE);
        ui.painter().text(
            center,
            egui::Align2::CENTER_CENTER,
            count.min(99).to_string(),
            egui::FontId::proportional(11.0),
            CANVAS,
        );
    }
    response
}

fn conversation_row(
    ui: &mut egui::Ui,
    conversation: &client::ConversationPreview,
    selected: bool,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 68.0), egui::Sense::click());
    let fill = if selected {
        SURFACE_RAISED
    } else if response.hovered() {
        SURFACE
    } else {
        egui::Color32::TRANSPARENT
    };
    ui.painter().rect_filled(rect, 10.0, fill);
    paint_avatar(
        ui.painter(),
        egui::pos2(rect.left() + 25.0, rect.center().y),
        17.0,
        &conversation.display_name,
        &conversation.user_id,
    );
    ui.painter().text(
        egui::pos2(rect.left() + 52.0, rect.top() + 20.0),
        egui::Align2::LEFT_CENTER,
        &conversation.display_name,
        egui::FontId::proportional(14.0),
        TEXT,
    );
    let prefix = if conversation.from_me { "You: " } else { "" };
    ui.painter().text(
        egui::pos2(rect.left() + 52.0, rect.top() + 44.0),
        egui::Align2::LEFT_CENTER,
        format!("{prefix}{}", ellipsize(&conversation.text, 28)),
        egui::FontId::proportional(12.0),
        MUTED,
    );
    response
}

fn contact_row(
    ui: &mut egui::Ui,
    contact: &client::ContactEntry,
    selected: bool,
) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 62.0), egui::Sense::click());
    let fill = if selected {
        SURFACE_RAISED
    } else if response.hovered() {
        SURFACE
    } else {
        egui::Color32::TRANSPARENT
    };
    ui.painter().rect_filled(rect, 10.0, fill);
    paint_avatar(
        ui.painter(),
        egui::pos2(rect.left() + 24.0, rect.center().y),
        16.0,
        &contact.nickname,
        &contact.user_id,
    );
    ui.painter().text(
        egui::pos2(rect.left() + 50.0, rect.top() + 20.0),
        egui::Align2::LEFT_CENTER,
        &contact.nickname,
        egui::FontId::proportional(14.0),
        TEXT,
    );
    ui.painter().text(
        egui::pos2(rect.left() + 50.0, rect.top() + 42.0),
        egui::Align2::LEFT_CENTER,
        format!("@{}", contact.handle),
        egui::FontId::proportional(12.0),
        MUTED,
    );
    response
}

fn message_bubble(ui: &mut egui::Ui, message: &mycellium_engine::history::StoredMessage) {
    let layout = if message.from_me {
        egui::Layout::right_to_left(egui::Align::Min)
    } else {
        egui::Layout::left_to_right(egui::Align::Min)
    };
    ui.with_layout(layout, |ui| {
        egui::Frame::new()
            .fill(if message.from_me {
                MOSS.gamma_multiply(0.22)
            } else {
                SURFACE
            })
            .stroke(egui::Stroke::new(
                1.0,
                if message.from_me {
                    MOSS.gamma_multiply(0.38)
                } else {
                    BORDER
                },
            ))
            .corner_radius(11)
            .inner_margin(egui::Margin::symmetric(13, 9))
            .show(ui, |ui| {
                ui.set_max_width(430.0);
                ui.label(&message.text);
                ui.label(
                    egui::RichText::new(format_clock(message.timestamp))
                        .size(10.0)
                        .color(MUTED),
                );
            });
    });
}

fn avatar(ui: &mut egui::Ui, label: &str, seed: &str, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    paint_avatar(ui.painter(), rect.center(), size / 2.0, label, seed);
}

fn paint_avatar(painter: &egui::Painter, center: egui::Pos2, radius: f32, label: &str, seed: &str) {
    let color = if seed.as_bytes().first().copied().unwrap_or_default() % 2 == 0 {
        MOSS
    } else {
        SPORE
    };
    painter.circle_filled(center, radius, color.gamma_multiply(0.24));
    painter.circle_stroke(
        center,
        radius,
        egui::Stroke::new(1.0, color.gamma_multiply(0.7)),
    );
    let initial = label
        .chars()
        .find(|character| character.is_alphanumeric())
        .unwrap_or('?')
        .to_uppercase()
        .collect::<String>();
    painter.text(
        center,
        egui::Align2::CENTER_CENTER,
        initial,
        egui::FontId::proportional(radius * 0.85),
        color,
    );
}

fn network_mark(ui: &mut egui::Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let painter = ui.painter();
    let points = [
        egui::pos2(rect.left() + size * 0.18, rect.center().y),
        egui::pos2(rect.left() + size * 0.48, rect.top() + size * 0.24),
        egui::pos2(rect.left() + size * 0.48, rect.bottom() - size * 0.22),
        egui::pos2(rect.right() - size * 0.14, rect.center().y),
    ];
    for (from, to) in [(0, 1), (0, 2), (1, 3), (2, 3), (1, 2)] {
        painter.line_segment(
            [points[from], points[to]],
            egui::Stroke::new((size / 28.0).max(1.0), MOSS.gamma_multiply(0.62)),
        );
    }
    for (index, point) in points.into_iter().enumerate() {
        painter.circle_filled(
            point,
            (size / 12.0).max(2.5),
            if index == 3 { SPORE } else { MOSS },
        );
    }
}

fn trust_badge(ui: &mut egui::Ui, trust: TrustLevel) {
    let (label, color) = match trust {
        TrustLevel::Verified => ("Verified", MOSS),
        TrustLevel::Pinned => ("Known", SPORE),
        TrustLevel::Changed => ("Identity changed", DANGER),
        TrustLevel::Unverified => ("Unverified", MUTED),
    };
    egui::Frame::new()
        .fill(color.gamma_multiply(0.12))
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.45)))
        .corner_radius(10)
        .inner_margin(egui::Margin::symmetric(9, 4))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).size(11.0).strong().color(color));
        });
}

fn status_badge(ui: &mut egui::Ui, active: bool) {
    let (label, color) = if active {
        ("● Ready", MOSS)
    } else {
        ("○ Not active", SPORE)
    };
    ui.label(egui::RichText::new(label).size(12.0).color(color));
}

fn callout(ui: &mut egui::Ui, color: egui::Color32, title: &str, body: &str) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.09))
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.38)))
        .corner_radius(10)
        .inner_margin(egui::Margin::same(13))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(title).strong().color(color));
            ui.label(egui::RichText::new(body).color(MUTED));
        });
}

fn empty_people(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(76.0);
        network_mark(ui, 48.0);
        ui.add_space(14.0);
        ui.label(egui::RichText::new("No people yet").size(22.0).strong());
        ui.label(
            egui::RichText::new("Add someone using their signed connection card.").color(MUTED),
        );
    });
}

fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(label).color(MUTED));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(value).monospace().size(12.0));
        });
    });
}

fn open_history(data_dir: &std::path::Path, identity: &Identity) -> Result<FileStore> {
    FileStore::open(data_dir.join("history"), identity.storage_key())
        .map_err(|error| anyhow!("could not open local message history: {error}"))
}

fn load_account_session(store: &FileStore) -> Result<Option<client::registry::RegistrySession>> {
    let Some(bytes) = store
        .get(REGISTRY_SESSION_KEY)
        .map_err(|error| anyhow!("could not read the local account session: {error}"))?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| anyhow!("the local account session is corrupt"))
}

fn save_account_session(
    store: &mut FileStore,
    session: &client::registry::RegistrySession,
) -> Result<()> {
    let bytes = serde_json::to_vec(session)?;
    store
        .put(REGISTRY_SESSION_KEY, &bytes)
        .map_err(|error| anyhow!("could not save the local account session: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn serve_linux_connection(
    inbound: InboundFrame,
    identity: &Identity,
    store: &Arc<Mutex<FileStore>>,
    own_record: &Arc<Mutex<Option<SignedRecord>>>,
    device_current: &Arc<AtomicBool>,
    network: &client::DirectNetwork,
    events: &Sender<RuntimeEvent>,
    ctx: &egui::Context,
) {
    let mut platform = OsPlatform;
    let mut sink = EventSink {
        sender: events.clone(),
        ctx: ctx.clone(),
    };
    if !network.is_running() || !device_current.load(Ordering::Acquire) {
        return;
    }
    let Ok(PeerFrame::Delivery { delivery_id, item }) = wire::decode::<PeerFrame>(inbound.bytes())
    else {
        return;
    };
    if client::mail_item_sender_device(&item).is_none() {
        return;
    }
    let Some(record) = own_record.lock().ok().and_then(|record| record.clone()) else {
        return;
    };
    let me = record.record.handle.clone();
    let acknowledgement = {
        let Ok(mut store) = store.lock() else {
            let _ = events.send(RuntimeEvent::Error("local store is unavailable".into()));
            ctx.request_repaint();
            return;
        };
        client::accept_delivery(
            identity,
            &me,
            &record,
            &mut platform,
            &mut store,
            delivery_id,
            *item,
            &mut sink,
        )
    };
    if let Some(reply) = acknowledgement {
        let _ = inbound.reply(&reply);
        let _ = events.send(RuntimeEvent::Notice("New message received".into()));
        ctx.request_repaint();
    }
}

fn send_message_now(
    identity: &Identity,
    store: &Arc<Mutex<FileStore>>,
    network: &client::DirectNetwork,
    registry_url: &str,
    me: &Handle,
    selected_user_id: &str,
    text: &str,
) -> Result<String> {
    let refreshed = client::registry::RegistryClient::new(registry_url)
        .and_then(|registry| registry.get_record_for_user(selected_user_id))
        .ok()
        .flatten();
    let now = OsPlatform.now_unix_secs();
    let app = AppMessage {
        id: random_id(),
        timestamp: now,
        expires_at: None,
        body: Body::Text(text.to_string()),
    };
    let mut guard = store
        .lock()
        .map_err(|_| anyhow!("local store lock poisoned"))?;
    if let Some(record) = refreshed {
        let _ = client::apply_registry_record(&mut *guard, selected_user_id, record);
    }
    let (peer, peer_record) = client::resolve_local_record(&mut *guard, selected_user_id).map_err(
        |error| match error {
            flow::TrustError::BadHandle => anyhow!("this person is no longer available"),
            flow::TrustError::Unverified => anyhow!("their identity record is invalid"),
            flow::TrustError::IdentityChanged => {
                anyhow!("their identity changed; review it in People before sending")
            }
            flow::TrustError::StaleRecord => anyhow!("their identity record is stale"),
        },
    )?;
    let info = client::verification_info_for_record(&*guard, identity, &peer, &peer_record)?;
    if !matches!(info.level, TrustLevel::Pinned | TrustLevel::Verified) {
        bail!("add this person before messaging them");
    }

    let mut prepared: Vec<(String, Device, MailItem)> = Vec::new();
    let mut deliver = |transaction: &mut mycellium_storage::filestore::FileTransaction<'_>,
                       handle: &Handle,
                       record: &SignedRecord,
                       device: &Device,
                       item: MailItem,
                       pairwise_plaintext: Option<Vec<u8>>| {
        let delivery_id = client::delivery_id_for_item(&item);
        let parked = match pairwise_plaintext {
            Some(plaintext) => client::park_pairwise_outbox(
                transaction,
                delivery_id.clone(),
                handle,
                record,
                device,
                item.clone(),
                plaintext,
                now,
            ),
            None => client::park_outbox(
                transaction,
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
    let mut transaction = guard.transaction();
    let mut outcome = client::send_direct(
        identity,
        &mut transaction,
        &mut OsPlatform,
        me,
        &peer,
        &peer_record,
        &app,
        &mut deliver,
    )?;
    transaction.commit()?;
    drop(guard);

    for (delivery_id, device, item) in prepared {
        if client::attempt_parked_delivery(store, network, &device, &delivery_id, &item, now)? {
            outcome.outboxed = outcome.outboxed.saturating_sub(1);
            outcome.direct += 1;
            outcome.delivered += 1;
        }
    }
    if outcome.direct == 0 && outcome.outboxed == 0 {
        bail!("message could not be sent or saved for retry");
    }
    if outcome.direct > 0 {
        Ok("Sent".to_string())
    } else {
        Ok("Direct connection unavailable. This device will keep trying.".to_string())
    }
}

fn default_data_dir() -> PathBuf {
    resolve_data_dir(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))
}

fn resolve_data_dir(
    xdg_data_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> PathBuf {
    if let Some(dir) = xdg_data_home {
        return PathBuf::from(dir).join("mycellium");
    }
    if let Some(home) = home {
        return PathBuf::from(home).join(".local/share/mycellium");
    }
    PathBuf::from(".mycellium")
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    OsPlatform.fill_random(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ellipsize(value: &str, max_chars: usize) -> String {
    let mut characters = value.chars();
    let prefix: String = characters.by_ref().take(max_chars).collect();
    if characters.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

fn short_id(value: &str) -> String {
    if value.len() <= 16 {
        value.to_string()
    } else {
        format!("{}…{}", &value[..8], &value[value.len() - 6..])
    }
}

fn group_safety_number(value: &str) -> String {
    value
        .as_bytes()
        .chunks(5)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_clock(timestamp: u64) -> String {
    let seconds = timestamp % 86_400;
    format!("{:02}:{:02} UTC", seconds / 3_600, (seconds % 3_600) / 60)
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    bytes
        .iter()
        .take(count)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_session_is_encrypted_with_local_device_state() {
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "mycellium-linux-account-{}",
            u64::from_le_bytes(nonce)
        ));
        let session = client::registry::RegistrySession {
            registry_url: "https://registry.example".into(),
            account_id: "0123456789abcdef0123456789abcdef".into(),
            session_token: "unique-session-secret".into(),
            session_expires_at: 100,
        };
        let mut store = FileStore::open(root.clone(), [7u8; 32]).unwrap();

        save_account_session(&mut store, &session).unwrap();
        drop(store);

        for entry in std::fs::read_dir(&root).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("unique-session-secret"));
        }

        let store = FileStore::open(root.clone(), [7u8; 32]).unwrap();
        let loaded = load_account_session(&store).unwrap().unwrap();
        assert_eq!(loaded.account_id, session.account_id);
        assert_eq!(loaded.session_token, session.session_token);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn data_directory_follows_xdg_then_home_then_safe_local_fallback() {
        assert_eq!(
            resolve_data_dir(Some("/xdg".into()), Some("/home/user".into())),
            PathBuf::from("/xdg/mycellium")
        );
        assert_eq!(
            resolve_data_dir(None, Some("/home/user".into())),
            PathBuf::from("/home/user/.local/share/mycellium")
        );
        assert_eq!(resolve_data_dir(None, None), PathBuf::from(".mycellium"));
    }
}
