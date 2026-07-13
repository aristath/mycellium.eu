//! Native Linux Mycellium client.
//!
//! This is deliberately a thin shell: it owns the window, local unlock UX, and
//! rendering. Protocol and local-state behavior stay in `mycellium-client`.

use std::path::PathBuf;
use std::sync::{
    mpsc::{self, Receiver, Sender},
    Arc, Mutex,
};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use eframe::egui;

use mycellium_core::identity::{Handle, Identity};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, SignedRecord};
use mycellium_core::transport::Transport;
use mycellium_core::wire;
use mycellium_engine::flow::{self, FlowEvent};
use mycellium_engine::groups::PeerFrame;
use mycellium_engine::verified::TrustLevel;
use mycellium_storage::filestore::FileStore;
use mycellium_storage::store;
use mycellium_transport::link::FrameReader;
use mycellium_transport::net::TcpTransport;
use zeroize::Zeroize;

use mycellium_client as client;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1080.0, 720.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Mycellium",
        options,
        Box::new(|cc| Ok(Box::new(LinuxClient::new(cc)))),
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
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Chats,
    Contacts,
    Records,
    Outbox,
}

struct Session {
    identity: Arc<Identity>,
    store: Arc<Mutex<FileStore>>,
    network: client::DirectNetwork,
    listener_addr: Option<String>,
}

enum RuntimeEvent {
    Flow(FlowEvent),
    Notice(String),
    Error(String),
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
    passphrase: String,
    display_name: String,
    session: Option<Session>,
    events_tx: Sender<RuntimeEvent>,
    events_rx: Receiver<RuntimeEvent>,
    tab: Tab,
    notice: String,
    error: String,

    my_handle: String,
    peer: String,
    message: String,
    selected_peer: String,

    contact_nickname: String,
    contact_handle: String,

    record_handle: String,
    record_addr: String,
    record_blob: String,
}

impl LinuxClient {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut fonts = egui::FontDefinitions::default();
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "Ubuntu".to_string());
        cc.egui_ctx.set_fonts(fonts);
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        let (events_tx, events_rx) = mpsc::channel();
        Self {
            ctx: cc.egui_ctx.clone(),
            data_dir: default_data_dir(),
            passphrase: String::new(),
            display_name: String::new(),
            session: None,
            events_tx,
            events_rx,
            tab: Tab::Chats,
            notice: String::new(),
            error: String::new(),
            my_handle: String::new(),
            peer: String::new(),
            message: String::new(),
            selected_peer: String::new(),
            contact_nickname: String::new(),
            contact_handle: String::new(),
            record_handle: String::new(),
            record_addr: "127.0.0.1:7000".to_string(),
            record_blob: String::new(),
        }
    }

    fn unlock(&mut self) {
        self.run("Unlocked", |this| {
            let identity =
                store::load_identity_with_passphrase_from(&this.data_dir, &this.passphrase)?;
            let store = open_history(&this.data_dir, &identity)?;
            let network = client::DirectNetwork::new(identity.device_secret());
            this.session = Some(Session {
                identity: Arc::new(identity),
                store: Arc::new(Mutex::new(store)),
                network,
                listener_addr: None,
            });
            this.passphrase.zeroize();
            Ok(())
        });
    }

    fn create_identity(&mut self) {
        self.run("Created identity", |this| {
            let mut platform = OsPlatform;
            let identity = client::create_identity(&mut platform)?;
            store::save_identity_with_passphrase_at(&this.data_dir, &identity, &this.passphrase)?;
            let store = open_history(&this.data_dir, &identity)?;
            let network = client::DirectNetwork::new(identity.device_secret());
            this.session = Some(Session {
                identity: Arc::new(identity),
                store: Arc::new(Mutex::new(store)),
                network,
                listener_addr: None,
            });
            this.passphrase.zeroize();
            Ok(())
        });
    }

    fn session_mut(&mut self) -> Result<&mut Session> {
        self.session
            .as_mut()
            .ok_or_else(|| anyhow!("unlock or create an identity first"))
    }

    fn run(&mut self, ok: &str, f: impl FnOnce(&mut Self) -> Result<()>) {
        self.error.clear();
        self.notice.clear();
        match f(self) {
            Ok(()) => self.notice = ok.to_string(),
            Err(err) => self.error = err.to_string(),
        }
    }

    fn register_record(&mut self) {
        self.run("Record updated", |this| {
            let handle = Handle::new(this.record_handle.trim())
                .map_err(|_| anyhow!("enter a valid handle"))?;
            let name = if this.display_name.trim().is_empty() {
                handle.as_str().to_string()
            } else {
                this.display_name.trim().to_string()
            };
            let addr = this.record_addr.trim().to_string();
            let (identity, store, record) = {
                let session = this.session_mut()?;
                let mut store = session
                    .store
                    .lock()
                    .map_err(|_| anyhow!("local store lock poisoned"))?;
                let record = client::publish_active_device_record(
                    &mut *store,
                    &mut OsPlatform,
                    &session.identity,
                    &handle,
                    &name,
                    &addr,
                )?;
                (
                    Arc::clone(&session.identity),
                    Arc::clone(&session.store),
                    record,
                )
            };
            this.my_handle = handle.as_str().to_string();
            this.record_blob = client::encode_record(&record);
            this.start_listener(handle, record, identity, store, addr)?;
            Ok(())
        });
    }

    fn import_record(&mut self) {
        self.run("Record imported", |this| {
            let handle = Handle::new(this.record_handle.trim())
                .map_err(|_| anyhow!("enter a valid handle"))?;
            let record = client::decode_record(this.record_blob.trim())?;
            let session = this.session_mut()?;
            let mut store = session
                .store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            client::import_record(&mut *store, &handle, record)
        });
    }

    fn add_contact(&mut self) {
        self.run("Contact saved", |this| {
            let handle = Handle::new(this.contact_handle.trim())
                .map_err(|_| anyhow!("enter a valid handle"))?;
            let nickname = this.contact_nickname.trim().to_string();
            let session = this.session_mut()?;
            let mut store = session
                .store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            client::add_contact(&mut *store, &nickname, &handle)
        });
    }

    fn send_message(&mut self) {
        self.run("Sent or saved for delivery", |this| {
            let me =
                Handle::new(this.my_handle.trim()).map_err(|_| anyhow!("enter your handle"))?;
            let resolved_peer = if this.peer.trim().is_empty() {
                this.selected_peer.trim().to_string()
            } else {
                this.peer.trim().to_string()
            };
            let text = this.message.trim().to_string();
            if text.is_empty() {
                return Err(anyhow!("write a message first"));
            }
            let app = AppMessage {
                id: random_id(),
                timestamp: OsPlatform.now_unix_secs(),
                expires_at: None,
                body: Body::Text(text),
            };
            let session = this.session_mut()?;
            let identity = Arc::clone(&session.identity);
            let store = Arc::clone(&session.store);
            let network = session.network.clone();
            let now = OsPlatform.now_unix_secs();
            let mut store_guard = store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            let (peer, peer_record) =
                client::resolve_local_record(&mut *store_guard, resolved_peer.trim()).map_err(
                    |err| match err {
                        flow::TrustError::BadHandle => {
                            anyhow!("no signed record for '{resolved_peer}'")
                        }
                        flow::TrustError::Unverified => anyhow!("peer record failed verification"),
                        flow::TrustError::IdentityChanged => anyhow!(
                    "identity changed for '{resolved_peer}'; compare the safety number first"
                ),
                        flow::TrustError::StaleRecord => {
                            anyhow!("stale record for '{resolved_peer}'")
                        }
                    },
                )?;
            let info = client::verification_info_for_record(
                &*store_guard,
                &identity,
                &peer,
                &peer_record,
            )?;
            if !matches!(info.level, TrustLevel::Pinned | TrustLevel::Verified) {
                return Err(anyhow!(
                    "first contact '{resolved_peer}' is unverified; add it as a contact first"
                ));
            }
            let mut deliver = |store: &mut FileStore,
                               handle: &Handle,
                               _record: &SignedRecord,
                               device: &Device,
                               item|
             -> mycellium_engine::reachability::DeliveryPath {
                client::deliver_or_park(store, &network, handle, device, item, now)
            };
            client::send_direct(
                &identity,
                &mut *store_guard,
                &mut OsPlatform,
                &me,
                &peer,
                &peer_record,
                &app,
                &mut deliver,
            )?;
            this.selected_peer = peer.as_str().to_string();
            this.peer.clear();
            this.message.clear();
            Ok(())
        });
    }

    fn retry_outbox(&mut self) {
        self.run("Tried pending deliveries", |this| {
            let now = OsPlatform.now_unix_secs();
            let session = this.session_mut()?;
            let network = session.network.clone();
            let mut store = session
                .store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))?;
            client::make_outbox_due(&mut *store)?;
            let _ = client::flush_due_outbox(&mut *store, &network, now)?;
            Ok(())
        });
    }

    fn start_listener(
        &mut self,
        me: Handle,
        my_record: SignedRecord,
        identity: Arc<Identity>,
        store: Arc<Mutex<FileStore>>,
        addr: String,
    ) -> Result<()> {
        let session = self.session_mut()?;
        if let Some(active) = &session.listener_addr {
            if active == &addr {
                return Ok(());
            }
            return Err(anyhow!(
                "already listening on {active}; restart to use {addr}"
            ));
        }
        let mut listener = TcpTransport::listening(&addr)
            .map_err(|err| anyhow!("could not listen on {addr}: {err}"))?;
        session.listener_addr = Some(addr.clone());
        let events = self.events_tx.clone();
        let ctx = self.ctx.clone();
        thread::spawn(move || loop {
            let mut conn = match listener.accept() {
                Ok(conn) => conn,
                Err(err) => {
                    let _ = events.send(RuntimeEvent::Error(format!("listener failed: {err}")));
                    ctx.request_repaint();
                    return;
                }
            };
            let identity = Arc::clone(&identity);
            let store = Arc::clone(&store);
            let my_record = my_record.clone();
            let me = me.clone();
            let events = events.clone();
            let ctx = ctx.clone();
            thread::spawn(move || {
                let mut platform = OsPlatform;
                let mut sink = EventSink {
                    sender: events.clone(),
                    ctx: ctx.clone(),
                };
                while let Ok(bytes) = conn.recv_frame() {
                    let Ok(frame) = wire::decode::<PeerFrame>(&bytes) else {
                        continue;
                    };
                    let PeerFrame::Delivery { delivery_id, item } = frame else {
                        continue;
                    };
                    let Ok(mut store) = store.lock() else {
                        let _ =
                            events.send(RuntimeEvent::Error("local store lock poisoned".into()));
                        ctx.request_repaint();
                        return;
                    };
                    if client::accept_delivery(
                        &identity,
                        &me,
                        &my_record,
                        &[],
                        &mut platform,
                        &mut store,
                        &mut conn,
                        delivery_id,
                        *item,
                        &mut sink,
                    ) {
                        let _ = events.send(RuntimeEvent::Notice("Received message".into()));
                        ctx.request_repaint();
                    }
                }
            });
        });
        self.notice = format!("Listening on {addr}");
        Ok(())
    }

    fn drain_events(&mut self) {
        while let Ok(event) = self.events_rx.try_recv() {
            match event {
                RuntimeEvent::Flow(FlowEvent::DirectMessage { from, text, .. }) => {
                    self.selected_peer = from.clone();
                    self.notice = format!("Received from {from}: {text}");
                    self.error.clear();
                }
                RuntimeEvent::Flow(FlowEvent::GroupMessage { name, sender, .. }) => {
                    self.notice = format!("Received in {name} from {sender}");
                    self.error.clear();
                }
                RuntimeEvent::Flow(FlowEvent::GroupJoined { name, inviter, .. }) => {
                    self.notice = format!("Joined {name} from {inviter}");
                    self.error.clear();
                }
                RuntimeEvent::Flow(FlowEvent::Receipt { from, .. }) => {
                    self.notice = format!("Receipt from {from}");
                    self.error.clear();
                }
                RuntimeEvent::Flow(_) => {
                    self.notice = "Received update".into();
                    self.error.clear();
                }
                RuntimeEvent::Notice(message) => {
                    self.notice = message;
                    self.error.clear();
                }
                RuntimeEvent::Error(message) => {
                    self.error = message;
                    self.notice.clear();
                }
            }
        }
    }
}

impl eframe::App for LinuxClient {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_events();
        egui::Frame::central_panel(ui.style()).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Mycellium");
                ui.label("hard-serverless Linux client");
                if let Some(session) = &self.session {
                    let info = client::identity_info(&session.identity);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(short_hex(&info.device));
                    });
                }
            });

            if self.session.is_none() {
                self.unlock_view(ui);
                return;
            }

            ui.horizontal(|ui| {
                tab(ui, &mut self.tab, Tab::Chats, "Chats");
                tab(ui, &mut self.tab, Tab::Contacts, "Contacts");
                tab(ui, &mut self.tab, Tab::Records, "Records");
                tab(ui, &mut self.tab, Tab::Outbox, "Outbox");
            });
            ui.separator();
            self.status(ui);

            match self.tab {
                Tab::Chats => self.chats_view(ui),
                Tab::Contacts => self.contacts_view(ui),
                Tab::Records => self.records_view(ui),
                Tab::Outbox => self.outbox_view(ui),
            }
        });
    }
}

impl LinuxClient {
    fn unlock_view(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.heading("Unlock this device");
            ui.label(self.data_dir.display().to_string());
            ui.add_space(16.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.passphrase)
                    .password(true)
                    .hint_text("Passphrase"),
            );
            ui.add(egui::TextEdit::singleline(&mut self.display_name).hint_text("Display name"));
            ui.horizontal(|ui| {
                if ui.button("Unlock").clicked() {
                    self.unlock();
                }
                if ui.button("Create identity").clicked() {
                    self.create_identity();
                }
            });
            self.status(ui);
        });
    }

    fn chats_view(&mut self, ui: &mut egui::Ui) {
        ui.columns(2, |cols| {
            cols[0].heading("Conversations");
            let conversations = self
                .session
                .as_mut()
                .and_then(|s| {
                    let mut store = s.store.lock().ok()?;
                    client::conversations(&mut *store, OsPlatform.now_unix_secs()).ok()
                })
                .unwrap_or_default();
            if conversations.is_empty() {
                cols[0].label("No conversations yet.");
            }
            for conversation in conversations {
                if cols[0]
                    .selectable_label(self.selected_peer == conversation.peer, &conversation.peer)
                    .clicked()
                {
                    self.selected_peer = conversation.peer;
                }
            }

            cols[1].heading(if self.selected_peer.is_empty() {
                "New message"
            } else {
                self.selected_peer.as_str()
            });
            if !self.selected_peer.is_empty() {
                if let Some(session) = &mut self.session {
                    let messages = session.store.lock().ok().and_then(|mut store| {
                        client::history_with(
                            &mut *store,
                            &self.selected_peer,
                            OsPlatform.now_unix_secs(),
                        )
                        .ok()
                    });
                    if let Some((_peer, messages)) = messages {
                        egui::ScrollArea::vertical()
                            .max_height(360.0)
                            .show(&mut cols[1], |ui| {
                                for message in messages {
                                    let who = if message.from_me {
                                        "You"
                                    } else {
                                        &self.selected_peer
                                    };
                                    ui.label(format!("{who}: {}", message.text));
                                }
                            });
                    }
                }
            }
            cols[1].add(egui::TextEdit::singleline(&mut self.my_handle).hint_text("Your handle"));
            cols[1].add(egui::TextEdit::singleline(&mut self.peer).hint_text("Peer or contact"));
            cols[1].add(
                egui::TextEdit::multiline(&mut self.message)
                    .hint_text("Message")
                    .desired_rows(3),
            );
            if cols[1].button("Save for delivery").clicked() {
                self.send_message();
            }
        });
    }

    fn contacts_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.contact_nickname).hint_text("Nickname"));
            ui.add(egui::TextEdit::singleline(&mut self.contact_handle).hint_text("Handle"));
            if ui.button("Add contact").clicked() {
                self.add_contact();
            }
        });
        ui.separator();
        if let Some(session) = &self.session {
            let contacts = session
                .store
                .lock()
                .map_err(|_| anyhow!("local store lock poisoned"))
                .and_then(|store| client::list_contacts(&*store));
            match contacts {
                Ok(contacts) if contacts.is_empty() => {
                    ui.label("No contacts yet.");
                }
                Ok(contacts) => {
                    for contact in contacts {
                        ui.horizontal(|ui| {
                            ui.label(contact.nickname);
                            ui.monospace(contact.handle);
                            ui.label(if contact.verified {
                                "verified"
                            } else {
                                "pinned"
                            });
                        });
                    }
                }
                Err(err) => {
                    ui.label(err.to_string());
                }
            }
        }
    }

    fn records_view(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.record_handle).hint_text("Handle"));
            ui.add(egui::TextEdit::singleline(&mut self.record_addr).hint_text("host:port"));
            if ui.button("Register active device").clicked() {
                self.register_record();
            }
        });
        ui.add(
            egui::TextEdit::multiline(&mut self.record_blob)
                .hint_text("Signed record")
                .desired_rows(5),
        );
        if ui.button("Import record").clicked() {
            self.import_record();
        }
        ui.separator();
        if let Some(session) = &self.session {
            let records = session
                .store
                .lock()
                .ok()
                .and_then(|store| client::list_records(&*store).ok())
                .unwrap_or_default();
            for record in records {
                ui.horizontal(|ui| {
                    ui.monospace(&record.handle);
                    ui.label(&record.record.record.name);
                    if ui.button("Copy/export").clicked() {
                        self.record_handle = record.handle.clone();
                        self.record_blob = client::encode_record(&record.record);
                    }
                });
            }
        }
    }

    fn outbox_view(&mut self, ui: &mut egui::Ui) {
        if ui.button("Try pending now").clicked() {
            self.retry_outbox();
        }
        if let Some(session) = &self.session {
            let entries = session
                .store
                .lock()
                .ok()
                .and_then(|store| client::list_outbox(&*store).ok())
                .unwrap_or_default();
            let pending = entries.iter().filter(|entry| entry.is_pending()).count();
            ui.label(format!("{pending} pending local deliveries"));
            ui.separator();
            for entry in entries {
                ui.horizontal(|ui| {
                    ui.monospace(&entry.id[..12.min(entry.id.len())]);
                    ui.label(entry.recipient);
                    ui.label(format!("{:?}", entry.status));
                    ui.label(format!("{} attempts", entry.attempts));
                });
            }
        }
    }

    fn status(&mut self, ui: &mut egui::Ui) {
        if !self.error.is_empty() {
            ui.colored_label(egui::Color32::from_rgb(255, 116, 116), &self.error);
        } else if !self.notice.is_empty() {
            ui.colored_label(egui::Color32::from_rgb(128, 220, 155), &self.notice);
        }
    }
}

fn tab(ui: &mut egui::Ui, current: &mut Tab, tab: Tab, label: &str) {
    if ui.selectable_label(*current == tab, label).clicked() {
        *current = tab;
    }
}

fn open_history(data_dir: &std::path::Path, identity: &Identity) -> Result<FileStore> {
    FileStore::open(data_dir.join("history"), identity.storage_key())
        .map_err(|err| anyhow!("could not open local history store: {err}"))
}

fn default_data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(dir).join("mycellium");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/share/mycellium");
    }
    PathBuf::from(".mycellium")
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    OsPlatform.fill_random(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn short_hex(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}
