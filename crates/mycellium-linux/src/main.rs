//! Native Linux Mycellium client.
//!
//! This is deliberately a thin shell: it owns the window, local unlock UX, and
//! rendering. Protocol and local-state behavior stay in `mycellium-client`.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use eframe::egui;

use mycellium_core::identity::{Handle, Identity};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, SignedRecord};
use mycellium_storage::filestore::FileStore;
use mycellium_storage::store;
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
    identity: Identity,
    store: FileStore,
    network: client::DirectNetwork,
}

struct LinuxClient {
    data_dir: PathBuf,
    passphrase: String,
    display_name: String,
    session: Option<Session>,
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

        Self {
            data_dir: default_data_dir(),
            passphrase: String::new(),
            display_name: String::new(),
            session: None,
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
                identity,
                store,
                network,
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
                identity,
                store,
                network,
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
            let session = this.session_mut()?;
            let record = client::publish_active_device_record(
                &mut session.store,
                &mut OsPlatform,
                &session.identity,
                &handle,
                &name,
                &addr,
            )?;
            this.my_handle = handle.as_str().to_string();
            this.record_blob = client::encode_record(&record);
            Ok(())
        });
    }

    fn import_record(&mut self) {
        self.run("Record imported", |this| {
            let handle = Handle::new(this.record_handle.trim())
                .map_err(|_| anyhow!("enter a valid handle"))?;
            let record = client::decode_record(this.record_blob.trim())?;
            let session = this.session_mut()?;
            client::import_record(&mut session.store, &handle, record)
        });
    }

    fn add_contact(&mut self) {
        self.run("Contact saved", |this| {
            let handle = Handle::new(this.contact_handle.trim())
                .map_err(|_| anyhow!("enter a valid handle"))?;
            let nickname = this.contact_nickname.trim().to_string();
            let session = this.session_mut()?;
            client::add_contact(&mut session.store, &nickname, &handle)
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
            let peer = Handle::new(client::resolve_name(
                &this.session_mut()?.store,
                resolved_peer.trim(),
            )?)
            .map_err(|_| anyhow!("enter a valid peer"))?;
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
            let peer_record = client::require_record(&session.store, &peer)?;
            let network = session.network.clone();
            let now = OsPlatform.now_unix_secs();
            let mut deliver = |store: &mut FileStore,
                               handle: &Handle,
                               _record: &SignedRecord,
                               device: &Device,
                               item|
             -> mycellium_engine::reachability::DeliveryPath {
                let delivery_id = random_id();
                client::deliver_or_park(store, &network, handle, device, delivery_id, item, now)
            };
            client::send_direct(
                &session.identity,
                &mut session.store,
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
            client::make_outbox_due(&mut session.store)?;
            let _ = client::flush_due_outbox(&mut session.store, &network, now)?;
            Ok(())
        });
    }
}

impl eframe::App for LinuxClient {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
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
                .and_then(|s| client::conversations(&mut s.store, OsPlatform.now_unix_secs()).ok())
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
                    if let Ok((_peer, messages)) = client::history_with(
                        &mut session.store,
                        &self.selected_peer,
                        OsPlatform.now_unix_secs(),
                    ) {
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
            match client::list_contacts(&session.store) {
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
            for record in client::list_records(&session.store).unwrap_or_default() {
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
            let entries = client::list_outbox(&session.store).unwrap_or_default();
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
    let mut bytes = [0u8; 6];
    OsPlatform.fill_random(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn short_hex(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect()
}
