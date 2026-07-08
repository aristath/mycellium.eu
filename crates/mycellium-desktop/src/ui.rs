//! The egui frontend: a thin view over the [`crate::engine`] controller. It holds
//! only view-model snapshots the controller pushes, forwards user actions as
//! [`Command`]s, and never touches the async engine directly.
//!
//! Layout: a top bar (account + status), a left panel (add-contact form, contacts,
//! conversations), a central panel (the selected transcript + composer), and a
//! bottom activity log (status, trust signals, errors).

use std::collections::HashMap;
use std::path::PathBuf;

use eframe::egui;
use mycellium_app::{config, Config};

use crate::engine::{
    spawn, Command, ContactView, ConversationView, EngineHandle, MessageView, UiEvent,
};

/// Launch the desktop client.
pub fn run() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([960.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Mycellium",
        options,
        Box::new(|cc| Ok(Box::new(DesktopApp::new(cc)))),
    )
}

/// A pending relay/account setup, shown when no account exists yet.
#[derive(Default)]
struct SetupForm {
    import_nsec: String,
    relay: String,
    error: Option<String>,
}

struct DesktopApp {
    ctx: egui::Context,
    data_dir: PathBuf,
    engine: Option<EngineHandle>,

    setup: SetupForm,

    account_npub: String,
    status: String,
    contacts: Vec<ContactView>,
    conversations: Vec<ConversationView>,
    transcripts: HashMap<String, Vec<MessageView>>,
    selected: Option<String>,
    log: Vec<String>,

    add_handle: String,
    add_name: String,
    composer: String,
}

impl DesktopApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let data_dir = config::default_data_dir().unwrap_or_else(|_| PathBuf::from(".mycellium"));
        let mut app = Self {
            ctx: cc.egui_ctx.clone(),
            data_dir,
            engine: None,
            setup: SetupForm {
                relay: config::DEFAULT_RELAY.to_string(),
                ..Default::default()
            },
            account_npub: String::new(),
            status: "no account".to_string(),
            contacts: Vec::new(),
            conversations: Vec::new(),
            transcripts: HashMap::new(),
            selected: None,
            log: Vec::new(),
            add_handle: String::new(),
            add_name: String::new(),
            composer: String::new(),
        };
        // Open an existing account automatically; otherwise fall to the setup screen.
        if Config::exists(&app.data_dir) {
            match Config::load(&app.data_dir) {
                Ok(cfg) => app.start_engine(cfg),
                Err(e) => app.setup.error = Some(e.to_string()),
            }
        }
        app
    }

    /// Persist (if new) and start the controller for `config`.
    fn start_engine(&mut self, config: Config) {
        let ctx = self.ctx.clone();
        let handle = spawn(config, self.data_dir.clone(), move || ctx.request_repaint());
        self.account_npub = handle.account_npub.clone();
        self.status = "starting…".to_string();
        self.engine = Some(handle);
    }

    /// Apply everything the controller has emitted since the last frame.
    fn drain_events(&mut self) {
        let Some(engine) = &self.engine else { return };
        let mut events = Vec::new();
        while let Some(ev) = engine.try_recv() {
            events.push(ev);
        }
        for ev in events {
            match ev {
                UiEvent::Ready => {
                    self.status = "connected".to_string();
                    self.send(Command::Refresh);
                }
                UiEvent::Status(s) => self.status = s,
                UiEvent::Error(e) => self.log.push(format!("⚠ {e}")),
                UiEvent::Contacts(c) => self.contacts = c,
                UiEvent::Conversations(c) => self.conversations = c,
                UiEvent::Transcript {
                    conversation,
                    messages,
                } => {
                    self.transcripts.insert(conversation, messages);
                }
                UiEvent::ConversationStarted { conversation, .. } => {
                    self.select(conversation);
                }
                UiEvent::Trust(t) => self.log.push(format!("🔑 {t}")),
            }
        }
    }

    fn send(&self, command: Command) {
        if let Some(engine) = &self.engine {
            engine.send(command);
        }
    }

    fn select(&mut self, conversation: String) {
        self.send(Command::OpenConversation {
            conversation: conversation.clone(),
        });
        self.selected = Some(conversation);
    }
}

impl eframe::App for DesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events();

        if self.engine.is_none() {
            self.setup_screen(ctx);
        } else {
            self.main_screen(ctx);
        }

        // A slow steady tick so late relay events surface even if the waker missed.
        ctx.request_repaint_after(std::time::Duration::from_millis(500));
    }
}

impl DesktopApp {
    fn setup_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| {
                ui.heading("Welcome to Mycellium");
                ui.label("Create a new identity, or import a Nostr key you already hold.");
            });
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                ui.label("Relay:");
                ui.text_edit_singleline(&mut self.setup.relay);
            });
            ui.add_space(8.0);

            let relays = vec![self.setup.relay.trim().to_string()];
            let mut chosen: Option<Config> = None;

            ui.horizontal(|ui| {
                if ui.button("Create new account").clicked() {
                    chosen = Some(Config::generate(relays.clone()));
                }
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label("or import nsec:");
                ui.text_edit_singleline(&mut self.setup.import_nsec);
                if ui.button("Import").clicked() {
                    match Config::import(self.setup.import_nsec.trim(), relays.clone()) {
                        Ok(cfg) => chosen = Some(cfg),
                        Err(e) => self.setup.error = Some(e.to_string()),
                    }
                }
            });

            if let Some(err) = &self.setup.error {
                ui.add_space(8.0);
                ui.colored_label(egui::Color32::RED, err);
            }

            if let Some(cfg) = chosen {
                match cfg.create(&self.data_dir, false) {
                    Ok(()) => {
                        self.setup.error = None;
                        self.start_engine(cfg);
                    }
                    Err(e) => self.setup.error = Some(e.to_string()),
                }
            }
        });
    }

    fn main_screen(&mut self, ctx: &egui::Context) {
        // Commands gathered while rendering, dispatched after (avoids borrow tangles).
        let mut outgoing: Vec<Command> = Vec::new();
        let mut to_select: Option<String> = None;

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Mycellium");
                ui.separator();
                ui.label(short(&self.account_npub));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(&self.status);
                });
            });
        });

        egui::TopBottomPanel::bottom("log")
            .resizable(true)
            .default_height(96.0)
            .show(ctx, |ui| {
                ui.label("Activity");
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in &self.log {
                            ui.label(line);
                        }
                    });
            });

        egui::SidePanel::left("side")
            .default_width(280.0)
            .show(ctx, |ui| {
                ui.collapsing("Add contact", |ui| {
                    ui.label("npub / hex key");
                    ui.text_edit_singleline(&mut self.add_handle);
                    ui.label("name (optional)");
                    ui.text_edit_singleline(&mut self.add_name);
                    if ui.button("Add").clicked() && !self.add_handle.trim().is_empty() {
                        let name = (!self.add_name.trim().is_empty())
                            .then(|| self.add_name.trim().to_string());
                        outgoing.push(Command::AddContact {
                            handle: self.add_handle.trim().to_string(),
                            name,
                        });
                        self.add_handle.clear();
                        self.add_name.clear();
                    }
                });

                ui.separator();
                ui.heading("Contacts");
                egui::ScrollArea::vertical()
                    .id_salt("contacts")
                    .max_height(180.0)
                    .show(ui, |ui| {
                        for c in &self.contacts {
                            ui.horizontal(|ui| {
                                ui.label(format!("{} · {}", c.name, c.trust));
                                if ui.small_button("chat").clicked() {
                                    outgoing.push(Command::StartConversation {
                                        contact: c.id.clone(),
                                    });
                                }
                            });
                        }
                    });

                ui.separator();
                ui.heading("Conversations");
                egui::ScrollArea::vertical()
                    .id_salt("conversations")
                    .show(ui, |ui| {
                        for conv in &self.conversations {
                            let selected = self.selected.as_deref() == Some(conv.id.as_str());
                            if ui.selectable_label(selected, &conv.title).clicked() {
                                to_select = Some(conv.id.clone());
                            }
                        }
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| match &self.selected {
            None => {
                ui.centered_and_justified(|ui| {
                    ui.label("Pick a conversation, or start one from a contact.");
                });
            }
            Some(conv_id) => {
                let empty = Vec::new();
                let messages = self.transcripts.get(conv_id).unwrap_or(&empty);
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for m in messages {
                            let who = if m.from_me { "you" } else { m.author.as_str() };
                            ui.label(format!("{who}: {}", m.text));
                        }
                    });
                ui.separator();
                ui.horizontal(|ui| {
                    let entry = ui.text_edit_singleline(&mut self.composer);
                    let send = ui.button("Send").clicked()
                        || (entry.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                    if send && !self.composer.trim().is_empty() {
                        outgoing.push(Command::SendText {
                            conversation: conv_id.clone(),
                            text: self.composer.trim().to_string(),
                        });
                        self.composer.clear();
                    }
                });
            }
        });

        if let Some(conv) = to_select {
            self.select(conv);
        }
        for command in outgoing {
            self.send(command);
        }
    }
}

/// Shorten a long key string for display.
fn short(s: &str) -> String {
    if s.len() <= 20 {
        s.to_string()
    } else {
        format!("{}…{}", &s[..12], &s[s.len() - 6..])
    }
}
