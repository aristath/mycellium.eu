//! The **controller**: a GUI-agnostic bridge between a synchronous UI and the
//! async [`mycellium_app::App`] engine.
//!
//! [`spawn`] starts a dedicated thread running a Tokio runtime that owns the `App`,
//! announces this device to the relays, then loops: it drains [`Command`]s from the
//! UI, applies them to the engine, and polls the engine for incoming events —
//! pushing [`UiEvent`]s back over a channel the UI drains each frame. A `waker`
//! callback is fired on every emission so the UI can request a repaint.
//!
//! Access to the `App` is single-threaded (one task, serialized), so there is no
//! shared mutable state and no locks: the UI only ever sees plain view-model
//! snapshots ([`ContactView`], [`ConversationView`], [`MessageView`]).

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

use mycellium_app::{
    App, AppEvent, Config, Contact, ConversationId, Device, StoredMessage, TrustEvent,
};
use nostr::nips::nip19::ToBech32;
use nostr::PublicKey;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// How long each engine poll waits for an incoming event before looping back to
/// check for queued commands — the upper bound on command latency.
const POLL: Duration = Duration::from_millis(250);

/// A request from the UI to the engine.
#[derive(Debug, Clone)]
pub enum Command {
    /// Reload the contact and conversation lists.
    Refresh,
    /// Pin a contact by `npub`/hex key under an optional local name.
    AddContact {
        handle: String,
        name: Option<String>,
    },
    /// Start a 1:1 conversation with a pinned contact (by local id).
    StartConversation { contact: String },
    /// Load (or reload) a conversation's transcript.
    OpenConversation { conversation: String },
    /// Send a text message to a conversation.
    SendText { conversation: String, text: String },
    /// Shut the engine down cleanly.
    Shutdown,
}

/// A contact as the UI shows it.
#[derive(Debug, Clone)]
pub struct ContactView {
    pub id: String,
    pub name: String,
    pub npub: String,
    /// A short human trust label (`verified` / `pinned`).
    pub trust: String,
    pub nip05: Option<String>,
}

/// A conversation as the UI shows it.
#[derive(Debug, Clone)]
pub struct ConversationView {
    pub id: String,
    pub title: String,
}

/// A single transcript line as the UI shows it.
#[derive(Debug, Clone)]
pub struct MessageView {
    pub from_me: bool,
    /// `you` for our own sends, else a short author-key fingerprint.
    pub author: String,
    pub text: String,
    pub timestamp: u64,
}

/// An update from the engine to the UI.
#[derive(Debug, Clone)]
pub enum UiEvent {
    /// Startup finished: connected, subscribed, and announced to the relays.
    Ready,
    /// A transient status line.
    Status(String),
    /// Something went wrong (non-fatal unless it precedes no `Ready`).
    Error(String),
    /// The full contact list.
    Contacts(Vec<ContactView>),
    /// The full conversation list.
    Conversations(Vec<ConversationView>),
    /// A conversation's full transcript.
    Transcript {
        conversation: String,
        messages: Vec<MessageView>,
    },
    /// A conversation was just created locally (so the UI can select it).
    ConversationStarted {
        contact: String,
        conversation: String,
    },
    /// A passive trust signal for a pinned contact (key change, device change, …).
    Trust(String),
}

/// A handle the UI holds: send [`Command`]s, drain [`UiEvent`]s, read account info.
pub struct EngineHandle {
    /// This account's `npub`, for display.
    pub account_npub: String,
    commands: UnboundedSender<Command>,
    events: Receiver<UiEvent>,
}

impl EngineHandle {
    /// Queue a command for the engine (non-blocking).
    pub fn send(&self, command: Command) {
        let _ = self.commands.send(command);
    }

    /// Take the next pending event, if any (non-blocking) — call each UI frame.
    pub fn try_recv(&self) -> Option<UiEvent> {
        self.events.try_recv().ok()
    }
}

/// Start the engine for `config`/`data_dir`. `waker` is fired after every emitted
/// event so a UI can request a repaint; pass a no-op for headless use.
pub fn spawn(config: Config, data_dir: PathBuf, waker: impl Fn() + Send + 'static) -> EngineHandle {
    let account_npub = config
        .account_keys()
        .ok()
        .and_then(|k| k.public_key().to_bech32().ok())
        .unwrap_or_else(|| "unknown".to_string());

    let (cmd_tx, cmd_rx) = unbounded_channel();
    let (ev_tx, ev_rx) = channel();
    let emitter = Emitter {
        tx: ev_tx,
        waker: Box::new(waker),
    };

    thread::Builder::new()
        .name("mycellium-engine".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("engine tokio runtime");
            rt.block_on(run(config, data_dir, cmd_rx, emitter));
        })
        .expect("spawn engine thread");

    EngineHandle {
        account_npub,
        commands: cmd_tx,
        events: ev_rx,
    }
}

/// Wraps the event channel + repaint waker so every emission wakes the UI.
struct Emitter {
    tx: Sender<UiEvent>,
    waker: Box<dyn Fn() + Send>,
}

impl Emitter {
    fn emit(&self, event: UiEvent) {
        // If the UI is gone the send fails; the loop's command channel closing is
        // what actually stops us, so ignore the error here.
        let _ = self.tx.send(event);
        (self.waker)();
    }
}

/// The engine's whole lifetime: open, announce, then serve commands + incoming.
async fn run(
    config: Config,
    data_dir: PathBuf,
    mut commands: UnboundedReceiver<Command>,
    em: Emitter,
) {
    let mut app = match startup(&config, &data_dir, &em).await {
        Ok(app) => app,
        Err(msg) => {
            em.emit(UiEvent::Error(msg));
            return;
        }
    };

    em.emit(UiEvent::Ready);
    push_contacts(&app, &em);
    push_conversations(&app, &em);

    loop {
        // Apply every queued command first (each may touch the engine).
        loop {
            match commands.try_recv() {
                Ok(Command::Shutdown) => {
                    app.shutdown().await;
                    return;
                }
                Ok(command) => handle_command(&mut app, &em, command).await,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                // UI dropped the sender — shut down.
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    app.shutdown().await;
                    return;
                }
            }
        }
        // Then poll the relay for one incoming event (bounded, so commands stay responsive).
        match app.next_event(POLL).await {
            Ok(Some(event)) => handle_incoming(&app, &em, event),
            Ok(None) => {}
            Err(e) => em.emit(UiEvent::Error(format!("receive error: {e}"))),
        }
    }
}

/// Open the app, connect, subscribe, and announce this device (KeyPackage +
/// single-device list) so contacts can reach it.
async fn startup(config: &Config, data_dir: &std::path::Path, em: &Emitter) -> Result<App, String> {
    let mut app = config
        .open(data_dir)
        .map_err(|e| format!("opening the account: {e}"))?;
    em.emit(UiEvent::Status("connecting…".into()));
    app.connect()
        .await
        .map_err(|e| format!("connecting: {e}"))?;
    app.subscribe()
        .await
        .map_err(|e| format!("subscribing: {e}"))?;
    app.publish_key_package()
        .await
        .map_err(|e| format!("publishing key package: {e}"))?;
    // A solo desktop device announces just itself. (A multi-device account is
    // managed from the device that holds the full device list.)
    app.publish_device_list(vec![Device::new(app.device_pubkey())])
        .await
        .map_err(|e| format!("publishing device list: {e}"))?;
    Ok(app)
}

async fn handle_command(app: &mut App, em: &Emitter, command: Command) {
    match command {
        Command::Shutdown => {} // handled in the loop
        Command::Refresh => {
            push_contacts(app, em);
            push_conversations(app, em);
        }
        Command::AddContact { handle, name } => {
            let Ok(pubkey) = PublicKey::parse(handle.trim()) else {
                em.emit(UiEvent::Error(format!(
                    "'{handle}' is not a valid npub or hex key"
                )));
                return;
            };
            let id = name
                .clone()
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| handle.trim().to_string());
            match app.add_contact(&id, pubkey, None, name).await {
                Ok(status) => {
                    em.emit(UiEvent::Status(format!("added {id} ({status:?})")));
                    push_contacts(app, em);
                }
                Err(e) => em.emit(UiEvent::Error(format!("adding contact: {e}"))),
            }
        }
        Command::StartConversation { contact } => match app.start_conversation(&contact).await {
            Ok(conv) => {
                em.emit(UiEvent::ConversationStarted {
                    contact,
                    conversation: conv.as_str().to_string(),
                });
                push_conversations(app, em);
                push_transcript(app, em, conv.as_str());
            }
            Err(e) => em.emit(UiEvent::Error(format!("starting conversation: {e}"))),
        },
        Command::OpenConversation { conversation } => push_transcript(app, em, &conversation),
        Command::SendText { conversation, text } => {
            let Ok(conv) = ConversationId::parse(&conversation) else {
                em.emit(UiEvent::Error("invalid conversation id".into()));
                return;
            };
            match app.send_text(&conv, &text).await {
                Ok(()) => push_transcript(app, em, &conversation),
                Err(e) => em.emit(UiEvent::Error(format!("sending: {e}"))),
            }
        }
    }
}

fn handle_incoming(app: &App, em: &Emitter, event: AppEvent) {
    match event {
        AppEvent::Message(msg) => {
            let conv = msg.conversation.as_str().to_string();
            // A message may open a brand-new conversation (someone messaged us), so
            // refresh the list too, then push the up-to-date transcript.
            push_conversations(app, em);
            push_transcript(app, em, &conv);
            em.emit(UiEvent::Status("new message".into()));
        }
        AppEvent::Trust(trust) => em.emit(UiEvent::Trust(describe_trust(&trust))),
    }
}

// -- view-model projections -------------------------------------------------

fn push_contacts(app: &App, em: &Emitter) {
    match app.contacts() {
        Ok(contacts) => em.emit(UiEvent::Contacts(
            contacts.iter().map(contact_view).collect(),
        )),
        Err(e) => em.emit(UiEvent::Error(format!("loading contacts: {e}"))),
    }
}

fn push_conversations(app: &App, em: &Emitter) {
    match app.conversations() {
        Ok(list) => em.emit(UiEvent::Conversations(
            list.into_iter()
                .map(|(id, title)| ConversationView {
                    id: id.as_str().to_string(),
                    title,
                })
                .collect(),
        )),
        Err(e) => em.emit(UiEvent::Error(format!("loading conversations: {e}"))),
    }
}

fn push_transcript(app: &App, em: &Emitter, conversation: &str) {
    let Ok(conv) = ConversationId::parse(conversation) else {
        em.emit(UiEvent::Error("invalid conversation id".into()));
        return;
    };
    match app.transcript(&conv) {
        Ok(messages) => em.emit(UiEvent::Transcript {
            conversation: conversation.to_string(),
            messages: messages.iter().map(message_view).collect(),
        }),
        Err(e) => em.emit(UiEvent::Error(format!("loading transcript: {e}"))),
    }
}

fn contact_view(c: &Contact) -> ContactView {
    ContactView {
        id: c.id.clone(),
        name: c.name.clone().unwrap_or_else(|| c.id.clone()),
        npub: c.account.to_bech32().unwrap_or_else(|_| c.account.to_hex()),
        trust: if c.verified { "verified" } else { "pinned" }.to_string(),
        nip05: c.nip05.clone(),
    }
}

fn message_view(m: &StoredMessage) -> MessageView {
    MessageView {
        from_me: m.from_me,
        author: match &m.author {
            Some(pk) => short_key(pk),
            None => "you".to_string(),
        },
        text: m.text.clone(),
        timestamp: m.timestamp,
    }
}

fn short_key(pk: &PublicKey) -> String {
    let hex = pk.to_hex();
    format!("{}…", &hex[..hex.len().min(8)])
}

fn describe_trust(t: &TrustEvent) -> String {
    match t {
        TrustEvent::KeyMigrationPending {
            contact,
            new_safety_number,
            ..
        } => format!(
            "{contact} published a key migration — compare the new safety number \
             out of band before accepting: {new_safety_number}"
        ),
        TrustEvent::ContactDevicesChanged { contact, devices } => {
            format!(
                "{contact}'s device list changed ({} device(s))",
                devices.len()
            )
        }
        TrustEvent::ForgedMigration { contact, reason } => {
            format!("{contact}: a forged key-migration was rejected ({reason})")
        }
        TrustEvent::Nip05Mismatch { contact, .. } => format!(
            "{contact}'s NIP-05 name now resolves to a DIFFERENT key — possible \
             impersonation; do not trust it without re-verifying"
        ),
    }
}
