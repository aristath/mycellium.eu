//! A full-screen terminal chat UI over an established session.
//!
//! Layers on the same full-duplex machinery as line-mode chat: a reader thread
//! decrypts incoming messages and forwards them to the UI over a channel, while
//! the UI thread renders the transcript + input box and sends what you type.
//! The rendering model ([`ChatModel`]) is separated out and unit-tested; the
//! ratatui event loop around it is thin.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use mycellium_core::message::AppMessage;
use mycellium_core::platform::Platform;
use mycellium_core::ratchet::RatchetMessage;
use mycellium_core::wire;

use mycellium_storage::filestore::FileStore;
use mycellium_engine::history::{self, StoredMessage};
use mycellium_transport::link::{FrameReader, FrameWriter};
use mycellium_engine::platform::OsPlatform;
use crate::Session;

/// Who authored a line in the transcript.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Author {
    Me,
    Peer,
    System,
}

/// One rendered line of the transcript.
#[derive(Clone, Debug)]
pub struct ChatLine {
    pub author: Author,
    pub text: String,
}

/// The transcript model — the testable heart of the UI.
#[derive(Debug)]
pub struct ChatModel {
    pub peer_name: String,
    pub lines: Vec<ChatLine>,
}

impl ChatModel {
    pub fn new(peer_name: impl Into<String>) -> Self {
        ChatModel { peer_name: peer_name.into(), lines: Vec::new() }
    }

    pub fn sent(&mut self, text: impl Into<String>) {
        self.lines.push(ChatLine { author: Author::Me, text: text.into() });
    }

    pub fn received(&mut self, text: impl Into<String>) {
        self.lines.push(ChatLine { author: Author::Peer, text: text.into() });
    }

    pub fn system(&mut self, text: impl Into<String>) {
        self.lines.push(ChatLine { author: Author::System, text: text.into() });
    }

    /// Render one line as styled spans, with a sender prefix.
    fn line_spans(&self, line: &ChatLine) -> Line<'static> {
        let (prefix, color) = match line.author {
            Author::Me => ("you".to_string(), Color::Cyan),
            Author::Peer => (self.peer_name.clone(), Color::Green),
            Author::System => ("*".to_string(), Color::DarkGray),
        };
        Line::from(vec![
            Span::styled(format!("{prefix}: "), Style::default().fg(color)),
            Span::raw(line.text.clone()),
        ])
    }
}

/// A message from the reader thread to the UI thread.
enum Incoming {
    Message(String),
    Disconnected,
}

/// Run the interactive terminal chat until the user quits (Esc / Ctrl-C).
pub fn run(
    reader: Box<dyn FrameReader>,
    mut writer: Box<dyn FrameWriter>,
    session: Session,
    history: Arc<Mutex<FileStore>>,
) -> Result<()> {
    let Session { ratchet, ad, peer_name } = session;
    let ratchet = Arc::new(Mutex::new(ratchet));
    let ad = Arc::new(ad);
    let peer_name = Arc::new(peer_name);

    // Reader thread: decrypt incoming frames, persist them, forward to the UI.
    let (tx, rx) = mpsc::channel::<Incoming>();
    {
        let ratchet = Arc::clone(&ratchet);
        let ad = Arc::clone(&ad);
        let history = Arc::clone(&history);
        let peer = Arc::clone(&peer_name);
        let mut reader = reader;
        std::thread::spawn(move || {
            let mut platform = OsPlatform;
            loop {
                let frame = match reader.recv_frame() {
                    Ok(frame) => frame,
                    Err(_) => {
                        let _ = tx.send(Incoming::Disconnected);
                        break;
                    }
                };
                if let Ok(msg) = wire::decode::<RatchetMessage>(&frame) {
                    let decrypted = ratchet.lock().unwrap().decrypt(&mut platform, &msg, &ad);
                    if let Ok(plaintext) = decrypted {
                        let text = match AppMessage::decode(&plaintext) {
                            Ok(m) => m.summary(),
                            Err(_) => String::from_utf8_lossy(&plaintext).into_owned(),
                        };
                        record(&history, &peer, false, text.clone());
                        let _ = tx.send(Incoming::Message(text));
                    }
                }
            }
        });
    }

    let mut terminal = ratatui::init();
    let mut model = ChatModel::new((*peer_name).clone());
    // Replay earlier conversation into the transcript (pruning expired).
    let now = OsPlatform.now_unix_secs();
    if let Ok(past) = history::load_active(&mut *history.lock().unwrap(), &peer_name, now) {
        for m in past {
            if m.from_me {
                model.sent(m.text);
            } else {
                model.received(m.text);
            }
        }
    }
    model.system("connected — end-to-end encrypted. Esc to quit.");
    let mut input = String::new();

    // Keep the loop in a closure so the terminal is always restored afterward.
    let outcome = (|| -> Result<()> {
        loop {
            while let Ok(event) = rx.try_recv() {
                match event {
                    Incoming::Message(text) => model.received(text),
                    Incoming::Disconnected => model.system("peer disconnected"),
                }
            }

            terminal.draw(|frame| render(frame, &model, &input))?;

            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    match key.code {
                        KeyCode::Esc => break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                        KeyCode::Enter => {
                            if !input.is_empty() {
                                submit(&ratchet, &ad, &mut *writer, &history, &peer_name, &mut model, &input);
                                input.clear();
                            }
                        }
                        KeyCode::Backspace => {
                            input.pop();
                        }
                        KeyCode::Char(c) => input.push(c),
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    })();

    ratatui::restore();
    outcome
}

/// Encrypt and send `input`, recording it in the transcript and history.
#[allow(clippy::too_many_arguments)]
fn submit(
    ratchet: &Arc<Mutex<mycellium_core::ratchet::Ratchet>>,
    ad: &[u8],
    writer: &mut dyn FrameWriter,
    history: &Arc<Mutex<FileStore>>,
    peer: &str,
    model: &mut ChatModel,
    input: &str,
) {
    if !ratchet.lock().unwrap().can_send() {
        model.system("waiting for the peer's first message before you can reply");
        return;
    }
    let app = AppMessage {
        id: String::new(),
        timestamp: OsPlatform.now_unix_secs(),
        expires_at: None,
        body: mycellium_core::message::Body::Text(input.to_string()),
    };
    let msg = ratchet.lock().unwrap().encrypt(&app.encode(), ad);
    match writer.send_frame(&wire::encode(&msg)) {
        Ok(()) => {
            model.sent(input);
            record(history, peer, true, input.to_string());
        }
        Err(_) => model.system("failed to send"),
    }
}

/// Persist one message to the encrypted history store (best-effort).
fn record(history: &Arc<Mutex<FileStore>>, peer: &str, from_me: bool, text: String) {
    let message = StoredMessage { id: String::new(), from_me, text, timestamp: OsPlatform.now_unix_secs(), expires_at: None };
    let _ = history::append(&mut *history.lock().unwrap(), peer, message);
}

fn render(frame: &mut Frame, model: &ChatModel, input: &str) {
    let chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(3)]).split(frame.area());

    // Show the last messages that fit inside the transcript pane.
    let visible = chunks[0].height.saturating_sub(2) as usize;
    let start = model.lines.len().saturating_sub(visible);
    let transcript: Vec<Line> = model.lines[start..].iter().map(|l| model.line_spans(l)).collect();

    frame.render_widget(
        Paragraph::new(transcript).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("mycellium — chatting with {}", model.peer_name)),
        ),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(input).block(
            Block::default()
                .borders(Borders::ALL)
                .title("message · Enter to send · Esc to quit"),
        ),
        chunks[1],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_records_authors_in_order() {
        let mut model = ChatModel::new("bob");
        model.system("connected");
        model.sent("hi");
        model.received("hey");
        model.sent("how are you");

        assert_eq!(model.lines.len(), 4);
        assert_eq!(model.lines[0].author, Author::System);
        assert_eq!(model.lines[1].author, Author::Me);
        assert_eq!(model.lines[2].author, Author::Peer);
        assert_eq!(model.lines[2].text, "hey");
        assert_eq!(model.lines[3].author, Author::Me);
    }

    #[test]
    fn peer_lines_are_labelled_with_the_peer_name() {
        let mut model = ChatModel::new("alice");
        model.received("ping");
        let line = model.line_spans(&model.lines[0]);
        // The first span is the "alice: " prefix.
        assert!(format!("{:?}", line).contains("alice"));
    }
}
