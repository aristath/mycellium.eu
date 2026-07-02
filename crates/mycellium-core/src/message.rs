//! The application message: the structured payload carried inside the encrypted
//! channel (1:1, offline, and group). Giving each message an id lets later
//! messages **reply to** or **react to** an earlier one.
//!
//! This is the plaintext that gets encrypted — the transports never see it.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::error::Error;

/// A message's content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body {
    /// Plain text.
    Text(String),
    /// A reply to the message with id `to`.
    Reply {
        /// Id of the message being replied to.
        to: String,
        /// The reply text.
        text: String,
    },
    /// A reaction (e.g. an emoji) to the message with id `to`.
    Reaction {
        /// Id of the message being reacted to.
        to: String,
        /// The reaction, e.g. `👍`.
        emoji: String,
    },
    /// A delivery/read receipt for the message with id `message_id`.
    Receipt {
        /// Id of the message being acknowledged.
        message_id: String,
        /// `true` once read, `false` for delivered-only.
        read: bool,
    },
    /// A file attachment (carried end-to-end like any other message).
    File {
        /// File name (basename only).
        name: String,
        /// MIME type, best-effort.
        mime: String,
        /// The file bytes.
        data: Vec<u8>,
    },
    /// An edit of a previous message (by id).
    Edit {
        /// Id of the message being edited.
        to: String,
        /// The new text.
        text: String,
    },
    /// A deletion (unsend) of a previous message (by id).
    Delete {
        /// Id of the message being deleted.
        to: String,
    },
}

/// A structured application message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppMessage {
    /// A short id, assigned by the sender, that others can reference.
    pub id: String,
    /// Sender's clock (display/ordering only).
    pub timestamp: u64,
    /// Unix time after which this message should disappear, if any.
    pub expires_at: Option<u64>,
    /// The content.
    pub body: Body,
}

impl AppMessage {
    /// Whether this message has expired as of `now`.
    pub fn is_expired(&self, now: u64) -> bool {
        matches!(self.expires_at, Some(at) if now >= at)
    }

    /// Serialize to the bytes that get encrypted.
    pub fn encode(&self) -> Vec<u8> {
        crate::wire::encode(self)
    }

    /// Parse from decrypted bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        crate::wire::decode(bytes)
    }

    /// A human-readable rendering of the body.
    pub fn summary(&self) -> String {
        match &self.body {
            Body::Text(text) => text.clone(),
            Body::Reply { to, text } => {
                let mut s = String::from("↪ (re ");
                s.push_str(to);
                s.push_str(") ");
                s.push_str(text);
                s
            }
            Body::Reaction { to, emoji } => {
                let mut s = String::from("reacted ");
                s.push_str(emoji);
                s.push_str(" to ");
                s.push_str(to);
                s
            }
            Body::Receipt { message_id, read } => {
                let mut s = String::from(if *read { "✓✓ read " } else { "✓ delivered " });
                s.push_str(message_id);
                s
            }
            Body::File { name, data, .. } => {
                let mut s = String::from("📎 ");
                s.push_str(name);
                s.push_str(" (");
                // Small manual usize→string to stay no_std-friendly.
                s.push_str(&itoa(data.len()));
                s.push_str(" bytes)");
                s
            }
            Body::Edit { to, text } => {
                let mut s = String::from("✎ (edit ");
                s.push_str(to);
                s.push_str(") ");
                s.push_str(text);
                s
            }
            Body::Delete { to } => {
                let mut s = String::from("🗑 deleted ");
                s.push_str(to);
                s
            }
        }
    }
}

/// Minimal usize→decimal, avoiding `format!`/`alloc::format` in `no_std`.
fn itoa(mut n: usize) -> String {
    if n == 0 {
        return String::from("0");
    }
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    while n > 0 {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    core::str::from_utf8(&digits[i..]).unwrap().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn round_trip(msg: &AppMessage) {
        let decoded = AppMessage::decode(&msg.encode()).unwrap();
        assert_eq!(&decoded, msg);
    }

    #[test]
    fn every_body_round_trips() {
        round_trip(&AppMessage {
            id: "a1".to_string(),
            timestamp: 1,
            expires_at: None,
            body: Body::Text("hello".to_string()),
        });
        round_trip(&AppMessage {
            id: "a2".to_string(),
            timestamp: 2,
            expires_at: None,
            body: Body::Reply { to: "a1".to_string(), text: "hi back".to_string() },
        });
        round_trip(&AppMessage {
            id: "a3".to_string(),
            timestamp: 3,
            expires_at: None,
            body: Body::Reaction { to: "a1".to_string(), emoji: "👍".to_string() },
        });
        let file = AppMessage {
            id: "a4".to_string(),
            timestamp: 4,
            expires_at: None,
            body: Body::File {
                name: "hi.txt".to_string(),
                mime: "text/plain".to_string(),
                data: alloc::vec![1, 2, 3, 4, 5],
            },
        };
        round_trip(&file);
        assert_eq!(file.summary(), "📎 hi.txt (5 bytes)");
    }

    #[test]
    fn summaries_read_well() {
        let text = AppMessage { id: "x".into(), timestamp: 0, expires_at: None, body: Body::Text("yo".into()) };
        assert_eq!(text.summary(), "yo");
        let reply = AppMessage {
            id: "y".into(),
            timestamp: 0,
            expires_at: None,
            body: Body::Reply { to: "x".into(), text: "sup".into() },
        };
        assert_eq!(reply.summary(), "↪ (re x) sup");
        let react = AppMessage {
            id: "z".into(),
            timestamp: 0,
            expires_at: None,
            body: Body::Reaction { to: "x".into(), emoji: "🔥".into() },
        };
        assert_eq!(react.summary(), "reacted 🔥 to x");
    }

    #[test]
    fn expiry_is_respected() {
        let mut m = AppMessage { id: "e".into(), timestamp: 0, expires_at: None, body: Body::Text("x".into()) };
        assert!(!m.is_expired(1_000)); // no expiry set
        m.expires_at = Some(100);
        assert!(!m.is_expired(99));
        assert!(m.is_expired(100));
        assert!(m.is_expired(101));
    }
}
