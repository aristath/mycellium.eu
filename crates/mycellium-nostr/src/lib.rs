//! Nostr **relay transport** for Mycellium's MLS-over-Nostr (Marmot) stack.
//!
//! # What this owns vs. what `mycellium-mls` owns
//!
//! This crate is a **thin, honest async wrapper** over [`nostr_sdk::Client`]. It
//! owns exactly one thing: **moving already-built Nostr events across a relay
//! socket** — connecting, publishing, subscribing, and querying. It knows
//! nothing about MLS crypto or the Marmot event format.
//!
//! The layer above it, [`mycellium-mls`](mycellium_mls), owns the crypto and the
//! event *building*: it drives MDK, produces the KeyPackage (kind:30443),
//! gift-wraps the Welcome rumor (kind:1059 wrapper over a kind:444 rumor via
//! NIP-59), and encrypts the kind:445 group message. A caller signs an event
//! with `mycellium-mls`'s `wire` helpers and hands the finished [`Event`] to
//! this crate's [`NostrTransport::publish`]; incoming events pulled off a
//! subscription here are routed back into `mycellium-mls`'s `MlsEngine`.
//!
//! ```text
//!   mycellium-mls   MlsEngine + wire   (crypto + event format)
//!         │  builds/decrypts Events
//!         ▼
//!   mycellium-nostr NostrTransport     (this crate: relay I/O only)
//!         │  publish / subscribe / fetch
//!         ▼
//!        relay  ── ws:// socket ──  relay
//! ```
//!
//! # Version pinning
//!
//! Pinned to the **nostr 0.44** line (`nostr-sdk = "0.44"`), matching MDK 0.8's
//! re-exported `nostr` types so events built by `mycellium-mls` are the exact
//! [`Event`] type this transport ships. Do not float to a `0.45-alpha` without
//! re-validating the round-trip — see `mycellium-mls`'s alpha note.

use std::time::Duration;

use nostr_sdk::prelude::{Client, Event, EventId, Filter, Keys, Kind, PublicKey, RelayUrl};
use nostr_sdk::{RelayPoolNotification, SubscriptionId};
use tokio::sync::broadcast;

// Re-export the handful of nostr-sdk types a caller touches when driving the
// transport, so downstream crates depend on `mycellium-nostr` rather than
// reaching into `nostr-sdk` directly.
pub use nostr_sdk::prelude::{Client as NostrClient, Filter as NostrFilter};
pub use nostr_sdk::{RelayPoolNotification as Notification, SubscriptionId as SubId};

/// Errors surfaced by the transport. Every variant is a genuine relay-I/O
/// failure from `nostr-sdk`; this crate adds no error semantics of its own.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the underlying `nostr-sdk` client (connect / publish /
    /// subscribe / fetch).
    #[error(transparent)]
    Client(#[from] nostr_sdk::client::Error),
}

/// Convenience result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A thin async relay client for one Mycellium participant.
///
/// Wraps a single [`nostr_sdk::Client`] bound to that participant's [`Keys`].
/// One `NostrTransport` corresponds to one identity, mirroring
/// [`mycellium_mls::MlsEngine`]: together they are everything a participant
/// needs to speak Marmot over real relays.
pub struct NostrTransport {
    client: Client,
}

impl NostrTransport {
    /// Build a transport for `keys`. The signer lets the client answer relay
    /// auth (NIP-42) if a relay demands it; published events are already signed
    /// by `mycellium-mls`, so the signer is never used to re-sign them.
    #[must_use]
    pub fn new(keys: &Keys) -> Self {
        Self {
            client: Client::new(keys.clone()),
        }
    }

    /// Escape hatch to the underlying `nostr-sdk` client for operations this
    /// wrapper does not surface. Prefer the wrapper methods.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Add every relay in `relays` and open the connections, waiting up to
    /// `timeout` for them to come up before returning.
    pub async fn connect(&self, relays: &[RelayUrl], timeout: Duration) -> Result<()> {
        for url in relays {
            self.client.add_relay(url.clone()).await?;
        }
        self.client.connect().await;
        self.client.wait_for_connection(timeout).await;
        Ok(())
    }

    /// Publish an already-signed event to the connected relays, returning its id.
    ///
    /// The event is built + signed upstream (e.g. `wire::key_package_event`,
    /// `wire::gift_wrap_welcome`, `MlsEngine::encrypt_message`); this only ships
    /// it over the socket.
    pub async fn publish(&self, event: &Event) -> Result<EventId> {
        let output = self.client.send_event(event).await?;
        Ok(output.val)
    }

    /// Fetch the latest kind:30443 KeyPackage event published by `author`.
    ///
    /// Runs a bounded (`timeout`) filter query and returns the newest matching
    /// event, or `None` if the author has no KeyPackage on the queried relays.
    pub async fn fetch_key_package(
        &self,
        author: PublicKey,
        timeout: Duration,
    ) -> Result<Option<Event>> {
        let filter = Filter::new()
            .author(author)
            .kind(Kind::Custom(mycellium_mls::KIND_KEY_PACKAGE))
            .limit(1);
        // `Events` is ordered newest-first, so `first_owned` is the latest.
        let events = self.client.fetch_events(filter, timeout).await?;
        Ok(events.first_owned())
    }

    /// Fetch the latest kind:0 profile metadata event published by `author`.
    ///
    /// Runs a bounded (`timeout`) filter query and returns the newest matching
    /// event, or `None` if the author has published no profile on the queried
    /// relays. Used to read a contact's *claimed* NIP-05 (the `nip05` field of
    /// their profile) so it can be checked against the pinned key.
    pub async fn fetch_metadata(
        &self,
        author: PublicKey,
        timeout: Duration,
    ) -> Result<Option<Event>> {
        let filter = Filter::new().author(author).kind(Kind::Metadata).limit(1);
        let events = self.client.fetch_events(filter, timeout).await?;
        Ok(events.first_owned())
    }

    /// Open a live subscription for `filter`. New matching events arrive on the
    /// [`NostrTransport::notifications`] stream. Returns the subscription id so
    /// the caller can later [`NostrTransport::unsubscribe`].
    pub async fn subscribe(&self, filter: Filter) -> Result<SubscriptionId> {
        let output = self.client.subscribe(filter, None).await?;
        Ok(output.val)
    }

    /// Open (or **replace**) a live subscription under a caller-chosen, stable
    /// [`SubscriptionId`]. Re-issuing the same `id` with a new `filter` edits the
    /// existing subscription in place rather than opening a second one — used to
    /// keep a single, merged subscription whose filter widens as it is refreshed
    /// (e.g. the pinned-contact trust set growing as contacts are added).
    pub async fn subscribe_with_id(&self, id: SubscriptionId, filter: Filter) -> Result<()> {
        self.client.subscribe_with_id(id, filter, None).await?;
        Ok(())
    }

    /// Close a subscription previously opened with [`NostrTransport::subscribe`].
    pub async fn unsubscribe(&self, id: &SubscriptionId) {
        self.client.unsubscribe(id).await;
    }

    /// A receiver for the incoming-event stream.
    ///
    /// Each subscribed event surfaces once as [`RelayPoolNotification::Event`]
    /// (events this client itself sent are excluded). Grab this receiver
    /// **before** the events you care about are published so none are missed,
    /// then await them with [`NostrTransport::next_event`]. Route the resulting
    /// [`Event`]s into `mycellium-mls` (`unwrap_welcome` / `process_incoming`).
    #[must_use]
    pub fn notifications(&self) -> broadcast::Receiver<RelayPoolNotification> {
        self.client.notifications()
    }

    /// Await the next incoming event that satisfies `matches`, up to `timeout`.
    ///
    /// A bounded wait over a `notifications` receiver: it drains non-event
    /// notifications and non-matching events, returning the first [`Event`] for
    /// which `matches` is true, or `None` if `timeout` elapses (or the stream
    /// closes) first. `Lagged` is tolerated — a slow consumer keeps waiting
    /// rather than erroring.
    pub async fn next_event<F>(
        notifications: &mut broadcast::Receiver<RelayPoolNotification>,
        timeout: Duration,
        mut matches: F,
    ) -> Option<Event>
    where
        F: FnMut(&Event) -> bool,
    {
        let wait = async {
            loop {
                match notifications.recv().await {
                    Ok(RelayPoolNotification::Event { event, .. }) if matches(&event) => {
                        return Some(*event);
                    }
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        };
        tokio::time::timeout(timeout, wait).await.ok().flatten()
    }

    /// Disconnect from all relays and shut the client down.
    pub async fn shutdown(&self) {
        self.client.shutdown().await;
    }
}
