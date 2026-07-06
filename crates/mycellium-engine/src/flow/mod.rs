//! `engine::flow` — the shared, platform-generic messaging orchestration.
//!
//! The three clients (native CLI/engine, the UniFFI SDK, and the browser wasm
//! build) used to each carry their own copy of this logic, which drifted and
//! grew latent security gaps. `flow` owns the orchestration **once**, generic
//! over the [`Storage`] and [`Platform`] ports plus an injected [`FlowNet`] seam
//! (each client binds its own `HttpTransport` — `ureq` / `xhr` / the native
//! blocking clients), and a per-device `deliver` closure that performs the
//! client-specific delivery. It never names a concrete `FileStore`,
//! `OsPlatform`, `DirectoryClient`, `QueueClient`, or transport, so it compiles
//! to wasm32 alongside the browser build.

use mycellium_core::group::{Group, GroupMessage, SenderKeyDistribution};
use mycellium_core::identity::{Handle, Identity};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::offline::Envelope;
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, SignedRecord};
use mycellium_core::storage::Storage;

use crate::blocklist;
use crate::groups::{
    self, GroupInvitePayload, GroupLeavePayload, GroupSyncPayload, MailItem, StoredGroup,
};
use crate::history::{self, GroupStoredMessage, StoredMessage};
use crate::names;
use crate::reachability::DeliveryPath;
use crate::verified;
use crate::wireops;
use crate::{antirollback, verified::TrustLevel};

/// The directory lookup seam. Each client wraps its own `DirectoryClient`
/// (bound to `ureq` / `xhr` / the native blocking transport); `flow` only needs
/// to resolve a handle to its signed directory record.
pub trait FlowNet {
    /// Look up a peer's signed directory record.
    fn lookup(&self, handle: &Handle) -> anyhow::Result<SignedRecord>;
}

/// Why the shared trust chokepoint ([`lookup_verified`]) refused a record.
///
/// The three clients each render this differently (the CLI prints a rich
/// out-of-band-verification hint, the SDK maps to `SdkError` + fires
/// `on_key_change`, wasm returns a `JsValue` string), so `flow` returns the
/// *reason* and leaves presentation to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustError {
    /// The wallet the directory served no longer matches the pinned/verified one
    /// — a possible impersonation, or the peer re-registered with a new key.
    IdentityChanged,
    /// The directory served a record older than one we've already pinned (a
    /// rollback that could re-introduce a removed device or redirect mail).
    StaleRecord,
    /// The record's self-signature did not verify.
    Unverified,
    /// The handle was malformed, or no record could be resolved for it.
    BadHandle,
}

/// The disposition of one inbound [`MailItem`] after [`process_item`]: whether it
/// was consumed, or must stay in the caller's inbound retry store for another
/// attempt. This unifies the three clients' old retry contracts (the engine's
/// `Result<()>.is_ok()`, the SDK's `Processed`, and wasm's `bool`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemOutcome {
    /// Fully handled (applied, dropped, or permanently rejected) — remove it.
    Handled,
    /// Not handled yet (undecryptable, or for a group whose invite/sync hasn't
    /// arrived) — keep it in the inbound store and re-try on the next drain.
    Retry,
}

/// One observable outcome of processing an inbound item, emitted through a
/// [`FlowSink`]. The receive orchestration ([`process_item`]) has already applied
/// every state change (history, groups, key material) to the store; a sink only
/// *renders* — the CLI prints each event with its terminal wording, the SDK turns
/// the message-bearing ones into `Message` DTOs, and wasm persists attachment
/// bytes it couldn't store generically. This is the single seam that replaces the
/// ~30 `println!`s the three receive paths used to each carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowEvent {
    /// A decrypted 1:1 message from `from` (never our own — see [`FlowEvent::SelfMirror`]).
    DirectMessage {
        /// The authenticated sender's handle.
        from: String,
        /// The message id (empty only for a legacy/undecodable raw payload).
        id: String,
        /// The display text ([`AppMessage::summary`]).
        text: String,
        /// Always `false` on the receive path; present for symmetry with DTOs.
        from_me: bool,
    },
    /// A mirror of a message *this account* sent from another device (Layer 11
    /// self-sync). Already recorded in `peer`'s transcript as our own outgoing.
    SelfMirror {
        /// The peer the mirrored message was addressed to.
        peer: String,
        /// The mirrored message id.
        id: String,
        /// The mirrored message's display text.
        text: String,
    },
    /// A decrypted group message (already appended to the group transcript).
    GroupMessage {
        /// The group's id.
        group_id: String,
        /// The group's display name.
        name: String,
        /// The resolved sender handle (or a raw device id if unmapped).
        sender: String,
        /// The message id (empty only for an undecodable raw payload).
        id: String,
        /// The display text.
        text: String,
    },
    /// An earlier message was edited (already applied to the transcript).
    Edited {
        /// The conversation the edit landed in: the peer handle (1:1) or the
        /// group's display name (group).
        thread: String,
        /// The edited message's id.
        id: String,
        /// The new text.
        text: String,
        /// Whether this is a group edit.
        group: bool,
    },
    /// An earlier message was deleted (already tombstoned in the transcript).
    Deleted {
        /// The conversation: the peer handle (1:1) or group display name (group).
        thread: String,
        /// The deleted message's id.
        id: String,
        /// Whether this is a group delete.
        group: bool,
    },
    /// An incoming delivery/read receipt for a message we sent.
    Receipt {
        /// Who acknowledged it.
        from: String,
        /// The id of the message they acknowledged.
        message_id: String,
        /// `true` = read, `false` = merely delivered.
        read: bool,
    },
    /// We joined a group from an invite (state already saved; our key distributed).
    GroupJoined {
        /// The group's id.
        group_id: String,
        /// The group's display name.
        name: String,
        /// The member who invited us.
        inviter: String,
    },
    /// A member's authenticated departure was processed: they were dropped and the
    /// group re-keyed (our fresh key already redistributed).
    GroupLeft {
        /// The group's id.
        group_id: String,
        /// The group's display name.
        name: String,
        /// The member who left.
        member: String,
    },
    /// This device was bootstrapped into a group from a sibling's group-sync
    /// (state saved; our own key distributed so we can also send).
    GroupBootstrapped {
        /// The group's id.
        group_id: String,
        /// The group's display name.
        name: String,
    },
    /// An inbound attachment the host must persist however it renders: the CLI
    /// writes it to the downloads dir, wasm keeps it as a `data:` URL, the SDK
    /// ignores it (the "📎 name" summary is already in history).
    Attachment {
        /// The bearing message's id (the key hosts store it under).
        id: String,
        /// The file name.
        name: String,
        /// The MIME type.
        mime: String,
        /// The raw bytes.
        data: Vec<u8>,
    },
    /// A non-fatal warning worth surfacing (reserved for hosts that log).
    Warn(String),
}

/// The render seam for [`process_item`]: every visible outcome is emitted here so
/// the host decides how to present it (print / DTO / persist). Kept deliberately
/// tiny — one method — because `flow` owns all the *logic*; a sink owns only
/// presentation and so never needs the store, network, or identity.
pub trait FlowSink {
    /// Render one [`FlowEvent`]. Called while `process_item` holds the store, so a
    /// sink must not need store access during the call (it buffers instead — see
    /// the wasm attachment sink).
    fn emit(&mut self, event: FlowEvent);
}

/// The **shared trust chokepoint** for every outbound path (1:1 send, forward,
/// broadcast, chat, and the group paths): resolve `handle`, look it up through
/// the injected [`FlowNet`], check the record's self-signature, fail closed on a
/// changed pinned wallet ([`verified::level`]), and refuse a rolled-back record
/// ([`antirollback::check_and_pin`], which also pins the seq on success).
///
/// Contacts-nickname resolution is host-specific (the native CLI resolves a
/// saved nickname to a handle first), so this takes an already-resolved handle
/// string. Owns no presentation: it returns a bare [`TrustError`] the host maps
/// to its own error surface.
pub fn lookup_verified<S, N>(
    store: &mut S,
    net: &N,
    handle: &str,
) -> Result<(Handle, SignedRecord), TrustError>
where
    S: Storage,
    N: FlowNet,
{
    let handle = Handle::new(handle.to_string()).map_err(|_| TrustError::BadHandle)?;
    let record = net.lookup(&handle).map_err(|_| TrustError::BadHandle)?;
    // The directory does not verify records; check the self-signature before we
    // trust the record's device keys / queue (core review).
    record.verify().map_err(|_| TrustError::Unverified)?;
    // Fail closed if the current wallet doesn't match a pinned/verified one: the
    // peer re-registered, or someone is impersonating them (core review).
    if verified::level(store, handle.as_str(), &record.record.wallet) == TrustLevel::Changed {
        return Err(TrustError::IdentityChanged);
    }
    // Anti-rollback: refuse (and never pin) a record older than one we've already
    // seen for this handle — a downgrade the wallet-change guard cannot see (HIGH).
    if !antirollback::check_and_pin(store, handle.as_str(), record.record.seq)
        .map_err(|_| TrustError::StaleRecord)?
    {
        return Err(TrustError::StaleRecord);
    }
    Ok((handle, record))
}

/// The per-path tally of one 1:1 send (Layer 11 device fan-out), returned by
/// [`send_app`]. `delivered` counts devices handed off live or into the queue;
/// `outboxed` counts devices parked for retry (or that couldn't be sealed).
/// `direct`/`relay`/`queued` break the live/queue delivery down for reporting.
#[derive(Debug, Clone, Default)]
pub struct SendOutcome {
    /// The sent message's id (`AppMessage::id`).
    pub id: String,
    /// Devices the copy reached (direct + relay + queued).
    pub delivered: u32,
    /// Devices reached by a live direct push.
    pub direct: u32,
    /// Devices reached live through a Circuit Relay v2 node.
    pub relay: u32,
    /// Devices reached by a queue deposit.
    pub queued: u32,
    /// Devices we couldn't reach (parked in the outbox for retry).
    pub outboxed: u32,
}

/// The **shared 1:1 send fan-out**, generic over the [`Storage`]/[`Platform`]
/// ports and the injected [`FlowNet`]. For each of the peer's devices (Layer 11)
/// it X3DH-seals one copy ([`wireops::seal_to`]) into a [`MailItem::Direct`] and
/// hands it to `deliver`, tallying by the returned [`DeliveryPath`]; then it
/// records our own transcript copy; then it self-syncs the send to our *own*
/// other devices via `self_deliver`.
///
/// The two closures own the client-specific transport + retry policy: the engine
/// binds its live delivery ladder (direct TCP/libp2p + relay + reachability
/// scoring) with an outbox fallback, while the SDK/wasm deposit into the
/// recipient's queue. The store is threaded *through* the closures (rather than
/// captured) so the seal loop and the closures' own writes share one handle.
///
/// The caller resolves and trust-checks the peer via [`lookup_verified`] first
/// and passes the already-verified `peer_record` in, so this never re-fetches or
/// re-checks it — the trust decision stays at the one chokepoint.
#[allow(clippy::too_many_arguments)]
pub fn send_app<S, P, N>(
    identity: &Identity,
    store: &mut S,
    platform: &mut P,
    net: &N,
    me: &Handle,
    my_name: &str,
    my_queue: &str,
    peer: &Handle,
    peer_record: &SignedRecord,
    app: &AppMessage,
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem) -> DeliveryPath,
    self_deliver: &mut dyn FnMut(&mut S, &Handle, &Device, MailItem),
) -> SendOutcome
where
    S: Storage,
    P: Platform,
    N: FlowNet,
{
    let encoded = app.encode();
    let mut out = SendOutcome {
        id: app.id.clone(),
        ..Default::default()
    };

    // Fan out one sealed copy per recipient device (Layer 11) — each device has
    // its own keys. A device we can't reach is parked by the `deliver` closure.
    for device in &peer_record.record.devices {
        let Ok(env) = wireops::seal_to(platform, identity, me, my_name, my_queue, device, &encoded)
        else {
            continue;
        };
        match deliver(store, peer, peer_record, device, MailItem::Direct(env)) {
            DeliveryPath::Direct => {
                out.direct += 1;
                out.delivered += 1;
            }
            DeliveryPath::Relay => {
                out.relay += 1;
                out.delivered += 1;
            }
            DeliveryPath::Queue => {
                out.queued += 1;
                out.delivered += 1;
            }
            DeliveryPath::Outbox | DeliveryPath::Failed => {}
        }
    }
    let total = peer_record.record.devices.len() as u32;
    out.outboxed = total - out.delivered;

    // Record our own copy in this device's transcript, so the conversation shows
    // what we sent (edits/deletes apply to it; other kinds append).
    match &app.body {
        Body::Edit { to, text } => {
            let _ = history::edit(store, peer.as_str(), to, text, true);
        }
        Body::Delete { to } => {
            let _ = history::delete(store, peer.as_str(), to, true);
        }
        Body::Receipt { .. } => {}
        _ => {
            let _ = history::append(
                store,
                peer.as_str(),
                StoredMessage {
                    id: app.id.clone(),
                    from_me: true,
                    text: app.summary(),
                    timestamp: app.timestamp,
                    expires_at: app.expires_at,
                },
            );
        }
    }

    // Self-sync: mirror this message to our own other devices (Layer 11), so a
    // sibling device shows what we sent from here. Never to this device itself.
    if let Ok(my_record) = net.lookup(me) {
        let my_key = identity.device_public();
        for device in &my_record.record.devices {
            if device.device_key == my_key {
                continue;
            }
            let Ok(env) =
                wireops::seal_to(platform, identity, me, my_name, my_queue, device, &encoded)
            else {
                continue;
            };
            let sync = MailItem::SelfSync {
                peer: peer.as_str().to_string(),
                envelope: env,
            };
            self_deliver(store, me, device, sync);
        }
    }

    out
}

/// Seal our current group sender key to every device of each `targets` handle,
/// **failing closed** on a member whose record is unverifiable or whose pinned
/// wallet has changed. This is the one shared copy of what used to be the
/// engine's `distribute_key_to`, the SDK's `distribute_key`, and the wasm
/// `distribute_key`.
///
/// The flow owns the shared logic — lookup, `verify()`, the TOFU pin check
/// ([`verified::level`] against `store`), and per-device sealing ([`wireops::seal_to`]).
/// `deliver` performs the client-specific per-device delivery: the engine runs
/// its live ladder + outbox fallback (which is why it is handed the store back
/// mutably), while the SDK/wasm deposit into the recipient's queue. The store is
/// threaded through `deliver` rather than captured by it so the pin check (which
/// only reads) and the engine's reachability/outbox writes share the one handle.
///
/// The pin check is the security fix this unification carries: previously only
/// the engine held a store, so a compelled directory that swapped a member's
/// *pinned* wallet could still harvest the group key from the SDK/wasm. Now all
/// three refuse it.
#[allow(clippy::too_many_arguments)]
pub fn distribute_key<S, P, N>(
    identity: &Identity,
    store: &mut S,
    platform: &mut P,
    net: &N,
    me: &Handle,
    my_name: &str,
    my_queue: &str,
    group_id: &str,
    name: &str,
    distribution: &SenderKeyDistribution,
    members: &[String],
    targets: &[String],
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem),
) where
    S: Storage,
    P: Platform,
    N: FlowNet,
{
    let payload = GroupInvitePayload {
        group_id: group_id.to_string(),
        name: name.to_string(),
        members: members.to_vec(),
        sender_id: wireops::my_group_id(identity),
        distribution: distribution.clone(),
    };
    let Ok(plaintext) = serde_json::to_vec(&payload) else {
        return;
    };

    for target in targets {
        let Ok(handle) = Handle::new(target.clone()) else {
            continue;
        };
        let Ok(record) = net.lookup(&handle) else {
            continue;
        };
        // Never seal our group sender key to an unverifiable record.
        if record.verify().is_err() {
            continue;
        }
        // Fail closed if the member's wallet no longer matches the pinned or
        // verified one — a compelled directory that swaps a member's wallet must
        // not trick us into sealing our group sender key to the impostor (the
        // same fail-closed check 1:1 sends make; core review).
        if verified::level(store, handle.as_str(), &record.record.wallet)
            == verified::TrustLevel::Changed
        {
            continue;
        }
        // Seal the sender key to every device in the member's cluster (Layer 11) —
        // including our *own* siblings, but never this device itself.
        for device in &record.record.devices {
            if device.device_key == identity.device_public() {
                continue;
            }
            let Ok(env) = wireops::seal_to(
                platform, identity, me, my_name, my_queue, device, &plaintext,
            ) else {
                continue;
            };
            deliver(store, &handle, &record, device, MailItem::GroupInvite(env));
        }
    }
}

/// The immutable per-item receive context, bundled so the six inbound handlers
/// don't each thread five shared references. All fields are `Copy` shared refs, so
/// this is `Copy` and free to pass by value.
#[derive(Clone, Copy)]
struct Recv<'a> {
    identity: &'a Identity,
    me: &'a Handle,
    my_name: &'a str,
    my_queue: &'a str,
    blocked: &'a [String],
}

/// The **shared inbound dispatch**: decrypt/authenticate one [`MailItem`], apply
/// its effect to the store (history, groups, key material), emit what the host
/// should render through `sink`, and run any follow-up send it triggers (a read
/// receipt, a group key (re)distribution) *inside* the flow. Returns whether the
/// item was [`ItemOutcome::Handled`] or must be kept for [`ItemOutcome::Retry`].
///
/// This is the single copy of what used to be triplicated across the engine's
/// `process_item` + six `handle_*`, the SDK's `process_blob` + `process_*`, and
/// wasm's `process_blob` (whose `_ => true` catch-all silently dropped `SelfSync`,
/// `GroupSync`, and `GroupLeave` — all now handled here). `deliver`/`self_deliver`
/// are the same client-specific per-device delivery closures [`send_app`] and
/// [`distribute_key`] take, threaded so the follow-up sends reuse the host's
/// transport + retry policy; the store is passed *through* them, never captured.
#[allow(clippy::too_many_arguments)]
pub fn process_item<S, P, N>(
    identity: &Identity,
    store: &mut S,
    platform: &mut P,
    net: &N,
    me: &Handle,
    my_name: &str,
    my_queue: &str,
    blocked: &[String],
    item: MailItem,
    sink: &mut dyn FlowSink,
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem) -> DeliveryPath,
    self_deliver: &mut dyn FnMut(&mut S, &Handle, &Device, MailItem),
) -> ItemOutcome
where
    S: Storage,
    P: Platform,
    N: FlowNet,
{
    let r = Recv {
        identity,
        me,
        my_name,
        my_queue,
        blocked,
    };
    match item {
        MailItem::Direct(env) => {
            recv_direct(r, store, platform, net, sink, &env, deliver, self_deliver)
        }
        MailItem::SelfSync { peer, envelope } => {
            recv_self_sync(r, store, platform, sink, &peer, &envelope)
        }
        MailItem::GroupInvite(env) => {
            recv_group_invite(r, store, platform, net, sink, &env, deliver)
        }
        MailItem::GroupText { group_id, message } => {
            recv_group_text(r, store, platform, sink, &group_id, &message)
        }
        MailItem::GroupSync(env) => recv_group_sync(r, store, platform, net, sink, &env, deliver),
        MailItem::GroupLeave(env) => recv_group_leave(r, store, platform, net, sink, &env, deliver),
    }
}

/// Decrypt and act on a one-to-one offline message: surface + persist real
/// messages (and reply with a read receipt), apply edits/deletes, or show an
/// incoming receipt.
#[allow(clippy::too_many_arguments)]
fn recv_direct<S, P, N>(
    r: Recv,
    store: &mut S,
    platform: &mut P,
    net: &N,
    sink: &mut dyn FlowSink,
    env: &Envelope,
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem) -> DeliveryPath,
    self_deliver: &mut dyn FnMut(&mut S, &Handle, &Device, MailItem),
) -> ItemOutcome
where
    S: Storage,
    P: Platform,
    N: FlowNet,
{
    let Ok((from, bytes)) = wireops::open_envelope(platform, r.identity, env) else {
        return ItemOutcome::Retry; // not for us / can't decrypt yet
    };
    if blocklist::is_blocked(r.blocked, from.as_str()) {
        return ItemOutcome::Handled; // silently drop — no surface, storage, or receipt
    }
    // Learn the sender's self-set name (from their signed record); a saved contact
    // still wins downstream.
    let _ = names::note(store, from.as_str(), &env.sender_record.record.name);

    match AppMessage::decode(&bytes) {
        Ok(app) => match &app.body {
            // A receipt: surface the status; never receipt a receipt (no loops).
            Body::Receipt { message_id, read } => sink.emit(FlowEvent::Receipt {
                from: from.as_str().to_string(),
                message_id: message_id.clone(),
                read: *read,
            }),
            // An edit or deletion of an earlier message: apply to the transcript.
            Body::Edit { to, text } => {
                let _ = history::edit(store, from.as_str(), to, text, false);
                sink.emit(FlowEvent::Edited {
                    thread: from.as_str().to_string(),
                    id: to.clone(),
                    text: text.clone(),
                    group: false,
                });
            }
            Body::Delete { to } => {
                let _ = history::delete(store, from.as_str(), to, false);
                sink.emit(FlowEvent::Deleted {
                    thread: from.as_str().to_string(),
                    id: to.clone(),
                    group: false,
                });
            }
            // Already expired in transit? drop it entirely.
            _ if app.is_expired(platform.now_unix_secs()) => {}
            // A real message: surface, persist, and send a read receipt back.
            _ => {
                if let Body::File { name, mime, data } = &app.body {
                    sink.emit(FlowEvent::Attachment {
                        id: app.id.clone(),
                        name: name.clone(),
                        mime: mime.clone(),
                        data: data.clone(),
                    });
                }
                sink.emit(FlowEvent::DirectMessage {
                    from: from.as_str().to_string(),
                    id: app.id.clone(),
                    text: app.summary(),
                    from_me: false,
                });
                let entry = StoredMessage {
                    id: app.id.clone(),
                    from_me: false,
                    text: app.summary(),
                    timestamp: platform.now_unix_secs(),
                    expires_at: app.expires_at,
                };
                let _ = history::append(store, from.as_str(), entry);
                send_read_receipt(
                    r,
                    store,
                    platform,
                    net,
                    &from,
                    &app.id,
                    deliver,
                    self_deliver,
                );
            }
        },
        Err(_) => {
            // Older/raw payloads: best-effort surface + record (no id, no receipt).
            let text = String::from_utf8_lossy(&bytes).into_owned();
            sink.emit(FlowEvent::DirectMessage {
                from: from.as_str().to_string(),
                id: String::new(),
                text: text.clone(),
                from_me: false,
            });
            let entry = StoredMessage {
                id: String::new(),
                from_me: false,
                text,
                timestamp: platform.now_unix_secs(),
                expires_at: None,
            };
            let _ = history::append(store, from.as_str(), entry);
        }
    }
    ItemOutcome::Handled
}

/// Send a read receipt for `message_id` back to `to` (best-effort), fanned across
/// the sender's whole device cluster via the shared 1:1 send.
#[allow(clippy::too_many_arguments)]
fn send_read_receipt<S, P, N>(
    r: Recv,
    store: &mut S,
    platform: &mut P,
    net: &N,
    to: &Handle,
    message_id: &str,
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem) -> DeliveryPath,
    self_deliver: &mut dyn FnMut(&mut S, &Handle, &Device, MailItem),
) where
    S: Storage,
    P: Platform,
    N: FlowNet,
{
    let Ok(record) = net.lookup(to) else { return };
    if record.verify().is_err() {
        return;
    }
    let receipt = wireops::app_message(
        platform,
        Body::Receipt {
            message_id: message_id.to_string(),
            read: true,
        },
    );
    // [`send_app`] fans the receipt to every device of the sender (Layer 11); a
    // `Receipt` body records no transcript line (it is not a visible message).
    let _ = send_app(
        r.identity,
        store,
        platform,
        net,
        r.me,
        r.my_name,
        r.my_queue,
        to,
        &record,
        &receipt,
        deliver,
        self_deliver,
    );
}

/// Process a mirror of a message *this account* sent from another device: record
/// it in the peer's transcript as our own outgoing message (Layer 11 self-sync).
fn recv_self_sync<S, P>(
    r: Recv,
    store: &mut S,
    platform: &mut P,
    sink: &mut dyn FlowSink,
    peer: &str,
    env: &Envelope,
) -> ItemOutcome
where
    S: Storage,
    P: Platform,
{
    let Ok((_from, bytes)) = wireops::open_envelope(platform, r.identity, env) else {
        return ItemOutcome::Retry;
    };
    // A self-sync mirror must come from our OWN cluster: the envelope's sender
    // record has to be signed by our own wallet. Otherwise any peer who can seal a
    // valid envelope to us could forge a `SelfSync` and inject (`from_me:true`) or
    // edit/delete (`by_me:true`) our real outgoing transcript. Fail closed.
    if env.sender_record.record.wallet != r.identity.wallet_public() {
        return ItemOutcome::Handled;
    }
    let Ok(app) = AppMessage::decode(&bytes) else {
        return ItemOutcome::Handled;
    };
    match &app.body {
        Body::Edit { to, text } => {
            let _ = history::edit(store, peer, to, text, true);
        }
        Body::Delete { to } => {
            let _ = history::delete(store, peer, to, true);
        }
        Body::Receipt { .. } => {} // receipts aren't mirrored
        _ => {
            sink.emit(FlowEvent::SelfMirror {
                peer: peer.to_string(),
                id: app.id.clone(),
                text: app.summary(),
            });
            let entry = StoredMessage {
                id: app.id.clone(),
                from_me: true,
                text: app.summary(),
                timestamp: platform.now_unix_secs(),
                expires_at: app.expires_at,
            };
            let _ = history::append(store, peer, entry);
        }
    }
    ItemOutcome::Handled
}

/// Join a group from an invite (or learn an existing member's sender key), then
/// distribute our own key to the members who need it.
#[allow(clippy::too_many_arguments)]
fn recv_group_invite<S, P, N>(
    r: Recv,
    store: &mut S,
    platform: &mut P,
    net: &N,
    sink: &mut dyn FlowSink,
    env: &Envelope,
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem) -> DeliveryPath,
) -> ItemOutcome
where
    S: Storage,
    P: Platform,
    N: FlowNet,
{
    let Ok((from, bytes)) = wireops::open_envelope(platform, r.identity, env) else {
        return ItemOutcome::Retry;
    };
    let Ok(payload) = serde_json::from_slice::<GroupInvitePayload>(&bytes) else {
        return ItemOutcome::Retry;
    };
    // Senders are keyed by their device id (Layer 11), carried in the payload; we
    // remember which handle is behind it for display and block checks.
    let sender_id = payload.sender_id.clone();

    match groups::load(store, &payload.group_id) {
        Ok(Some(mut stored)) => {
            // An invite for a group we're already in is only trustworthy from an
            // existing member — the group id travels in cleartext inside every
            // group MailItem, so anyone who learns it could otherwise inject their
            // sender key or add members we then leak our key to. Ignore non-members.
            if !stored.members.iter().any(|m| m == from.as_str()) {
                return ItemOutcome::Handled;
            }
            let Ok(mut group) = Group::import(stored.state.clone()) else {
                return ItemOutcome::Retry;
            };
            if group
                .add_member(sender_id.clone(), &payload.distribution)
                .is_err()
            {
                return ItemOutcome::Retry;
            }
            stored.note_sender(sender_id, from.as_str());
            // Learn any members we didn't know about, and send them our key.
            let newcomers: Vec<String> = payload
                .members
                .iter()
                .filter(|m| !stored.members.iter().any(|x| x == *m))
                .cloned()
                .collect();
            for m in &newcomers {
                stored.members.push(m.clone());
            }
            stored.state = group.export();
            let _ = groups::save(store, &stored);
            if !newcomers.is_empty() {
                distribute_group_key(
                    r, store, platform, net, &stored, &group, &newcomers, deliver,
                );
            }
            ItemOutcome::Handled
        }
        Ok(None) => {
            // First time we hear of this group: join, and reply with our key.
            let mut group = Group::new(platform, wireops::my_group_id(r.identity));
            if group
                .add_member(sender_id.clone(), &payload.distribution)
                .is_err()
            {
                return ItemOutcome::Retry;
            }
            let mut stored = StoredGroup {
                id: payload.group_id.clone(),
                name: payload.name.clone(),
                members: payload.members.clone(),
                me: r.me.as_str().to_string(),
                sender_handles: Vec::new(),
                state: group.export(),
            };
            stored.note_sender(sender_id, from.as_str());
            stored.note_sender(wireops::my_group_id(r.identity), r.me.as_str());
            let _ = groups::save(store, &stored);
            sink.emit(FlowEvent::GroupJoined {
                group_id: stored.id.clone(),
                name: stored.name.clone(),
                inviter: from.as_str().to_string(),
            });
            let targets = stored.members.clone();
            distribute_group_key(r, store, platform, net, &stored, &group, &targets, deliver);
            ItemOutcome::Handled
        }
        Err(_) => ItemOutcome::Retry,
    }
}

/// Decrypt a received group message and store it. Returns [`ItemOutcome::Retry`]
/// when we don't have the group / sender key yet (its invite/sync hasn't arrived).
fn recv_group_text<S, P>(
    r: Recv,
    store: &mut S,
    platform: &mut P,
    sink: &mut dyn FlowSink,
    group_id: &str,
    message: &GroupMessage,
) -> ItemOutcome
where
    S: Storage,
    P: Platform,
{
    let mut stored = match groups::load(store, group_id) {
        Ok(Some(s)) => s,
        // Unknown group (its invite/sync hasn't been processed) or a store error:
        // keep the item so it retries once we know the group.
        _ => return ItemOutcome::Retry,
    };
    // Map the device-keyed sender id back to a handle for display/block checks.
    let sender = stored
        .handle_of(&message.sender)
        .map(str::to_string)
        .unwrap_or_else(|| String::from_utf8_lossy(&message.sender).into_owned());
    if blocklist::is_blocked(r.blocked, &sender) {
        return ItemOutcome::Handled; // drop group messages from blocked members
    }
    let Ok(mut group) = Group::import(stored.state.clone()) else {
        return ItemOutcome::Retry;
    };
    let Ok(plaintext) = group.decrypt(message, &wireops::group_ad(group_id)) else {
        // Missing this sender's key yet — keep the item for retry.
        return ItemOutcome::Retry;
    };
    // Advance/persist the ratchet state regardless of the payload.
    stored.state = group.export();
    let _ = groups::save(store, &stored);

    let (id, display, expires_at) = match AppMessage::decode(&plaintext) {
        Ok(app) => match &app.body {
            Body::Edit { to, text } => {
                let _ = history::group_edit(store, group_id, to, text, &sender);
                sink.emit(FlowEvent::Edited {
                    thread: stored.name.clone(),
                    id: to.clone(),
                    text: text.clone(),
                    group: true,
                });
                return ItemOutcome::Handled;
            }
            Body::Delete { to } => {
                let _ = history::group_delete(store, group_id, to, &sender);
                sink.emit(FlowEvent::Deleted {
                    thread: stored.name.clone(),
                    id: to.clone(),
                    group: true,
                });
                return ItemOutcome::Handled;
            }
            _ => {
                if app.is_expired(platform.now_unix_secs()) {
                    return ItemOutcome::Handled; // already expired — drop
                }
                if let Body::File { name, mime, data } = &app.body {
                    sink.emit(FlowEvent::Attachment {
                        id: app.id.clone(),
                        name: name.clone(),
                        mime: mime.clone(),
                        data: data.clone(),
                    });
                }
                (app.id.clone(), app.summary(), app.expires_at)
            }
        },
        Err(_) => (
            String::new(),
            String::from_utf8_lossy(&plaintext).into_owned(),
            None,
        ),
    };
    sink.emit(FlowEvent::GroupMessage {
        group_id: group_id.to_string(),
        name: stored.name.clone(),
        sender: sender.clone(),
        id: id.clone(),
        text: display.clone(),
    });
    let entry = GroupStoredMessage {
        id,
        sender,
        text: display,
        timestamp: platform.now_unix_secs(),
        expires_at,
    };
    let _ = history::group_append(store, group_id, entry);
    ItemOutcome::Handled
}

/// Bootstrap this device into a group from a sibling's [`GroupSyncPayload`], then
/// announce our own key to the members so this device can also *send*.
#[allow(clippy::too_many_arguments)]
fn recv_group_sync<S, P, N>(
    r: Recv,
    store: &mut S,
    platform: &mut P,
    net: &N,
    sink: &mut dyn FlowSink,
    env: &Envelope,
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem) -> DeliveryPath,
) -> ItemOutcome
where
    S: Storage,
    P: Platform,
    N: FlowNet,
{
    let Ok((_from, bytes)) = wireops::open_envelope(platform, r.identity, env) else {
        return ItemOutcome::Retry;
    };
    // A group-sync bootstrap must come from our OWN cluster — otherwise any peer
    // who can seal an envelope to us could hand us an attacker-chosen group
    // (roster, keys, sender→handle map) and make us distribute our sender key to
    // members of their choosing. Fail closed on a foreign sender.
    if env.sender_record.record.wallet != r.identity.wallet_public() {
        return ItemOutcome::Handled;
    }
    let Ok(payload) = serde_json::from_slice::<GroupSyncPayload>(&bytes) else {
        return ItemOutcome::Retry;
    };
    match groups::load(store, &payload.group_id) {
        Ok(Some(_)) => return ItemOutcome::Handled, // already have this group
        Ok(None) => {}
        Err(_) => return ItemOutcome::Retry,
    }
    // A fresh own sender key (this device signs under its device id); import every
    // sender key the cluster shared so we can decrypt current members.
    let mut group = Group::new(platform, wireops::my_group_id(r.identity));
    for (id, dist) in &payload.keys {
        let _ = group.add_member(id.clone(), dist);
    }
    let mut stored = StoredGroup {
        id: payload.group_id.clone(),
        name: payload.name.clone(),
        members: payload.members.clone(),
        me: r.me.as_str().to_string(),
        sender_handles: payload.sender_handles.clone(),
        state: group.export(),
    };
    stored.note_sender(wireops::my_group_id(r.identity), r.me.as_str());
    let _ = groups::save(store, &stored);
    let targets = stored.members.clone();
    distribute_group_key(r, store, platform, net, &stored, &group, &targets, deliver);
    sink.emit(FlowEvent::GroupBootstrapped {
        group_id: stored.id.clone(),
        name: stored.name.clone(),
    });
    ItemOutcome::Handled
}

/// React to a member's **authenticated** departure: drop their sender key, re-key
/// so they can't read future messages, and redistribute our fresh key.
///
/// The leaver is the envelope's authenticated sender — not a field an attacker
/// could set — so this can only ever remove the person who actually left.
#[allow(clippy::too_many_arguments)]
fn recv_group_leave<S, P, N>(
    r: Recv,
    store: &mut S,
    platform: &mut P,
    net: &N,
    sink: &mut dyn FlowSink,
    env: &Envelope,
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem) -> DeliveryPath,
) -> ItemOutcome
where
    S: Storage,
    P: Platform,
    N: FlowNet,
{
    let Ok((from, bytes)) = wireops::open_envelope(platform, r.identity, env) else {
        return ItemOutcome::Handled; // not for us / can't authenticate — ignore
    };
    let Ok(payload) = serde_json::from_slice::<GroupLeavePayload>(&bytes) else {
        return ItemOutcome::Handled;
    };
    let member = from.as_str().to_string(); // the authenticated leaver
    if member == r.me.as_str() {
        return ItemOutcome::Handled;
    }
    let mut stored = match groups::load(store, &payload.group_id) {
        Ok(Some(s)) => s,
        Ok(None) => return ItemOutcome::Handled,
        Err(_) => return ItemOutcome::Retry,
    };
    if !stored.members.iter().any(|m| m == &member) {
        return ItemOutcome::Handled; // not a member of this group — nothing to do
    }
    stored.members.retain(|m| m != &member);
    let Ok(mut session) = Group::import(stored.state.clone()) else {
        return ItemOutcome::Retry;
    };
    for (id, handle) in &stored.sender_handles {
        if handle == &member {
            session.remove_member(id);
        }
    }
    stored.sender_handles.retain(|(_, h)| h != &member);
    session.rotate(platform);
    stored.state = session.export();
    let _ = groups::save(store, &stored);
    let targets = stored.members.clone();
    distribute_group_key(
        r, store, platform, net, &stored, &session, &targets, deliver,
    );
    sink.emit(FlowEvent::GroupLeft {
        group_id: stored.id.clone(),
        name: stored.name.clone(),
        member,
    });
    ItemOutcome::Handled
}

/// Adapt the receive path's `deliver` closure (which reports a [`DeliveryPath`])
/// to [`distribute_key`]'s delivery closure (which doesn't), and run the shared
/// lookup/verify/pin-check/seal loop to (re)distribute our group sender key.
#[allow(clippy::too_many_arguments)]
fn distribute_group_key<S, P, N>(
    r: Recv,
    store: &mut S,
    platform: &mut P,
    net: &N,
    stored: &StoredGroup,
    group: &Group,
    targets: &[String],
    deliver: &mut dyn FnMut(&mut S, &Handle, &SignedRecord, &Device, MailItem) -> DeliveryPath,
) where
    S: Storage,
    P: Platform,
    N: FlowNet,
{
    let mut dk = |s: &mut S, h: &Handle, rec: &SignedRecord, d: &Device, i: MailItem| {
        deliver(s, h, rec, d, i);
    };
    distribute_key(
        r.identity,
        store,
        platform,
        net,
        r.me,
        r.my_name,
        r.my_queue,
        &stored.id,
        &stored.name,
        &group.distribution(),
        &stored.members,
        targets,
        &mut dk,
    );
}

#[cfg(test)]
mod recv_tests {
    //! The receive-dispatch security guards + retry contract, exercised through
    //! the public [`process_item`] with in-memory ports (no real network / disk).

    use super::*;
    use mycellium_core::group::GroupMessage;
    use std::collections::HashMap;
    use std::convert::Infallible;

    #[derive(Default)]
    struct MemStore(HashMap<Vec<u8>, Vec<u8>>);
    impl Storage for MemStore {
        type Error = Infallible;
        fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, Infallible> {
            Ok(self.0.get(k).cloned())
        }
        fn put(&mut self, k: &[u8], v: &[u8]) -> Result<(), Infallible> {
            self.0.insert(k.to_vec(), v.to_vec());
            Ok(())
        }
        fn delete(&mut self, k: &[u8]) -> Result<(), Infallible> {
            self.0.remove(k);
            Ok(())
        }
    }

    struct TestPlatform;
    impl Platform for TestPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            getrandom::getrandom(buf).unwrap();
        }
        fn now_unix_secs(&self) -> u64 {
            1_000
        }
    }

    /// A [`FlowNet`] that resolves nothing — the paths under test never look up.
    struct NoNet;
    impl FlowNet for NoNet {
        fn lookup(&self, _handle: &Handle) -> anyhow::Result<SignedRecord> {
            anyhow::bail!("no network in this test")
        }
    }

    #[derive(Default)]
    struct CollectSink(Vec<FlowEvent>);
    impl FlowSink for CollectSink {
        fn emit(&mut self, event: FlowEvent) {
            self.0.push(event);
        }
    }

    fn run(
        me: &Identity,
        my_handle: &Handle,
        store: &mut MemStore,
        item: MailItem,
        sink: &mut CollectSink,
    ) -> ItemOutcome {
        let mut platform = TestPlatform;
        let net = NoNet;
        let mut deliver =
            |_: &mut MemStore, _: &Handle, _: &SignedRecord, _: &Device, _: MailItem| {
                DeliveryPath::Failed
            };
        let mut self_deliver = |_: &mut MemStore, _: &Handle, _: &Device, _: MailItem| {};
        process_item(
            me,
            store,
            &mut platform,
            &net,
            my_handle,
            "",
            "",
            &[],
            item,
            sink,
            &mut deliver,
            &mut self_deliver,
        )
    }

    // A forged `SelfSync` from a FOREIGN identity must not touch our transcript:
    // the mirror's sender record must be signed by our OWN wallet, else any peer
    // who can seal an envelope to us could inject (or edit/delete) our outgoing
    // history (core review, HIGH). This guard now lives once, in the flow.
    #[test]
    fn self_sync_rejects_a_forged_mirror_from_a_foreign_identity() {
        let mut p = TestPlatform;
        let victim = Identity::generate(&mut p).unwrap();
        let attacker = Identity::generate(&mut p).unwrap();
        let vh = Handle::new("victimhandle").unwrap();
        let ah = Handle::new("attackerhandle").unwrap();
        let vrec = wireops::build_record(&mut p, &victim, &vh, "", "", "");
        let vdev = vrec.record.primary();

        // ATTACK: a foreign identity seals a mirror to the victim, wrapped SelfSync.
        let forged = wireops::text_message(&mut p, "forged outgoing").encode();
        let env = wireops::seal_to(&mut p, &attacker, &ah, "", "", vdev, &forged).unwrap();

        let mut store = MemStore::default();
        let mut sink = CollectSink::default();
        let outcome = run(
            &victim,
            &vh,
            &mut store,
            MailItem::SelfSync {
                peer: "someone".to_string(),
                envelope: env,
            },
            &mut sink,
        );
        assert_eq!(outcome, ItemOutcome::Handled);
        assert!(
            history::load(&store, "someone").unwrap().is_empty(),
            "a forged self-sync from a foreign identity must NOT touch our history",
        );
        assert!(sink.0.is_empty(), "a rejected forgery emits nothing");
    }

    // A group message for a group we don't have yet must be KEPT for retry (its
    // invite/sync hasn't been processed), not dropped as handled (issue #46).
    #[test]
    fn group_text_for_unknown_group_is_kept_for_retry() {
        let mut p = TestPlatform;
        let me = Identity::generate(&mut p).unwrap();
        let mh = Handle::new("mehandle").unwrap();
        let mut store = MemStore::default();
        let mut sink = CollectSink::default();
        let msg = GroupMessage {
            sender: vec![1],
            iteration: 0,
            ciphertext: vec![2, 3],
            signature: vec![4; 64],
        };
        let outcome = run(
            &me,
            &mh,
            &mut store,
            MailItem::GroupText {
                group_id: "no-such-group".to_string(),
                message: msg,
            },
            &mut sink,
        );
        assert_eq!(outcome, ItemOutcome::Retry);
    }
}
