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

use mycellium_core::group::SenderKeyDistribution;
use mycellium_core::identity::{Handle, Identity};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, SignedRecord};
use mycellium_core::storage::Storage;

use crate::groups::{GroupInvitePayload, MailItem};
use crate::history::{self, StoredMessage};
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
