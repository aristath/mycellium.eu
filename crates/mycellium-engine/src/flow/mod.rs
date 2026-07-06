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
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, SignedRecord};
use mycellium_core::storage::Storage;

use crate::groups::{GroupInvitePayload, MailItem};
use crate::verified;
use crate::wireops;

/// The directory lookup seam. Each client wraps its own `DirectoryClient`
/// (bound to `ureq` / `xhr` / the native blocking transport); `flow` only needs
/// to resolve a handle to its signed directory record.
pub trait FlowNet {
    /// Look up a peer's signed directory record.
    fn lookup(&self, handle: &Handle) -> anyhow::Result<SignedRecord>;
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
