//! Platform-agnostic envelope sealing/opening and record building.
//!
//! These are the pure-crypto building blocks shared by the native orchestration
//! (`app`, behind the `native` feature) and the browser (wasm) build. They take a
//! [`Platform`] explicitly (clock + RNG) rather than hardcoding the OS one, and
//! take the identity's display name and queue URL as arguments rather than
//! reading the environment — so they run anywhere, including wasm32.

use anyhow::{anyhow, bail, Result};

use mycellium_core::identity::{DevicePublicKey, Handle, Identity, MessagingPublicKey, PeerId};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::offline::Envelope;
use mycellium_core::platform::Platform;
use mycellium_core::ratchet::Ratchet;
use mycellium_core::record::{Device, Record, SignedPreKey, SignedRecord};
use mycellium_core::userid::user_id;
use mycellium_core::x3dh;

/// The AEAD associated data binding a message to both parties' identity keys.
pub fn associated_data(
    initiator_ik: &MessagingPublicKey,
    responder_ik: &MessagingPublicKey,
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(&initiator_ik.0);
    ad.extend_from_slice(&responder_ik.0);
    ad
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// A short random message id, from the platform RNG.
pub fn random_id<P: Platform>(platform: &mut P) -> String {
    let mut bytes = [0u8; 6];
    platform.fill_random(&mut bytes);
    hex(&bytes)
}

/// Wrap a message `body` into an [`AppMessage`] with a fresh id + timestamp.
pub fn app_message<P: Platform>(platform: &mut P, body: Body) -> AppMessage {
    AppMessage {
        id: random_id(platform),
        timestamp: platform.now_unix_secs(),
        expires_at: None,
        body,
    }
}

/// A plain-text application message (no expiry).
pub fn text_message<P: Platform>(platform: &mut P, text: &str) -> AppMessage {
    app_message(platform, Body::Text(text.to_string()))
}

/// The mailbox slot a device drains: the full hex of its key. Account-wide items
/// (groups, control, receipts) use the `"account"` slot instead.
pub fn device_slot(key: &DevicePublicKey) -> String {
    hex(&key.0)
}

/// This device's unique sender id inside any group (Layer 11): its device key,
/// so two devices of one account are distinct senders and don't collide.
pub fn my_group_id(identity: &Identity) -> Vec<u8> {
    identity.device_public().0.to_vec()
}

/// The AEAD associated data binding a message to its group.
pub fn group_ad(group_id: &str) -> Vec<u8> {
    let mut ad = b"group:".to_vec();
    ad.extend_from_slice(group_id.as_bytes());
    ad
}

/// This device's directory entry (keys + signed pre-key). Pure — derived from
/// the identity.
pub fn this_device(identity: &Identity, addr: &str) -> Device {
    Device {
        device_key: identity.device_public(),
        peer_id: PeerId(addr.as_bytes().to_vec()),
        id_key: identity.messaging_public(),
        signed_pre_key: SignedPreKey::create(identity.signed_pre_key_public(), identity),
    }
}

/// Build and sign this identity's directory record. `name` is the display name
/// and `queue` the queue endpoint (supplied by the caller, not the environment).
pub fn build_record<P: Platform>(
    platform: &mut P,
    identity: &Identity,
    handle: &Handle,
    name: &str,
    queue: &str,
    addr: &str,
) -> SignedRecord {
    let record = Record {
        // The record binds `user_id(name)`, so the directory never sees the name.
        handle: user_id(handle.as_str()),
        name: name.to_string(),
        wallet: identity.wallet_public(),
        queue: queue.to_string(),
        devices: vec![this_device(identity, addr)],
        seq: platform.now_unix_secs(),
    };
    SignedRecord::sign(record, identity)
}

/// Asynchronously X3DH-seal `plaintext` for one recipient `device` (offline,
/// one-shot session). `my_name`/`my_queue` populate the sender's self-record
/// embedded in the envelope.
pub fn seal_to<P: Platform>(
    platform: &mut P,
    identity: &Identity,
    me: &Handle,
    my_name: &str,
    my_queue: &str,
    device: &Device,
    plaintext: &[u8],
) -> Result<Envelope> {
    let responder_ik = device.id_key;
    let responder_spk = device.signed_pre_key.public;
    // Fails closed if the recipient device published a low-order key.
    let initiated = x3dh::initiate(platform, identity, &responder_ik, &responder_spk)
        .map_err(|e| anyhow!("{e}"))?;
    let mut ratchet = Ratchet::new_initiator(platform, &initiated.shared_secret, &responder_spk)
        .map_err(|e| anyhow!("{e}"))?;
    let ad = associated_data(&identity.messaging_public(), &responder_ik);
    let sealed = ratchet.encrypt(plaintext, &ad);
    Ok(Envelope {
        from: me.clone(),
        sender_record: build_record(platform, identity, me, my_name, my_queue, ""),
        init: initiated.init,
        message: sealed,
        timestamp: platform.now_unix_secs(),
    })
}

/// Decrypt an incoming envelope, verifying the sender's self-record binds their
/// name, identity key, and handshake.
pub fn open_envelope<P: Platform>(
    platform: &mut P,
    identity: &Identity,
    env: &Envelope,
) -> Result<(Handle, Vec<u8>)> {
    env.sender_record
        .verify()
        .map_err(|_| anyhow!("sender record failed verification"))?;
    // The envelope carries the sender's plaintext name for display; it's
    // self-verifying — its id must equal the id in the wallet-signed record.
    if user_id(env.from.as_str()) != env.sender_record.record.handle {
        bail!("sender name does not match its record");
    }
    if env.init.initiator_ik != env.sender_record.record.primary().id_key {
        bail!("handshake is not bound to the sender's identity");
    }
    let shared = x3dh::respond(identity, &env.init).map_err(|e| anyhow!("{e}"))?;
    let mut ratchet = Ratchet::new_responder(&shared, identity);
    let ad = associated_data(&env.init.initiator_ik, &identity.messaging_public());
    let plaintext = ratchet
        .decrypt(platform, &env.message, &ad)
        .map_err(|_| anyhow!("could not decrypt message"))?;
    Ok((env.from.clone(), plaintext))
}
