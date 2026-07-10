//! Platform-agnostic envelope sealing/opening and record building.
//!
//! These pure-crypto building blocks take a [`Platform`] explicitly (clock + RNG)
//! rather than hardcoding the OS one, and take the identity's display name as an
//! argument rather than reading the environment.

use anyhow::{anyhow, bail, Result};

use mycellium_core::identity::{DevicePublicKey, Handle, Identity, MessagingPublicKey, PeerId};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::offline::Envelope;
use mycellium_core::platform::Platform;
use mycellium_core::ratchet::Ratchet;
use mycellium_core::record::{Device, Record, SignedRecord};
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

/// The stable device slot id: the full hex of its device key.
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

/// This device's peer-record entry (keys + signed pre-key).
pub fn this_device(identity: &Identity, addr: &str, seq: u64) -> Device {
    Device::create(identity, PeerId(addr.as_bytes().to_vec()), seq)
}

/// Build and sign this identity's peer record.
pub fn build_record<P: Platform>(
    platform: &mut P,
    identity: &Identity,
    handle: &Handle,
    name: &str,
    addr: &str,
) -> SignedRecord {
    let record = Record {
        // The record binds `user_id(handle)`, so discovery can carry the record
        // without becoming naming authority.
        handle: user_id(handle.as_str()),
        name: name.to_string(),
        wallet: identity.wallet_public(),
        devices: vec![this_device(identity, addr, platform.now_unix_secs())],
        seq: platform.now_unix_secs(),
    };
    SignedRecord::sign(record, identity)
}

/// Asynchronously X3DH-seal `plaintext` for one recipient `device` (offline,
/// one-shot session), embedding an already-built sender self-record.
///
/// This is the hot-loop entry point for the send fan-out: the sender's
/// [`SignedRecord`] costs two secp256k1 ECDSA signs to build (record signature +
/// signed-pre-key signature), yet it is *identical* for every recipient device of
/// one send. Callers that fan out over many devices build it **once** (via
/// [`build_record`]) and pass it here per device, instead of re-signing it N
/// times. One-shot callers use [`seal_to`], which builds the record then calls
/// this. The embedded record is byte-for-byte what [`seal_to`] would embed, so the
/// receiver's per-message re-verification ([`open_envelope`]) is unchanged.
pub fn seal_to_with_record<P: Platform>(
    platform: &mut P,
    identity: &Identity,
    me: &Handle,
    sender_record: &SignedRecord,
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
    // Pad inside the AEAD, so a network observer sees a coarse size bucket
    // instead of the exact message length.
    let sealed = ratchet.encrypt(&pad_bucket(plaintext), &ad);
    Ok(Envelope {
        from: me.clone(),
        sender_record: sender_record.clone(),
        init: initiated.init,
        message: sealed,
        timestamp: platform.now_unix_secs(),
    })
}

/// Asynchronously X3DH-seal `plaintext` for one recipient `device` (offline,
/// one-shot session). `my_name` populates the sender's self-record embedded in
/// the envelope. Builds the sender record once, then delegates to
/// [`seal_to_with_record`] — the one-shot convenience for callers that seal to a
/// single device.
pub fn seal_to<P: Platform>(
    platform: &mut P,
    identity: &Identity,
    me: &Handle,
    my_name: &str,
    device: &Device,
    plaintext: &[u8],
) -> Result<Envelope> {
    let sender_record = build_record(platform, identity, me, my_name, "");
    seal_to_with_record(platform, identity, me, &sender_record, device, plaintext)
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
    let padded = ratchet
        .decrypt(platform, &env.message, &ad)
        .map_err(|_| anyhow!("could not decrypt message"))?;
    // Strip the size-bucket padding the sender added before sealing (#51). The
    // length prefix is inside the AEAD, so a bad value means the authenticated
    // plaintext is itself inconsistent — fail closed.
    let plaintext = unpad_bucket(&padded)?;
    Ok((env.from.clone(), plaintext))
}

/// Size buckets (bytes of the pre-seal payload) that envelope plaintexts are
/// padded up to, so the wire sees coarse blob sizes rather than exact message
/// lengths.
const PAD_BUCKETS: &[usize] = &[256, 1024, 4096, 16384, 65536, 262144];

/// Pad `payload` up to a size bucket. Layout: `[u32-LE real_len][payload][zeros]`.
/// The result is sealed inside the envelope AEAD, so the padding is authenticated.
/// Payloads larger than the top bucket round up to the next 64 KiB.
fn pad_bucket(payload: &[u8]) -> Vec<u8> {
    let needed = 4 + payload.len();
    let target = PAD_BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= needed)
        .unwrap_or_else(|| needed.div_ceil(65536) * 65536);
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out.resize(target, 0);
    out
}

/// Strip the [`pad_bucket`] framing, returning the original payload. Fails closed
/// on a malformed length prefix.
fn unpad_bucket(padded: &[u8]) -> Result<Vec<u8>> {
    let len_bytes: [u8; 4] = padded
        .get(0..4)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("padded payload too short"))?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    let end = 4usize
        .checked_add(len)
        .filter(|&e| e <= padded.len())
        .ok_or_else(|| anyhow!("padded length prefix out of range"))?;
    Ok(padded[4..end].to_vec())
}

#[cfg(test)]
mod pad_tests {
    use super::{pad_bucket, unpad_bucket, PAD_BUCKETS};

    #[test]
    fn round_trips_and_lands_on_a_bucket() {
        for len in [0usize, 1, 100, 252, 253, 1000, 5000, 60000, 200000] {
            let payload = vec![7u8; len];
            let padded = pad_bucket(&payload);
            // Padded size is a coarse bucket (or a 64 KiB multiple above the top).
            assert!(
                PAD_BUCKETS.contains(&padded.len()) || padded.len().is_multiple_of(65536),
                "len {len} padded to {}",
                padded.len()
            );
            // Padding hides the exact length: a 1-byte and a 100-byte message
            // both occupy the 256-byte bucket.
            assert!(padded.len() >= 4 + len);
            assert_eq!(unpad_bucket(&padded).unwrap(), payload);
        }
    }

    #[test]
    fn small_messages_share_the_smallest_bucket() {
        assert_eq!(pad_bucket(&[1]).len(), 256);
        assert_eq!(pad_bucket(&[9; 100]).len(), 256);
    }

    #[test]
    fn malformed_padding_fails_closed() {
        assert!(unpad_bucket(&[]).is_err());
        assert!(unpad_bucket(&[1, 2]).is_err());
        // A length prefix claiming more bytes than exist is rejected.
        let mut bad = 999u32.to_le_bytes().to_vec();
        bad.extend_from_slice(&[0u8; 10]);
        assert!(unpad_bucket(&bad).is_err());
    }
}
