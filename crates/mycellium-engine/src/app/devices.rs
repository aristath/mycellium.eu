#![allow(clippy::too_many_arguments)]
use super::*;

// ---- commands ---------------------------------------------------------------

pub fn identity_new() -> Result<()> {
    if store::exists() {
        bail!("an identity already exists at {}", store::path().display());
    }
    let identity = Identity::generate(&mut OsPlatform)?;
    store::save_identity(&identity)?;
    println!("New identity created.");
    println!("wallet: {}", hex(&identity.wallet_public().0));
    println!(
        "\nThere is no seed phrase: recover this account via email verification on your\n\
         directory, and add more devices by pairing (they never see your account key)."
    );
    Ok(())
}

pub fn identity_show() -> Result<()> {
    let identity = store::load_identity()?;
    println!("wallet:      {}", hex(&identity.wallet_public().0));
    println!("device:      {}", hex(&identity.device_public().0));
    println!(
        "device-id:   {}  (this device, as shown by `devices`)",
        short_device_id(&identity.device_public())
    );
    println!("messaging:   {}", hex(&identity.messaging_public().0));
    println!("signed-pk:   {}", hex(&identity.signed_pre_key_public().0));
    Ok(())
}

pub fn register(handle: &str, addr: &str, libp2p: bool, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;

    // The record's location is a raw `host:port` for TCP, or a full multiaddr
    // (with the PeerId) for libp2p. `chat` auto-detects which by its leading `/`.
    let location = if libp2p {
        libp2p_net::advertised_multiaddr(addr, identity.device_secret())?
    } else {
        addr.to_string()
    };
    let record = build_record(&identity, &handle, &location);

    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    client.publish(&token, &handle, &record)?;
    println!("registered '{}' reachable at {}", handle.as_str(), location);
    Ok(())
}

// ---- helpers ----------------------------------------------------------------

/// A short, human-usable id for a device: the first 4 bytes of its key, in hex.
pub fn short_device_id(key: &DevicePublicKey) -> String {
    hex(&key.0[..4])
}

pub use crate::wireops::device_slot;

/// Re-sign and publish a record with a new device set (seq bumped past `prev`).
pub fn update_devices(
    client: &DirectoryClient,
    token: &str,
    identity: &Identity,
    handle: &Handle,
    devices: Vec<Device>,
    prev_seq: u64,
) -> Result<()> {
    let seq = prev_seq.saturating_add(1).max(OsPlatform.now_unix_secs());
    let record = Record {
        // The record binds the *id*, not the plaintext name (Layer 6).
        handle: user_id(handle.as_str()),
        name: display_name_for(handle),
        wallet: identity.wallet_public(),
        queue: own_queue(),
        devices,
        seq,
    };
    let signed = SignedRecord::sign(record, identity);
    client.publish(token, handle, &signed)
}

pub fn list_devices(handle: &str, directory: &str) -> Result<()> {
    let me = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let client = DirectoryClient::new(directory);
    let record = client.lookup(&me)?;
    record
        .verify()
        .map_err(|_| anyhow!("record failed verification"))?;
    println!("devices for '{handle}':");
    for d in &record.record.devices {
        println!(
            "  {}  {}",
            short_device_id(&d.device_key),
            String::from_utf8_lossy(&d.peer_id.0)
        );
    }
    Ok(())
}

pub fn revoke_device(handle: &str, device_id: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let current = client.lookup(&me)?;
    current
        .verify()
        .map_err(|_| anyhow!("record failed verification"))?;
    if current.record.wallet != identity.wallet_public() {
        bail!("'{handle}' is not your account");
    }

    // Require an *unambiguous* match — the full displayed short id (8 hex chars)
    // or the full device-key hex — and revoke exactly one device, never several.
    let wanted = device_id.to_lowercase();
    let idx = find_device(&current.record.devices, &wanted)?;
    let target = current.record.devices[idx].device_key;
    let devices: Vec<Device> = current
        .record
        .devices
        .iter()
        .filter(|d| d.device_key != target)
        .cloned()
        .collect();
    if devices.is_empty() {
        bail!("cannot revoke the last device in the cluster");
    }
    update_devices(&client, &token, &identity, &me, devices, current.record.seq)?;
    println!("revoked device '{device_id}' from '{handle}'");
    Ok(())
}

/// Find the single device matching `wanted` — its full 8-char short id or its
/// full key hex. Errors if nothing matches, or (defensively) if more than one
/// does, rather than revoking multiple devices from an ambiguous prefix.
fn find_device(devices: &[Device], wanted: &str) -> Result<usize> {
    let hits: Vec<usize> = devices
        .iter()
        .enumerate()
        .filter(|(_, d)| short_device_id(&d.device_key) == wanted || hex(&d.device_key.0) == wanted)
        .map(|(i, _)| i)
        .collect();
    match hits.as_slice() {
        [] => bail!("no device matching '{wanted}' — use the full 8-character id from `devices` (or the full key)"),
        [i] => Ok(*i),
        _ => bail!("'{wanted}' is ambiguous ({} devices) — use the full device key", hits.len()),
    }
}

pub fn build_record(identity: &Identity, handle: &Handle, addr: &str) -> SignedRecord {
    // Supply the OS platform, plus the display name and queue from the
    // environment; the platform-agnostic core lives in `crate::wireops`.
    crate::wireops::build_record(
        &mut OsPlatform,
        identity,
        handle,
        &display_name_for(handle),
        &own_queue(),
        addr,
    )
}

pub use crate::wireops::my_group_id;

/// This device's entry for a record: its transport address plus its own
/// (currently seed-derived) messaging keys, signed by the account wallet.
pub use crate::wireops::this_device;

#[cfg(test)]
mod tests {
    use super::*;
    use mycellium_core::identity::{DevicePublicKey, MessagingPublicKey, PeerId, Signature};
    use mycellium_core::record::SignedPreKey;

    fn dev(first4: [u8; 4], tag: u8) -> Device {
        let mut key = [tag; 32]; // `tag` distinguishes the full key
        key[..4].copy_from_slice(&first4);
        Device {
            device_key: DevicePublicKey(key),
            peer_id: PeerId(Vec::new()),
            id_key: MessagingPublicKey([0u8; 32]),
            signed_pre_key: SignedPreKey {
                public: MessagingPublicKey([0u8; 32]),
                signature: Signature(vec![0u8; 64]),
            },
        }
    }

    #[test]
    fn revocation_requires_unambiguous_match() {
        let a = dev([0xaa, 0xbb, 0xcc, 0xdd], 1); // short id "aabbccdd"
        let b = dev([0x11, 0x22, 0x33, 0x44], 2);
        let c = dev([0xaa, 0xbb, 0xcc, 0xdd], 3); // same short id as `a`, different full key

        // Exact full short id, unique → matches.
        assert_eq!(find_device(&[a.clone(), b.clone()], "aabbccdd").unwrap(), 0);
        // A short prefix no longer matches (must be the full 8 chars).
        assert!(find_device(&[a.clone(), b.clone()], "aa").is_err());
        // Two devices share the short id → ambiguous, rejected (not both revoked).
        assert!(find_device(&[a.clone(), c.clone()], "aabbccdd").is_err());
        // The full device-key hex disambiguates.
        let full = hex(&a.device_key.0);
        assert_eq!(find_device(&[a, c], &full).unwrap(), 0);
    }
}
