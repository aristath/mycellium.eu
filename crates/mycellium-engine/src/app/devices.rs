#![allow(clippy::too_many_arguments)]
use super::*;

// ---- commands ---------------------------------------------------------------

pub fn identity_new() -> Result<()> {
    if store::exists() {
        bail!("an identity already exists at {}", store::path().display());
    }
    let identity = Identity::generate(&mut OsPlatform)?;
    store::save_identity(&identity)?;
    println!("New identity created. Write down these 24 words and keep them safe:\n");
    println!("    {}\n", identity.mnemonic());
    println!("wallet: {}", hex(&identity.wallet_public().0));
    Ok(())
}



pub fn identity_show() -> Result<()> {
    let identity = store::load_identity()?;
    println!("wallet:      {}", hex(&identity.wallet_public().0));
    println!("device:      {}", hex(&identity.device_public().0));
    println!("device-id:   {}  (this device, as shown by `devices`)", short_device_id(&identity.device_public()));
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



pub fn guardian_split(shares: u8, threshold: u8) -> Result<()> {
    let identity = store::load_identity()?;
    let mut platform = OsPlatform;
    let parts = shamir::split(identity.mnemonic().as_bytes(), threshold, shares, &mut platform)
        .map_err(|_| anyhow!("invalid --shares/--threshold (need 1 <= threshold <= shares)"))?;

    println!("{threshold}-of-{shares} social recovery. Give one share to each guardian:\n");
    for part in &parts {
        let mut encoded = Vec::with_capacity(1 + part.body.len());
        encoded.push(part.index);
        encoded.extend_from_slice(&part.body);
        println!("  share {}: {}", part.index, hex(&encoded));
    }
    println!("\nAny {threshold} of these can restore your identity with `guardian-recover`.");
    Ok(())
}



pub fn guardian_recover(share_strs: &[String]) -> Result<()> {
    if store::exists() {
        bail!("an identity already exists at {}", store::path().display());
    }
    let mut shares = Vec::with_capacity(share_strs.len());
    for s in share_strs {
        let bytes = from_hex(s)?;
        if bytes.len() < 2 {
            bail!("a share is too short");
        }
        shares.push(Share { index: bytes[0], body: bytes[1..].to_vec() });
    }

    let secret = shamir::combine(&shares).map_err(|_| anyhow!("could not combine shares"))?;
    let phrase = String::from_utf8(secret).map_err(|_| anyhow!("recovered data is not text"))?;
    let identity = Identity::from_phrase(phrase.trim(), &mut OsPlatform)
        .map_err(|_| anyhow!("recovered phrase is invalid — wrong shares, or fewer than the threshold"))?;

    store::save_identity(&identity)?;
    println!("identity recovered on this device (a fresh device in your cluster).");
    println!("wallet: {}", hex(&identity.wallet_public().0));
    Ok(())
}



// ---- helpers ----------------------------------------------------------------

/// A short, human-usable id for a device: the first 4 bytes of its key, in hex.
pub fn short_device_id(key: &DevicePublicKey) -> String {
    hex(&key.0[..4])
}



/// The mailbox slot a device drains: the full hex of its key. Account-wide
/// items (group, control, receipts) instead use [`ACCOUNT_SLOT`].
pub fn device_slot(key: &DevicePublicKey) -> String {
    hex(&key.0)
}




/// Read the account's seed phrase from `MYCELLIUM_PHRASE` or stdin.
pub fn read_phrase() -> Result<String> {
    if let Ok(p) = std::env::var("MYCELLIUM_PHRASE") {
        return Ok(p);
    }
    eprint!("Enter your 24-word seed phrase: ");
    std::io::Write::flush(&mut std::io::stderr()).ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}



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



pub fn link_device(handle: &str, addr: &str, libp2p: bool, directory: &str) -> Result<()> {
    if store::exists() {
        bail!("an identity already exists here — link-device runs on a fresh device (a new MYCELLIUM_HOME)");
    }
    let phrase = read_phrase()?;
    let identity =
        Identity::from_phrase(phrase.trim(), &mut OsPlatform).map_err(|_| anyhow!("invalid seed phrase"))?;
    store::save_identity(&identity)?;

    let me = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let location = if libp2p {
        libp2p_net::advertised_multiaddr(addr, identity.device_secret())?
    } else {
        addr.to_string()
    };
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let current = client
        .lookup(&me)
        .map_err(|_| anyhow!("no record for '{handle}' — register it on your first device first"))?;
    current.verify().map_err(|_| anyhow!("existing record failed verification"))?;
    if current.record.wallet != identity.wallet_public() {
        bail!("'{handle}' belongs to a different account (wallet mismatch)");
    }

    let mut devices = current.record.devices.clone();
    let mine = this_device(&identity, &location);
    if devices.iter().any(|d| d.device_key == mine.device_key) {
        println!("this device is already linked to '{handle}'");
        return Ok(());
    }
    devices.push(mine);
    let count = devices.len();
    update_devices(&client, &token, &identity, &me, devices, current.record.seq)?;
    println!("linked this device to '{handle}' — cluster now has {count} device(s)");
    Ok(())
}



pub fn list_devices(handle: &str, directory: &str) -> Result<()> {
    let me = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let client = DirectoryClient::new(directory);
    let record = client.lookup(&me)?;
    record.verify().map_err(|_| anyhow!("record failed verification"))?;
    println!("devices for '{handle}':");
    for d in &record.record.devices {
        println!("  {}  {}", short_device_id(&d.device_key), String::from_utf8_lossy(&d.peer_id.0));
    }
    Ok(())
}



pub fn revoke_device(handle: &str, device_id: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    let current = client.lookup(&me)?;
    current.verify().map_err(|_| anyhow!("record failed verification"))?;
    if current.record.wallet != identity.wallet_public() {
        bail!("'{handle}' is not your account");
    }

    let wanted = device_id.to_lowercase();
    let before = current.record.devices.len();
    let devices: Vec<Device> = current
        .record
        .devices
        .iter()
        .filter(|d| !short_device_id(&d.device_key).starts_with(&wanted))
        .cloned()
        .collect();
    if devices.len() == before {
        bail!("no device matching '{device_id}'");
    }
    if devices.is_empty() {
        bail!("cannot revoke the last device in the cluster");
    }
    let removed = before - devices.len();
    update_devices(&client, &token, &identity, &me, devices, current.record.seq)?;
    println!("revoked {removed} device(s) from '{handle}'");
    Ok(())
}



pub fn build_record(identity: &Identity, handle: &Handle, addr: &str) -> SignedRecord {
    // Supply the OS platform, plus the display name and queue from the
    // environment; the platform-agnostic core lives in `crate::wireops`.
    crate::wireops::build_record(&mut OsPlatform, identity, handle, &display_name_for(handle), &own_queue(), addr)
}



/// This device's unique sender id inside any group (Layer 11): its device key,
/// so two devices of one account are distinct senders and don't collide.
pub fn my_group_id(identity: &Identity) -> Vec<u8> {
    identity.device_public().0.to_vec()
}



/// This device's entry for a record: its transport address plus its own
/// (currently seed-derived) messaging keys, signed by the account wallet.
pub use crate::wireops::this_device;
