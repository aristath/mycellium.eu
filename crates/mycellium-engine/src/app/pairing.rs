//! Seedless device **pairing** (the native flow) — replaces seed-phrase linking.
//!
//! The **new** device runs [`pair_new`]: it prints a one-time *offer* (a
//! rendezvous id + its ephemeral public key + the rendezvous queue) for the user
//! to carry to an existing device, then polls the queue rendezvous. The
//! **existing** device runs [`pair_approve`] with that offer: it seals the
//! account key to the offer's ephemeral key (see [`mycellium_core::pairing`]) and
//! relays it through the queue. The new device decrypts it, adopts the account
//! with fresh device keys, and merges itself into the account's record.
//!
//! The account key is only ever sealed to the ephemeral key printed in the
//! offer, so a network attacker (or the relaying queue) can't read it, and the
//! offer is single-use and short-lived.

use super::*;

use mycellium_core::pairing::{self, PairingMessage, PairingResponder, PairingResponderPublic};

/// How long the new device waits for approval before giving up (matches the
/// queue's rendezvous TTL).
const PAIR_TIMEOUT: u64 = 300;

/// The **new** device: emit a pairing offer, then wait to adopt the account.
pub fn pair_new(
    handle: &str,
    addr: &str,
    libp2p: bool,
    queue: &str,
    directory: &str,
) -> Result<()> {
    if store::exists() {
        bail!("an identity already exists here — pair runs with a fresh client config");
    }
    if queue.is_empty() {
        bail!("--queue is required: it is the rendezvous both devices talk through");
    }
    let responder = PairingResponder::new(&mut OsPlatform);
    let mut rid_bytes = [0u8; 16];
    getrandom::getrandom(&mut rid_bytes).map_err(|_| anyhow!("RNG failure"))?;
    let rid = hex(&rid_bytes);

    // The offer the user carries to their existing device.
    let offer = hex(
        serde_json::json!({ "r": rid, "k": hex(&responder.public().0), "q": queue })
            .to_string()
            .as_bytes(),
    );
    println!("On your EXISTING device, run:\n");
    println!("    mycellium pair-approve {offer} --as {handle} --directory {directory}\n");
    println!(
        "Waiting for approval (up to {} minutes)…",
        PAIR_TIMEOUT / 60
    );

    let qclient = QueueClient::new(queue);
    let deadline = OsPlatform.now_unix_secs() + PAIR_TIMEOUT;
    loop {
        if OsPlatform.now_unix_secs() > deadline {
            bail!("pairing timed out — start again with a fresh offer");
        }
        for m in qclient.pair_fetch(&rid).unwrap_or_default() {
            let Ok(raw) = from_hex(&m) else { continue };
            let Ok(pm) = wire::decode::<PairingMessage>(&raw) else {
                continue;
            };
            let Ok(payload) = responder.open(&pm) else {
                continue;
            };
            return adopt_and_register(&payload, handle, addr, libp2p, directory);
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

/// Decrypt the provisioning payload, become the account, and join its record.
fn adopt_and_register(
    payload: &[u8],
    handle: &str,
    addr: &str,
    libp2p: bool,
    directory: &str,
) -> Result<()> {
    let v: serde_json::Value =
        serde_json::from_slice(payload).map_err(|_| anyhow!("malformed provisioning payload"))?;
    let ws = from_hex(
        v["ws"]
            .as_str()
            .ok_or_else(|| anyhow!("bad provisioning"))?,
    )?;
    let ws: [u8; 32] = ws
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("bad account key length"))?;
    // Prefer the account's own handle/directory as sent by the approving device.
    let acc_handle = v["h"].as_str().unwrap_or(handle);
    let acc_dir = v["d"].as_str().unwrap_or(directory);

    let identity =
        Identity::adopt(&mut OsPlatform, ws).map_err(|_| anyhow!("invalid account key"))?;
    store::save_identity(&identity)?;

    let me = Handle::new(acc_handle).map_err(|_| anyhow!("invalid handle"))?;
    let location = if libp2p {
        libp2p_net::advertised_multiaddr(addr, identity.device_secret())?
    } else {
        addr.to_string()
    };
    let client = DirectoryClient::new(acc_dir);
    let token = client.login(&identity)?;
    let current = client.lookup(&me).map_err(|_| {
        anyhow!("no record for '{acc_handle}' — register it first on an existing device")
    })?;
    current
        .verify()
        .map_err(|_| anyhow!("existing record failed verification"))?;
    if current.record.wallet != identity.wallet_public() {
        bail!("account mismatch — the offer was approved for a different account");
    }
    let mut devices = current.record.devices.clone();
    let mine = this_device(&identity, &location);
    if !devices.iter().any(|d| d.device_key == mine.device_key) {
        devices.push(mine);
    }
    let count = devices.len();
    update_devices(&client, &token, &identity, &me, devices, current.record.seq)?;
    println!("paired — this device joined '{acc_handle}' (cluster now has {count} device(s))");
    Ok(())
}

/// The **existing** device: seal the account to the offer and relay it.
pub fn pair_approve(offer: &str, handle: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let bytes = from_hex(offer.trim()).map_err(|_| anyhow!("invalid pairing offer"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid pairing offer"))?;
    let rid = v["r"].as_str().ok_or_else(|| anyhow!("bad offer"))?;
    let k = from_hex(v["k"].as_str().ok_or_else(|| anyhow!("bad offer"))?)?;
    let k: [u8; 32] = k
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("bad ephemeral key"))?;
    let queue = v["q"].as_str().ok_or_else(|| anyhow!("bad offer"))?;

    println!("Pairing a new device to '{handle}' — this shares your account key with it.");
    let payload = serde_json::json!({
        "ws": hex(&identity.wallet_secret()),
        "h": handle,
        "d": directory,
        "q": own_queue(),
    })
    .to_string();
    let msg = pairing::seal_provisioning(
        &mut OsPlatform,
        &PairingResponderPublic(k),
        payload.as_bytes(),
    )
    .map_err(|e| anyhow!("{e}"))?;
    QueueClient::new(queue).pair_post(rid, &hex(&wire::encode(&msg)))?;
    println!("approved — the new device will finish pairing.");
    Ok(())
}
