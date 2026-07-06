#![allow(clippy::too_many_arguments)]
use super::*;

pub fn announce(whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    client.announce(&token, &me)?;
    println!("announced '{}' online", me.as_str());
    Ok(())
}

pub fn verify(peer: &str, directory: &str, confirm: bool) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let client = DirectoryClient::new(directory);
    let (peer_handle, peer_record) = lookup_verified(&client, &mut fs, peer)?;
    let wallet = peer_record.record.wallet;
    let sn = safety::safety_number(&identity.wallet_public(), &wallet);
    let level = verified::level(&fs, peer_handle.as_str(), &wallet);

    println!("'{}' — {}", peer_handle.as_str(), level.label());
    println!("safety number: {sn}");

    if confirm {
        verified::mark(&mut fs, peer_handle.as_str(), &wallet)?;
        println!(
            "✓ marked '{}' as verified. Its wallet is pinned; if it ever changes you'll be warned.",
            peer_handle.as_str()
        );
    } else if level != TrustLevel::Verified {
        // Plain-language explanation of what a safety number is and how to use it.
        println!(
            "\nA safety number is a short code both of you can see. Read it aloud (or compare\n\
             it in person / over a call you trust) with '{}'. If the two numbers match, no one\n\
             is sitting in the middle impersonating either of you.\n\
             If it matches, run:  verify {} --confirm   to remember it as verified.",
            peer_handle.as_str(),
            peer
        );
    }
    Ok(())
}

/// Emit **your own** contact card — a compact `{handle, wallet}` you show out of
/// band (in person / a trusted channel) so a peer can verify you without reading
/// a long safety number aloud. The wallet is public, so a card carries no secret.
pub fn contact_card(handle: &str) -> Result<String> {
    let identity = store::load_identity()?;
    let handle = Handle::new(handle).map_err(|_| anyhow!("invalid handle"))?;
    let card = serde_json::json!({
        "v": 1,
        "h": handle.as_str(),
        "w": hex(&identity.wallet_public().0),
    })
    .to_string();
    Ok(hex(card.as_bytes()))
}

/// Verify a peer's contact card: parse it, look up its handle in the directory,
/// and compare the card's wallet (which reached you *out of band*) against the
/// record the directory serves. A **match** means the directory is honest for that
/// handle, so we mark it verified. A **mismatch** means the directory handed you a
/// different identity — a MITM — so we refuse.
pub fn verify_card(card: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let mut fs = open_history(&identity)?;
    let bytes = from_hex(card.trim()).map_err(|_| anyhow!("invalid contact card"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid contact card"))?;
    let handle = v["h"].as_str().ok_or_else(|| anyhow!("malformed card"))?;
    let card_wallet = v["w"].as_str().ok_or_else(|| anyhow!("malformed card"))?;
    let handle_h = Handle::new(handle).map_err(|_| anyhow!("invalid handle in card"))?;

    let client = DirectoryClient::new(directory);
    let record = client
        .lookup(&handle_h)
        .map_err(|_| anyhow!("no record for '{handle}' — is the handle registered?"))?;
    record
        .verify()
        .map_err(|_| anyhow!("that handle's record failed verification"))?;

    if hex(&record.record.wallet.0) != card_wallet {
        bail!(
            "⚠ MISMATCH: the card for '{handle}' does NOT match the directory's record.\n   \
             Either the directory is serving a different identity (a possible MITM), or the\n   \
             card is stale/forged. Do NOT trust this identity."
        );
    }
    verified::mark(&mut fs, handle, &record.record.wallet)?;
    println!("✓ verified '{handle}' from its contact card — the directory's record matches.");
    Ok(())
}

pub fn presence(peer: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let handle_str = contacts::resolve(&fs, peer)?;
    let handle = Handle::new(handle_str).map_err(|_| anyhow!("invalid handle or nickname"))?;
    let client = DirectoryClient::new(directory);
    let online = client.presence(&handle)?;
    println!(
        "{} is {}",
        handle.as_str(),
        if online { "online" } else { "offline" }
    );
    Ok(())
}

/// Resolve a nickname to a handle (or pass a raw handle through), then verify
/// the record matches any pinned wallet for that contact (TOFU).
pub fn lookup_verified(
    client: &DirectoryClient,
    fs: &mut FileStore,
    input: &str,
) -> Result<(Handle, SignedRecord)> {
    let resolved = contacts::resolve(fs, input)?;
    let handle = Handle::new(resolved).map_err(|_| anyhow!("invalid handle or nickname"))?;
    let record = client.lookup(&handle)?;
    record
        .verify()
        .map_err(|_| anyhow!("peer's record failed verification"))?;

    // Fail closed if the current wallet doesn't match a pinned or verified one:
    // either the peer re-registered (e.g. after email recovery) or someone is
    // impersonating them. Either way, don't silently trust the new identity.
    if verified::level(fs, handle.as_str(), &record.record.wallet) == TrustLevel::Changed {
        bail!(
            "⚠ IDENTITY CHANGED for '{h}'.\n   \
             The wallet the directory returned does NOT match the one you {verb} — someone may be\n   \
             impersonating '{h}', or '{h}' recovered/re-registered with a new key.\n   \
             Do NOT trust it until you re-check the safety number out of band, then run:\n   \
             verify {h} --confirm   (to accept the new identity), or `contact add` to re-pin.",
            h = handle.as_str(),
            verb = if verified::get(fs, handle.as_str())?.is_some() { "verified" } else { "pinned" },
        );
    }

    // Anti-rollback: refuse a record older than one we've already pinned for this
    // handle. A malicious/compelled directory can serve a stale (still validly
    // signed, same-wallet) record to re-introduce a removed device or redirect
    // our mail — a downgrade the wallet-change guard above cannot see (HIGH).
    if !crate::antirollback::check_and_pin(fs, handle.as_str(), record.record.seq)? {
        bail!(
            "⚠ STALE RECORD for '{h}': the directory returned an older record (seq {seq}) than one \
             you've already seen. Refusing — a rollback could re-introduce a device you removed or \
             redirect your messages. If '{h}' legitimately rolled back, clear the pin and re-verify.",
            h = handle.as_str(),
            seq = record.record.seq,
        );
    }
    Ok((handle, record))
}
