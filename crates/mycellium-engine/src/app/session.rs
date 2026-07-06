#![allow(clippy::too_many_arguments)]
use super::*;

/// An established, ready-to-use session: the ratchet, the AEAD associated data,
/// and the peer's display name.
pub struct Session {
    pub ratchet: Ratchet,
    pub ad: Vec<u8>,
    pub peer_name: String,
}

/// Initiator handshake: send our record + X3DH init, build the session.
pub fn handshake_initiator(
    conn: &mut dyn Wire,
    identity: &Identity,
    me: &Handle,
    peer_handle: &Handle,
    peer_record: &SignedRecord,
    location: &str,
) -> Result<Session> {
    let my_record = build_record(identity, me, "");
    conn.send(&wire::encode(&my_record))?;
    // Our plaintext name for display — self-verifying (its id must equal the id
    // in the record we just sent), since the record only carries the id now.
    conn.send(me.as_str().as_bytes())?;

    let mut platform = OsPlatform;
    let responder_ik = peer_record.record.primary().id_key;
    let responder_spk = peer_record.record.primary().signed_pre_key.public;
    let initiated = x3dh::initiate(&mut platform, identity, &responder_ik, &responder_spk)
        .map_err(|e| anyhow!("{e}"))?;
    conn.send(&wire::encode(&initiated.init))?;

    let ratchet = Ratchet::new_initiator(&mut platform, &initiated.shared_secret, &responder_spk)
        .map_err(|e| anyhow!("{e}"))?;
    let ad = associated_data(&identity.messaging_public(), &responder_ik);

    let sn = safety::safety_number(&identity.wallet_public(), &peer_record.record.wallet);
    println!(
        "connected to '{}' at {} — end-to-end encrypted.",
        peer_handle.as_str(),
        location
    );
    println!(
        "safety number: {sn}\n(compare it out of band, then `verify {} --confirm` to remember it)",
        peer_handle.as_str()
    );
    println!("Type messages (Ctrl-D to quit):");

    Ok(Session {
        ratchet,
        ad,
        peer_name: peer_handle.as_str().to_string(),
    })
}

/// Responder handshake: read the peer's record + X3DH init, build the session.
pub fn handshake_responder(conn: &mut dyn Wire, identity: &Identity) -> Result<Session> {
    let peer_record: SignedRecord = wire::decode(&conn.recv()?)?;
    peer_record
        .verify()
        .map_err(|_| anyhow!("peer's record failed verification"))?;
    // The peer's plaintext name, self-verifying against the id in their record.
    let who = String::from_utf8(conn.recv()?).map_err(|_| anyhow!("bad peer name"))?;
    if user_id(&who) != peer_record.record.handle {
        bail!("peer name does not match its record");
    }
    let init: HandshakeInit = wire::decode(&conn.recv()?)?;
    // Bind the handshake to the peer's published identity — the init's identity
    // key MUST be the one in their wallet-signed record (the same check
    // `open_envelope` makes on the offline path). Without it an attacker can
    // replay a victim's public record with their OWN init and complete a session
    // we'd label as the victim — and the safety number below, computed from the
    // record's wallet, would still match, defeating the out-of-band defense
    // (core review, HIGH).
    if init.initiator_ik != peer_record.record.primary().id_key {
        bail!("handshake is not bound to the peer's identity");
    }

    let shared = x3dh::respond(identity, &init).map_err(|e| anyhow!("{e}"))?;
    let ratchet = Ratchet::new_responder(&shared, identity);
    let ad = associated_data(&init.initiator_ik, &identity.messaging_public());

    let sn = safety::safety_number(&identity.wallet_public(), &peer_record.record.wallet);
    println!("connected with '{who}' — end-to-end encrypted.");
    println!("safety number: {sn}\n(compare it out of band, then `verify {who} --confirm` to remember it)");
    println!("Type messages (Ctrl-D to quit):");

    Ok(Session {
        ratchet,
        ad,
        peer_name: who,
    })
}
