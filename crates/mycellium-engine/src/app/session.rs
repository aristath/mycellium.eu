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
    let initiated = x3dh::initiate(&mut platform, identity, &responder_ik, &responder_spk).map_err(|e| anyhow!("{e}"))?;
    conn.send(&wire::encode(&initiated.init))?;

    let ratchet = Ratchet::new_initiator(&mut platform, &initiated.shared_secret, &responder_spk).map_err(|e| anyhow!("{e}"))?;
    let ad = associated_data(&identity.messaging_public(), &responder_ik);

    let sn = safety::safety_number(&identity.wallet_public(), &peer_record.record.wallet);
    println!("connected to '{}' at {} — end-to-end encrypted.", peer_handle.as_str(), location);
    println!("safety number (verify with '{}' out of band): {sn}", peer_handle.as_str());
    println!("Type messages (Ctrl-D to quit):");

    Ok(Session { ratchet, ad, peer_name: peer_handle.as_str().to_string() })
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

    let shared = x3dh::respond(identity, &init).map_err(|e| anyhow!("{e}"))?;
    let ratchet = Ratchet::new_responder(&shared, identity);
    let ad = associated_data(&init.initiator_ik, &identity.messaging_public());

    let sn = safety::safety_number(&identity.wallet_public(), &peer_record.record.wallet);
    println!("connected with '{who}' — end-to-end encrypted.");
    println!("safety number (verify with '{who}' out of band): {sn}");
    println!("Type messages (Ctrl-D to quit):");

    Ok(Session { ratchet, ad, peer_name: who })
}
