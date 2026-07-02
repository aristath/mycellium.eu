//! The Double Ratchet (Layer 8.6, per-message step).
//!
//! Seeded by the X3DH shared secret, this gives every message a fresh key and
//! advances the key material with each exchange — forward secrecy plus
//! post-compromise recovery. It is built directly on vetted primitives, exactly
//! as Layer 8.7 requires (we assemble; we do not invent):
//!
//! - **X25519** for the DH ratchet,
//! - **HKDF-SHA256** for the root KDF,
//! - **HMAC-SHA256** for the chain/message-key KDF,
//! - **ChaCha20-Poly1305** for the message AEAD.
//!
//! The algorithm follows the Signal Double Ratchet specification. Skipped
//! message keys are retained (bounded by [`MAX_SKIP`]) so out-of-order delivery
//! still decrypts.

use alloc::vec::Vec;

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::cipher::{aead_decrypt, aead_encrypt, kdf_ck};
use crate::error::Error;
use crate::identity::{Identity, MessagingPublicKey};
use crate::platform::Platform;
use crate::x3dh::SharedSecret;

/// Maximum number of skipped message keys retained across chains.
pub const MAX_SKIP: u32 = 256;

/// The per-message header sent in the clear (but authenticated as AEAD AD).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Sender's current ratchet public key.
    pub dh: MessagingPublicKey,
    /// Number of messages in the previous sending chain.
    pub pn: u32,
    /// Message number within the current sending chain.
    pub n: u32,
}

/// A ratchet-encrypted message: header plus AEAD ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// Cleartext, authenticated header.
    pub header: Header,
    /// ChaCha20-Poly1305 ciphertext (includes the auth tag).
    pub ciphertext: Vec<u8>,
}

/// One side of a Double Ratchet session.
pub struct Ratchet {
    root: [u8; 32],
    dhs: StaticSecret,
    dhs_pub: [u8; 32],
    dhr: Option<[u8; 32]>,
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: Vec<SkippedKey>,
}

struct SkippedKey {
    dh: [u8; 32],
    n: u32,
    mk: [u8; 32],
}

impl Ratchet {
    /// Initialise the **initiator's** ratchet after X3DH.
    ///
    /// The remote ratchet key is the responder's signed pre-key; the initiator
    /// generates a fresh ratchet key and derives its first sending chain, so it
    /// can send immediately.
    pub fn new_initiator<P: Platform>(
        platform: &mut P,
        sk: &SharedSecret,
        responder_spk: &MessagingPublicKey,
    ) -> Self {
        let (dhs, dhs_pub) = generate_dh(platform);
        let dhr = responder_spk.0;
        let (root, cks) = kdf_rk(sk.as_bytes(), &dh(&dhs, &dhr));
        Ratchet {
            root,
            dhs,
            dhs_pub,
            dhr: Some(dhr),
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
        }
    }

    /// Initialise the **responder's** ratchet after X3DH.
    ///
    /// The responder's first ratchet key *is* its signed pre-key (the key the
    /// initiator already ran X3DH against). It has no sending chain until it
    /// receives the first message and performs a DH ratchet.
    pub fn new_responder(sk: &SharedSecret, responder: &Identity) -> Self {
        let dhs = responder.signed_pre_key_secret().clone();
        let dhs_pub = PublicKey::from(&dhs).to_bytes();
        Ratchet {
            root: *sk.as_bytes(),
            dhs,
            dhs_pub,
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
        }
    }

    /// Whether a sending chain exists yet.
    ///
    /// An initiator can send immediately; a responder can only send after it has
    /// received the first message (which establishes its sending chain via the
    /// DH ratchet). Callers should check this before [`encrypt`](Self::encrypt).
    pub fn can_send(&self) -> bool {
        self.cks.is_some()
    }

    /// Encrypt `plaintext`. `ad` is extra associated data bound into the AEAD
    /// (e.g. the two identities); it must match on decrypt.
    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> RatchetMessage {
        let cks = self.cks.expect("sending chain must be established before sending");
        let (cks_next, mk) = kdf_ck(&cks);
        self.cks = Some(cks_next);

        let header = Header {
            dh: MessagingPublicKey(self.dhs_pub),
            pn: self.pn,
            n: self.ns,
        };
        self.ns += 1;

        let aad = associated_data(ad, &header);
        let ciphertext = aead_encrypt(&mk, plaintext, &aad);
        RatchetMessage { header, ciphertext }
    }

    /// Decrypt a [`RatchetMessage`], advancing the ratchet as needed.
    pub fn decrypt<P: Platform>(
        &mut self,
        platform: &mut P,
        msg: &RatchetMessage,
        ad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // A previously-skipped key may already cover this message.
        if let Some(plaintext) = self.try_skipped(msg, ad)? {
            return Ok(plaintext);
        }

        let header_dh = msg.header.dh.0;
        if self.dhr != Some(header_dh) {
            // New ratchet key: bank the rest of the current chain, then step.
            self.skip_message_keys(msg.header.pn)?;
            self.dh_ratchet(platform, header_dh);
        }
        self.skip_message_keys(msg.header.n)?;

        let ckr = self.ckr.expect("receiving chain established by DH ratchet");
        let (ckr_next, mk) = kdf_ck(&ckr);
        self.ckr = Some(ckr_next);
        self.nr += 1;

        let aad = associated_data(ad, &msg.header);
        aead_decrypt(&mk, &msg.ciphertext, &aad)
    }

    fn try_skipped(&mut self, msg: &RatchetMessage, ad: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let dh = msg.header.dh.0;
        let n = msg.header.n;
        if let Some(pos) = self.skipped.iter().position(|s| s.dh == dh && s.n == n) {
            let mut entry = self.skipped.remove(pos);
            let aad = associated_data(ad, &msg.header);
            let plaintext = aead_decrypt(&entry.mk, &msg.ciphertext, &aad)?;
            entry.mk.zeroize();
            Ok(Some(plaintext))
        } else {
            Ok(None)
        }
    }

    fn skip_message_keys(&mut self, until: u32) -> Result<(), Error> {
        let ckr = match self.ckr {
            Some(ck) => ck,
            None => return Ok(()), // no receiving chain yet — nothing to skip
        };
        if until < self.nr {
            return Ok(());
        }
        if until - self.nr > MAX_SKIP {
            return Err(Error::TooManySkipped);
        }
        if self.skipped.len() as u32 + (until - self.nr) > MAX_SKIP {
            return Err(Error::TooManySkipped);
        }

        let dhr = self.dhr.expect("receiving chain implies a remote ratchet key");
        let mut ck = ckr;
        while self.nr < until {
            let (ck_next, mk) = kdf_ck(&ck);
            self.skipped.push(SkippedKey {
                dh: dhr,
                n: self.nr,
                mk,
            });
            ck = ck_next;
            self.nr += 1;
        }
        self.ckr = Some(ck);
        Ok(())
    }

    fn dh_ratchet<P: Platform>(&mut self, platform: &mut P, header_dh: [u8; 32]) {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        self.dhr = Some(header_dh);

        let (root, ckr) = kdf_rk(&self.root, &dh(&self.dhs, &header_dh));
        self.root = root;
        self.ckr = Some(ckr);

        let (dhs, dhs_pub) = generate_dh(platform);
        self.dhs = dhs;
        self.dhs_pub = dhs_pub;

        let (root, cks) = kdf_rk(&self.root, &dh(&self.dhs, &header_dh));
        self.root = root;
        self.cks = Some(cks);
    }
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.root.zeroize();
        if let Some(mut ck) = self.cks.take() {
            ck.zeroize();
        }
        if let Some(mut ck) = self.ckr.take() {
            ck.zeroize();
        }
        for s in &mut self.skipped {
            s.mk.zeroize();
        }
    }
}

/// Generate a fresh X25519 ratchet keypair from host entropy.
fn generate_dh<P: Platform>(platform: &mut P) -> (StaticSecret, [u8; 32]) {
    let mut bytes = [0u8; 32];
    platform.fill_random(&mut bytes);
    let secret = StaticSecret::from(bytes);
    bytes.zeroize();
    let public = PublicKey::from(&secret).to_bytes();
    (secret, public)
}

/// X25519 DH between our secret and a remote public.
fn dh(secret: &StaticSecret, remote: &[u8; 32]) -> [u8; 32] {
    secret.diffie_hellman(&PublicKey::from(*remote)).to_bytes()
}

/// Root KDF: `(root', chain) = HKDF(root, dh_out)`.
fn kdf_rk(root: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(root), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(b"Mycellium-DR-Root", &mut okm)
        .expect("64 is a valid HKDF-SHA256 output length");
    let mut root_next = [0u8; 32];
    let mut chain = [0u8; 32];
    root_next.copy_from_slice(&okm[..32]);
    chain.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (root_next, chain)
}

/// Bind the caller's `ad` and the message header into the AEAD associated data.
fn associated_data(ad: &[u8], header: &Header) -> Vec<u8> {
    let header_bytes = crate::wire::canonical(header);
    let mut out = Vec::with_capacity(ad.len() + header_bytes.len());
    out.extend_from_slice(ad);
    out.extend_from_slice(&header_bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh;

    /// A single, continuously-advancing (INSECURE) entropy source — tests only.
    /// One instance is shared across a whole test so no two generated keys
    /// collide (a real CSPRNG never repeats).
    struct SeededPlatform(u8);
    impl Platform for SeededPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
        fn now_unix_secs(&self) -> u64 {
            0
        }
    }

    /// Establish two ratchets that share an X3DH secret, initiator + responder.
    fn established(p: &mut SeededPlatform) -> (Ratchet, Ratchet) {
        let alice = Identity::generate(p).unwrap();
        let bob = Identity::generate(p).unwrap();

        let initiated = x3dh::initiate(
            p,
            &alice,
            &bob.messaging_public(),
            &bob.signed_pre_key_public(),
        );
        let bob_sk = x3dh::respond(&bob, &initiated.init);

        let alice_r = Ratchet::new_initiator(p, &initiated.shared_secret, &bob.signed_pre_key_public());
        let bob_r = Ratchet::new_responder(&bob_sk, &bob);
        (alice_r, bob_r)
    }

    const AD: &[u8] = b"alice|bob";

    #[test]
    fn single_message() {
        let mut p = SeededPlatform(0);
        let (mut alice, mut bob) = established(&mut p);
        let msg = alice.encrypt(b"hello bob", AD);
        let got = bob.decrypt(&mut p, &msg, AD).unwrap();
        assert_eq!(got, b"hello bob");
    }

    #[test]
    fn back_and_forth_ratchets() {
        let mut p = SeededPlatform(0);
        let (mut alice, mut bob) = established(&mut p);
        for i in 0..5u8 {
            let a = alice.encrypt(&[b'a', i], AD);
            assert_eq!(bob.decrypt(&mut p, &a, AD).unwrap(), [b'a', i]);
            let b = bob.encrypt(&[b'b', i], AD);
            assert_eq!(alice.decrypt(&mut p, &b, AD).unwrap(), [b'b', i]);
        }
    }

    #[test]
    fn out_of_order_within_a_chain() {
        let mut p = SeededPlatform(0);
        let (mut alice, mut bob) = established(&mut p);
        let m1 = alice.encrypt(b"first", AD);
        let m2 = alice.encrypt(b"second", AD);
        let m3 = alice.encrypt(b"third", AD);

        // Deliver 3, then 1, then 2 — skipped keys must cover the gaps.
        assert_eq!(bob.decrypt(&mut p, &m3, AD).unwrap(), b"third");
        assert_eq!(bob.decrypt(&mut p, &m1, AD).unwrap(), b"first");
        assert_eq!(bob.decrypt(&mut p, &m2, AD).unwrap(), b"second");
    }

    #[test]
    fn wrong_ad_fails() {
        let mut p = SeededPlatform(0);
        let (mut alice, mut bob) = established(&mut p);
        let msg = alice.encrypt(b"secret", AD);
        assert!(bob.decrypt(&mut p, &msg, b"wrong").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut p = SeededPlatform(0);
        let (mut alice, mut bob) = established(&mut p);
        let mut msg = alice.encrypt(b"secret", AD);
        msg.ciphertext[0] ^= 0xff;
        assert!(bob.decrypt(&mut p, &msg, AD).is_err());
    }

    #[test]
    fn message_survives_wire_round_trip() {
        let mut p = SeededPlatform(0);
        let (mut alice, mut bob) = established(&mut p);
        let msg = alice.encrypt(b"over the wire", AD);
        let bytes = crate::wire::encode(&msg);
        let decoded: RatchetMessage = crate::wire::decode(&bytes).unwrap();
        assert_eq!(bob.decrypt(&mut p, &decoded, AD).unwrap(), b"over the wire");
    }
}
