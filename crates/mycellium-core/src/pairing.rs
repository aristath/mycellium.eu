//! Seedless device **pairing**: move the account (wallet) key to a new device
//! over an ephemeral, in-person-authenticated channel — with no seed phrase
//! anywhere, and nothing reusable left behind.
//!
//! The flow (mirrors Signal-style provisioning), with the **new** device B
//! showing the QR and the **existing** device A scanning it:
//!
//! 1. B generates an ephemeral X25519 keypair and shows its public key in a QR
//!    (alongside a rendezvous id handled by the transport). B keeps the secret.
//! 2. A scans the QR — so B's ephemeral public key is authenticated **visually,
//!    out of band**, which a network attacker can't substitute — asks the user
//!    to confirm, then [`seal_provisioning`]s the account payload to it and
//!    posts the result to the rendezvous.
//! 3. B [`open`](PairingResponder::open)s it and adopts the account.
//!
//! Security rests on B's ephemeral public key never leaving the QR: only a party
//! that scanned it can derive the shared secret, so the AEAD makes B reject
//! anything a malicious rendezvous injects. The ephemeral keys are single-use, so
//! the QR is worthless after pairing (unlike a seed phrase). The shared secret is
//! rejected if it degenerates to all-zero (a low-order/contributory guard).

use alloc::vec::Vec;

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::Error;
use crate::platform::Platform;

/// AEAD associated data binding a provisioning ciphertext to this protocol.
const PAIRING_AAD: &[u8] = b"mycellium-pairing-v1";

/// B's ephemeral public key, shown in the pairing QR. This is the *only* channel
/// it travels over, and it is what authenticates the whole exchange.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingResponderPublic(pub [u8; 32]);

/// A → B provisioning message, relayed through the rendezvous. Confidential and
/// authenticated to whoever scanned the QR; a relay learns nothing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PairingMessage {
    /// A's ephemeral X25519 public key.
    pub initiator_eph: [u8; 32],
    /// The account payload, sealed under the ECDH shared secret.
    pub ciphertext: Vec<u8>,
}

/// The **new** device (B): holds the ephemeral secret behind the QR.
pub struct PairingResponder {
    eph: StaticSecret,
}

impl PairingResponder {
    /// Generate a fresh ephemeral keypair for one pairing attempt.
    pub fn new<P: Platform>(platform: &mut P) -> Self {
        let mut bytes = [0u8; 32];
        platform.fill_random(&mut bytes);
        PairingResponder {
            eph: StaticSecret::from(bytes),
        }
    }

    /// The public key to put in the QR.
    pub fn public(&self) -> PairingResponderPublic {
        PairingResponderPublic(PublicKey::from(&self.eph).to_bytes())
    }

    /// Open a provisioning message from A, returning the account payload.
    pub fn open(&self, msg: &PairingMessage) -> Result<Vec<u8>, Error> {
        let shared = self.eph.diffie_hellman(&PublicKey::from(msg.initiator_eph));
        let key = pairing_key(shared.as_bytes())?;
        crate::cipher::aead_decrypt(&key, &msg.ciphertext, PAIRING_AAD)
    }
}

/// The **existing** device (A): after scanning B's QR and confirming, seal the
/// account `payload` to B's ephemeral public key.
pub fn seal_provisioning<P: Platform>(
    platform: &mut P,
    responder: &PairingResponderPublic,
    payload: &[u8],
) -> Result<PairingMessage, Error> {
    let mut bytes = [0u8; 32];
    platform.fill_random(&mut bytes);
    let eph = StaticSecret::from(bytes);
    let shared = eph.diffie_hellman(&PublicKey::from(responder.0));
    let key = pairing_key(shared.as_bytes())?;
    let ciphertext = crate::cipher::aead_encrypt(&key, payload, PAIRING_AAD);
    Ok(PairingMessage {
        initiator_eph: PublicKey::from(&eph).to_bytes(),
        ciphertext,
    })
}

/// Derive the AEAD key from the ECDH shared secret, rejecting a degenerate
/// (all-zero) secret from a low-order/contributory public key.
fn pairing_key(shared: &[u8; 32]) -> Result<[u8; 32], Error> {
    if shared.iter().all(|&b| b == 0) {
        return Err(Error::WeakKey);
    }
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hk.expand(b"mycellium:pairing:v1", &mut key)
        .expect("32 is a valid HKDF-SHA256 output length");
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic, INSECURE entropy — tests only. Varies by seed so A and B
    /// draw different ephemeral keys.
    struct P(u8);
    impl Platform for P {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31).wrapping_add(self.0);
            }
            self.0 = self.0.wrapping_add(97);
        }
        fn now_unix_secs(&self) -> u64 {
            0
        }
    }

    #[test]
    fn provisioning_round_trips() {
        let mut pa = P(1);
        let mut pb = P(200);
        let b = PairingResponder::new(&mut pb);
        let secret = b"the-account-wallet-secret-32-byte";
        let msg = seal_provisioning(&mut pa, &b.public(), secret).unwrap();
        assert_eq!(b.open(&msg).unwrap(), secret);
    }

    #[test]
    fn a_different_responder_cannot_open() {
        let mut pa = P(1);
        let mut pb = P(200);
        let mut pc = P(50);
        let b = PairingResponder::new(&mut pb);
        let c = PairingResponder::new(&mut pc); // a different new device
        let msg = seal_provisioning(&mut pa, &b.public(), b"secret").unwrap();
        // c didn't have its key in the QR A scanned, so it can't decrypt.
        assert!(c.open(&msg).is_err());
    }

    #[test]
    fn a_tampered_ciphertext_is_rejected() {
        let mut pa = P(1);
        let mut pb = P(200);
        let b = PairingResponder::new(&mut pb);
        let mut msg = seal_provisioning(&mut pa, &b.public(), b"secret").unwrap();
        msg.ciphertext[0] ^= 0xff;
        assert!(b.open(&msg).is_err());
    }

    #[test]
    fn a_low_order_public_key_is_rejected() {
        // An all-zero responder key forces an all-zero shared secret.
        let mut pa = P(1);
        let res = seal_provisioning(&mut pa, &PairingResponderPublic([0u8; 32]), b"x");
        assert!(matches!(res, Err(Error::WeakKey)));
    }
}
