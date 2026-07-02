//! X3DH: the initial key agreement (Layer 8.6, bootstrap step).
//!
//! Two peers derive the same 32-byte shared secret `SK` from a handful of
//! Diffie-Hellman results. Every DH here pairs *one* private key with *one*
//! public key (the property the old spec got wrong); the four public identities
//! involved are the initiator's identity + ephemeral and the responder's
//! identity + signed pre-key.
//!
//! This is the **interactive** POC variant: the responder is online and holds
//! its own secrets. One-time pre-keys are deferred (Layer 8.7). `SK` seeds the
//! Double Ratchet, and the responder's signed pre-key doubles as its first
//! ratchet public key.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::identity::{Identity, MessagingPublicKey};
use crate::platform::Platform;

/// HKDF info string — domain separation for the X3DH output.
const KDF_INFO: &[u8] = b"Mycellium-X3DH-v1";

/// The 32-byte shared secret produced by X3DH. Zeroized on drop.
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    /// Borrow the raw secret (to seed the ratchet).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// What the initiator sends the responder so it can derive the same `SK`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeInit {
    /// Initiator's long-term identity (messaging) public key.
    pub initiator_ik: MessagingPublicKey,
    /// Initiator's one-time ephemeral public key.
    pub initiator_ek: MessagingPublicKey,
}

/// The initiator's output: the shared secret and the message to send.
pub struct Initiated {
    /// Derived shared secret.
    pub shared_secret: SharedSecret,
    /// Message for the responder.
    pub init: HandshakeInit,
}

/// Run X3DH as the **initiator** (Alice) against the responder's public keys,
/// which come from the responder's directory record.
pub fn initiate<P: Platform>(
    platform: &mut P,
    initiator: &Identity,
    responder_ik: &MessagingPublicKey,
    responder_spk: &MessagingPublicKey,
) -> Initiated {
    // Fresh ephemeral key.
    let mut ek_bytes = [0u8; 32];
    platform.fill_random(&mut ek_bytes);
    let ephemeral = StaticSecret::from(ek_bytes);
    ek_bytes.zeroize();
    let ephemeral_public = MessagingPublicKey(PublicKey::from(&ephemeral).to_bytes());

    // DH1 = IK_A · SPK_B   DH2 = EK_A · IK_B   DH3 = EK_A · SPK_B
    let dh1 = initiator.dh_identity(responder_spk);
    let dh2 = ephemeral
        .diffie_hellman(&PublicKey::from(responder_ik.0))
        .to_bytes();
    let dh3 = ephemeral
        .diffie_hellman(&PublicKey::from(responder_spk.0))
        .to_bytes();

    let shared_secret = kdf(&dh1, &dh2, &dh3);

    Initiated {
        shared_secret,
        init: HandshakeInit {
            initiator_ik: initiator.messaging_public(),
            initiator_ek: ephemeral_public,
        },
    }
}

/// Run X3DH as the **responder** (Bob) from the initiator's [`HandshakeInit`].
///
/// Uses the responder's own identity and signed pre-key secrets to reach the
/// exact same `SK` (because `DH(a, B) == DH(b, A)`).
pub fn respond(responder: &Identity, init: &HandshakeInit) -> SharedSecret {
    // DH1 = SPK_B · IK_A   DH2 = IK_B · EK_A   DH3 = SPK_B · EK_A
    let dh1 = responder.dh_signed_pre_key(&init.initiator_ik);
    let dh2 = responder.dh_identity(&init.initiator_ek);
    let dh3 = responder.dh_signed_pre_key(&init.initiator_ek);

    kdf(&dh1, &dh2, &dh3)
}

/// HKDF-SHA256 over `DH1 || DH2 || DH3` into a 32-byte secret.
fn kdf(dh1: &[u8; 32], dh2: &[u8; 32], dh3: &[u8; 32]) -> SharedSecret {
    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(dh1);
    ikm[32..64].copy_from_slice(dh2);
    ikm[64..].copy_from_slice(dh3);

    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut sk = [0u8; 32];
    hk.expand(KDF_INFO, &mut sk)
        .expect("32 is a valid HKDF-SHA256 output length");

    ikm.zeroize();
    SharedSecret(sk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Platform;

    /// Distinct, deterministic (INSECURE) entropy per instance — tests only.
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

    #[test]
    fn both_sides_agree_on_the_secret() {
        let alice = Identity::generate(&mut SeededPlatform(1)).unwrap();
        let bob = Identity::generate(&mut SeededPlatform(150)).unwrap();

        // Alice initiates against Bob's published identity + signed pre-key.
        let initiated = initiate(
            &mut SeededPlatform(60),
            &alice,
            &bob.messaging_public(),
            &bob.signed_pre_key_public(),
        );

        // Bob responds from the handshake message.
        let bob_secret = respond(&bob, &initiated.init);

        assert_eq!(
            initiated.shared_secret.as_bytes(),
            bob_secret.as_bytes(),
            "initiator and responder must derive the same SK"
        );
    }

    #[test]
    fn a_different_responder_derives_a_different_secret() {
        let alice = Identity::generate(&mut SeededPlatform(1)).unwrap();
        let bob = Identity::generate(&mut SeededPlatform(150)).unwrap();
        let mallory = Identity::generate(&mut SeededPlatform(200)).unwrap();

        let initiated = initiate(
            &mut SeededPlatform(60),
            &alice,
            &bob.messaging_public(),
            &bob.signed_pre_key_public(),
        );
        // Mallory tries to respond with her own keys — she can't reach Bob's SK.
        let mallory_secret = respond(&mallory, &initiated.init);
        assert_ne!(initiated.shared_secret.as_bytes(), mallory_secret.as_bytes());
    }
}
