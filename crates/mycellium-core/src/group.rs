//! Group messaging via **sender keys** (the WhatsApp/Signal-groups design).
//!
//! Each member holds, per group, a **sender key**: a symmetric chain key that
//! ratchets forward once per message, plus an Ed25519 signing key. A member
//! distributes its sender key to the others *once*, over a pairwise
//! end-to-end envelope. Thereafter it encrypts each group
//! message **once** with its chain, signs it, and fans the ciphertext out; every
//! member who holds that sender key decrypts and verifies it.
//!
//! Properties and trade-offs (standard for sender keys):
//! - **Forward secrecy** within a sender's chain (the symmetric ratchet).
//! - **Authentication** of the true sender (the per-sender signature stops one
//!   member forging another's messages).
//! - **No post-compromise recovery**, and a membership change requires everyone
//!   to *rotate* their sender key (distribute a fresh one) — the trade-off for
//!   encrypting a group message only once instead of per-recipient.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::cipher::{aead_decrypt, aead_encrypt, kdf_ck};
use crate::error::Error;
use crate::platform::Platform;

/// Maximum number of skipped message keys retained per sender.
pub const MAX_SKIP: u32 = 1024;

/// One member's group message: whose it is, where in their chain, ciphertext,
/// and a signature that authenticates the true sender.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMessage {
    /// The sender's opaque id (e.g. their messaging public key).
    pub sender: Vec<u8>,
    /// The sender's chain position for this message.
    pub iteration: u32,
    /// AEAD ciphertext.
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature over `iteration || ciphertext`.
    pub signature: Vec<u8>,
}

/// What a member shares with the others so they can decrypt its messages.
///
/// Contains the current chain key, so it is a **secret** — distribute it only
/// over the pairwise end-to-end channel, never in the clear.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderKeyDistribution {
    /// Chain position the chain key is at.
    pub iteration: u32,
    /// The current chain key (secret — distribute only over E2E).
    pub chain_key: [u8; 32],
    /// The sender's group signing public key.
    pub signing_public: [u8; 32],
}

/// A member's own sender key: the chain it ratchets and the key it signs with.
struct SenderKey {
    chain_key: [u8; 32],
    iteration: u32,
    signing: SigningKey,
}

impl SenderKey {
    fn generate<P: Platform>(platform: &mut P) -> Self {
        let mut chain_key = [0u8; 32];
        let mut signing_seed = [0u8; 32];
        platform.fill_random(&mut chain_key);
        platform.fill_random(&mut signing_seed);
        let signing = SigningKey::from_bytes(&signing_seed);
        signing_seed.zeroize();
        SenderKey {
            chain_key,
            iteration: 0,
            signing,
        }
    }

    fn distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution {
            iteration: self.iteration,
            chain_key: self.chain_key,
            signing_public: self.signing.verifying_key().to_bytes(),
        }
    }

    fn encrypt(&mut self, sender: Vec<u8>, plaintext: &[u8], ad: &[u8]) -> GroupMessage {
        let (next, mk) = kdf_ck(&self.chain_key);
        let iteration = self.iteration;
        self.chain_key = next;
        self.iteration += 1;

        let ciphertext = aead_encrypt(&mk, plaintext, ad);
        let signature = self.signing.sign(&signed_bytes(iteration, &ciphertext));
        GroupMessage {
            sender,
            iteration,
            ciphertext,
            signature: signature.to_bytes().to_vec(),
        }
    }
}

impl Drop for SenderKey {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

/// The state needed to decrypt one sender's messages.
#[derive(Clone)]
struct ReceiverKey {
    chain_key: [u8; 32],
    iteration: u32,
    signing_public: VerifyingKey,
    skipped: Vec<(u32, [u8; 32])>,
}

impl ReceiverKey {
    fn from_distribution(dist: &SenderKeyDistribution) -> Result<Self, Error> {
        let signing_public =
            VerifyingKey::from_bytes(&dist.signing_public).map_err(|_| Error::Malformed)?;
        Ok(ReceiverKey {
            chain_key: dist.chain_key,
            iteration: dist.iteration,
            signing_public,
            skipped: Vec::new(),
        })
    }

    fn decrypt(&mut self, msg: &GroupMessage, ad: &[u8]) -> Result<Vec<u8>, Error> {
        // Authenticate the true sender before doing anything else.
        let signature = EdSignature::from_slice(&msg.signature).map_err(|_| Error::BadSignature)?;
        self.signing_public
            .verify_strict(&signed_bytes(msg.iteration, &msg.ciphertext), &signature)
            .map_err(|_| Error::BadSignature)?;

        // Advance/remove keys on a private copy and commit only after the AEAD
        // verifies. A valid message tried with the wrong associated data must
        // not consume the live chain key and desync the receiver.
        let mut next = self.clone();
        let mut mk = next.message_key(msg.iteration)?;
        let plaintext = aead_decrypt(&mk, &msg.ciphertext, ad)?;
        mk.zeroize();
        *self = next;
        Ok(plaintext)
    }

    /// The message key for `target`, ratcheting forward (and banking skipped
    /// keys) as needed.
    fn message_key(&mut self, target: u32) -> Result<[u8; 32], Error> {
        if let Some(pos) = self.skipped.iter().position(|(i, _)| *i == target) {
            return Ok(self.skipped.remove(pos).1);
        }
        if target < self.iteration {
            return Err(Error::DecryptFailed); // already consumed and not retained
        }
        if target - self.iteration > MAX_SKIP {
            return Err(Error::TooManySkipped);
        }
        while self.iteration < target {
            let (next, mk) = kdf_ck(&self.chain_key);
            self.bank_skipped(self.iteration, mk);
            self.chain_key = next;
            self.iteration += 1;
        }
        let (next, mk) = kdf_ck(&self.chain_key);
        self.chain_key = next;
        self.iteration += 1;
        Ok(mk)
    }

    /// Bank a skipped message key, capping the *total* retained set. `MAX_SKIP`
    /// bounds only the per-call gap; across many widely-spaced messages the set
    /// would otherwise grow (and persist) without bound. Evict the oldest key
    /// (zeroizing it) so the retained set can never exceed `MAX_SKIP`.
    fn bank_skipped(&mut self, iteration: u32, mk: [u8; 32]) {
        while self.skipped.len() >= MAX_SKIP as usize {
            let (_, mut oldest) = self.skipped.remove(0);
            oldest.zeroize();
        }
        self.skipped.push((iteration, mk));
    }
}

impl Drop for ReceiverKey {
    fn drop(&mut self) {
        self.chain_key.zeroize();
        for (_, mk) in &mut self.skipped {
            mk.zeroize();
        }
    }
}

/// A member's view of a group: its own sender key plus a receiver key per other
/// member. Encrypt once to send to everyone; decrypt by looking up the sender.
pub struct Group {
    own_id: Vec<u8>,
    own: SenderKey,
    members: BTreeMap<Vec<u8>, ReceiverKey>,
}

impl Group {
    /// Create a fresh group membership for `own_id` (an opaque member id).
    pub fn new<P: Platform>(platform: &mut P, own_id: Vec<u8>) -> Self {
        Group {
            own_id,
            own: SenderKey::generate(platform),
            members: BTreeMap::new(),
        }
    }

    /// Our own sender-key distribution, to hand to each other member over the
    /// pairwise end-to-end channel.
    pub fn distribution(&self) -> SenderKeyDistribution {
        self.own.distribution()
    }

    /// Accept another member's distribution so we can decrypt their messages.
    pub fn add_member(&mut self, id: Vec<u8>, dist: &SenderKeyDistribution) -> Result<(), Error> {
        self.members
            .insert(id, ReceiverKey::from_distribution(dist)?);
        Ok(())
    }

    /// Replace our sender key with a fresh one (re-key).
    ///
    /// Used on membership changes: after rotating, we distribute the new key to
    /// the remaining members, so a removed member — who still holds our *old*
    /// key — can no longer read what we send.
    pub fn rotate<P: Platform>(&mut self, platform: &mut P) {
        self.own = SenderKey::generate(platform);
    }

    /// Forget a member's sender key, so we no longer accept their messages.
    pub fn remove_member(&mut self, id: &[u8]) {
        self.members.remove(id);
    }

    /// Encrypt a message to the whole group (once).
    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> GroupMessage {
        self.own.encrypt(self.own_id.clone(), plaintext, ad)
    }

    /// Decrypt a group message from a known member.
    pub fn decrypt(&mut self, msg: &GroupMessage, ad: &[u8]) -> Result<Vec<u8>, Error> {
        let member = self.members.get_mut(&msg.sender).ok_or(Error::Malformed)?;
        member.decrypt(msg, ad)
    }
}

/// A serializable snapshot of a [`Group`], for persistence across sessions.
///
/// Contains secret key material (chain keys, the signing seed), so it must be
/// stored encrypted at rest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupState {
    own_id: Vec<u8>,
    own_chain: [u8; 32],
    own_iteration: u32,
    own_signing: [u8; 32],
    members: Vec<MemberState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MemberState {
    id: Vec<u8>,
    chain: [u8; 32],
    iteration: u32,
    signing_public: [u8; 32],
    skipped: Vec<(u32, [u8; 32])>,
}

impl Group {
    /// Snapshot the group's full secret state for persistence.
    pub fn export(&self) -> GroupState {
        GroupState {
            own_id: self.own_id.clone(),
            own_chain: self.own.chain_key,
            own_iteration: self.own.iteration,
            own_signing: self.own.signing.to_bytes(),
            members: self
                .members
                .iter()
                .map(|(id, rk)| MemberState {
                    id: id.clone(),
                    chain: rk.chain_key,
                    iteration: rk.iteration,
                    signing_public: rk.signing_public.to_bytes(),
                    skipped: rk.skipped.clone(),
                })
                .collect(),
        }
    }

    /// Restore a group from a [`GroupState`] snapshot.
    pub fn import(state: GroupState) -> Result<Self, Error> {
        let own = SenderKey {
            chain_key: state.own_chain,
            iteration: state.own_iteration,
            signing: SigningKey::from_bytes(&state.own_signing),
        };
        let mut members = BTreeMap::new();
        for m in state.members {
            let signing_public =
                VerifyingKey::from_bytes(&m.signing_public).map_err(|_| Error::Malformed)?;
            members.insert(
                m.id,
                ReceiverKey {
                    chain_key: m.chain,
                    iteration: m.iteration,
                    signing_public,
                    skipped: m.skipped,
                },
            );
        }
        Ok(Group {
            own_id: state.own_id,
            own,
            members,
        })
    }
}

/// The bytes a group message's signature covers.
fn signed_bytes(iteration: u32, ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + ciphertext.len());
    out.extend_from_slice(&iteration.to_be_bytes());
    out.extend_from_slice(ciphertext);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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

    const AD: &[u8] = b"group-42";

    /// Build a 3-member group where everyone has everyone else's sender key.
    fn three_members() -> (Group, Group, Group) {
        let mut a = Group::new(&mut SeededPlatform(1), b"alice".to_vec());
        let mut b = Group::new(&mut SeededPlatform(80), b"bob".to_vec());
        let mut c = Group::new(&mut SeededPlatform(160), b"carol".to_vec());

        let (da, db, dc) = (a.distribution(), b.distribution(), c.distribution());
        a.add_member(b"bob".to_vec(), &db).unwrap();
        a.add_member(b"carol".to_vec(), &dc).unwrap();
        b.add_member(b"alice".to_vec(), &da).unwrap();
        b.add_member(b"carol".to_vec(), &dc).unwrap();
        c.add_member(b"alice".to_vec(), &da).unwrap();
        c.add_member(b"bob".to_vec(), &db).unwrap();
        (a, b, c)
    }

    #[test]
    fn everyone_decrypts_a_group_message() {
        let (mut a, mut b, mut c) = three_members();
        let msg = a.encrypt(b"hello group", AD);
        assert_eq!(b.decrypt(&msg, AD).unwrap(), b"hello group");
        assert_eq!(c.decrypt(&msg, AD).unwrap(), b"hello group");
    }

    #[test]
    fn all_members_can_send() {
        let (mut a, mut b, mut c) = three_members();
        let from_b = b.encrypt(b"bob speaks", AD);
        assert_eq!(a.decrypt(&from_b, AD).unwrap(), b"bob speaks");
        assert_eq!(c.decrypt(&from_b, AD).unwrap(), b"bob speaks");

        let from_c = c.encrypt(b"carol too", AD);
        assert_eq!(a.decrypt(&from_c, AD).unwrap(), b"carol too");
        assert_eq!(b.decrypt(&from_c, AD).unwrap(), b"carol too");
    }

    #[test]
    fn out_of_order_within_a_sender_chain() {
        let (mut a, mut b, _c) = three_members();
        let m0 = a.encrypt(b"first", AD);
        let m1 = a.encrypt(b"second", AD);
        let m2 = a.encrypt(b"third", AD);
        // Deliver 2, 0, 1 out of order.
        assert_eq!(b.decrypt(&m2, AD).unwrap(), b"third");
        assert_eq!(b.decrypt(&m0, AD).unwrap(), b"first");
        assert_eq!(b.decrypt(&m1, AD).unwrap(), b"second");
    }

    #[test]
    fn a_non_member_cannot_decrypt() {
        let (mut a, _b, _c) = three_members();
        let msg = a.encrypt(b"secret", AD);
        // Mallory has no sender keys at all.
        let mut mallory = Group::new(&mut SeededPlatform(200), b"mallory".to_vec());
        assert!(mallory.decrypt(&msg, AD).is_err());
    }

    #[test]
    fn forged_signature_is_rejected() {
        let (mut a, mut b, _c) = three_members();
        let mut msg = a.encrypt(b"authentic", AD);
        msg.signature[0] ^= 0xff;
        assert!(
            b.decrypt(&msg, AD).is_err(),
            "a forged signature must not verify"
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut a, mut b, _c) = three_members();
        let mut msg = a.encrypt(b"authentic", AD);
        // Re-sign is impossible without alice's key, but even flipping ciphertext
        // must fail (signature covers it, and the AEAD tag too).
        msg.ciphertext[0] ^= 0xff;
        assert!(b.decrypt(&msg, AD).is_err());
    }

    #[test]
    fn wrong_ad_does_not_advance_receiver_chain() {
        let (mut a, mut b, _c) = three_members();
        let msg = a.encrypt(b"bound to group", AD);

        assert!(b.decrypt(&msg, b"wrong-group").is_err());
        assert_eq!(b.decrypt(&msg, AD).unwrap(), b"bound to group");
    }

    #[test]
    fn wrong_ad_on_skipped_message_does_not_consume_banked_key() {
        let (mut a, mut b, _c) = three_members();
        let m0 = a.encrypt(b"first", AD);
        let m1 = a.encrypt(b"second", AD);

        assert_eq!(b.decrypt(&m1, AD).unwrap(), b"second");
        assert!(b.decrypt(&m0, b"wrong-group").is_err());
        assert_eq!(b.decrypt(&m0, AD).unwrap(), b"first");
    }

    #[test]
    fn message_survives_wire_round_trip() {
        let (mut a, mut b, _c) = three_members();
        let msg = a.encrypt(b"over the wire", AD);
        let bytes = crate::wire::encode(&msg);
        let decoded: GroupMessage = crate::wire::decode(&bytes).unwrap();
        assert_eq!(b.decrypt(&decoded, AD).unwrap(), b"over the wire");
    }

    #[test]
    fn rotating_excludes_holders_of_the_old_key() {
        let (mut a, mut b, _c) = three_members();
        let m = a.encrypt(b"before", AD);
        assert_eq!(b.decrypt(&m, AD).unwrap(), b"before");

        // Alice re-keys. Bob still has her OLD key, so new messages fail...
        a.rotate(&mut SeededPlatform(240));
        let stale = a.encrypt(b"after rotate", AD);
        assert!(
            b.decrypt(&stale, AD).is_err(),
            "old key must not read new messages"
        );

        // ...until Bob learns the new key.
        b.add_member(b"alice".to_vec(), &a.distribution()).unwrap();
        let fresh = a.encrypt(b"after rekey", AD);
        assert_eq!(b.decrypt(&fresh, AD).unwrap(), b"after rekey");
    }

    #[test]
    fn removed_member_is_not_accepted() {
        let (mut a, mut b, _c) = three_members();
        a.remove_member(b"bob");
        let from_b = b.encrypt(b"still here?", AD);
        assert!(
            a.decrypt(&from_b, AD).is_err(),
            "a removed member must be rejected"
        );
    }

    /// A sender that transmits at widely spaced iterations makes the receiver
    /// bank a full window of skipped keys on each delivery. Without a total cap on
    /// `skipped`, this grows without bound (and is persisted). The set must stay
    /// bounded, while normal small-gap out-of-order delivery still decrypts.
    #[test]
    fn skipped_set_is_bounded() {
        let sender = SenderKey::generate(&mut SeededPlatform(1));
        let dist = sender.distribution();
        let mut receiver = ReceiverKey::from_distribution(&dist).unwrap();

        // Each call jumps the largest single-call gap (MAX_SKIP), banking a full
        // window. Across many calls the total must never exceed the bound.
        let mut target = 0u32;
        for _ in 0..8 {
            target += MAX_SKIP;
            let _ = receiver.message_key(target).unwrap();
            assert!(
                receiver.skipped.len() <= MAX_SKIP as usize,
                "skipped set grew past the bound: {}",
                receiver.skipped.len()
            );
        }

        // Normal small-gap out-of-order delivery must still decrypt.
        let (mut a, mut b, _c) = three_members();
        let m0 = a.encrypt(b"first", AD);
        let m1 = a.encrypt(b"second", AD);
        assert_eq!(b.decrypt(&m1, AD).unwrap(), b"second");
        assert_eq!(b.decrypt(&m0, AD).unwrap(), b"first");
    }

    #[test]
    fn group_survives_export_import() {
        let (mut a, mut b, _c) = three_members();

        // Advance a's chain a little, then round-trip its state through bytes.
        let _ = a.encrypt(b"one", AD);
        let state = a.export();
        let bytes = crate::wire::encode(&state);
        let restored: GroupState = crate::wire::decode(&bytes).unwrap();
        let mut a2 = Group::import(restored).unwrap();

        // The restored group continues the same chain and b can still decrypt.
        let msg = a2.encrypt(b"after restore", AD);
        assert_eq!(b.decrypt(&msg, AD).unwrap(), b"after restore");

        // And a2 can still decrypt from b (its receiver keys survived).
        let from_b = b.encrypt(b"reply", AD);
        assert_eq!(a2.decrypt(&from_b, AD).unwrap(), b"reply");
    }
}
