//! Randomized model tests: correctness properties over a large valid input
//! space, not just hand-picked cases.
//!
//! - The Double Ratchet decrypts correctly under many random interleavings of
//!   two-way traffic (in-order delivery per direction).
//! - Shamir sharing round-trips for random thresholds, secrets, and subsets.

use std::collections::VecDeque;

use mycellium_core::identity::Identity;
use mycellium_core::platform::Platform;
use mycellium_core::ratchet::{Ratchet, RatchetMessage};
use mycellium_core::shamir::{self, Share};
use mycellium_core::x3dh;

/// Deterministic xorshift PRNG.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() & 0xff) as u8).collect()
    }
}

/// A non-repeating entropy source, so generated keys never collide.
struct RngPlatform(Rng);
impl Platform for RngPlatform {
    fn fill_random(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = (self.0.next() & 0xff) as u8;
        }
    }
    fn now_unix_secs(&self) -> u64 {
        0
    }
}

const AD: &[u8] = b"a|b";

fn established(p: &mut RngPlatform) -> (Ratchet, Ratchet) {
    let alice = Identity::generate(p).unwrap();
    let bob = Identity::generate(p).unwrap();
    let initiated = x3dh::initiate(p, &alice, &bob.messaging_public(), &bob.signed_pre_key_public());
    let bob_sk = x3dh::respond(&bob, &initiated.init);
    let a = Ratchet::new_initiator(p, &initiated.shared_secret, &bob.signed_pre_key_public());
    let b = Ratchet::new_responder(&bob_sk, &bob);
    (a, b)
}

#[test]
fn ratchet_correct_under_random_interleavings() {
    for seed in 0..80u64 {
        let mut p = RngPlatform(Rng(seed.wrapping_mul(0x9e3779b97f4a7c15) | 1));
        let (mut alice, mut bob) = established(&mut p);
        let mut rng = Rng(seed.wrapping_mul(0xd1b54a32d192ed03) | 1);

        // In-flight messages per direction, delivered front-to-back (in order).
        let mut to_bob: VecDeque<(Vec<u8>, RatchetMessage)> = VecDeque::new();
        let mut to_alice: VecDeque<(Vec<u8>, RatchetMessage)> = VecDeque::new();
        let mut bob_can_send = false; // responder can only send after receiving
        let mut counter = 0u32;

        for _ in 0..32 {
            match rng.next() % 4 {
                0 => {
                    let pt = format!("a{counter}").into_bytes();
                    counter += 1;
                    let ct = alice.encrypt(&pt, AD);
                    to_bob.push_back((pt, ct));
                }
                1 if bob_can_send => {
                    let pt = format!("b{counter}").into_bytes();
                    counter += 1;
                    let ct = bob.encrypt(&pt, AD);
                    to_alice.push_back((pt, ct));
                }
                2 => {
                    if let Some((pt, ct)) = to_bob.pop_front() {
                        assert_eq!(bob.decrypt(&mut p, &ct, AD).unwrap(), pt, "seed {seed}");
                        bob_can_send = true;
                    }
                }
                _ => {
                    if let Some((pt, ct)) = to_alice.pop_front() {
                        assert_eq!(alice.decrypt(&mut p, &ct, AD).unwrap(), pt, "seed {seed}");
                    }
                }
            }
        }

        // Drain whatever is left, still in order.
        while let Some((pt, ct)) = to_bob.pop_front() {
            assert_eq!(bob.decrypt(&mut p, &ct, AD).unwrap(), pt, "drain bob, seed {seed}");
        }
        while let Some((pt, ct)) = to_alice.pop_front() {
            assert_eq!(alice.decrypt(&mut p, &ct, AD).unwrap(), pt, "drain alice, seed {seed}");
        }
    }
}

#[test]
fn shamir_random_thresholds_round_trip() {
    let mut meta = Rng(0xabcd_ef01_2345_6789);
    for _ in 0..400 {
        let n = (meta.next() % 8 + 2) as u8; // 2..=9 shares
        let t = (meta.next() % n as u64 + 1) as u8; // 1..=n threshold
        let secret_len = (meta.next() % 40 + 1) as usize;
        let secret = meta.bytes(secret_len);

        let mut plat = RngPlatform(Rng(meta.next() | 1));
        let shares = shamir::split(&secret, t, n, &mut plat).unwrap();
        assert_eq!(shares.len(), n as usize);

        // A random t-subset must reconstruct the secret.
        let mut order: Vec<usize> = (0..shares.len()).collect();
        for i in (1..order.len()).rev() {
            let j = (meta.next() as usize) % (i + 1);
            order.swap(i, j);
        }
        let subset: Vec<Share> = order[..t as usize].iter().map(|&i| shares[i].clone()).collect();
        assert_eq!(shamir::combine(&subset).unwrap(), secret, "t={t} n={n}");
    }
}
