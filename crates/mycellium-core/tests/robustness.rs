//! Adversarial / negative-path tests.
//!
//! Untrusted bytes arrive from the network and get decoded into wire types,
//! then verified or decrypted. These tests hammer those paths with garbage,
//! truncation, and bit-flips, asserting the code always **errors gracefully**
//! (never panics, never over-allocates) and **never accepts tampered data**.

use mycellium_core::identity::{Handle, Identity, PeerId};
use mycellium_core::offline::Envelope;
use mycellium_core::platform::Platform;
use mycellium_core::ratchet::{Ratchet, RatchetMessage};
use mycellium_core::record::{Device, Record, SignedPreKey, SignedRecord};
use mycellium_core::wire;
use mycellium_core::x3dh::{self, HandshakeInit};

/// Deterministic xorshift PRNG — reproducible fuzz input, no dependencies.
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

/// A single continuously-advancing (INSECURE) entropy source for tests.
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

fn valid_signed_record(p: &mut SeededPlatform) -> SignedRecord {
    let id = Identity::generate(p).unwrap();
    let record = Record {
        handle: Handle::new("ari").unwrap(),
        wallet: id.wallet_public(),
        devices: vec![Device {
            device_key: id.device_public(),
            peer_id: PeerId(vec![1, 2, 3, 4]),
            id_key: id.messaging_public(),
            signed_pre_key: SignedPreKey::create(id.signed_pre_key_public(), &id),
        }],
        seq: 1,
    };
    SignedRecord::sign(record, &id)
}

const AD: &[u8] = b"a|b";

/// Establish two ratchets sharing an X3DH secret.
fn established(p: &mut SeededPlatform) -> (Ratchet, Ratchet) {
    let alice = Identity::generate(p).unwrap();
    let bob = Identity::generate(p).unwrap();
    let initiated = x3dh::initiate(p, &alice, &bob.messaging_public(), &bob.signed_pre_key_public());
    let bob_sk = x3dh::respond(&bob, &initiated.init);
    let a = Ratchet::new_initiator(p, &initiated.shared_secret, &bob.signed_pre_key_public());
    let b = Ratchet::new_responder(&bob_sk, &bob);
    (a, b)
}

#[test]
fn decoding_garbage_never_panics() {
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for _ in 0..30_000 {
        let len = (rng.next() % 512) as usize;
        let mut bytes = rng.bytes(len);
        // Half the time, prefix the valid version byte to reach the body decoder.
        if rng.next() & 1 == 0 {
            bytes.insert(0, wire::VERSION);
        }
        // Every decoder must return Result, never unwind or abort.
        let _ = wire::decode::<SignedRecord>(&bytes);
        let _ = wire::decode::<Record>(&bytes);
        let _ = wire::decode::<RatchetMessage>(&bytes);
        let _ = wire::decode::<HandshakeInit>(&bytes);
        let _ = wire::decode::<Envelope>(&bytes);
    }
}

#[test]
fn truncated_encodings_never_panic() {
    let mut p = SeededPlatform(1);
    let record = valid_signed_record(&mut p);
    let (mut alice, _bob) = established(&mut p);
    let msg = alice.encrypt(b"hello", AD);

    for full in [wire::encode(&record), wire::encode(&msg)] {
        for len in 0..=full.len() {
            let slice = &full[..len];
            let _ = wire::decode::<SignedRecord>(slice);
            let _ = wire::decode::<RatchetMessage>(slice);
            let _ = wire::decode::<Envelope>(slice);
        }
    }
}

#[test]
fn tampered_records_never_verify() {
    let mut p = SeededPlatform(1);
    let record = valid_signed_record(&mut p);
    let full = wire::encode(&record);

    for byte in 0..full.len() {
        for bit in 0..8 {
            let mut tampered = full.clone();
            tampered[byte] ^= 1 << bit;
            // If a tampered encoding still decodes, it must NOT verify.
            if let Ok(decoded) = wire::decode::<SignedRecord>(&tampered) {
                assert!(
                    decoded.verify().is_err(),
                    "a tampered record verified (byte {byte}, bit {bit})",
                );
            }
        }
    }
}

#[test]
fn ratchet_rejects_replays() {
    let mut p = SeededPlatform(1);
    let (mut alice, mut bob) = established(&mut p);

    let msg = alice.encrypt(b"exactly once", AD);
    assert_eq!(bob.decrypt(&mut p, &msg, AD).unwrap(), b"exactly once");
    // Replaying the same message must fail (its key was consumed).
    assert!(bob.decrypt(&mut p, &msg, AD).is_err(), "replay was accepted");
}

#[test]
fn ratchet_enforces_skip_limit_without_panicking() {
    let mut p = SeededPlatform(1);
    let (mut alice, mut bob) = established(&mut p);

    // Skip far more than MAX_SKIP messages, then deliver a distant one.
    let mut last = alice.encrypt(b"m", AD);
    for _ in 0..400 {
        last = alice.encrypt(b"m", AD);
    }
    // Bob has seen none of the earlier ones; the gap exceeds the skip limit.
    let result = bob.decrypt(&mut p, &last, AD);
    assert!(result.is_err(), "an unbounded skip gap should be rejected");
}
