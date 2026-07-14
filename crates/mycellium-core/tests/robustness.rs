//! Adversarial / negative-path tests.
//!
//! Untrusted bytes arrive from the network and get decoded into wire types,
//! then verified or decrypted. These tests hammer those paths with garbage,
//! truncation, and bit-flips, asserting the code always **errors gracefully**
//! (never panics, never over-allocates) and **never accepts tampered data**.

use mycellium_core::identity::{Handle, Identity};
use mycellium_core::offline::Envelope;
use mycellium_core::one_shot::OneShotMessage;
use mycellium_core::platform::Platform;
use mycellium_core::record::{Device, Record, SignedRecord};
use mycellium_core::userid::user_id;
use mycellium_core::wire;
use mycellium_core::x3dh::HandshakeInit;

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
        user_id: user_id(&id.wallet_public()),
        handle: Handle::new("ari").unwrap(),
        name: String::new(),
        wallet: id.wallet_public(),
        device: Device::create(&id, 1),
        seq: 1,
    };
    SignedRecord::sign(record, &id)
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
        let _ = wire::decode::<OneShotMessage>(&bytes);
        let _ = wire::decode::<HandshakeInit>(&bytes);
        let _ = wire::decode::<Envelope>(&bytes);
    }
}

#[test]
fn truncated_encodings_never_panic() {
    let mut p = SeededPlatform(1);
    let record = valid_signed_record(&mut p);
    let msg = OneShotMessage::X3dhChaCha20Poly1305V1 {
        ciphertext: vec![1, 2, 3, 4],
    };

    for full in [wire::encode(&record), wire::encode(&msg)] {
        for len in 0..=full.len() {
            let slice = &full[..len];
            let _ = wire::decode::<SignedRecord>(slice);
            let _ = wire::decode::<OneShotMessage>(slice);
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
