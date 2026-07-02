//! Out-of-band verification — the "safety number" (Layer 5 trust hardening).
//!
//! The directory tells you *who* a handle is; normally you trust it. To close
//! even that gap, two peers compare a short code derived from **both their
//! wallet identity keys**. It's the same on both devices (the inputs are sorted,
//! so it's independent of who computes it), and it changes completely if either
//! identity differs from what you expect. Read it aloud or scan it in person:
//! codes match → the directory told the truth; codes differ → someone is in the
//! middle.

use alloc::string::String;

use sha2::{Digest, Sha512};

use crate::identity::WalletPublicKey;

/// Number of 5-digit groups in a safety number.
const GROUPS: usize = 6;

/// Compute the safety number for a pair of identities.
///
/// Order-independent: `safety_number(a, b) == safety_number(b, a)`.
pub fn safety_number(a: &WalletPublicKey, b: &WalletPublicKey) -> String {
    // Sort the two keys so both peers hash the same input.
    let (lo, hi) = if a.0 <= b.0 { (a, b) } else { (b, a) };

    let mut hasher = Sha512::new();
    hasher.update(b"messe-safety-number-v1");
    hasher.update(lo.0);
    hasher.update(hi.0);
    let digest = hasher.finalize();

    let mut out = String::with_capacity(GROUPS * 6);
    for i in 0..GROUPS {
        let chunk = &digest[i * 5..i * 5 + 5];
        let mut value: u64 = 0;
        for &byte in chunk {
            value = (value << 8) | byte as u64;
        }
        if i > 0 {
            out.push(' ');
        }
        push_5(&mut out, (value % 100_000) as u32);
    }
    out
}

/// Append `value` as exactly five decimal digits, zero-padded.
fn push_5(out: &mut String, mut value: u32) {
    let mut digits = [0u8; 5];
    for slot in digits.iter_mut().rev() {
        *slot = b'0' + (value % 10) as u8;
        value /= 10;
    }
    for d in digits {
        out.push(d as char);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wallet(byte: u8) -> WalletPublicKey {
        WalletPublicKey([byte; 33])
    }

    #[test]
    fn is_order_independent() {
        let a = wallet(1);
        let b = wallet(2);
        assert_eq!(safety_number(&a, &b), safety_number(&b, &a));
    }

    #[test]
    fn differs_for_different_identities() {
        let a = wallet(1);
        let b = wallet(2);
        let c = wallet(3);
        assert_ne!(safety_number(&a, &b), safety_number(&a, &c));
    }

    #[test]
    fn has_the_expected_shape() {
        let sn = safety_number(&wallet(1), &wallet(2));
        let groups: Vec<&str> = sn.split(' ').collect();
        assert_eq!(groups.len(), GROUPS);
        assert!(groups.iter().all(|g| g.len() == 5 && g.bytes().all(|b| b.is_ascii_digit())));
    }
}
