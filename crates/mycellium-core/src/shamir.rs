//! Social recovery via Shamir Secret Sharing (Layer 9, recovery factors).
//!
//! Split a secret (e.g. the seed phrase) into `n` shares such that any `t` of
//! them reconstruct it, and fewer than `t` reveal nothing. Give the shares to
//! trusted guardians; losing your device no longer means losing your identity,
//! and no single guardian can impersonate you.
//!
//! Standard SSS over GF(2^8) (the AES field), evaluating one random polynomial
//! per secret byte. `no_std`, constant-field arithmetic, no external crate.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::platform::Platform;

/// One guardian's share: a non-zero x-coordinate and the y-values (one per
/// secret byte) of the sharing polynomials evaluated at that x.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    /// The share's index (x-coordinate), in `1..=n`.
    pub index: u8,
    /// Polynomial evaluations, one per secret byte.
    pub body: Vec<u8>,
}

/// Split `secret` into `shares` shares, any `threshold` of which recover it.
pub fn split<P: Platform>(
    secret: &[u8],
    threshold: u8,
    shares: u8,
    platform: &mut P,
) -> Result<Vec<Share>, Error> {
    if threshold == 0 || shares < threshold || secret.is_empty() {
        return Err(Error::Malformed);
    }

    let mut out: Vec<Share> = (1..=shares)
        .map(|index| Share {
            index,
            body: Vec::with_capacity(secret.len()),
        })
        .collect();

    let mut coeffs = alloc::vec![0u8; threshold as usize];
    for &byte in secret {
        // Constant term is the secret byte; higher coefficients are random.
        coeffs[0] = byte;
        if threshold > 1 {
            platform.fill_random(&mut coeffs[1..]);
        }
        for share in out.iter_mut() {
            share.body.push(eval(&coeffs, share.index));
        }
    }
    Ok(out)
}

/// Reconstruct the secret from `shares` (must be `>= threshold` distinct shares).
pub fn combine(shares: &[Share]) -> Result<Vec<u8>, Error> {
    if shares.is_empty() {
        return Err(Error::Malformed);
    }
    let len = shares[0].body.len();
    if shares.iter().any(|s| s.index == 0 || s.body.len() != len) {
        return Err(Error::Malformed);
    }
    // Indices must be distinct, or Lagrange interpolation divides by zero.
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].index == shares[j].index {
                return Err(Error::Malformed);
            }
        }
    }

    let mut secret = Vec::with_capacity(len);
    for pos in 0..len {
        let mut acc = 0u8;
        for (i, si) in shares.iter().enumerate() {
            // Lagrange basis for share i, evaluated at x = 0.
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, sj) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                num = mul(num, sj.index); // (0 - x_j) == x_j in GF(2^8)
                den = mul(den, si.index ^ sj.index); // (x_i - x_j) == x_i ^ x_j
            }
            let basis = mul(num, inv(den));
            acc ^= mul(si.body[pos], basis);
        }
        secret.push(acc);
    }
    Ok(secret)
}

/// Evaluate a polynomial (given by coefficients, low-order first) at `x`.
fn eval(coeffs: &[u8], x: u8) -> u8 {
    let mut acc = 0u8;
    for &c in coeffs.iter().rev() {
        acc = mul(acc, x) ^ c;
    }
    acc
}

/// Multiply in GF(2^8) with the AES reduction polynomial (0x11b).
fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

/// Multiplicative inverse in GF(2^8): `a^254` (Fermat).
fn inv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u32;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mul(result, base);
        }
        base = mul(base, base);
        exp >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Platform;

    struct SeededPlatform(u8);
    impl Platform for SeededPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(31);
            }
        }
        fn now_unix_secs(&self) -> u64 {
            0
        }
    }

    const SECRET: &[u8] = b"twelve word seed phrase goes right here";

    #[test]
    fn any_threshold_subset_recovers() {
        let mut p = SeededPlatform(1);
        let shares = split(SECRET, 2, 3, &mut p).unwrap();

        // Every 2-of-3 combination reconstructs the secret.
        assert_eq!(
            combine(&[shares[0].clone(), shares[1].clone()]).unwrap(),
            SECRET
        );
        assert_eq!(
            combine(&[shares[0].clone(), shares[2].clone()]).unwrap(),
            SECRET
        );
        assert_eq!(
            combine(&[shares[1].clone(), shares[2].clone()]).unwrap(),
            SECRET
        );
        // All three also work.
        assert_eq!(combine(&shares).unwrap(), SECRET);
    }

    #[test]
    fn fewer_than_threshold_does_not_recover() {
        let mut p = SeededPlatform(5);
        let shares = split(SECRET, 3, 5, &mut p).unwrap();
        // Two shares when three are required must not yield the secret.
        let got = combine(&[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_ne!(got, SECRET);
    }

    #[test]
    fn rejects_bad_parameters() {
        let mut p = SeededPlatform(1);
        assert!(split(SECRET, 0, 3, &mut p).is_err());
        assert!(split(SECRET, 4, 3, &mut p).is_err()); // threshold > shares
        assert!(split(b"", 2, 3, &mut p).is_err());
        assert!(combine(&[]).is_err());

        let dup = Share {
            index: 1,
            body: alloc::vec![1, 2],
        };
        assert!(combine(&[dup.clone(), dup]).is_err()); // duplicate indices
    }

    #[test]
    fn field_inverse_is_correct() {
        for a in 1u8..=255 {
            assert_eq!(mul(a, inv(a)), 1, "inverse of {a}");
        }
    }
}
