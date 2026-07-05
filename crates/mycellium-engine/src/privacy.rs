//! Privacy modes for **queued** delivery: the delay/batching knobs from
//! [`docs/PRIVACY-MODES.md`](../../../docs/PRIVACY-MODES.md).
//!
//! These tune *when* an item is deposited into the recipient's untrusted queue,
//! so a burst of sends doesn't produce a burst of same-timed deposits an
//! observer can correlate. They apply only to the store-and-forward (queue)
//! path — live P2P delivery is never delayed. See the design doc for what these
//! do and, importantly, do *not* do (they are not anonymity).

use mycellium_core::platform::Platform;

/// How aggressively to delay + batch a queued deposit.
///
/// The variants map 1:1 to the modes in `docs/PRIVACY-MODES.md`. The engine
/// carries the mode as a delivery parameter; mode *selection* (global default,
/// per-contact pin, per-message override) is client-side (#67–#72).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PrivacyMode {
    /// Immediate deposit, lowest latency. Delay is always `0`.
    #[default]
    Normal,
    /// Randomized short delay (0–30 s), batched.
    Private,
    /// Randomized minutes-scale delay (2–10 min), batched aggressively.
    HighRisk,
}

impl PrivacyMode {
    /// A randomized delivery delay, in seconds, drawn *uniformly within* this
    /// mode's window from the host CSPRNG (`platform.fill_random`):
    ///
    /// - `Normal`   → `0` (immediate),
    /// - `Private`  → uniform in `0..=30`,
    /// - `HighRisk` → uniform in `120..=600`.
    ///
    /// The randomization is deliberately *within* the window rather than a
    /// fixed offset: a fixed offset merely shifts the correlatable spike in
    /// time (a burst of N sends still lands as N same-timed deposits), whereas
    /// an independent per-item draw spreads the burst across the window and
    /// lets the outbox coalesce whatever falls due together.
    ///
    /// Entropy comes from [`Platform::fill_random`] — never `rand` or a
    /// wall-clock reading — because the core forbids ambient randomness/time.
    pub fn delivery_delay<P: Platform>(self, platform: &mut P) -> u64 {
        let (lo, hi) = match self {
            PrivacyMode::Normal => return 0,
            PrivacyMode::Private => (0u64, 30u64),
            PrivacyMode::HighRisk => (120u64, 600u64),
        };
        let mut buf = [0u8; 8];
        platform.fill_random(&mut buf);
        // Uniform in [lo, hi]. The modulo bias is negligible: the window spans a
        // few hundred values against a 2^64 draw.
        let span = hi - lo + 1;
        lo + u64::from_le_bytes(buf) % span
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic CSPRNG stand-in: each `fill_random` yields the next value
    /// from a supplied sequence, little-endian. Lets us pin exact draws.
    struct SeqPlatform {
        values: Vec<u64>,
        idx: usize,
    }
    impl Platform for SeqPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            let v = self.values[self.idx % self.values.len()];
            self.idx += 1;
            let bytes = v.to_le_bytes();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = bytes[i % 8];
            }
        }
        fn now_unix_secs(&self) -> u64 {
            0
        }
    }

    /// A counter-based platform: successive draws are 0,1,2,3,… so we can sweep
    /// the whole window and check the bounds are inclusive on both ends.
    struct CounterPlatform(u64);
    impl Platform for CounterPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            let bytes = self.0.to_le_bytes();
            let n = bytes.len().min(buf.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            self.0 += 1;
        }
        fn now_unix_secs(&self) -> u64 {
            0
        }
    }

    #[test]
    fn normal_is_always_immediate() {
        let mut p = SeqPlatform {
            values: vec![u64::MAX, 12345, 0],
            idx: 0,
        };
        for _ in 0..100 {
            assert_eq!(PrivacyMode::Normal.delivery_delay(&mut p), 0);
        }
    }

    #[test]
    fn private_lands_in_window() {
        let mut p = CounterPlatform(0);
        for _ in 0..10_000 {
            let d = PrivacyMode::Private.delivery_delay(&mut p);
            assert!(d <= 30, "private delay {d} out of 0..=30");
        }
    }

    #[test]
    fn high_risk_lands_in_window() {
        let mut p = CounterPlatform(0);
        for _ in 0..10_000 {
            let d = PrivacyMode::HighRisk.delivery_delay(&mut p);
            assert!(
                (120..=600).contains(&d),
                "high-risk delay {d} out of 120..=600"
            );
        }
    }

    #[test]
    fn windows_reach_both_bounds() {
        // Sweeping consecutive draws 0..span-1 must hit the min and the max.
        let mut p = CounterPlatform(0);
        let mut lo_hit = false;
        let mut hi_hit = false;
        for _ in 0..31 {
            match PrivacyMode::Private.delivery_delay(&mut p) {
                0 => lo_hit = true,
                30 => hi_hit = true,
                _ => {}
            }
        }
        assert!(lo_hit && hi_hit, "private window did not reach both bounds");

        let mut p = CounterPlatform(0);
        let mut lo_hit = false;
        let mut hi_hit = false;
        for _ in 0..481 {
            match PrivacyMode::HighRisk.delivery_delay(&mut p) {
                120 => lo_hit = true,
                600 => hi_hit = true,
                _ => {}
            }
        }
        assert!(
            lo_hit && hi_hit,
            "high-risk window did not reach both bounds"
        );
    }
}
