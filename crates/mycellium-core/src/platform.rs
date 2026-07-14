//! The **Platform** capability: secure randomness and the clock.
//!
//! The two things a portable crypto core cannot invent for itself. Rich hosts
//! use the OS CSPRNG and system clock; embedded hosts a hardware RNG and a
//! monotonic timer.

/// Host-supplied entropy and time.
pub trait Platform {
    /// Fill `buf` with cryptographically secure random bytes.
    ///
    /// This MUST come from a CSPRNG. Everything from seed generation to
    /// ephemeral handshake keys depends on it; a weak source breaks the whole
    /// protocol.
    fn fill_random(&mut self, buf: &mut [u8]);

    /// Current wall-clock time in whole seconds since the Unix epoch.
    ///
    /// Used for record freshness and session bookkeeping, not as a security
    /// boundary (anti-rollback rests on `seq`, not the clock).
    fn now_unix_secs(&self) -> u64;
}
