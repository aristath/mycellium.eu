//! The Full-tier [`Platform`]: OS entropy and the system clock.

use std::time::{SystemTime, UNIX_EPOCH};

use mycellium_core::platform::Platform;

/// A desktop/server platform backed by the OS CSPRNG and wall clock.
pub struct OsPlatform;

impl Platform for OsPlatform {
    fn fill_random(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("OS RNG must be available");
    }

    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}
