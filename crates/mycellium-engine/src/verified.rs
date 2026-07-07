//! Out-of-band **verification** records: `handle → the wallet you confirmed`
//! matches its safety number.
//!
//! This is deliberately separate from the address book ([`crate::contacts`]):
//! a peer can be *pinned* on first use (TOFU) without you ever comparing a safety
//! number, and comparing it out of band is a stronger, explicit act. Keeping the
//! "I verified this" record apart from "I have a contact for this" lets the UI
//! show three honest states — unverified, pinned, verified — and flag a wallet
//! that has *changed* since either (issue #57).

use serde::{Deserialize, Serialize};

use mycellium_core::identity::WalletPublicKey;
use mycellium_core::storage::Storage;
use mycellium_core::wire;

/// How much we trust that a peer's current wallet is really theirs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Confirmed out of band — you compared the safety number and it matched.
    Verified,
    /// Pinned on first use (TOFU), but not yet out-of-band verified.
    Pinned,
    /// A wallet was pinned/verified before, but the current one **differs** —
    /// a new account, or an impersonation attempt. Treat with suspicion.
    Changed,
    /// Never pinned or verified — a first, unverified contact.
    Unverified,
}

impl TrustLevel {
    /// A short, glanceable label for CLI/TUI output.
    pub fn label(self) -> &'static str {
        match self {
            TrustLevel::Verified => "✓ verified",
            TrustLevel::Pinned => "• pinned (TOFU, not verified)",
            TrustLevel::Changed => "⚠ IDENTITY CHANGED",
            TrustLevel::Unverified => "? unverified (first contact)",
        }
    }
}

fn key(handle: &str) -> Vec<u8> {
    let mut k = b"verified:".to_vec();
    k.extend_from_slice(handle.as_bytes());
    k
}

/// Record that `handle` was verified out of band as owning `wallet`.
pub fn mark<S: Storage>(
    store: &mut S,
    handle: &str,
    wallet: &WalletPublicKey,
) -> Result<(), S::Error> {
    store.put(&key(handle), &wire::encode(wallet))
}

/// The wallet last verified for `handle`, if any.
pub fn get<S: Storage>(store: &S, handle: &str) -> Result<Option<WalletPublicKey>, S::Error> {
    Ok(crate::load_opt(
        store.get(&key(handle))?,
        "verification record",
    ))
}

/// Classify how much `current` (the wallet just looked up for `handle`) is
/// trusted, given the out-of-band verification record and the address-book pin.
pub fn level<S: Storage>(store: &S, handle: &str, current: &WalletPublicKey) -> TrustLevel {
    // An explicit out-of-band verification is the strongest signal.
    if let Ok(Some(v)) = get(store, handle) {
        return if &v == current {
            TrustLevel::Verified
        } else {
            TrustLevel::Changed
        };
    }
    // Else fall back to the TOFU pin held in the address book, if any.
    if let Ok(Some(c)) = crate::contacts::by_handle(store, handle) {
        return if &c.wallet == current {
            TrustLevel::Pinned
        } else {
            TrustLevel::Changed
        };
    }
    TrustLevel::Unverified
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::convert::Infallible;

    #[derive(Default)]
    struct Mem(HashMap<Vec<u8>, Vec<u8>>);
    impl Storage for Mem {
        type Error = Infallible;
        fn get(&self, k: &[u8]) -> Result<Option<Vec<u8>>, Infallible> {
            Ok(self.0.get(k).cloned())
        }
        fn put(&mut self, k: &[u8], v: &[u8]) -> Result<(), Infallible> {
            self.0.insert(k.to_vec(), v.to_vec());
            Ok(())
        }
        fn delete(&mut self, k: &[u8]) -> Result<(), Infallible> {
            self.0.remove(k);
            Ok(())
        }
    }

    fn w(b: u8) -> WalletPublicKey {
        WalletPublicKey([b; 33])
    }

    #[test]
    fn trust_levels_reflect_pin_and_verification() {
        let mut s = Mem::default();
        // Nobody known → unverified first contact.
        assert_eq!(level(&s, "bob", &w(1)), TrustLevel::Unverified);

        // Pin bob via a contact (TOFU) → pinned, and a different wallet → changed.
        crate::contacts::save(
            &mut s,
            &crate::contacts::Contact {
                nickname: "bob".into(),
                handle: "bob".into(),
                wallet: w(1),
            },
        )
        .unwrap();
        assert_eq!(level(&s, "bob", &w(1)), TrustLevel::Pinned);
        assert_eq!(level(&s, "bob", &w(2)), TrustLevel::Changed);

        // Verify bob out of band → verified; a later different wallet → changed.
        mark(&mut s, "bob", &w(1)).unwrap();
        assert_eq!(level(&s, "bob", &w(1)), TrustLevel::Verified);
        assert_eq!(level(&s, "bob", &w(2)), TrustLevel::Changed);
    }
}
