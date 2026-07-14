//! Out-of-band **verification** records: `user id → the wallet you confirmed`
//! matches its safety number.
//!
//! This is deliberately separate from the address book ([`crate::contacts`]):
//! a peer can be *pinned* on first use (TOFU) without you ever comparing a safety
//! number, and comparing it out of band is a stronger, explicit act. Keeping the
//! "I verified this" record apart from "I have a contact for this" lets the UI
//! show three honest states — unverified, pinned, verified — and flag a wallet
//! that no longer matches the stable user id's pinned wallet.

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

fn key(user_id: &str) -> Vec<u8> {
    let mut k = b"verified:".to_vec();
    k.extend_from_slice(user_id.as_bytes());
    k
}

/// Record that `user_id` was verified out of band as owning `wallet`.
pub fn mark<S: Storage>(
    store: &mut S,
    user_id: &str,
    wallet: &WalletPublicKey,
) -> anyhow::Result<()>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    store.put(&key(user_id), &wire::encode(wallet))?;
    Ok(())
}

/// The wallet last verified for `user_id`, if any.
pub fn get<S: Storage>(store: &S, user_id: &str) -> anyhow::Result<Option<WalletPublicKey>>
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    crate::load_state(store.get(&key(user_id))?, "verification record")
}

/// Classify how much `current` (the wallet just looked up for `user_id`) is
/// trusted, given the out-of-band verification record and the address-book pin.
pub fn level<S: Storage>(store: &S, user_id: &str, current: &WalletPublicKey) -> TrustLevel
where
    S::Error: std::error::Error + Send + Sync + 'static,
{
    // An explicit out-of-band verification is the strongest signal.
    match get(store, user_id) {
        Ok(Some(v)) => {
            return if &v == current {
                TrustLevel::Verified
            } else {
                TrustLevel::Changed
            };
        }
        // A damaged verification pin must never downgrade to first-contact
        // trust. Treat it exactly like a changed identity until repaired.
        Err(_) => return TrustLevel::Changed,
        Ok(None) => {}
    }
    // Else fall back to the TOFU pin held in the address book, if any.
    match crate::contacts::by_user_id(store, user_id) {
        Ok(Some(c)) => {
            return if &c.wallet == current {
                TrustLevel::Pinned
            } else {
                TrustLevel::Changed
            };
        }
        Err(_) => return TrustLevel::Changed,
        Ok(None) => {}
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
        let user_id = "a".repeat(64);

        // Nobody known → unverified first contact.
        assert_eq!(level(&s, &user_id, &w(1)), TrustLevel::Unverified);

        // Pin bob via a contact (TOFU) → pinned, and a different wallet → changed.
        crate::contacts::save(
            &mut s,
            &crate::contacts::Contact {
                nickname: "bob".into(),
                handle: "bob".into(),
                user_id: user_id.clone(),
                wallet: w(1),
            },
        )
        .unwrap();
        assert_eq!(level(&s, &user_id, &w(1)), TrustLevel::Pinned);
        assert_eq!(level(&s, &user_id, &w(2)), TrustLevel::Changed);

        // Verify bob out of band → verified; a later different wallet → changed.
        mark(&mut s, &user_id, &w(1)).unwrap();
        assert_eq!(level(&s, &user_id, &w(1)), TrustLevel::Verified);
        assert_eq!(level(&s, &user_id, &w(2)), TrustLevel::Changed);
    }

    #[test]
    fn corrupt_verification_pin_fails_closed_as_changed_identity() {
        let mut store = Mem::default();
        let user_id = "a".repeat(64);
        store
            .put(&key(&user_id), b"corrupt verification pin")
            .unwrap();
        assert!(get(&store, &user_id).is_err());
        assert_eq!(level(&store, &user_id, &w(1)), TrustLevel::Changed);
        assert_eq!(
            store.get(&key(&user_id)).unwrap().as_deref(),
            Some(&b"corrupt verification pin"[..])
        );
    }
}
