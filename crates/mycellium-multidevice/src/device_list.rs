//! The **device list**: the account-layer artifact that maps one stable account
//! identity to the set of device pubkeys that belong to it.
//!
//! A device list is a single, signed, *replaceable* Nostr event published under
//! the **account** key (kind [`KIND_DEVICE_LIST`], addressable via a fixed `d`
//! tag — see [`crate::DEVICE_LIST_IDENTIFIER`]). Signing it with the account key
//! is exactly the authorization step: the account key is what *decides* which
//! devices are members of the account, so only the holder of that key can add or
//! remove a device from the list. Everyone else fetches and verifies it.
//!
//! The event's content is the JSON below; the `p` tags mirror the device pubkeys
//! so a relay can index "which accounts list device X" without parsing content.

use nostr::{PublicKey, Timestamp};
use serde::{Deserialize, Serialize};

/// One device belonging to an account.
///
/// The `pubkey` is the device's own Nostr identity — the key its MLS leaf and
/// KeyPackage (kind:30443) are bound to. It is *not* the account key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntry {
    /// The device's Nostr public key (its MLS-leaf / KeyPackage identity).
    pub pubkey: PublicKey,
    /// Optional human-facing label ("Alice's phone").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional unix-seconds timestamp of when the device was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_at: Option<u64>,
}

impl DeviceEntry {
    /// A bare entry for `pubkey` with no metadata.
    #[must_use]
    pub fn new(pubkey: PublicKey) -> Self {
        Self {
            pubkey,
            name: None,
            added_at: None,
        }
    }

    /// A named entry, stamped with the current time as `added_at`.
    #[must_use]
    pub fn named(pubkey: PublicKey, name: impl Into<String>) -> Self {
        Self {
            pubkey,
            name: Some(name.into()),
            added_at: Some(Timestamp::now().as_secs()),
        }
    }
}

/// The full, signed mapping `account -> {devices}`.
///
/// `account` is bound to the event signer on parse (see
/// [`crate::wire::parse_device_list`]): a device list only ever speaks for the
/// key that signed it, so a signer cannot claim devices on behalf of another
/// account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceList {
    /// The stable account identity this list speaks for.
    pub account: PublicKey,
    /// Every device the account currently authorizes.
    pub devices: Vec<DeviceEntry>,
    /// Unix-seconds timestamp of this revision (newest wins on the relay).
    pub updated_at: u64,
}

impl DeviceList {
    /// Build a list for `account` from `devices`, stamped now.
    #[must_use]
    pub fn new(account: PublicKey, devices: Vec<DeviceEntry>) -> Self {
        Self {
            account,
            devices,
            updated_at: Timestamp::now().as_secs(),
        }
    }

    /// The device pubkeys, in listed order.
    #[must_use]
    pub fn pubkeys(&self) -> Vec<PublicKey> {
        self.devices.iter().map(|d| d.pubkey).collect()
    }

    /// Whether `pubkey` is one of this account's devices.
    #[must_use]
    pub fn contains(&self, pubkey: &PublicKey) -> bool {
        self.devices.iter().any(|d| &d.pubkey == pubkey)
    }
}
