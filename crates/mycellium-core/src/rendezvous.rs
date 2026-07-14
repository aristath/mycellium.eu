//! Registry-assisted introduction for direct device-to-device connections.
//!
//! The registry carries only these control messages. It tells two currently
//! connected devices which temporary UDP mappings to punch; application
//! messages never use this protocol or pass through the registry.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::identity::DevicePublicKey;
use crate::userid::UserId;

/// libp2p stream protocol used only for live introductions.
pub const PROTOCOL: &str = "/mycellium/rendezvous/1.0";

/// Largest accepted control frame. This is an abuse ceiling, not a data-model
/// limit; ordinary frames are only a few hundred bytes.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// The role a peer takes while both sides dial the same direct QUIC path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PunchRole {
    /// Normal QUIC dialer role.
    Dialer,
    /// Dial while retaining the listener role, as required by simultaneous
    /// hole punching.
    Listener,
}

/// Control messages sent from a device to the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Authenticate this live transport connection as the account's current
    /// active device.
    Register {
        /// Stable protocol identity whose published record names this device.
        user_id: UserId,
        /// Stable device identity bound to the authenticated libp2p peer.
        device: DevicePublicKey,
    },
    /// Ask the registry to introduce the current device to another live device.
    Introduce {
        /// Stable device identity to find.
        device: DevicePublicKey,
    },
}

/// Control messages sent from the registry to a device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMessage {
    /// Registration succeeded and this device can now receive introductions.
    Registered,
    /// Dial this peer's temporary observed UDP mapping now.
    Connect {
        /// Stable identity of the peer being introduced.
        device: DevicePublicKey,
        /// Binary libp2p multiaddr observed by the registry.
        address: Vec<u8>,
        /// Which side of the simultaneous dial this device must take.
        role: PunchRole,
    },
    /// The requested device has no authenticated live registry connection.
    Unavailable {
        /// Device that could not be introduced.
        device: DevicePublicKey,
    },
    /// Authentication or protocol validation failed. The registry closes the
    /// control stream after this response.
    Rejected,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_messages_round_trip() {
        let message = ServerMessage::Connect {
            device: DevicePublicKey([7; 32]),
            address: b"/ip4/203.0.113.7/udp/49152/quic-v1".to_vec(),
            role: PunchRole::Listener,
        };
        let bytes = crate::wire::encode(&message);
        let decoded: ServerMessage = crate::wire::decode(&bytes).unwrap();
        assert_eq!(decoded, message);
        assert!(bytes.len() < MAX_FRAME_BYTES);
    }
}
