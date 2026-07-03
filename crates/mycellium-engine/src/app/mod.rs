//! The engine's orchestration (headless): create/restore an identity, register,
//! open a direct line (X3DH + Double Ratchet), deliver live or via the mailbox,
//! run groups and multi-device — everything a shell drives, minus presentation.
#![allow(clippy::too_many_arguments)]

use anyhow::{anyhow, bail, Context, Result};

use mycellium_core::group::{Group, GroupMessage};
use mycellium_core::identity::{DevicePublicKey, Handle, Identity, MessagingPublicKey, PeerId};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::offline::Envelope;
use mycellium_core::platform::Platform;
use mycellium_core::ratchet::Ratchet;
use mycellium_core::record::{Device, Record, SignedPreKey, SignedRecord};
use mycellium_core::safety;
use mycellium_core::shamir::{self, Share};
use mycellium_core::transport::Transport;
use mycellium_core::wire;
use mycellium_core::x3dh::{self, HandshakeInit};

use mycellium_directory_client::DirectoryClient;
use mycellium_queue_client::{wallet_hex, QueueClient};
use mycellium_storage::filestore::FileStore;
use mycellium_storage::store;
use crate::blocklist;
use crate::contacts::{self, Contact};
use crate::draft;
use crate::expiry;
use crate::groups::{self, GroupInvitePayload, GroupSyncPayload, MailItem, StoredGroup};
use crate::history::{self, GroupStoredMessage, StoredMessage};
use crate::outbox;
use crate::platform::OsPlatform;
use mycellium_transport::libp2p_net::{self};
use mycellium_transport::link::{FrameReader, FrameWriter, Wire};
use mycellium_transport::net::{self, TcpTransport};

/// The cluster-wide mailbox slot, read by every device of an account. Shared by
/// several submodules, so it lives at the `app` root (reached via `super::*`).
const ACCOUNT_SLOT: &str = "account";

mod session;
mod messaging;
mod grouping;
mod devices;
mod directory_ops;
mod organize;
mod backup;
mod util;

pub use session::*;
pub use messaging::*;
pub use grouping::*;
pub use devices::*;
pub use directory_ops::*;
pub use organize::*;
pub use backup::*;
pub use util::*;
