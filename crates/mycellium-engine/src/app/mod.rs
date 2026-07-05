//! The engine's orchestration (headless): create/restore an identity, register,
//! open a direct line (X3DH + Double Ratchet), deliver live or via the mailbox,
//! run groups and multi-device — everything a shell drives, minus presentation.
#![allow(clippy::too_many_arguments)]

use anyhow::{anyhow, bail, Context, Result};

use mycellium_core::group::{Group, GroupMessage};
use mycellium_core::identity::{DevicePublicKey, Handle, Identity};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::offline::Envelope;
use mycellium_core::platform::Platform;
use mycellium_core::ratchet::Ratchet;
use mycellium_core::record::{Device, Record, SignedRecord};
use mycellium_core::safety;
use mycellium_core::transport::Transport;
use mycellium_core::userid::user_id;
use mycellium_core::wire;
use mycellium_core::x3dh::{self, HandshakeInit};

use crate::blocklist;
use crate::contacts::{self, Contact};
use crate::draft;
use crate::expiry;
use crate::groups::{
    self, GroupInvitePayload, GroupLeavePayload, GroupSyncPayload, MailItem, StoredGroup,
};
use crate::history::{self, GroupStoredMessage, StoredMessage};
use crate::inbound;
use crate::names;
use crate::outbox;
use crate::platform::OsPlatform;
use crate::verified::{self, TrustLevel};
use mycellium_directory_client::DirectoryClient;
use mycellium_queue_client::{wallet_hex, QueueClient};
use mycellium_storage::filestore::FileStore;
use mycellium_storage::store;
use mycellium_transport::libp2p_net::{self};
use mycellium_transport::link::{FrameReader, FrameWriter, Wire};
use mycellium_transport::net::{self, TcpTransport};

/// The cluster-wide mailbox slot, read by every device of an account. Shared by
/// several submodules, so it lives at the `app` root (reached via `super::*`).
const ACCOUNT_SLOT: &str = "account";

mod backup;
mod devices;
mod directory_ops;
mod grouping;
mod messaging;
mod organize;
mod pairing;
mod session;
mod util;

pub use backup::*;
pub use devices::*;
pub use directory_ops::*;
pub use grouping::*;
pub use messaging::*;
pub use organize::*;
pub use pairing::*;
pub use session::*;
pub use util::*;
