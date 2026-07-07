//! The engine's orchestration (headless): create/restore an identity, register,
//! open a direct line (X3DH + Double Ratchet), deliver live or via the mailbox,
//! run groups and multi-device — everything a shell drives, minus presentation.
#![allow(clippy::too_many_arguments)]

use anyhow::{anyhow, bail, Context, Result};

use mycellium_core::group::Group;
use mycellium_core::identity::{DevicePublicKey, Handle, Identity, WalletPublicKey};
use mycellium_core::message::{AppMessage, Body};
use mycellium_core::offline::Envelope;
use mycellium_core::platform::Platform;
use mycellium_core::ratchet::Ratchet;
use mycellium_core::record::{Device, Record, SignedRecord};
use mycellium_core::safety;
use mycellium_core::storage::Storage;
use mycellium_core::transport::Transport;
use mycellium_core::userid::user_id;
use mycellium_core::wire;
use mycellium_core::x3dh::{self, HandshakeInit};

use crate::blocklist;
use crate::contacts::{self, Contact};
use crate::draft;
use crate::expiry;
use crate::groups::{self, GroupSyncPayload, MailItem, StoredGroup};
use crate::history;
use crate::inbound;
use crate::outbox;
use crate::platform::OsPlatform;
use crate::reachability::{self, DeliveryPath};
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

/// The engine (native CLI) [`crate::flow::FlowNet`]: directory lookups over the
/// native blocking [`DirectoryClient`]. Borrows the client so the send shell and
/// the trust chokepoint share one connection without cloning.
pub(crate) struct EngineNet<'a> {
    pub dir: &'a DirectoryClient,
}

impl crate::flow::FlowNet for EngineNet<'_> {
    fn lookup(&self, handle: &Handle) -> anyhow::Result<SignedRecord> {
        self.dir.lookup(handle)
    }
    fn publish(&self, identity: &Identity, record: &SignedRecord) -> anyhow::Result<()> {
        let token = self.dir.login(identity)?;
        self.dir.publish(&token, record)
    }
}

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
