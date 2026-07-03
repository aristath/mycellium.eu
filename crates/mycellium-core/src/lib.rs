//! # mycellium-core
//!
//! The portable heart of Mycellium: identity, the signed directory record, and the
//! trait boundaries that let the same protocol run on everything from a
//! microcontroller to a desktop (see `docs/CONCEPT.md`, Layer 10).
//!
//! This crate is `no_std`-capable. It never touches the network, the disk, the
//! clock, or the OS random source directly — those are supplied by the host
//! through the [`transport`], [`storage`], and [`platform`] traits. Porting
//! Mycellium to a new device means implementing those traits, never editing the
//! protocol.
//!
//! ## What lives here
//! - [`identity`] — handles and the three key types (wallet / device / messaging).
//! - [`record`] — the self-certifying directory record (Layer 8.2).
//! - [`transport`], [`storage`], [`platform`] — the host-supplied capabilities.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod cipher;
pub mod error;
pub mod group;
pub mod identity;
pub mod login;
pub mod message;
pub mod offline;
pub mod platform;
pub mod ratchet;
pub mod record;
pub mod safety;
pub mod shamir;
pub mod storage;
pub mod transport;
pub mod wire;
pub mod x3dh;

pub use error::Error;
