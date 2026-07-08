//! **`mycellium-desktop`** — a native desktop client for Mycellium.
//!
//! Two layers:
//! - [`engine`] — a GUI-agnostic controller that owns the [`mycellium_app::App`]
//!   on its own Tokio runtime and exposes it to a synchronous UI through command
//!   and event channels. This is where the real behaviour lives, and it is tested
//!   end-to-end over a relay.
//! - [`ui`] (behind the default `gui` feature) — a thin [`egui`](https://egui.rs)
//!   frontend that renders the controller's view-model and forwards user actions.
//!
//! Keeping the GUI behind a feature means the controller compiles and tests
//! without pulling in windowing/GL system libraries.

pub mod engine;

#[cfg(feature = "gui")]
pub mod ui;
