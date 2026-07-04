//! Mycellium engine in WebAssembly (Tier 1.1, stage 1).
//!
//! Stage 1 proves the toolchain and the core crypto run correctly *in the
//! browser*: the deterministic account-id hash and real device-key generation.
//! Later stages add the pure send/receive step functions and JS-owned I/O
//! (`fetch` + IndexedDB), replacing the local Rust server entirely.

use mycellium_core::identity::Identity;
use mycellium_core::platform::Platform;
use mycellium_core::userid::user_id as core_user_id;
use wasm_bindgen::prelude::*;

/// The build's version string — a trivial export to confirm JS↔WASM bindings.
#[wasm_bindgen]
pub fn version() -> String {
    concat!("mycellium-wasm ", env!("CARGO_PKG_VERSION")).to_string()
}

/// The public directory id for an email/username. Must byte-for-byte match the
/// native engine's `user_id`, so the browser and servers agree on identities.
#[wasm_bindgen]
pub fn user_id(input: &str) -> String {
    core_user_id(input).as_str().to_string()
}

/// Generate a fresh device identity in the browser and return its wallet public
/// key (hex). Proves real key material is produced from browser entropy.
#[wasm_bindgen]
pub fn generate_wallet() -> Result<String, JsValue> {
    let identity = Identity::generate(&mut BrowserPlatform).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(hex(&identity.wallet_public().0))
}

/// Platform backed by browser APIs: entropy from the Web Crypto RNG (via
/// getrandom's `js` backend) and the clock from `Date.now()`.
struct BrowserPlatform;

impl Platform for BrowserPlatform {
    fn fill_random(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("browser CSPRNG must be available");
    }
    fn now_unix_secs(&self) -> u64 {
        (js_sys::Date::now() / 1000.0) as u64
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
