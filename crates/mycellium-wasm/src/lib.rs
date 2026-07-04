//! Mycellium engine in WebAssembly (Tier 1.1, stage 1).
//!
//! Stage 1 proves the toolchain and the core crypto run correctly *in the
//! browser*: the deterministic account-id hash and real device-key generation.
//! Later stages add the pure send/receive step functions and JS-owned I/O
//! (`fetch` + IndexedDB), replacing the local Rust server entirely.

use mycellium_core::http::{HttpResponse, HttpTransport};
use mycellium_core::identity::Identity;
use mycellium_core::platform::Platform;
use mycellium_core::userid::user_id as core_user_id;
use mycellium_directory_client::DirectoryClient;
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

/// Log into a directory from the browser: generate a device identity, run the
/// challenge → sign → verify handshake over (synchronous) XHR, and return the
/// session token. Proves the *entire* client stack — transport, shared client
/// logic, and crypto — runs in WASM against a real server.
#[wasm_bindgen]
pub fn directory_login(base: &str) -> Result<String, JsValue> {
    let identity = Identity::generate(&mut BrowserPlatform).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let client = DirectoryClient::with_transport(base, Box::new(XhrTransport));
    client.login(&identity).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// A synchronous `XMLHttpRequest`-backed [`HttpTransport`]. Synchronous so the
/// shared (blocking) client logic runs unchanged; a later stage moves this into
/// a Web Worker so it never blocks the UI thread.
struct XhrTransport;

impl HttpTransport for XhrTransport {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, String> {
        let xhr = web_sys::XmlHttpRequest::new().map_err(|_| "XHR unavailable".to_string())?;
        xhr.open_with_async(method, url, false).map_err(|e| format!("open: {e:?}"))?;
        for (k, v) in headers {
            let _ = xhr.set_request_header(k, v);
        }
        let sent = match body {
            Some(b) => xhr.send_with_opt_str(Some(&String::from_utf8_lossy(b))),
            None => xhr.send(),
        };
        sent.map_err(|e| format!("send: {e:?}"))?;
        let status = xhr.status().map_err(|e| format!("status: {e:?}"))?;
        let text = xhr.response_text().ok().flatten().unwrap_or_default();
        Ok(HttpResponse { status, body: text.into_bytes() })
    }
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
