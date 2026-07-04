//! An abstract **HTTP request/response** capability.
//!
//! The directory and queue clients speak HTTP, but *how* the bytes travel is the
//! host's business: native builds use `ureq` (blocking sockets); the browser
//! build uses `fetch`/`XMLHttpRequest`. Both implement this one trait, so the
//! client logic is shared verbatim across native and WebAssembly.
//!
//! (Distinct from [`crate::transport`], which is a peer-to-peer *byte-stream* to
//! another device — this is a client/server request/response.)

use alloc::string::String;
use alloc::vec::Vec;

/// A minimal HTTP response: status code + raw body bytes.
pub struct HttpResponse {
    /// The HTTP status code (e.g. 200, 404).
    pub status: u16,
    /// The raw response body bytes.
    pub body: Vec<u8>,
}

/// Perform HTTP requests. Object-safe, so clients hold `Box<dyn HttpTransport>`.
pub trait HttpTransport {
    /// Send a request. `Err` is a *transport-level* failure (connection refused,
    /// DNS, TLS); an HTTP error **status** is a successful `Ok` with
    /// `status >= 400`, so callers can distinguish "couldn't reach it" from "it
    /// said no".
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, String>;
}
