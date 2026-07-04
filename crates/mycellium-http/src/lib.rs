//! The native implementation of [`HttpTransport`] backed by `ureq` (blocking
//! sockets). The browser build provides its own `fetch`/XHR implementation; the
//! directory and queue clients are written against the trait, not this type.

use std::io::Read;

use mycellium_core::http::{HttpResponse, HttpTransport};

/// A blocking HTTP transport using `ureq`.
#[derive(Default)]
pub struct UreqTransport;

impl HttpTransport for UreqTransport {
    fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, String> {
        let mut req = ureq::request(method, url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        let result = match body {
            Some(bytes) => req.send_bytes(bytes),
            None => req.call(),
        };
        match result {
            Ok(resp) => read_response(resp),
            // ureq surfaces 4xx/5xx as an error; fold it back into a normal
            // response so callers see the status instead of a transport failure.
            Err(ureq::Error::Status(_, resp)) => read_response(resp),
            Err(e) => Err(e.to_string()),
        }
    }
}

fn read_response(resp: ureq::Response) -> Result<HttpResponse, String> {
    let status = resp.status();
    let mut body = Vec::new();
    resp.into_reader().read_to_end(&mut body).map_err(|e| e.to_string())?;
    Ok(HttpResponse { status, body })
}
