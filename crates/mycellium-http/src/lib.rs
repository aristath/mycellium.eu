//! The native implementation of [`HttpTransport`] backed by `ureq` (blocking
//! sockets). The browser build provides its own `fetch`/XHR implementation; the
//! directory and queue clients are written against the trait, not this type.

use std::io::Read;
use std::sync::OnceLock;
use std::time::Duration;

use mycellium_core::http::{HttpResponse, HttpTransport};

/// How long the TCP connect may take before giving up. Mirrors the TCP
/// transport's `CONNECT_TIMEOUT` (see `mycellium-transport/src/net.rs`).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a single read/write may block before erroring. Bounds a
/// slow/stalled/slow-loris directory or queue that connects then dribbles bytes
/// (or nothing) so it can no longer pin the caller's thread forever. The byte
/// cap in `read_response` bounds total SIZE; this bounds TIME.
const IO_TIMEOUT: Duration = Duration::from_secs(15);

/// The shared, timeout-and-redirect-hardened `ureq` agent. Built once and
/// reused so connection pooling works across requests.
fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout_read(IO_TIMEOUT)
            .timeout_write(IO_TIMEOUT)
            // Do NOT auto-follow redirects. The directory/queue are untrusted;
            // a hostile endpoint could 302 us to `http://…` (downgrading the
            // metadata channel) or to an internal address (SSRF). With this at
            // zero a 3xx surfaces to the caller as a normal response instead of
            // being silently chased.
            .redirects(0)
            .build()
    })
}

/// Cap for small responses (records, auth, push keys, deposit acks) — a hostile
/// endpoint can't make us allocate more than this.
const MAX_RESPONSE_SMALL: usize = 4 * 1024 * 1024; // 4 MiB
/// Cap for a mailbox collect, which legitimately returns the whole mailbox
/// (up to MAX_MAILBOX blobs of up to the deposit body size) — generous, but
/// still bounded rather than unbounded.
const MAX_RESPONSE_MAILBOX: usize = 320 * 1024 * 1024; // 320 MiB

/// The response cap for a URL: large only for the mailbox-collect path.
fn max_response_for(url: &str) -> usize {
    if url.contains("/mailbox/") {
        MAX_RESPONSE_MAILBOX
    } else {
        MAX_RESPONSE_SMALL
    }
}

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
        let mut req = agent().request(method, url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        let result = match body {
            Some(bytes) => req.send_bytes(bytes),
            None => req.call(),
        };
        let max = max_response_for(url);
        match result {
            Ok(resp) => read_response(resp, max),
            // ureq surfaces 4xx/5xx as an error; fold it back into a normal
            // response so callers see the status instead of a transport failure.
            Err(ureq::Error::Status(_, resp)) => read_response(resp, max),
            Err(e) => Err(e.to_string()),
        }
    }
}

fn read_response(resp: ureq::Response, max: usize) -> Result<HttpResponse, String> {
    let status = resp.status();
    let mut body = Vec::new();
    // Read one byte past the cap so we can distinguish "at cap" from "over cap".
    resp.into_reader()
        .take(max as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|e| e.to_string())?;
    if body.len() > max {
        return Err(format!("response body exceeds {max} bytes"));
    }
    Ok(HttpResponse { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn endpoint_response_caps() {
        assert_eq!(
            max_response_for("http://q/mailbox/abc/account"),
            MAX_RESPONSE_MAILBOX
        );
        assert_eq!(max_response_for("http://d/records/abc"), MAX_RESPONSE_SMALL);
        assert_eq!(max_response_for("http://d/auth/status"), MAX_RESPONSE_SMALL);
    }

    #[test]
    fn oversized_response_is_rejected() {
        // A tiny server that returns a body larger than the small cap.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut req = [0u8; 1024];
                let _ = s.read(&mut req);
                let n = MAX_RESPONSE_SMALL + 10;
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n");
                let chunk = vec![b'x'; 64 * 1024];
                let mut sent = 0;
                while sent < n {
                    let _ = s.write_all(&chunk);
                    sent += chunk.len();
                }
            }
        });
        match UreqTransport.request("GET", &format!("http://{addr}/records/x"), &[], None) {
            Err(e) => assert!(
                e.contains("exceeds"),
                "oversized response should be rejected, got: {e}"
            ),
            Ok(r) => panic!(
                "oversized response should be rejected, got {} bytes",
                r.body.len()
            ),
        }
    }

    #[test]
    fn redirects_are_not_followed() {
        // A hostile endpoint that 302s to another location. With redirects
        // disabled the 3xx must surface to the caller (folded into a normal
        // response by ureq's error handling) rather than being chased — a
        // followed redirect could downgrade https→http or reach an internal
        // address (SSRF). The Location here points somewhere the test never
        // serves, so if the client *did* follow it the request would fail to
        // connect instead of returning 302.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut req = [0u8; 1024];
                let _ = s.read(&mut req);
                let _ = write!(
                    s,
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/internal\r\nContent-Length: 0\r\n\r\n"
                );
            }
        });
        match UreqTransport.request("GET", &format!("http://{addr}/records/x"), &[], None) {
            Ok(r) => assert_eq!(
                r.status, 302,
                "redirect must surface as a 302, not be followed"
            ),
            Err(e) => panic!("redirect should surface as a 302 response, got error: {e}"),
        }
    }
}
