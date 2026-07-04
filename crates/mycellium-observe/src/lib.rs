//! Lightweight, dependency-free server observability (Tier 2.2).
//!
//! - [`Metrics`]: atomic request/error counters with a Prometheus text rendering
//!   for a `/metrics` endpoint.
//! - [`access_log`]: a structured (JSON) access-log line per request.
//!
//! Callers pass a **redacted route template** as the path (e.g.
//! `/records/:handle`, `/mailbox/:wallet/:slot`), not the raw request path, so
//! access logs record which endpoint was hit without the specific handle or
//! wallet identifier — no plaintext names/emails and no social-graph metadata.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Process-wide request counters. Cheap to share behind an `Arc`.
#[derive(Default)]
pub struct Metrics {
    requests: AtomicU64,
    client_errors: AtomicU64, // 4xx
    server_errors: AtomicU64, // 5xx
}

impl Metrics {
    /// Count one completed request by its status class.
    pub fn record(&self, status: u16) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if status >= 500 {
            self.server_errors.fetch_add(1, Ordering::Relaxed);
        } else if status >= 400 {
            self.client_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Prometheus text exposition, labelled by `service` (e.g. "directory").
    pub fn render(&self, service: &str) -> String {
        let r = self.requests.load(Ordering::Relaxed);
        let c = self.client_errors.load(Ordering::Relaxed);
        let s = self.server_errors.load(Ordering::Relaxed);
        format!(
            "# HELP mycellium_requests_total Total HTTP requests handled.\n\
             # TYPE mycellium_requests_total counter\n\
             mycellium_requests_total{{service=\"{service}\"}} {r}\n\
             # HELP mycellium_client_errors_total 4xx responses.\n\
             # TYPE mycellium_client_errors_total counter\n\
             mycellium_client_errors_total{{service=\"{service}\"}} {c}\n\
             # HELP mycellium_server_errors_total 5xx responses.\n\
             # TYPE mycellium_server_errors_total counter\n\
             mycellium_server_errors_total{{service=\"{service}\"}} {s}\n"
        )
    }
}

/// Emit a structured access-log line to stdout. Full access logging is on when
/// `MYCELLIUM_LOG` is set (and not "0"); 5xx responses are always logged.
pub fn access_log(service: &str, method: &str, path: &str, status: u16, ms: u128) {
    let verbose = std::env::var("MYCELLIUM_LOG").map(|v| v != "0").unwrap_or(false);
    if !verbose && status < 500 {
        return;
    }
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let path = path.replace(['"', '\\', '\n'], "");
    println!("{{\"t\":{t},\"svc\":\"{service}\",\"method\":\"{method}\",\"path\":\"{path}\",\"status\":{status},\"ms\":{ms}}}");
}
