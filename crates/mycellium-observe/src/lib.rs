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

use tracing::{info, warn};

/// Process-wide request counters. Cheap to share behind an `Arc`.
#[derive(Default)]
pub struct Metrics {
    requests: AtomicU64,
    client_errors: AtomicU64,      // 4xx
    server_errors: AtomicU64,      // 5xx
    push_send_failures: AtomicU64, // push wake fan-out failures (a provider may be down)
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

    /// Count one push wake fan-out that hit a transport error, so a push provider
    /// going down is visible on the dashboard instead of failing silently.
    pub fn inc_push_failure(&self) {
        self.push_send_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Prometheus text exposition, labelled by `service` (e.g. "directory").
    pub fn render(&self, service: &str) -> String {
        let r = self.requests.load(Ordering::Relaxed);
        let c = self.client_errors.load(Ordering::Relaxed);
        let s = self.server_errors.load(Ordering::Relaxed);
        let p = self.push_send_failures.load(Ordering::Relaxed);
        format!(
            "# HELP mycellium_requests_total Total HTTP requests handled.\n\
             # TYPE mycellium_requests_total counter\n\
             mycellium_requests_total{{service=\"{service}\"}} {r}\n\
             # HELP mycellium_client_errors_total 4xx responses.\n\
             # TYPE mycellium_client_errors_total counter\n\
             mycellium_client_errors_total{{service=\"{service}\"}} {c}\n\
             # HELP mycellium_server_errors_total 5xx responses.\n\
             # TYPE mycellium_server_errors_total counter\n\
             mycellium_server_errors_total{{service=\"{service}\"}} {s}\n\
             # HELP mycellium_push_send_failures_total Push wake fan-outs that hit a transport error.\n\
             # TYPE mycellium_push_send_failures_total counter\n\
             mycellium_push_send_failures_total{{service=\"{service}\"}} {p}\n"
        )
    }
}

/// Emit a structured access-log event through `tracing`, so every service log
/// (banners, errors, access logs) shares one sink + format.
///
/// Level mapping — an operator tunes verbosity purely via `RUST_LOG`:
/// - **5xx** (server errors) → `warn!`: always emitted, so it clears the default
///   `info` filter and a failing endpoint is never silent.
/// - **everything else** → `info!`, but only when `access_log` is enabled in
///   config — so the default is "5xx only", and full request logging is opt-in
///   (config flag) *or* reachable by raising `RUST_LOG` to see the `info` events.
pub fn access_log(
    service: &str,
    method: &str,
    path: &str,
    status: u16,
    ms: u128,
    access_log: bool,
) {
    let path = path.replace(['"', '\\', '\n'], "");
    let ms = ms as u64;
    if status >= 500 {
        warn!(svc = service, method, path, status, ms, "request");
    } else if access_log {
        info!(svc = service, method, path, status, ms, "request");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_reports_push_send_failures() {
        let m = Metrics::default();
        // Simulate a push fan-out that hit a down transport.
        m.inc_push_failure();
        let out = m.render("queue");
        assert!(
            out.contains("# TYPE mycellium_push_send_failures_total counter"),
            "render must expose the push-failure counter:\n{out}"
        );
        assert!(
            out.contains("mycellium_push_send_failures_total{service=\"queue\"} 1"),
            "render must show >= 1 push failure after a simulated failure:\n{out}"
        );
    }
}
