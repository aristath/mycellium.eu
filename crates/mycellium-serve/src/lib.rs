//! Shared production HTTP runtime for the Mycellium services.
//!
//! The directory and the queue are both small JSON APIs whose real logic lives
//! in a plain, synchronous core (`Directory` / `Queue`). This crate owns the
//! *serving* concern they share, on a modern, maintained async stack —
//! **axum + hyper + tokio + rustls** — so each service only has to describe its
//! routes and hand over its state.
//!
//! Every service built through [`Server::run`] gets, uniformly:
//! - `/health` and `/metrics` (Prometheus) endpoints;
//! - permissive CORS (the browser PWA calls these APIs cross-origin);
//! - a request-body size cap enforced by the stack (over-cap → `413`);
//! - a metrics counter + structured access log per request, where the logged
//!   path is axum's **matched route template** (e.g. `/records/{handle}`), so a
//!   looked-up handle or wallet never lands in a log line;
//! - optional TLS from explicit config (rustls);
//! - **graceful shutdown** on `SIGINT`/`SIGTERM`, so in-flight requests finish
//!   and the durable store is dropped cleanly.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request, State};
use axum::http::header;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use tower_http::cors::{Any, CorsLayer};

pub use mycellium_observe::Metrics;

/// TLS PEM paths for the shared HTTP runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// Explicit HTTP serving options.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpConfig {
    pub tls: Option<TlsConfig>,
    pub access_log: bool,
}

/// A configured HTTP server for one Mycellium service.
pub struct Server {
    service: &'static str,
    metrics: Arc<Metrics>,
    max_body: usize,
}

impl Server {
    /// Create a runtime for `service` (the metrics/log label, e.g. `"directory"`),
    /// capping request bodies at `max_body` bytes.
    pub fn new(service: &'static str, max_body: usize) -> Self {
        Server {
            service,
            metrics: Arc::new(Metrics::default()),
            max_body,
        }
    }

    /// The shared metrics handle, so a service can also record events that don't
    /// flow through an HTTP handler if it ever needs to.
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// Serve `app` (the service's routes, with its state already applied) on
    /// `addr` until a shutdown signal arrives, wrapping it in the shared
    /// middleware stack + `/health` + `/metrics` and terminating TLS when
    /// configured. Returns when the server has shut down gracefully.
    pub async fn run(self, addr: &str, app: Router, config: HttpConfig) -> std::io::Result<()> {
        let Server {
            service,
            metrics,
            max_body,
        } = self;

        let metrics_route = {
            let metrics = Arc::clone(&metrics);
            move || {
                let metrics = Arc::clone(&metrics);
                async move {
                    (
                        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
                        metrics.render(service),
                    )
                }
            }
        };

        let ctx = ObserveCtx {
            metrics: Arc::clone(&metrics),
            service,
            access_log: config.access_log,
        };

        // Layer order is outermost-last: the observe layer wraps everything (so it
        // still counts a body-limit `413`), then CORS, then the body cap closest
        // to the handlers.
        let app = app
            .route("/health", get(|| async { "\"ok\"" }))
            .route("/metrics", get(metrics_route))
            .layer(axum::extract::DefaultBodyLimit::max(max_body))
            .layer(cors_layer())
            .layer(middleware::from_fn_with_state(ctx, observe));

        let sockaddr = resolve_addr(addr)?;
        let handle = axum_server::Handle::new();
        tokio::spawn(shutdown_signal(handle.clone()));

        match config.tls {
            Some(tls) => {
                // rustls 0.23 requires a process-wide crypto provider; install the
                // ring backend once (idempotent — a second call is a no-op).
                let _ = rustls::crypto::ring::default_provider().install_default();
                let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                    &tls.cert_path,
                    &tls.key_path,
                )
                .await
                .map_err(|e| {
                    std::io::Error::other(format!(
                        "TLS config from {}/{}: {e}",
                        tls.cert_path, tls.key_path
                    ))
                })?;
                println!("  tls: enabled ({}) — rustls", tls.cert_path);
                axum_server::bind_rustls(sockaddr, rustls_config)
                    .handle(handle)
                    .serve(app.into_make_service())
                    .await
            }
            None => {
                println!("  tls: disabled (terminate at a proxy or configure TLS)");
                axum_server::bind(sockaddr)
                    .handle(handle)
                    .serve(app.into_make_service())
                    .await
            }
        }
    }
}

/// State threaded into the per-request observe middleware.
#[derive(Clone)]
struct ObserveCtx {
    metrics: Arc<Metrics>,
    service: &'static str,
    access_log: bool,
}

/// Count every response and emit an access-log line whose path is the **matched
/// route template** — never the concrete handle/wallet that was requested.
async fn observe(
    State(ctx): State<ObserveCtx>,
    matched: Option<MatchedPath>,
    req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = req.method().as_str().to_owned();
    // The template (`/records/{handle}`) carries no identifier; an unrouted path
    // is logged as a placeholder so a probed URL is never echoed verbatim either.
    let path = matched
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "<unmatched>".to_owned());

    let resp = next.run(req).await;

    let status = resp.status().as_u16();
    ctx.metrics.record(status);
    mycellium_observe::access_log(
        ctx.service,
        &method,
        &path,
        status,
        start.elapsed().as_millis(),
        ctx.access_log,
    );
    resp
}

/// Permissive CORS so the browser-served PWA (a different origin) can call the
/// API directly. Matches the previous hand-rolled headers.
fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
}

/// Resolve a `HOST:PORT` bind string to a concrete socket address.
fn resolve_addr(addr: &str) -> std::io::Result<SocketAddr> {
    addr.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("could not resolve bind address '{addr}'"),
        )
    })
}

/// Resolve when the process is asked to stop (Ctrl-C, or `SIGTERM` under an init
/// system / container), then start a bounded graceful shutdown.
async fn shutdown_signal(handle: axum_server::Handle) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }

    println!("shutting down — draining in-flight requests");
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
}
