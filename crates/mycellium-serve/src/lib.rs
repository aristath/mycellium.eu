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
use tracing::info;

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
        Self::with_metrics(service, max_body, Arc::new(Metrics::default()))
    }

    /// Like [`Server::new`], but over a caller-owned [`Metrics`] so a service can
    /// keep its own `Arc<Metrics>` handle (e.g. the queue records push-fan-out
    /// failures on the *same* counters the `/metrics` endpoint renders).
    pub fn with_metrics(service: &'static str, max_body: usize, metrics: Arc<Metrics>) -> Self {
        Server {
            service,
            metrics,
            max_body,
        }
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
            // Innermost app layer: turn a handler panic into a `500` instead of
            // killing the task/connection. Combined with poison-tolerant state
            // locks in the services, one panicking request can no longer take the
            // whole service down (it stays inside the `observe` layer, so the 500
            // is still counted + logged).
            .layer(tower_http::catch_panic::CatchPanicLayer::new())
            .layer(axum::extract::DefaultBodyLimit::max(max_body))
            .layer(cors_layer())
            .layer(middleware::from_fn_with_state(ctx, observe));

        let sockaddr = resolve_addr(addr)?;
        let handle = axum_server::Handle::new();
        tokio::spawn(shutdown_signal(handle.clone()));

        let tls_enabled = config.tls.is_some();
        info!(service, addr = %sockaddr, tls = tls_enabled, "listening");

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
                info!(cert = %tls.cert_path, "tls enabled — rustls");
                axum_server::bind_rustls(sockaddr, rustls_config)
                    .handle(handle)
                    .serve(app.into_make_service())
                    .await
            }
            None => {
                info!("tls disabled — terminate at a proxy or configure TLS");
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

    info!("shutting down — draining in-flight requests");
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
}

#[cfg(test)]
mod panic_recovery_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Mutex;
    use tower::ServiceExt;

    // One handler panic (while holding the state lock) must NOT take the service
    // down: CatchPanicLayer turns it into a 500, and the poison-tolerant lock lets
    // the very next request still succeed — no poison cascade.
    #[tokio::test]
    async fn a_handler_panic_does_not_poison_the_service() {
        let state = Arc::new(Mutex::new(0u32));
        let panic_state = Arc::clone(&state);
        let ping_state = Arc::clone(&state);

        let app = Router::new()
            .route(
                "/panic",
                get(move || {
                    let s = Arc::clone(&panic_state);
                    async move {
                        let _g = s.lock().unwrap_or_else(|e| e.into_inner());
                        panic!("boom while holding the lock");
                        #[allow(unreachable_code)]
                        ""
                    }
                }),
            )
            .route(
                "/ping",
                get(move || {
                    let s = Arc::clone(&ping_state);
                    async move {
                        let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
                        *g += 1;
                        "ok"
                    }
                }),
            )
            .layer(tower_http::catch_panic::CatchPanicLayer::new());

        let r1 = app
            .clone()
            .oneshot(Request::get("/panic").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r1.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // The mutex is poisoned now, but the next request still works.
        let r2 = app
            .oneshot(Request::get("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::OK);
    }
}
