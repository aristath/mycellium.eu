# mycellium-serve

**Layer:** service runtime (library) · **Depends on:** axum, axum-server, hyper, tokio, rustls, tower-http, mycellium-observe

The shared production HTTP runtime for the Mycellium services. The directory and
the queue are both small JSON APIs whose real logic lives in a plain, synchronous
core (`Directory` / `Queue`); this crate owns the *serving* concern they share, on
a modern, maintained async stack — **axum + hyper + tokio + rustls** — so each
service only describes its routes and hands over its state.

## What every service gets

`Server::new(service, max_body).run(addr, router).await` wraps a service's axum
`Router` with, uniformly:

- **`/health`** and **`/metrics`** (Prometheus) endpoints.
- **CORS** (permissive) so the browser-served PWA can call the API cross-origin.
- A **request-body size cap** enforced by the stack — over-cap requests get `413`.
- A per-request **metrics counter + structured access log**, where the logged path
  is axum's **matched route template** (e.g. `/records/{handle}`), so a looked-up
  handle or wallet never lands in a log line — redaction is structural, not a
  hand-maintained list.
- Optional **TLS** from `MYCELLIUM_TLS_CERT` / `MYCELLIUM_TLS_KEY`, terminated
  in-process by **rustls** (pure-Rust; no system OpenSSL).
- **Graceful shutdown** on `SIGINT` / `SIGTERM`: in-flight requests drain (up to
  10 s) and the durable store is dropped cleanly, so a rolling restart drops no
  work.

## Public API

- `Server::new(service: &'static str, max_body: usize) -> Server` — a runtime for
  one service, labelling its metrics/logs and capping request bodies.
- `Server::run(self, addr: &str, app: Router) -> io::Result<()>` — serve `app`
  (routes with state already applied) until a shutdown signal, then return.
- `Server::metrics(&self) -> Arc<Metrics>` — the shared metrics handle.
- `Metrics` — re-exported from [`mycellium-observe`](../mycellium-observe/README.md).

## Environment

- `MYCELLIUM_TLS_CERT` / `MYCELLIUM_TLS_KEY` — PEM cert + key → serve HTTPS
  (rustls). Unset → plain HTTP (typically behind a TLS-terminating reverse proxy).
- `MYCELLIUM_LOG` — `1` → a structured JSON access-log line per request (see
  `mycellium-observe`); otherwise only 5xx are logged.
