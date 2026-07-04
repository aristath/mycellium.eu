# mycellium-observe

> Dependency-free server observability: request metrics + structured access logs.

**Layer:** support (library) · **Depends on:** nothing (std only)

## What it does

A tiny, zero-dependency observability kit shared by the `mycellium-directory` and
`mycellium-queue` HTTP shells. Two pieces: `Metrics`, a set of atomic counters that
render to Prometheus text for a `/metrics` endpoint; and `access_log`, a structured
(JSON) one-line-per-request log. Both are privacy-safe by construction — the paths
they see contain only opaque ids (hashes), never plaintext handles or emails.

## Public API

- `Metrics` — process-wide counters (`Default`, cheap to share behind an `Arc`).
  - `record(status)` — count one completed request by class (total, plus 4xx / 5xx).
  - `render(service)` — Prometheus exposition labelled by service name, exposing
    `mycellium_requests_total`, `mycellium_client_errors_total`, and
    `mycellium_server_errors_total`.
- `access_log(service, method, path, status, ms)` — emit a JSON access line to
  stdout. On when `MYCELLIUM_LOG` is set (and not `"0"`); `5xx` responses are
  **always** logged regardless.

## How it fits

Each service holds an `Arc<Metrics>`, calls `record(status)` as it finishes every
request, serves `render("directory"|"queue")` on `GET /metrics`, and calls
`access_log(...)` per request. See `docs/DEPLOY.md` for scraping and log setup.

## Notes

Uses only `std::sync::atomic` and `std::time`, so it adds no dependencies and is
safe to embed anywhere. Counters are `Relaxed` — exact enough for monitoring, and
never a synchronization bottleneck on the request path.
