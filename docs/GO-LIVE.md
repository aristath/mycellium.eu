# Go-Live Checklist

A pre-flight list for putting Mycellium in front of real users. Pair it with
[`DEPLOY.md`](DEPLOY.md) (the how) and [`PRODUCTION-READINESS.md`](PRODUCTION-READINESS.md)
(the roadmap). Boxes that are hard blockers are marked **⛔**.

## Before launch

- [ ] **⛔ Independent security/crypto audit** (T3.1). The protocol uses vetted
      primitives, but the composition has not been externally reviewed. See
      [`SECURITY.md`](SECURITY.md).
- [ ] **⛔ Durable storage on.** `MYCELLIUM_DATA` set for *both* services (else state
      is in-memory and lost on restart, including all Web Push subscriptions).
- [ ] **⛔ HTTPS everywhere.** Directory, queue, and the PWA all over TLS (proxy or
      native). The PWA will not register a service worker or Web Push otherwise.
- [ ] **⛔ Your own SMTP.** `MYCELLIUM_SMTP_*` pointed at infrastructure you control —
      never a US SMS/email gateway. Verify a real signup email arrives.
- [x] **Browser test hook is gated.** `window.mycellium` (the engine handle for e2e
      tests) is exposed only on `localhost`/`127.0.0.1`, so a real deployment never
      hands the engine to page scripts — nothing to strip.
- [ ] **Load test** (T2.4). Confirm throughput and that nothing drops under the
      concurrency you expect; watch redb file growth and memory.
- [ ] **Back up `MYCELLIUM_DATA`.** Snapshot the redb files (and `vapid.key`) on a
      schedule; test a restore. Losing `vapid.key` invalidates every push subscription.

## Deployment

- [ ] Run `mycellium-server` and `mycellium-queue` under a supervisor (systemd unit
      or container) with restart-on-failure and resource limits.
- [ ] Reverse proxy (Caddy/nginx) terminating TLS, with the CORS-friendly services
      bound to localhost behind it.
- [ ] Serve `clients/web/` (built via `build.sh`) as static files over HTTPS; publish
      the `?dir=…&queue=…` bootstrap URL.
- [ ] Pin versions: `wasm-bindgen-cli` must match the crate's pinned `wasm-bindgen`.

## Monitoring & operations

- [ ] Scrape **`GET /metrics`** on both services into Prometheus; alert on a rising
      `mycellium_server_errors_total` (5xx) rate and on `/health` failure.
- [ ] Ship access logs (`MYCELLIUM_LOG=1`, JSON) to your aggregator. Paths carry only
      opaque ids — safe to retain.
- [ ] Watch: request rate, 4xx/5xx ratio, redb file size, process memory/FDs, rate-
      limit rejections (a spike may be abuse or a misconfigured client).
- [ ] Have a rollback plan (previous binary + a data snapshot) and a private channel
      for vulnerability reports.

## Capacity & scaling

- [ ] **Directory:** read-mostly and cloneable behind a load balancer; plan the move
      off single-node redb (→ Postgres) before you need multi-node (T0.1).
- [ ] **Queue:** per-recipient store-and-forward; shard by recipient wallet when one
      node isn't enough. Tune `DEPOSIT_RATE_LIMIT` / `MAX_MAILBOX` for your traffic.
- [ ] Size the worker pools and connection limits for the box; re-run the load test
      after any change.

## Known gaps to disclose to early users

- No independent audit yet.
- Browser: one account per profile; new mail arrives by ~3 s polling. See
  [`BROWSER.md`](BROWSER.md).
- No NAT traversal for direct P2P; delivery falls back to the queue.
- Metadata (who talks to whom, when) is minimized but not hidden — see
  [`SECURITY.md`](SECURITY.md).
