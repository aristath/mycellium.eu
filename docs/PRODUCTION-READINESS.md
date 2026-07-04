# Production Readiness

*What stands between the current working prototype and a service thousands of
people can use seamlessly and reliably.* Ordered by priority. Check items off as
they land.

The protocol and crypto are sound; the gaps are **durability, concurrency,
deployment shape, and the operational essentials** around them.

---

## Tier 0 — Blockers (cannot serve real users without these)

- [x] **T0.1 — Durable storage.** *(directory + queue done)* Bindings, records,
  emails, pepper (directory) and mailboxes + push subs (queue) persist to an
  embedded `redb` store — write-through, loaded on startup. Ephemeral state
  (challenges, tokens, presence, rate, pending codes) stays in memory. Enabled
  via `MYCELLIUM_DATA` (a data directory; `directory.redb` / `queue.redb`
  inside); unset = in-memory. Reopen tests prove survival. *Next: Postgres for
  multi-node.*

- [x] **T0.2 — Concurrency.** *(directory + queue done)* Both servers now use a
  worker-thread pool sharing `Arc<Server>` (each thread calls `recv()`), state
  behind a `Mutex`, push sends off the lock. *Next: validate under load (T2.4),
  connection limits (T2.5).*

- [x] **T0.3 — TLS / HTTPS.** *(done)* Both servers serve HTTPS natively when
  `MYCELLIUM_TLS_CERT` + `MYCELLIUM_TLS_KEY` point at PEM files (tiny_http
  rustls), else plain HTTP behind a proxy. [docs/DEPLOY.md](DEPLOY.md) documents
  the recommended Caddy reverse-proxy (automatic Let's Encrypt) and the native
  option. Verified with a self-signed cert.

- [x] **T0.4 — Real email sending.** *(done)* A `mailer` module sends the
  verification code by **SMTP** (via `lettre`, rustls — no OpenSSL) when
  configured, else a dev fallback that logs the code and returns it in the API.
  Config: `MYCELLIUM_SMTP_HOST` (set = production), `_PORT` (587/STARTTLS, or 465
  implicit TLS), `_FROM`, `_USER`, `_PASS`. Sent **off the request lock** in a
  thread, best-effort (a flaky SMTP never fails signup); `dev_code` is returned
  only in dev mode. *Next: bounce/deliverability handling if needed.*

- [x] **T0.5 — Account recovery.** *(mechanism done)* The directory now lets a
  **new device key re-bind an existing username** when — and only when — the
  caller proves control of the **same registered email** (`auth_confirm`);
  `auth_start` no longer blocks the flow prematurely. Anyone with a different
  email is rejected (`HandleTaken`). The native email-signup path therefore
  recovers end to end on a fresh device; the client already **pins peer wallets**,
  so a peer's key change (recovery *or* attack) is detected — the "safety number
  changed" signal. Test: `account_recovery_rebinds_only_with_matching_email`.
  *Follow-on: surface the key-change as a friendly warning (not a hard error) in
  the UI, and register PWA accounts via the email flow so they're recoverable.*

---

## Tier 1 — Seamlessness (hitches users would feel)

- [x] **T1.1 — Consumer distribution (WASM PWA).** *(done)* The engine is
  compiled to WASM and served as a static PWA that runs entirely in the browser,
  talking straight to the directory/queue — no local Rust server. Same engine
  code as native (feature-gating + `wireops` + a `Session` façade), native never
  regressed (125 tests). Six headless-Chrome suites cover it end to end. The
  staged path:
  - [x] **Stage 1 — pipeline + core crypto in-browser.** `crates/mycellium-wasm`
    (excluded from the native workspace) exposes `user_id` + device-key
    generation via `wasm-bindgen`; `clients/web` loads it. A headless-Chrome test
    proves the WASM `user_id` matches an independent SHA-256 and that keys come
    from real browser entropy. Build: `clients/web/build.sh`.
  - [x] **Stage 2 — browser I/O.** *(done)* **2a:** HTTP behind a
    `core::http::HttpTransport` trait; native `ureq` impl in `mycellium-http`;
    directory/queue clients hold `Box<dyn HttpTransport>` and compile to wasm32
    (ureq feature-gated). **2b:** a synchronous `XMLHttpRequest` transport + CORS
    on both servers — the in-browser WASM engine does a full directory login
    cross-origin against a real server. **2c:** an in-memory `Storage` (`MemStore`,
    the wasm counterpart to `FileStore`) plus a `Session` that snapshots to/from
    IndexedDB — state survives page reloads. All proven by headless-Chrome tests
    (`clients/rust/e2e/wasm*.test.mjs`).
  - [x] **Stage 3 — engine in the browser.** *(done)* **3a:** native-only parts
    (`app`, `platform`) feature-gated behind `native`; the generic modules
    compile to wasm32 and the real `history` module runs against the browser
    store (IndexedDB). **3b:** platform-agnostic sealing/opening extracted into an
    ungated `wireops` module (native fns are thin wrappers). **Networked:**
    `Session` now does `register`/`send`/`sync` — a headless-Chrome test delivers
    a full message **browser → real directory+queue → browser** (register, X3DH
    seal, queue deposit, collect, decrypt, history), same engine code as native.
    Five browser suites green.
  - [x] **Stage 4 — the PWA.** *(done)* `clients/web` is now a real static
    messenger (setup → username registration → threads → compose → send, polling
    to receive) driving the WASM `Session` — no local server. Identity persists
    across reloads (`Session.restore`); `manifest.json` + service worker make it
    installable/offline-capable. A two-user headless-Chrome test (isolated
    contexts) registers both through the UI and delivers a message Alice → real
    directory+queue → Bob's PWA. **"Open a link and message someone" works.**

- [ ] **T1.2 — Real-time delivery when open.** Replace 2s polling with a live
  channel (WebSocket/SSE) while the app is open — instant messages, far less
  load on the shared services. Keep Web Push for the closed case.

- [ ] **T1.3 — Multi-device.** People expect the same account on phone + laptop.
  Impossible without the seed today. Needs device-linking (QR) or email-based
  multi-device, with safety-number warnings.

- [~] **T1.4 — Web Push: verify + persist VAPID.** *(persist done)* The queue now
  loads its VAPID keypair from `MYCELLIUM_DATA/vapid.key` (0600), generating +
  persisting on first run — so the public key (browsers' `applicationServerKey`)
  is stable and existing subscriptions keep working across restarts. Verified the
  key is identical after a restart. *Left: confirm closed-app wake delivery on a
  real device (needs a real vendor push round-trip; can't be done headlessly).*

---

## Tier 2 — Reliability & scale hardening

- [~] **T2.1 — Anti-abuse.** *(email rate-limiting done)* The directory now
  fixed-window rate-limits `auth_start` — the endpoint that sends real email —
  **per caller wallet** (5/min) and **per recipient address** (3/min), so it
  can't be used as an SMTP spam/mailbox-bomb relay. **`publish`** is also
  rate-limited per wallet (30/min) to cap durable-storage-write spam. Test:
  `auth_start_is_rate_limited_per_email`. *Left: limits on login/challenge, Sybil
  resistance (proof-of-work/cost on claims), enumeration defenses, abuse
  reporting.*
- [~] **T2.2 — Observability.** *(logs + metrics done)* Both servers now expose a
  Prometheus `GET /metrics` (request + 4xx/5xx counters, labelled by service) and
  emit structured JSON access logs (`MYCELLIUM_LOG=1`; 5xx always logged) — via a
  shared dependency-free `mycellium-observe` crate. `GET /health` already exists.
  *Left: latency histograms, domain gauges (mailbox depth, bindings), alerting.*
- [ ] **T2.3 — Outbox coverage.** Retry currently only wraps 1:1 sends; extend to
  groups, receipts, and self-sync.
- [ ] **T2.4 — Load & scale testing.** Exercise the directory (designed to be
  cloned) and queue (per-user) under thousands of concurrent users; document the
  horizontal-scale story.
- [~] **T2.5 — Backpressure & limits.** *(body caps + mailbox caps done)* Both
  servers reject oversized request bodies with `413` before buffering them
  (directory 256 KiB, queue 1 MiB) — via `Content-Length` *and* a capped read, so
  a chunked/lying request can't exhaust memory either. Mailboxes are already
  capped (`MAX_MAILBOX`). *Left: per-IP connection limits, request timeouts,
  graceful shutdown.*

---

## Tier 3 — Trust

- [ ] **T3.1 — Independent crypto/security audit** before onboarding real users.
- [ ] **T3.2 — Moderation & safety at scale** — blocking, key-change warnings in
  the UI, reporting.
- [ ] **T3.3 — Large-group scalability** — fan-out is O(members × devices).

---

## Current focus

**Durability first, then the WASM/hosted PWA.** Nothing is safe to build on
in-memory state, and the WASM PWA is what turns "run a binary" into "open a
link." TLS, SMTP, and recovery land alongside, since real onboarding needs them.

Working order: **T0.1 + T0.2 (directory) → T0.1 + T0.2 (queue) → T0.4 → T0.3 →
T0.5 → T1.1 …**
