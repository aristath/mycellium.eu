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

- [ ] **T0.5 — Account recovery.** The seed phrase was dropped; email is the
  recovery *hook* but the recover-on-a-new-device flow doesn't exist. Device
  loss = permanent account loss.
  - *Approach:* re-verify the email → re-bind the username id to the new device's
    key → surface a "safety number changed" warning to contacts.

---

## Tier 1 — Seamlessness (hitches users would feel)

- [ ] **T1.1 — Consumer distribution (WASM PWA).** Today a user must run a local
  Rust server and open `localhost` — not consumer-grade. Compile the engine to
  WASM and serve the PWA over HTTPS so it runs entirely in the browser, talking
  straight to the directory/queue. **Biggest single unlock.** Staged, because the
  engine couples blocking `ureq` + `std::fs` into each function:
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
  - [~] **Stage 3 — engine in the browser.** *(3a + 3b done)* **3a:** the
    engine's native-only parts (`app`, `platform`) are feature-gated behind
    `native`; its generic modules compile to wasm32, and the real `history`
    module runs against the browser store (persists to IndexedDB). **3b:**
    extracted the platform-agnostic sealing/opening into an ungated `wireops`
    module (native fns are thin wrappers) — the browser now does **real X3DH +
    Double Ratchet**: two in-browser Sessions encrypt/decrypt a message, sender
    identity recovered from the signed record, non-recipient blocked. *Left:
    wire send/receive to the live directory+queue (networked), then the PWA.*
  - [ ] **Stage 4 — port the PWA** off the local server; ship as a static HTTPS
    PWA.

- [ ] **T1.2 — Real-time delivery when open.** Replace 2s polling with a live
  channel (WebSocket/SSE) while the app is open — instant messages, far less
  load on the shared services. Keep Web Push for the closed case.

- [ ] **T1.3 — Multi-device.** People expect the same account on phone + laptop.
  Impossible without the seed today. Needs device-linking (QR) or email-based
  multi-device, with safety-number warnings.

- [ ] **T1.4 — Web Push: verify + persist VAPID.** Confirm closed-app wake on a
  real device; persist the VAPID keypair so subscriptions survive queue
  restarts.

---

## Tier 2 — Reliability & scale hardening

- [ ] **T2.1 — Anti-abuse.** Free account creation = Sybil; no directory rate
  limits; name/email enumeration; weak spam defenses. Add rate limiting,
  proof-of-work or cost on claims, and abuse reporting.
- [ ] **T2.2 — Observability.** Structured logs, metrics, health/readiness
  probes, alerting. Production is blind without it.
- [ ] **T2.3 — Outbox coverage.** Retry currently only wraps 1:1 sends; extend to
  groups, receipts, and self-sync.
- [ ] **T2.4 — Load & scale testing.** Exercise the directory (designed to be
  cloned) and queue (per-user) under thousands of concurrent users; document the
  horizontal-scale story.
- [ ] **T2.5 — Backpressure & limits.** Mailbox caps, connection limits, request
  timeouts, graceful shutdown.

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
