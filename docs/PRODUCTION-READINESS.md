# Production Readiness

*What stands between the current working prototype and a service thousands of
people can use seamlessly and reliably.* Ordered by priority. Check items off as
they land.

The protocol and crypto are sound; the gaps are **durability, concurrency,
deployment shape, and the operational essentials** around them.

---

## Tier 0 — Blockers (cannot serve real users without these)

- [ ] **T0.1 — Durable storage.** The directory and queue keep all state in
  in-memory `HashMap`s. A restart wipes every account (names, records, email
  bindings) and every queued message + push subscription.
  - *Persist:* directory `bindings`, `records`, `emails`, `pepper`; queue
    `mailboxes`, push `subs`.
  - *Keep in-memory (ephemeral, fine to lose):* login challenges, session
    tokens, presence, rate counters, pending email codes.
  - *Approach:* embedded pure-Rust store (`redb`) for the first durable version;
    load on startup, write-through on change. Move to Postgres for multi-node.

- [ ] **T0.2 — Concurrency.** `tiny_http`'s loop serves one request at a time;
  thousands of clients polling + sending will serialize into unusable latency.
  - *Approach:* a worker-thread pool sharing `Arc<Server>` (each thread calls
    `recv()`), with the state behind a `Mutex`/pool. Keep push sends off the
    lock (already done).

- [ ] **T0.3 — TLS / HTTPS.** Service workers, Web Push, PWA install, and basic
  security all require HTTPS off `localhost`. Everything is `http://` today.
  - *Approach:* terminate TLS at a reverse proxy (nginx/caddy) in front of the
    directory/queue, or add rustls to the servers. Document the deploy.

- [ ] **T0.4 — Real email sending.** Signup verification codes are logged, not
  emailed (`deliver_email` is a dev stub). Nobody can actually register.
  - *Approach:* pluggable sender; SMTP implementation (self-hosted, **never** a
    US SMS/email gateway). Gate `dev_code` off when SMTP is configured.

- [ ] **T0.5 — Account recovery.** The seed phrase was dropped; email is the
  recovery *hook* but the recover-on-a-new-device flow doesn't exist. Device
  loss = permanent account loss.
  - *Approach:* re-verify the email → re-bind the username id to the new device's
    key → surface a "safety number changed" warning to contacts.

---

## Tier 1 — Seamlessness (hitches users would feel)

- [ ] **T1.1 — Consumer distribution (WASM PWA).** Today a user must run a local
  Rust server and open `localhost` — not consumer-grade. Compile the engine to
  WASM (the core is already `no_std`) and serve the PWA over HTTPS so it runs
  entirely in the browser, talking straight to the directory/queue. (Native apps
  are the alternative.) **Biggest single unlock.**

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
