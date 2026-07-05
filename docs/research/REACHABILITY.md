# Native direct-P2P reachability & reachability scoring

*Design for issues [#59](https://github.com/aristath/messe/issues/59) (improve
native direct P2P reachability) and
[#60](https://github.com/aristath/messe/issues/60) (native peer reachability
scoring), both under parent [#48](https://github.com/aristath/messe/issues/48).
Research/design only — no code changes accompany this document.*

*Related: LAN discovery [#62](https://github.com/aristath/messe/issues/62) (see
[`LOCAL-DISCOVERY.md`](./LOCAL-DISCOVERY.md)), native product roadmap
[#74](https://github.com/aristath/messe/issues/74).*

---

## TL;DR / recommendation

Today a native message is delivered **directly** only when the recipient is
publicly reachable — a raw-TCP dial to the `host:port` in their record. Behind a
NAT or firewall (the common case) that dial fails and we fall back to the
store-and-forward **queue**. This document designs a **reachability ladder** that
tries progressively more capable (and more costly) direct techniques before
conceding to the queue, and a small **local-only scoring** module (#60) so the
ladder tries the most-likely-to-succeed path first instead of always paying a
dial timeout for a peer we already know is unreachable that way.

The recommendation, in order:

1. **Wire the Noise-authenticated libp2p transport into `deliver()` first.**
   [`app::messaging::deliver`](../../crates/mycellium-engine/src/app/messaging.rs)
   currently opens a raw-TCP
   [`net::TcpConnection`](../../crates/mycellium-transport/src/net.rs) and
   **skips** any `peer_id` that looks like a multiaddr
   (`!addr.starts_with('/')`). The whole
   [`libp2p_net`](../../crates/mycellium-transport/src/libp2p_net.rs) transport
   (TCP + Noise + Yamux) exists but is **not exercised on the send side**. Every
   technique below (hole punching, relay) is a libp2p behaviour, so this is the
   unavoidable first step. **Highest-value single change in the whole plan.**
2. **Add NAT traversal**: AutoNAT (learn whether we're reachable), STUN-style
   observed-address discovery, and **hole punching** (libp2p DCUtR) so two
   NATed peers can form a direct connection.
3. **Add relay fallback** (libp2p Circuit Relay v2) — a *live, still-E2E* stream
   through a third node, attempted **only after** direct fails, and kept
   distinct from the queue.
4. **Add per-peer, per-path reachability scoring** (#60) — a small engine module
   over [`Storage`](../../crates/mycellium-core/src/storage.rs), local-only,
   decaying, never published — that reorders the ladder per peer.
5. **Add a `DeliveryPath` outcome** the engine records and surfaces, so
   direct/relay/queue/outbox are distinguishable in logs and tests (#59
   acceptance criterion).

The invariant throughout: **every path is end-to-end authenticated** — the same
Noise handshake to the device key plus the pinned wallet-signed record. Relays
and STUN servers carry ciphertext they cannot read and cannot impersonate. The
untrusted **queue remains the guaranteed fallback**; direct P2P is strictly
best-effort optimization on top of it.

---

## 1. Background: how native direct delivery works today

### 1.1 The record and the two-step reach

A peer is a self-certifying, **wallet-signed**
[`SignedRecord`](../../crates/mycellium-core/src/record.rs). Its body lists one or
more [`Device`](../../crates/mycellium-core/src/record.rs)s; each device carries a
`device_key` (Ed25519, the basis of the libp2p `PeerId`), a `peer_id` field
("where to reach it" — either a raw `host:port` **or** a multiaddr
`/ip4/…/tcp/…/p2p/<peer-id>`), and the X3DH messaging keys. The **single wallet
signature covers the whole record**, so a dishonest directory can withhold or
stale a record but never forge one
([`SignedRecord::verify`](../../crates/mycellium-core/src/record.rs)).

Reaching a peer is: (1) **address + presence** from the directory
(`lookup(handle)` + `presence(handle)`), then (2) **connection** to the device's
`peer_id`.

### 1.2 The delivery ladder as it exists

[`app::messaging`](../../crates/mycellium-engine/src/app/messaging.rs) implements
the ladder. [`deliver`](../../crates/mycellium-engine/src/app/messaging.rs) is the
per-device rung:

```text
deliver(dir, handle, queue, device, item):
    if dir.presence(handle) == online:
        addr = utf8(device.peer_id)
        if addr non-empty AND NOT addr.starts_with('/'):   // raw host:port only
            net::TcpConnection::connect(addr)              // raw TCP, 10s timeout
            conn.send_frame(item)  → return delivered-live
    else / on failure:
        queue.deposit(slot, item)                          // store-and-forward
```

Above it: [`send`](../../crates/mycellium-engine/src/app/messaging.rs) fans one
sealed copy per recipient device and, when `deliver` returns false, parks the
copy in the encrypted
[`outbox`](../../crates/mycellium-engine/src/outbox.rs);
[`deliver_to_cluster`](../../crates/mycellium-engine/src/app/messaging.rs) /
[`deliver_to_cluster_or_queue`](../../crates/mycellium-engine/src/app/messaging.rs)
fan a group item across a cluster; and
[`flush_outbox`](../../crates/mycellium-engine/src/app/messaging.rs) retries the
parked entries on the next `send`/`inbox`.

So the effective ladder today is **direct-TCP → queue → outbox**.

### 1.3 The transports

- [`net.rs`](../../crates/mycellium-transport/src/net.rs) — raw framed TCP
  (`TcpConnection`, 4-byte length prefix, 1 MiB cap, 10 s connect / 30 s I/O
  timeouts). Carries the app-layer E2E payload, so it is a genuine direct line,
  but it is **not transport-authenticated**: TCP alone doesn't prove the remote
  holds the device key.
- [`libp2p_net.rs`](../../crates/mycellium-transport/src/libp2p_net.rs) —
  `Libp2pNode`: TCP + **Noise** + Yamux, `PeerId` derived from the **device
  key**, a `/mycellium/1.0` byte-stream protocol, an async swarm on a background
  Tokio runtime bridged to the sync `Connection` trait. `dial()` requires a
  `/p2p/<peer-id>` and the **Noise handshake proves the remote holds that
  device key's secret** — this is the transport-authentication the raw-TCP path
  lacks. Its own module doc already flags: *"NAT traversal (DHT, relay, DCUtR)
  is the next increment — the swarm is the place to add it, with no change to
  the app above."*
- **libp2p is pulled deliberately trimmed** — in
  [`Cargo.toml`](../../crates/mycellium-transport/Cargo.toml),
  `default-features = false` with only `["tokio", "tcp", "noise", "yamux",
  "macros", "ed25519"]`; DNS/mDNS/QUIC/UPnP are dropped to keep the audit
  surface small. Each NAT-traversal behaviour below (`autonat`, `dcutr`,
  `relay`, `identify`) is a **conscious, scoped re-expansion** of that surface
  and belongs behind explicit features.

### 1.4 Failure modes (the audit #59 asks for)

| Scenario | Today's outcome | Why |
|---|---|---|
| Peer publicly reachable / port-forwarded, online | **Direct** (raw TCP) | `host:port` dial succeeds |
| Peer behind NAT/firewall, online | **Queue** | Inbound dial to a NATed `host:port` fails → fallback |
| Peer advertises a **multiaddr** `peer_id` | **Queue** (skipped!) | `deliver` skips `addr.starts_with('/')` — libp2p never dialed |
| Peer offline | **Queue** → **Outbox** if queue absent/unreachable | expected |
| Peer online but presence stale/false-negative | **Queue** | never even attempts a dial |
| No queue published, unreachable directly | **Outbox** retry | last resort |

The dominant loss is rows 2 and 3: **most real peers are NATed**, and the one
transport that could authenticate a NAT-friendly multiaddr dial is precisely the
one `deliver` skips. Both are addressed below.

---

## 2. #59 — the reachability strategy

### 2.1 Design principles

- **Cheapest, most-likely path first; escalate only on failure.** Each rung
  costs latency (a dial timeout), traffic, and sometimes a third party. Never
  pay for a rung a cheaper one already satisfied.
- **Direct beats relay beats queue.** Relay is a live E2E stream but burdens a
  third node; the queue is store-and-forward. Prefer the leftmost that works.
- **Everything stays E2E-authenticated.** No rung weakens the trust model: Noise
  to the device key + record binding to the pinned wallet, on every path. STUN
  servers, relays, and the directory are all **untrusted infrastructure**
  handling ciphertext.
- **The queue is the guaranteed floor.** Direct P2P is best-effort; if the whole
  direct/relay ladder fails, store-and-forward still delivers. We are optimizing
  the *percentage delivered directly*, not replacing the safety net.

### 2.2 The ladder of techniques, cheapest → costliest

**Rung 0 — LAN direct (#62).** If local discovery has a cached multiaddr for a
device key in the recipient's record, dial it over Noise on the local link. No
directory, no queue, works offline. Designed in
[`LOCAL-DISCOVERY.md`](./LOCAL-DISCOVERY.md); it is the leftmost, cheapest rung
and feeds this same ladder.

**Rung 1 — direct dial of the published address (libp2p/Noise).** The
prerequisite fix: route multiaddr `peer_id`s through
[`libp2p_net`](../../crates/mycellium-transport/src/libp2p_net.rs) instead of
skipping them. For a publicly reachable or port-forwarded peer, or a peer whose
NAT happens to permit the inbound connection, this is a plain authenticated dial.
This alone recovers failure-mode row 3 above.

**Rung 2 — NAT traversal.** When the direct dial to the published address fails
because the peer is behind a NAT/firewall:

- **AutoNAT (reachability discovery).** libp2p `autonat`: peers tell each other
  *"I dialed the address you think you have — it worked / it didn't."* This lets
  a node learn whether it is **publicly reachable** at all. Cheap, and it decides
  *which* strategy is even worth attempting: a publicly-reachable node needs no
  traversal; a NATed one must hole-punch or relay. AutoNAT results also feed the
  scoring module (#60) — a node that learns it is private stops advertising a
  bare `host:port` as if it were dialable.
- **STUN-style observed-address discovery.** libp2p `identify` reports each
  peer the *observed* remote address it saw — the public `ip:port` the NAT
  mapped. This is the STUN function (learn your own public mapping) without a
  dedicated STUN server: any peer or relay we already talk to can tell us how we
  appear from outside. The observed address is what we then try to publish / use
  for hole punching.
- **Hole punching (DCUtR).** libp2p `dcutr` (Direct Connection Upgrade through
  Relay): two NATed peers, having established observed addresses, **simultaneously
  dial** each other's predicted public mappings so both NATs see the connection
  as outbound and permit it. DCUtR is **coordinated over a relay connection**
  (rung 3 provides the meeting point), then *upgrades* to a direct link. Works
  for the large class of **endpoint-independent (cone) NATs**; **fails for
  symmetric NATs** (the mapping differs per destination, so the predicted port is
  wrong) — for those, we stay on the relay. Be honest: hole punching is
  probabilistic and environment-dependent, not guaranteed.

**When to use which:** AutoNAT first (am I even NATed?). If publicly reachable →
rung 1 suffices. If NATed → obtain observed address (identify), establish a relay
connection (rung 3), attempt DCUtR (rung 2 hole punch); if it upgrades to direct,
great; if not, keep using the relay.

**Rung 3 — relay fallback (Circuit Relay v2).** libp2p `relay`: a third node
forwards an **end-to-end-encrypted** stream between two peers that cannot connect
directly. This is a **live** connection — real-time delivery, receipts, session
continuity — that merely transits a relay. Crucially:

- **Relay ≠ queue.** A relay forwards a *live E2E stream* between two
  simultaneously-online peers; it stores nothing and reads nothing (Noise
  terminates at the endpoints, the relay sees ciphertext). The **queue** is
  *store-and-forward*: it accepts sealed ciphertext for an **offline** recipient
  and holds it until they collect it. Relay keeps a peer "online-direct-ish";
  queue handles "offline."
- **Only after direct fails.** Relaying burdens a third node and adds a hop, so
  it is attempted only once rungs 1–2 are exhausted.
- **Still E2E-authenticated.** The relayed connection runs the same Noise
  handshake to the device key and the same record binding — the relay cannot
  impersonate either side.
- Relays can be community/self-hosted nodes; a peer advertising relay
  reservations could list them in its record (a future record extension) or they
  can be a small configured set. Relay selection and abuse-resistance (rate
  limits, reservations) are open questions (§7).

**Rung 4 — queue (store-and-forward).** Recipient offline or no live path
established: deposit the sealed
[`MailItem`](../../crates/mycellium-engine/src/groups.rs) into their queue
([`QueueTarget::deposit`](../../crates/mycellium-engine/src/app/messaging.rs)),
exactly as today. Guaranteed floor for an offline-but-has-a-queue peer.

**Rung 5 — outbox.** No queue reachable / none published: park the sealed item in
the local encrypted
[`outbox`](../../crates/mycellium-engine/src/outbox.rs) and retry on the next
`send`/`inbox`/`flush_outbox`. Last resort; unchanged.

### 2.3 The final ordering

```text
Rung 0  LAN direct (#62)              ┐
Rung 1  public/published direct dial  │  direct — Noise to device key, best
Rung 2  NAT-traversed (hole-punched)  ┘
Rung 3  relay (Circuit Relay v2)         live E2E stream via a third node
Rung 4  queue                            store-and-forward ciphertext (offline)
Rung 5  outbox                           local park + retry
```

All of rungs 0–3 are **live, E2E-authenticated direct-ish delivery** (Noise +
pinned wallet). Rungs 4–5 are the store-and-forward safety net. The scoring module
(#60, §3) decides the *starting rung and the order of attempts within the direct
band* per peer, so we don't blindly walk 0→5 every time.

---

## 3. #60 — reachability scoring

### 3.1 Problem

Walking the full ladder for every message is wasteful: a peer that is reliably
reachable only via relay should not eat a 10–30 s direct-dial timeout on every
send; a peer reliably direct should not be probed through a relay first. #60 asks
for a **local record of recent outcomes per peer/device/path** so the ladder
starts at the most-likely-successful rung — **without** skipping direct entirely
(the acceptance criterion: still *periodically* retry direct) and **without**
becoming shared metadata.

### 3.2 Data model

A per-**device** (keyed by `device_key`, since a cluster's devices differ in
reachability), per-**path** record:

```text
ReachabilityScore {
    device_key: DevicePublicKey,          // the specific device, not the account
    paths: map<DeliveryPath, PathStat>,
}

PathStat {
    successes: u32,
    failures: u32,
    last_success: u64,        // unix secs, 0 = never
    last_attempt: u64,
    last_latency_ms: u32,     // last successful dial/handshake time
    // derived, not stored: a decayed score (see §3.4)
}
```

`DeliveryPath` is the shared enum from §4 (`LanDirect`, `Direct`, `HolePunched`,
`Relay`, `Queue`, `Outbox`). Keying on the **device key** (not the handle) is
essential — a laptop may be relay-only while the same account's phone is direct —
and it aligns with the existing per-device `slot`/fan-out model in
[`send`](../../crates/mycellium-engine/src/app/messaging.rs).

### 3.3 How the ladder consults it

Before delivering to a device, the ladder computes an **ordering** of the direct
band (rungs 0–3) by decayed score, then appends the guaranteed floor
(queue → outbox):

- **Order attempts by recent success.** If `Relay` has a fresh `last_success` and
  `Direct` has only recent failures, try relay first — but see the next point.
- **Never fully abandon direct (acceptance criterion).** Even a
  known-unreachable-direct device is **periodically** re-probed on the cheaper
  rungs (e.g. once per *N* minutes or after the failure record decays past a
  threshold), because NAT mappings, networks, and port-forwards change. The score
  changes the *order and cadence*, never removes a rung permanently.
- **Skip obviously-doomed repeats (acceptance criterion).** Within a short window,
  a device with several consecutive `Direct` failures and zero successes is
  **deprioritized** so we don't pay its timeout on every message in a burst — we
  jump to the rung that recently worked, while still scheduling an occasional
  direct re-probe.
- **Cold start = today's behavior.** No score → try the full ladder in the
  default 0→5 order. Scoring only ever *reorders*; the absence of data is never
  worse than today.

This directly serves #59's acceptance criterion — *"queue fallback remains
available but is not the first choice for reachable peers"* — from the other
direction: a reachable peer's fresh direct score keeps it off the queue.

### 3.4 Storage, decay, aging

- **Where.** A new engine module, e.g. `reachability.rs`, over the
  [`Storage`](../../crates/mycellium-core/src/storage.rs) key-value trait,
  mirroring [`outbox`](../../crates/mycellium-engine/src/outbox.rs) and
  [`verified`](../../crates/mycellium-engine/src/verified.rs): a single
  `KEY = b"reachability"` blob, `load`/`save` via
  [`wire::encode`](../../crates/mycellium-core/src/wire.rs)/`decode`, a
  `record_outcome(device_key, path, ok, latency, now)` mutator, and an
  `order_paths(device_key, now) -> Vec<DeliveryPath>` query the ladder calls.
- **Decay.** Raw counts must not accrue forever (a device direct-reachable a year
  ago is not evidence today). Age the influence of an observation by its
  recency — e.g. weight a success/failure by `exp(-Δt / half_life)` when scoring,
  or simpler: treat any `last_success` older than a TTL (say 24 h) as "stale,
  re-probe." Reuse the pattern already in
  [`outbox`](../../crates/mycellium-engine/src/outbox.rs) (`TTL_SECS`,
  `is_expired`) for consistency.
- **Bounded size.** Prune device entries not touched within a TTL and cap the
  total, so the store can't grow without bound (same discipline as the outbox).

### 3.5 Privacy — must not become a presence oracle

This is the delicate part and #60's hard acceptance criterion (*"Reachability
state is local and does not become shared infrastructure metadata"*):

- **Local-only, never published.** The score lives in this device's
  [`Storage`](../../crates/mycellium-core/src/storage.rs) and is **never** put in
  a [`Record`](../../crates/mycellium-core/src/record.rs), sent to the directory,
  the queue, or any peer. It is a private cache of *my* observations, like the
  outbox.
- **Not a covert presence oracle.** A naive "last time I reached Alice directly"
  log is a **social-graph + presence-history** artifact: it reveals who I talk to,
  when they were online, and their network movements. Mitigations:
  - **Store outcomes, not a timeline.** Keep aggregate counts + a single
    `last_success` per path, **not** a per-message history — enough to order the
    ladder, not enough to reconstruct a presence log.
  - **Coarse timestamps.** `last_success` at minute/hour granularity, not
    millisecond, blunts fine-grained presence inference if the store is later
    read by malware.
  - **Encrypt at rest with the rest of engine state** (it lives alongside the
    already-sensitive outbox/history under the same at-rest protection —
    [#65](https://github.com/aristath/messe/issues/65) native secure storage).
  - **No cross-peer correlation surface.** The module exposes only
    per-device order/record calls; it never aggregates "who is online now"
    across peers into a queryable presence view.
  - **User-clearable.** Like history/blocklist, the score store can be wiped; it
    is derived data, never authoritative.
- **Honest one-liner:** *"Your device remembers how it last reached each contact
  so it doesn't waste time on dead paths — this memory is private, never
  uploaded, and stores only 'did this path work recently,' not a log of when
  people were online."*

---

## 4. Observability — the `DeliveryPath` outcome

#59 requires the delivery path be **observable in logs/test output**, and #60
needs it as the scoring key. One shared type serves both:

```text
enum DeliveryPath {
    LanDirect,     // rung 0 — discovered LAN multiaddr, Noise
    Direct,        // rung 1 — published address, Noise
    HolePunched,   // rung 2 — DCUtR-upgraded direct
    Relay,         // rung 3 — Circuit Relay v2 live stream
    Queue,         // rung 4 — deposited store-and-forward
    Outbox,        // rung 5 — parked locally for retry
    Failed,        // nothing worked this pass
}
```

- **Return it from the ladder.** Today
  [`deliver`](../../crates/mycellium-engine/src/app/messaging.rs) returns a bare
  `bool`. Change it to return a `DeliveryPath` (or `DeliveryOutcome { path,
  latency_ms }`); `send`/`broadcast`/`deliver_to_cluster*`/`flush_outbox` map
  "any live/queue path" to their existing delivered/parked logic, and additionally
  (a) feed it to `reachability::record_outcome` and (b) surface it.
- **Surface it.** The existing user-facing lines already hint at counts
  (*"sent to 'x' — 2/3 device(s)"*); extend with the path
  (*"2 direct, 1 relayed"* / *"1 queued"*). Structured log/trace at `debug` for
  diagnostics; a per-path counter for tests to assert on.
- **Tests assert on the enum, not on network side-effects.** e.g. "reachable peer
  → `Direct`", "NATed peer with a working relay → `Relay`", "offline peer →
  `Queue`", "no queue → `Outbox`" — matching #59's requested end-to-end test
  matrix.

---

## 5. Testability — honest about the boundary

### 5.1 Unit-testable in-repo (no real network)

- **Ladder ordering given a scoring state.** Feed a fabricated
  `ReachabilityScore` and assert `order_paths` produces the expected sequence
  (fresh-direct → direct first; stale-direct + fresh-relay → relay first but
  direct still scheduled for periodic re-probe; cold start → default 0→5).
- **Score update & decay.** `record_outcome` bumps the right counters/timestamps;
  a success older than TTL is treated as stale; pruning bounds the store. Pure
  functions over [`Storage`](../../crates/mycellium-core/src/storage.rs) — mirror
  the existing `MemStore` tests in
  [`outbox.rs`](../../crates/mycellium-engine/src/outbox.rs).
- **Path selection / fallback logic.** With a mockable dialer, assert that a
  direct failure escalates to relay then queue then outbox, and that
  `DeliveryPath` is reported correctly for each outcome.
- **`DeliveryPath` plumbing.** `deliver`'s outcome maps correctly into
  `send`'s delivered/queued counts and the scoring update.
- **libp2p loopback smoke.** The existing
  [`two_nodes_stream_a_message`](../../crates/mycellium-transport/src/libp2p_net.rs)
  test already proves Noise dial + framed stream on loopback; extend with a
  relay-on-loopback test once `relay` is wired (both peers + relay on
  `127.0.0.1`, assert the stream transits).

### 5.2 NOT unit-testable — needs a real multi-NAT harness

**Actual hole punching cannot be tested on loopback or in CI honestly.** DCUtR
success depends on real NAT behaviour (cone vs symmetric, mapping timeouts,
firewall state) that a single-host test cannot reproduce. Verifying it requires a
**network harness with real/emulated NATs** — e.g. containers/network namespaces
with `iptables` NAT rules of different types, or multi-host cloud runners behind
distinct NATs. This is integration/infra work, out of the unit suite, and its
results are **probabilistic** (a given NAT pair either punches or doesn't). We
should:

- Build a **manual/opt-in NAT test matrix** (analogous to the interop matrix in
  recent contentless-push QA), documenting which NAT combinations we verified
  hole-punch vs fall back to relay.
- Keep CI honest: unit-test the *decision logic and fallback*, integration-test
  *relay on loopback*, and mark true hole-punch verification as **manual, real
  network**. Do not fake a NAT in a unit test and claim traversal coverage.

---

## 6. Phased plan, first steps, per-crate footprint

### 6.1 Phases (each independently shippable)

**Phase 0 — this document.** Agree the ladder, the E2E-on-every-path invariant,
the local-only/non-oracle scoring posture.

**Phase 1 — wire libp2p into delivery (the foundation).**
- Route multiaddr `peer_id`s in
  [`deliver`](../../crates/mycellium-engine/src/app/messaging.rs) through
  [`libp2p_net`](../../crates/mycellium-transport/src/libp2p_net.rs) (Noise) and
  apply the record-binding trust check; keep raw-TCP for legacy `host:port`.
- Introduce `DeliveryPath` and thread it through the ladder + user output
  (§4). Add the unit tests for ordering/outcome mapping.
- *Ships value immediately:* recovers failure-mode row 3 (multiaddr peers now
  dialed) and makes delivery observable — with **no** new NAT dependency.

**Phase 2 — reachability scoring (#60).**
- New `reachability.rs` engine module over
  [`Storage`](../../crates/mycellium-core/src/storage.rs); `record_outcome` +
  `order_paths` + decay/prune. Ladder consults it. Local-only, non-oracle (§3.5).
- Unit tests: update, decay, ordering, periodic-re-probe, privacy shape.

**Phase 3 — NAT traversal.**
- Enable `identify` + `autonat` (observed address + reachability) behind features;
  learn public mapping and NAT status, feed scoring.
- Enable `dcutr` + `relay` (client side) behind features; implement rung 2/3.
- Relay-on-loopback integration test; manual NAT matrix for real hole punching.

**Phase 4 — relay operation & selection.**
- Relay discovery/reservation, self-hosted relay support, abuse-resistance
  (rate limits, reservations). Open questions in §7.

### 6.2 Concrete first steps (in order)

1. Change [`deliver`](../../crates/mycellium-engine/src/app/messaging.rs) to
   return `DeliveryPath` and route multiaddr `peer_id`s through
   [`libp2p_net`](../../crates/mycellium-transport/src/libp2p_net.rs) with the
   record-binding check (**the single highest-value change**).
2. Add the `DeliveryPath` enum + surface it in `send`/`broadcast` output and a
   test-observable counter.
3. Scaffold `reachability.rs` (data model + `record_outcome`/`order_paths` + the
   `MemStore` unit tests) and have the ladder consult it.

### 6.3 Per-crate change footprint

- **[`mycellium-transport/Cargo.toml`](../../crates/mycellium-transport/Cargo.toml)**
  — new **opt-in features** (`autonat`, `dcutr`, `relay`, `identify`) enabling the
  corresponding `libp2p` features; **not** in `default`, documented as a scoped
  re-expansion of the trimmed audit surface (as the existing comment does for
  DNS/mDNS/QUIC/UPnP).
- **[`mycellium-transport/src/libp2p_net.rs`](../../crates/mycellium-transport/src/libp2p_net.rs)**
  — behind those features, add `identify`/`autonat`/`dcutr`/`relay` behaviours to
  the `SwarmBuilder`; expose observed-address + NAT-status + relay-reservation to
  the engine; add a relay-dial / hole-punch-attempt API alongside `dial`. No
  change to the `Connection` bridge above — same framed streams.
- **[`mycellium-engine/src/app/messaging.rs`](../../crates/mycellium-engine/src/app/messaging.rs)**
  — `deliver` returns `DeliveryPath`, routes multiaddrs through libp2p, walks the
  rung order from scoring, escalates direct → relay → queue → outbox, records the
  outcome. `send`/`broadcast`/`deliver_to_cluster*`/`flush_outbox` map the new
  outcome to their existing logic + surface the path.
- **`mycellium-engine/src/reachability.rs`** *(new)* — the scoring module over
  [`Storage`](../../crates/mycellium-core/src/storage.rs) (§3), modeled on
  [`outbox.rs`](../../crates/mycellium-engine/src/outbox.rs) /
  [`verified.rs`](../../crates/mycellium-engine/src/verified.rs).
- **CLI/TUI** — show delivery path in send output; optionally a `reachability`
  inspect/clear command.
- **No changes to** [`record.rs`](../../crates/mycellium-core/src/record.rs) or
  the wire format for Phases 1–3 (multiaddrs already fit `peer_id`; relay
  addresses in records are a Phase 4 extension). No new signed object.

---

## 7. Open questions

- **Relay selection & trust.** Where do relays come from — a configured set,
  self-hosted, advertised in records? How do we resist a malicious relay (it can
  DoS/observe timing but not read ciphertext) and relay abuse (rate limits,
  reservations)?
- **Symmetric-NAT reality rate.** What fraction of real peer pairs fail DCUtR and
  must relay? Drives how much relay capacity matters.
- **Re-probe cadence (#60).** How often to re-attempt a known-dead direct path —
  fixed interval, exponential, or network-change-triggered? Trade-off: freshness
  vs wasted timeouts.
- **Scoring granularity vs privacy.** Coarser timestamps leak less but order the
  ladder less well — where is the line so it never becomes a presence log (§3.5)?
- **Presence signal from dialing.** Attempting a direct/hole-punch dial reveals
  we tried to reach a peer (a minor presence hint, as in
  [`LOCAL-DISCOVERY.md`](./LOCAL-DISCOVERY.md) §5). Acceptable, but note it.
- **AutoNAT reflexivity.** AutoNAT needs peers willing to dial us back; in a
  sparse network that may be scarce — do we need dedicated AutoNAT/relay helpers?

---

## 8. Cross-links

- Parent roadmap: **[#48](https://github.com/aristath/messe/issues/48)** — native
  privacy, metadata minimization, trust model.
- **[#59](https://github.com/aristath/messe/issues/59)** — improve native direct
  P2P reachability (the ladder, §2, §4, §5).
- **[#60](https://github.com/aristath/messe/issues/60)** — native peer
  reachability scoring (§3).
- **[#62](https://github.com/aristath/messe/issues/62)** /
  [`LOCAL-DISCOVERY.md`](./LOCAL-DISCOVERY.md) — LAN discovery, rung 0 of this
  ladder and a co-located input to it; shares the "wire multiaddrs through
  libp2p" prerequisite.
- **[#74](https://github.com/aristath/messe/issues/74)** — native product
  roadmap; direct reachability + scoring are delivery dependencies under it, and
  at-rest protection of the score store depends on native secure storage
  ([#65](https://github.com/aristath/messe/issues/65)).
- Repo code: [`app::messaging`](../../crates/mycellium-engine/src/app/messaging.rs)
  (the ladder), [`libp2p_net`](../../crates/mycellium-transport/src/libp2p_net.rs)
  (the Noise transport where traversal behaviours live),
  [`net`](../../crates/mycellium-transport/src/net.rs) (raw TCP),
  [`outbox`](../../crates/mycellium-engine/src/outbox.rs) /
  [`verified`](../../crates/mycellium-engine/src/verified.rs) (the storage-module
  pattern the scoring module follows),
  [`record`](../../crates/mycellium-core/src/record.rs) (device addresses).
