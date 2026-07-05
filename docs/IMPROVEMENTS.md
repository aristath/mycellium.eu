# Conceptual Gaps & Improvement Opportunities

A running, honest list of rough edges found while auditing the codebase against its
docs. The medium-severity correctness bugs and the security-relevant items from the
first pass have since been **fixed** (see below); what remains is low-severity,
self-healing, or a by-design trade-off. Separate from
[`PRODUCTION-READINESS.md`](PRODUCTION-READINESS.md) (the launch roadmap).

## ✅ Resolved

- **Group control messages now use the retry outbox.** `group_remove` and sender-key
  distribution deliver via `deliver_to_cluster_or_queue` / an outbox fallback, so a
  removal or re-key isn't silently lost on a transient failure.
  (`crates/mycellium-engine/src/app/grouping.rs`)
- **Browser `register` merges the device list.** Renaming/re-registering no longer
  drops a device a prior pairing added — both share a `publish_merged` helper
  that looks up the current record, appends this device, and bumps `seq`. Covered by
  `wasm-multidevice.test.mjs`. (`crates/mycellium-wasm/src/lib.rs`)
- **Deleted attachments are garbage-collected.** Applying a `Body::Delete` now also
  drops the message's `file:<id>` blob. (`crates/mycellium-wasm/src/lib.rs`)
- **Queue session tokens expire.** A `TOKEN_TTL` (24 h) with issue-time tracking +
  pruning on `verify`, and an expiry check on `deposit` — matching the directory.
  Test: `token_expires_after_ttl`. (`crates/mycellium-queue/src/lib.rs`)
- **Passphrase strength on creation.** New identities require ≥ `MIN_PASSPHRASE_LEN`
  (8) characters; unlocking an existing one is unchanged. (`crates/mycellium-storage/src/store.rs`)
- **Browser test hook gated to localhost.** `window.mycellium` (the engine handle for
  e2e tests) is exposed only on `localhost`/`127.0.0.1`, never on a real deployment.
  (`clients/web/index.html`)
- **Worker startup failures are legible.** A WASM-init or IndexedDB failure now
  rejects with a clear "engine failed to start" message. (`clients/web/worker.js`)

## Open (low severity / by design)

- **[low, self-healing] Group-invite ordering.** Out-of-order invites can briefly give
  asymmetric group read access; it resolves on the next `sync` (which is why the group
  test uses a `settle()` re-sync helper). A full-roster re-distribute would cure it but
  add O(N²) traffic per add — not worth it for small groups. (`crates/mycellium-wasm/src/lib.rs`)
- **[by design] `Ratchet::encrypt` panics without a sending chain.** This is a
  precondition guard (a responder must receive before it can send), with a clear
  message — not a reachable bug in normal flows. Left as an invariant rather than
  rippling a `Result` through the `no_std` core and every caller. (`crates/mycellium-core/src/ratchet.rs`)
- **[info] The device-link payload is the account seed.** Correctly UI-gated and
  warned. No change — called out so it's never treated casually.

## Open (design clarity — docs/refactor, not bugs)

- **`PeerId` encoding is transport-specific** (host:port for TCP, multiaddr for libp2p)
  but the type doesn't say so — document the contract or make it explicit.
- **No wire/group-state version story.** `wire::VERSION = 1` and `Group::export()` have
  no written forward/back-compat plan; write one before the format ever changes.
- **`app/session.rs` prints to stdout**, coupling handshake orchestration to a terminal;
  return the safety number/status as data for non-terminal shells.
- **`app/util.rs` mixes native-only and portable helpers** — move the env-reading ones
  behind the `native` gate so a portable module can't call them by mistake.
- **`MAX_FRAME` (1 MiB) isn't exported** from `mycellium-transport`; make it a `pub const`.

## Documentation

The README-vs-code drift found in the audit (missing crate READMEs, stale "in-memory
today" notes, undocumented endpoints, the `native` gating, `wireops`, `HttpTransport`)
was corrected across the crate READMEs, `ARCHITECTURE.md`, and the guides
(`QUICKSTART`, `BROWSER`, `SECURITY`, `GO-LIVE`, `CONTRIBUTING`). One real bug was fixed
en route: the `mycellium-server` banner advertised queue routes the directory doesn't serve.
