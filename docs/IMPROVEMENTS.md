# Conceptual Gaps & Improvement Opportunities

A running, honest list of rough edges found while auditing the codebase against its
docs — things that are correct enough today but worth hardening. Ordered by area,
tagged by rough severity. This is deliberately separate from
[`PRODUCTION-READINESS.md`](PRODUCTION-READINESS.md) (the launch checklist): these
are *refinements*, not blockers, unless noted.

## Correctness & delivery reliability

- **[med] Group control messages bypass the outbox.** `group_remove` and key
  re-distribution deliver over direct cluster send (`deliver_to_cluster`), not the
  retrying `deliver_to_cluster_or_queue`. On a transient failure a member may never
  learn they were removed, or never receive the rotated key. *Fix:* route
  `GroupRemove` and key distribution through the outbox like group text.
  (`crates/mycellium-engine/src/app/grouping.rs`)

- **[med] Browser `register` resets to a single device.** After `link_device`
  merges a sibling into the record, any later `register` (e.g. renaming in Settings)
  republishes with only the current device, dropping the others. *Fix:* have the
  browser `register` (and `link_device`) merge the existing device list before
  publishing — the merge logic already exists in `link_device`.
  (`crates/mycellium-wasm/src/lib.rs`)

- **[low] Group-invite ordering can give asymmetric access.** When invites arrive
  out of order, a node distributes its key only to detected *newcomers*, so two
  devices can briefly read each other unequally until both invites settle. *Fix:*
  re-distribute to the full roster on membership change, or track a "last-synced
  roster." (`crates/mycellium-wasm/src/lib.rs`, `handle_group_invite`)

- **[low] `Ratchet::encrypt` panics if `can_send()` is false.** It `expect`s an
  established sending chain rather than returning an `Err`. Callers must pre-check.
  *Fix:* return a `Result` so misuse is a recoverable error, not a panic.
  (`crates/mycellium-core/src/ratchet.rs`)

- **[low] Deleted attachments aren't garbage-collected.** A `Body::Delete`
  tombstones the message but leaves its `file:<id>` data URL in the store, growing it
  unboundedly. *Fix:* drop the `file:*` entry when applying a delete.
  (`crates/mycellium-wasm/src/lib.rs`, `apply_to_history`)

- **[low] Worker init failure is silent.** If WASM `init()` or the IndexedDB open
  fails, the worker's `ready` promise rejects and every RPC hangs or rejects
  cryptically. *Fix:* surface a single "engine failed to start" message to the UI.
  (`clients/web/worker.js`)

## Security & privacy

- **[med] No passphrase-strength policy.** `mycellium-storage` accepts a 1-character
  passphrase for the at-rest identity; Argon2id is the only guard. *Fix:* enforce a
  minimum length / warn on weak input. (`crates/mycellium-storage/src/store.rs`)

- **[low] Queue session tokens never expire** (the directory's do, after 24 h), so
  they accumulate until restart. *Fix:* add a TTL + pruning to match the directory.
  (`crates/mycellium-queue/src/lib.rs`)

- **[low] Browser test hooks expose the full engine on `window`.** `window.mycellium`
  exposes the `Session` class + RPC for e2e tests; any script in the origin can call
  it. Intended for tests, but should be gated out of a production build.
  (`clients/web/index.html`)

- **[info] The device-link payload is the account seed.** Correctly UI-gated and
  warned, but inherently the account's full read/write key. No change needed; called
  out so it's never treated casually (e.g. logged, or shown outside the link flow).

## API & design clarity

- **[low] `PeerId` format is transport-specific** (host:port for TCP, multiaddr for
  libp2p) but the type doesn't say so; mixing transports could confuse it. *Fix:*
  document the contract, or make the encoding explicit. (`crates/mycellium-core/src/identity.rs`)

- **[low] No wire/group-state version story.** `wire::VERSION = 1` and
  `Group::export()` have no documented forward/backward-compat or migration plan.
  *Fix:* write down the versioning strategy before the format ever changes.
  (`crates/mycellium-core/src/wire.rs`, `group.rs`)

- **[low] `app/session.rs` prints to stdout.** Handshake helpers print safety numbers
  and status directly, coupling orchestration to a terminal. *Fix:* return these as
  data so non-terminal shells can render them. (`crates/mycellium-engine/src/app/session.rs`)

- **[low] `app/util.rs` mixes native-only and ungated helpers.** Env-reading helpers
  (`own_name`, `own_queue`) sit beside portable ones; a portable module could call
  one by mistake. *Fix:* move native-only helpers into a gated submodule.

- **[nit] `MAX_FRAME` (1 MiB) isn't exported** from `mycellium-transport`, so callers
  hardcode the limit. *Fix:* make it a `pub const`.

## Documentation (addressed in this pass)

The README-vs-code drift found during the audit — missing crate READMEs
(`http`/`observe`/`wasm`/`clients-web`), stale "in-memory today" notes, undocumented
endpoints (auth, push, metrics), the `native` feature gating, `wireops`, and the
`HttpTransport` abstraction — has been corrected across the crate READMEs,
`ARCHITECTURE.md`, and the new guides (`QUICKSTART`, `BROWSER`, `SECURITY`,
`GO-LIVE`, `CONTRIBUTING`). One real bug was fixed en route: the `mycellium-server`
startup banner advertised queue routes (`/mailbox/...`) the directory doesn't serve.
