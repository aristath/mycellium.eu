# Mycellium core implementation review — 2026-07

A complete **engineering** review of the core (clients secondary), across four lenses:
architecture & module design, API/code quality & idiom, performance & efficiency, and
testing/maintainability/operability. Security is reviewed separately in
[`CORE-REVIEW-2026-07.md`](CORE-REVIEW-2026-07.md). Method: four parallel deep reviewers,
one per lens, grounded in `file:line`; findings prioritized P1 (should fix) / P2 (worth
doing) / P3 (nit).

## Verdict

**This is strong, production-grade Rust — not a POC wearing production clothes.** The
foundation is genuinely well-built and all four reviewers converged on the same praise:
`mycellium-core` is a model `no_std` crate (clean port traits, thorough `Zeroize`/`Drop`,
fail-closed crypto, validated newtypes); `deliver_ladder` is exemplary pure-logic-with-IO-at-
the-edges; the test suite asserts *real behavior* with deliberately-engineered non-vacuity;
every in-memory server map is bounded + pruned; startup fails closed and HTTP shuts down
gracefully; and the docs explain *why* and are accurate rather than aspirational.

The weaknesses are **systemic but shallow — consistency, duplication, and operability, not
correctness of the foundation.** They cluster in four themes:

1. **The delivery orchestration is triplicated and has diverged** (the dominant issue).
2. **Service auth/session scaffolding is duplicated 4×**; only the HTTP *runtime* was shared.
3. **The persistence layer rewrites whole collections and fsyncs under the global lock** —
   the real scaling risk.
4. **Operability under failure is thin** — a mutex-poison cascade, no structured logging,
   silent push death.

---

## The dominant theme: triplicated, diverged orchestration

The send fan-out ("seal per recipient device → `MailItem::Direct` → deposit") and the receive
dispatch (`match MailItem { … }`) exist in **three independent copies**: the engine
(`app/messaging.rs` `send`/`process_item`), the SDK (`client.rs` `deliver_app`/`process_blob`
— its own comments say "mirrors the engine's `process_item`"), and wasm (`wasm/lib.rs`). They
have **already drifted**:

- The **engine** ladder does live P2P push (TCP/libp2p) + reachability scoring + relay-path
  labeling (#59) + self-sync + outbox parking.
- The **SDK and wasm** `deliver_app` do **queue-deposit only** — no live push, no scoring, no
  relay, no outbox.

So a directly-reachable peer is delivered *live* by the CLI but *always queue-routed* by the
native apps and the browser — and the relay work reaches only one of the three clients. This
is an honest correction to the earlier "SDK proven through three languages": the languages are
proven, but each **reimplements** the orchestration rather than sharing it.

**Root cause:** the engine `app/*` — documented as "the headless engine, no terminal UI" — is
actually a **CLI command layer**: 105 `println!`/`eprintln!`, reads `MYCELLIUM_*` env vars
directly (`app/util.rs`), and loads identity via `store::load_identity()` which **prompts for a
passphrase on the TTY** (`storage/store.rs`). A library binding can't block on a terminal prompt
or print to stdout, so it's `native`-gated and unusable as a library — which *forced* the
copies. The team already knows the right pattern: `wireops.rs` takes `Platform` + name/queue as
args (no env, no print) and compiles to wasm unchanged; the orchestration just didn't follow it.

**Fix (highest-leverage in the workspace):** extract a platform-generic `engine::flow` layer
parameterized over `Platform`/`Storage`/`HttpTransport` + the directory/queue clients, returning
**structured results** and taking an outcome sink instead of `println!`. The CLI, SDK, and wasm
then become thin adapters. This single refactor unifies live delivery + relay across all clients.

---

## P1 — should fix

1. **Unify the triplicated orchestration + de-CLI-ify the engine** (above). `app/messaging.rs`,
   `sdk/client.rs:1041,1347`, `wasm/lib.rs`. Also lifts the SDK/wasm clients to live delivery + relay.
2. **`ratchet.rs` `try_skipped` is not fail-closed** (correctness). `try_skipped` does
   `self.skipped.remove(pos)` **before** `aead_decrypt(...)?`, so ordinary corruption of one
   out-of-order copy consumes the banked key and the later *correct* copy can never decrypt —
   the exact bug the main-path fix (clone-then-commit, `ratchet.rs:169`) closed, still present on
   the skipped-key path. Fix: peek → decrypt → `remove` + zeroize only on success. (Related:
   `ratchet.rs:138 encrypt` and `record.rs:96 primary()` still `panic`/`expect` on states a
   caller can reach — return `Result`/`Option`; see the security review's LOW items.)
3. **Duplicated service auth/session scaffolding (SIWE handshake duplicated 4×).** The directory
   and queue each re-implement `challenge`/`verify`/`authed` with identical TTL/token/rate
   constants, a byte-identical `ApiError`+`IntoResponse`, the `ok`/`parse`/`bearer` helpers, the
   rate limiter, and the redb/`MYCELLIUM_DATA` loader; the two client crates copy-paste an
   identical `json`/`call`/`login` + the four auth DTOs. Add a **`mycellium-service-kit`** crate
   (session state machine, `HttpError` trait + blanket `IntoResponse`, helpers, durable-open) and
   a shared `JsonHttpClient` in `mycellium-http`. `mycellium-serve` shared only the runtime.
4. **fsync inside the global `Mutex`, on the tokio worker** (scaling). Every directory/queue
   handler holds `std::sync::Mutex<State>` across the redb `commit()` (a durable fsync), on an
   async worker with no `spawn_blocking` — so throughput is capped at ~1/fsync-latency and a slow
   disk stalls the runtime. The push fan-out already does the right thing off-lock; the store
   write doesn't. Fix: lock only to mutate the map + capture what to persist, drop the lock, then
   commit via `spawn_blocking` (optionally group-commit).
5. **Mutex-poison cascade → total outage.** Every handler `.lock().unwrap()`s and `mycellium-serve`
   installs no `CatchPanicLayer`, so one handler panic poisons the lock → every later request 500s
   until restart, while `/health` still returns 200. Fix: `CatchPanicLayer` + poison-tolerant locks
   (`parking_lot`, or `unwrap_or_else(|e| e.into_inner())`). ~10 lines, kills the class.
6. **No structured logging + silent push death.** Zero `tracing`/`log` in `crates/*/src`; the push
   fan-out discards every result except pruning `Gone` subs, so if APNs/FCM/WebPush is down,
   notifications stop with **no log and no metric** while the queue reports healthy. Fix: adopt
   `tracing` as the spine; add `mycellium_push_send_failures_total` + `warn!` on push/storage errors.
7. **O(n²) persistence rewrites.** Queue `deposit` re-serializes + re-fsyncs the *entire* mailbox
   (`lib.rs:384` → `persist.rs:62`) per message; history `append` re-encodes + re-encrypts + rewrites
   the *entire* transcript file (`history.rs:98`, `filestore.rs:83`) per message. Both are O(n²) over
   a mailbox/thread's life. Fix: per-blob mailbox keys (deposit O(1), collect = range drain); chunked
   transcript segments so appends touch only the tail.

## P2 — worth doing

- **KV-blob persistence duplicated ~11× with inconsistent corruption policy** (`history`/`contacts`/
  `outbox`/`inbound`/`verified`/`blocklist`/`draft`/`names`/`expiry`/`groups`). Some route through
  `decode_or_warn` (preserves corrupt bytes loudly); others silently `.ok()` — **silently discarding
  corrupt state**. Introduce a typed `KvBlob<T>`/`KvMap<T>` helper to unify the policy.
- **`seal_to` re-signs the sender record once per *device*** instead of once per *send* — ~2·N ECDSA
  signs per send (`wireops.rs:139`). Build + sign the embedded record once per send, clone into each
  envelope; cache the (invariant) pre-key signature.
- **`opt-level="z"` applied to the server binaries.** Right for the embedded/wasm core, but the
  directory/queue/relay do ECDSA/AEAD/postcard in hot loops where `opt-level=3` is 1.5–3× faster at
  irrelevant size cost. Per-package profile override.
- **Error-handling inconsistency (4 strategies, no `thiserror`) + swallowing.** Core `enum Error`,
  engine `anyhow` (80 refs, incl. library-ish helpers the SDK re-wraps), SDK `SdkError`, services
  `ApiError` + stringly `Result<Self, String>`. Swallows that hide failures: `client.rs:982
  export_backup` returns `Vec<u8>` swallowing read errors (a partial backup looks like success);
  `client.rs:366 sync` `unwrap_or_default()` after login (network error ≡ "no mail"); `set_setting`
  `let _ = put`. Pick a principled boundary (typed at lib edges, `anyhow` in shells); make these
  three return `Result`. Also: `SdkError::crypto(format!("{e:?}"))` ×9 — use `Display`.
- **Stringly-typed JSON at the SDK's pairing/card boundary** (`client.rs:622,636,731,1160` — magic
  keys `"ws"`/`"h"`/`"n"`, manual `as_str().ok_or`). Replace with serde structs (`ContactCard`,
  `PairingOffer`, `Provisioning`) so a typo can't compile.
- **Context-struct smell + blanket `#![allow(clippy::too_many_arguments)]` on 9 engine modules.**
  `distribute_key(8 args)`/`send(11 args)`/the `deliver` family carry the same bundle repeatedly.
  Introduce `SelfContext`/`Deliverer`; drop the module-wide allows (keep per-fn where justified).
- **Group state machine only e2e-tested.** `grouping.rs` (747 LOC / 1 unit test), `organize.rs`
  (0), `devices.rs`/`groups.rs` (1). The most complex state in the system; error branches
  (malformed invite, out-of-order key announce, partial sync) would regress unnoticed. Add
  `MemStore`-based unit tests over the pure transitions.
- **No concurrency test of the shared server state** (`Arc<Mutex<…>>` under parallel handlers).
  Add a multi-threaded deposit/collect stress test (or `loom` on the map ops).
- **Untracked, unbounded detached threads** for push (per deposit) and email (per `auth_start`) —
  no pool/semaphore, and they outlive the 10s graceful-shutdown drain. Route through a bounded
  worker / `spawn_blocking` behind a `Semaphore`.
- **MSRV unenforced + "microcontroller support" never cross-compiled.** `rust-version=1.96` declared
  but every job installs `stable`; `no_std` is proven only on the host target. Add a `1.96` job + a
  bare-metal (`thumbv7em-none-eabi`) core build so the headline portability claim is verified.
- **Structural duplication:** `MailItem` (the system-wide mailbox unit) lives in `groups.rs`; the
  frame codec is hand-rolled 4× despite `link::Wire`; the passphrase-sealing crypto (`Sealed` +
  Argon2id + ChaCha) is copied between `storage/store.rs` and `sdk/secrets.rs` (must stay
  bit-compatible — extract one primitive); the queue inlines router+handlers in a 1761-line
  `lib.rs` while the directory isolates `http.rs` (give the queue an `http.rs`).
- **`reachability::record` rewrites the whole score store + prunes unconditionally per attempt**
  (`reachability.rs:228`). Prune only near the cap / on a timer; skip the rewrite when unchanged.
- **`push_agent()` has no timeouts** (`queue/push.rs:169`) and is rebuilt per send — a slow endpoint
  hangs a detached thread. One `OnceLock` agent with the 5s/15s timeouts (mirror `mycellium-http`).
- **`MYCELLIUM_PUSH_ALLOW_HOSTS` (the SSRF-guard escape hatch) is undocumented**; document it +
  the other bind/name env vars in DEPLOY.md.

## P3 — nits

- Hex encode (×6), `from_hex` (×3), `random_hex` (×3), a `Message`-DTO builder (×12), a test
  `MemStore` (×7), the `resolve_addr`/arg-parse + `load_or_generate_*`/`restrict_perms` idioms
  (across the 3 service bins) are all copy-pasted — hoist into `mycellium-core`/`serve`.
- Env-var reading inconsistent (`is_empty()` vs `trim().is_empty()`, three helper styles) — one
  `env_nonempty(key)`.
- Two stale "(POC) … swap the maps for a database" labels (`directory/lib.rs:95`, `queue/lib.rs:168`)
  though durable redb persistence shipped; `PRODUCTION-READINESS.md` has a multi-device checkbox
  contradicting the shipped (and tested) pairing.
- Non-atomic local writes (`filestore.rs:105` `fs::write`, no temp+rename/fsync) — a crash mid-write
  can drop queued outbox mail. Write-temp + atomic rename.
- No dead-letter visibility (outbox drops past `MAX_ATTEMPTS`/`TTL` silently); `directory parse()`
  mislabels bad bodies as `InvalidRecord`(422); dead code (`Error::StaleRecord`, `Server::metrics()`,
  `Directory::challenge_message`); CI gaps (no `cargo doc`/`cargo-deny`/coverage; wasm never
  fmt/clippy/tested); `mycellium-sdk` has no README + is missing from the ARCHITECTURE crate table;
  `mycellium-relay` uses `thread::park()` with no SIGTERM drain; naming (`hex`/`hex33`/`wallet_hex`);
  `MAX_SKIP` means 1024-evict in `group.rs` vs 256-hard-error in `ratchet.rs`.

## Strengths (all four reviewers, consistently)

- **`mycellium-core` is a model `no_std` crate** — `unsafe forbid`, every dep `default-features=false`,
  one crisp responsibility per module, the only `std` touch `cfg`-gated.
- **The four port traits are the right seams**, minimally designed, no host leakage; `HttpTransport`
  is object-safe so the directory/queue client logic compiles verbatim native + wasm.
- **`deliver_ladder` / `outbox::flush_pass` / `reachability::best_paths`** — pure decision logic split
  from IO, exhaustively unit-tested through a `MemStore` seam. The model the rest should follow.
- **Fail-closed crypto** — clone-then-commit `decrypt`, low-order/contributory DH guards before use,
  thorough `Zeroize`/`Drop`, validated newtypes, shape limits enforced after signature check.
- **Tests assert real behavior with engineered non-vacuity**; deterministic fuzz + bit-flip tamper +
  back-compat/migration coverage; only 2 TODOs in the whole tree.
- **Every server map is bounded + pruned + TTL'd with a test**; fail-closed startup; graceful
  SIGINT/SIGTERM shutdown; `/metrics` with route-template redaction; IO timeouts at every boundary.
- **Honest docs** that gate go-live on external audit and never overclaim a guarantee the code
  doesn't uphold.

## Recommended remediation order

1. **Unify the orchestration into `engine::flow`** (P1-1) — de-CLI-ify `app/*`, delete the SDK/wasm
   copies, and get live delivery + relay onto every client. Biggest correctness+maintainability win.
2. **`try_skipped` fail-closed** (P1-2) — small, closes a real corruption bug the main-path fix left.
3. **`service-kit` + shared client plumbing** (P1-3) — collapses the 4× SIWE duplication.
4. **fsync off the lock + `CatchPanicLayer` + `tracing`/push metrics** (P1-4/5/6) — the operability
   trio; cheap and high-impact for running this in production.
5. **Per-blob mailbox keys + chunked transcripts** (P1-7) — the O(n²) removals.
6. P2 (group unit tests, sign-once, `opt-level=3`, error strategy, KvBlob) then P3 hygiene.

The foundation is production-grade; this list is about making the *implementation* consistent with
the quality the core already demonstrates.
