# The Browser Build

How Mycellium runs entirely inside a web page: the same Rust engine, compiled to
WebAssembly, with all crypto client-side and the servers still seeing only
ciphertext. This is the companion to [`ARCHITECTURE.md`](ARCHITECTURE.md) for the
web target; the crates are [`mycellium-wasm`](../crates/mycellium-wasm/README.md)
and the app is [`clients/web`](../clients/web/README.md).

## Why WASM, not a rewrite

The engine is written once. The browser is "just another platform" — it implements
the same four core ports (`Transport`, `Storage`, `Platform`, `HttpTransport`) with
browser primitives, and the engine's domain logic compiles to `wasm32` untouched
(the native-only `app/*` orchestration is behind the default `native` feature, off
for this build). There is no second implementation of X3DH, the ratchet, or groups
to keep in sync — a class of bug that simply cannot occur here.

## Build pipeline

`clients/web/build.sh`:

1. `cargo build -p mycellium-wasm --target wasm32-unknown-unknown --release`
2. `wasm-bindgen --target web` emits `clients/web/pkg/`:
   - `mycellium_wasm.js` — an ES module exporting the `Session` class + free fns.
   - `mycellium_wasm_bg.wasm` — the compiled engine.

`pkg/` is generated output (git-ignored). `wasm-bindgen-cli` must match the crate's
pinned `wasm-bindgen` version.

## Runtime: three coordinated contexts

```
┌── UI thread (index.html) ─────────────┐        ┌── Web Worker (worker.js) ───────┐
│  screens, state, event handlers        │  RPC   │  the WASM Session (the engine)  │
│  rpc(op,args) ─ postMessage ──────────────────▶ │  IndexedDB (the durable store)  │
│  ◀───────────── {id, ok, result|err} ───────────│  restores on boot, snapshots    │
│  never blocks: no XHR, no crypto here  │        │  after every mutation           │
└────────────────────────────────────────┘        └─────────────────────────────────┘
             │ registers
             ▼
┌── Service worker (sw.js) ──────────────────────────────────────────────────────┐
│  caches the app shell (offline load) · receives Web Push → shows a notification │
└────────────────────────────────────────────────────────────────────────────────┘
```

**Why a worker?** The browser `HttpTransport` uses *synchronous* `XMLHttpRequest`,
and crypto is CPU-bound. Both would jank or freeze the UI thread. Running the engine
in a Web Worker makes every engine call a non-blocking `await rpc(...)` from the UI's
point of view — typing and scrolling stay smooth even while a `sync` is mid-flight.

**RPC protocol.** The UI posts `{id, op, args}` where `op` is a `Session` method
name; the worker runs `session[op](...args)` and posts back `{id, ok, result}` or
`{id, ok:false, err}`. `id` correlates the reply to a pending promise. That's the
whole contract — no code generation, no schema.

## The four ports, in the browser

| Port | Browser implementation | Notes |
|------|------------------------|-------|
| `HttpTransport` | `XhrTransport` (sync `XMLHttpRequest`) | Safe because it's inside the worker. Injected into the directory + queue clients. |
| `Storage` | `MemStore` + IndexedDB snapshot | In-memory during a session; `export()`/`restore()` persist the whole store. |
| `Platform` | `BrowserPlatform` | RNG via Web Crypto (`getrandom` "js"), time via `Date.now`. |
| `Transport` (device↔device) | *unused* | The browser reaches peers only through the queue, never a raw socket. |

## Persistence & identity

The **worker owns durability.** On boot it opens IndexedDB (`db "mycellium"`,
store `"state"`, key `"snapshot"`); if a snapshot exists it does
`Session.restore(bytes)`, otherwise `new Session()` and saves an initial snapshot.
After any *mutating* RPC it re-snapshots via `session.export()`; read-only ops
(`peers`, `thread`, `wallet`, …) skip the write. Identity and app config
(`myc:me`, dir/queue URLs) live inside the store, so a reload restores the whole
account. Because the snapshot contains the account seed, it is **encrypted at rest**
with an AES-GCM key kept non-extractable in IndexedDB (transparent — no passphrase
prompt); see [`SECURITY.md`](SECURITY.md) for the residual limitation. "Reset this device" in Settings deletes the IndexedDB database +
`localStorage` and reloads.

## Multi-device: seedless pairing

A second device **adopts** the account over an authenticated, one-time channel —
the account key never rides in a copyable payload:

1. The **new** device chooses *Join an existing account*; the app calls
   `pair_offer(queue)`, which mints an ephemeral X25519 keypair and returns a
   one-time **offer** (a rendezvous id + its public key). The app renders it as a
   `qr_svg(offer)` QR and a copyable code, then polls `pair_poll(queue)`.
2. The **existing** device (Settings → *Approve a device*) pastes/scans the offer
   and calls `pair_approve(offer, handle, dir)`, which **seals the account key** to
   the offer's ephemeral key over ECDH and relays it through a short-lived queue
   rendezvous.
3. `pair_poll` on the new device decrypts it (only the scanner can), adopts the
   account with **fresh device keys**, and merges itself into the directory record
   (looks up the current record, appends its device, re-signs, publishes).
4. A message to the account now fans out to *both* device slots; each device
   decrypts its own copy. (Verified by `wasm-multidevice.test.mjs`.)

**Security:** the offer's ephemeral public key is authenticated by the existing
device *scanning it* (out of band), so a malicious rendezvous can't substitute it;
the offer is single-use and worthless after pairing, and only ciphertext sealed to
that key is ever relayed. No seed phrase, and nothing reusable is left behind.

## Web Push (waking a closed app)

1. On grant, the app fetches the queue's VAPID key (`push_key`) and subscribes via
   the browser's push service, registering the endpoint with the queue
   (`push_subscribe`).
2. When mail is deposited, the queue sends a **contentless** push (no sender, no
   content) to that endpoint.
3. `sw.js` receives it and shows a "New message" notification; opening the app
   fetches and decrypts the actual message. The vendor push service learns nothing
   but "some device got a ping."

Delivery can't be verified headlessly (it needs a real vendor round-trip); the e2e
suite verifies the *wiring* (VAPID key + subscribe) instead.

### Contentless-push interoperability matrix (manual QA)

Real delivery must be verified manually against each vendor's push service — it
can't run in headless CI. Endpoint-only storage (see `push.rs`) is sufficient for
these contentless VAPID pings; the `p256dh`/`auth` keys would only be needed if we
ever sent encrypted payloads (we don't). Verify a bodyless VAPID ping wakes the
service worker and shows a notification, with only the endpoint stored:

| Browser / service      | Contentless VAPID ping | Notes |
|------------------------|------------------------|-------|
| Chrome / FCM           | ☐ not yet verified     | primary target |
| Edge / Windows (WNS)   | ☐ not yet verified     | Chromium; expected same as Chrome |
| Firefox / Mozilla push | ☐ not yet verified     |       |
| Safari / APNs (macOS)  | ☐ not yet verified     | web push needs macOS 13+/iOS 16.4+; may be unsupported |

Update this table (and the "Known limitations" list) as each is confirmed on
staging. Until a vendor row is checked, treat its push delivery as unverified.
Tracked in issue #30.

## Offline

The service worker caches the shell (`index.html`, manifest, icon, `pkg/`), so the
app loads with no network. New mail is discovered by **polling** `sync` every ~3 s;
a failed poll flips a visible "offline" indicator, and a subsequent success clears
it and re-renders.

## Known limitations

- **One account per browser profile** — IndexedDB is per-origin, per-profile.
- **Polling, not push, for foreground sync** — ~3 s latency; no live socket (the
  browser can't hold the engine's P2P transport).
- **`sync` does network inline for group invites** — processing a `GroupInvite`
  performs look-ups/deposits within the call; the worker keeps the UI responsive but
  the sync itself can be slow behind a slow peer.
- **A group invite can briefly give asymmetric read access** if invites arrive out of
  order — it self-heals on the next `sync`.

These are tracked in [`IMPROVEMENTS.md`](IMPROVEMENTS.md).
