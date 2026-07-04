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
account. "Reset this device" in Settings deletes the IndexedDB database +
`localStorage` and reloads.

## Multi-device: QR and link

A second device **adopts** the account rather than sharing a key:

1. Device A → Settings → *Link another device* calls `link_payload(...)`, which
   returns base64 JSON **containing the seed phrase** plus the dir/queue/handle/name.
2. The app renders it two ways: a `qr_svg(url)` **QR code** and a copyable
   `…/#link=<payload>` **URL**.
3. Device B scans the QR with its camera (opening the URL) or pastes the link. On
   load the app sees `#link=`, calls `link_device(payload)` → a **new device key on
   the same seed**, which it merges into the directory record (looks up the current
   record, appends its device, re-signs, publishes).
4. A message to the account now fans out to *both* device slots; each device
   decrypts its own copy. (Verified by `wasm-multidevice.test.mjs`.)

**Security:** the link payload *is* the account key — anyone holding it gains full
read/write. The UI shows it only in this flow, with a warning, and never logs it.

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

## Offline

The service worker caches the shell (`index.html`, manifest, icon, `pkg/`), so the
app loads with no network. New mail is discovered by **polling** `sync` every ~3 s;
a failed poll flips a visible "offline" indicator, and a subsequent success clears
it and re-renders.

## Known limitations

- **One account per browser profile** — IndexedDB is per-origin, per-profile.
- **Polling, not push, for foreground sync** — ~3 s latency; no live socket (the
  browser can't hold the engine's P2P transport).
- **Re-registering resets to a single device.** `register` (e.g. renaming in
  Settings) republishes the record with only the current device, dropping siblings a
  prior `link_device` merged. Re-link afterward. *(Fixing this needs `register` to
  merge the existing device list — a good next increment.)*
- **`sync` does network inline for group invites** — processing a `GroupInvite`
  performs look-ups/deposits within the call; the worker keeps the UI responsive but
  the sync itself can be slow behind a slow peer.
- **Deleted attachments aren't garbage-collected** — a `Body::Delete` tombstones the
  message but leaves its `file:<id>` data URL in the store.

These are tracked in [`IMPROVEMENTS.md`](IMPROVEMENTS.md).
