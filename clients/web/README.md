# Mycellium PWA (`clients/web`)

> The browser client: an installable, offline-capable messenger that runs the whole engine as WebAssembly.

A static web app — no application server of its own. It talks to a Mycellium
**directory** and **queue** over HTTP, but every private operation (identity,
sealing, the ratchet, groups) happens in your browser via `mycellium-wasm`. The
servers see only ciphertext and opaque ids.

## Files

| File | Role |
| ---- | ---- |
| `index.html` | The entire UI (single file): screens, state, RPC client to the worker. |
| `worker.js` | A **Web Worker** that owns the WASM `Session` and IndexedDB, off the UI thread. |
| `sw.js` | Service worker: caches the app shell (offline) and handles Web Push wake pings. |
| `manifest.json` / `icon.svg` | PWA install metadata + icon. |
| `build.sh` | Compiles `mycellium-wasm` → `pkg/` (wasm + JS bindings). |
| `pkg/` | Generated `wasm-bindgen` output (git-ignored; produced by `build.sh`). |

## Architecture

The engine's network is **synchronous** (blocking XHR) and crypto is CPU-bound, so
neither may run on the UI thread. The design:

```
index.html (UI thread)  ──postMessage {id,op,args}──▶  worker.js
        ▲                                                  │  owns: Session (WASM),
        └──────── {id, ok, result | err} ◀─────────────────┘  IndexedDB, config
```

- **RPC**: every engine call is `await rpc(op, args)` — the UI never blocks; a slow
  `sync` or `send` can't freeze scrolling or typing.
- **The worker owns durability**: it restores the `Session` from IndexedDB on start
  and re-snapshots (`export()`) after every mutation. Reads skip the snapshot.
- **The service worker** caches `index.html`, the manifest, icon, and the `pkg/`
  bindings for offline load, and on a Web Push wake ping shows a "New message"
  notification (the message itself is fetched + decrypted in-app — the push carries
  no content).

See `docs/BROWSER.md` for the full walk-through.

## Build & run locally

```sh
# 1. build the WASM engine into pkg/
./clients/web/build.sh

# 2. run a directory + queue (see docs/QUICKSTART.md)
cargo run -p mycellium-server -- --addr 127.0.0.1:8080 &
cargo run -p mycellium-queue  -- --addr 127.0.0.1:8090 &

# 3. serve this folder statically and open it with the two URLs
python3 -m http.server 8000 --directory clients/web
#   → http://localhost:8000/?dir=http://localhost:8080&queue=http://localhost:8090
```

The `?dir=…&queue=…` query configures the endpoints on first load (also settable on
the Setup screen); they're remembered in `localStorage`.

## Features

1:1 and **group** chat (create / add / leave, with a bidirectional sender-key mesh),
reply / react / delete-for-everyone, image **attachments**, desktop **notifications**
+ **Web Push**, learned **display names**, timestamps, a **settings** screen
(rename, device key, reset), an **offline** indicator, and **multi-device** linking
via QR **or** copyable link.

## Deploying

Serve the folder as static files behind HTTPS (required for service workers, Web
Push, and installability). The directory and queue must send permissive CORS (they
do) and should be HTTPS too. See `docs/DEPLOY.md` → "Serving the browser PWA".

## Testing

The suites in `clients/rust/e2e/` drive this app in headless Chrome (Puppeteer) plus
the WASM `Session` directly — `pwa.test.mjs` runs the full two-user UI flow;
`wasm-*.test.mjs` exercise the engine in-browser. See `clients/rust/e2e/README.md`.

## Limitations

- One account per browser profile (IndexedDB is per-origin, per-profile).
- New mail is discovered by **polling** `sync` (every ~3 s), not a live socket.
- Re-registering (e.g. renaming in settings) currently resets the account to a single
  device — re-link other devices afterward (see `docs/BROWSER.md`).
