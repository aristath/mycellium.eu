# mycellium-client

> A local Rust app that embeds a web server and serves a browser **PWA** — the first real face over the Mycellium engine.

**Layer:** client (binary + PWA) · **Depends on:** mycellium-engine, mycellium-core, mycellium-storage, tiny_http

## What it does

Runs on your machine, binds to `127.0.0.1` only, and is a thin face over the
headless [`mycellium-engine`](../../crates/mycellium-engine/README.md): HTTP/JSON
in, engine calls out, structured state back. The browser app is a dependency-free
**PWA** (installable, offline shell) embedded in the binary, so the whole client
ships as a single self-contained executable. It owns **UI only** — every bit of
crypto, delivery, and storage lives in the engine.

Four features, all backed by existing engine functions (no protocol logic here):

- **Login / registration** — create an identity (a random wallet key, no seed
  phrase), claim a handle, or unlock/restore an existing one. It's a *local* app,
  so "login" means unlocking your on-disk identity with your passphrase.
- **Contacts** — add (pins the peer's wallet, TOFU), list, remove.
- **Threads** — 1:1 conversations with message bubbles and a composer.
- **Groups** — create, list, open, and message groups.

## Running it

Start a directory and a queue, then the client:

```sh
cargo run -p mycellium-server -- --addr 127.0.0.1:8080 &
cargo run -p mycellium-queue  -- --addr 127.0.0.1:8090 &
cargo run -p mycellium-client -- --port 8800 \
    --directory http://127.0.0.1:8080 --queue http://127.0.0.1:8090
# then open http://127.0.0.1:8800
```

Flags: `--port` (default 8800), `--directory`, `--queue`, `--data-dir` (default
`$HOME/.mycellium`). All also take their `MYCELLIUM_*` env equivalents.

## How it's built

```
src/main.rs   embedded tiny_http server: static PWA assets + /api dispatch
src/api.rs    JSON API → engine (reads pull from stores; actions call commands)
src/web.rs    the PWA, embedded via include_bytes! (single-file binary)
web/          index.html · app.js · styles.css · manifest · sw.js · icon.svg
```

The browser polls `POST /api/sync` (which drains your queue into local history
via the engine) and re-fetches the open view — so new messages arrive without a
running `serve`. Reads (`/api/threads`, `/api/contacts`, `/api/groups`) return
straight from the engine's stores; writes (`send`, `register`, `contact_add`,
`group_create`) call the engine's command functions and the browser refetches.

## Notes & limits

- The client isn't reachable for **live push** (it has no listening address), so
  delivery to it flows through its **queue** — exactly the offline path.
- Single-user, single identity per process; the server is synchronous (fine for
  a local app). Live updates are by polling, not WebSocket/SSE yet.
- Background delivery on mobile (waking the app) is a separate, still-unbuilt
  piece — see [`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md).
