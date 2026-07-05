# mycellium-wasm

> The Mycellium engine compiled to WebAssembly: a `Session` the browser drives, with all crypto running client-side.

**Layer:** browser adapter · **Depends on:** mycellium-core, mycellium-engine (`default-features = false`), mycellium-directory-client, mycellium-queue-client (browser transport), wasm-bindgen, js-sys, web-sys, getrandom (`js`), qrcode

## What it does

Wraps the **same** engine the native CLI uses as a `wasm-bindgen` `Session` object,
so a web page can register, message, and run groups with every byte of crypto
happening in the browser — the servers still see only ciphertext and opaque ids.
This crate is the thin browser end of the "one engine, two builds" split: it turns
off the engine's `native` feature and supplies the three host ports itself —

- **`XhrTransport`** — an `HttpTransport` over synchronous `XMLHttpRequest`,
  injected into the directory and queue clients (they're generic over the trait, so
  they compile here unchanged). Synchronous is fine because it runs inside a Web
  Worker, off the UI thread.
- **`BrowserPlatform`** — `Platform` via Web Crypto RNG (`getrandom`) + `Date.now`.
- **`MemStore`** — an in-memory `Storage` snapshotted to/from IndexedDB by
  `export()` / `restore()`.

## The `Session` API

Constructors & identity:

| Method | Purpose |
| ------ | ------- |
| `new()` / `restore(snapshot)` | Fresh identity, or rebuild one from an exported IndexedDB snapshot. |
| `register(dir, queue, handle, name)` | Publish a signed record; cache handle/name/dir/queue for later group work. |
| `wallet()` | This device's wallet public key (hex) — the stable device id shown in settings. |
| `export()` / `import(bytes)` | Serialize / restore the whole store (the IndexedDB snapshot). |
| `put/get/del(key[, value])` | UTF-8 key–value store used for app config (`myc:me`, etc.). |

Direct messages:

| Method | Purpose |
| ------ | ------- |
| `send / reply / react / delete_message / send_file(...)` | Look up the peer, X3DH-seal one copy per device, deposit to the queue, record locally; returns the device count. |
| `sync(queue)` | Drain the queue: decrypt `Direct` / `GroupInvite` / `GroupText` items, apply edits/deletes/receipts to history, process invites. Returns items handled. |
| `thread(peer)` / `peers()` / `name_of(peer)` / `file(id)` | Read views: a conversation, the conversation list, a learned display name, an attachment as a `data:` URL. |

Groups:

| Method | Purpose |
| ------ | ------- |
| `group_create(dir, …, name, members_json)` | Create a group and seal the sender key to every member. |
| `group_send(dir, …, gid, text)` | Encrypt with the group key and fan out to all members. |
| `group_add(dir, …, gid, member)` | Add a member and redistribute keys to the newcomer + roster. |
| `group_leave(gid)` | Drop the group's keys and state locally. |
| `groups()` / `group_thread(gid)` | Read views (JSON). |

Multi-device & push:

| Method | Purpose |
| ------ | ------- |
| `pair_offer(queue)` | On a **new** device: mint an ephemeral key + return a one-time pairing offer (show as QR/code), then poll. |
| `qr_svg(text)` | Render `text` (the pairing offer) as a scannable QR (SVG). |
| `pair_approve(offer, handle, dir)` | On an **existing** device: seal the account key to the offer and relay it via the queue rendezvous. |
| `pair_poll(queue)` | On the new device: adopt the account once approved; returns `{dir,queue,handle,name}` or `undefined`. |
| `push_key(queue)` / `push_subscribe(queue, endpoint)` | Fetch the VAPID key / register a Web Push endpoint. |

Free functions (`version`, `user_id`, `generate_wallet`, `directory_login`) and
`add_message` exist for diagnostics and the browser test suites.

## How it fits

`clients/web/build.sh` compiles this crate to `wasm32-unknown-unknown` and runs
`wasm-bindgen --target web` into `clients/web/pkg/`. The PWA loads that module
inside a **Web Worker** (`clients/web/worker.js`) which owns the `Session` and
IndexedDB; `clients/web/index.html` talks to it by RPC. See `docs/BROWSER.md` for
the full browser architecture and `clients/web/README.md` for the app.

## Notes

- **Seedless pairing, no copyable secret.** A new device runs `pair_offer(queue)`
  (mints an ephemeral key, returns a one-time offer); an existing device runs
  `pair_approve(offer, handle, dir)` (seals the account key to the offer over ECDH,
  relays it via a queue rendezvous); the new device `pair_poll(queue)`s, decrypts,
  and adopts the account with fresh device keys. The account key never rides in a
  transferable payload, and the offer is single-use — see `mycellium_core::pairing`.
- **`register` merges the device list.** Renaming/re-registering looks up the current
  record and re-appends this device, so it never drops a sibling a prior pairing
  added (`publish_merged`).
- **`sync` does network inline.** Processing a `GroupInvite` performs directory
  look-ups and queue deposits within the sync call; a slow peer slows that sync.
  Running in the worker keeps the UI responsive regardless.
