# mycellium-queue-client

> Thin HTTP client for the message queue: log in, deposit for a recipient wallet, collect your own, register push wake targets, and relay pairing payloads.

**Layer:** adapter · **Depends on:** mycellium-core, serde, anyhow (and `ureq` via mycellium-http under the `native` feature)

## What it does

An HTTP client for a running `mycellium-queue`. The queue is keyed by
**wallet**, not handle: you `deposit` an opaque blob addressed to a recipient's
wallet (as lowercase hex), and you may only `collect` from your own wallet's
mailbox. Login is SIWE-style — fetch a challenge, sign it with your identity,
exchange it for a bearer token — using the shared login contract in
`mycellium-core`. It also registers contentless push wake targets and relays the
opaque sealed payloads used by seedless device pairing. It is separate from the
directory client because the queue is a separate service.

## Public API

All methods hang off `QueueClient`, which wraps a base URL and an injectable HTTP
transport.

**Construction**

- `QueueClient::new(base: impl Into<String>) -> Self` — point the client at a
  queue base URL (e.g. `http://127.0.0.1:8090`); a trailing `/` is trimmed. Uses
  the native `ureq` transport and is **gated behind the `native` feature** (on by
  default).
- `QueueClient::with_transport(base: impl Into<String>, transport: Box<dyn HttpTransport>) -> Self`
  — supply an explicit `mycellium_core::http::HttpTransport`. Browser/WASM builds
  use this to inject an XHR/`fetch` transport, since `native` (and therefore
  `new`) is not available there.

**Login, mailbox**

- `login(&self, identity: &Identity) -> Result<String>` — challenge/sign/verify;
  returns a bearer token.
- `deposit(&self, token: &str, recipient_wallet_hex: &str, slot: &str, blob: &str) -> Result<()>`
  — deposit `blob` into the recipient wallet's mailbox `slot`.
- `collect(&self, token: &str, wallet_hex: &str, slot: &str) -> Result<Vec<String>>`
  — drain one slot of your own mailbox.

**Push wake targets**

- `push_key(&self) -> Result<String>` — fetch the queue's VAPID public key, for
  use as the browser's `applicationServerKey` when subscribing.
- `push_subscribe(&self, token: &str, endpoint: &str) -> Result<()>` — register a
  browser push `endpoint` for the logged-in wallet using the legacy bare-endpoint
  form.
- `push_subscribe_sub(&self, token: &str, sub: &PushSub) -> Result<()>` — register
  a tagged Web Push/APNs/FCM/UnifiedPush subscription for the logged-in wallet.
- `push_unsubscribe_sub(&self, token: &str, sub: &PushSub) -> Result<()>` — remove
  that exact tagged subscription.

**Pairing rendezvous**

- `pair_post(&self, rid: &str, msg: &str) -> Result<()>` — relay one sealed
  pairing payload to rendezvous `rid`.
- `pair_fetch(&self, rid: &str) -> Result<Vec<String>>` — drain sealed pairing
  payloads for `rid`.

**Helper**

- `wallet_hex(wallet: &WalletPublicKey) -> String` — lowercase hex of a
  compressed wallet key, the queue's mailbox key.

## How it fits

The engine resolves a recipient's queue endpoint from their signed record, then
uses this client to `deposit` a sealed blob keyed by their wallet (step 2 of the
delivery ladder). Your inbox uses `collect` to drain your own wallet's slots
from your queue, and Web Push lets the queue nudge a backgrounded browser to
collect promptly.

## Notes

The HTTP transport is injectable via `mycellium_core::http::HttpTransport`, so
the exact same request logic runs on native and in the browser — only the
transport differs. The `native` feature pulls in `mycellium-http`'s `ureq`-backed
transport and enables the `new` constructor; a WASM build compiles with
`--no-default-features` and constructs the client through `with_transport`.
