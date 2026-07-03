# mycellium-directory-client

> A thin HTTP client for the Mycellium directory: login, publish, lookup, presence.

**Layer:** adapter · **Depends on:** mycellium-core, ureq, serde, anyhow

## What it does

Speaks the directory's HTTP contract to a running `mycellium-directory`
(served by `mycellium-server`). It performs the SIWE-style login handshake,
publishes and looks up wallet-signed records under a handle, and announces or
queries presence. It knows only the wire contract and the shared types from
`mycellium-core` — it does **not** depend on the directory library itself.

## Public API

All methods hang off `DirectoryClient`, which wraps a base URL.

- `DirectoryClient::new(base: impl Into<String>) -> Self` — point at a directory
  base URL, e.g. `http://127.0.0.1:8080` (a trailing `/` is trimmed).
- `login(&self, identity: &Identity) -> Result<String>` — full login: fetch a
  challenge, sign `mycellium_core::login::challenge_message(nonce)`, exchange it
  for a session token.
- `publish(&self, token: &str, handle: &Handle, record: &SignedRecord) -> Result<()>`
  — `PUT` a signed record under `handle`, authorized by a session `token`.
- `lookup(&self, handle: &Handle) -> Result<SignedRecord>` — `GET` the signed
  record for `handle`.
- `announce(&self, token: &str, handle: &Handle) -> Result<()>` — presence
  heartbeat: mark the handle online.
- `presence(&self, handle: &Handle) -> Result<bool>` — query whether a handle is
  currently online.

## How it fits

The engine uses this adapter for the name layer — logging in, registering and
resolving records, and tracking presence. Message deposit and collect are a
separate concern and go through `mycellium-queue-client` instead.
