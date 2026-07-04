# mycellium-directory-client

> A thin HTTP client for the Mycellium directory: login, the email-verified username claim, publish, lookup, presence.

**Layer:** adapter · **Depends on:** mycellium-core, serde, anyhow (and `ureq` via mycellium-http under the `native` feature)

## What it does

Speaks the directory's HTTP contract to a running `mycellium-directory`
(served by `mycellium-server`). It performs the SIWE-style login handshake,
runs the email-verified username claim (used for both signup and account
recovery), publishes and looks up wallet-signed records under a handle, and
announces or queries presence. It knows only the wire contract and the shared
types from `mycellium-core` — it does **not** depend on the directory library
itself.

It is also the single boundary where a **plaintext username becomes a directory
id**. Every handle is hashed with `mycellium_core::userid::user_id` before it
goes on the wire, so the directory only ever sees and stores opaque ids — never
a name. This is a real privacy boundary: a compromised or curious directory
cannot enumerate or leak the plaintext handles of its users, because it was
never told them. The username claim hashes the same way — the directory binds
the id, not the plaintext.

## Public API

All methods hang off `DirectoryClient`, which wraps a base URL and an injectable
HTTP transport.

**Construction**

- `DirectoryClient::new(base: impl Into<String>) -> Self` — point at a directory
  base URL, e.g. `http://127.0.0.1:8080` (a trailing `/` is trimmed), using the
  native `ureq` transport. **Gated behind the `native` feature** (on by
  default).
- `DirectoryClient::with_transport(base: impl Into<String>, transport: Box<dyn HttpTransport>) -> Self`
  — supply an explicit `mycellium_core::http::HttpTransport`. Browser/WASM builds
  use this to inject an XHR/`fetch` transport, since `native` (and therefore
  `new`) is not available there.

**Login, records, presence**

- `login(&self, identity: &Identity) -> Result<String>` — full login: fetch a
  challenge, sign `mycellium_core::login::challenge_message(nonce)`, exchange it
  for a session token.
- `publish(&self, token: &str, handle: &Handle, record: &SignedRecord) -> Result<()>`
  — `PUT` a signed record under `handle`'s directory id, authorized by a session
  `token`.
- `lookup(&self, handle: &Handle) -> Result<SignedRecord>` — `GET` the signed
  record for `handle`'s directory id.
- `announce(&self, token: &str, handle: &Handle) -> Result<()>` — presence
  heartbeat: mark the handle online.
- `presence(&self, handle: &Handle) -> Result<bool>` — query whether a handle is
  currently online.

**Email-verified username claim (signup + recovery)**

- `auth_start(&self, token: &str, username: &str, email: &str) -> Result<(String, Option<String>)>`
  — begin a claim. Hashes `username` to a directory id and asks the directory to
  send a verification code to `email`. Returns `(pending_token, dev_code)`, where
  `dev_code` is `Some` only when the directory runs in dev mode (no SMTP), so the
  local flow works without a real inbox.
- `auth_confirm(&self, pending: &str, code: &str) -> Result<String>` — confirm a
  verification code (typed, or carried by the one-tap link). Returns the verified
  username.
- `auth_status(&self, pending: &str) -> Result<(bool, String)>` — poll a pending
  claim; returns `(verified, username)`.

## How it fits

The engine uses this adapter for the name layer — logging in, claiming and
recovering a username, registering and resolving records, and tracking presence.
Message deposit and collect are a separate concern and go through
`mycellium-queue-client` instead.

## Notes

The HTTP transport is injectable via `mycellium_core::http::HttpTransport`, so
the exact same request logic runs on native and in the browser — only the
transport differs. The `native` feature pulls in `mycellium-http`'s `ureq`-backed
transport and enables the `new` constructor; a WASM build compiles with
`--no-default-features` and constructs the client through `with_transport`.
