# mycellium-directory

> The untrusted name registry: SIWE-style wallet login, a store of self-signed records, and presence.

**Layer:** service (library) · **Depends on:** mycellium-core, tiny_http, serde

## What it does

Maps handles to wallet-signed `SignedRecord`s and tracks per-handle presence. It
is deliberately *untrusted*: every record is signed by its owner's wallet, so the
directory cannot forge one — the worst a dishonest directory can do is withhold or
serve a stale record, never impersonate. It holds **no** message queue; offline
store-and-forward lives in `mycellium-queue`. The security rules —
self-certification, permanent handle binding, and `seq` anti-rollback — all live
in `Directory::publish`.

## HTTP API

Routes from `src/http.rs` (`route`):

| Method | Path                | Auth   | Purpose                                        |
| ------ | ------------------- | ------ | ---------------------------------------------- |
| POST   | `/login/challenge`  | none   | Issue a login nonce for a wallet.              |
| POST   | `/login/verify`     | none   | Verify the signed nonce, return a session token. |
| PUT    | `/records/{handle}` | Bearer | Publish/update a `SignedRecord` under a handle. |
| GET    | `/records/{handle}` | none   | Look up the record for a handle (404 if none). |
| POST   | `/presence/{handle}`| Bearer | Heartbeat: the owner marks the handle online.  |
| GET    | `/presence/{handle}`| none   | Query whether a handle is online.              |
| GET    | `/health`           | none   | Liveness check (`"ok"`).                        |

## Public API (library)

- `Directory` — the in-memory registry state.
- `Directory::challenge(wallet)` — step 1 of login: issue a nonce.
- `Directory::verify(wallet, nonce, signature)` — step 2: check the signature, return a session token.
- `Directory::publish(token, handle, record)` — store a signed record, enforcing every directory rule.
- `Directory::lookup(handle)` — fetch the latest record; open, no auth.
- `Directory::heartbeat(token, handle, now)` — mark the authenticated owner online.
- `Directory::presence(handle, now)` — whether the handle was seen within `PRESENCE_TTL`.
- `Directory::challenge_message(nonce)` — the exact bytes a client signs.
- `ApiError` — a rejected request plus its HTTP `status()` and `reason()`.
- `serve(addr)` — bind `addr` and run the HTTP shell over a `Directory`.

## How it fits

The deployable `mycellium-server` binary serves this library over HTTP; clients
(the engine) reach it through `mycellium-directory-client`.

## Notes

State is in-memory today — plain `HashMap`s for challenges, tokens, bindings,
records, and presence. A real deployment swaps them for a durable or replicated
store; because each record is self-certifying, replication is safe — a replica
cannot forge or tamper, only serve what the owner signed.
