# mycellium-directory

> The untrusted name registry: SIWE-style wallet login, a store of self-signed records, and presence.

**Layer:** service (library) · **Depends on:** mycellium-core, axum, mycellium-serve, serde

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
| POST   | `/auth/start`       | none   | Begin an email-verified username claim; sends a code (rate-limited per wallet + per email). |
| POST   | `/auth/confirm`     | none   | Confirm the code to bind (or recover) a handle. |
| POST   | `/auth/status`      | none   | Poll whether a claim has been confirmed.        |
| PUT    | `/records/{handle}` | Bearer | Publish/update a `SignedRecord` under a handle (rate-limited per wallet). |
| GET    | `/records/{handle}` | none   | Look up the record for a handle (404 if none). |
| POST   | `/presence/{handle}`| Bearer | Heartbeat: the owner marks the handle online.  |
| GET    | `/presence/{handle}`| none   | Query whether a handle is online.              |
| GET    | `/metrics`          | none   | Prometheus counters (via `mycellium-observe`). |
| GET    | `/health`           | none   | Liveness check (`"ok"`).                        |

All responses carry permissive CORS headers (browser clients call it directly), and
request bodies are capped (413 above 256 KiB).

## Public API (library)

- `Directory` — the registry state (challenges, tokens, bindings, records, presence, rate counters, email pepper).
- `Directory::new()` — a fresh in-memory registry; `Directory::open(path)` — one backed by a durable redb store (loads existing bindings/records/emails on start).
- `Directory::challenge(wallet)` / `verify(wallet, nonce, signature)` — the two login steps; `verify` returns a session token.
- `Directory::auth_start(...)` / `auth_confirm(...)` / `auth_status(...)` — the email-verified username claim + recovery flow (a code is mailed out; confirming binds or re-binds the handle).
- `Directory::publish(token, handle, record)` — store a signed record, enforcing every directory rule (self-certification, permanent binding, `seq` anti-rollback, rate limit).
- `Directory::lookup(handle)` — fetch the latest record; open, no auth.
- `Directory::heartbeat(token, handle, now)` / `presence(handle, now)` — mark online / query within `PRESENCE_TTL`.
- `Directory::challenge_message(nonce)` — the exact bytes a client signs.
- `ApiError` — a rejected request plus its HTTP `status()` and `reason()` (includes `RateLimited`, `Storage`).
- `serve(addr)` — bind `addr` and run the HTTP shell over a `Directory` (async, via the shared `mycellium-serve` runtime; honours `MYCELLIUM_DATA`, `MYCELLIUM_TLS_*`, `MYCELLIUM_SMTP_*`).

## How it fits

The deployable `mycellium-server` binary serves this library over HTTP; clients
(the engine) reach it through `mycellium-directory-client`.

## Configuration (env)

| Variable | Effect |
| -------- | ------ |
| `MYCELLIUM_DATA` | Directory for the durable redb store. Unset ⇒ in-memory (dev). |
| `MYCELLIUM_TLS_CERT` / `MYCELLIUM_TLS_KEY` | Serve HTTPS directly (PEM). Unset ⇒ plain HTTP, intended behind a TLS-terminating reverse proxy. |
| `MYCELLIUM_SMTP_HOST` / `_PORT` / `_FROM` / `_USER` / `_PASS` | Send real verification email. Unset ⇒ dev mode returns the code in the API response. |
| `MYCELLIUM_LOG` | Set (≠ `"0"`) for a JSON access-log line per request (5xx always logged). |

## Notes

Persistence is durable when `MYCELLIUM_DATA` is set: challenges/tokens stay
in-memory (ephemeral by nature), while bindings, records, and email claims are
kept in redb (see `persist.rs`) and reloaded on start. Because every record is
self-certifying, this — and future replication — is safe: a store can withhold or
serve stale, but can never forge or tamper. Abuse is bounded by fixed-window rate
limits (`auth_start` per wallet + per email, `publish` per wallet) and challenge /
token expiry pruning. Emails are never stored in the clear — a claim is keyed by a
peppered hash, which is what makes email-proved *recovery* possible without the
directory ever holding your address.
