# mycellium-queue

> A per-recipient, wallet-keyed store-and-forward mailbox, decoupled from the directory.

**Layer:** service (library + binary) · **Depends on:** mycellium-core, axum, mycellium-serve, serde

## What it does

A store-and-forward mailbox keyed by the recipient's **wallet** (not their handle),
so it needs *zero* directory data to work. It stores opaque, end-to-end-encrypted
blobs and hands them back only to the wallet that owns them — it never sees anything
but ciphertext. It is deliberately *not* the directory: the tiny name registry can be
cloned across thousands of opportunistic nodes, but people's queued messages must not
be, so a queue is a separate service you (or a provider) run. Deposits are open —
anyone authenticated may drop a blob for a wallet, rate-limited — but only the owning
wallet may collect.

## HTTP API

| Method | Path                       | Auth          | Purpose                                          |
|--------|----------------------------|---------------|--------------------------------------------------|
| GET    | `/health`                  | none          | Liveness check (`"ok"`).                          |
| POST   | `/login/challenge`         | none          | Issue a login nonce for a `wallet`.              |
| POST   | `/login/verify`            | none          | Verify the signed nonce, return a session token. |
| POST   | `/mailbox/{wallet}/{slot}` | Bearer token  | Deposit an opaque blob (any authed sender, rate-limited). |
| GET    | `/mailbox/{wallet}/{slot}` | Bearer token  | Collect & drain the slot (owning wallet only).   |
| GET    | `/push/key`                | none          | The queue's VAPID public key (for `applicationServerKey`). |
| POST   | `/push/subscribe`          | Bearer token  | Register a Web Push endpoint (HTTPS; capped + deduped per wallet). |
| POST   | `/push/unsubscribe`        | Bearer token  | Remove a previously registered push endpoint. |
| GET    | `/metrics`                 | none          | Prometheus counters (via `mycellium-observe`).   |

Login is the SIWE-style wallet contract from `mycellium_core::login`. The token is
passed as `Authorization: Bearer <token>`. `{slot}` is a device id (targeted) or
`"account"` (cluster-wide). All responses carry permissive CORS headers; bodies are
capped (413 above 1 MiB).

## Public API (library)

- `Queue` — the queue state (challenges, tokens, mailboxes, push subscriptions, rate counters).
- `Queue::new()` — a fresh in-memory queue; `Queue::open(path)` — one backed by a durable redb store (mailboxes + push subscriptions reload on start).
- `Queue::challenge(wallet)` — step 1 of login: issue a challenge nonce.
- `Queue::verify(wallet, nonce, signature)` — step 2: verify and issue a session token.
- `Queue::deposit(token, recipient_wallet_hex, slot, blob, now)` — deposit an opaque blob (rate-limited per sender wallet); triggers a contentless Web Push wake to the recipient's subscriptions.
- `Queue::collect(token, wallet_hex, slot)` — drain one slot; caller may only collect their own wallet.
- `Queue::subscribe(token, endpoint)` / `subscriptions(wallet_hex)` — register / list Web Push endpoints for a wallet.
- `ApiError` — a rejected request and its HTTP status (`BadChallenge`, `BadSignature`, `Unauthorized`, `Forbidden`, `RateLimited`, `MailboxFull`, `BadRequest`); `.status()` / `.reason()`.
- `serve(addr)` — run the queue as an HTTP service on `addr` (blocks).
- `hex33(&[u8; 33])` — lowercase hex of a 33-byte compressed wallet key.
- `MAX_MAILBOX` (256) — max queued messages per `(wallet, slot)` mailbox.
- `DEPOSIT_RATE_LIMIT` (30) — deposits allowed per sender wallet per window.
- `RATE_WINDOW` (60) — the rate-limit window, in seconds.

## Running it

```sh
cargo run -p mycellium-queue -- --addr HOST:PORT
```

The address defaults to `127.0.0.1:8090`, and may also be set via the
`MYCELLIUM_QUEUE_ADDR` environment variable (the `--addr` flag takes precedence).

## How it fits

A recipient publishes their queue endpoint in their directory record; senders deposit
there via `mycellium-queue-client`. You can self-host a queue or point your record at a
provider's — either way it reads nothing but ciphertext.

## Configuration (env)

| Variable | Effect |
| -------- | ------ |
| `MYCELLIUM_QUEUE_ADDR` | Bind address (or `--addr`, which wins). Default `127.0.0.1:8090`. |
| `MYCELLIUM_DATA` | Directory for the durable redb store **and** the persisted `vapid.key`. Unset ⇒ in-memory + an ephemeral VAPID key. |
| `MYCELLIUM_TLS_CERT` / `MYCELLIUM_TLS_KEY` | Serve HTTPS directly (PEM). Unset ⇒ plain HTTP behind a proxy. |
| `MYCELLIUM_LOG` | Set (≠ `"0"`) for a JSON access-log line per request (5xx always logged). |

## Notes

Persistence is durable when `MYCELLIUM_DATA` is set: mailboxes and push
subscriptions are kept in redb and reloaded on start, and the VAPID keypair is
persisted to `MYCELLIUM_DATA/vapid.key` (0600) so the public key browsers subscribed
against survives a restart — without it, every restart would invalidate all
subscriptions. Deposits are rate-limited per sender wallet (`DEPOSIT_RATE_LIMIT` per
`RATE_WINDOW`) and each mailbox is bounded (`MAX_MAILBOX`). Login state is
self-bounding like the directory's: challenges expire after `CHALLENGE_TTL` and
session tokens after `TOKEN_TTL`, both pruned as new logins come in (and an expired
token is rejected on use). **Web Push is
contentless** (RFC 8291/8292): the wake ping carries no sender and no message, only
"you have mail" — the app fetches and decrypts the actual message itself, so the
vendor push service learns nothing.
