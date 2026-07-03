# mycellium-queue

> A per-recipient, wallet-keyed store-and-forward mailbox, decoupled from the directory.

**Layer:** service (library + binary) · **Depends on:** mycellium-core, tiny_http, serde

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
| POST   | `/mailbox/{wallet}/{slot}` | Bearer token  | Deposit an opaque blob (any authed sender).      |
| GET    | `/mailbox/{wallet}/{slot}` | Bearer token  | Collect & drain the slot (owning wallet only).   |

Login is the SIWE-style wallet contract from `mycellium_core::login`. The token is
passed as `Authorization: Bearer <token>`. `{slot}` is a device id (targeted) or
`"account"` (cluster-wide).

## Public API (library)

- `Queue` — the in-memory queue state (challenges, tokens, mailboxes, rate counters).
- `Queue::new()` — a fresh, empty queue.
- `Queue::challenge(wallet)` — step 1 of login: issue a challenge nonce.
- `Queue::verify(wallet, nonce, signature)` — step 2: verify and issue a session token.
- `Queue::deposit(token, recipient_wallet_hex, slot, blob, now)` — deposit an opaque blob (rate-limited per sender wallet).
- `Queue::collect(token, wallet_hex, slot)` — drain one slot; caller may only collect their own wallet.
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

## Notes

State is in-memory today (a real deployment swaps the maps for a durable store; the
logic is unchanged). Deposits are rate-limited per sender wallet (`DEPOSIT_RATE_LIMIT`
per `RATE_WINDOW`), and each mailbox is bounded (`MAX_MAILBOX`).
