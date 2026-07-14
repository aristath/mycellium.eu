# mycellium-registry

Account registry for Mycellium.

The registry provides login, identity recovery, encrypted backup storage, and
signed public-record lookup. It does not store, queue, relay, acknowledge,
inspect, introduce, or carry messages.

## Run

```sh
MYCELLIUM_REGISTRY_BIND='[::1]:8787' \
MYCELLIUM_REGISTRY_DATA_DIR=.mycellium-registry \
MYCELLIUM_REGISTRY_RECOVERY_KEY=<64 hexadecimal characters> \
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=log \
cargo run -p mycellium-registry
```

Rust 1.96 or newer is required.

## Configuration

| Variable | Required | Default | Meaning |
|----------|----------|---------|---------|
| `MYCELLIUM_REGISTRY_BIND` | no | `[::1]:8787` | HTTP listen address |
| `MYCELLIUM_REGISTRY_DATA_DIR` | no | `.mycellium-registry` | Durable data directory |
| `MYCELLIUM_REGISTRY_RECOVERY_KEY` | yes | none | 32-byte recovery master key encoded as exactly 64 hexadecimal characters |
| `MYCELLIUM_REGISTRY_EMAIL_TRANSPORT` | yes | none | `log`, `brevo`, or `smtp` |

Email variables:

| Variable | Used by | Default |
|----------|---------|---------|
| `MYCELLIUM_REGISTRY_EMAIL_FROM` | Brevo, SMTP | required |
| `MYCELLIUM_REGISTRY_BREVO_API_KEY` | Brevo | required |
| `MYCELLIUM_REGISTRY_BREVO_ENDPOINT` | Brevo | `https://api.brevo.com/v3/smtp/email` |
| `MYCELLIUM_REGISTRY_SMTP_HOST` | SMTP | required |
| `MYCELLIUM_REGISTRY_SMTP_PORT` | SMTP | `587` |
| `MYCELLIUM_REGISTRY_SMTP_USERNAME` | SMTP | no authentication |
| `MYCELLIUM_REGISTRY_SMTP_PASSWORD` | SMTP | no authentication |
| `MYCELLIUM_REGISTRY_EMAIL_SUBJECT` | Brevo, SMTP | `Your Mycellium login code` |
| `MYCELLIUM_REGISTRY_LOGIN_URL_TEMPLATE` | Brevo, SMTP | code-only email; `{token}` is replaced when configured |

`log` prints the token to stderr and is only suitable for local operation.

Use only a verified HTTPS App Link/Universal Link in production login URLs.
Custom URI schemes are not secure login-token channels.

## Container deployment

`Dockerfile.registry` builds the registry and exposes HTTP TCP `8787`:

```sh
docker build -f Dockerfile.registry -t mycellium-registry .
```

Set `MYCELLIUM_REGISTRY_BIND=[::]:8787`, mount a persistent volume at `/data`,
and use `MYCELLIUM_REGISTRY_DATA_DIR=/data`. The runtime user is `10001:10001`,
so that volume must be writable only by that identity.

## HTTP API

Public endpoints:

| Method and path | Request | Response |
|-----------------|---------|----------|
| `GET /users/{user_id}/record` | none | Raw signed public-record bytes, or `404` |
| `GET /accounts/{account_id}/record` | none | Raw signed public-record bytes, or `404` |
| `POST /login/email/request` | JSON `{ "email": "user@example.com" }` | `202` with JSON `{ "expires_at": <unix-seconds> }` |
| `POST /login/confirm` | JSON `{ "token": "<one-time-token>" }` | Account and bearer-session JSON |

Login confirmation returns:

```json
{
  "account_id": "<32 lowercase hexadecimal characters>",
  "created": true,
  "session_token": "<bearer token>",
  "session_expires_at": 1700000900
}
```

Account endpoints below require
`Authorization: Bearer <session_token>` for that exact account:

| Method and path | Body | Response |
|-----------------|------|----------|
| `PUT /accounts/{account_id}/backup` | Opaque client-encrypted bytes, at most 16 MiB | Blob metadata JSON |
| `GET /accounts/{account_id}/backup` | none | Raw backup bytes, or `404` |
| `PUT /accounts/{account_id}/recovery` | Exactly 32 bytes containing the wallet root | Blob metadata JSON |
| `GET /accounts/{account_id}/recovery` | none | Raw 32-byte wallet root, or `404` |
| `PUT /accounts/{account_id}/record` | `mycellium_core::wire`-encoded `SignedRecord`, at most 1 MiB | Blob metadata JSON |

Blob metadata is `{ "id": "...", "size": 0, "sha256": "..." }`. Errors are
JSON `{ "error": "..." }` with the relevant HTTP status.

The recovery root is write-once. Repeating the same value is idempotent;
attempting to replace it returns `409 Conflict`. A public record is accepted
only after recovery exists, when its wallet matches that recovery identity, and
when it is not stale or conflicting.

Login tokens are single-use and expire after 15 minutes. Bearer sessions also
expire after 15 minutes, and creating one immediately revokes the previous
session for that account.

## Durable storage and security

The data directory contains:

```text
registry.redb
blobs/users/<first-3>/<next-3>/<next-3>/<account-id>/<kind>-<sha256>.data
```

`redb` stores accounts, hashed login indexes and tokens, sessions, rate-limit
buckets, user-id indexes, and blob references. Blob reads verify their recorded
size and SHA-256.

Generic account backups remain opaque and client-encrypted. Recovery roots are
sealed with ChaCha20-Poly1305 under `MYCELLIUM_REGISTRY_RECOVERY_KEY` and bound
to their account id.

Back up the data directory through a consistent snapshot/export. Back up
`MYCELLIUM_REGISTRY_RECOVERY_KEY` separately. Losing the recovery key makes
recovery blobs unreadable.

Compromise of the running registry plus recovery key can recover a protocol
identity, publish a replacement device, impersonate that user, and receive
future messages. It cannot decrypt existing local history or old messages
because the registry never stores device/message keys or message data.

## Verify

```sh
cargo test -p mycellium-registry --all-targets
```
