# mycellium-registry

Account registry and live-device introduction service.

The registry provides account login, identity recovery, signed-record lookup,
and discovery between two live devices. It does not store, queue, relay,
acknowledge, inspect, or carry messages.

## Run

```sh
MYCELLIUM_REGISTRY_BIND=127.0.0.1:8787 \
MYCELLIUM_REGISTRY_RENDEZVOUS_BIND=127.0.0.1:8788 \
MYCELLIUM_REGISTRY_RENDEZVOUS_PUBLIC_ADDR=/ip4/127.0.0.1/udp/8788/quic-v1 \
MYCELLIUM_REGISTRY_DATA_DIR=.mycellium-registry \
MYCELLIUM_REGISTRY_RECOVERY_KEY=<64 hexadecimal characters> \
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=log \
cargo run -p mycellium-registry
```

Rust 1.96 or newer is required.

## Configuration

These variables configure the service itself:

| Variable | Required | Default | Meaning |
|----------|----------|---------|---------|
| `MYCELLIUM_REGISTRY_BIND` | no | `127.0.0.1:8787` | HTTP listen address |
| `MYCELLIUM_REGISTRY_RENDEZVOUS_BIND` | no | `0.0.0.0:8788` | UDP/QUIC listen address |
| `MYCELLIUM_REGISTRY_RENDEZVOUS_PUBLIC_ADDR` | production | loopback address using the rendezvous port | Externally reachable QUIC multiaddr without `/p2p` |
| `MYCELLIUM_REGISTRY_DATA_DIR` | no | `.mycellium-registry` | Durable data directory |
| `MYCELLIUM_REGISTRY_RECOVERY_KEY` | yes | none | 32-byte recovery master key encoded as exactly 64 hexadecimal characters |
| `MYCELLIUM_REGISTRY_EMAIL_TRANSPORT` | yes | none | `log`, `brevo`, or `smtp` |

The registry appends its stable PeerId to the public rendezvous address and
returns the complete multiaddr from `GET /rendezvous`.

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

SMTP username and password must either both be set or both be absent.
The optional login URL template must contain exactly one `{token}` placeholder.
Use only a verified HTTPS App Link/Universal Link in production; custom URI
schemes are not secure login-token channels.

Brevo HTTPS configuration:

```text
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=brevo
MYCELLIUM_REGISTRY_EMAIL_FROM=Mycellium <no-reply@mail.mycellium.eu>
MYCELLIUM_REGISTRY_BREVO_API_KEY=<api key>
```

Generic SMTP configuration:

```text
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=smtp
MYCELLIUM_REGISTRY_EMAIL_FROM=Mycellium <no-reply@mail.mycellium.eu>
MYCELLIUM_REGISTRY_SMTP_HOST=smtp-relay.brevo.com
MYCELLIUM_REGISTRY_SMTP_PORT=587
MYCELLIUM_REGISTRY_SMTP_USERNAME=<username>
MYCELLIUM_REGISTRY_SMTP_PASSWORD=<password>
```

`log` prints the token to stderr and is only suitable for local operation.

On Bunny Magic Containers, `BUNNYNET_MC_PODIP` is provided by the platform. If
the configured rendezvous bind is a wildcard, the binary binds to that pod IP
internally so libp2p does not depend on the sandboxed interface watcher. The
public address remains the configured UDP Anycast address.

## Container deployment

`Dockerfile.registry` builds the registry and exposes TCP `8787` plus UDP
`8788`:

```sh
docker build -f Dockerfile.registry -t mycellium-registry .
```

A hosted container must set the HTTP bind to `0.0.0.0:8787`, set the public
rendezvous multiaddr to its real UDP endpoint, mount a persistent volume at
`/data`, and use `MYCELLIUM_REGISTRY_DATA_DIR=/data`. The runtime user is
`10001:10001`, so that volume must be writable only by that identity. Keep exactly one replica
until rendezvous affinity exists. `GET /rendezvous` is the deployment readiness
check: it must return the externally reachable QUIC multiaddr with the stable
registry PeerId.

## HTTP API

Public endpoints:

| Method and path | Request | Response |
|-----------------|---------|----------|
| `GET /rendezvous` | none | JSON `{ "address": "<quic-multiaddr-with-peer-id>" }` |
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
when it is not a stale or conflicting record.

Login tokens are single-use and expire after 15 minutes. Bearer sessions also
expire after 15 minutes, and creating one immediately revokes the account's
previous session. Email requests are limited to five per normalized email hash
in each 15-minute window, plus a separate generous source-address ceiling.
Email addresses are trimmed, lowercased, and stored only as a domain-separated
hash. Login and session tokens are also stored only by hash. Emails contain the
code only unless the optional login URL template is configured.

## Live introduction protocol

Live devices use authenticated libp2p QUIC protocol
`/mycellium/rendezvous/1.0`. Each frame is a four-byte big-endian length followed
by `mycellium_core::wire` bytes. Frames larger than 1 MiB are rejected before
allocation.

The introduction pattern borrows BEP 55's observed-endpoint exchange and
coordinated simultaneous connection. It does not use BitTorrent trackers,
torrents, or BitTorrent payload transport.

Client messages:

- `Register { session_token, device }`
- `Introduce { device }`

Registry messages:

- `Registered`
- `Connect { device, address, role }`
- `Unavailable { device }`
- `Rejected`

Registration succeeds only when the bearer session owns the current signed
record, that record names the submitted device key, and the remote QUIC PeerId
is the exact PeerId encoded from that key. `Connect.address` is the peer's
temporary observed UDP mapping. It is never persisted or treated as identity.

The same client UDP socket remains open for registry presence and the direct
simultaneous dial. Message payloads and recipient ACKs use only
`/mycellium/1.0` on the resulting device-to-device QUIC connection. The
rendezvous protocol has no payload or delivery-ack message.

## Network and scaling requirements

Expose the HTTP port over TCP and the rendezvous port over UDP. The UDP ingress
must preserve each client's source IP and port; otherwise the observed mapping
cannot be used for hole punching. NAT and firewall policy must also permit the
simultaneous QUIC attempt. Failure leaves the message pending on the sender and
must not trigger a relay.

Live presence is process-local. Run exactly one registry process unless all
clients for a rendezvous shard are guaranteed to reach the same process or a
shared control-only presence coordinator is added. A coordinator may carry
presence and introduction state, never application payloads.

## Durable storage and security

The data directory contains:

```text
registry.redb
rendezvous.key
blobs/users/<first-3>/<next-3>/<next-3>/<account-id>/<kind>-<sha256>.data
```

`redb` stores accounts, hashed login indexes and tokens, sessions, rate-limit
buckets, user-id indexes, and blob references. Blob reads verify their recorded
size and SHA-256. Generic account backups remain opaque and client-encrypted.
Recovery roots are sealed with ChaCha20-Poly1305 under
`MYCELLIUM_REGISTRY_RECOVERY_KEY` and bound to their account id.

Login-token, session, and rate-limit expiry indexes are cleaned in bounded
transactions until the backlog is drained. Blob publication uses
compare-and-swap; a successful write removes only the exact previous blob it
displaced, so concurrent unpublished writes cannot be swept accidentally.

Back up all three durable paths through a consistent snapshot/export. Keep the
recovery master key in separate secret storage and test restores. Losing
`rendezvous.key` changes the registry PeerId; losing the recovery key makes
recovery blobs unreadable. Do not change the recovery key without atomically
re-encrypting every existing recovery blob.

Compromise of the running registry and recovery key can recover a protocol
identity, publish a replacement device, impersonate that user, and receive
future messages. It cannot decrypt existing local history, old messages, or
pending outbox items because the registry never stores device/message keys or
message data. Existing clients detect a replacement record and disable network
activity while keeping local history visible.

## Verify

```sh
cargo test -p mycellium-registry --all-targets
```

The ignored live test proves that a deployed public QUIC endpoint completes an
authenticated handshake and rejects an unauthorized device:

```sh
MYCELLIUM_LIVE_RENDEZVOUS='<multiaddr returned by GET /rendezvous>' \
cargo test -p mycellium-registry \
  rendezvous::tests::live_rendezvous_rejects_an_unauthorized_device_after_quic_handshake \
  -- --ignored --exact
```

That test does not prove NAT punching. The two-client, two-network delivery test
in the project TODO remains required.
