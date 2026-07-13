# Mycellium

Mycellium is a hard-serverless, end-to-end encrypted peer-to-peer messenger.

The core rule is simple:

> A message is delivered peer-to-peer, or it is not delivered yet.

There is no required directory server, queue, relay, mailbox, push service,
browser backend, or SDK server surface in the message protocol. Peers exchange
self-authenticating records, dial each other directly, and keep undelivered
messages in the sender's encrypted local outbox.

The workspace also contains an optional account registry. It exists for account
UX: login identities, encrypted identity recovery, account backups, and
publishing signed public records. It does not store, queue, relay, or route
messages.

## Workspace

- `crates/mycellium-core`: portable identity, records, messages, X3DH, ratchet,
  groups, and storage/transport traits.
- `crates/mycellium-engine`: hard-serverless orchestration, local peer records,
  direct delivery, outbox, history, contacts, and verification.
- `crates/mycellium-client`: reusable headless client API for account/device
  records and local client state mutations.
- `crates/mycellium-storage`: encrypted local identity and history storage.
- `crates/mycellium-transport`: direct TCP and direct libp2p transports.
- `crates/mycellium-registry`: optional account registry using `redb` metadata
  and filesystem blobs.
- `crates/mycellium-cli`: terminal client.
- `crates/mycellium-linux`: native Linux client shell.

## Quickstart

Create two local profiles:

```json
{
  "data_dir": "./data/alice",
  "passphrase": "alice dev passphrase",
  "display_name": "Alice",
  "dht_bootstrap": []
}
```

```json
{
  "data_dir": "./data/bob",
  "passphrase": "bob dev passphrase",
  "display_name": "Bob",
  "dht_bootstrap": []
}
```

Create identities:

```sh
cargo run -p mycellium-cli -- --config alice.json identity-new
cargo run -p mycellium-cli -- --config bob.json identity-new
```

Create signed local records and copy the printed `record:` values:

```sh
cargo run -p mycellium-cli -- --config alice.json register alice --addr 127.0.0.1:9001
cargo run -p mycellium-cli -- --config bob.json register bob --addr 127.0.0.1:9002
```

Import each peer's record:

```sh
cargo run -p mycellium-cli -- --config alice.json record import bob '<bob-record>'
cargo run -p mycellium-cli -- --config bob.json record import alice '<alice-record>'
```

After one direct record is known, peers can gossip signed records without making
discovery authoritative:

```sh
cargo run -p mycellium-cli -- --config alice.json discover bob --want carol
```

For network-scale discovery, run any peer as a DHT participant and publish
signed records into it. The DHT stores only signed peer records; every lookup is
verified locally before import.

```sh
cargo run -p mycellium-cli -- --config bob.json dht serve --addr 127.0.0.1:9100
cargo run -p mycellium-cli -- --config alice.json dht publish alice --bootstrap /ip4/127.0.0.1/tcp/9100/p2p/<bob-peer-id>
cargo run -p mycellium-cli -- --config bob.json dht lookup alice --bootstrap /ip4/127.0.0.1/tcp/9100/p2p/<bob-peer-id>
```

Profiles may keep bootstrap peers in `dht_bootstrap`. Normal send and group
flows try the local peerbook first, then import a signed record from the
configured DHT before failing. `register` automatically publishes the updated
signed record when configured bootstrap peers exist; `dht publish` is still
available as an explicit retry.

Run Bob's receiver:

```sh
cargo run -p mycellium-cli -- --config bob.json serve --as bob --addr 127.0.0.1:9002
```

Send from Alice:

```sh
cargo run -p mycellium-cli -- --config alice.json send bob --as alice --message "hi"
```

If Bob is unreachable, Alice keeps the sealed message locally:

```sh
cargo run -p mycellium-cli -- --config alice.json outbox list
cargo run -p mycellium-cli -- --config alice.json outbox retry
cargo run -p mycellium-cli -- --config alice.json outbox cancel <id>
```

The CLI has no registry login UI. To switch devices through the CLI, explicitly
move the wallet secret to a fresh profile, import the current signed record,
then register the new device. The native Linux app performs account recovery
after email login instead. Profiles with configured DHT bootstrap peers publish
the updated record automatically:

```sh
cargo run -p mycellium-cli -- --config alice.json identity-export-wallet --yes
cargo run -p mycellium-cli -- --config alice-laptop.json identity-adopt '<wallet-secret>'
cargo run -p mycellium-cli -- --config alice-laptop.json record import alice '<alice-record>'
cargo run -p mycellium-cli -- --config alice-laptop.json register alice --addr 127.0.0.1:9011
```

The native Linux client can be launched with:

```sh
cargo run -p mycellium-linux
```

The app is organized around Messages, People, and This device. It restores the
local profile and listener on unlock, exchanges signed identities as connection
cards, exposes safety-number verification with each person, and keeps offline
delivery status out of the normal chat flow. Conversations and pending delivery
targets use stable user IDs internally; handles remain display names. A message
is accepted by the recipient's active device or remains pending on the sender's
device. New installs verify an email before creating or recovering an identity.
Switching devices keeps the same protocol identity, creates fresh device keys,
and leaves old local message history where it was created. The bearer session
is kept inside the device's encrypted local store, never in a plaintext config
file.

## Optional Registry

Run the development registry:

```sh
MYCELLIUM_REGISTRY_BIND=127.0.0.1:8787 \
MYCELLIUM_REGISTRY_DATA_DIR=.mycellium-registry \
MYCELLIUM_REGISTRY_RECOVERY_KEY=<64 hexadecimal characters> \
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=log \
cargo run -p mycellium-registry
```

Defaults:

```text
MYCELLIUM_REGISTRY_BIND=127.0.0.1:8787
MYCELLIUM_REGISTRY_DATA_DIR=.mycellium-registry
MYCELLIUM_REGISTRY_RECOVERY_KEY=<64 hexadecimal characters>
```

The registry binary requires an explicit email transport:

```text
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=log
```

or:

```text
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=brevo
MYCELLIUM_REGISTRY_EMAIL_FROM=Mycellium <login@example.com>
MYCELLIUM_REGISTRY_BREVO_API_KEY=<brevo api key>
```

or:

```text
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=smtp
MYCELLIUM_REGISTRY_EMAIL_FROM=Mycellium <login@example.com>
MYCELLIUM_REGISTRY_SMTP_HOST=smtp-relay.brevo.com
MYCELLIUM_REGISTRY_SMTP_PORT=587
MYCELLIUM_REGISTRY_SMTP_USERNAME=<smtp username>
MYCELLIUM_REGISTRY_SMTP_PASSWORD=<smtp password>
```

Brevo uses the HTTPS transactional email API, so it does not require outbound
SMTP ports to be opened by the host.

Optional:

```text
MYCELLIUM_REGISTRY_EMAIL_SUBJECT=Your Mycellium login code
MYCELLIUM_REGISTRY_LOGIN_URL_TEMPLATE=mycellium://login?token={token}
MYCELLIUM_REGISTRY_BREVO_ENDPOINT=https://api.brevo.com/v3/smtp/email
```

Current API:

```text
POST /login/email/request
POST /login/confirm
PUT  /accounts/{account_id}/backup
GET  /accounts/{account_id}/backup
PUT  /accounts/{account_id}/recovery
GET  /accounts/{account_id}/recovery
PUT  /accounts/{account_id}/record
GET  /accounts/{account_id}/record
```

Protected endpoints use:

```text
Authorization: Bearer <session_token>
```

`/login/email/request` returns `202 Accepted` and sends the one-time token
through the configured email sender. The token is not returned in the HTTP
response.

Current upload limits:

```text
backup: 16 MiB
public record: 1 MiB
```

The registry stores metadata in `redb` and account bytes in filesystem blobs.
The dedicated recovery endpoint accepts only the 32-byte wallet root, encrypts
it before storage with `MYCELLIUM_REGISTRY_RECOVERY_KEY`, and will not replace
it with another identity. Public records remain signed records and must match
that recovery identity.

## Commands

```sh
mycellium identity-new
mycellium identity-adopt <wallet-secret>
mycellium identity-show
mycellium identity-export-wallet --yes
mycellium register <handle> --addr <host:port> [--libp2p]
mycellium record export <handle>
mycellium record import <handle> <record>
mycellium record list
mycellium discover <known-peer> [--want alice,bob]
mycellium dht serve --addr <host:port> [--bootstrap <multiaddr>...]
mycellium dht publish <handle> [--bootstrap <multiaddr>...] [--listen <host:port>]
mycellium dht lookup <handle> [--bootstrap <multiaddr>...] [--listen <host:port>]
mycellium device <handle>
mycellium send <peer> --as <me> --message <text>
mycellium serve --as <me> --addr <host:port> [--libp2p]
mycellium outbox list
mycellium outbox retry
mycellium outbox cancel <id|all>
mycellium group create <name> --as <me> --members alice,bob
mycellium group send <group> --as <me> --message <text>
mycellium group add <group> --as <me> --member <handle>
mycellium group history <group>
mycellium group info <group>
mycellium group leave <group> --as <me>
mycellium group list
mycellium-registry
```

## Test

```sh
cargo test --workspace
```
