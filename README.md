# Mycellium

Mycellium is a hard-serverless, end-to-end encrypted peer-to-peer messenger.

The core rule is simple:

> A message is delivered peer-to-peer, or it is not delivered yet.

There is no required directory server, queue, relay, mailbox, push service,
browser backend, or SDK server surface in the message protocol. Peers exchange
self-authenticating records, dial each other directly, and keep undelivered
messages in the sender's encrypted local outbox.

The workspace also contains an optional account registry. It exists for account
UX: login identities, encrypted account backups, and publishing signed public
records. It does not store, queue, relay, or route messages.

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

Profiles may keep bootstrap peers in `dht_bootstrap`. Normal send, chat, and
group flows try the local peerbook first, then import a signed record from the
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

To add another device to the same account, explicitly move the wallet secret to a
fresh profile, import the current signed record, then register the new device.
Profiles with configured DHT bootstrap peers publish the updated record
automatically:

```sh
cargo run -p mycellium-cli -- --config alice.json identity-export-wallet --yes
cargo run -p mycellium-cli -- --config alice-laptop.json identity-adopt '<wallet-secret>'
cargo run -p mycellium-cli -- --config alice-laptop.json record import alice '<alice-record>'
cargo run -p mycellium-cli -- --config alice-laptop.json register alice --addr 127.0.0.1:9011
```

For direct interactive chat, run `listen` on one side and `chat` on the other.

## Optional Registry

Run the development registry:

```sh
MYCELLIUM_REGISTRY_BIND=127.0.0.1:8787 \
MYCELLIUM_REGISTRY_DATA_DIR=.mycellium-registry \
cargo run -p mycellium-registry
```

Defaults:

```text
MYCELLIUM_REGISTRY_BIND=127.0.0.1:8787
MYCELLIUM_REGISTRY_DATA_DIR=.mycellium-registry
```

Current API:

```text
POST /login/email/request
POST /login/confirm
PUT  /accounts/{account_id}/backup
GET  /accounts/{account_id}/backup
PUT  /accounts/{account_id}/record
GET  /accounts/{account_id}/record
```

Protected endpoints use:

```text
Authorization: Bearer <session_token>
```

`/login/email/request` currently returns `dev_token` directly. That is a
development placeholder until a real email sender is wired in.

Current upload limits:

```text
backup: 16 MiB
public record: 1 MiB
```

The registry stores metadata in `redb` and opaque encrypted account bytes in
filesystem blobs. Public records are still signed records; clients must verify
them locally.

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
mycellium listen --addr <host:port> [--libp2p] [--tui]
mycellium chat <peer> --as <me> [--tui]
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
