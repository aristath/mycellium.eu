# Mycellium

Mycellium is an end-to-end encrypted messenger built on **MLS-over-Nostr
([Marmot](https://github.com/parres-hq/mdk))**: forward-secret group messaging
(MLS, via MDK) carried over the open [Nostr](https://nostr.com) relay network
(via [rust-nostr](https://rust-nostr.org)). It is a real, interoperable Nostr
identity with a hardened secure-messaging layer on top — see
[docs/design/NOSTR-DIRECTION.md](docs/design/NOSTR-DIRECTION.md) for the
direction.

The repository is a Rust workspace: four engine crates that build up from the
crypto to a headless messenger core, plus a thin CLI that drives it.

## Workspace

```text
  mycellium-cli          the `mycellium` binary — a thin shell over the engine
    │
  mycellium-app          headless messenger core: accounts, contacts + trust,
    │                    conversations, receive loop, persisted history
    ▼
  mycellium-multidevice  one account, many device-leaves in every group
    ▼
  mycellium-mls          MLS crypto + Marmot event building (over MDK)
    ▼
  mycellium-nostr        Nostr relay transport (connect / publish / subscribe)
    ▼
       relay
```

- `crates/mycellium-mls` — a thin, honest wrapper over MDK (the MLS-over-Nostr
  crypto engine).
- `crates/mycellium-nostr` — async relay transport over `nostr-sdk`.
- `crates/mycellium-multidevice` — multi-device accounts: one logical account
  whose device-leaves all participate in every group.
- `crates/mycellium-app` — the messenger engine: setup, contacts with
  key-change hardening (trust-on-first-use + identity-change detection),
  conversations, the receive loop, and SQLCipher-encrypted history.
- `crates/mycellium-cli` — the `mycellium` binary.

Durable state lives in two SQLCipher-encrypted SQLite databases per device (MLS
state + app data), keyed from the device seed.

## CLI quickstart

```sh
# Build the binary.
cargo build -p mycellium-cli        # produces target/debug/mycellium

# Create an identity + config (defaults to a public relay; --relay is repeatable).
mycellium account new --relay wss://relay.damus.io

# Announce this device to the relays (KeyPackage + device list).
mycellium publish

# Add a contact by npub, hex pubkey, or nip05 handle, then list contacts.
mycellium contact add npub1... alice
mycellium contacts

# Open an interactive 1:1 conversation: type a line to send, Ctrl-D to quit.
mycellium chat alice

# Or drain incoming messages non-interactively.
mycellium inbox --seconds 10

# Inspect config.
mycellium account show
mycellium relays
```

Data lives under `--data-dir` (default `$HOME/.mycellium`, or
`$MYCELLIUM_DATA_DIR`): `config.json` alongside the encrypted databases.

## Test

```sh
cargo test --workspace
```

The `mls` / `nostr` / `multidevice` / `app` suites drive genuine relay sockets
via `nostr-relay-builder`'s in-process relay.
