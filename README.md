# Mycellium

Mycellium is an end-to-end encrypted messaging prototype built as a Rust
workspace. It has a small untrusted directory, an opaque mailbox queue, optional
libp2p relay support, a CLI, browser/WASM clients, and native SDK bindings.

## Start Locally

Throwaway services:

```sh
cargo run -p mycellium-server -- --dev
cargo run -p mycellium-queue -- --dev
```

Durable services use JSON config:

```json
{
  "addr": "127.0.0.1:8080",
  "data_dir": "./data/directory",
  "dev_auth": true
}
```

```json
{
  "addr": "127.0.0.1:8090",
  "data_dir": "./data/queue"
}
```

```sh
cargo run -p mycellium-server -- --config directory.json
cargo run -p mycellium-queue -- --config queue.json
```

CLI profiles are JSON as well:

```json
{
  "data_dir": "./data/alice",
  "passphrase": "alice dev passphrase",
  "queue": "http://127.0.0.1:8090",
  "name": "Alice"
}
```

```sh
cargo run -p mycellium-cli -- --config alice.client.json identity-new
cargo run -p mycellium-cli -- --config alice.client.json register alice \
  --addr 127.0.0.1:9001 --directory http://127.0.0.1:8080
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for a two-account flow.

## Workspace

- `crates/mycellium-core`: portable identity, messages, records, login, and traits.
- `crates/mycellium-engine`: native orchestration.
- `crates/mycellium-storage`: encrypted local state and explicit client config.
- `crates/mycellium-directory`: signed-record directory.
- `crates/mycellium-queue`: opaque mailbox queue.
- `crates/mycellium-relay`: libp2p relay server.
- `crates/mycellium-cli`: terminal client.
- `clients/web`, `clients/rust`, `clients/apple`, `clients/android`: app surfaces.

## Test

```sh
cargo test --workspace
cargo test -p mycellium-cli --test e2e
```

Browser tests live in `clients/rust/e2e` and require the WASM build:

```sh
./clients/web/build.sh
node clients/rust/e2e/pwa.test.mjs
```

## Docs

- [Quickstart](docs/QUICKSTART.md)
- [Deploy](docs/DEPLOY.md)
- [Security](docs/SECURITY.md)
- [Architecture](docs/ARCHITECTURE.md)
