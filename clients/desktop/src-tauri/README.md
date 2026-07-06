# Mycellium Tauri backend

> The standalone Rust package behind the desktop client: Tauri v2 commands over `mycellium-sdk`, with OS keyring storage.

This directory is its own Cargo workspace on purpose. It is not a member of the
repo root workspace, so Tauri's WebKit/GTK/Wry dependency tree does not affect
the server, CLI, SDK, or WASM builds. The parent desktop README covers the whole
client; this file documents the backend package boundary.

## Package Shape

```text
src-tauri/
├── Cargo.toml              standalone workspace, Tauri, SDK path dependency
├── Cargo.lock              backend lockfile
├── build.rs                tauri_build::build()
├── tauri.conf.json         product metadata, window, frontendDist ../src
├── icons/                  bundle icons
├── src/
│   ├── main.rs             Tauri state + command wrappers over the SDK
│   └── keyring_store.rs    desktop SecretStore adapter
└── tests/
    └── e2e.rs              headless SDK messaging/group round trips
```

The frontend lives one level up in `../src` and has no build step. Tauri serves
that directory through `frontendDist`.

## How It Fits

Unlike Android and Apple, the desktop backend is Rust all the way down:

```text
vanilla JS frontend -> Tauri invoke -> Rust command -> mycellium-sdk
```

There is no UniFFI layer and no C-ABI for the current Tauri app. The C-ABI remains
only a fallback for a future non-Rust desktop host.

## Command Boundary

`src/main.rs` holds one `MyceliumClient` in managed Tauri state and exposes thin
commands for the frontend:

- setup and account state
- email verification and registration
- send/sync/conversations/thread
- contacts and safety-number verification
- group create/add/send/leave/list/thread
- backup/import and push registration where surfaced

SDK calls are blocking because they touch encrypted file storage and blocking
HTTP clients. Commands therefore run SDK work through `tokio::task::spawn_blocking`
and return serializable DTOs to the frontend.

## Secret Storage

`src/keyring_store.rs` implements the SDK `SecretStore` trait using the
cross-platform `keyring` crate:

- Linux: Secret Service / libsecret
- Windows: Credential Manager
- macOS: Keychain

The identity secret goes into the OS keyring. Message history, contacts, groups,
and settings stay in the encrypted SDK file store under the app data directory.
The store fails closed: only a genuinely absent key becomes `None`; locked or
unavailable keyrings return an SDK storage error instead of minting a new
identity.

## Build And Run

From this directory:

```sh
cargo build
cargo test
cargo fmt
cargo clippy -- -D warnings
```

To launch the GUI from the parent desktop package:

```sh
cd clients/desktop
cargo tauri dev
```

The GUI requires a display and the OS webview. The backend tests are headless.

## Tests

`tests/e2e.rs` starts an in-process directory and queue, onboards two accounts
through the SDK email-verification flow, and verifies:

- Alice can send Bob a 1:1 message and Bob receives it through `sync()`.
- Alice can create a group with Bob and Bob receives/decrypts group messages.

The test uses `MyceliumClient::new(...)`, the SDK's development plaintext-file
secret store, because CI/headless systems usually do not have a running OS
keyring service. `cargo build` still compiles the production keyring adapter.

## Generated And Local Files

Tauri may generate schemas under `gen/`, and Rust builds go under `target/`.
Those are local artifacts. Edit source under `src/`, `tests/`, `Cargo.toml`, and
`tauri.conf.json`.
