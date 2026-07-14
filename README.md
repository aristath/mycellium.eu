# Mycellium

Mycellium is an end-to-end encrypted, peer-to-peer messenger.

> A message is delivered device-to-device, or it is not delivered yet.

The registry handles account login, identity recovery, encrypted backups, and
signed public-record discovery. It does not introduce live connections, store
messages, relay payloads, acknowledge delivery, or run a mailbox.

## How devices connect

1. Every user has a stable cryptographic `user_id`.
2. Handles and display names are non-unique labels.
3. The signed public record names one active device and its signed Reticulum
   destination.
4. A sender refreshes the recipient's signed record by `user_id`.
5. The sender sends the sealed item to the recipient's Reticulum destination.
6. Delivery is complete only after the recipient active device signs an ACK for
   the exact payload.

No IP address is a Mycellium identity or user-visible address.

See [SERVERLESS.md](SERVERLESS.md) for the protocol rules.

## Workspace

- `crates/mycellium-core`: identity, records, messages, crypto, shared traits.
- `crates/mycellium-engine`: local records, outbox, history, contacts, groups.
- `crates/mycellium-client`: reusable account, registry, and delivery runtime.
- `crates/mycellium-mobile`: UniFFI boundary shared by Android and iOS.
- `crates/mycellium-storage`: encrypted local identity/history storage.
- `crates/mycellium-transport`: Reticulum adapter plus optional diagnostics/DHT.
- `crates/mycellium-registry`: account registry using `redb` plus file blobs.
- `crates/mycellium-linux`: native Linux app.
- `crates/mycellium-cli`: low-level terminal tools.
- `clients/android`: native Jetpack Compose app.
- `clients/apple`: native SwiftUI app and Swift package.

## Native clients

Rust 1.96 or newer is required.

Run Linux:

```sh
cargo run -p mycellium-linux
```

The Linux app uses `https://registry.mycellium.eu` unless
`MYCELLIUM_REGISTRY_URL` is set. Local data is fixed to
`$XDG_DATA_HOME/mycellium`, or `~/.local/share/mycellium` when `XDG_DATA_HOME`
is unset.

Reticulum connectivity is configured outside the user identity model. For local
experiments, the Rust adapter reads optional Reticulum TCP nodes from:

```text
MYCELLIUM_RETICULUM_TCP_NODES=node1.example:4242,node2.example:4242
```

Build Android:

```sh
cd clients/android
ANDROID_HOME=/path/to/android-sdk \
ANDROID_NDK_HOME=/path/to/android-ndk \
./build-rust.sh
./gradlew :app:assembleDebug
```

Build/test Apple bindings on a host with Swift:

```sh
cd clients/apple
./build-rust.sh
swift test
```

Logging in on another device replaces the old active device. Local history and
pending outbox items do not move automatically.

## Registry

Run locally:

```sh
MYCELLIUM_REGISTRY_BIND='[::1]:8787' \
MYCELLIUM_REGISTRY_DATA_DIR=.mycellium-registry \
MYCELLIUM_REGISTRY_RECOVERY_KEY=<64 hexadecimal characters> \
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=log \
cargo run -p mycellium-registry
```

HTTP surface:

```text
GET  /users/{user_id}/record
POST /login/email/request
POST /login/confirm
PUT  /accounts/{account_id}/backup
GET  /accounts/{account_id}/backup
PUT  /accounts/{account_id}/recovery
GET  /accounts/{account_id}/recovery
PUT  /accounts/{account_id}/record
GET  /accounts/{account_id}/record
```

Email transport can be `log`, generic `smtp`, or Brevo HTTPS. Production uses:

```text
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=brevo
MYCELLIUM_REGISTRY_EMAIL_FROM=Mycellium <no-reply@mail.mycellium.eu>
MYCELLIUM_REGISTRY_BREVO_API_KEY=<brevo api key>
```

The registry accepts at most 16 MiB for an encrypted account backup and 1 MiB
for a signed public record. These are abuse ceilings.

See [crates/mycellium-registry/README.md](crates/mycellium-registry/README.md)
for registry details.

## Verify

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

See [TESTING.md](TESTING.md) for the testing matrix.
