# Mycellium

Mycellium is an end-to-end encrypted, direct peer-to-peer messenger.

> A message is delivered device-to-device, or it is not delivered yet.

The registry handles account login, signed public records, and live device
introduction. It never stores, queues, relays, acknowledges, or carries a
message. If a direct connection cannot be made, the delivery stays in the
sender's encrypted local outbox.

## How devices connect

1. Every user has a stable cryptographic user id. Handles and display names are
   non-unique human-readable labels, never identity keys.
2. The signed public record names the account's one active device and its stable
   libp2p PeerId. It stores no IP address.
3. A live device authenticates a QUIC control stream to the registry. The
   registry observes its temporary UDP mapping.
4. The sender refreshes the recipient's signed record by stable user id and asks
   for an introduction.
5. The registry gives the two live devices each other's temporary mappings and
   complementary simultaneous-dial roles.
6. The devices establish authenticated direct QUIC and exchange the encrypted
   payload and recipient-device ACK directly.

An IP address is a temporary connection candidate, never an identity or a
user-visible address. The registry control protocol has no payload message type.

See [SERVERLESS.md](SERVERLESS.md) for the protocol rules.

## Workspace

- `crates/mycellium-core`: identity, records, messages, crypto, shared traits,
  and the rendezvous control types.
- `crates/mycellium-engine`: local records, direct delivery, outbox, history,
  contacts, groups, and verification.
- `crates/mycellium-client`: reusable account, record-refresh, and direct-network
  runtime shared by native apps.
- `crates/mycellium-mobile`: UniFFI boundary shared by Android and iOS.
- `crates/mycellium-storage`: encrypted local identity and history storage.
- `crates/mycellium-transport`: libp2p QUIC, authenticated streams, simultaneous
  UDP hole punching, and lower-level transport tools.
- `crates/mycellium-registry`: account registry and live introduction service,
  using `redb` metadata and filesystem blobs.
- `crates/mycellium-linux`: native Linux app.
- `crates/mycellium-cli`: low-level terminal tools.
- `clients/android`: native Jetpack Compose app.
- `clients/apple`: native SwiftUI app and Swift package.

## Native clients

Rust 1.96 or newer is required.

On first use, a person enters an email address, confirms the one-time code, and
then chooses a display name and handle. The client creates a new protocol
identity or recovers the existing one, creates fresh device and message keys,
and publishes that device as the account's only active device.

Email is the currently implemented login surface, not the account identity.
The account model allows other verified login identities to be added without
changing the protocol user id.

Logging in on another device repeats that process with the same protocol
identity and replaces the old active device. Local history and pending outbox
items do not move. The old client detects the replacement, keeps its history
readable, and disables sending, receiving, and retries.

Run Linux:

```sh
cargo run -p mycellium-linux
```

The Linux app uses `https://registry.mycellium.eu` unless
`MYCELLIUM_REGISTRY_URL` is set. Local data is fixed to
`$XDG_DATA_HOME/mycellium`, or `~/.local/share/mycellium` when
`XDG_DATA_HOME` is unset; it is intentionally not exposed as a UI setting.

Build Android:

```sh
cd clients/android
ANDROID_HOME=/path/to/android-sdk \
ANDROID_NDK_HOME=/path/to/android-ndk \
./build-rust.sh
./gradlew :app:assembleDebug
```

The APK is written to
`clients/android/app/build/outputs/apk/debug/app-debug.apk`. Open
`clients/android` in Android Studio to run it on a phone or emulator.

Generate and test the Apple bindings on a host with Swift:

```sh
cd clients/apple
./build-rust.sh
swift test
```

Build the iOS application on macOS with Xcode:

```sh
cd clients/apple
./build-rust.sh
./build-xcframework.sh
xcodegen generate --spec App/project.yml
open Mycellium.xcodeproj
```

All three apps implement email login, automatic identity creation/recovery,
single-active-device replacement, connection cards, contacts, safety-number
verification, direct conversations, and sender-held pending delivery. Android
Keystore and Apple Keychain protect the opaque device identity. App data backup
is disabled so local message history is not copied into Android or iCloud
backups.

Client-specific instructions:

- [Linux](crates/mycellium-linux/README.md)
- [Android](clients/android/README.md)
- [iOS](clients/apple/README.md)
- [shared mobile boundary](crates/mycellium-mobile/README.md)

Mobile operating systems suspend ordinary app networking. While the recipient
app is asleep, delivery stays pending on the sender. See [TODO.md](TODO.md) for
the payload-free wake-hint design.

## Registry

Run locally:

```sh
MYCELLIUM_REGISTRY_BIND=127.0.0.1:8787 \
MYCELLIUM_REGISTRY_RENDEZVOUS_BIND=127.0.0.1:8788 \
MYCELLIUM_REGISTRY_RENDEZVOUS_PUBLIC_ADDR=/ip4/127.0.0.1/udp/8788/quic-v1 \
MYCELLIUM_REGISTRY_DATA_DIR=.mycellium-registry \
MYCELLIUM_REGISTRY_RECOVERY_KEY=<64 hexadecimal characters> \
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=log \
cargo run -p mycellium-registry
```

The HTTP API listens on TCP `8787`. Live introduction uses UDP `8788`; its
public address is returned by `GET /rendezvous` with the registry's stable
PeerId appended.

Account and discovery HTTP surface:

```text
GET  /rendezvous
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

Backup and recovery endpoints and record publication use
`Authorization: Bearer <session_token>`. Rendezvous lookup, record reads, and
login are public. Public records are signed and verified by clients. The
registry permits a live rendezvous registration only when the bearer session
owns the record naming that exact active device and the QUIC PeerId matches its
device key.

Email transport can be `log`, generic `smtp`, or Brevo HTTPS. Production uses:

```text
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=brevo
MYCELLIUM_REGISTRY_EMAIL_FROM=Mycellium <no-reply@mail.mycellium.eu>
MYCELLIUM_REGISTRY_BREVO_API_KEY=<brevo api key>
```

Emails contain the one-time code by default. A clickable login URL is opt-in;
production deployments must use a verified HTTPS App Link/Universal Link, not
an unverified custom URI scheme.

The registry accepts at most 16 MiB for an encrypted account backup and 1 MiB
for a signed public record. These are abuse ceilings, not expected object sizes.

See [crates/mycellium-registry/README.md](crates/mycellium-registry/README.md)
for all registry settings and deployment details.

## Verify

See [TESTING.md](TESTING.md) for the coverage matrix, native-client commands,
end-to-end scenarios, and required real-network acceptance checks.

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo audit
cargo deny check
```
