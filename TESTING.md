# Testing Mycellium

Automated tests defend protocol invariants, storage behavior, and client
boundaries. Real-network Reticulum delivery still needs separate acceptance
testing.

## Complete local verification

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Important coverage:

- signed records verify device and Reticulum destination bindings;
- delivery ACKs are bound to delivery id, payload bytes, and recipient device;
- pending outbox entries survive restart and retry without duplication;
- account login, recovery, public-record storage, and user-id lookup work over
  real HTTP/redb/filesystem registry state;
- registry files do not contain plaintext message content, login email, or
  wallet root;
- mobile bindings protect opaque identity material through platform storage.

Run registry suites:

```sh
cargo test -p mycellium-registry --all-targets -- --nocapture
```

## Android boundary

```sh
cd clients/android
ANDROID_HOME=/path/to/android-sdk \
ANDROID_NDK_HOME=/path/to/android-ndk \
./build-rust.sh
./gradlew :app:connectedDebugAndroidTest
```

## Apple boundary

```sh
cd clients/apple
./build-rust.sh
swift test
```

## Real-network acceptance

Before treating a deployment as production-ready, run Linux-to-Android and
Linux-to-iOS delivery with devices on separate real networks and confirm:

- both devices can publish and refresh signed records;
- both devices can receive over their Reticulum destinations;
- the recipient ACK reaches the sender;
- the registry never sees message payloads or ACKs;
- offline recipients leave messages pending only on the sender;
- restoring the recipient delivers exactly once;
- replacing a device prevents the retired device from sending or receiving.

This is tracked in [TODO.md](TODO.md) because it depends on deployed network
behavior, not repository code alone.
