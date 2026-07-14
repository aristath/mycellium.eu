# Testing Mycellium

Mycellium's automated tests defend the protocol invariants at several layers.
No test suite can prove that software is perfect, so production validation also
includes the real-network checks below.

## Complete local verification

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo audit
cargo deny check
```

`cargo test --workspace --all-targets` includes two socket-level end-to-end suites. They start
an isolated registry using real HTTP, redb, filesystem blobs, and the real
libp2p QUIC rendezvous service.

`mobile_full_stack` proves:

- email token delivery, account creation, recovery-root storage, and profile
  publication through real HTTP;
- authenticated live-device registration and direct QUIC introduction;
- encrypted message delivery, recipient-device ACK, and local history;
- an offline recipient leaves the message only in the sender's encrypted
  outbox, followed by successful retry when the recipient becomes reachable;
- retry does not duplicate recipient history;
- logging in on a new device preserves the user id, creates fresh device keys,
  disables the retired device, and routes future traffic to the replacement;
- registry files contain none of the test message plaintext.

`registry_persistence` proves:

- account, encrypted recovery material, signed records, user-id lookup, and the
  registry PeerId survive a clean restart;
- one-time login tokens cannot be replayed;
- invalid sessions receive HTTP 401 and cross-account sessions receive 403;
- public records remain discoverable while recovery material remains private;
- persistent files contain neither plaintext login email nor wallet root;
- the rendezvous identity file is mode `0600` on Unix.

The unit and adversarial suites additionally cover fail-closed local-state
corruption, atomic multi-key recovery, concurrent blob publication, per-email
and per-source login abuse controls, generic internal HTTP errors, bounded
expiry cleanup, authenticated ACKs, pairwise outbox resealing after a device
switch, and group-key re-sharing to a replacement device.

Run either suite alone with logs:

```sh
cargo test -p mycellium-registry --test mobile_full_stack -- --nocapture
cargo test -p mycellium-registry --test registry_persistence -- --nocapture
```

## Apple boundary

The Swift package tests malformed secure identities, unauthenticated calls, and
the fresh-client state through the generated UniFFI API:

```sh
cd clients/apple
./build-rust.sh
swift test
```

The package suite runs on Linux and macOS. Building and launching the iOS app
still requires Xcode on macOS.

## Android boundary

The Android instrumentation suite uses a disposable emulator/application data
directory. It proves that the 64-byte opaque identity is encrypted by Android
Keystore, lives under `noBackupFilesDir`, rejects invalid lengths and tampered
ciphertext, and is excluded from Android backup.

```sh
cd clients/android
ANDROID_HOME=/path/to/android-sdk \
ANDROID_NDK_HOME=/path/to/android-ndk \
./build-rust.sh
./gradlew :app:connectedDebugAndroidTest
```

Compile the instrumentation APK without a running device:

```sh
./gradlew :app:assembleDebugAndroidTest
```

CI generates the x86_64 JNI library and Kotlin bindings, runs JVM tests, and
assembles the debug APK. Emulator-backed instrumentation remains a separate
acceptance run because it requires Android Keystore and a running device.

## Real-network acceptance

Loopback tests cannot prove NAT behavior. Before treating a registry deployment
as production-ready, run Linux-to-Android and Linux-to-iOS delivery with the
devices on separate real networks and confirm all of the following:

- the registry observes usable original UDP source mappings;
- simultaneous QUIC hole punching establishes a direct device-to-device path;
- the recipient ACK reaches the sender over that direct path;
- registry traffic contains introductions only and never message payloads;
- taking the recipient offline leaves the message pending only on the sender;
- restoring the recipient delivers exactly once;
- replacing a device prevents the retired device from registering or receiving
  future messages.

This requirement is tracked in [TODO.md](TODO.md) because it depends on the
deployed network path rather than repository code alone.
