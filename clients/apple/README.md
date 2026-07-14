# Mycellium for iOS

Native SwiftUI UI over the same `mycellium-mobile` Rust library used by Android.
The package uses Swift 6 and supports iOS 17 and macOS 14 for host-side binding
tests. Building the application and XCFramework requires macOS with Xcode.

## Verify the Swift boundary

On a host with Swift installed:

```sh
cd clients/apple
./build-rust.sh
swift test
```

`build-rust.sh` creates bindings against the host Rust library. This verifies
the generated Swift package; it does not build an iOS application. Set
`MYCELLIUM_RUST_LIB_DIR` only when the host library is outside the default
workspace `target/debug` directory.

## Build the iOS application

On macOS with Xcode and XcodeGen:

```sh
brew install xcodegen
cd clients/apple
./build-rust.sh
./build-xcframework.sh
xcodegen generate --spec App/project.yml
open Mycellium.xcodeproj
```

`build-xcframework.sh` builds arm64 device and arm64 simulator Rust libraries
and creates `MycelliumFFI.xcframework`. Select a simulator or signed device in
Xcode and run the `Mycellium` scheme.

## Account, storage, and networking

First use is email, one-time code, then display name and non-unique handle. The
app creates or recovers the protocol identity and publishes this installation as
the account's only active device. Logging in on another device creates fresh
device/message keys and replaces this device; history and pending messages do
not transfer.

The opaque 64-byte identity is stored as a
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` Keychain item. Encrypted
history lives under `Application Support/Mycellium`, and that directory is
excluded from iCloud and device backups.

The app uses `https://registry.mycellium.eu`, opens QUIC on an OS-selected UDP
port, and is identified by its device-key-derived PeerId, never an IP address.
The registry supplies temporary observed mappings only for simultaneous direct
dialing. Message payloads and ACKs never pass through it.

Returning to the foreground refreshes live presence and active-device status. A
background monitor also checks for replacement. When iOS suspends ordinary
networking, senders retain pending messages locally.
