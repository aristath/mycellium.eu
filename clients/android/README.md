# Mycellium for Android

Native Kotlin/Jetpack Compose UI over the shared `mycellium-mobile` Rust
library. Rust owns identity, protocol, registry semantics, encrypted history,
trust, direct delivery, and pending retries.

The app requires Android 8.0/API 26 or newer. It compiles and targets API 34.

## Build

Requirements:

- Rust 1.96 or newer
- JDK 17
- Android SDK with platform 34 and platform tools
- Android NDK
- `cargo-ndk`

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk

cd clients/android
export JAVA_HOME=/path/to/jdk-17
export ANDROID_HOME=/path/to/android-sdk
export ANDROID_NDK_HOME=/path/to/android-ndk
./build-rust.sh
./gradlew :app:assembleDebug
```

The normal Rust build produces `arm64-v8a`, `armeabi-v7a`, and `x86_64` JNI
artifacts and packages only `libmycellium_mobile.so`. To build only for the
common emulator ABI:

```sh
ANDROID_ABIS=x86_64 ./build-rust.sh
```

The APK is `app/build/outputs/apk/debug/app-debug.apk`.

## Run on an emulator

Start an existing Android Virtual Device, install the APK, and open it:

```sh
$ANDROID_HOME/emulator/emulator -list-avds
$ANDROID_HOME/emulator/emulator -avd <avd-name>
$ANDROID_HOME/platform-tools/adb install -r app/build/outputs/apk/debug/app-debug.apk
$ANDROID_HOME/platform-tools/adb shell am start -n eu.mycellium.android/.MainActivity
```

Android Studio can instead open `clients/android` and run the `app`
configuration.

## Account, storage, and networking

First use is email, one-time code, then display name and non-unique handle. The
app creates or recovers the protocol identity and publishes this installation as
the account's only active device. Logging in on another device creates fresh
device/message keys and replaces this device; history and pending messages do
not transfer.

The opaque 64-byte identity is AES-GCM wrapped by a non-exportable Android
Keystore key and stored atomically at `noBackupFilesDir/identity.v1`. Encrypted
history is in `filesDir/mycellium`. Android backup is disabled for the entire
application.

The app uses `https://registry.mycellium.eu`, opens QUIC on an OS-selected UDP
port, and is identified by its device-key-derived PeerId, never an IP address.
The registry supplies temporary observed mappings only for simultaneous direct
dialing. Message payloads and ACKs never pass through it.

Returning to the foreground refreshes live presence and active-device status. A
background monitor also checks for replacement. When Android suspends ordinary
networking, senders retain pending messages locally.
