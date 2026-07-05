# Mycellium — Android client (#67)

A thin Jetpack-Compose UI over the `mycellium-sdk` UniFFI **Kotlin** bindings. No
protocol, crypto, storage, or network logic lives here — the app renders state
and forwards user intent; everything else is behind the SDK boundary. This is the
Android implementation of the shared blueprint in
[`docs/NATIVE-CLIENTS.md`](../../docs/NATIVE-CLIENTS.md); read that first.

> **Build-verified.** `./build-rust.sh` then `gradle assembleDebug` produces a
> working `app-debug.apk` — the `mycellium-sdk` compiles to Android (`.so` for
> `arm64-v8a` / `armeabi-v7a` / `x86_64` via cargo-ndk), the UniFFI Kotlin binding
> generates, and this Compose app compiles cleanly against it. Verified toolchain:
> **JDK 17**, **Android SDK 34** + **build-tools 34.0.0**, **NDK r26d**
> (`26.3.11579264`), **cargo-ndk 4.1.2**, **Gradle 8.9**, **AGP 8.5.2**,
> **Kotlin 2.0.20**. It is **not** in the main repo CI (no Android toolchain there);
> a local `gradle build` remains the per-change acceptance step.

## What it does

1:1 messaging MVP, every screen backed by real SDK calls:

- **Setup** — enter the directory + queue URLs (persisted via `set_setting`).
- **Onboarding** — handle + email → `start_email_verification` → enter the code →
  `confirm_email_verification` → `register`.
- **Conversations** — the threads list from `conversations()`.
- **Thread** — `thread(peer)` transcript + a compose box → `send_text`, with the
  optimistic `DeliveryState` shown per sent message.
- **Contacts / verify** — `add_contact`, `contacts()`, and a `safety_number`
  affordance to compare out of band.
- Foreground receive via `sync()` on resume + a light poll, plus a registered
  `EventListener` so inbound messages (`on_message`) surface live.

## Prerequisites

- **Android Studio** (Koala or newer) with the Android SDK.
- **Android NDK** (SDK Manager → SDK Tools → *NDK (Side by side)*); export
  `ANDROID_NDK_HOME` (or `ANDROID_NDK_ROOT`) so `cargo-ndk` can find it.
- **Rust** + the Android targets:
  ```sh
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
  ```
- **cargo-ndk**:
  ```sh
  cargo install cargo-ndk
  ```

## Build steps

From `clients/android`:

```sh
# 1. Build the native .so per ABI AND generate the UniFFI Kotlin binding.
#    Outputs (both gitignored build artifacts):
#      app/src/main/jniLibs/<abi>/libmycellium_sdk.so
#      app/build/generated/uniffi/uniffi/mycellium_sdk/mycellium_sdk.kt
./build-rust.sh

# 2. Materialize the Gradle wrapper once (the wrapper JAR is a binary and is
#    NOT committed). Needs a system Gradle >= 8.9.
gradle wrapper

# 3. Build (or open the folder in Android Studio and let it sync).
./gradlew assembleDebug
```

Re-run `./build-rust.sh` whenever the SDK's Rust surface changes, so the `.so`
and the generated binding stay in lockstep with the app code.

### Why the `@aar` JNA dependency matters

The generated Kotlin binding calls the Rust `.so` through **JNA** at runtime.
`app/build.gradle.kts` depends on `net.java.dev.jna:jna:5.14.0@aar` — the `@aar`
classifier pulls the Android artifact that bundles JNA's *own* native libraries
per ABI. A plain `:jna:` jar compiles but crashes on device with
`UnsatisfiedLinkError`. Do not change it to the jar.

## Secure storage — how this satisfies #65

The app **never** uses the plaintext dev constructor `MyceliumClient(dataDir)`.
`ClientHolder` builds the client with the production constructor:

```kotlin
MyceliumClient.newWithSecretStore(filesDir.path, AndroidKeystoreSecretStore(context))
```

`AndroidKeystoreSecretStore` (the #65 Android adapter) implements the SDK's
`SecretStore` seam with the **envelope** pattern from
[`docs/research/SECURE-STORAGE.md`](../../docs/research/SECURE-STORAGE.md) §2.1:

- a non-exportable **AES-256-GCM wrapping key** in the `AndroidKeyStore` provider
  (hardware-backed via **StrongBox**/TEE where available — StrongBox is tried
  first, with a TEE fallback);
- each secret the SDK stores (today the ~64-byte identity under `"identity"`) is
  sealed with that key; only the `[iv | ciphertext+tag]` blob is written to
  app-private `filesDir/secretstore/`.

It **fails closed** (SECURE-STORAGE.md §6): `load` returns `null` *only* for a
genuinely absent key; a corrupt blob, AEAD tag mismatch, or unavailable Keystore
throws an `SdkException` rather than returning `null` — so the SDK never mistakes
an unreadable identity for "no identity" and silently generates a fresh one.

The wrapped blob and the encrypted store are excluded from Auto Backup / device
transfer (`android:allowBackup="false"` plus the `res/xml` backup rules), so the
account root key never leaves the device via restore. **Residual limits** (stated
plainly, per the doc): this does not protect a **rooted device with the screen
unlocked** or an in-process attacker while unlocked, and StrongBox only raises the
cost. Losing the device is recoverable without exporting any secret — the account
re-binds from a fresh device by **email verification** (#6).

## Threading

All SDK methods **block**. Every call runs on `Dispatchers.IO` inside
`MessengerViewModel`; `SdkException` variants are mapped to user-facing errors.
The `EventListener` fires from a Rust thread and marshals a UI refresh back onto
the ViewModel scope.

## Layout

```
clients/android/
├── build-rust.sh              cargo-ndk build + uniffi-bindgen generate
├── settings.gradle.kts
├── build.gradle.kts           plugin versions (AGP 8.5.2, Kotlin 2.0.20)
├── gradle.properties
├── gradle/wrapper/gradle-wrapper.properties   (JAR regenerated via `gradle wrapper`)
├── README.md
├── .gitignore
└── app/
    ├── build.gradle.kts        Compose BOM, coroutines, JNA @aar, jniLibs + generated source sets
    ├── proguard-rules.pro      keep JNA + generated binding + callbacks
    └── src/main/
        ├── AndroidManifest.xml INTERNET; single Activity; backup exclusions
        ├── res/…               strings, theme, backup rules
        └── java/eu/mycellium/android/
            ├── MyceliumApp.kt
            ├── ClientHolder.kt              builds the one client via newWithSecretStore
            ├── AndroidKeystoreSecretStore.kt  the #65 Keystore SecretStore adapter
            ├── MessengerViewModel.kt        all SDK calls on Dispatchers.IO + EventListener
            ├── MainActivity.kt
            └── ui/
                ├── Screens.kt              Setup / Onboarding / Conversations / Thread / Contacts
                └── theme/Theme.kt
```

## Relationship to the rest of the repo

This project is **outside** the Cargo workspace and outside main CI on purpose —
it depends on `mycellium-sdk` only through the generated binding + the cargo-ndk
`.so`, never as a workspace member. Nothing here modifies any Rust crate. See
[`docs/NATIVE-CLIENTS.md`](../../docs/NATIVE-CLIENTS.md) for the multi-platform
plan (iOS/macOS via the shared Swift binding; desktop via Tauri).
