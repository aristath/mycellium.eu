# Mycellium Android app module

> The Gradle `:app` package for the Android client: a Jetpack Compose shell over the UniFFI Kotlin binding generated from `mycellium-sdk`.

This directory is the installable Android application package (`applicationId =
eu.mycellium.android`). It deliberately contains no protocol, crypto, queue,
directory, or local-store logic. Those live in Rust behind the SDK; this module
owns Android UI, lifecycle, secure-storage glue, and the build wiring that loads
the generated binding and native libraries.

For the full client overview, start with [`../README.md`](../README.md). This
file documents the app-module boundary.

## What Lives Here

```text
app/
├── build.gradle.kts                  Android app plugin, Compose, JNA, test deps
├── proguard-rules.pro                Keep rules for JNA, UniFFI, and callbacks
└── src/
    ├── main/
    │   ├── AndroidManifest.xml       INTERNET, single Activity, backup disabled
    │   ├── java/eu/mycellium/android/
    │   │   ├── AndroidKeystoreSecretStore.kt
    │   │   ├── ClientHolder.kt
    │   │   ├── MainActivity.kt
    │   │   ├── MessengerViewModel.kt
    │   │   ├── MyceliumApp.kt
    │   │   └── ui/
    │   └── res/
    └── androidTest/
        └── java/eu/mycellium/android/MessagingE2eTest.kt
```

Generated artifacts are intentionally not source:

- `src/main/jniLibs/<abi>/libmycellium_sdk.so`
- `build/generated/uniffi/uniffi/mycellium_sdk/mycellium_sdk.kt`

Run `../build-rust.sh` to regenerate both whenever the SDK surface changes.

## Build Contract

`build.gradle.kts` wires the two generated SDK artifacts into the app:

- `sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")` loads the Rust
  `cdylib` files produced by `cargo-ndk`.
- `sourceSets["main"].java.srcDir(layout.buildDirectory.dir("generated/uniffi"))`
  compiles the generated Kotlin binding.
- `checkRustArtifacts` runs before `preBuild` and fails early with a clear error
  when either artifact is missing.

The app depends on `net.java.dev.jna:jna:5.14.0@aar`. Keep the `@aar` classifier:
the generated Kotlin binding calls the Rust library through JNA, and the Android
AAR is what bundles JNA's own per-ABI native libraries.

## Runtime Shape

- `ClientHolder` owns the single SDK client for the process.
- `AndroidKeystoreSecretStore` implements the SDK `SecretStore` boundary with an
  Android Keystore wrapping key and app-private sealed blobs.
- `MessengerViewModel` is the UI boundary. SDK calls are blocking, so they run on
  `Dispatchers.IO`; state is exposed to Compose screens.
- `MainActivity` hosts the Compose UI.
- `network_security_config.xml` allows emulator/device development against local
  directory and queue endpoints.

The production app must use `MyceliumClient.newWithSecretStore(...)`, not the
plaintext development constructor.

## Build

From `clients/android`:

```sh
./build-rust.sh
./gradlew :app:assembleDebug
```

Open `clients/android` in Android Studio if you want IDE sync and device deploy.
Re-run `./build-rust.sh` after changing `crates/mycellium-sdk`.

## Instrumented Tests

`src/androidTest/.../MessagingE2eTest.kt` exercises the real Android stack:

```text
UniFFI Kotlin binding -> JNA -> libmycellium_sdk.so -> HTTP ->
live directory + queue -> decrypt
```

The tests expect host-side directory and queue services reachable from the
emulator, usually at `10.0.2.2`, and the directory must run with
`MYCELLIUM_DEV_AUTH=1` so email verification returns a dev code.

The runner accepts optional arguments:

- `host` default `10.0.2.2`
- `dirPort` default `18080`
- `queuePort` default `18090`

Example:

```sh
./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.host=10.0.2.2 \
  -Pandroid.testInstrumentationRunnerArguments.dirPort=18080 \
  -Pandroid.testInstrumentationRunnerArguments.queuePort=18090
```

## Do Not Hand-Edit

- Generated UniFFI Kotlin under `app/build/generated/uniffi/`
- Native libraries under `app/src/main/jniLibs/`
- Anything under `app/build/`

Change the Rust SDK, rerun `../build-rust.sh`, then rebuild this module.
