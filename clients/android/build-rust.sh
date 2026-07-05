#!/usr/bin/env bash
# Build the mycellium-sdk native libraries for Android and generate the UniFFI
# Kotlin binding the app compiles against.
#
# Two outputs, both build artifacts (gitignored — never commit them):
#   1. app/src/main/jniLibs/<abi>/libmycellium_sdk.so   (via cargo-ndk)
#   2. app/build/generated/uniffi/uniffi/mycellium_sdk/mycellium_sdk.kt
#                                                        (via uniffi-bindgen)
#
# Prerequisites (install once):
#   - Rust + the Android targets:
#       rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#   - cargo-ndk:
#       cargo install cargo-ndk
#   - The Android NDK, with ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) pointing at it
#     (Android Studio: SDK Manager -> SDK Tools -> NDK (Side by side)).
#
# Run this from clients/android BEFORE the first Gradle sync/build, and again
# whenever the SDK's Rust surface changes. See README.md.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
app_dir="$script_dir/app"
jni_dir="$app_dir/src/main/jniLibs"
binding_dir="$app_dir/build/generated/uniffi"

# ABIs to build. Keep in sync with `abiFilters` in app/build.gradle.kts.
# arm64-v8a  -> aarch64-linux-android      (modern phones)
# armeabi-v7a-> armv7-linux-androideabi    (older 32-bit phones)
# x86_64     -> x86_64-linux-android       (emulator on x86 hosts)
abis=(arm64-v8a armeabi-v7a x86_64)

command -v cargo >/dev/null || { echo "error: cargo not found (install Rust)" >&2; exit 1; }
command -v cargo-ndk >/dev/null || {
  echo "error: cargo-ndk not found. Install it: cargo install cargo-ndk" >&2
  exit 1
}
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${ANDROID_NDK_ROOT:-}" ]; then
  echo "warning: neither ANDROID_NDK_HOME nor ANDROID_NDK_ROOT is set;" >&2
  echo "         cargo-ndk will try to locate the NDK but may fail." >&2
fi

echo "==> Building libmycellium_sdk.so for: ${abis[*]}"
cargo_ndk_args=()
for abi in "${abis[@]}"; do
  cargo_ndk_args+=(-t "$abi")
done
# cargo-ndk resolves each -t <android-abi> to the matching rustup target and
# drops the built .so into <-o>/<abi>/libmycellium_sdk.so.
( cd "$repo_root" && cargo ndk "${cargo_ndk_args[@]}" -o "$jni_dir" build --release -p mycellium-sdk )

echo "==> Generating the UniFFI Kotlin binding"
mkdir -p "$binding_dir"
# Generate from one of the freshly built Android .so files so the binding always
# matches the ABI/metadata of the library the app will load. uniffi-bindgen only
# reads the embedded interface metadata, so any one ABI's .so is fine.
lib="$jni_dir/arm64-v8a/libmycellium_sdk.so"
[ -f "$lib" ] || lib="$(find "$jni_dir" -name 'libmycellium_sdk.so' | head -1)"
[ -n "$lib" ] && [ -f "$lib" ] || { echo "error: no libmycellium_sdk.so was produced" >&2; exit 1; }

( cd "$repo_root" && cargo run -q -p mycellium-sdk --bin uniffi-bindgen -- \
    generate --library "$lib" --language kotlin --out-dir "$binding_dir" )

kt="$(find "$binding_dir" -name 'mycellium_sdk.kt' | head -1)"
[ -n "$kt" ] || { echo "error: Kotlin binding was not generated" >&2; exit 1; }

echo "ok:"
echo "  native libs -> $jni_dir/<abi>/libmycellium_sdk.so"
echo "  binding     -> $kt"
echo "Next: open clients/android in Android Studio (or run 'gradle build')."
