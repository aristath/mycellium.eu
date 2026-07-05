#!/usr/bin/env bash
# Generate the UniFFI foreign-language bindings for mycellium-sdk.
#
# - Kotlin  → Android (`clients/android`, consumed with the cargo-ndk .so)
# - Swift   → iOS + macOS (`clients/apple`, packaged as an xcframework)
# - The generated `mycellium_sdkFFI.h` C header is the **desktop C-ABI** surface
#   (Tauri/desktop shells can bind the crate directly or via this header).
#
# Doubles as a CI **smoke test**: if the SDK's UniFFI surface ever stops being
# binding-compatible, generation fails and the build goes red. See
# docs/NATIVE-CLIENTS.md for how each app consumes these.
#
# Usage: crates/mycellium-sdk/bindings/generate.sh [OUT_DIR]
set -euo pipefail

crate_dir="$(cd "$(dirname "$0")/.." && pwd)"
repo_root="$(cd "$crate_dir/../.." && pwd)"
out="${1:-$crate_dir/bindings/generated}"

cd "$repo_root"
cargo build -p mycellium-sdk --lib

lib="$(find "$repo_root/target/debug" -maxdepth 1 \
  \( -name 'libmycellium_sdk.so' -o -name 'libmycellium_sdk.dylib' -o -name 'mycellium_sdk.dll' \) \
  | head -1)"
if [ -z "$lib" ]; then
  echo "error: could not find the built mycellium-sdk cdylib under target/debug" >&2
  exit 1
fi

mkdir -p "$out"
for lang in kotlin swift; do
  cargo run -q -p mycellium-sdk --bin uniffi-bindgen -- \
    generate --library "$lib" --language "$lang" --out-dir "$out"
done

# Assert the expected artifacts materialized (the smoke-test assertion).
kt="$(find "$out" -name '*.kt' | head -1)"
sw="$(find "$out" -name '*.swift' | head -1)"
[ -n "$kt" ] || { echo "error: no Kotlin binding was generated" >&2; exit 1; }
[ -n "$sw" ] || { echo "error: no Swift binding was generated" >&2; exit 1; }
echo "ok: generated Kotlin ($kt) + Swift ($sw) bindings + C header in $out"
