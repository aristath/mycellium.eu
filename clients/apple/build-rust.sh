#!/usr/bin/env bash
# Build the mycellium-sdk host library and generate the UniFFI *Swift* binding
# this SwiftPM package compiles against.
#
# Outputs (all build artifacts — gitignored, never commit them):
#   1. <repo>/target/debug/libmycellium_sdk.so     (host lib, for `swift test` on Linux)
#   2. Sources/MyceliumSDK/Generated/mycellium_sdk.swift   (the Swift binding)
#   3. Sources/mycellium_sdkFFI/mycellium_sdkFFI.h         (the C ABI header)
#
# The committed Sources/mycellium_sdkFFI/module.modulemap references (3) by name.
#
# Run this from clients/apple BEFORE `swift build` / `swift test`, and again
# whenever the SDK's Rust surface changes, so the binding stays in lockstep.
#
# Prerequisites: Rust (`cargo`) + Swift (`swift`, only needed for build/test).
# Optional: swiftformat (bindgen auto-formats the output if present; a warning
# if absent is harmless).
#
# ── Building for Apple devices (Mac only; documented, not run here) ───────────
# This script builds the *host* `.so` so the package's core + tests build and run
# on Linux/CI. To ship the SwiftUI app under App/ on a Mac you additionally build
# the Apple static libs and bundle them into an xcframework:
#
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim \
#                     x86_64-apple-ios aarch64-apple-darwin x86_64-apple-darwin
#   for t in aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin; do
#     cargo build --release -p mycellium-sdk --target "$t"
#   done
#   # (lipo the sim/macos arches together, then:)
#   xcodebuild -create-xcframework \
#     -library target/aarch64-apple-ios/release/libmycellium_sdk.a        -headers Sources/mycellium_sdkFFI \
#     -library target/aarch64-apple-ios-sim/release/libmycellium_sdk.a    -headers Sources/mycellium_sdkFFI \
#     -library target/aarch64-apple-darwin/release/libmycellium_sdk.a     -headers Sources/mycellium_sdkFFI \
#     -output MyceliumFFI.xcframework
#
# The generated `mycellium_sdk.swift` is identical for host and device (bindgen
# reads interface metadata only), so it is reused as-is. See README.md.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
gen_swift_dir="$script_dir/Sources/MyceliumSDK/Generated"
ffi_dir="$script_dir/Sources/mycellium_sdkFFI"

command -v cargo >/dev/null || { echo "error: cargo not found (install Rust)" >&2; exit 1; }

echo "==> Building libmycellium_sdk (host, debug)"
( cd "$repo_root" && cargo build -p mycellium-sdk --lib )

lib="$repo_root/target/debug/libmycellium_sdk.so"
[ -f "$lib" ] || lib="$repo_root/target/debug/libmycellium_sdk.dylib"   # macOS host
[ -f "$lib" ] || { echo "error: no libmycellium_sdk.{so,dylib} was produced" >&2; exit 1; }

echo "==> Generating the UniFFI Swift binding from: $lib"
tmp_out="$(mktemp -d)"
trap 'rm -rf "$tmp_out"' EXIT
( cd "$repo_root" && cargo run -q -p mycellium-sdk --bin uniffi-bindgen -- \
    generate --library "$lib" --language swift --out-dir "$tmp_out" )

for f in mycellium_sdk.swift mycellium_sdkFFI.h mycellium_sdkFFI.modulemap; do
  [ -f "$tmp_out/$f" ] || { echo "error: bindgen did not produce $f" >&2; exit 1; }
done

mkdir -p "$gen_swift_dir" "$ffi_dir"
# The Swift binding -> the MyceliumSDK target; the C header -> the FFI target
# (its committed module.modulemap references the header by name).
cp "$tmp_out/mycellium_sdk.swift" "$gen_swift_dir/mycellium_sdk.swift"
cp "$tmp_out/mycellium_sdkFFI.h"  "$ffi_dir/mycellium_sdkFFI.h"
# NOTE: we do NOT copy the generated *.modulemap — our committed
# Sources/mycellium_sdkFFI/module.modulemap is the one SwiftPM uses (it must be
# named exactly `module.modulemap`). They are byte-identical in content.

echo "ok:"
echo "  host lib -> $lib"
echo "  binding  -> $gen_swift_dir/mycellium_sdk.swift"
echo "  header   -> $ffi_dir/mycellium_sdkFFI.h"
echo "Next: 'swift build' then 'swift test' (start a dev directory+queue first — see README)."
