#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
headers="$script_dir/Sources/mycellium_mobileFFI"

command -v xcodebuild >/dev/null || {
  echo "xcodebuild is required; run this script on macOS with Xcode installed" >&2
  exit 1
}

rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
(cd "$repo_root" && cargo build --release -p mycellium-mobile --target aarch64-apple-ios)
(cd "$repo_root" && cargo build --release -p mycellium-mobile --target aarch64-apple-ios-sim)

rm -rf "$script_dir/MycelliumFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$repo_root/target/aarch64-apple-ios/release/libmycellium_mobile.a" -headers "$headers" \
  -library "$repo_root/target/aarch64-apple-ios-sim/release/libmycellium_mobile.a" -headers "$headers" \
  -output "$script_dir/MycelliumFFI.xcframework"
