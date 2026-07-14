#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
generated="$script_dir/Sources/MycelliumMobile/Generated"
ffi="$script_dir/Sources/mycellium_mobileFFI"

(cd "$repo_root" && cargo build -p mycellium-mobile --lib)

library="$repo_root/target/debug/libmycellium_mobile.so"
test -f "$library" || library="$repo_root/target/debug/libmycellium_mobile.dylib"
test -f "$library" || { echo "Host Mycellium library was not produced" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
(cd "$repo_root" && cargo run -q -p mycellium-mobile --bin uniffi-bindgen -- \
  generate --library "$library" --language swift --out-dir "$tmp")

mkdir -p "$generated" "$ffi"
cp "$tmp/mycellium_mobile.swift" "$generated/mycellium_mobile.swift"
cp "$tmp/mycellium_mobileFFI.h" "$ffi/mycellium_mobileFFI.h"

echo "Apple Swift bindings are ready."
