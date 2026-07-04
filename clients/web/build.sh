#!/usr/bin/env bash
# Build the Mycellium WASM engine and generate browser bindings into ./pkg.
# Requires: rustup target add wasm32-unknown-unknown; cargo install wasm-bindgen-cli.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(cd ../.. && pwd)"
CRATE="$ROOT/crates/mycellium-wasm"

( cd "$CRATE" && cargo build --target wasm32-unknown-unknown --release )
wasm-bindgen --target web \
  --out-dir "$ROOT/clients/web/pkg" \
  "$CRATE/target/wasm32-unknown-unknown/release/mycellium_wasm.wasm"

echo "built → clients/web/pkg"
