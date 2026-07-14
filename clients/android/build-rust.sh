#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
jni_dir="$script_dir/app/src/main/jniLibs"
binding_dir="$script_dir/app/build/generated/uniffi"
read -r -a abis <<< "${ANDROID_ABIS:-arm64-v8a armeabi-v7a x86_64}"

command -v cargo-ndk >/dev/null || {
  echo "cargo-ndk is required: cargo install cargo-ndk" >&2
  exit 1
}

args=()
for abi in "${abis[@]}"; do
  args+=(-t "$abi")
done

(cd "$repo_root" && cargo ndk "${args[@]}" -o "$jni_dir" build --release -p mycellium-mobile)

# cargo-ndk also copies cdylib artifacts produced by dependencies. The mobile
# library links those dependencies statically, so only package our JNI entrypoint.
find "$jni_dir" -type f -name '*.so' ! -name 'libmycellium_mobile.so' -delete

library="$(find "$jni_dir" -name libmycellium_mobile.so -print -quit)"
test -n "$library" || { echo "libmycellium_mobile.so was not produced" >&2; exit 1; }
mkdir -p "$binding_dir"
(cd "$repo_root" && cargo run -q -p mycellium-mobile --bin uniffi-bindgen -- \
  generate --library "$library" --language kotlin --out-dir "$binding_dir")

echo "Android Rust libraries and Kotlin bindings are ready."
