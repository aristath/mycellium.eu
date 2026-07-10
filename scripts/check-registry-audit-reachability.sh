#!/usr/bin/env bash
set -euo pipefail

tree_output="$(mktemp)"
trap 'rm -f "$tree_output"' EXIT

check_registry_unreachable() {
  local package="$1"

  if cargo tree -p mycellium-registry -i "$package" >"$tree_output" 2>&1; then
    cat "$tree_output" >&2
    echo "$package is reachable from mycellium-registry" >&2
    exit 1
  fi

  if ! rg -q "did not match any packages|nothing to print" "$tree_output"; then
    cat "$tree_output" >&2
    exit 1
  fi
}

check_registry_unreachable hickory-proto
check_registry_unreachable lru
check_registry_unreachable paste

if cargo tree -p mycellium-transport --target all | rg "hickory|libp2p-dns|libp2p-mdns"; then
  echo "hickory DNS/mDNS packages are reachable from active mycellium-transport features" >&2
  exit 1
fi
