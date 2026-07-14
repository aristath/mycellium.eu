# Mycellium for Linux

Native `egui` desktop client.

Run with Rust 1.96 or newer:

```sh
cargo run -p mycellium-linux
```

The production registry is `https://registry.mycellium.eu`. Override it for a
local registry with:

```sh
MYCELLIUM_REGISTRY_URL=http://127.0.0.1:8787 cargo run -p mycellium-linux
```

Local data is always stored at `$XDG_DATA_HOME/mycellium`, or
`~/.local/share/mycellium` when `XDG_DATA_HOME` is unset. The fallback when no
home directory exists is `.mycellium`. The path is not user-configurable in the
app. The identity is protected by the user's passphrase; message history and
the registry session are encrypted with the identity-derived storage key.

First use is email, one-time code, passphrase, then display name and non-unique
handle. The client publishes one active device and opens direct QUIC on an
OS-selected UDP port. Contacts are added with self-authenticating connection
cards, not by handle lookup.

Logging in on another device replaces this device. The client checks the
registry record at startup and every minute. A replaced client keeps local
history visible but disables sending, receiving, and outbox retries until the
user logs in and deliberately activates it again.
