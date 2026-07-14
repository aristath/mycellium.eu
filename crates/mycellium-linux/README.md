# Mycellium for Linux

Native `egui` desktop client.

Run with Rust 1.96 or newer:

```sh
cargo run -p mycellium-linux
```

The production registry is `https://registry.mycellium.eu`. Override it for a
local registry with:

```sh
MYCELLIUM_REGISTRY_URL='http://[::1]:8787' cargo run -p mycellium-linux
```

Local data is always stored at `$XDG_DATA_HOME/mycellium`, or
`~/.local/share/mycellium` when `XDG_DATA_HOME` is unset. The path is not
user-configurable in the app.

First use is email, one-time code, passphrase, then display name and non-unique
handle. The client publishes one active device with a Reticulum destination.

For local Reticulum connectivity experiments:

```sh
MYCELLIUM_RETICULUM_TCP_NODES=node.example:4242 cargo run -p mycellium-linux
```

Logging in on another device replaces this device. The client keeps local
history visible but disables sending, receiving, and outbox retries until the
user logs in and deliberately activates it again.
