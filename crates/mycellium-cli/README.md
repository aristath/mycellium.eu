# mycellium-cli

Low-level terminal tools for exercising protocol, storage, record exchange,
Reticulum delivery, DHT record discovery, outbox, groups, and trust behavior.

This is a diagnostic shell, not the polished end-user client.

```sh
cargo run -p mycellium-cli -- --help
cargo run -p mycellium-cli -- <command> --help
```

By default it stores encrypted state under `.mycellium`. `--config <file>`
accepts JSON keys `data_dir`, `passphrase`, `display_name`, and
`dht_bootstrap`. Omitting `passphrase` uses a no-echo terminal prompt.

Native Linux, Android, and Apple clients identify devices by signed Reticulum
destinations in public records. CLI DHT commands are non-authoritative
signed-record distribution tools, not message transport.
