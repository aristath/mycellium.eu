# mycellium-cli

Low-level terminal tools for exercising protocol, storage, record exchange,
direct transport, DHT record discovery, outbox, groups, and trust behavior.
This is a diagnostic shell, not the end-user account-login client.

```sh
cargo run -p mycellium-cli -- --help
cargo run -p mycellium-cli -- <command> --help
```

By default it stores encrypted state under `.mycellium`. `--config <file>`
accepts JSON keys `data_dir`, `passphrase`, `display_name`, and
`dht_bootstrap`. Omitting `passphrase` uses a no-echo terminal prompt.

TCP addresses accepted by some commands are explicit low-level routes for
local tools. Native Linux, Android, and Apple clients identify devices by
PeerId and use registry-coordinated direct QUIC instead.
