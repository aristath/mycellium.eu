# mycellium-relay

The deployable Circuit Relay v2 server for libp2p traffic.

## Run

```sh
mycellium-relay --dev
mycellium-relay --config relay.json
```

Config is JSON:

```json
{
  "addr": "0.0.0.0:8700",
  "data_dir": "./data/relay"
}
```

`data_dir` stores `relay.key`, which keeps the relay PeerId stable across
restarts. `--dev` uses an ephemeral key and is only for local experiments.
