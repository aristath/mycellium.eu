# Architecture

Mycellium is split into small crates:

- `mycellium-core`: portable identity, record, message, login, and storage traits.
- `mycellium-engine`: native orchestration over the core.
- `mycellium-storage`: encrypted local storage plus explicit client config.
- `mycellium-directory`: signed-record and presence directory.
- `mycellium-queue`: opaque store-and-forward mailbox.
- `mycellium-relay`: libp2p Circuit Relay v2 server.
- `mycellium-cli`, `mycellium-client`, and platform clients: user-facing shells.

Services are configured with JSON and can run in explicit `--dev` mode for local
work. Durable deployments set `data_dir` in JSON; TLS, SMTP, access logging, and
push allowlists are JSON fields, not shell state.
