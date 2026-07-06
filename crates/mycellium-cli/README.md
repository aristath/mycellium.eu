# mycellium-cli

The terminal shell over `mycellium-engine`.

## Config

Pass a JSON config with `--config`:

```json
{
  "data_dir": "./data/alice",
  "passphrase": "a local dev passphrase",
  "queue": "http://127.0.0.1:8090",
  "name": "Alice"
}
```

`data_dir` selects the local profile. `passphrase` is optional; without it the
CLI prompts. `queue` is recorded in your signed directory record so other peers
can leave offline messages. `name` is the display name published in your record.

## Quick Start

```sh
mycellium --config alice.client.json identity-new
mycellium --config alice.client.json register alice \
  --addr 127.0.0.1:9001 --directory http://127.0.0.1:8080
mycellium --config alice.client.json send bob --as alice \
  --message "hi" --directory http://127.0.0.1:8080
mycellium --config alice.client.json inbox --as alice \
  --directory http://127.0.0.1:8080
```

## Commands

- `identity-new`, `identity-show`
- `register`, `pair`, `pair-approve`, `devices`, `revoke-device`
- `send`, `chat`, `listen`, `serve`, `inbox`, `outbox`, `broadcast`, `forward`
- `announce`, `presence`, `verify`, `card`, `verify-card`
- `group create/send/add/history/info/leave/sync/list`
- `contact add/list/remove`
- `history`, `clear-history`, `conversations`, `search`
- `draft set/show/clear`, `expire set/clear/show`
- `block`, `unblock`, `blocked`
- `export`, `import`, `wipe`

Every command that talks to the directory accepts `--directory`, defaulting to
`http://127.0.0.1:8080`.
