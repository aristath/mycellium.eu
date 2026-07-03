# mycellium-server

> The deployable directory server — a thin binary shell that serves `mycellium-directory` over HTTP.

**Layer:** service (binary) · **Depends on:** mycellium-directory

## What it does

Runs the directory as a long-lived process. It owns the *process* concerns —
argument parsing, the environment fallback, and the bind address — then hands
off to `mycellium_directory::serve`. No protocol logic lives here: the server
holds no keys, reads no message content, and can at worst withhold or serve a
stale record. It is deliberately dependency-lean (no arg-parsing crate).

## Running it

```sh
# Default bind (127.0.0.1:8080)
cargo run -p mycellium-server

# Explicit address
cargo run -p mycellium-server -- --addr 0.0.0.0:8080

# Address via environment (overridden by --addr)
MYCELLIUM_DIRECTORY_ADDR=0.0.0.0:8080 cargo run -p mycellium-server

cargo run -p mycellium-server -- --help      # or -h
cargo run -p mycellium-server -- --version   # or -V
```

Address resolution order: `--addr HOST:PORT`, then `MYCELLIUM_DIRECTORY_ADDR`,
then the default `127.0.0.1:8080`. On start it prints a banner listing the
served routes (`/health`, `/login/{challenge,verify}`, `/records/{handle}`,
`/mailbox/{handle}/{slot}`, `/presence/{handle}`).

## How it fits

All directory logic — login, the signed-record store, presence — lives in
`mycellium-directory`; this crate is just the shell that binds it to a socket.
The queue is a separate service with its own server (`mycellium-queue`).

## Notes

Deliberately minimal today: plain HTTP, in-memory state, single process, no
configuration beyond the address. A production deployment would add TLS,
persistence for the record store, and replication (the directory is tiny and
unforgeable, so it is designed to be cloned across many nodes).
