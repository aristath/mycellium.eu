# mycellium-relay

> The deployable **Circuit Relay v2** server — a thin binary shell around a listening `Libp2pNode` that forwards circuit traffic so NAT'd peers stay reachable (#59).

**Layer:** service (binary) · **Depends on:** mycellium-transport (`libp2p` feature)

## What it does

Runs a public **libp2p Circuit Relay v2** relay as a long-lived process. A
recipient behind a NAT/firewall reserves a slot on it, publishes its
`…/p2p-circuit/…` address in the directory, and senders reach that recipient
*through* this relay — no port-forwarding on the recipient's side.

It is a thin shell: all the relay mechanism (the swarm, `relay::Behaviour` as a
server, reservation grants, and circuit forwarding on a background task) already
lives in `mycellium-transport`'s `Libp2pNode`. This binary just owns the
*process* concerns — argument parsing, the environment fallback, a **stable
identity**, and staying alive — mirroring `mycellium-server` / `mycellium-queue`.

**It forwards, it never reads.** Circuit traffic is end-to-end Noise-encrypted
between the two peers; the relay only shuttles opaque bytes. It holds no message
keys and can read nothing it forwards — the worst it can do is drop traffic, and
peers then fall back to another route or the queue.

## Running it

```sh
# Default bind (0.0.0.0:8700)
cargo run -p mycellium-relay

# Explicit address
cargo run -p mycellium-relay -- --addr 0.0.0.0:8700

# Address via environment (overridden by --addr)
MYCELLIUM_RELAY_ADDR=0.0.0.0:8700 cargo run -p mycellium-relay

cargo run -p mycellium-relay -- --help      # or -h
cargo run -p mycellium-relay -- --version   # or -V
```

Address resolution order: `--addr HOST:PORT`, then `MYCELLIUM_RELAY_ADDR`, then
the default `0.0.0.0:8700`. On start it prints the **dialable multiaddr** to
advertise to peers:

```
    /ip4/203.0.113.7/tcp/8700/p2p/12D3KooW…
```

That full multiaddr (the concrete bound address plus `/p2p/<peer-id>`) is what
operators publish and what recipients pass to `serve --relay`.

## Stable identity (set `MYCELLIUM_DATA`)

A relay's PeerId is derived from a 32-byte device key and is **baked into every
client's `--relay <…/p2p/<id>>` address** — so it must not change across
restarts, or those addresses break.

- **`MYCELLIUM_DATA` set** → the key is loaded from `MYCELLIUM_DATA/relay.key`,
  or generated once and persisted there (`0600` on Unix). The PeerId is stable
  across restarts. **Set this in production.**
- **`MYCELLIUM_DATA` unset** → an ephemeral key is used and the relay warns that
  its PeerId (and every advertised relay address) will change on restart. Dev
  only.

The relay stores **no secrets of its clients** and holds no message content —
`relay.key` is only its own transport identity.

## Using it as a recipient

Point your `serve` at the relay's advertised multiaddr:

```sh
mycellium-cli serve --libp2p --relay /ip4/203.0.113.7/tcp/8700/p2p/12D3KooW… --as you
```

`serve` reserves a slot on the relay, re-publishes your circuit address to the
directory, and accepts relayed streams — so a sender who only knows your circuit
address reaches you live through the relay.

## How it fits

The relay is **independent** of the directory and queue: run it alongside them or
on its own box. It complements the queue (store-and-forward when a recipient is
offline) by giving an *online-but-NAT'd* recipient a live path. See
[`docs/DEPLOY.md`](../../docs/DEPLOY.md#running-a-relay-59) for deployment.
