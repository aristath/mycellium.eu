# mycellium-transport

> Concrete `Transport` adapters — framed TCP and libp2p — that carry the app-layer end-to-end payload.

**Layer:** adapter · **Implements:** mycellium-core `Transport` / `Connection` · **Key deps:** libp2p (feature-gated), libp2p-stream, tokio, futures, anyhow

## What it does

Provides the "direct line" between two nodes as concrete implementations of the core `Transport`/`Connection` ports. Messages are length-prefixed (a big-endian `u32` frame header, capped at 1 MiB) over the wire; the payload is the app-layer E2E ciphertext (X3DH + Double Ratchet), so even a bare TCP link is a genuine direct line. Two backends are offered: a minimal framed TCP transport, and a production libp2p stack (TCP + Noise + Yamux with a `/mycellium/1.0` stream protocol), whose PeerId is derived from the device key. The engine above depends only on the core ports, never on these types.

## Public API

- `net::TcpTransport` — a TCP `Transport`; `dialer()` (dial-only) or `listening(addr)` (also accepts). `dial` reads the target `host:port` out of the `PeerId`.
- `net::TcpConnection` — a framed `Connection` over one `TcpStream`; `connect(addr)` and `split()` into cloned read/write handles.
- `link::Wire` — a framed send/recv channel; blanket-implemented for any core `Connection<Error = io::Error>`.
- `link::FrameReader` / `link::FrameWriter` — the `Send` read/write halves used by full-duplex chat.
- `libp2p_net::Libp2pNode` — a running libp2p node owning the Tokio runtime and swarm task; `new(device_secret, listen_addr)`, `dial`/`dial_str`, `accept`, `peer_id`, `drain(millis)`.
- `libp2p_net::Libp2pConnection` — a framed `Connection` over one libp2p stream; `split()` into `Libp2pReadHalf` / `Libp2pWriteHalf` (yamux allows concurrent I/O).
- `libp2p_net::advertised_multiaddr(addr, device_secret)` — the dialable `/ip4/…/tcp/…/p2p/<peer-id>` string to publish.
- `libp2p_net::listen_multiaddr(addr)` / `peer_id_string(device_secret)` — build a listen multiaddr / derive the PeerId string without starting a node.

## Feature flags

- `libp2p` (default) — pulls in `libp2p`, `libp2p-stream`, `tokio`, and `futures`, and compiles the `libp2p_net` module (the whole libp2p backend). Disable it for a minimal or embedded shell that only needs the framed TCP transport; the `link` and `net` modules remain available.

## How it fits

The engine picks a transport behind the core `Transport` trait, so app and handshake logic never learn which backend is in use. The CLI exposes `--libp2p` to advertise a multiaddr instead of a raw TCP address; `chat` then auto-detects from the peer's published address — a leading `/` marks a libp2p multiaddr, anything else is a TCP `host:port`.

## Notes

NAT traversal (DHT, relay, DCUtR) is the remaining libp2p increment. It belongs in the swarm inside `Libp2pNode`, with no change to the app above.
