# WebRTC as a Mycellium transport

*Design note / future work. Where WebRTC would help Mycellium, how it fits the
existing architecture, and what it would cost. Nothing here is implemented yet —
this exists so a future session picks it up instead of rediscovering it.*

## The one-line case

WebRTC solves the two places Mycellium **can't currently deliver directly**:

1. **In the browser.** The PWA has no peer-to-peer path at all — a browser can't
   open a raw TCP or libp2p-TCP socket, so `clients/web` talks only over HTTP
   (`XhrTransport`) to the directory + queue. Every browser message is
   store-and-forward through the queue; there is no browser↔anyone direct line.
   **WebRTC DataChannels are the only mechanism that gives a browser real P2P.**
2. **Behind hard NATs (natively).** Direct delivery today works for
   publicly-reachable peers (TCP) and, since the #59 work, libp2p multiaddrs — but
   NAT traversal (hole punching, relay) is unbuilt. WebRTC's **ICE** stack (STUN
   for reflexive addresses, TURN for relayed fallback) is the most battle-tested
   NAT-traversal solution there is.

Both are the *same* machinery, so one WebRTC transport serves both.

## It's a transport, not a crypto change

This is the load-bearing point. Mycellium's security lives in the **core**
(X3DH + Double Ratchet over the `Transport`/`Connection` ports in
`crates/mycellium-core/src/transport.rs`). A WebRTC transport is a **new adapter
implementing those same ports** — a `Connection` whose bytes happen to flow over a
DataChannel — exactly as `mycellium-transport`'s `net.rs` (TCP) and `libp2p_net.rs`
(libp2p) do today. The engine's delivery ladder (`app/messaging.rs`) and the
ratchet don't change; they just get another rung.

WebRTC's own DTLS/SRTP encrypts the channel hop-by-hop, but **E2E stays
Mycellium's** — the Double Ratchet runs *on top of* the DataChannel, same as it
runs on top of TCP now. WebRTC never sees plaintext, and a compromised TURN relay
sees only ratchet ciphertext. So this adds reach, not trust.

## Signaling rides the queue we already have

WebRTC needs an out-of-band channel to exchange **SDP offers/answers + ICE
candidates** before a peer connection forms. Mycellium already has the perfect
carrier: the **queue**, and specifically the **rendezvous-relay pattern** the
device-pairing flow already uses (`crates/mycellium-queue/src/lib.rs` — the `pair`
slots: bounded, TTL'd, ephemeral relay of opaque messages by id). Signaling is:

- Send the SDP offer to the peer as a **sealed queue message** (or a pairing-style
  rendezvous slot). The peer replies with its answer + trickled ICE candidates the
  same way.
- No new signaling server — the queue *is* the signaling relay, and the payloads
  are E2E-sealed like everything else, so the queue learns nothing new beyond the
  sender↔recipient linkage it already has.

This means the hard "where does signaling live" question is already answered.

## Rust / platform fit

- **Native (engine + SDK):** [`webrtc-rs`](https://github.com/webrtc-rs/webrtc) — a
  pure-Rust WebRTC stack (ICE + DTLS + SCTP DataChannels). It slots behind the
  `Transport`/`Connection` ports like libp2p does. Heavy, but real.
- **Browser (PWA):** the browser's **built-in** WebRTC via `web-sys`
  (`RTCPeerConnection` / `RTCDataChannel`) — no `webrtc-rs` needed in wasm, just a
  thin `Connection` adapter over the JS API. This is what finally gives the WASM
  engine a P2P transport (today it has only `XhrTransport`).

One `Transport` port, two adapters — the same shape as TCP-vs-libp2p today.

## The wins, concretely

- **PWA becomes a first-class P2P peer.** Browser↔browser and browser↔native
  direct, live E2E messaging — instead of the queue-only PWA of today. This is the
  single biggest unlock and is *impossible* without WebRTC (or a WebSocket relay,
  which isn't P2P).
- **NAT traversal for #59.** ICE/STUN/TURN is a mature alternative (arguably more
  proven at internet scale than libp2p AutoNAT/DCUtR/Circuit-Relay) for getting
  direct delivery through NATs — and it composes with the existing reachability
  ladder + `DeliveryPath` scoring: WebRTC becomes the `Direct`/`Relay` rung when
  TCP/libp2p can't connect, with the queue still the guaranteed floor.
- **Future voice/video.** If Mycellium ever adds calls, WebRTC is the standard
  media stack — the DataChannel work lays the groundwork.

## The honest costs

- **TURN relay servers.** For symmetric-NAT pairs, ICE falls back to a **TURN**
  relay — a live, always-on relay a recipient/provider must run. This is real
  operational overhead, and it *overlaps conceptually* with two things Mycellium
  already has: the store-and-forward **queue**, and the **Circuit-Relay** idea in
  `REACHABILITY.md`. Worth deciding whether TURN replaces or coexists with those.
  (A relayed WebRTC channel is live/low-latency; the queue is store-and-forward —
  different trade-offs, both useful.)
- **Dependency weight + complexity.** `webrtc-rs` is large (ICE + DTLS + SCTP +
  SDP). It's heavier than raw TCP and a meaningful addition to the native build.
- **Not anonymity.** Like every transport, WebRTC hides content (via the ratchet)
  but not *that*/*whom*/*when* — STUN/TURN servers and the signaling relay see
  connection metadata. It changes reach, not the metadata story (see
  `SECURITY.md`, `PRIVACY-MODES.md`).

## How it relates to the rest of the roadmap

- **#59 (native reachability):** WebRTC ICE is an alternative/complement to the
  libp2p AutoNAT/DCUtR/relay path. A project could pick one; WebRTC has the bonus
  of also solving the browser.
- **#62 (LAN discovery):** a LAN-discovered peer could form a WebRTC channel
  directly (host ICE candidates), no STUN/TURN needed.
- **PWA (`clients/web`):** this is the doc that says how the browser client stops
  being queue-only. Ties into the native-first framing — even as a
  POC/fallback, a P2P-capable PWA is far more capable.

## Suggested phased plan

1. **Design spike:** confirm the `Connection`-over-DataChannel shape against the
   `webrtc-rs` and `web-sys` APIs; define the SDP/ICE signaling message types that
   ride the queue (reuse the pairing rendezvous where possible).
2. **Browser DataChannel transport (highest value):** a `web-sys` `Connection`
   adapter in the wasm build + signaling over the queue → two PWAs exchange a
   ratchet message browser↔browser directly, no queue store-and-forward. This is
   the unlock and is self-contained.
3. **Native `webrtc-rs` transport:** the same `Connection` behind
   `mycellium-transport`, wired into the delivery ladder as a `Direct`/`Relay`
   rung with STUN.
4. **TURN fallback + ops:** stand up TURN (or fold it into the relay story),
   decide its relationship to the queue/Circuit-Relay.
5. **(Later) voice/video** if it's ever on the roadmap.

## Per-crate change footprint (rough)

- `mycellium-core`: possibly nothing — the `Transport`/`Connection` ports already
  fit; maybe an async variant if `webrtc-rs`'s async model demands it.
- `mycellium-transport`: a new `webrtc.rs` (native, `webrtc-rs`).
- `mycellium-wasm` / `clients/web`: a `web-sys` DataChannel `Connection` +
  signaling glue over the queue client.
- `mycellium-queue`: likely reuse the existing rendezvous/relay; maybe a dedicated
  signaling slot type.
- `mycellium-engine`: add the WebRTC rung to the reachability ladder + scoring.

## Non-goals / cautions

- Don't let WebRTC's DTLS tempt anyone into treating it as the E2E layer — the
  ratchet stays on top; WebRTC is transport only.
- Don't add it as a hard dependency of the core or the servers — it belongs in the
  client/transport layer, feature-gated like libp2p, so the lean server binaries
  and the `no_std` core are unaffected.
