# mycellium-transport

Concrete transport adapters for Mycellium.

Native clients use authenticated libp2p QUIC:

- `/mycellium/1.0` carries framed message payloads and ACKs directly between
  device PeerIds.
- `/mycellium/rendezvous/1.0` carries only authenticated presence and
  introduction control between a device and the registry.
- `/mycellium/kad/1.0` is optional non-authoritative distribution of signed
  public records; it never stores messages.

The device listens on an OS-selected UDP port. Its stable identity is its
device-key-derived PeerId. The registry reports short-lived observed UDP
mappings and complementary simultaneous-dial roles; both devices then punch and
form their own QUIC connection. There is no relay transport or server-payload
fallback.

`link` implements four-byte big-endian length framing with a 16 MiB abuse
ceiling. `net` is a minimal TCP adapter retained for low-level local tools and
tests; it is not the native-client discovery path. The `libp2p` feature is
enabled by default.
