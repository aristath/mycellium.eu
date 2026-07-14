# mycellium-transport

Concrete transport adapters for Mycellium.

Native delivery uses Reticulum:

- each active device publishes a signed Reticulum destination in its public
  record;
- messages and ACKs are sent to that destination;
- lower-level Reticulum routes are transport plumbing, never Mycellium identity.

`reticulum_net` is enabled by default. It reads optional Reticulum TCP nodes
from `MYCELLIUM_RETICULUM_TCP_NODES`.

`link` implements four-byte big-endian length framing with a 16 MiB abuse
ceiling.

`libp2p_net` and `net` are optional legacy/diagnostic adapters. They are not the
native delivery path.
