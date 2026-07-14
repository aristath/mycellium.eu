# mycellium-core

Portable, `no_std`-capable protocol types and cryptography.

The account root is a secp256k1 wallet key. It defines the stable `UserId` and
signs one active device record. Handles and display names are non-unique labels.

The active device owns:

- an Ed25519 device signing key;
- X25519 messaging material;
- a Reticulum destination derived from device-local key material.

Signed public records bind the user id, wallet, labels, one active device, and
that device's Reticulum destination. They contain no IP address, server route,
message payload, or mailbox reference.

Pairwise envelopes use fresh asynchronous X3DH and ChaCha20-Poly1305. Group
messages use sender keys and a symmetric forward ratchet, with device-specific
sender-key distribution carried inside pairwise envelopes.

`wire::encode` writes one format-version byte followed by deterministic postcard
bytes. `wire::canonical` omits that envelope byte and is used for signatures.

The crate never accesses networking, disk, time, or OS randomness directly;
hosts provide those capabilities through traits.
