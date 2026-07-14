# mycellium-core

Portable, `no_std`-capable protocol types and cryptography.

The account root is a secp256k1 wallet key. It certifies one active device's
Ed25519 transport key and X25519 messaging material. The Ed25519 public key is
encoded into the exact stable libp2p PeerId. Handles and display names are
non-unique labels; `UserId`, derived from the wallet public key, is the stable
person identifier. Handles are 1–32 bytes of lowercase ASCII letters, digits,
or underscores. Display names are free-form and limited to 128 encoded bytes.

Signed public records bind the user id, wallet, profile labels, and one active
device. They contain no persistent IP address. Rendezvous types carry only
short-lived introduction control.

Each pairwise envelope performs a fresh asynchronous X3DH exchange and uses the
result for one ChaCha20-Poly1305 ciphertext. The format is explicitly versioned
and does not claim a persistent Double Ratchet session. Group messages use
sender keys and a symmetric forward ratchet, with device-specific sender-key
distribution carried inside pairwise envelopes.

`wire::encode` writes one format-version byte followed by deterministic postcard
bytes. `wire::canonical` omits that envelope byte and is used for signatures.
The crate never accesses networking, disk, time, or OS randomness directly;
hosts provide those capabilities through traits.
