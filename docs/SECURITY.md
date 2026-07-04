# Security Model

What Mycellium protects, what it assumes, and what it deliberately does *not* claim.
This describes the system as built; see [`ARCHITECTURE.md`](ARCHITECTURE.md) for the
mechanisms and [`IMPROVEMENTS.md`](IMPROVEMENTS.md) for known rough edges.

> **Status:** not independently audited. The cryptography is assembled from vetted
> primitives (below), never invented, but a public launch should be gated on an
> external review — see [`PRODUCTION-READINESS.md`](PRODUCTION-READINESS.md) T3.1.

## Identity & trust root

Your account **is** a 24-word BIP-39 seed. From it derive a secp256k1 **wallet**
(the signing root) and, per device, distinct Ed25519 (transport) + X25519
(messaging) keys. Nothing is *issued* to you: names, devices, and reachability all
certify themselves under your wallet signature. Lose the seed and the account is
gone (that's the point); social recovery (`guardian-split`/`-recover`, Shamir over
GF(2⁸)) exists to split it across trustees.

## Cryptographic building blocks

| Purpose | Primitive |
|---------|-----------|
| Session establishment | **X3DH** over X25519 |
| Message ratchet (forward secrecy + PCS) | **Signal Double Ratchet** |
| Message AEAD | **ChaCha20-Poly1305** |
| KDFs | HKDF-SHA512 (identity), HKDF-SHA256 (root), HMAC-SHA256 (chain) |
| Wallet identity / signatures | secp256k1 (`k256`), **Ed25519** (device + group) |
| Groups | sender keys + a per-group ratchet, keyed per **device** |
| At-rest identity | Argon2id + ChaCha20-Poly1305 |
| Social recovery | Shamir secret sharing (GF(2⁸)) |

All from the RustCrypto ecosystem; secret material is held in `zeroize`-on-drop
types and `unsafe` is forbidden in the core.

## What we defend against

- **A passive network / ISP.** Sees only ciphertext and opaque, hashed ids. Message
  contents, and even usernames (hashed via `user_id` before they hit the wire), are
  not exposed.
- **A dishonest directory.** Every record is wallet-signed and self-certifying. The
  worst it can do is *withhold* or serve a *stale* record — it can never forge one or
  bind your handle to a wallet you don't control. Handles are permanently bound
  (anti-rollback via `seq`); email-proved recovery re-binds only to someone who
  controls the original verification email.
- **A dishonest queue.** Sees only opaque E2E blobs addressed to a wallet — never
  content, never the sender. It can drop or delay, not read or attribute.
- **Key compromise (bounded).** The Double Ratchet gives forward secrecy (a stolen
  current key can't decrypt past messages) and post-compromise security (the session
  heals on the next round trip).
- **Impersonation.** Knowing someone's public key gives *zero* forging power;
  authenticity requires their private key. First contact is **TOFU** — a peer's
  wallet is pinned on first sight and a later mismatch is rejected.
- **Malformed input.** The wire decoders are fuzzed (garbage / truncated / bit-flipped
  never panics and never accepts a tampered record); the ratchet rejects replays and
  bounds skipped keys.

## What is out of scope (by design or not yet)

- **Metadata.** The directory learns *who is asking about whom* and presence; the
  queue learns *which wallet has mail, and when, and roughly how much*. We minimize
  it (hashed ids, contentless push, separate services) but do **not** claim traffic
  or social-graph privacy. No cover traffic, no mixnet.
- **Seed loss / coercion.** If your seed is stolen or you're compelled to reveal it,
  the account is compromised — the security is exactly the secrecy of the seed. The
  device-link payload carries the seed, so treat a link QR like the seed itself.
- **Endpoint compromise.** Malware on your device reading plaintext is not something
  E2E can prevent. In the browser, the test hook `window.mycellium` should be
  stripped from a production build (see [`IMPROVEMENTS.md`](IMPROVEMENTS.md)).
- **Availability.** A queue you don't control can withhold your mail (run your own,
  or point your record at one you trust). NAT traversal for direct P2P is unfinished.
- **Independent audit.** Not yet done.

## Transport & at-rest posture

Peer↔peer links use Noise (via libp2p) or framed TCP; client↔service traffic is
HTTP that should run over TLS (native `MYCELLIUM_TLS_*` or a terminating proxy — see
[`DEPLOY.md`](DEPLOY.md)). Local state (history, contacts, groups, drafts, outbox)
is an encrypted file KV keyed from the identity; the seed at rest is Argon2id-sealed
under a passphrase. Servers persist only self-certifying records and opaque blobs.

In the **browser**, the IndexedDB session snapshot (which includes the seed) is
encrypted with an AES-GCM key generated once and stored **non-extractable** — the
browser holds the raw key bytes, never JavaScript, so the snapshot is ciphertext on
disk and a script can't read the seed straight out of it. This is transparent (no
passphrase prompt). *Residual limitation:* a determined attacker with the entire
browser profile could, depending on browser internals, still recover a
non-extractable key — so this raises the bar but is not a substitute for OS-level
full-disk encryption on an untrusted device.

## Reporting

Found a vulnerability? Please report privately rather than opening a public issue,
and allow time to fix before disclosure.
