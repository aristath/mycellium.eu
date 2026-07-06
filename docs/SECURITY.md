# Security Model

What Mycellium protects, what it assumes, and what it deliberately does *not* claim.
This describes the system as built; see [`ARCHITECTURE.md`](ARCHITECTURE.md) for the
mechanisms and [`PRODUCTION-READINESS.md`](PRODUCTION-READINESS.md) for launch status.

> **Status:** not independently audited. The cryptography is assembled from vetted
> primitives (below), never invented, but a public launch should be gated on an
> external review — see [`PRODUCTION-READINESS.md`](PRODUCTION-READINESS.md) T3.1.

## Identity & trust root

Your account **is** a random secp256k1 **wallet key** — the signing root. There is
**no seed phrase**: the key is generated from the OS CSPRNG and held encrypted at
rest, never shown to you or written to a URL. Each device additionally holds its own
distinct Ed25519 (transport) + X25519 (messaging) keys, derived from a per-device
random seed. Nothing is *issued* to you: names, devices, and reachability all
certify themselves under your wallet signature.

- **More devices** adopt the account over the [pairing protocol](#device-pairing):
  a new device shows an ephemeral QR, an existing device scans and confirms, and the
  account key is transferred over an authenticated, single-use channel — the key
  never rides in a transferable payload.
- **Recovery** is via the directory's email verification: prove control of a
  registered email and re-bind your handle. Note the trade-off — an email rebind
  points the handle at a **new** wallet, so peers see a new key and re-verify. Losing
  every device with no registered email means the account is unrecoverable (and
  unclaimable by anyone else — nobody can forge your signature).

## Cryptographic building blocks

| Purpose | Primitive |
|---------|-----------|
| Session establishment | **X3DH** over X25519 |
| Message ratchet (forward secrecy + PCS) | **Signal Double Ratchet** |
| Message AEAD | **ChaCha20-Poly1305** |
| KDFs | HKDF-SHA512 (identity), HKDF-SHA256 (root), HMAC-SHA256 (chain) |
| Wallet identity / signatures | secp256k1 (`k256`), **Ed25519** (device + group) |
| Groups | sender keys + a per-group ratchet, keyed per **device** |
| Device pairing | ephemeral X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305 |
| At-rest identity | Argon2id + ChaCha20-Poly1305 |

All from the RustCrypto ecosystem; secret material is held in `zeroize`-on-drop
types and `unsafe` is forbidden in the core. Contributory (all-zero) X25519 outputs
are rejected in X3DH, the ratchet, and pairing.

## What we defend against

- **A passive network / ISP.** Sees only ciphertext and opaque, hashed ids. Message
  contents, and even usernames (hashed via `user_id` before they hit the wire), are
  not exposed on the wire. Transport *metadata* — who connects to which service/peer,
  when, and how much — is **not** hidden; see [Metadata exposure](#metadata-exposure).
- **A dishonest directory.** Every record is wallet-signed and self-certifying. The
  worst it can do is *withhold* or serve a *stale* record — it can never forge one or
  bind your handle to a wallet you don't control. Handles are permanently bound
  (anti-rollback via `seq`); email-proved recovery re-binds only to someone who
  controls the original verification email. It **does** learn metadata (below).
- **A dishonest queue.** Sees only opaque E2E blobs — never content. It can drop or
  delay, not read. It **does** learn the sender and recipient wallets and timing
  (below): it can *attribute*, just not *read*.
- **Key compromise (bounded).** The Double Ratchet gives forward secrecy (a stolen
  current key can't decrypt past messages) and post-compromise security (the session
  heals on the next round trip).
- **Impersonation.** Knowing someone's public key gives *zero* forging power;
  authenticity requires their private key. First contact is **TOFU** — a peer's
  wallet is pinned on first sight and a later mismatch is rejected.
- **Malformed input.** The wire decoders are fuzzed (garbage / truncated / bit-flipped
  never panics and never accepts a tampered record); the ratchet rejects replays and
  bounds skipped keys.

## Metadata exposure

Content is end-to-end encrypted, so no server or network observer reads messages.
**Metadata is a different matter** — and we do not claim to hide it. This is the
precise picture of what each actor can observe.

### The directory observes

The directory hosts `handle → signed record` and presence. Its records are **public**
(lookups are open and unauthenticated), so the directory operator — and anyone who
can query it — learns:

- **Record contents:** your handle → wallet, each device's keys, your queue
  endpoint(s), and transport addresses. Anyone can resolve a handle to all of this.
- **Who looks up whom:** each lookup ties a requester (IP) to a queried handle — an
  interest/social-graph signal to the operator.
- **Presence:** `announce`/heartbeat and presence queries reveal who is online and when.
- **Publish timing:** when a wallet updates its record.
- **Login events:** which wallet authenticates (SIWE challenge/verify), and when.
- **Recovery/claim events:** an email-verified claim or recovery is happening, and
  when. The email itself is held only transiently while a code is outstanding and is
  stored **only as a keyed hash** (a per-server secret pepper) — the operator can't
  read your address, though with the pepper it could *test* a guessed address.
- **Handle availability:** anyone can probe whether a handle is taken.

### The queue observes

The queue is a per-recipient, wallet-addressed mailbox. Deposits are
**sender-authenticated** (the depositor logs in with their own wallet), so the queue
operator learns:

- **Sender ↔ recipient linkage:** which wallet deposited for which recipient wallet —
  i.e. *that A messaged B*, and when. It never sees content, but it *can attribute*.
- **Device slot:** which device (or the cluster-wide slot) the mail is for.
- **Timing:** deposit time and collection time.
- **Approximate size:** the blob length ≈ the (padded-only-if-a-privacy-mode) message
  size. Sizes are not yet bucketed — see #51.
- **Queue depth:** how much mail is waiting for a wallet.
- **Push subscriptions:** the browser push endpoints registered per wallet (the push
  itself is contentless).

Running your **own** queue (the endpoint lives in your signed record — see
[recipient-owned queues](DEPLOY.md)) keeps this metadata under infrastructure you
control. Removing the sender from the queue's view entirely is open research (#55).

### A network observer

- **Client ↔ service** traffic is HTTP that should run under TLS. With TLS the bodies
  are hidden, but connection metadata (your IP ↔ the directory/queue, timing, sizes)
  is not. **Without** TLS, everything is visible — always terminate TLS (#`MYCELLIUM_TLS_*`
  or a proxy).
- **Direct peer ↔ peer** delivery (framed TCP or libp2p/Noise) encrypts the payload,
  but the two endpoints' IP addresses, the fact and timing of a connection, and the
  ciphertext sizes are visible to anyone on the path.

### Privacy dimensions, separated

| Dimension | Posture |
|---|---|
| **Content** | Strong — E2E, forward-secret, per-device. |
| **Authenticity** | Strong — wallet signatures, TOFU pinning, anti-rollback. |
| **Metadata** | **Limited** — the directory sees lookups/presence; the queue sees sender↔recipient, timing, and size. No cover traffic, no mixnet. |
| **Availability** | Depends on the queue you choose (run your own). |
| **Endpoint** | Out of scope — E2E can't stop malware on your device. |

### In one line, for users

Mycellium **hides what you say** from every server and network observer. It does
**not hide that you are talking, to whom, and roughly when** from the directory and
queue infrastructure you use. It is not an anonymity system, and it makes no
social-graph-privacy claim without mixnet/cover-traffic-level protections we do not
have.

## Out of scope (by design or not yet)

- **Traffic-analysis / social-graph privacy.** As above — the infrastructure sees
  who-talks-to-whom metadata. The [privacy roadmap](https://github.com/aristath/mycellium.eu/issues/48)
  (padding, batching, sealed-sender research) narrows specific leaks, but anonymity is
  a non-goal.
- **Account-key theft / coercion.** If your wallet key is exfiltrated from a device or
  you are compelled to unlock it, the account is compromised — security is exactly the
  secrecy of that key at rest.
- **Endpoint compromise.** Malware reading plaintext on your device is not something
  E2E can prevent. In the browser, the test hook `window.mycellium` is gated to
  localhost and must never ship in a production build.
- **Availability.** A queue you don't control can withhold your mail (run your own, or
  point your record at one you trust). NAT traversal for direct P2P is unfinished (#59).
- **Independent audit.** Not yet done.

## Device pairing

Adding a device transfers the account key over an **authenticated, ephemeral** channel
instead of a copyable secret. The new device generates a one-time X25519 keypair and
shows its public key in a QR; an existing device scans it (authenticating it visually,
out of band), confirms, and seals the account key to it over ECDH, relaying the
ciphertext through a short-lived queue rendezvous. Only the scanner can decrypt; the
QR is single-use and worthless afterwards. See [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Transport & at-rest posture

Peer↔peer links use Noise (via libp2p) or framed TCP; client↔service traffic is HTTP
that should run over TLS (native `MYCELLIUM_TLS_*` or a terminating proxy — see
[`DEPLOY.md`](DEPLOY.md)). Local state (history, contacts, groups, drafts, outbox) is
an encrypted file KV keyed from the identity; the account key at rest is Argon2id-sealed
under a passphrase. Servers persist only self-certifying records and opaque blobs; when
`MYCELLIUM_DATA` is set they **fail closed** if the durable store can't be opened.

In the **browser**, the IndexedDB session snapshot (which includes the account key) is
encrypted with an AES-GCM key generated once and stored **non-extractable** — the
browser holds the raw key bytes, never JavaScript, so the snapshot is ciphertext on
disk and a script can't read the key straight out of it. This is transparent (no
passphrase prompt). *Residual limitation:* a determined attacker with the entire
browser profile could, depending on browser internals, still recover a non-extractable
key — so this raises the bar but is not a substitute for OS-level full-disk encryption
on an untrusted device.

## Reporting

Found a vulnerability? Please report privately rather than opening a public issue, and
allow time to fix before disclosure.
