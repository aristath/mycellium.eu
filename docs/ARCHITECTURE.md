# Mycellium Architecture

*How the system is built today.* For the design narrative and rationale, see
[`CONCEPT.md`](CONCEPT.md). Each crate also has its own `README.md` with its
detailed API; this document is the map that ties them together.

---

## What Mycellium is

A peer-to-peer, end-to-end-encrypted messenger with no central server in the
path of a conversation. Your identity is a **wallet** (a seed phrase you own);
messages travel **device→device**; the only shared infrastructure is a thin,
untrusted **directory** (names → signed records) and, optionally, a **queue**
(per-recipient store-and-forward) that only ever holds ciphertext.

Three properties drive every decision:

- **No trusted middle.** Shared services can withhold data but can never read or
  forge it. Every record is wallet-signed; every message is E2E-encrypted.
- **Self-sovereign.** Your seed phrase *is* your account. Devices, names, and
  reachability all derive from keys you hold — nothing is issued to you.
- **Portable.** The protocol core is `no_std` and depends only on traits, so the
  same code runs from a microcontroller to a desktop to (eventually) a browser
  via WASM.

---

## Design principle: ports and adapters

The codebase is a **hexagonal (ports-and-adapters) architecture**. The core
defines *ports* — traits for everything host-specific — and never touches an OS
directly. Adapters implement those ports per platform; the engine orchestrates;
a shell drives the engine.

```
        ┌─────────────────────────── mycellium-core ───────────────────────────┐
        │  the contract: identity, records, X3DH, Double Ratchet, group keys,   │
        │  wire codec, login challenge — plus the PORTS (traits):               │
        │        Transport          Storage          Platform                   │
        └───────────▲───────────────────▲────────────────────▲──────────────────┘
                    │ implements         │ implements          │ provided by
      ┌─────────────┴──────┐  ┌──────────┴────────┐   ┌────────┴─────────┐
      │ mycellium-transport│  │ mycellium-storage │   │  OsPlatform      │
      │  (TCP + libp2p)    │  │ (encrypted file KV)│   │ (in the engine)  │
      └─────────────▲──────┘  └──────────▲────────┘   └────────▲─────────┘
                    │                     │                     │
        ┌───────────┴─────────────────────┴─────────────────────┴──────────────┐
        │                          mycellium-engine                             │
        │  headless peer: register, send/receive, deliver ladder, outbox,       │
        │  groups, multi-device, contacts, history — talks to the two services  │
        │  below through their HTTP clients                                     │
        └───────▲───────────────────────────────────────────────▲──────────────┘
                │ drives                                          │ HTTP clients
        ┌───────┴────────┐                          ┌────────────┴─────────────┐
        │ mycellium-cli  │                          │ directory-client         │
        │ (clap + TUI)   │                          │ queue-client             │
        └────────────────┘                          └────────────┬─────────────┘
                                                                 │ HTTP
                                    ┌────────────────────────────┴────────────┐
                                    │  mycellium-directory   mycellium-queue   │
                                    │  (names/records/       (wallet-keyed     │
                                    │   presence)             store-forward)   │
                                    │  served by mycellium-server              │
                                    └──────────────────────────────────────────┘
```

The core depends on **nothing but its own traits**. Everything platform-specific
is an adapter you can swap; the engine and shells sit on top.

---

## The crates

| Crate | Layer | Responsibility |
|-------|-------|----------------|
| [`mycellium-core`](../crates/mycellium-core/README.md) | contract | Identity, records, X3DH, Double Ratchet, group sender keys, wire codec, login contract, and the `Transport`/`Storage`/`Platform` ports. `no_std`. |
| [`mycellium-directory`](../crates/mycellium-directory/README.md) | service (lib) | The name registry: login + signed-record store + presence. Holds only self-signed records it cannot forge. |
| [`mycellium-server`](../crates/mycellium-server/README.md) | service (bin) | Deployable binary that serves the directory over HTTP. |
| [`mycellium-queue`](../crates/mycellium-queue/README.md) | service (lib+bin) | Per-recipient store-and-forward mailbox, **keyed by wallet**, decoupled from the directory. Holds only ciphertext. |
| [`mycellium-directory-client`](../crates/mycellium-directory-client/README.md) | adapter | HTTP client for the directory (login, publish, lookup, presence). |
| [`mycellium-queue-client`](../crates/mycellium-queue-client/README.md) | adapter | HTTP client for the queue (login, deposit, collect). |
| [`mycellium-transport`](../crates/mycellium-transport/README.md) | adapter | `Transport` implementations: framed TCP and libp2p (Noise + Yamux). |
| [`mycellium-storage`](../crates/mycellium-storage/README.md) | adapter | `Storage` implementation: an encrypted local file KV, plus at-rest identity. |
| [`mycellium-engine`](../crates/mycellium-engine/README.md) | engine | The headless peer — all orchestration, minus presentation. |
| [`mycellium-cli`](../crates/mycellium-cli/README.md) | shell | A terminal shell over the engine (clap + interactive UI). |

Dependency graph is acyclic: `core ← {directory ← server, queue, transport,
storage, directory-client, queue-client} ← engine ← cli`.

---

## Core concepts

**Identity.** A 24-word BIP-39 seed derives the **wallet** (secp256k1, the root
identity that signs) and, per device, a random-but-persisted set of **device
keys** (Ed25519 for transport identity, X25519 for messaging). The seed is the
authority; devices add themselves to the account rather than sharing keys.

**Device cluster.** An account is a *set* of devices. Each carries its own
messaging keys; the wallet's single signature over the record vouches for the
whole set. Adding a device re-signs the record with a higher `seq`.

**Record.** The self-certifying answer to *"who and where is this handle?"*: the
wallet, the account's **queue endpoint**, and the device set — all under one
wallet signature. A dishonest directory can withhold or serve stale records, but
never forge one.

**Directory.** The name layer: `handle → signed record`, plus presence. Tiny,
read-mostly, and safe to replicate widely — it holds only data it cannot forge.

**Queue.** The message layer, kept **separate** from the directory: a
per-recipient store-and-forward mailbox keyed by wallet, at an endpoint the
recipient publishes in their record. Holds only opaque E2E blobs. You can run
your own, or point at a provider — either way it reads nothing.

**Outbox.** A local, encrypted retry buffer. When a message can reach neither a
live peer nor a queue, it parks here and is retried on every `send`/`inbox` and
via the `outbox` command.

**Groups.** Sender-key groups keyed by **device** (so two devices of one account
are distinct senders). Each member distributes its key pairwise over E2E; group
text is one ciphertext fanned out to every member device.

---

## Key data flows

**Register.** `engine` builds a record (wallet + queue endpoint + this device),
signs it, and `PUT`s it to the directory under the handle. Re-registering or
linking a device re-signs with a higher `seq`.

**Send (the delivery ladder).** For each of the recipient's devices, the engine
seals the message with X3DH → Double Ratchet, then tries, in order:
1. **Live push** — if the peer is present, open a direct connection and deliver.
2. **Queue deposit** — else deposit the blob into the recipient's queue (from
   their record), keyed by their wallet.
3. **Outbox** — if neither works, park it locally for retry.

**Receive.** `inbox` drains *your* queue (your wallet's slots); `serve` receives
live pushes. Both run every item through the same processing: decrypt, verify the
sender, display, persist to encrypted history, and (for direct messages) send a
read receipt back.

**Multi-device self-sync.** A message you send is also mirrored, sealed
device→device, to your *own* other devices, so a conversation reads consistently
across your cluster.

**Groups.** `group create`/`add` distribute your sender key to each member's
devices; `group send` encrypts once and fans the ciphertext out; removals rotate
the key and tell members to re-key.

---

## Security model

- **Confidentiality & forward secrecy.** X3DH establishes a session; the Double
  Ratchet advances keys per message. A compromised key can't decrypt past or
  future messages.
- **Authenticity.** Every record is wallet-signed; every message is bound to the
  sender's identity. Knowing someone's public key (their "CID") gives **zero**
  power to impersonate them — forging requires their private key.
- **Trust-on-first-use (TOFU).** On first contact a peer's wallet is pinned; a
  later key mismatch is rejected. (On-chain identity anchoring, below, is what
  closes even the first-contact gap.)
- **What the services see.** The directory sees signed records and presence — it
  cannot forge or read messages. The queue sees only opaque ciphertext blobs
  addressed to a wallet — never content or sender. Neither is in the trust path
  for confidentiality.
- **At rest.** Local history, contacts, groups, drafts, and the outbox are stored
  in an encrypted file KV keyed from the identity.

---

## Design direction (not yet built)

- **Naming.** Human-global-unique names can't be *free* without a trusted
  authority (Zooko's triangle), so the default is **self-certifying names**
  (`label#key-fingerprint`) — free, instant, decentralized, self-authenticating —
  with petnames making them feel clean. A globally-unique bare label is an
  optional extra over a **feeless (proof-of-work) chain** — pay with a few
  seconds of compute, never money.
- **Distribution.** The directory is designed to be cloned across many
  opportunistic nodes (it's tiny and unforgeable); the queue stays per-user.
- **Background delivery.** Waking a backgrounded mobile app needs a small,
  contentless **push relay** — explicitly **not** hosted by any US company, for
  privacy. Contentless (opaque per-contact tag), so it learns nothing.

See [`CONCEPT.md`](CONCEPT.md) for the full reasoning behind each of these.
