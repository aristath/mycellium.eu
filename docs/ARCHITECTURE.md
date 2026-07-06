# Mycellium Architecture

*How the system is built today.* For the design narrative and rationale, see
[`CONCEPT.md`](CONCEPT.md). Each crate also has its own `README.md` with its
detailed API; this document is the map that ties them together.

---

## What Mycellium is

A peer-to-peer, end-to-end-encrypted messenger with no central server in the
path of a conversation. Your identity is a **wallet key** you hold (no seed
phrase); messages travel **device→device**; the only shared infrastructure is a thin,
untrusted **directory** (names → signed records) and, optionally, a **queue**
(per-recipient store-and-forward) that only ever holds ciphertext.

Three properties drive every decision:

- **No trusted middle.** Shared services can withhold data but can never read or
  forge it. Every record is wallet-signed; every message is E2E-encrypted.
- **Self-sovereign.** Your wallet key *is* your account (held encrypted, never a
  copyable seed). Devices, names, and reachability all derive from keys you hold —
  nothing is issued to you.
- **Portable.** The protocol core is `no_std` and depends only on traits, so the
  same code runs from a microcontroller to a desktop to a **browser via WASM**. Every
  client is a thin shell over **one shared engine** — no protocol or crypto logic
  lives in UI code. Today that's the native CLI and the browser PWA; the **product
  target is native apps** (Android, iOS, macOS, Linux, Windows) over a native SDK —
  see [Clients: native-first](#clients-native-first-the-product-target) below.

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
        │     Transport      Storage      Platform      HttpTransport           │
        └──────▲──────────────▲──────────────▲───────────────▲──────────────────┘
   implemented │              │              │               │  (client HTTP)
     by, per   │       ┌──────┴──────┬───────┴───────┐   ┌───┴───────────────┐
     build:    │       │             │               │   │ native: mycellium-│
      ┌────────┴─────┐ │  ┌──────────┴───┐  ┌─────────┴─┐ │  http (ureq)      │
      │  transport   │ │  │ native: file │  │ native:   │ │ browser: XhrTrans-│
      │ (TCP/libp2p) │ │  │ KV / browser:│  │ OsPlatform│ │  port (in wasm)   │
      │  *native*    │ │  │ IndexedDB    │  │ browser:  │ └───────────────────┘
      └──────────────┘ │  │ (MemStore)   │  │ Browser…  │
                       │  └──────────────┘  └───────────┘
        ┌──────────────┴────────────────────────────────────────────────────────┐
        │                          mycellium-engine                             │
        │  headless peer: register, send/receive, deliver ladder, outbox,       │
        │  groups, multi-device, contacts, history. Domain modules are generic  │
        │  and compile to wasm; native orchestration (app/*) is behind the      │
        │  `native` feature; `wireops` is the shared, platform-agnostic crypto. │
        └──────▲────────────────────────────────────────────────▲──────────────┘
        drives │ (shells over one engine)                        │ HTTP clients
      ┌────────┴────────┐  ┌───────────────────────────┐  ┌──────┴───────────────┐
      │ cli + sdk       │  │ mycellium-wasm → clients/ │  │ directory-client      │
      │ native shells   │  │ web PWA (Web Worker + IDB)│  │ queue-client          │
      └─────────────────┘  └───────────────────────────┘  └──────┬───────────────┘
                                                                 │ HTTP (+ CORS, TLS)
                                    ┌────────────────────────────┴────────────┐
                                    │  mycellium-directory   mycellium-queue   │
                                    │  (names/records/       (wallet-keyed     │
                                    │   presence, redb)       store-forward,   │
                                    │  served by              redb + Web Push) │
                                    │  mycellium-server   +   mycellium-observe │
                                    └──────────────────────────────────────────┘
```

The core depends on **nothing but its own traits**. Everything platform-specific
is an adapter you can swap — and the four ports are exactly what differs between
the native and browser builds: same engine, different `Transport` / `Storage` /
`Platform` / `HttpTransport` implementations underneath.

---

## Clients: native-first (the product target)

The engine is the shared **brain**; every client is a thin shell over it. Architecturally
the shells are **peers** — the CLI, PWA, SDK, and native app shells all drive the
same engine through the same ports — but they are not peers in *product priority*:

- **Native apps — the target product (early scaffolds exist).** Android, iOS/macOS,
  Linux, and Windows apps are thin platform-native UI shells over the same core +
  engine, bound through a **native SDK** (`mycellium-sdk`: **UniFFI** for
  Kotlin/Swift, a **C-ABI**/Rust crate path for desktop — #64). Early Android,
  Apple, and Tauri desktop shells now live under `clients/` and exercise the
  SDK, email onboarding, messaging, and OS-backed `SecretStore` adapters. They are
  not product-complete yet. Native is where the things a real messenger needs live:
  OS secure storage (Keychain / Keystore / DPAPI / libsecret — #65), native
  push/wake (APNs / FCM — #71), background delivery, direct P2P reachability
  (#59/#60), and platform-native UX. Tracked as the native client roadmap (#74):
  Android #67, iOS #68, macOS #69, Linux #70, Windows #72.
- **The CLI** ([`mycellium-cli`](../crates/mycellium-cli/README.md)) — a native
  terminal shell; what runs today for development and power use.
- **The browser PWA** ([`clients/web`](../clients/web/README.md)) — the WASM build; a
  **proof-of-concept / fallback / demo / test-harness** surface, not the primary
  product. Full walk-through in [`BROWSER.md`](BROWSER.md).

No protocol or crypto logic lives in any UI: shells call the engine, the engine owns
the contract. Adding a platform means implementing the four ports for it, never
reimplementing the protocol. Privacy / metadata / trust direction is tracked in #48.

---

## The crates

| Crate | Layer | Responsibility |
|-------|-------|----------------|
| [`mycellium-core`](../crates/mycellium-core/README.md) | contract | Identity, records, X3DH, Double Ratchet, group sender keys, wire codec, login contract, and the `Transport`/`Storage`/`Platform` ports. `no_std`. |
| [`mycellium-directory`](../crates/mycellium-directory/README.md) | service (lib) | The name registry: login + signed-record store + presence. Holds only self-signed records it cannot forge. |
| [`mycellium-server`](../crates/mycellium-server/README.md) | service (bin) | Deployable binary that serves the directory over HTTP. |
| [`mycellium-queue`](../crates/mycellium-queue/README.md) | service (lib+bin) | Per-recipient store-and-forward mailbox, **keyed by wallet**, decoupled from the directory. Holds only ciphertext. |
| [`mycellium-relay`](../crates/mycellium-relay/README.md) | service (bin) | Deployable libp2p Circuit Relay v2 server for online-but-NAT'd peers. Forwards opaque Noise-encrypted circuit traffic. |
| [`mycellium-directory-client`](../crates/mycellium-directory-client/README.md) | adapter | HTTP client for the directory (login, publish, lookup, presence, email claim). Generic over `HttpTransport`. |
| [`mycellium-queue-client`](../crates/mycellium-queue-client/README.md) | adapter | HTTP client for the queue (login, deposit, collect, push wake targets, pairing rendezvous). Generic over `HttpTransport`. |
| [`mycellium-http`](../crates/mycellium-http/README.md) | adapter | The **native** `HttpTransport` (ureq). The browser supplies its own (in `mycellium-wasm`). |
| [`mycellium-transport`](../crates/mycellium-transport/README.md) | adapter | `Transport` implementations: framed TCP and libp2p (Noise + Yamux). |
| [`mycellium-storage`](../crates/mycellium-storage/README.md) | adapter | `Storage` implementation: an encrypted local file KV, plus at-rest identity. |
| [`mycellium-observe`](../crates/mycellium-observe/README.md) | support | Zero-dependency server metrics (`/metrics`) + JSON access logs. |
| [`mycellium-engine`](../crates/mycellium-engine/README.md) | engine | The headless peer — all orchestration, minus presentation. Domain modules compile to wasm; `app/*` is behind the `native` feature. |
| [`mycellium-sdk`](../crates/mycellium-sdk/README.md) | shell boundary | Stable UniFFI API for Android, Apple, and desktop clients: account setup, email verification, messaging, sync, contacts/trust, pairing, groups, push registration, backup/restore, and platform `SecretStore` injection. |
| [`mycellium-cli`](../crates/mycellium-cli/README.md) | shell | A terminal shell over the engine (clap + interactive UI). |
| [`mycellium-wasm`](../crates/mycellium-wasm/README.md) | shell | The engine as WebAssembly: a `Session` façade + browser `HttpTransport`/`Storage`/`Platform`, driving `clients/web` (the PWA). |

Dependency graph is acyclic: `core ← {directory ← server, queue, transport ← relay,
storage, directory-client, queue-client, http, observe} ← engine ← {cli, sdk, wasm}`.
The servers (`directory`, `queue`) persist to embedded **redb** when `MYCELLIUM_DATA`
is set, and share `mycellium-observe` for metrics and logs.

---

## Core concepts

**Identity.** A random **wallet** key (secp256k1, the root identity that signs) —
no seed phrase — plus, per device, a random-but-persisted set of **device keys**
(Ed25519 for transport identity, X25519 for messaging). The wallet is the
authority; a new device **pairs** in (the account key moves over an authenticated
one-time channel) and adds itself to the account rather than sharing message keys.

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

## The two builds: native and browser

The same engine ships as a native binary **and** as WebAssembly, because the only
things that differ are the four ports:

| Port | Native | Browser |
|------|--------|---------|
| `HttpTransport` | `mycellium-http` (ureq, blocking) | `XhrTransport` (sync `XMLHttpRequest`, in `mycellium-wasm`) |
| `Storage` | encrypted file KV (`mycellium-storage`) | `MemStore` snapshotted to **IndexedDB** |
| `Platform` | `OsPlatform` (OS RNG + clock) | `BrowserPlatform` (Web Crypto + `Date.now`) |
| `Transport` (P2P) | TCP / libp2p | *not used* — the browser reaches peers only via the queue |

The engine's **domain modules** (history, contacts, groups, blocklist, drafts,
expiry, outbox) are generic over `Storage` and compile to `wasm32` unchanged. The
native-only orchestration (`app/*`) and `OsPlatform` sit behind the default
**`native`** feature; the browser build turns it off and calls the ungated
`wireops` module (sealing, records, ids) with its own `Platform`. `mycellium-wasm`
exposes a `Session` object; `clients/web` runs it **inside a Web Worker** (so the
blocking XHR never touches the UI thread) and talks to it by RPC. Full walk-through:
[`BROWSER.md`](BROWSER.md).

## Persistence & observability (servers)

Both services are durable when `MYCELLIUM_DATA` is set: the directory keeps
bindings, records, and email claims in embedded **redb**; the queue keeps mailboxes,
Web Push subscriptions, and its VAPID keypair. Both run on a shared async runtime
(**axum + hyper + tokio**, the `mycellium-serve` crate) with graceful shutdown,
cap request bodies, emit permissive CORS (browser clients call them directly), can
terminate TLS natively with **rustls** (`MYCELLIUM_TLS_*`) or sit behind a proxy, and expose
`/metrics` + JSON access logs via `mycellium-observe`. Because records are
self-certifying, persistence and replication are safe — a store can withhold or
serve stale, never forge.

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
- **Background delivery.** *(Browser: built.)* The queue implements contentless
  **Web Push** (VAPID) to wake a closed PWA — the ping carries no sender or content.
  The equivalent for a native mobile app (a push relay explicitly **not** hosted by
  any US company) is still design-direction.

Already built since this doc's first draft: durable server storage (redb),
email-verified handles + recovery, native TLS, the browser/WASM client, groups,
multi-device linking, and Web Push. See [`PRODUCTION-READINESS.md`](PRODUCTION-READINESS.md)
for status and [`CONCEPT.md`](CONCEPT.md) for the full reasoning behind each direction.
