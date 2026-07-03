# Mycellium

*A living design document. We start at the highest level and zoom in only when the concept forces us to.*

---

## Layer 0 — The idea

**Mycellium is a peer-to-peer messenger. Your message travels directly from your device to the other person's device. Nothing sits in the middle of your conversation.**

That is the whole idea. Everything else in this document exists to make that one sentence true in the real world.

---

## Layer 1 — Why this is different

Ordinary messengers are shaped like a **hub**. Everyone connects to a company's servers; the servers hold the conversation and pass it along. Even when the content is encrypted, the hub is still *in the middle* — it decides who can talk, it sees the flow of messages, and it is the thing that must be trusted, paid for, and kept running.

Mycellium is shaped like a **line between two people**. The two devices are the system. There is no hub that owns the conversation.

This is not primarily a privacy feature — privacy simply *falls out* of the shape. If no one is in the middle, there is no one in the middle to read, block, log, or monetize the conversation. The privacy is a side effect of the architecture, not a bolt-on.

---

## Layer 2 — The one hard problem

Direct is easy to say and hard to do, because of a single stubborn fact:

> **Two personal devices can't simply call each other.**

Phones and laptops sit behind home routers and mobile networks that block unsolicited incoming connections. Even when both people are online and willing, their devices have no obvious way to learn each other's address or open a direct line through those barriers.

So the entire design of Mycellium is really the answer to one question:

**How do two devices find each other and open a direct line, when nothing in the network is built to let them?**

Every piece of machinery we add later — discovery, the rendezvous, key exchange — earns its place *only* by helping answer that question. If a piece doesn't serve the direct line between two people, it doesn't belong.

---

## Layer 3 — The cast (who exists, and why)

There are only three kinds of thing in Mycellium, in order of importance:

1. **You and your peer** — two devices. This is the system. This is where messages live, where they are encrypted, and where they are read.

2. **The directory** — a server whose job is to let you in and help you find the person you're looking for. It does three tightly-bounded things and nothing else: **log you in** (you prove you hold your identity secret by signing a challenge — no passwords), **answer lookups** (given a handle, return the signed record that says who and where that person is — see Layer 6), and act as a **rendezvous** (the mutually-reachable point where two peers open a direct line through their routers). It helps the line *get made*; it never carries what travels over it. The moment a message exists, the server is already out of the loop.

3. **The rules** — the shared agreement (the protocol) that lets two logged-in devices establish a private, direct line and trust that they're talking to the right person.

Notice what is *not* on this list: a server that carries, stores, or routes your messages. The server checks you at the door and lets you in; it never holds your identity. If we ever find it touching a message, we've drifted from the idea.

**A note on words, since we'll need them from here on:**

- **Handle** — your public name (`john`, `mary`). How you're *found*. Anyone can look it up.
- **Identity secret** — a private secret only your device holds. How you're *proven*. It never leaves the device.
- **Public identity** — the shareable half that pairs with your identity secret, published so others can reach you securely. What the server vouches for when someone looks up your handle.

So "your identity" is the secret plus its public half; your handle is just the label that points at it.

---

## Layer 4 — What we build first (the POC)

We build the concept in its purest form and prove the hard part works before we soften it.

**In scope for the POC:**

- A thin server (the **directory**, Layer 6) that does three tightly-bounded things: **login** (you sign a challenge to prove you hold your identity secret), **lookup** (`handle → signed record`, so a peer can find you), and **rendezvous** (help two logged-in peers open a direct connection through their routers). All three help the line get made; none of them see what flows over it.
- After the line is made, **100% peer-to-peer messaging** over a direct libp2p connection. Every message travels directly between the two devices, with the server entirely out of the loop. Ciphertext never passes through a relay network.

This is deliberate: the direct line is the essence, so we build the essence first and let everything else attach to a working core.

---

## Layer 5 — The private line (channel + identity are one thing)

The rendezvous introduces two devices. But an introduction is not trust, and a connection is not privacy. The moment the line is open, Mycellium answers two questions *with a single act*:

- **Is this line private?** — can anyone but the two of us read it?
- **Is this really my peer?** — is the device on the other end who it claims to be?

With end-to-end encryption from day one, these are not two problems. They are one.

**The key idea: your identity has a private half your device never gives up.**

Every account holds an **identity secret** that never leaves the device — think of it as the account's true name, one that can be *proven* but never *handed over*. Its **public identity** is the matching half the server publishes. Your login proves to the server that you hold the secret; it does not reveal it. When two peers meet through the rendezvous, they use their identity secrets to do two things at once:

1. **Agree on a private key that only the two of them know** — derived directly between the devices, so the resulting channel is readable by no one else, not even the rendezvous that introduced them.
2. **Prove to each other that they hold the identity secret behind their claimed public identity** — so each side knows the line goes to the right person and not to an impostor.

Because the channel key is built *from* the identity secrets, you cannot have a private line to the wrong person: privacy and authenticity succeed or fail together. The rendezvous can connect you to a peer, but it can neither read the line nor pretend to be the person at the other end, because it never holds either secret.

**Discovery and verification are two different jobs — don't confuse them.**

- **Discovery — "who is the handle `mary`, and how do I reach her?"** This is *always* the server's job, and it can't be removed. John's app cannot find Mary out of thin air; it looks up her **handle**, and the server answers with her **public identity** and how to reach her device. Every path in the POC and beyond relies on the server for this.

- **Verification — "is this really Mary's public identity, or did the server lie?"** A *separate, optional* check layered on top. Normally John simply trusts what the server told him. Verification is the seatbelt for the case where the server is *dishonest* and hands John a fake public identity for `mary` so it can secretly stand in the middle. John and Mary catch that by comparing a short code out of band (read aloud on a call, scanned in person). Codes match → the server told the truth. Codes differ → someone's in the middle.

Verification is **not an alternative to the server** — you still need the server to find Mary either way. It only closes the one remaining "what if the server lies" gap.

**One honest limit — and how Layer 6 shrinks it.** Because the POC has discovery but not out-of-band verification, you are trusting the directory to tell you the truth about *whose public identity* sits behind a handle. It still cannot read your messages — that's guaranteed by the end-to-end encryption regardless. But a naive directory could, in principle, hand you the wrong public identity for a handle.

Layer 6 shrinks this sharply: because each record is **signed by its owner's identity secret**, the directory holds data it *cannot forge*. The worst a dishonest directory can do drops from *"impersonate Mary"* all the way down to *"withhold Mary's record or serve a stale one."* Out-of-band verification later closes even that residual gap. For the POC: **the directory can't read your messages and can't fake who Mary is — it can only stall.**

---

## Layer 6 — The directory (the one thing that needs a home)

Everything in Mycellium is peer-to-peer except one stubborn piece: *something* has to answer **"given the handle `mary`, what is her identity, and how do I start reaching her?"** You cannot derive that from nothing. This lookup is the single genuinely-hosted part of the system — and the whole art is making it need as little trust as possible.

**The move: store self-certifying records.** The directory does not store a value it *asserts*. It stores a record **signed by the owner's identity secret**:

```
mary  →  {
  publicIdentity: <Mary's public key>,   // her identity / encryption key
  peerId:         <libp2p PeerID>,        // how the direct line gets opened
  seq:            42,                      // freshness / anti-rollback
  signature:      <signed by Mary's identity secret>
}
```

Because the record is signed, the directory holds data **it cannot forge**. Hand John a tampered record and the signature fails to verify — John rejects it. This is what downgrades the server from a *trusted authority* to an *untrusted directory*: the worst it can do is **withhold** a record or serve a **stale** one. It can never impersonate anyone.

**Who hosts it only affects availability, not authenticity.** Since the record certifies itself, the directory can live anywhere along an upgrade path — behind one interface, so the rest of the app never changes:

| Home for the directory | Trust | Cost | When |
|---|---|---|---|
| **Thin KV server** (ours) | Availability only — can't forge | Trivial | **POC — start here** |
| **libp2p DHT** (Kademlia) | Fully decentralized | Free-ish, eventual consistency | Later |
| **ENS** (`mary.eth` + text records) | On-chain, censorship-resistant | Gas / registration | The trustless endgame |

ENS *is* this directory, decentralized. So the POC builds a thin signed-KV server that we can later point at a DHT or ENS without touching anything else. The directory helps the line *get made*; it never carries the line — messages always travel device-to-device.

---

## Layer 7 — The web3 substrate (the tech we lean on)

Mycellium's concept — keypair identity, no hub, direct lines — is the web3 worldview already. We use web3 at the **edges** (identity, naming, auth, discovery) and keep the **line itself pure**: ciphertext only ever travels device-to-device, never through a relay network.

| Mycellium piece | What we use | Why |
|---|---|---|
| **Identity secret / public identity** | Wallet keypair, expressed as a DID (`did:pkh`) | A wallet *is* an identity secret; the address is a natural public identity. |
| **Handle** | Off-chain in the POC directory → **ENS** (`.eth`) later | ENS decentralizes the exact `handle → record` map we need. |
| **Login** | **SIWE**-style (sign a challenge, EIP-4361) | Proves you hold the secret without revealing it. No passwords, no account DB. |
| **Discovery / rendezvous** | **libp2p** (DHT routing, rendezvous, AutoNAT, circuit-relay, DCUtR hole-punching) | The web3-native P2P stack; solves the Layer 2 reachability problem. |
| **The line** | **libp2p Noise**-secured direct stream | A real device-to-device channel — nothing in the middle. |
| **Offline handoff** (deferred) | IPFS / Waku store / Arweave | Parked until the online case works. |

**A deliberate rejection:** we do *not* build on XMTP, Waku, or Push as the message transport, even though they'd give offline delivery nearly for free — because they relay ciphertext through their own node networks. That would put nodes back "in the middle" and break Layer 0. We may borrow them later *only* for the deferred offline case, never for the live direct line.

One consequence worth noting: with signed records (Layer 6) + SIWE + libp2p, the server keeps shrinking. Auth is a signature, naming will become ENS, and rendezvous is libp2p infrastructure. What began as a "server" is really just a **thin, untrusted directory plus some bootstrap/relay nodes** — much closer to "no hub" than a normal messenger ever gets.

---

## Layer 8 — The wire (the concrete handshake)

This is where implementation finally enters. Everything above is the *what*; this is the *how*.

### 8.1 Three keys, one root of trust

The identity secret can't do every job, so we split roles across three keys — all chained back to the wallet:

| Key | Type | Job | Touches the channel? |
|---|---|---|---|
| **Wallet key** | secp256k1 | Root identity. Signs your record; does SIWE login. | No |
| **Device key** | Ed25519 (libp2p) | Its hash *is* your PeerID; secures the libp2p transport (Noise). | Transport only |
| **Messaging key** | X25519 | Long-term key for the ratchet's key agreement (X3DH). | Yes — end-to-end |

The wallet key **certifies the other two** by signing a record that contains them. One identity vouches for everything; there is a single root to trust or verify.

### 8.2 The signed record (expanded)

```
mary → {
  address:      0xMary…,             // wallet — root identity
  peerId:       12D3…,               // device key — libp2p transport
  idKey:        <X25519 public>,     // messaging key — X3DH
  signedPreKey: <X25519 public> + <sig>,  // medium-term; enables async init later
  seq:          42,                  // freshness / anti-rollback
  signature:    <wallet-signed over everything above>
}
```

The PeerID is stable, so the record never goes stale on network change — libp2p resolves *current* addresses live from it. `signedPreKey` is included now so the same record works for the deferred offline/async case without a format change.

### 8.3 Onboarding (once)

Generate the three keys → assemble the signed record → SIWE-login → publish `mary → record` to the directory.

### 8.4 Login (SIWE)

The directory hands out a nonce; the client signs it with the **wallet key** (EIP-4361). The directory verifies the signature against the claimed address and issues a session. No passwords, no secret ever leaves the device. Login is needed to *publish/update* your record and to be reachable via rendezvous; *lookups are open*.

### 8.5 Find and dial

1. John looks up `mary` → gets her signed record → **verifies the wallet signature himself** (self-certifying; the directory cannot forge it).
2. John dials Mary's **PeerID** over libp2p; DHT + rendezvous resolve her addresses; DCUtR punches a **direct** connection.
3. libp2p runs a **Noise** handshake → encrypted transport, cryptographically bound to Mary's PeerID.
4. John checks the Noise-authenticated PeerID **equals the PeerID in Mary's record** → the pipe provably reaches Mary's device.
5. Mutual: John sends *his* signed record on the stream; Mary verifies it the same way. Both sides now authenticate each other **peer-to-peer — the directory is not involved past step 1.**

### 8.6 The end-to-end layer (rides on top of the pipe)

Transport security (Noise) is not our end-to-end guarantee — the **application-layer ratchet is**, so the guarantee holds no matter what the pipe becomes later (e.g. a relay for offline).

- **Bootstrap — X3DH.** The initiator combines several Diffie-Hellman results — each pairing *his* private key with *her* public key (his identity × her signed pre-key, his ephemeral × her identity, his ephemeral × her signed pre-key, and, when present, his ephemeral × a one-time pre-key) — and hashes them into one shared secret `SK`. Both sides arrive at the same `SK`.
- **Per-message — Double Ratchet.** `SK` seeds a ratchet that derives a fresh key for every message and advances with each exchange. Compromising one message key reveals neither past nor future ones (forward secrecy + post-compromise recovery).

Because this sits above the transport, a compromised or relaying intermediary in the future still sees only ciphertext it cannot open.

### 8.7 POC reductions (stated honestly)

- **Interactive, not async.** Both peers are online, so X3DH runs live over the Noise stream. Published pre-key bundles for fully async init are wired into the record format (8.2) but exercised only when offline arrives.
- **No one-time pre-keys yet.** They defend a replay corner of the *async* case; safe to defer while we're interactive.
- **Never roll our own crypto.** Use a vetted implementation (e.g. libsignal, or `vodozemac`) for X3DH + Double Ratchet, and libp2p's audited Noise. We assemble primitives; we do not invent them.

---

## Layer 9 — Identity, registration & recovery

There is no "sign up" here — no email, no password, no server-created account. A keypair *is* an account. So **registration is three steps**: create your identity, claim a handle, publish your record.

### 9.1 The seed is the identity

Your identity secret is generated from a **24-word BIP-39 seed phrase** (256 bits of entropy — beyond brute force, permanently). The seed derives your root **wallet key**; the wallet key is who you are.

Deliberate choices, all in the name of "secure by default, and always recoverable":

- **24 words**, always. No 12-word option — we don't offer a weaker setting.
- **A single standard wordlist** (the user's locale, English as the interoperable default). Standard BIP-39 is what *guarantees* the phrase can always be restored; that reliability is the point.
- **No custom words** — a human-chosen phrase is a "brain wallet," guessable and drainable. Memorable names are the *handle's* job (9.2), never the seed's.
- **No custom passphrase, no word-count or mixing options.** 256 bits is already an unbreakable secret; extra knobs add recovery risk and non-standard fragility without adding real security.

### 9.2 Claiming a handle (permanent, by design)

You pick a handle (`ari`) and the directory binds `ari → your wallet` on first claim. Two invariants make this safe:

- **Only your signature can change it.** Every update to `ari`'s record must be signed by the bound wallet. Nobody else can touch it.
- **The binding is permanent — never activity-based.** No TTL, no "reclaimed after N days idle." Going silent for a month, or a year, frees nothing. `ari` is yours until *you* (and only you) release it.

Together these make the fear "someone takes my identity while I'm away" *cryptographically impossible*. (This is also why we don't lean on plain ENS for naming: ENS names are *rented* and expire if unrenewed — the exact failure mode we refuse.)

### 9.3 Publish the record

Sign your record (Layer 8.2) with the wallet key and publish it to the directory. You are now findable and reachable.

### 9.4 Recovery — and why the seed preserves the identity chain

New phone, or a month away: install the app, **enter your 24 words**, and your root wallet key is *re-derived* — not replaced. This is the quiet superpower of seed-phrase recovery:

- Your **root identity is restored, not rotated.** The wallet key is exactly the same one, so `ari`'s handle binding still verifies and your contacts see the *same* signing identity — **no "safety number changed" alarm.**
- Only the **device-level keys rotate** (a new phone means a new libp2p key / PeerID and messaging key). You simply re-sign a fresh record — `seq`-bumped — with the unchanged wallet key. Because the root vouches for the new device keys, the chain of trust is intact end to end.

This is a genuine advantage of leading with the seed over phone/email recovery, which would *rotate* the root key and force every contact to re-verify.

### 9.5 The one accepted limit

If you lose the seed **and** every device that holds the key, the identity goes **permanently dormant** — unrecoverable by you, and unclaimable by anyone else (nobody can forge your signature). That is the price of pure self-custody, and we accept it for the POC. The later recovery factors (social recovery, phone, email — all deferred) exist precisely to give people a softer landing than "the words or nothing."

---

## Layer 10 — The client (one core, everywhere)

Mycellium must run across a six-orders-of-magnitude range — a microcontroller to a desktop. No single running binary crosses that, but a single *core* can. The whole strategy is one move: **separate the protocol from the platform.**

### 10.1 The principle

The protocol — identity, encryption, message format — is small, portable, and *identical* on every device. Everything that differs per device (networking, storage, UI, randomness, clock) hides behind interfaces the core calls into. Port Mycellium to a new platform by implementing those interfaces, never by touching the protocol.

```
   ┌──────────────── per-platform UI shell ────────────────┐
   │ Desktop · Android (Kotlin) · iOS (Swift) · CLI · Web  │
   └───────────────────────────┬───────────────────────────┘
                               │  uniffi / FFI / wasm-bindgen
   ┌───────────────────────────▼───────────────────────────┐
   │      MYCELLIUM CORE  —  portable Rust, no_std-capable  │
   │  identity/keys · X3DH + Double Ratchet · record        │
   │  sign/verify · message format · session state machine  │
   └──────┬──────────────────┬───────────────────┬─────────┘
   traits:│ Transport        │ Storage           │ Platform (rng/time)
   ┌──────▼──────┐   ┌────────▼───────┐   ┌───────▼──────┐
   │ libp2p      │   │ SQLite / files │   │ OS entropy   │
   │ minimal TCP │   │ flash KV       │   │ HW RNG       │
   └─────────────┘   └────────────────┘   └──────────────┘
```

### 10.2 Rust, and why

Rust is the only mainstream language that genuinely reaches this whole range: native desktop, Android (NDK), iOS (FFI), browser (WASM), *and* bare-metal microcontrollers (`no_std`). rust-libp2p exists; RustCrypto/dalek provide `no_std` crypto. And for an end-to-end messenger, memory safety is not a nicety — a buffer bug is a security hole. C reaches everything too, but hands you those bugs; Rust does not.

### 10.3 The trait boundaries

The core depends on *behaviours*, not implementations:

- **Transport** — open/accept a secure connection to a peer. libp2p is the plug-in for capable devices; a minimal Noise-over-TCP/UDP for constrained ones. **The core never hard-depends on libp2p** — a refinement of Layers 7–8: *libp2p where it fits, abstracted everywhere.*
- **Storage** — persist identity, sessions, and messages. SQLite/files on rich platforms; a flash key-value store on embedded.
- **Platform** — entropy and time. OS RNG or a hardware RNG; a monotonic clock.

### 10.4 Capability tiers

| Tier | Devices | RAM | Transport | Role |
|---|---|---|---|---|
| **Full** | Desktop, phone, RPi, browser | 100 MB+ | rust-libp2p — DHT, NAT traversal, relay | Full peer; can bootstrap/relay others |
| **Constrained** | ESP32, Cortex-M4/M7 | 256 KB–8 MB | Minimal Noise-over-TCP/UDP; dial a *known* peer/relay; little or no DHT | Real peer, reduced discovery |
| **Minimal** | 8-bit AVR (Uno) | ~2 KB | Crypto only, over serial to a companion | **Not an independent peer** — a sensor behind a host |

The floor for a **first-class, independent peer is the Constrained tier (ESP32 / Cortex-M).** Below it, an 8-bit chip can hold a key and encrypt, but needs a companion device to reach the network — which reintroduces a helper in the middle, so it is explicitly *not* a full Mycellium node. Constrained peers also accept a real limitation: with little or no DHT, they generally reach others through a *known* peer or relay rather than open discovery.

### 10.5 The shells

One core, compiled and wrapped per platform: desktop (native, egui/Tauri or CLI), Android (Kotlin UI over the core via `uniffi`), iOS (Swift over FFI), web (WASM), embedded (`no_std` + esp-hal / Cortex-M HAL). The UI is per-platform; the protocol is shared and audited once.

---

## Layer 11 — Devices (a cluster is one identity)

*Design for multi-device. Not yet implemented — this is the plan.*

Your account is your seed/wallet. You may run it on several devices — phone,
laptop, tablet. They form a **cluster** that looks like one identity to the
outside world, while each device holds its *own* message keys. The goal is the
"normal app" feel — *add a device and my messages show up there* — without
giving up end-to-end guarantees or bolting on a trusted server.

### 11.1 A device, and joining the cluster

The published record (Layer 8.2) stops being a single keyset and becomes a
**wallet-signed set of devices**. Each entry is `{ device-id, device signing
key, messaging + pre-keys }`, where the **device-id is derived from the device's
own public key** (self-certifying, no central assignment). The wallet signature
over the set is what proves every listed device belongs to the account.

- **Adding a device needs no ceremony.** Install, enter the seed → the device
  derives the wallet, generates its *own random* message keys, signs itself into
  the record (the seed is the authority), and republishes (`seq++`). No QR scan
  from an old phone — the seed *is* the permission, the same property that lets
  it recover the identity (9.4).
- **Removing a device** republishes the set without it (`seq++`). Anti-rollback
  (9.4) already stops a dropped device from re-appearing with a stale record.
- Per-device keys mean a **seed leak lets an attacker authorize a new device**
  (identity compromise — revocable) **but never retroactively decrypts past
  traffic**, because message keys are device-local, not seed-derived. Wallet =
  authority; per-device keys = confidentiality.

### 11.2 A conversation is a group of *devices*

The unifying idea: **1:1, group, and multi-device are one mechanism.** A
conversation's members are *devices*, not identities. John ↔ Mary is the device
group `{John's devices} ∪ {Mary's devices}`; a group chat is the union across
all members. Each device has its own **sender key** (the exact sender-keys
machinery from group messaging), distributed once to every other device over the
pairwise X3DH-sealed channel. This is *why* we built sender keys — multi-device
falls out of them.

### 11.3 Sending: encrypt once, the cluster reads it

The message body is encrypted **once** with the sender's sender key. A single
ciphertext goes to the conversation; every member device decrypts it with the
sender key it already holds. Only the small **sender-key distribution** is
per-device, and only once per membership change — never per message. (Treating
the cluster like a group is the design, not a later optimization.)

- **Sync-to-self is free.** Your own other devices are members of the
  conversation, so they read the same ciphertext and show your sent messages
  automatically — no separate sync channel.
- Because the content ciphertext is **identical for the whole cluster**, the
  directory can hold one blob the cluster reads (per-device read cursor,
  non-draining) rather than one copy per device.

### 11.4 Delivery: the directory is the blind server

We are **not** bypassing a server here — the directory *is* the server for this,
just blind. This is exactly how "normal" E2E apps work: in Signal / WhatsApp /
iMessage the **sender's client** encrypts per recipient device, and the server
only **routes** the already-encrypted blobs — it never sees plaintext and never
fans out *crypto*, only *delivery*. The per-device encryption is the cost of
end-to-end encryption itself, not a P2P tax. Our directory plays that same role:
device **registry** (the set lives in the signed record), a blind **mailbox**,
and **presence**. Online devices still take the direct `serve` fast-path;
offline ones read the mailbox — the same `deliver` decision we already make.

### 11.5 A new device starts fresh

A device added at time *T* sees messages from *T* onward. **No history
backfill** — which is what you want (a phone you just linked shouldn't suddenly
hold years of history) and is *also* better for secrecy: it cannot read anything
sent before it joined. To carry history to a new device, move it explicitly with
`export` / `import`.

### 11.6 The honest trade-off

Using sender keys for the cluster (instead of a pairwise Double Ratchet per
device) buys the encrypt-once efficiency and the unified model, at the standard
sender-keys cost: **forward secrecy yes** (symmetric chain), **weaker
per-message post-compromise security** than the DH ratchet. Mitigation: periodic
**sender-key rotation** (already in `group`) restores PCS at chosen intervals,
and every membership change forces a re-key. Trust inside a cluster is mutual —
your devices trust each other (all wallet-authorized); a compromised device
reads the conversation until revoked, the same limit every messenger has. The
directory still sees the *shape* (who has how many devices, who talks to whom) —
the same metadata honesty as Layers 6/8 — but never the content.

---

## Where we zoom in next

Concept, wire, identity, and client architecture are now all specified end to end:

> **A direct libp2p line between two seed-derived wallet identities: Noise-secured transport carrying an X3DH + Double-Ratchet end-to-end payload, discovered through a thin untrusted directory of permanent, self-signed handle records — an intermediary that can neither read the line, sit in the middle of it, nor fake who anyone is.**

What remains is no longer concept — it's building and hardening:

- **Build the POC** — ✅ *done.* The **Rust core** (`mycellium-core`: seed/keys, handle, record sign/verify, X3DH + Double Ratchet, wire codec, behind the Transport/Storage/Platform traits), the **directory service** (`mycellium-directory`: login + signed-KV + anti-rollback + permanent binding), and a **Full-tier shell** (`mycellium-cli`) that runs the whole flow — register → look up → direct connect → X3DH → ratchet → E2E messages — over a TCP transport. See [`../README.md`](../README.md) to run it.
- **libp2p transport** — ✅ *done.* A `Transport` impl over rust-libp2p (TCP + Noise + Yamux, PeerId derived from the device key, a `/mycellium/1.0` byte-stream protocol) sits behind the same trait as the TCP transport; `mycellium-cli` selects it with `--libp2p` and auto-detects it from the peer's multiaddr. **NAT traversal** (DHT, relay, DCUtR) is the remaining increment — added in the swarm, with no change to the app above.
- **Live delivery with mailbox fallback** — ✅ *done.* A member runs `serve` to stay online (it announces presence). When sending (1:1, group, broadcast, forward), the client checks each recipient's presence and **pushes the message directly over a live connection if they're online**, falling back to the offline mailbox otherwise. Group messages therefore reach online members live and offline ones via their mailbox — one `deliver` path, verified by an e2e live-push test. (Full 1:1 *interactive* chat still uses the dedicated `chat`/`listen` ratchet path.)
- **Conversations overview** — ✅ *done.* `conversations` lists every peer and group with a last-message preview (pruning expired).
- **Full-duplex chat** — ✅ *done.* Live chat is bidirectional: the connection is split into read/write halves, the ratchet is shared under a mutex, and a reader thread prints incoming messages while the main thread sends. Works identically over TCP and libp2p (the responder starts replying once it has received the first message). A `--tui` flag gives a full-screen terminal interface.
- **Directory rate limiting** — ✅ *done.* Mailbox deposits are capped per authenticated wallet in a fixed time window (anti-spam), returning `429` when exceeded — a first abuse control on the one hosted piece.
- **Presence** — ✅ *done.* The directory keeps a last-seen timestamp per handle (`announce` heartbeats, authenticated; only the handle's owner may set it) and answers an open `presence` query as online/offline within a TTL. This is deliberately coarse — the directory already sees reachability metadata (Layer 8.2); it never sees content.
- **Export / import backup** — ✅ *done.* `export` bundles the encrypted identity and the whole local store into one file; `import` restores it into a fresh device (refusing to overwrite an existing identity). Everything in the bundle is already encrypted at rest, so the backup needs no extra protection.
- **Block list** — ✅ *done.* A local, encrypted block list (`block` / `unblock` / `blocked`): messages from blocked handles are silently dropped on the offline inbox (direct and group — no display, storage, or receipt), and live connection attempts from blocked peers are refused after the handshake reveals who they are.
- **Client conveniences** — ✅ *done.* Beyond the core: `verify` (safety number out of band), `forward`, `broadcast` (one message to many), `group leave`/`info`, `draft` messages, `clear-history`, and `wipe` (erase all local data). All operate on the same encrypted local store and typed-message machinery.
- **Contacts (with TOFU pinning)** — ✅ *done.* A local, encrypted address book (`contact add/list/remove`) maps nicknames to handles and **pins each contact's wallet on first add**. `send`/`chat` accept a nickname, and before connecting they check the looked-up record's wallet against the pin — a mismatch means the directory handed over a *different* identity, and Mycellium refuses. This turns the Layer 5 "dishonest directory" concern into an automatic trust-on-first-use guard.
- **Typed messages** — ✅ *done.* The encrypted payload is a structured `AppMessage` (`mycellium-core::message`) with an id and a body of **text**, **reply** (references another message's id), **reaction** (emoji + target id), or **receipt**. Reading an offline message auto-returns a **read receipt** to the sender (receipts never receipt each other, so there's no loop); the sender sees the read status on their next inbox. A **file** body (`send --file`) carries an attachment end-to-end like any message (size-capped, saved to a downloads folder on receipt) — works for 1:1 and groups. **Edit** and **delete/unsend** bodies (`send --edit <id>` / `--delete <id>`) reference an earlier message by id and mutate the recipient's stored transcript (best-effort, like disappearing messages).
- **Disappearing messages** — ✅ *done.* Optional per-message TTL (`send --expire 1h`) plus a per-conversation default (`expire set/clear/show`). The expiry rides in the E2E `AppMessage`; a message already expired on arrival is dropped (no display/store/receipt), and stored transcripts are pruned lazily whenever history is loaded. Honestly best-effort, not enforced: our client deletes on schedule, but — like every messenger — a modified peer client could keep a copy. Every path — live, offline, group — carries it, message ids are shown on receipt, and `send`/`group send` take `--reply-to` and `--react/--to`. (Verified by an offline reply+reaction e2e test.)
- **Local message history** — ✅ *done.* The `Storage` trait now has an implementation: an encrypted file-backed key-value store (key derived from the identity via HKDF). Transcripts are persisted per peer, encrypted at rest, replayed when a chat opens, and viewable with `history <peer>`. `search <query>` scans all local 1:1 and group transcripts (case-insensitive, pruning expired as it goes).
- **Group messaging (core)** — ✅ *protocol done.* Groups use **sender keys** (the WhatsApp/Signal-groups design): each member has a per-group symmetric chain + Ed25519 signing key, distributed to the others *once* over the pairwise Double-Ratchet channel; thereafter a member encrypts each message **once** with its chain and signs it, and every holder of that sender key decrypts and verifies. This gives forward secrecy within a sender's chain and authenticates the true sender, at the cost of no post-compromise recovery and a re-key (fresh sender key) on membership change — the standard sender-keys trade-off, chosen so a group message is encrypted once rather than per-recipient. The `mycellium-core::group` module implements it (3-member flow, out-of-order, forgery/non-member rejection all tested), and the CLI wires it end to end over the offline mailbox: `group create` invites members (sender keys distributed inside pairwise E2E envelopes), `inbox` processes invites and does the mesh key exchange, and `group send` fans a single ciphertext out to every member. Verified by a 3-member e2e test. **Membership changes** are handled too: `group add` invites a newcomer and propagates the updated roster (existing members send it their keys); `group remove` drops the member, **rotates** every remaining member's sender key, and redistributes — so a removed member, who still holds the old keys, can read nothing further (verified by add/remove e2e tests). The directory sees only that someone deposits to several mailboxes (group membership is metadata it can observe — the same honest limit as 1:1); message content stays end-to-end.
- **Trust hardening** — ✅ *done.* Out-of-band **safety numbers** (Layer 5): a short code derived from both peers' wallet identities, shown after the handshake, that catches a dishonest directory.
- **More recovery factors** — ✅ **social recovery** done: Shamir *t-of-n* guardian shares (`guardian-split` / `guardian-recover`) reconstruct a lost seed from a threshold of guardians, softening the 9.5 "words or nothing" limit; no single guardian can impersonate you. Phone/email as *combined* factors remain future. (Seed at rest is also encrypted — Argon2id + ChaCha20-Poly1305.)
- **Offline** — ✅ *done.* Async X3DH (against the recipient's published `signedPreKey`) + a per-handle **mailbox** in the directory. The sender seals an [`Envelope`] the mailbox stores but cannot read; the recipient drains and decrypts it later. `mycellium-cli send` / `inbox`.

  **A deliberate, documented softening of Layer 3.** Offline delivery is the one place the directory *holds* a message rather than merely brokering discovery. We keep it honest: it stores only opaque, end-to-end-encrypted envelopes (it can't read them), any authenticated sender may deposit, and only the handle's owner may collect. This is the trade-off Layer 4 deferred, now made explicit — the directory is still not a hub that owns your conversation, but it does briefly *carry* sealed messages for peers who aren't online.

### Known gaps in the POC (honest list)

- **No NAT traversal yet** — the libp2p direct line works, but peers still reach each other by an address published in the record; DHT/relay/DCUtR is the next step.
- **`PeerId` in the record is a location string** — the core carries the transport address (TCP `host:port` or a libp2p multiaddr) in the record's `peer_id` field; a cleaner split of identity vs. reachability is future work.
- **Multi-device not yet built** — the design is settled (Layer 11: per-device keys, seed self-authorizes a device into the cluster, a conversation is a group of devices, encrypt-once via sender keys, blind directory delivery, new devices start fresh). Implementation — record-as-device-set, `link-device` / `revoke-device`, per-device delivery, and cluster fan-out — is the next build.
- **Reactions/edits are best-effort and flattened in history** — they mutate the stored transcript rather than being aggregated onto their target in a structured UI.

(The wallet key now uses standard **BIP-44** (`m/44'/60'/0'/0/0`), verified against a known vector, so a Mycellium seed imports into external wallets. Device/messaging keys stay on HKDF, as X25519 has no external HD standard.)
