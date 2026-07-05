# Mycellium — Security & Cryptography Audit Brief

*Prepared for an independent auditor scoping a pre-launch crypto/protocol review.*
Tracks [issue #66](https://github.com/aristath/mycellium.eu/issues/66). This document
is the starting point; the authoritative detail lives in the code and in
[`SECURITY.md`](SECURITY.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), and
[`CONCEPT.md`](CONCEPT.md), cross-linked throughout.

> **Status:** Mycellium has **not** been independently audited. The cryptography is
> assembled from vetted RustCrypto primitives — never invented — but the *composition*,
> the protocol state machines, and the service trust boundaries have never had external
> review. A public launch is gated on that review (this issue, and the ⛔ item in
> [`GO-LIVE.md`](GO-LIVE.md)). Nothing here has a formal proof.

---

## 1. System overview

Mycellium is a peer-to-peer, end-to-end-encrypted messenger with **no trusted middle**.

- **Identity is a wallet key you hold.** Your account *is* a random secp256k1 key
  (the signing root). There is **no seed phrase** — the key is generated from the OS
  CSPRNG, held encrypted at rest, and moved to additional devices only over an
  authenticated pairing channel (never as a copyable payload). Each device also holds
  its own Ed25519 (transport) + X25519 (messaging) keys.
- **The directory is untrusted.** It maps `handle → wallet-signed record`. Every record
  is self-certifying, so the operator can withhold or serve stale data but can never
  forge a record or bind a handle to a wallet the user does not control.
- **The queue is untrusted.** A per-recipient, wallet-addressed store-and-forward
  mailbox that holds only opaque E2E ciphertext. It can drop or delay, not read.
- **Delivery is direct P2P** (framed TCP or libp2p Noise/Yamux) when the peer is
  reachable, falling back to the queue, then to a local encrypted outbox.

Read first: [`ARCHITECTURE.md`](ARCHITECTURE.md) (the map that ties the crates
together) and [`CONCEPT.md`](CONCEPT.md) (the design rationale). The protocol core is
`no_std`, forbids `unsafe`, and holds all secret material in `zeroize`-on-drop types.

---

## 2. Cryptographic composition — the core of what to audit

Every primitive below is from the RustCrypto ecosystem. Exact locations and the
domain-separation strings are given so a reviewer can go straight to the code.

### 2.1 Primitives and versions

| Purpose | Primitive | Crate (version) |
|---|---|---|
| Wallet identity / record & pre-key signatures / login | secp256k1 ECDSA (deterministic, over SHA-256) | `k256` 0.13 (`ecdsa`, `arithmetic`) |
| Device transport identity / group message signatures | Ed25519 | `ed25519-dalek` 2 |
| Key agreement (X3DH, Double Ratchet DH, pairing ECDH) | X25519 | `x25519-dalek` 2 (`static_secrets`) |
| Message & envelope AEAD | ChaCha20-Poly1305 | `chacha20poly1305` 0.10 |
| Session KDF (X3DH), ratchet root KDF, AEAD key/nonce, pairing KDF, identity key derivation | HKDF (SHA-256 for wire KDFs; SHA-512 for identity/storage key derivation) | `hkdf` 0.12, `sha2` 0.10 |
| Ratchet & sender-key chain KDF | HMAC-SHA256 | `hmac` 0.12, `sha2` 0.10 |
| Safety number | SHA-512 | `sha2` 0.10 |
| At-rest passphrase KDF | Argon2id | `argon2` 0.5 |
| Wire encoding (also the signed canonical form) | postcard (deterministic for a fixed type) | `postcard` 1 |
| P2P transport encryption | Noise + Yamux via libp2p | `libp2p` 0.56 (`tcp`, `noise`, `yamux`, `ed25519`) |
| Service TLS | rustls | via `axum-server` 0.7 / `mycellium-serve` |

### 2.2 Identity — `crates/mycellium-core/src/identity.rs`

- The **wallet secret** is a raw 32-byte secp256k1 scalar drawn directly from the
  platform CSPRNG in a rejection loop (`Identity::generate`), never a seed-phrase
  derivation. It signs records and login challenges; it never enters the encrypted
  channel.
- **Device and messaging keys** are derived from an independent random **device seed**
  via `HKDF-SHA512` with distinct domain labels (`mycellium:device:ed25519:v1`,
  `mycellium:messaging:x25519:v1`, `mycellium:spk:x25519:v1:0`). Consequence, and worth
  verifying: a wallet-key leak lets an attacker authorize a *new* device but does not
  retroactively yield this device's messaging keys or its at-rest `storage_key`.
- `storage_key()` derives the local-storage key by `HKDF-SHA512` from the device key
  with label `mycellium:local-storage:v1`.
- `Identity` zeroizes the wallet secret and device seed on drop; the dalek/k256 types
  zeroize their own material.

### 2.3 Key agreement — X3DH — `crates/mycellium-core/src/x3dh.rs`

- Three Diffie-Hellmans over X25519: `DH1 = IK_A·SPK_B`, `DH2 = EK_A·IK_B`,
  `DH3 = EK_A·SPK_B`, where `EK_A` is a fresh initiator ephemeral. `SK = HKDF-SHA256`
  over `DH1‖DH2‖DH3` (salt `[0u8;32]`, info `Mycellium-X3DH-v1`).
- **One-time pre-keys are deferred** — this is the interactive/one-shot async variant
  (documented in-file and in [`offline.rs`](../crates/mycellium-core/src/offline.rs)).
  A reviewer should assess the forward-secrecy / first-message-replay properties this
  gives up versus full X3DH.
- Contributory (all-zero) DH outputs are rejected before key derivation on both sides.
- No identity-binding signature is transmitted in the handshake itself; sender identity
  is authenticated separately by the signed record carried in the `Envelope`
  (`offline.rs`) and by TOFU pinning in the engine. **Confirm this binding is airtight**
  (that a valid `SK` cannot be reached with a mismatched claimed identity).

### 2.4 Double Ratchet — `crates/mycellium-core/src/ratchet.rs`

- Signal Double Ratchet: X25519 DH ratchet; root KDF `HKDF-SHA256` (info
  `Mycellium-DR-Root`); chain/message-key KDF `HMAC-SHA256` (`0x01`/`0x02`); AEAD
  ChaCha20-Poly1305. Seeded by the X3DH `SK`; the responder's signed pre-key doubles as
  its first ratchet key.
- The per-message `Header` (`dh`, `pn`, `n`) is sent in the clear but bound as AEAD
  associated data (concatenated with the caller's `ad`, which the engine sets to the two
  identities).
- Skipped keys bounded by `MAX_SKIP = 256`; replays and over-long skips rejected. A
  low-order remote ratchet key is rejected **before** any state mutation, so a bad
  header can't leave the ratchet half-stepped.

### 2.5 Symmetric core — `crates/mycellium-core/src/cipher.rs`

- One shared implementation for the ratchet and for group sender keys.
- `kdf_ck`: `mk = HMAC(ck, 0x01)`, `ck' = HMAC(ck, 0x02)`.
- `message_keys`: the AEAD key **and 12-byte nonce** are both derived from the message
  key via `HKDF-SHA256` (salt `[0u8;32]`, info `Mycellium-Msg`). **The nonce is
  deterministic, not random** — safe only because each `mk` is unique per message. A
  reviewer should confirm no code path ever reuses an `mk` across two encryptions (this
  is the load-bearing invariant for nonce-reuse safety).

### 2.6 Offline envelopes — `crates/mycellium-core/src/offline.rs`

- A self-contained one-shot session: sender's handle, sender's `SignedRecord` (for
  identity verification), the X3DH `HandshakeInit`, and one `RatchetMessage`. Opaque to
  whatever stores it. Long-lived async ratchets are future work.

### 2.7 Records & anti-rollback — `crates/mycellium-core/src/record.rs`

- `SignedRecord` = `Record` + wallet ECDSA signature over domain-tagged canonical bytes
  (`mycellium-record-v1\0` ‖ postcard). Per-device signed pre-keys carry their own
  wallet signature over `mycellium-prekey-v1\0` ‖ key.
- `verify()` checks the record signature, every device's pre-key signature, a non-empty
  device set, and shape limits (`MAX_DEVICES = 32`, `MAX_NAME_LEN = 128`,
  `MAX_QUEUE_LEN = 512`, `MAX_PEER_ID_LEN = 256`) to bound abusive-but-valid records.
- **Anti-rollback** is the monotonic `seq` (u64), enforced at the directory on publish
  (§4). The domain/version prefix lives *inside* the signed bytes so a schema bump
  cleanly invalidates old signatures.

### 2.8 Groups / sender keys — `crates/mycellium-core/src/group.rs`

- Sender-key design keyed **per device**. Each member's sender key = an `HMAC-SHA256`
  chain + an Ed25519 signing key; distributions travel over the pairwise Double Ratchet.
  Each message is encrypted once (ChaCha20-Poly1305) and signed (Ed25519 `verify_strict`,
  which the receiver checks *before* decrypting).
- Properties to weigh: forward secrecy within a sender's chain; **no post-compromise
  recovery**; membership change requires every member to rotate and redistribute.
  `MAX_SKIP = 1024`. `GroupState` serializes secret chain keys and the signing seed —
  it **must** be stored encrypted at rest (it is, via the identity-keyed store).

### 2.9 Device pairing — `crates/mycellium-core/src/pairing.rs`

- Seedless provisioning: the **new** device shows an ephemeral X25519 public key in a
  QR; the **existing** device scans it (out-of-band visual authentication), then seals
  the account payload with ephemeral-static X25519 ECDH → `HKDF-SHA256` (info
  `mycellium:pairing:v1`) → ChaCha20-Poly1305 (AAD `mycellium-pairing-v1`), relayed
  through a short-lived rendezvous. Single-use; all-zero shared secret rejected. Security
  rests on the QR public key never leaving the visual channel — a reviewer should confirm
  the rendezvous relay cannot substitute keys undetected.

### 2.10 Safety numbers — `crates/mycellium-core/src/safety.rs`

- `SHA-512` over `mycellium-safety-number-v1` ‖ sorted(walletA, walletB), rendered as 6
  groups of 5 decimal digits (30 digits). Order-independent. Derived from the **wallet
  identity keys**. Reviewer note: assess the effective collision/preimage resistance of
  the 30-digit truncation for the OOB-comparison threat.

### 2.11 Login contract — `crates/mycellium-core/src/login.rs`

- SIWE-style: the signed message is `mycellium-login:` ‖ nonce. Defined once in the core
  so directory server and clients cannot disagree.

### 2.12 Wire codec — `crates/mycellium-core/src/wire.rs`

- postcard. `canonical()` = the exact signed bytes (no version prefix, so signatures
  survive envelope changes). `encode()`/`decode()` frame with a 1-byte version and reject
  unknown versions. Decoders are fuzzed (garbage/truncated/bit-flipped input must never
  panic and never accept a tampered record).

### 2.13 At-rest — `crates/mycellium-storage/`

- **Identity sealing** (`store.rs`): passphrase → `Argon2id` (`argon2` 0.5 defaults:
  Argon2id, 19 MiB, t=2, p=1) → 32-byte key; seals `{wallet_secret, device_seed}` with
  ChaCha20-Poly1305 (16-byte random salt, 12-byte random nonce). Files are `chmod 0600`
  best-effort. `MIN_PASSPHRASE_LEN = 8`.
- **Local KV** (`filestore.rs`): each value is `nonce ‖ ChaCha20-Poly1305(value)` under
  the identity's `storage_key()`.
- **Doc drift to flag (not a code bug):** `store.rs`'s module comment still refers to a
  "seed phrase" / "24 words" / "mnemonic" — vocabulary left over from before the seedless
  refactor (#6). The *code* seals `wallet_secret + device_seed`; there is no mnemonic.
  Worth correcting so an auditor isn't misled by the prose.

### 2.14 SDK identity-at-rest — interim, **known weakness** — `crates/mycellium-sdk/`

- `mycellium-sdk` currently persists the device identity secret
  (`{wallet_secret, device_seed}`) to `data_dir/identity.json` as **plaintext JSON**,
  `chmod 0600` best-effort on Unix only (`load_or_create_identity`,
  `restrict_secret_file`). It is **not encrypted** — the FileStore is keyed *by* the
  identity, so it cannot hold its own key, and no OS-secure-storage adapter exists yet.
  **[#65](https://github.com/aristath/mycellium.eu/issues/65)** replaces this sidecar
  with OS-native secure storage (Keychain / Keystore / DPAPI / libsecret) behind the same
  API. Call this out explicitly to early users and to the auditor as a scoped, tracked
  interim state.

---

## 3. Trust boundaries & threat model

Full treatment in [`SECURITY.md`](SECURITY.md); summarized here. Mycellium is
**explicitly not an anonymity system** and makes no social-graph-privacy claim.

| Actor | Can | Cannot |
|---|---|---|
| **Directory operator** | See record contents (handle → wallet, device keys, queue endpoint, transport addrs — records are *public*, lookups unauthenticated); who looks up whom; presence; publish/login/recovery timing; probe handle availability. Withhold or serve stale records. | Forge a record or rebind a handle to a wallet it doesn't control; read message content. Email is kept only as a keyed hash (per-server pepper) — it can *test* a guessed address, not read one. |
| **Queue operator** | Learn **sender ↔ recipient linkage** and timing (deposits are sender-authenticated — the depositor logs in with their own wallet), device slot, approximate blob size (not yet bucketed — [#51](https://github.com/aristath/mycellium.eu/issues/51)), queue depth, push endpoints. Drop or delay. | Read content; forge; collect another wallet's mail. |
| **Passive network observer** | See IP↔service and IP↔peer connection metadata, timing, sizes. Without TLS on client↔service HTTP, see everything — **TLS is mandatory**. | Read content over TLS or over P2P Noise/framed links. |
| **Malicious peer** | Send you traffic; try malformed input. | Impersonate a third party (needs their private key); forge a record; get past TOFU pinning with a mismatched key. |
| **Compromised device** | Read that device's plaintext and its keys — endpoint compromise is **out of scope** for E2E. | Retroactively decrypt other devices' traffic (per-device message keys); the Double Ratchet gives forward secrecy + post-compromise recovery for the pairwise channel. |

**Honest non-goals / metadata reality** (from `SECURITY.md`): the infrastructure sees
*who talks to whom and roughly when*. There is no cover traffic and no mixnet. First
contact is **TOFU** (pin-on-first-sight); the transparency-log direction that would close
the first-contact gap is [#56](https://github.com/aristath/mycellium.eu/issues/56), and
removing the sender from the queue's view (sealed-sender) is
[#55](https://github.com/aristath/mycellium.eu/issues/55). Account-key theft/coercion and
availability of a queue you don't control are also out of scope.

---

## 4. Audit targets

Priority order roughly high → low. Component READMEs under each crate give the API detail.

1. **`mycellium-core`** — identity, X3DH, Double Ratchet, symmetric core (nonce-derivation
   invariant, §2.5), offline envelopes, records + anti-rollback, groups/sender-keys,
   pairing, safety numbers, wire codec. *This is the crown jewel; §2 is the map.*
2. **`mycellium-engine`** — the orchestration that composes the core primitives:
   - **Delivery ladder** (live push → queue deposit → outbox) and the associated-data
     each message is bound to.
   - **Self-sync** (mirroring your own messages device→device, sealed).
   - **Group fan-out** (sender-key distribution over the pairwise channel, one-ciphertext
     fan-out, rotation on membership change).
   - **Outbox** (encrypted local retry buffer).
   - **Contact pinning / TOFU** and **key-change handling** (what happens on a mismatch,
     and how a legitimate email-rebind key change is surfaced vs. rejected).
3. **`mycellium-storage`** — identity sealing (Argon2id params, salt/nonce handling) and
   the encrypted local KV; confirm no secret is written outside the sealed paths.
4. **`mycellium-directory`** (+ `mycellium-server`) — signed-record **validation** on
   publish, **handle binding**, **`seq` anti-rollback** enforcement, **login**
   (challenge TTL 5 min, signature verify), **recovery** (email kept only as a
   pepper-keyed SHA-256 hash; rebind semantics), and **rate limits** (fixed-window,
   `RATE_WINDOW = 60 s`, pruned at 10k buckets).
5. **`mycellium-queue`** (+ `mycellium-queue-client`) — **sender-authenticated deposits**
   (session token → wallet; `DEPOSIT_RATE_LIMIT = 30`/60 s; `MAX_MAILBOX = 256`),
   **collection authorization** (only the owning wallet may collect), **ciphertext
   handling** (blobs are opaque; key/slot validation), and **Web Push** (contentless
   VAPID; endpoint storage).
   - *Discrepancy to resolve during audit:* the module doc-comment in
     `mycellium-queue/src/lib.rs` says deposits are "open (anyone may drop…)", but the
     `deposit` code path calls `authed(token)` and rate-limits per **sender** wallet —
     i.e. deposits *are* sender-authenticated, matching `SECURITY.md`. The comment is
     stale; confirm the intended posture and fix the prose.
6. **Native SDK / FFI boundary** (`mycellium-sdk`; UniFFI + C-ABI is #64) — the trust
   boundary between platform UI and the engine, and the interim plaintext identity
   sidecar (§2.14 / #65).
7. **Browser/WASM snapshot model** (`mycellium-wasm`, `clients/web`) — **lower priority**
   (POC surface). The IndexedDB session snapshot (which includes the account key) is
   sealed with a non-extractable AES-GCM key; note the residual full-profile-theft
   caveat in `SECURITY.md`, and that the `window.mycellium` test hook must be
   localhost-gated in any real build.

---

## 5. Known limitations & non-goals (disclose upfront)

- **Not independently audited** and **no formal proofs.** This review is that first
  audit.
- **No anonymity / no traffic-analysis resistance.** The directory sees lookups and
  presence; the queue sees sender↔recipient, timing, and (currently un-bucketed) size.
  No cover traffic, no mixnet.
- **SDK identity-at-rest is plaintext-0600 interim** (§2.14) pending OS secure storage
  ([#65](https://github.com/aristath/mycellium.eu/issues/65)).
- **X3DH one-time pre-keys deferred** (§2.3); offline sessions are one-shot.
- **Groups have no post-compromise recovery** and require rotation on membership change
  (§2.8).
- **First contact is TOFU;** no transparency log yet
  ([#56](https://github.com/aristath/mycellium.eu/issues/56)).
- **Sealed-sender is open research** ([#55](https://github.com/aristath/mycellium.eu/issues/55));
  message-size bucketing is pending ([#51](https://github.com/aristath/mycellium.eu/issues/51)).
- **Endpoint compromise, account-key theft/coercion, and queue availability** are out of
  scope by design.
- **Doc drift:** the `mycellium-storage` module comment still uses seed-phrase vocabulary
  (§2.13); the queue deposit comment is stale (§4.5). Both are prose, not code, but they
  can mislead a reviewer.

---

## 6. Logistics checklist

Mirrors the task list in [issue #66](https://github.com/aristath/mycellium.eu/issues/66);
the launch decision it feeds is the ⛔ audit gate in [`GO-LIVE.md`](GO-LIVE.md).

- [ ] **Freeze the audit target.** Tag a specific commit/release; all findings reference
      that tag. Record it here and in `GO-LIVE.md`.
- [ ] **Hand over the package.** This brief + `SECURITY.md` + `ARCHITECTURE.md` +
      `CONCEPT.md` + the frozen tree. Threat model and non-goals are §3 / §5.
- [ ] **Select an auditor** with crypto/protocol experience (Signal-family protocols,
      Rust crypto, AEAD/KDF composition).
- [ ] **Run the audit; collect findings privately** (no public issues until remediated —
      see the reporting note in `SECURITY.md`).
- [ ] **Triage by severity** (critical / high / medium / low / informational).
- [ ] **Fix all critical & high before launch.** Re-verify against the same or a new
      frozen tag.
- [ ] **Decide on medium findings** — block launch or accept as documented follow-ups
      with written rationale.
- [ ] **Publish a public disclosure summary** after remediation, and update
      `GO-LIVE.md` + the audit-status line in `SECURITY.md` to reflect the final decision.

**Acceptance (from #66):** independent audit completed against a named commit/tag;
critical/high fixed or explicitly accepted with rationale; public docs state audit
status; `GO-LIVE.md` reflects the decision.
