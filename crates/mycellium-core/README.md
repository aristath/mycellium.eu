# mycellium-core

> The portable protocol contract: identity, self-certifying records, the E2E crypto, the wire codec, and the host-port traits — and nothing platform-specific.

**Layer:** contract · **`no_std`:** yes · **Key deps:** `k256` (secp256k1), `ed25519-dalek`, `x25519-dalek`, `bip39`, `bip32`, `chacha20poly1305`, `hkdf`/`hmac`/`sha2`, `postcard`, `zeroize`

## What it does

Defines the Mycellium protocol as pure logic: how a seed becomes a wallet + device keys, how a directory record certifies itself, how two peers agree a session (X3DH) and advance it per-message (Double Ratchet), how a group shares sender keys, how bytes are canonically encoded and signed, and the exact message a client signs at login. It owns the *contract*, not the machine: it never touches the network, disk, clock, or OS RNG — those arrive through the `Transport`, `Storage`, and `Platform` traits. Porting Mycellium to a new device means implementing those three traits, never editing this crate.

## Public API

**Identity** (`identity`)
- `Identity` — the local secret: a random `wallet_secret` (secp256k1) + device seed → wallet, device (Ed25519), and messaging (X25519) keys. **No seed phrase.** `generate` (fresh account), `adopt` (an existing account key onto a new device, via pairing), `from_wallet_secret` (reload from persisted secrets); `sign`, `wallet_public`, `device_public`, `messaging_public`, `signed_pre_key_public`, `storage_key`; `wallet_secret` / `device_seed` (the two secrets to persist encrypted or transfer over pairing), `device_secret` (Ed25519 seed for the libp2p keypair), and `peer_id`. No `Debug`/`Clone`; zeroizes on drop.
- `Handle` — a validated lowercase `[a-z0-9_]` public name (≤ 32 bytes).
- `WalletPublicKey` / `DevicePublicKey` / `MessagingPublicKey` / `PeerId` / `Signature` — the public key and signature types.

**Records** (`record`)
- `Record` — the unsigned body: handle, free-form display `name`, wallet, queue endpoint, device set, `seq`.
- `Device` / `SignedPreKey` — one device's keys in the cluster; a wallet-signed pre-key.
- `SignedRecord` — `Record` + wallet signature; `sign` and `verify` (self-certifying: a directory can withhold but never forge).

**Sessions / crypto** (`x3dh`, `ratchet`, `offline`)
- `x3dh::initiate` / `x3dh::respond` / `SharedSecret` / `HandshakeInit` — the initial key agreement.
- `Ratchet` — the Double Ratchet: `new_initiator`, `new_responder`, `encrypt`, `decrypt`, `can_send`; `Header` / `RatchetMessage`; skipped keys bounded by `MAX_SKIP`.
- `offline::Envelope` — a self-contained one-shot async message for store-and-forward.

**Groups** (`group`)
- `Group` — sender-key membership: `distribution`, `add_member`, `remove_member`, `rotate`, `encrypt`, `decrypt`, `export`/`import`.
- `SenderKeyDistribution` / `GroupMessage` / `GroupState`.

**Messages & trust** (`message`, `safety`)
- `AppMessage` / `Body` — the structured plaintext (text, reply, reaction, receipt, file, edit, delete); `encode`/`decode`, `is_expired`, `summary`.
- `safety::safety_number` — the out-of-band verification code over a pair of wallet identity keys; inputs are sorted, so both sides compute the same number regardless of who asks.

**Device pairing** (`pairing`)
- `pairing` — seedless device pairing: an ephemeral-ECDH, in-person-QR-authenticated channel that transfers the account key to a new device (`PairingResponder`, `seal_provisioning`). Contributory (all-zero) DH outputs are rejected.

**Identifiers & wire & login** (`userid`, `wire`, `login`)
- `userid::user_id` — deterministically hash a username to the opaque `Handle` that actually travels on the wire, so a directory can resolve a name it's given without ever learning the plaintext of names it *isn't*. (An attacker who already guesses a name can confirm it — the usual hash-of-identifier caveat.)
- `wire::canonical` — deterministic bytes that get signed (no version prefix); `wire::encode` / `wire::decode` — framed, versioned bytes for transmission.
- `login::challenge_message` — the exact SIWE-style bytes a client signs against a login nonce.

**Ports / traits** (`transport`, `http`, `storage`, `platform`)
- `Transport` / `Connection` — dial/accept a secured, message-framed byte channel to a *peer* (device-to-device).
- `http::HttpTransport` / `HttpResponse` — an abstract *client/server* HTTP request. Native builds back it with `ureq` (`mycellium-http`); the browser backs it with `fetch`/XHR — so the directory/queue clients compile unchanged to both. A returned `Err` is a transport failure (refused/DNS/TLS); an HTTP error status is an `Ok` with `status >= 400`.
- `Storage` — a byte-keyed `get`/`put`/`delete` KV.
- `Platform` — host CSPRNG (`fill_random`) and wall clock (`now_unix_secs`).

- `Error` — the single protocol-level error enum (host traits carry their own associated error types).

## How it fits

The adapter crates (`mycellium-transport`, `mycellium-storage`) implement its ports, and `mycellium-engine` builds all orchestration on top of these types — so the same protocol runs from a microcontroller to a desktop. See `docs/ARCHITECTURE.md`.

## Notes

`no_std`-capable: it is `no_std` with `extern crate alloc`, and `std` is on only by default. Build for a constrained target with `--no-default-features` (turns off `std` across every crypto dependency); `std` merely adds `std::error::Error` for `Error` and the `std` features of the deps.

Crypto is assembled from vetted primitives, never invented: **X3DH** and the **Signal Double Ratchet** over **X25519**; **Ed25519** device and group-signing keys; **secp256k1** (`k256`) wallet identity (a raw random key, no BIP-39 seed / BIP-32 derivation); **HKDF-SHA512** domain-separated derivation of device/messaging keys; **HMAC-SHA256** chain KDF and **HKDF-SHA256** root KDF; **ChaCha20-Poly1305** message AEAD; and an ephemeral-**X25519**-ECDH pairing channel for seedless device onboarding. Secret material is held in types that `zeroize` on drop; `unsafe_code` is forbidden.
