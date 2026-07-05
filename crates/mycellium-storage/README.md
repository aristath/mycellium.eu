# mycellium-storage

> Encrypted local file storage for a Mycellium peer: a key-value store for app data, plus the identity sealed at rest.

**Layer:** adapter · **Implements:** mycellium-core `Storage` · **Key deps:** `chacha20poly1305` (ChaCha20-Poly1305), `argon2` (Argon2id), `getrandom`, `serde`/`serde_json`

## What it does

Provides the durable local state a peer keeps on a rich host. `FileStore` is a
directory-backed key-value store implementing the core `Storage` port: every
value the engine persists — message history, contacts, groups, drafts, outbox —
is written as one file per key, encrypted at rest. Each entry is stored as
`nonce || ChaCha20-Poly1305(value)` under a 32-byte key derived from the
identity (via `Identity::storage_key`), so on-disk data stays consistent with the
account. A separate `store` module seals the identity itself: the account
`wallet_secret` and this device's seed are serialized, then encrypted under a key
that Argon2id derives from a user passphrase and a random salt. There is no seed
phrase — account recovery after losing every device is via the directory's email
verification, and more devices are added by pairing.

## Public API

**`filestore::FileStore`** — a directory of encrypted KV files.
- `FileStore::open(dir, key)` — open (creating the dir if needed), encrypting with a 32-byte key.
- `get` / `put` / `delete` — the core `Storage` trait: read, write, and remove values; keys map to hex-named files.

**`store`** — the identity at rest.
- `save_identity(&Identity)` — Argon2id + ChaCha20-Poly1305 seal the wallet secret and device seed under a passphrase.
- `load_identity() -> Identity` — decrypt and restore the same device from disk.
- `data_dir()` — the data-directory root, for other local state.
- `path()` — path to the encrypted identity file (`identity.enc`).
- `exists()` — whether an identity is already stored.

## Environment

- `MYCELLIUM_HOME` — the data directory; defaults to `.mycellium`. Sets where `identity.enc` and other local state live.
- `MYCELLIUM_PASSPHRASE` — the passphrase used to seal/unseal the identity. If set, used non-interactively; otherwise it is prompted for on stdin.

## How it fits

The engine derives a 32-byte key from its loaded identity and opens a
`FileStore` in `data_dir()` for all local persistence. A different platform
(web, embedded) swaps this crate for its own `Storage` adapter; the core
depends only on the trait.

## Notes

There is no passphrase strength policy: a one-character passphrase is accepted
(only an empty one is rejected), so Argon2id's work factor is the sole guard on a
weak passphrase. Choose a strong one — the seed's on-disk secrecy rests on it.
