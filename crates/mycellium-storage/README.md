# mycellium-storage

Encrypted local storage for Mycellium clients.

`filestore::FileStore` implements `mycellium_core::storage::Storage` with one
encrypted file per logical key. Values use ChaCha20-Poly1305 under the
identity-derived storage key, with the logical key bound as associated data.
Multi-key mutations use an encrypted, fsynced write-ahead journal so interrupted
commits are replayed when the store reopens. On Unix, directories are restricted
to mode `0700` and files to `0600`.

`store` is the Linux/CLI identity envelope. It serializes the wallet root and
current device seed, derives a wrapping key from the user's passphrase with
Argon2id, and seals the identity with ChaCha20-Poly1305. A device switch recovers
the wallet root through the authenticated registry account, then creates a fresh
device seed; it does not copy an old device identity.

Android and Apple do not use the passphrase envelope. Their native shells keep
the opaque 64-byte identity in Android Keystore or Apple Keychain and pass it to
the shared Rust mobile layer. Their message history still uses `FileStore`.

`ClientConfig` exists for the CLI and other explicit non-GUI callers. Native
apps choose their platform data path and secret-storage mechanism themselves.
