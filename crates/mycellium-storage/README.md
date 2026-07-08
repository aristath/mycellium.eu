# mycellium-storage

Encrypted local file storage for a Mycellium peer.

`filestore::FileStore` is a directory-backed key-value store implementing the
core `Storage` trait. Values are encrypted with ChaCha20-Poly1305 under a key
derived from the identity.

`store` seals the local identity itself: wallet secret plus device seed are
serialized and encrypted under an Argon2id-derived passphrase key.

Native apps configure the local data directory, optional noninteractive
passphrase, and display name before using the engine.
