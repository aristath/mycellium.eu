# mycellium-storage

Encrypted local file storage for a Mycellium peer.

`filestore::FileStore` is a directory-backed key-value store implementing the
core `Storage` trait. Values are encrypted with ChaCha20-Poly1305 under a key
derived from the identity.

`store` seals the local identity itself: wallet secret plus device seed are
serialized and encrypted under an Argon2id-derived passphrase key.

## Process Config

Native apps set storage config explicitly:

```rust
mycellium_storage::store::configure(mycellium_storage::store::ClientConfig {
    data_dir: "data/alice".into(),
    passphrase: Some("dev passphrase".into()),
    queue_url: "http://127.0.0.1:8090".into(),
    display_name: "Alice".into(),
});
```

Without a configured passphrase, identity load/save prompts on the terminal.
