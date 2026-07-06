# Security

Mycellium keeps infrastructure untrusted:

- The directory stores signed records and presence. It cannot forge records.
- The queue stores opaque encrypted blobs keyed by wallet. It cannot read mail.
- The relay forwards Noise-encrypted circuit traffic. It cannot read payloads.
- Local history is encrypted with keys derived from the identity.
- The local identity is sealed under a passphrase or platform secret store.

Production services should use durable `data_dir` values, SMTP-backed directory
verification, and TLS either in service JSON or at a terminating proxy.
