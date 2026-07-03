# mycellium-queue-client

> Thin HTTP client for the message queue: log in, deposit for a recipient wallet, collect your own.

**Layer:** adapter · **Depends on:** mycellium-core, ureq, serde, anyhow

## What it does

An HTTP client for a running `mycellium-queue`. The queue is keyed by
**wallet**, not handle: you `deposit` an opaque blob addressed to a recipient's
wallet (as lowercase hex), and you may only `collect` from your own wallet's
mailbox. Login is SIWE-style — fetch a challenge, sign it with your identity,
exchange it for a bearer token — using the shared login contract in
`mycellium-core`. It is separate from the directory client because the queue is
a separate service.

## Public API

- `QueueClient::new(base: impl Into<String>) -> Self` — point the client at a queue base URL (e.g. `http://127.0.0.1:8090`); a trailing `/` is trimmed.
- `QueueClient::login(&self, identity: &Identity) -> Result<String>` — challenge/sign/verify; returns a bearer token.
- `QueueClient::deposit(&self, token: &str, recipient_wallet_hex: &str, slot: &str, blob: &str) -> Result<()>` — deposit `blob` into the recipient wallet's mailbox `slot`.
- `QueueClient::collect(&self, token: &str, wallet_hex: &str, slot: &str) -> Result<Vec<String>>` — drain one slot of your own mailbox.
- `wallet_hex(wallet: &WalletPublicKey) -> String` — lowercase hex of a compressed wallet key, the queue's mailbox key.

## How it fits

The engine resolves a recipient's queue endpoint from their signed record, then
uses this client to `deposit` a sealed blob keyed by their wallet (step 2 of the
delivery ladder). Your inbox uses `collect` to drain your own wallet's slots
from your queue.
