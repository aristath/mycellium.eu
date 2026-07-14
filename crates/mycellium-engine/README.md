# mycellium-engine

Platform-neutral local messaging behavior.

The engine owns contacts, cached signed records, anti-rollback checks, trust and
verification, conversations, groups, history, drafts, blocking, expiry, and the
sender-owned outbox. It operates through the `mycellium_core::storage::Storage`
trait and emits structured flow events.

It does not open sockets, call the registry, read environment variables, choose
filesystem paths, or render UI. Native orchestration belongs in
`mycellium-client`; concrete encrypted storage belongs in
`mycellium-storage`.

Persisted data that cannot be decoded is left in place, reported through
`take_diagnostics()`, and fails closed instead of being treated as empty state
that a later write could overwrite.
