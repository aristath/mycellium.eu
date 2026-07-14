# mycellium-client

Reusable headless orchestration shared by native applications.

This crate composes `mycellium-core`, `mycellium-engine`, encrypted storage, and
the direct transport. It provides:

- email login and registry sessions
- identity creation and device-switch recovery
- current signed-record publication and refresh by stable user id
- one active device per account
- authenticated direct QUIC delivery and recipient-device ACK verification
- sender-local pending delivery and outbox retries

`DirectNetwork` reuses one libp2p QUIC swarm and UDP socket for authenticated
registry presence, simultaneous hole punching, and direct peer streams. The
registry only introduces live devices. When introduction or direct connection
fails, `deliver_or_park` keeps the delivery in the encrypted local outbox.
Pairwise entries retain encrypted sender-local resealing material only while
pending, allowing the same user's replacement active device to receive them;
that material is erased on every final state. Group sender keys are shared once
per active member device and re-shared before the first group message after a
device switch.

A connection card is the lowercase hexadecimal form of a wire-encoded
`SignedRecord`. Import verifies the record signature and identity binding before
it can become a contact.

The production registry default is `https://registry.mycellium.eu`. UI,
platform lifecycle, and OS secure-secret storage remain the responsibility of
the native shell.
