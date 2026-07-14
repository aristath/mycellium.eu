# mycellium-client

Reusable headless orchestration shared by native applications.

This crate composes `mycellium-core`, `mycellium-engine`, encrypted storage, the
registry client, and the Reticulum delivery runtime.

It provides:

- email login and registry sessions;
- identity creation and device-switch recovery;
- current signed-record publication and refresh by stable user id;
- one active device per account;
- Reticulum delivery and recipient-device ACK verification;
- sender-local pending delivery and outbox retries.

`DirectNetwork` reuses one Reticulum node for outbound and inbound delivery.
The registry is used only to refresh signed records. When delivery cannot reach
the recipient's signed Reticulum destination, `deliver_or_park` keeps the item
in the encrypted local outbox.

Pairwise entries retain encrypted sender-local resealing material only while
pending, allowing the same user's replacement active device to receive them.
That material is erased on every final state.

A connection card is the lowercase hexadecimal form of a wire-encoded
`SignedRecord`. Import verifies the record signature and identity binding before
it can become a contact.
