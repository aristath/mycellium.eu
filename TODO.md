# TODO

## Back up and restore the live registry

The live Bunny deployment currently depends on one persistent volume. Add an
automated backup of all durable registry state:

- `registry.redb`
- `blobs/`
- `rendezvous.key`

Take a consistent snapshot/export rather than copying a live database and blobs
independently. Store it in durable object storage and regularly prove a restore
into a clean registry instance. Back up `MYCELLIUM_REGISTRY_RECOVERY_KEY`
separately; putting it beside the encrypted recovery blobs defeats that
separation. Recovery-key rotation must re-encrypt every recovery blob; replacing
the key alone makes existing accounts unrecoverable.

## Prove production UDP source preservation

Bunny exposes a UDP Anycast endpoint, but its documentation does not explicitly
guarantee that the container sees each client's original source IP and port.
Test direct Linux-to-Android and Linux-to-iOS delivery with unlocked clients on
separate real networks. The test must prove that the observed mappings support
simultaneous QUIC hole punching and that payloads travel directly.

If the endpoint rewrites the source tuple, move rendezvous to infrastructure
that preserves it. Do not add a payload relay.

## Preserve rendezvous affinity when scaling

Live device presence is held only in the registry process that accepted the
QUIC control stream. The deployed registry must remain one instance until
multiple instances have deterministic device affinity, rendezvous sharding, or
a shared control-only presence coordinator. Two devices must always reach the
same introducer. No scaling mechanism may carry message payloads.

## Configure verified HTTPS login links

Login email is deliberately code-only until the release signing identities are
available. Configure Android App Links and Apple Universal Links for
`registry.mycellium.eu`, publish the platform association files, and set
`MYCELLIUM_REGISTRY_LOGIN_URL_TEMPLATE` only after both platforms verify the
HTTPS domain. Do not use a custom URI scheme for production login tokens.

## Add optional mobile wake hints

Android and iOS suspend ordinary app networking. Direct delivery therefore
works while the recipient is reachable and remains pending on the sender when
the recipient app sleeps.

Add optional FCM/APNs wake hints that contain no sender, recipient, message, or
conversation data. A hint may wake the app so it can establish the direct
connection; it must never carry or acknowledge a message, and direct delivery
must continue to work without the wake service. APNs background delivery is not
guaranteed, so the UI must preserve the same honest pending state.
