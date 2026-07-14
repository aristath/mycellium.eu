# TODO

## Back up and restore the live registry

The live registry depends on one persistent volume. Add automated backups for:

- `registry.redb`
- `blobs/`

Take a consistent snapshot/export rather than copying a live database and blobs
independently. Store it in durable object storage and regularly prove a restore
into a clean registry instance.

Back up `MYCELLIUM_REGISTRY_RECOVERY_KEY` separately. Recovery-key rotation must
re-encrypt every recovery blob; replacing the key alone makes existing accounts
unrecoverable.

## Prove Reticulum production connectivity

Run Linux-to-Android and Linux-to-iOS delivery with unlocked clients on separate
real networks.

The test must prove:

- both clients can announce/reach their signed Reticulum destinations;
- payloads and ACKs do not traverse the registry;
- taking the recipient offline leaves the item pending only on the sender;
- restoring the recipient delivers exactly once.

## Configure verified HTTPS login links

Login email is deliberately code-only until release signing identities are
available. Configure Android App Links and Apple Universal Links for
`registry.mycellium.eu`, publish the platform association files, and set
`MYCELLIUM_REGISTRY_LOGIN_URL_TEMPLATE` only after both platforms verify the
HTTPS domain.

Do not use a custom URI scheme for production login tokens.

## Add optional mobile wake hints

Android and iOS suspend ordinary app networking. Direct delivery therefore
works while the recipient is reachable and remains pending on the sender when
the recipient app sleeps.

Add optional FCM/APNs wake hints that contain no sender, recipient, message, or
conversation data. A hint may wake the app so it can receive through Reticulum.
It must never carry or acknowledge a message.
