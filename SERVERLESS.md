# Serverless P2P Messaging Architecture

Document version: 2.4  
Date: 2026-07-14  
Status: hard model specification

## Core law

> A message is delivered peer-to-peer, or it is not delivered yet.

Mycellium has no message server, mailbox, queue, push payload, delivery relay,
or server acknowledgement. If Bob cannot receive a message now, Alice keeps it
locally and retries later.

The registry exists for account UX and discovery of signed identity records. It
does not introduce live connections and it never carries message payloads.

## Identity

- A user has one stable protocol `user_id`, derived from the account wallet key.
- Handles and display names are non-unique labels.
- A user account may have several login identities: email now, phone/passkeys or
  other surfaces later.
- Exactly one device is active at a time.
- Device switching creates fresh device/message keys and publishes a new signed
  public record for the same user.
- Old devices keep local history readable but must stop sending, receiving, and
  retrying once they see that another device is active.

## Public records

A signed public record binds:

- stable `user_id`
- wallet public key
- display labels
- the one active device key
- the active device's signed Reticulum destination

The record contains no IP address, no socket address, no server route, and no
message data.

Reticulum destination is the device address. Any lower-level route used by
Reticulum is temporary transport plumbing, not Mycellium identity.

## Discovery

Discovery carries claims; it is not authority.

The registry can answer:

- "what is the current signed record for this `user_id`?"
- "store this account's current signed record"
- "store/recover the account identity root after authenticated login"

Clients still verify every returned record locally: signature, wallet-derived
user id, active device binding, freshness, and local trust policy.

Other discovery fabrics may also carry signed records later. None of them become
identity authority.

## Delivery

The sender builds a sealed delivery item and sends it to the recipient's active
Reticulum destination.

Delivery is complete only when the recipient active device returns an ACK signed
by that device and bound to:

- delivery id
- exact payload bytes
- recipient device key

If the sender cannot reach that Reticulum destination, the item remains pending
in the sender's encrypted local outbox.

There is no durable "queued on server" state.

## Local outbox

The local outbox is the offline primitive.

For pairwise messages, a pending item may retain the minimum local material
needed to reseal for the same user's replacement active device. That material is
encrypted locally and erased when the entry is delivered, failed, or cancelled.

Pending delivery does not move to a new device unless the user imports local
state through an explicit, protected backup/transfer.

## Registry responsibilities

Allowed:

- account ids
- login identity indexes
- one-time login/session tokens
- email login delivery
- encrypted account backup blobs
- registry-sealed recovery identity blobs
- signed public-record storage and lookup
- rate limits and expiry cleanup

Forbidden:

- message payloads
- message queues
- message relays
- delivery acknowledgements
- live connection introduction
- persistent device routes
- treating handles as unique identity

Current HTTP surface:

```text
GET  /users/{user_id}/record
POST /login/email/request
POST /login/confirm
PUT  /accounts/{account_id}/backup
GET  /accounts/{account_id}/backup
PUT  /accounts/{account_id}/recovery
GET  /accounts/{account_id}/recovery
PUT  /accounts/{account_id}/record
GET  /accounts/{account_id}/record
```

Protected endpoints use:

```text
Authorization: Bearer <session_token>
```

Login tokens and bearer sessions expire after 15 minutes. Creating a new session
revokes the previous session for that account.

Upload abuse ceilings:

```text
backup: 16 MiB
public record: 1 MiB
```

## Registry storage

The registry is a key-value/index service, not a relational source of truth.

Current backend:

- `redb` for metadata and indexes
- filesystem blobs for opaque account bytes and public-record bytes

Durable shape:

```text
metadata store = indexes and small operational facts
blob store     = opaque account bytes and signed public records
client         = creates protocol identity and device/message key material
```

`redb` is implementation infrastructure. The protocol depends on the storage
interface and signed-record semantics, not on `redb` specifically.

## Security reality

Compromise of the registry plus login/recovery channel can recover the account
identity, publish a replacement active device, impersonate the user, and receive
future messages after peers refresh the valid replacement record.

It still cannot decrypt existing local history, old messages, or pending outbox
items, because those live only on user devices.

Database/blob theft without the recovery master key cannot recover identity
roots.

## Product semantics

The UI must not fake delivery.

Useful states:

- saved locally
- connecting
- waiting for recipient
- delivered
- failed
- cancelled

"Sent" must not mean "uploaded to infrastructure." It should mean either saved
locally for delivery or accepted by the recipient active device.

## Final definition

Mycellium is a peer-to-peer messaging protocol where discovery is
non-authoritative, identity records are self-authenticating, messages remain
with the sender until a route to the recipient's active device exists, and no
Mycellium server stores, carries, acknowledges, or completes delivery.
