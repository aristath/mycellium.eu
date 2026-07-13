# Serverless P2P Messaging Architecture

**Document Version:** 2.1  
**Date:** 2026-07-10  
**Status:** Hard Model Specification

---

## Executive Summary

Mycellium is not a server-backed messenger with decentralization features.

Mycellium is an edge-held messaging protocol: identity, delivery state, and
messages live with users. The network only helps peers find each other.

The hard serverless model is governed by one delivery law:

> A message is delivered peer-to-peer, or it is not delivered yet.

This architecture deliberately rejects infrastructure-mediated delivery.
Convenience features that require message custody, relays, push services,
hosted rendezvous, or always-on delivery servers are not core Mycellium.

Mycellium may still have a central registry for product account UX. That
registry may create accounts, verify login identities, store encrypted wallet
backups, and publish signed public records. Handles are display names, not
unique identities. The registry must not store, queue, relay, or route messages.

The goal is not to simulate WhatsApp without owning servers. The goal is to make
messaging behave like a direct human-to-human line. When the line cannot be
made, the sender keeps the delivery locally until a direct line exists.

---

## 1. The Three Laws

### 1.1 No Required Server

A Mycellium node may use a bootstrap hint, cached peers, LAN discovery, QR
exchange, a registry record lookup, or any other entry point, but the
message protocol must not depend on a standing service.

A bootstrap node may help a peer enter the graph. A registry may improve account
UX. Neither may be required for message delivery or conversation continuity.

### 1.2 No Third-Party Message Custody

If Bob is offline, Alice keeps the message.

Not a queue. Not a mailbox. Not a hosted relay. Not a distributed storage layer
pretending not to be infrastructure.

Delivery resumes when Alice and Bob can form a peer-to-peer path.

### 1.3 No Authority in Discovery

Discovery is a transport for claims. It is not the source of truth.

DHT records, bootstrap responses, peer gossip, cached addresses, QR imports, and
manual configuration may all help a node find another node. Registry record
responses are the same kind of thing: carriers for signed claims. None of them
can make an identity, name, device, or reachability claim true.

All identity and reachability records must be self-authenticating and locally
verified.

---

## 2. Core Architecture

```
        Optional bootstrap hint
       (seed, QR, cached peer,
        LAN, manual address)
                 |
                 v
        +------------------+
        |  Peer discovery  |
        |  DHT / gossip /  |
        |  cached records  |
        +------------------+
                 |
                 v
+----------------+                 +----------------+
|    Alice       |  direct P2P     |      Bob       |
| local identity |<--------------->| local identity |
| local outbox   |  E2E payloads   | local store    |
+----------------+                 +----------------+

If no direct path exists:

+----------------+
|    Alice       |
| local outbox   |  message remains pending locally
+----------------+
```

The network helps Alice discover Bob. It does not carry the message for Bob.

The message leaves Alice's custody only when Alice can deliver it directly to
Bob.

---

## 3. Delivery Semantics

### 3.1 Direct Or Local

Every outgoing device-copy has one of these core states:

| State | Meaning |
|-------|---------|
| `pending` | The sealed delivery item exists only on the sender's device and may be retried. |
| `connecting` | The sender is attempting to form a direct route. This may be an ephemeral runtime state, not a durable record. |
| `delivered` | The recipient device accepted the exact payload over a direct peer-to-peer path and returned a valid ACK. |
| `failed` | The sender concluded this delivery item is no longer retryable. |
| `cancelled` | The user explicitly stopped retrying this local delivery item. |

There is no core `queued` state.

There is no core "stored for recipient by infrastructure" state.

Only `pending` items are retried. `delivered`, `failed`, and `cancelled` are
local facts about the sender's own delivery responsibility; they do not imply
that any server learned, stored, or routed the message.

### 3.2 Offline Delivery Means Delayed Edge Delivery

Offline delivery does not mean a server stores a message until the recipient
returns.

Offline delivery means:

1. Alice writes the encrypted message into Alice's local outbox.
2. Alice retries discovery and connection according to local policy.
3. Bob receives the message when both peers are online and reachable.
4. Until then, the message remains Alice's responsibility.

This is less convenient than hosted asynchronous messaging, and that is an
intentional trade.

If Alice has a stale address for Bob, retry may refresh Bob's signed discovery
record and try again. That refresh is still discovery, not custody: it moves only
self-authenticating records, not messages.

### 3.3 Sender Responsibility

The sender's active device owns pending delivery.

If Alice turns off her active device before Bob is reachable, delivery waits.
Switching devices replaces the active device. Pending delivery does not move to
the new device unless Alice explicitly imports local state through a
user-controlled, end-to-end-protected backup or transfer. The core protocol must
not assume a third-party pending-message host.

### 3.4 Local Outbox

The local outbox is the offline primitive. It is sender-owned delivery state, not
a network service.

A pending outbox entry carries the already-sealed payload for one recipient
device. The sender may retry it, inspect it, or cancel it. A delivered entry is
final only after the intended recipient device signs an acknowledgement bound to:

- the delivery id
- the exact payload bytes
- the recipient device key

Final delivery records may be retained locally as user-visible truth. Retention
or compaction of those local records is product policy; it is not part of the
message protocol.

---

## 4. Discovery

### 4.1 DHT As Discovery Fabric

The DHT is the preferred network-scale discovery fabric.

It may store and return:

- signed identity records
- signed device records
- signed reachability records
- peer addresses
- bootstrap peer sets

The DHT does not decide whether a record is valid. The receiving node verifies
the record locally.

Retry may use the DHT to refresh a stale peer record after a failed direct
connection. The DHT still carries only signed claims. It never receives the
pending message.

### 4.2 Bootstrap Is Ignition

A bootstrap peer answers one question:

> Here are some peers to try.

That is all.

A bootstrap peer must not:

- store messages
- route messages
- authorize identities
- own names
- decide account recovery
- decide which record is canonical
- be required after a node has joined the graph

Bootstrap can be replaced by any other discovery entry point: QR exchange,
manual address exchange, LAN discovery, cached peers, imported peer packs, or
friend-of-friend gossip.

### 4.3 Discovery Is Not Naming Authority

Names and handles cannot be trusted merely because a DHT returned them.

A discovery result is valid only if its signatures, identity bindings, sequence
rules, and local trust policy verify.

The network can help a node find "a claim about Alice." It cannot prove "this is
Alice."

## 5. Reachability

### 5.1 The Hard Model Uses Direct Routes

The hard serverless model requires a direct peer-to-peer route for message
delivery.

If the sender cannot form a direct route to the recipient, the message remains
pending.

### 5.2 NAT Failure Is A Real State

NATs, firewalls, captive networks, browser sandboxes, and sleeping devices are
not abstract implementation details. They are real reachability constraints.

The user experience must expose that truth instead of hiding it behind a queue.

Examples:

- `waiting for peer`
- `saved locally`
- `connecting`
- `route unavailable`
- `retrying`
- `peer discovered, connection failed`
- `discovery refreshed`
- `delivered`

### 5.3 Relays Are Outside The Core

Relays are not part of the hard serverless model.

A relay-assisted mode may exist as an explicit compatibility or degraded mode,
but using a relay means leaving the core model. Relays may be useful for testing,
migration, hostile networks, or user-selected convenience. They must not redefine
the protocol's delivery law.

Core Mycellium must remain understandable without relays:

> Direct route, or pending locally.

## 6. Registry And Account Identity

### 6.1 Account Model

The registry may provide account UX. It is not protocol identity authority.

A registry account has:

- `account_id`: a unique registry account identifier
- `login_identities`: ways to prove account access, such as email magic links,
  phone OTP, passkeys, biometrics, or future platform auth
- `protocol_identity`: the Mycellium cryptographic identity root
- `active_device`: the one installed app/device currently authorized under that
  protocol identity
- `handles`: non-unique user-readable display names

Email is only the first login surface. It is not essential to the model and must
not be baked into record validity.

A user account may have multiple login identities. Adding phone, passkeys,
biometrics, or future authentication methods should not change the protocol
identity model.

A user account has one active device at a time. Device switching is supported by
publishing a new signed record that replaces the previous active device.

A handle is not unique and is not identity. It is display metadata.

The registry may authenticate access to an account and store an encrypted wallet
backup. It must not store raw keys. Key material should be created or decrypted
by the client, with the user never needing to see it.

On a new device, the user proves account access through any supported login
identity, downloads the encrypted backup, decrypts it locally, creates fresh
device keys, and publishes an updated signed record.

### 6.2 Registry Storage Shape

The registry storage model is key-value plus secondary indexes. It should not
depend on complex relational joins.

The registry needs searchable indexes for:

- `account_id` to account metadata
- login identity hash to `account_id`
- login token hash to login attempt and expiry
- `account_id` to current signed public record pointer
- `account_id` to encrypted wallet backup pointer
- rate-limit keys to counters and expiry

Opaque per-user data may live outside the metadata store as one account bundle
or as versioned blobs. For example:

```text
users/876/128/736/account.data
```

That bundle may contain encrypted backups, signed record snapshots, device-list
snapshots, and export data. It is not a substitute for indexes. Login by email,
phone, passkey, or future identity still requires a fast lookup from that login
identity to `account_id`.

The registry should be written behind a small storage interface. SQLite,
Postgres, embedded key-value stores, distributed key-value stores, and object
storage can all satisfy the model if they preserve the same record semantics.

The durable rule is:

```text
metadata store = indexes and small operational facts
blob/file store = opaque encrypted account bytes
client = creates, decrypts, and owns key material
```

The metadata store is operational infrastructure. It is not protocol authority.
Signed records still verify locally.

### 6.3 Preferred First Registry Backend

The first embedded metadata backend should be `redb`.

Why:

- native Rust
- embedded, with no separate database service
- ACID transactions
- crash-safe storage
- ordered key-value tables that fit registry records and indexes
- simple enough to inspect, backup, and replace

`fjall` is the larger/write-heavy Rust-native candidate. It may become useful if
the registry needs LSM-tree behavior, compression, or heavier sustained writes.

RocksDB is a battle-tested fallback if the project needs mature LSM behavior
more than native Rust.

`sled` should not be used for the registry core. Registry storage is
reliability-sensitive, and novelty is not useful there.

The registry code must still depend on a small `RegistryStore` interface, not on
`redb` as protocol doctrine. The backend is replaceable infrastructure.

### 6.4 Current Registry Surface

The current development registry exposes only account UX:

```text
POST /login/email/request
POST /login/confirm
PUT  /accounts/{account_id}/backup
GET  /accounts/{account_id}/backup
PUT  /accounts/{account_id}/record
GET  /accounts/{account_id}/record
```

Protected endpoints use a bearer session:

```text
Authorization: Bearer <session_token>
```

`/login/email/request` currently returns a `dev_token` directly. That is a
development placeholder until a real email sender exists.

Current upload limits are deliberately small:

```text
backup: 16 MiB
public record: 1 MiB
```

The registry binary is configured by:

```text
MYCELLIUM_REGISTRY_BIND
MYCELLIUM_REGISTRY_DATA_DIR
```

This HTTP surface does not change the delivery law. It publishes and retrieves
account data and signed records. It does not store, queue, relay, or route
messages.

---

## 7. Security Model

### 7.1 What The Hard Model Protects

| Threat | Hard Model Response |
|--------|---------------------|
| Server seizure | No required message server exists. |
| Message custody demands | Messages wait on the sender's active device, not infrastructure. |
| Central message metadata | There is no central message path. |
| Central service outage | Discovery may degrade, but existing peer knowledge remains useful. |
| Server-side account control | Discovery records must be self-authenticating. |

### 7.2 What The Hard Model Does Not Magically Solve

| Problem | Reality |
|---------|---------|
| Offline recipient | Delivery waits until sender and recipient can meet. |
| Sleeping sender | Pending delivery stops when the sender's active device is offline. |
| Sybil attacks | DHT participation needs local trust, rate limits, and record validation. |
| Metadata leakage | Peers and discovery nodes may observe addresses and timing. |
| Browser limitations | Browser peers need browser-native P2P mechanisms or remain constrained. |

The hard model chooses honesty over hidden infrastructure.

---

## 8. Product Semantics

### 8.1 No Fake Sent State

The UI must not imply that a message has left the sender's responsibility when it
has merely entered a server queue.

In the hard model, "sent" should mean one of two explicit things:

- saved locally for delivery
- delivered to the recipient

Anything between those states should be visible as pending work.

### 8.2 Pending Is Normal

Pending messages are not errors. They are the natural consequence of a protocol
that refuses third-party custody.

The product should make pending feel calm and legible:

- show which peer is unreachable
- show whether discovery succeeded
- show whether connection attempts are active
- allow user cancellation
- allow manual retry
- allow out-of-band address exchange

### 8.3 Usability Adapts To Serverlessness

The hard model does not preserve every convenience of server-backed messaging.

That is acceptable.

Mycellium's promise is not instant delivery through hidden infrastructure. Its
promise is user-held state, direct delivery, and no required message custodian.

---

## 9. Implementation Direction

### 9.1 Discovery First

Implement self-authenticating records over a DHT or equivalent peer-discovery
fabric.

Success means:

- a new node can join through any known peer
- records verify locally
- cached peers can replace the original bootstrap path
- discovery failure does not invalidate existing local contacts

### 9.2 Local Outbox As The Offline Primitive

Implement durable sender-side pending delivery.

Success means:

- outgoing messages survive restart
- retry policy is local and inspectable
- delivery state is explicit
- only pending entries retry
- no queue or mailbox is required

### 9.3 Direct Transport As The Core Path

Implement delivery over direct peer-to-peer connections.

Success means:

- no server sees message transport
- no relay is required for the core success path
- failed reachability leaves the message pending
- delivery receipt is produced only after recipient-device acceptance

### 9.4 Optional Modes Stay Labelled

If compatibility modes exist, they must be labelled as such.

Examples:

- relay-assisted mode
- queued legacy mode
- hosted rendezvous mode
- browser compatibility mode

They may be useful, but they do not define core Mycellium.

### 9.5 Registry Account UX

If a registry exists, success means:

- account IDs are stable and unique
- login identities are pluggable
- handles remain non-unique display names
- `redb` is the preferred first embedded metadata backend
- registry storage is modeled as portable key-value records plus indexes
- opaque account bytes can live in file/blob storage
- registry HTTP stays limited to account UX and signed-record publication
- removing the registry does not break existing local identity or direct delivery

---

## 10. Final Definition

Hard serverless Mycellium is:

> A peer-to-peer messaging protocol where discovery is non-authoritative,
> identity records are self-authenticating, messages remain with the sender until
> a direct route to the recipient exists, and no server is required to store,
> route, authorize, or complete delivery.

Anything that stores or carries a message for an offline recipient is outside the
core model.

Anything that becomes required for delivery is outside the core model.

Anything that can be removed without invalidating identity, local state, or
direct delivery may be useful infrastructure. It is not the protocol.

---

*Document ends.*
