# Serverless P2P Messaging Architecture

**Document Version:** 2.3
**Date:** 2026-07-13
**Status:** Hard Model Specification

---

## Executive Summary

Mycellium is not a server-backed messenger with decentralization features.

Mycellium is an edge-held messaging protocol: identity, delivery state, and
messages live with users. The network only helps peers find each other.

The hard serverless model is governed by one delivery law:

> A message is delivered peer-to-peer, or it is not delivered yet.

This architecture deliberately rejects infrastructure-mediated delivery.
Message custody, payload relays, server queues, and server acknowledgements are
not part of Mycellium. A registry may introduce two live devices, but the
resulting connection and every application payload are device-to-device.

Mycellium may still have a central registry for product account UX. That
registry may create accounts, verify login identities, store registry-sealed
identity recovery material and opaque encrypted backups, publish signed public
records, and introduce live devices. Handles are display names, not unique
identities. The registry must not store, queue, relay, inspect, acknowledge, or
otherwise carry messages.

The goal is not to simulate WhatsApp without owning servers. The goal is to make
messaging behave like a direct human-to-human line. When the line cannot be
made, the sender keeps the delivery locally until a direct line exists.

---

## 1. The Three Laws

### 1.1 No Server In The Message Path

A Mycellium node may use the registry, cached peers, LAN discovery, QR exchange,
or another entry point to establish a direct connection. Discovery may depend
on a standing service. Message transport must not.

The current native clients use the registry to learn the current signed device
record and coordinate a live UDP hole punch. Once a direct authenticated
connection exists, the registry is not in that connection and does not carry a
single byte of the message protocol.

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
can make an identity, name, or device claim true.

All identity and device records must be self-authenticating and locally
verified. A temporary observed network mapping is not an identity claim. It is
accepted only as a short-lived connection candidate delivered over an
authenticated registry control stream and bound to the expected device key.

---

## 2. Core Architecture

```
        Registry introduction
       (current signed record +
        temporary UDP mappings)
                 |
                 v
        +------------------+
        |  Peer discovery  |
        |  signed records  |
        |  live mappings   |
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

Before a new delivery, Alice may refresh Bob's current signed record by Bob's
stable user id. If Bob is live, the registry may then provide both devices with
their temporary observed UDP mappings. Those operations are discovery, not
custody: they move signed public records and connection candidates, never
messages.

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

A pending outbox entry carries the ciphertext for one recipient device. For
pairwise deliveries it also retains the minimum plaintext needed to reseal for
the same user's replacement active device. Both are encrypted in the sender's
local store, and the resealing material is erased when the entry becomes
delivered, failed, or cancelled. The sender may retry, inspect, or cancel the
entry. A delivered entry is final only after the intended recipient device
signs an acknowledgement bound to:

- the delivery id
- the exact payload bytes
- the recipient device key

Final delivery records may be retained locally as user-visible truth. Retention
or compaction of those local records is product policy; it is not part of the
message protocol.

---

## 4. Discovery

### 4.1 Stable Identity, Temporary Route

A device has a stable cryptographic identity: its device key, represented on
the transport as a libp2p PeerId. An IPv4 address, IPv6 address, port, LAN
address, or NAT mapping is never a device identity.

The signed public record binds the stable user id to the one active device. It
contains the active device key and transport PeerId, but no persistent network
address.

### 4.2 Registry Introduction

The native clients use a BEP 55-style introduction pattern:

“BEP 55-style” describes the observed-endpoint exchange and coordinated
simultaneous connection. Mycellium does not use BitTorrent trackers, torrents,
or the BitTorrent payload protocol.

1. Each live device opens an authenticated QUIC control stream to the registry.
2. The registry verifies the bearer session, current signed active-device
   record, and QUIC PeerId.
3. The registry observes each device's temporary public UDP mapping.
4. Alice identifies Bob by stable user id and verifies Bob's current signed
   record locally.
5. Alice asks for Bob's active device. The registry sends Alice and Bob each
   other's observed mapping plus complementary simultaneous-dial roles.
6. Alice and Bob establish an authenticated direct QUIC connection.
7. The message and its recipient-device acknowledgement travel only over that
   direct connection.

The registry keeps live presence and observed mappings only in process memory.
It does not persist them. Its control protocol has no application-payload,
mailbox, delivery, or acknowledgement message type.

If either device is unavailable or the hole punch fails, the sealed item stays
in Alice's local outbox.

### 4.3 Current Record Lookup

The registry indexes a stable protocol user id to the account holding its
current signed public record. Clients may fetch that record before sending so a
device switch does not leave contacts targeting the retired device.

This lookup does not make the registry's answer true. The client verifies the
record signature, wallet-derived user id, sequence rules, and existing local
trust before replacing its cached record.

### 4.4 Other Discovery Fabrics

DHTs, LAN discovery, QR exchange, cached peers, or friend-of-friend gossip may
also carry signed records or connection candidates. They are alternative
discovery mechanisms, not message transports, and are not required by the
native-client path.

### 4.5 Discovery Is Not Naming Authority

Names and handles cannot be trusted merely because a DHT returned them.

A discovery result is valid only if its signatures, identity bindings, sequence
rules, and local trust policy verify.

The network can help a node find "a claim about Alice." It cannot prove "this is
Alice." Only the record's cryptographic identity binding and the user's local
trust decision can do that.

## 5. Reachability

### 5.1 The Hard Model Uses Direct Routes

The hard serverless model requires a direct peer-to-peer route for message
delivery.

If the sender cannot form a direct route to the recipient, the message remains
pending.

The current direct route is libp2p QUIC authenticated by the active device's
PeerId. Both devices reuse the same UDP socket for registry presence and the
simultaneous direct dial, which lets common NATs create the required mappings.
The registry coordinates the attempt but is not a relay.

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

### 5.3 Mycellium Has No Payload Relay Mode

Mycellium does not carry message payloads through a registry, hosted relay,
third-party forwarding service, or store-and-forward network. This is not an
automatic fallback, compatibility mode, or user-selectable delivery option.

Infrastructure may introduce two live devices and coordinate simultaneous hole
punching. It must stop at connection information. If the resulting direct path
cannot be formed, delivery remains pending on the sender:

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

Pairwise pending deliveries may be resealed locally for that same user's new
active device. Group senders share their current sender key once with each
active member device and re-share it before the first group message after a
device switch. Receiving that authenticated replacement share removes the old
device's sender key for the same user.

A handle is not unique and is not identity. It is display metadata.

Clients must therefore key contacts, conversations, trust decisions, and
pending delivery targets by stable user identity. A handle may label those
records for people, but must never select or merge them internally.

The registry may authenticate access to an account and hold the protocol
identity root needed for account recovery. The identity root is created by the
client, sent only through authenticated HTTPS, encrypted before persistent
storage with a registry master key, and never shown to the user. It is
write-once for an account: device switching recovers it but cannot replace it.

On a new device, the user proves account access through any supported login
identity, recovers the same protocol identity root, creates fresh device keys,
and publishes an updated signed record. Old device keys, message keys, local
history, and pending messages are not copied.

This is an explicit account-UX trust boundary. Control of a login identity can
recover the protocol identity through the registry. Compromise of the running
registry or its recovery master key can do the same. An attacker with that
access can publish a fresh active device, impersonate the account, and receive
future messages after contacts refresh the valid replacement record. Theft of
the database and blobs without the recovery master key cannot recover the
identity.

Account recovery does not reveal old device keys, message keys, local history,
or pending messages. The replaced device detects that the registry's current
record names another device. It keeps its local history visible but disables
sending, receiving, and outbox retries until the user logs in and intentionally
makes it active again.

### 6.2 Registry Storage Shape

The registry storage model is key-value plus secondary indexes. It should not
depend on complex relational joins.

The registry needs searchable indexes for:

- `account_id` to account metadata
- stable protocol `user_id` to `account_id`
- login identity hash to `account_id`
- login token hash to login attempt and expiry
- `account_id` to current signed public record pointer
- `account_id` to opaque encrypted account-backup pointer
- `account_id` to registry-sealed recovery identity pointer
- rate-limit keys to counters and expiry

Opaque per-user data lives outside the metadata store as content-addressed
blobs. The current filesystem layout shards by the first nine characters of the
32-character account id and then uses the full account id:

```text
blobs/users/876/128/736/<full-account-id>/<kind>-<sha256>.data
```

These blobs hold generic encrypted backups, registry-sealed recovery material,
and current signed public records. They are not a substitute for indexes. Login
by email, phone, passkey, or a future identity still requires a fast lookup from
that login identity to `account_id`.

The registry should be written behind a small storage interface. SQLite,
Postgres, embedded key-value stores, distributed key-value stores, and object
storage can all satisfy the model if they preserve the same record semantics.

The durable rule is:

```text
metadata store = indexes and small operational facts
blob/file store = opaque account bytes and signed public records
client = creates protocol identity and device/message key material
```

The metadata store is operational infrastructure. It is not protocol authority.
Signed records still verify locally.

### 6.3 Current Registry Backend

The registry uses `redb` for metadata.

Why:

- native Rust
- embedded, with no separate database service
- ACID transactions
- crash-safe storage
- ordered key-value tables that fit registry records and indexes
- simple enough to inspect, back up, restore, and replace

The registry code must still depend on a small `RegistryStore` interface, not on
`redb` as protocol doctrine. The backend is replaceable infrastructure.

### 6.4 Current Registry Surface

The registry exposes account UX and live device introduction:

```text
GET  /rendezvous
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

Protected endpoints use a bearer session:

```text
Authorization: Bearer <session_token>
```

`GET /rendezvous`, both public-record `GET` routes, and both login routes are
public. Backup and recovery routes and `PUT /accounts/{account_id}/record`
require the account's bearer session.

`/login/email/request` returns `202 Accepted` and sends the one-time token
through the configured email sender. The token is not returned in the HTTP
response. Login tokens and bearer sessions both expire after 15 minutes. A new
session immediately revokes the previous session for that account.
Email login requests are limited to five per normalized email hash in each
15-minute window, with separate generous source-address ceilings to prevent
one source from bypassing that guard with many addresses.

Current upload limits are abuse guards:

```text
backup: 16 MiB
public record: 1 MiB
```

The registry binary is configured by:

```text
MYCELLIUM_REGISTRY_BIND
MYCELLIUM_REGISTRY_RENDEZVOUS_BIND
MYCELLIUM_REGISTRY_RENDEZVOUS_PUBLIC_ADDR
MYCELLIUM_REGISTRY_DATA_DIR
MYCELLIUM_REGISTRY_RECOVERY_KEY
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT
MYCELLIUM_REGISTRY_EMAIL_FROM
MYCELLIUM_REGISTRY_BREVO_API_KEY
MYCELLIUM_REGISTRY_BREVO_ENDPOINT
MYCELLIUM_REGISTRY_SMTP_HOST
MYCELLIUM_REGISTRY_SMTP_PORT
MYCELLIUM_REGISTRY_SMTP_USERNAME
MYCELLIUM_REGISTRY_SMTP_PASSWORD
MYCELLIUM_REGISTRY_EMAIL_SUBJECT
MYCELLIUM_REGISTRY_LOGIN_URL_TEMPLATE
```

`MYCELLIUM_REGISTRY_RECOVERY_KEY` is a required 32-byte key encoded as 64
hexadecimal characters. It must be stored separately from the registry data and
backed up: losing it makes account recovery blobs unreadable.

The Linux client logs in before creating or recovering an identity. It checks
the account's signed public record on startup and every minute. If another
device is active, it keeps local history visible but disables sending,
receiving, and outbox retries until the user logs in and intentionally makes
the local device active again. Its bearer session is stored only inside the
device's encrypted local store and is unavailable before local unlock.

`MYCELLIUM_REGISTRY_EMAIL_TRANSPORT` must be explicit. `log` is for local
development. `smtp` sends through a generic SMTP server. `brevo` sends through
Brevo's HTTPS transactional email API, which is useful on hosts that block
outbound SMTP ports. Email delivery remains registry account UX, not protocol
message delivery.

Login emails contain the one-time code and no clickable link by default.
`MYCELLIUM_REGISTRY_LOGIN_URL_TEMPLATE` is optional and must contain exactly
one `{token}` placeholder. A production link must be a verified HTTPS App
Link/Universal Link; an unverified custom URI scheme can be claimed by another
application and is not an acceptable production login channel.

`GET /rendezvous` publishes the registry's stable, self-authenticating QUIC
multiaddr. The separate `/mycellium/rendezvous/1.0` QUIC control protocol
registers the current live device and coordinates direct hole punching. It
accepts no application payload.

Rendezvous frames are a four-byte big-endian length followed by a
`mycellium_core::wire` value, with a 1 MiB abuse ceiling. Devices send
`Register { session_token, device }` and `Introduce { device }`. The registry
answers with `Registered`, `Connect { device, address, role }`, `Unavailable`,
or `Rejected`. `address` is an ephemeral observed UDP mapping, never stored in
a public record or treated as identity.

Live presence is process-local and intentionally not persisted. The current
deployment must therefore run exactly one registry process. Multiple processes
require deterministic rendezvous affinity or a shared presence coordinator so
both devices meet at the same introducer. Such coordination may carry only
presence and introduction control, never message payloads.

The UDP endpoint must preserve each client's source IP and port. A load balancer
that rewrites that observed tuple makes simultaneous punching unusable and is
not an acceptable rendezvous endpoint. The solution is infrastructure that
preserves the tuple, not a payload relay.

This surface does not change the delivery law. It publishes account data and
signed records and introduces live devices. It does not store, queue, relay,
route, or acknowledge messages.

Expired login tokens, sessions, and rate-limit buckets have ordered expiry
indexes and are drained in bounded transactions. Concurrent blob publication
advances metadata with compare-and-swap and removes only the exact pointer it
successfully displaced; it never sweeps another writer's unpublished blob.

---

## 7. Security Model

### 7.1 What The Hard Model Protects

| Threat | Hard Model Response |
|--------|---------------------|
| Server seizure | No message server exists; the registry contains no message payloads or history. |
| Message custody demands | Messages wait on the sender's active device, not infrastructure. |
| Central message custody | There is no central message path or message database. |
| Registry outage | Existing direct connections remain usable; new introductions wait and messages remain local. |
| False discovery records | Clients verify identity bindings, signatures, freshness, and local trust. |

### 7.2 What The Hard Model Does Not Magically Solve

| Problem | Reality |
|---------|---------|
| Offline recipient | Delivery waits until sender and recipient can meet. |
| Sleeping sender | Pending delivery stops when the sender's active device is offline. |
| Sybil attacks | DHT participation needs local trust, rate limits, and record validation. |
| Metadata leakage | The registry observes temporary UDP mappings and introduction timing, but no payloads. |
| Registry or login compromise | An attacker can replace the active device and impersonate the account, but cannot decrypt existing local messages. |
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
- allow out-of-band signed-record exchange

### 8.3 Usability Adapts To Serverlessness

The hard model does not preserve every convenience of server-backed messaging.

That is acceptable.

Mycellium's promise is not instant delivery through hidden infrastructure. Its
promise is user-held state, direct delivery, and no required message custodian.

---

## 9. Implementation Direction

### 9.1 Authenticated Introduction

Discovery carries self-authenticating records and temporary connection
candidates. The registry introduction service is the native-client discovery
path.

Success means:

- records verify locally
- stable user ids resolve current active-device records
- IPv4, IPv6, ports, and NAT mappings never become identity
- two live devices can form a direct authenticated QUIC connection
- discovery failure leaves existing local contacts and messages intact
- no application payload can enter the registry protocol

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
- no payload-relay path exists
- failed reachability leaves the message pending
- delivery receipt is produced only after recipient-device acceptance

### 9.4 No Hidden Fallback

A failed direct connection must not fall back to a relay or server queue. A
transport that carries payload through a third party is not Mycellium delivery.

### 9.5 Registry Account UX

If a registry exists, success means:

- account IDs are stable and unique
- login identities are pluggable
- handles remain non-unique display names
- `redb` is the current embedded metadata backend
- registry storage is modeled as portable key-value records plus indexes
- opaque account bytes can live in file/blob storage
- registry HTTP stays limited to account UX, signed-record lookup, and
  rendezvous discovery
- the registry QUIC protocol carries only presence and introduction control
- removing the registry does not invalidate local identity, local state, or an
  already-established direct connection; a new connection then needs another
  discovery mechanism

---

## 10. Final Definition

Hard serverless Mycellium is:

> A peer-to-peer messaging protocol where discovery is non-authoritative,
> identity records are self-authenticating, messages remain with the sender until
> a direct route to the recipient exists, and no server stores, carries,
> acknowledges, or completes delivery.

Anything that stores or carries a message for an offline recipient is outside the
core model.

Infrastructure may be required to discover or introduce live devices. It must
never become a payload path or a condition for an already-established direct
connection to continue.

Anything that can be removed without invalidating identity, local state, or
direct delivery may be useful infrastructure. It is not the protocol.

---

*Document ends.*
