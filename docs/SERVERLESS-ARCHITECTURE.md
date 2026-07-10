# Serverless P2P Messaging Architecture

**Document Version:** 2.0  
**Date:** 2026-07-08  
**Status:** Hard Model Specification

---

## Executive Summary

Mycellium is not a server-backed messenger with decentralization features.

Mycellium is an edge-held messaging protocol: state lives with users, messages
wait with senders, and the network only helps peers find each other.

The hard serverless model is governed by one delivery law:

> A message is delivered peer-to-peer, or it is not delivered yet.

This architecture deliberately rejects infrastructure-mediated delivery.
Convenience features that require message custody, relays, push services,
hosted rendezvous, or always-on delivery servers are not core Mycellium.

Mycellium may still have a central registry for product account UX. That
registry may create accounts, reserve handles, authenticate recovery, store
encrypted wallet backups, and publish the latest signed public record. It must
not store, queue, relay, or route messages.

The goal is not to simulate WhatsApp without owning servers. The goal is to make
messaging behave like a direct human-to-human line. When the line cannot be
made, the message waits at the edge.

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

### 3.1 Direct Or Pending

Every outgoing message has one of these core states:

| State | Meaning |
|-------|---------|
| `pending` | The message exists only on the sender's device. |
| `connecting` | The sender is attempting to form a direct route. |
| `delivered` | The recipient accepted the message over a direct peer-to-peer path. |
| `failed` | The sender stopped retrying or the user cancelled delivery. |

There is no core `queued` state.

There is no core "stored for recipient by infrastructure" state.

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

### 3.3 Sender Responsibility

The sender's device owns pending delivery.

If Alice turns off every device before Bob is reachable, delivery waits. If Alice
has multiple devices, those devices may sync pending outbox state with each
other only through user-controlled, end-to-end-protected mechanisms. The core
protocol must not assume a third-party pending-message host.

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

### 4.4 Registry As Product Account UX

The registry is allowed because users need an account concept that can survive
device loss.

It may store:

- handle metadata
- authentication material for recovery
- account-bound encrypted wallet backup envelopes
- latest signed public peer record

It must not store:

- message plaintext
- message ciphertext for offline recipients
- sender outbox contents
- group sender keys
- device traffic keys

The client generates the wallet secret locally and uploads only an account-bound
encrypted wallet backup envelope. The backup key is derived from OPAQUE export
key material, not directly from a recovery secret, so a registry database leak is
not an offline recovery-secret oracle. Recovery authenticates with OPAQUE,
downloads the backup envelope, verifies the account metadata, decrypts it
locally, and adopts the recovered wallet on a fresh device.

Public registry lookup returns only the latest signed public peer record.
Encrypted wallet backups are private recovery material and must require
authenticated recovery. Recovery authentication must not send a long-lived
reusable password proof over the network: clients authenticate with OPAQUE, and
public deployments must use HTTPS. OPAQUE server setup material is sealed at
rest with the registry secret, so a database-only leak does not expose reusable
recovery credentials.

This creates two distinct kinds of continuity:

- account continuity: the service can let a user regain the handle/account
- cryptographic identity continuity: only possible if the wallet backup can be
  decrypted

If recovery rotates to a new wallet because the old wallet cannot be decrypted,
peers must see that as an identity change.

Registry account operations are state-machine operations, not generic writes:
registration start must bind registration finish to a handle and account id;
auth finish must produce a short-lived single-use token scoped to a purpose and
operation hash; record publication must authenticate before mutation; recovery
and wallet rotation must complete server-side before the client writes recovered
local identity state.

---

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
- `route unavailable`
- `retrying`
- `peer discovered, connection failed`
- `delivered`

### 5.3 Relays Are Outside The Core

Relays are not part of the hard serverless model.

A relay-assisted mode may exist as an explicit compatibility or degraded mode,
but using a relay means leaving the core model. Relays may be useful for testing,
migration, hostile networks, or user-selected convenience. They must not redefine
the protocol's delivery law.

Core Mycellium must remain understandable without relays:

> Direct route, or pending locally.

---

## 6. Non-Core Infrastructure

The following systems may exist in experiments, compatibility modes, migration
paths, or user-selected convenience layers. They are not core Mycellium.

| System | Why It Is Non-Core |
|--------|--------------------|
| Queue / mailbox | Third-party custody of messages for offline recipients. |
| Push service | Always-on infrastructure that wakes a peer on behalf of another peer. |
| Circuit relay | Third-party live message path. |
| TURN relay | Third-party live message path. |
| Hosted rendezvous | Standing service dependency for peer negotiation. |
| Message-carrying registry | Account UX is allowed; message custody is not. |
| Distributed message store | Message custody moved from one server to many peers. |
| Peer forwarding | Intermediary message custody or routing. |

These tools may still be valuable. They are simply not the hard model.

The hard model does not ask whether a server can read the message. It asks why a
server is required to carry it at all.

---

## 7. Security Model

### 7.1 What The Hard Model Protects

| Threat | Hard Model Response |
|--------|---------------------|
| Server seizure | No required message server exists. |
| Message custody demands | Messages wait on sender devices, not infrastructure. |
| Central message metadata | There is no central message path. |
| Central service outage | Discovery may degrade, but existing peer knowledge remains useful. |
| Server-side account control | Discovery records must be self-authenticating. |

### 7.2 What The Hard Model Does Not Magically Solve

| Problem | Reality |
|---------|---------|
| NAT traversal | Some peers will not be directly reachable. Messages remain pending. |
| Offline recipient | Delivery waits until sender and recipient can meet. |
| Sleeping sender | Pending delivery stops when all sender devices are offline. |
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
- no queue or mailbox is required

### 9.3 Direct Transport As The Core Path

Implement delivery over direct peer-to-peer connections.

Success means:

- no server sees message transport
- no relay is required for the core success path
- failed reachability leaves the message pending
- delivery receipt is produced only after recipient acceptance

### 9.4 Optional Modes Stay Labelled

If compatibility modes exist, they must be labelled as such.

Examples:

- relay-assisted mode
- queued legacy mode
- hosted rendezvous mode
- browser compatibility mode

They may be useful, but they do not define core Mycellium.

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
