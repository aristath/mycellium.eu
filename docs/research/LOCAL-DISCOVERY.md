# Native local-network (LAN) discovery

*Design for issue [#62](https://github.com/aristath/messe/issues/62) (parent
[#48](https://github.com/aristath/messe/issues/48)). Research/design only — no
code changes accompany this document.*

*Related: first-contact verification [#57](https://github.com/aristath/messe/issues/57),
direct-P2P reachability [#59](https://github.com/aristath/messe/issues/59),
reachability scoring [#60](https://github.com/aristath/messe/issues/60).*

---

## TL;DR / recommendation

Add **optional, opt-in** local-network peer discovery so two native devices on
the same LAN can find a direct address for each other **without** consulting the
directory (for presence/address) or the queue (for delivery). This is faster,
works on an offline or captive network, and keeps that message exchange off
shared services entirely.

The recommendation:

- **Mechanism:** enable **libp2p-mdns** behind a new, off-by-default
  `mdns` Cargo feature *and* a runtime toggle. Do **not** build a bespoke UDP
  beacon first — mDNS/DNS-SD is a solved, interoperable protocol and libp2p
  already speaks it; a custom beacon is only worth it if we later need
  contact-recognition without a connection attempt (see §Privacy).
- **Trust:** a discovery hit is a **hint, nothing more**. It never bypasses
  cryptographic verification. The discovered address is dialed with the existing
  Noise-authenticated libp2p transport, and the connection is only *trusted*
  once the remote's **device key is found inside a wallet-signed
  [`Record`](../../crates/mycellium-core/src/record.rs) that we already pin/verify**
  (TOFU from #57). A LAN attacker who advertises a bogus identity simply matches
  no pinned contact and is dropped.
- **Privacy:** mDNS **broadcasts presence to the whole LAN**. That is a real
  leak (someone runs Mycellium here, and — if the advertised id is stable —
  the same someone across networks). Mitigate with: **off by default**,
  advertise **no handle/name/wallet** in the clear, use a **rotating ephemeral
  local id** rather than a stable one, and keep the whole thing **LAN-scoped**
  with a clear UX switch. A conservative build may restrict discovery to
  **already-known contacts only**.

Everything below expands on and justifies these choices.

---

## 1. Background: how native peers connect today

A peer is described by a self-certifying, **wallet-signed**
[`SignedRecord`](../../crates/mycellium-core/src/record.rs). Its body lists one
or more `Device`s, and each device carries:

- `device_key` — the device's Ed25519 key, its stable identifier and the basis
  of the libp2p `PeerId` (Layer 8.1);
- `peer_id` — *where to reach it*: either a raw `host:port` (framed TCP) or a
  libp2p multiaddr `/ip4/…/tcp/…/p2p/<peer-id>`;
- `id_key` + `signed_pre_key` — the messaging keys for X3DH.

The account's **single wallet signature covers the entire record**, including
every device's `peer_id` and keys, so a dishonest directory can withhold or
stale a record but can never forge one ([`SignedRecord::verify`](../../crates/mycellium-core/src/record.rs)).

Reaching a peer today is a two-step affair:

1. **Address** comes from the directory: `lookup(handle) → SignedRecord`, plus a
   `presence(handle)` query to see whether they are online.
2. **Connection** is opened to the `peer_id` in the record. The production line
   is [`libp2p_net`](../../crates/mycellium-transport/src/libp2p_net.rs): TCP +
   **Noise** + Yamux, running a `/mycellium/1.0` byte-stream protocol. The dial
   requires a `/p2p/<peer-id>` component, and the **Noise handshake authenticates
   that the remote actually holds the secret for that `PeerId`** — i.e. the
   remote proves it is the advertised device key, not merely at the advertised
   address.

The engine's delivery ladder ([`app::messaging::deliver`](../../crates/mycellium-engine/src/app/messaging.rs))
is: *check directory presence → if online, connect and push the sealed item
live → else deposit into the recipient's queue → else park it in the local
encrypted [`outbox`](../../crates/mycellium-engine/src/outbox.rs) and retry.*

**libp2p is pulled deliberately trimmed.** In
[`mycellium-transport/Cargo.toml`](../../crates/mycellium-transport/Cargo.toml)
we set `default-features = false` and enable only
`["tokio", "tcp", "noise", "yamux", "macros", "ed25519"]`, with a comment
noting we drop libp2p's DNS/mDNS/QUIC/UPnP to keep the native build and audit
surface small. Re-enabling `mdns` for this feature is a conscious, scoped
re-expansion of that surface, which is why it belongs behind its own flag.

### What LAN discovery replaces

On a shared LAN, step 1 (directory lookup + presence) is exactly what we want to
avoid: it is a round trip to a shared service, it leaks a lookup/presence query,
and it does not work if the network has no internet. If both devices are on the
same link, they can find each other's *address* locally and skip straight to
step 2. Crucially, **step 2 is unchanged** — the same Noise-authenticated dial,
the same record-based trust decision. Discovery only supplies a candidate
address.

---

## 2. Goals and non-goals

**Goals**

- Two native devices on the same LAN discover a usable **direct** endpoint for
  each other without a directory address lookup or presence query.
- Discovery is **minimal and authenticated before trust** — a hint that feeds
  the existing verification path, never a shortcut around it.
- The feature is **opt-in** and **disableable** for hostile networks.
- Co-located devices can exchange messages with **no internet**, given they
  already hold each other's keys.

**Non-goals**

- Not a replacement for the directory/queue — it is a co-located fast path with
  a fallback.
- **No anonymity claim.** mDNS is a broadcast protocol; discovery *reveals*
  presence on the local link. This document is explicit about that trade-off; it
  does not try to hide it.
- Not internet-wide peer discovery, DHT, or rendezvous (that is the NAT-traversal
  work in #59). This is link-local only.
- Not a new trust root. Discovery must compose with existing wallet-signed
  records + TOFU pinning (#57) and safety numbers, never weaken them.

---

## 3. Mechanism: libp2p-mdns vs a bespoke UDP beacon

Both approaches answer *"what native peers are on this link, and at what
address?"* by sending to a multicast group and listening for others. They differ
in maturity, footprint, and how much control we have over the advertised bytes.

### Option A — libp2p mDNS (`libp2p::mdns`)

libp2p ships an mDNS/DNS-SD behaviour. Enabling the `mdns` feature adds it as a
`NetworkBehaviour`; it periodically multicasts a DNS-SD service record for the
local node and emits `Discovered(PeerId, Multiaddr)` events for peers it hears.
Those feed **directly** into the swarm we already run in
[`libp2p_net`](../../crates/mycellium-transport/src/libp2p_net.rs).

- **What it advertises by default:** the node's libp2p **`PeerId`** and its
  listen **multiaddrs** (`/ip4/…/tcp/…`). The `PeerId` is derived from the
  **device key** — so out of the box this **broadcasts a stable device
  identifier**, which is the tracking concern in §5.
- **Pros:** almost no new code — a behaviour toggle and wiring `Discovered`
  events into a candidate-address channel. Interoperable, well-tested, IPv4+IPv6.
  Discovered peers arrive already typed as `(PeerId, Multiaddr)`, exactly the
  shape our dialer wants.
- **Cons:** re-expands the trimmed libp2p feature set (mDNS pulls its own
  multicast/socket code). The default advertisement leaks the stable device
  `PeerId`; controlling *what* is broadcast means either accepting that or
  running mDNS under a **rotating, ephemeral libp2p keypair** distinct from the
  real device key (see §5), which complicates the "the PeerId is the device
  key" invariant.

### Option B — bespoke UDP multicast beacon

A small hand-rolled service: multicast a compact datagram on a well-known group
(e.g. `239.x.x.x:port` / an IPv6 link-local group) carrying a minimal, versioned
payload, and listen for others.

- **What it advertises:** entirely our choice — precisely the fields in §4 and
  nothing else. This is the main reason to consider it.
- **Pros:** total control over advertised bytes, framing, and rotation cadence;
  no new libp2p features; can carry a **rotating opaque token** that only known
  contacts can recognize (contact-scoped discovery) without ever emitting a
  stable id. Trivial to keep `no_std`-friendly / port to constrained shells.
- **Cons:** we own a network protocol — multicast socket setup, cross-platform
  quirks (interface selection, IPv6 scope ids, some OSes/APs filter multicast),
  reboot/duplicate handling, and rate control. It reinvents a slice of DNS-SD.
  More code and more test/audit surface than a behaviour toggle.

### Verdict

Start with **Option A (libp2p-mdns)** for the first increment: least code,
proven, and it drops cleanly into the existing swarm and dialer. Treat the
stable-`PeerId` leak as a **known limitation of phase 1**, gated behind
opt-in + "known contacts only" defaults. Keep **Option B in reserve** for the
one thing mDNS cannot cleanly give us — a **rotating, contact-recognizable token**
that avoids emitting a stable identifier — and only build it if the privacy
posture (§5) demands recognition-without-connection. The two can coexist: mDNS
for address discovery, a small beacon layer for private contact-scoped tokens.

---

## 4. What is advertised

The guiding rule: **advertise the minimum needed to open a connection, and
nothing that names or durably identifies the user.**

Advertised (phase 1, mDNS):

- A **local reachability address** — the listen multiaddr `/ip4/…/tcp/…`.
- A **connection identifier** — the libp2p `PeerId` needed to complete the Noise
  handshake to a specific node.

**Never** advertised in the clear:

- The **handle** (`user_id(email)`) — the value peers pin and the directory keys
  on.
- The **display name**.
- The **wallet public key** (the account root identity).
- The **queue endpoint** or any messaging keys.

The tension is the connection identifier. To dial a node, *some* stable-enough id
is required for that session; but a **permanently stable** id (the raw device
`PeerId`) is a cross-network tracking beacon. §5 resolves this by rotating it.

Note that omitting the handle/wallet does **not** by itself provide
authentication — it only reduces what a passive listener learns. Authentication
comes entirely from §5's record-match step, which is why we can afford to
advertise so little: the advertisement is not trusted, so it need not be rich.

---

## 5. Security — the crux

> **A discovery advertisement is a hint about *where*, never a claim about
> *who*. Trust is decided after connecting, by cryptographic verification
> against a wallet-signed record we already pin.**

### The threat

On a shared LAN, an attacker can send whatever multicast packets they like. They
can:

1. **Advertise a bogus peer** ("I am a Mycellium node at 10.0.0.5") — trying to
   get us to connect to *them*.
2. **Impersonate a specific contact** — advertise an address/id claiming to be
   Alice, hoping we send Alice's messages to the attacker.
3. **Spoof or race** the real peer's advertisement.

Discovery **must not** let any of these result in trust or message delivery to
the wrong party.

### Why they fail — the trust gate

Discovery hits are funneled through the **same authentication we already use for
directory-supplied addresses**, in two stages:

1. **Transport authentication (Noise).** Dialing the advertised multiaddr runs
   the libp2p Noise handshake, which **proves the remote holds the private key
   for the advertised `PeerId`** (its device key). An attacker cannot complete
   this for a `PeerId` whose secret they do not have. So attack (2) — claiming to
   be Alice's device key at the attacker's address — fails at the handshake: the
   attacker can advertise Alice's `PeerId` but cannot *be* it.

2. **Record binding (the trust decision).** Completing Noise only proves *"this
   endpoint holds device key X."* It does **not** prove X is anyone we care
   about. Trust is granted only if **device key X appears inside a wallet-signed
   `Record` belonging to a contact we pin/verify.** Concretely, after the
   handshake the engine checks the peer's device key against
   `Record::device(&key)` of the intended recipient's record, whose wallet is
   **pinned on first use** and whose trust level (Unverified / Pinned / Verified
   / Changed) is tracked in
   [`verified.rs`](../../crates/mycellium-engine/src/verified.rs) (#57). A
   device key that matches no pinned contact's record is a stranger — dropped.
   This defeats attack (1): a bogus node authenticates *as itself* and simply
   isn't anyone we trust.

So the security property is: **discovery can only ever accelerate reaching a
peer we could already have reached and verified via the directory. It can never
introduce a new trusted identity, and it cannot redirect trust to an attacker.**
The worst a LAN attacker achieves is denial of service (spam advertisements,
racing) — never impersonation.

### Composition with pinning + safety numbers

- **First contact still needs a record.** Discovery does not create contacts. To
  trust a discovered peer at all, we must already hold their wallet-signed record
  (from the directory earlier, or pre-shared via QR/contact card, see §7).
  First-use pins the wallet exactly as today.
- **Safety numbers are unchanged.** The out-of-band
  [`safety_number`](../../crates/mycellium-core/src/safety.rs) is computed from
  both wallets and is completely independent of transport. A LAN-discovered
  connection to a Verified contact is as trustworthy as a directory-discovered
  one; a connection to an Unverified contact is exactly as provisional. Discovery
  changes the *path*, never the *trust level*.
- **`Changed` still fires.** If a discovered peer presents a device key inside a
  record whose wallet differs from what we pinned, that is the same
  identity-changed alarm (#57) — surfaced loudly, not silently accepted.

### Residual risks (stated honestly)

- **Address confusion / connection DoS.** An attacker can flood advertisements or
  race the real peer to waste our dial attempts. Mitigate with per-source rate
  limits and by treating discovery as best-effort (fall back to directory/queue,
  §6). No message is mis-delivered; only latency suffers.
- **Presence confirmation.** Even though we drop untrusted peers, the *act of
  dialing* a spoofed address tells the attacker we tried — a minor presence
  signal. "Known contacts only" mode (§5 defaults) and not probing unknown
  advertisements reduce this.

---

## 6. Privacy — the tension

This is the part to be honest about: **mDNS broadcasts presence to the entire
local network.** Discovery inherently trades some privacy for the co-located
fast path. The job is to bound the leak, not to pretend it away.

### What leaks

| Leak | To whom | Severity |
|---|---|---|
| **"A Mycellium user is on this network."** | Anyone on the LAN | Inherent to any broadcast discovery; unavoidable if enabled. |
| **A stable identifier** (raw device `PeerId`) enabling **cross-network tracking** — recognizing the same device at the café, the office, a friend's house. | Anyone on those LANs, correlated | **High** if the advertised id is stable. This is the one to fix. |
| **Local IP / port / device count.** | LAN | Low–moderate; ordinary for any LAN service. |
| **Dial attempts** confirm we tried to reach an advertised peer. | An attacker probing us | Low; a presence hint (see §5 residual risks). |

Note what does **not** leak, by construction (§4): no handle, no display name, no
wallet, no queue, no social graph. A listener learns *a* Mycellium device is
here — not *who*.

### Mitigations

1. **Opt-in, off by default.** Discovery ships disabled. A user on a hostile or
   public network is never broadcasting unless they turned it on. (Acceptance
   criterion of #62: the feature can be disabled for high-risk environments —
   we go further and make *off* the default.)
2. **No identifying fields in the clear.** Enforce §4: advertise only address +
   connection id.
3. **Rotating / ephemeral local identifier.** Do **not** advertise the raw device
   `PeerId`. Run mDNS under an **ephemeral libp2p keypair rotated per session /
   per epoch**, decoupled from the durable device key, so the same device is not
   linkable across networks or over time. (Trade-off: a rotating id can't be
   recognized by a contact *before* connecting — see next point.)
4. **LAN-scoped only.** Multicast is link-local by design (TTL/scope); never
   forward or relay advertisements off the local link.
5. **Clear UX toggle.** A single, honest switch — e.g. `discovery on|off` — with
   plain-language help stating exactly what it broadcasts ("other Mycellium
   devices on this Wi-Fi can see that a device is present here"). Surface the
   current state; never silently enable it.
6. **"Known contacts only" as the conservative mode.** Because a rotating id
   defeats *recognition*, the privacy-maximizing configuration is a
   **contact-scoped beacon** (Option B): advertise a **rotating token derived
   from a secret shared with each known contact** (e.g. an epoch-keyed MAC over
   the pair's wallets), so *only* an already-established contact can recognize
   the advertiser, and a stranger sees an opaque, unlinkable blob. This gives
   discovery **only among people you already know**, with no stable id and no
   recognizability to outsiders — at the cost of the extra beacon protocol.

### Recommended defaults

- **Off by default.** Explicit opt-in per device.
- When enabled, default to the **least-leaky mechanism available**: contact-scoped
  rotating token if the beacon (Option B) is built; otherwise mDNS under a
  **rotating ephemeral keypair**, matched to trusted records only after
  connecting.
- Never advertise while on a captive/unknown network *and* configured for
  high-risk mode.

The honest one-line summary for docs/UX: **"Local discovery lets nearby devices
you know find each other faster and offline — but turning it on tells the local
network a Mycellium device is present. It's off until you enable it."**

---

## 7. Discovery → connection flow (delivery ladder)

Discovery slots in as a **new, preferred source of a direct address**, ahead of
the directory, inside the existing ladder. It does not add a new trust path — it
feeds the same dial + record-match.

Proposed ordering when sending to a recipient device, with discovery enabled:

1. **LAN candidate?** Consult the local discovery cache for an address whose
   device key matches a device in the recipient's (already-held, wallet-signed)
   record. If present, **dial it directly** over Noise and run the §5 record
   binding. On success → **delivered live, no directory or queue touched.** This
   is the co-located fast path and ties into the P2P-first goal of #59.
2. **Directory-supplied direct** (today's path): `presence` + dial the record's
   `peer_id`. Used when not co-located, or when the LAN dial failed.
3. **Queue deposit:** recipient offline / unreachable → deposit into their queue.
4. **Outbox:** neither worked → park sealed and retry
   ([`outbox`](../../crates/mycellium-engine/src/outbox.rs)).

Interaction with **reachability scoring (#60):** LAN-discovered addresses are a
distinct, high-value delivery outcome. Score them separately from
directory-direct and queue outcomes, so a device that is reliably reachable on
the LAN is tried there first, while stale LAN observations decay (a device that
left the network shouldn't be dialed forever). Discovery is best-effort: a failed
or absent LAN candidate falls through to the directory path with no user-visible
error — the ladder degrades gracefully.

Note a **current-state caveat** worth fixing alongside this work:
[`app::messaging::deliver`](../../crates/mycellium-engine/src/app/messaging.rs)
today opens live connections with `net::TcpConnection` and **skips** `peer_id`s
that look like multiaddrs (`addr.starts_with('/')`), so the Noise-authenticated
libp2p path is not yet exercised on the send side. LAN discovery yields
multiaddrs, so wiring discovered addresses through
[`libp2p_net`](../../crates/mycellium-transport/src/libp2p_net.rs) (which is what
gives us the §5 handshake guarantee) is a prerequisite, and dovetails with the
#59 reachability work.

---

## 8. Offline / no-directory operation

**Can two co-located devices exchange messages with no internet?** Yes — with one
precondition: **they must already hold each other's keys.** Discovery finds an
*address*; it does not distribute *identity*. Everything the crypto needs
(the peer's wallet-signed record: device key, `id_key`, `signed_pre_key` for
X3DH) must be obtained by some means other than the (unreachable) directory.

The minimum for a fully offline exchange:

1. **Pre-shared or cached records.** Either the record was **cached from an
   earlier online lookup**, or it was exchanged **out of band** — the natural fit
   is the QR/contact-card flow. The existing seedless
   [`pairing`](../../crates/mycellium-core/src/pairing.rs) already moves an
   account over an **in-person QR-authenticated** channel; the same idea extends
   to swapping *contact* records (a signed contact card, per #58) with no server.
   Because records are self-certifying (wallet-signed), a cached or QR-delivered
   record is exactly as trustworthy offline as online.
2. **LAN discovery** supplies the current local address for the peer's device key
   (§7 step 1).
3. **Noise dial + record binding** (§5) authenticates the connection against the
   held record.
4. **X3DH + Double Ratchet** establish/continue the session and messages flow —
   entirely on the local link.

What genuinely **cannot** work offline: **first contact with someone whose record
you have never obtained.** With the directory unreachable and no prior QR/cache,
there is no trustworthy way to learn their wallet — and discovery must not invent
one (that would be the impersonation hole §5 forbids). So the honest statement is:
**offline messaging works between devices that have already met (online or via
QR); it does not bootstrap trust with a total stranger over the LAN.**

This makes local discovery a strong fit for real co-located scenarios: two people
who added each other earlier, or a user's own device cluster (Layer 11), meeting
again on a network with no internet — a captive Wi-Fi, an event, a flight.

---

## 9. Recommendation and phased plan

**Phase 0 — this document.** Agree the trust gate (§5), the privacy posture (§6),
and off-by-default. No code.

**Phase 1 — mDNS behind a feature + runtime flag (native, opt-in).**

- Add an `mdns` Cargo feature to
  [`mycellium-transport`](../../crates/mycellium-transport/Cargo.toml) that
  enables `libp2p`'s `mdns` feature. **Off by default** (not in the `default`
  feature set), preserving the trimmed audit surface for builds that don't want
  it.
- In [`libp2p_net`](../../crates/mycellium-transport/src/libp2p_net.rs), when the
  feature *and* a runtime toggle are on, add the mDNS behaviour to the swarm and
  surface `Discovered(PeerId, Multiaddr)` events on a channel as **candidate
  addresses** (hints only).
- Prerequisite: route live delivery through the libp2p/Noise transport for
  multiaddr `peer_id`s (fixing the §7 caveat), so the §5 handshake actually runs.
- Engine: a **discovery cache** (device key → local multiaddr, with expiry), and
  a new **first rung** in the delivery ladder (§7 step 1) that dials a cached LAN
  address only when its device key matches a device in a **pinned** contact's
  record.
- UX: `discovery on|off` (default off) + status, with the honest one-liner from
  §6.
- **Known-contacts-only** matching from day one (never trust a discovered device
  key absent a pinned record).

**Phase 2 — privacy hardening.**

- Run mDNS under a **rotating ephemeral keypair** so the advertised id is not the
  durable device key (removes the cross-network tracking leak of §5).
- Reachability scoring integration (#60): score/decay LAN outcomes distinctly.

**Phase 3 — contact-scoped beacon (optional, Option B).**

- If §6's "recognition without a stable id" is wanted, add a small UDP multicast
  beacon advertising a **rotating, contact-derived token**, so only known
  contacts recognize the advertiser and outsiders see opaque bytes. Coexists with
  mDNS for address resolution.

Each phase is independently shippable and independently disableable.

---

## 10. Rough changes by crate

- **[`mycellium-transport/Cargo.toml`](../../crates/mycellium-transport/Cargo.toml)**
  — new `mdns` feature enabling `libp2p/mdns`; **not** in `default`. Document (as
  the existing comment does for the trimmed features) that turning it on
  re-expands the multicast audit surface.
- **[`mycellium-transport/src/libp2p_net.rs`](../../crates/mycellium-transport/src/libp2p_net.rs)**
  — behind `#[cfg(feature = "mdns")]` and a runtime flag, add the mDNS behaviour
  to `SwarmBuilder`; forward discovered `(PeerId, Multiaddr)` to a candidate
  channel. Optionally support a rotating ephemeral keypair for the advertised
  identity (Phase 2). Keep the raw device-key `PeerId` for *dialing/authenticating*
  peers; the ephemeral key is only for *what we broadcast about ourselves*.
- **[`mycellium-engine`](../../crates/mycellium-engine/src/app/messaging.rs)**
  — a discovery-cache module (device key → address, expiry); a new preferred rung
  in `deliver`/the ladder that dials a LAN candidate over libp2p and applies the
  §5 record binding before trusting it; route multiaddr delivery through
  [`libp2p_net`](../../crates/mycellium-transport/src/libp2p_net.rs) rather than
  skipping it. Reuse pinning/`TrustLevel` from
  [`contacts.rs`](../../crates/mycellium-engine/src/app/contacts.rs) /
  [`verified.rs`](../../crates/mycellium-engine/src/verified.rs) unchanged.
- **CLI/TUI** — `discovery on|off` + status; make the presence trade-off explicit.

No changes to [`record.rs`](../../crates/mycellium-core/src/record.rs),
[`safety.rs`](../../crates/mycellium-core/src/safety.rs), or the wire format:
discovery reuses the existing record/device-key/Noise machinery and adds no new
signed object.

---

## 11. Test plan (maps to #62 acceptance criteria)

- **Same-LAN discovery → direct delivery.** Two native nodes with mDNS on, no
  directory reachable: node A discovers B and delivers a message live over Noise;
  assert the directory/queue were never contacted.
- **Untrusted advertiser is dropped.** A node advertising a device key that
  matches no pinned contact is discovered but **not** trusted or delivered to.
- **Impersonation fails at the handshake.** A node advertising a *victim's*
  `PeerId` at an attacker address cannot complete Noise → no connection, no
  delivery.
- **`Changed` alarm.** A discovered device key inside a record whose wallet
  differs from the pin raises the identity-changed state (#57), not silent trust.
- **Disabled = silent.** With discovery off, the node neither advertises nor
  acts on advertisements (manual multicast-capture check that nothing is emitted).
- **Fallback.** LAN candidate absent/stale → ladder falls through to
  directory-direct → queue → outbox with no user-visible error.
- **Offline exchange.** Two devices holding each other's records, no internet:
  full send/receive over the LAN.

---

## 12. Open questions

- **Ephemeral-id rotation cadence** vs. reconnection churn — rotate per session,
  per epoch, or per network change? Faster rotation = less linkability, more
  re-discovery cost.
- **Recognition vs. anonymity.** Phase 1 (rotating id, match-after-connect) hides
  identity from outsiders but requires a dial to know *who* a peer is; the
  Phase 3 contact-token gives recognition-without-dial only to known contacts.
  Which is the right default for the average user?
- **Multicast reliability** across consumer APs (client isolation, multicast
  filtering) — how often does mDNS simply not work, and does that argue for the
  beacon fallback sooner?
- **Own-cluster (Layer 11) discovery** — a user's own devices on the same LAN are
  the easiest, safest first case (shared wallet, mutual records). Ship that path
  first?

---

## 13. Cross-links

- Parent roadmap: **[#48](https://github.com/aristath/messe/issues/48)** — native
  privacy, metadata minimization, trust-model roadmap.
- **[#57](https://github.com/aristath/messe/issues/57)** — first-contact
  verification UX (TOFU pinning + `TrustLevel`), the trust gate discovery composes
  with.
- **[#59](https://github.com/aristath/messe/issues/59)** /
  **[#60](https://github.com/aristath/messe/issues/60)** — direct-P2P reachability
  and reachability scoring; LAN discovery is a co-located input to that ladder.
- **[#58](https://github.com/aristath/messe/issues/58)** — QR/contact-card flow,
  the out-of-band channel that makes fully offline first contact possible.
- Repo docs: [`SECURITY.md`](../SECURITY.md) (trust model, TOFU),
  [`PRIVACY-MODES.md`](../PRIVACY-MODES.md) (queued-delivery metadata knobs — a
  parallel opt-in privacy surface).
