# Direction: Mycellium on Nostr

**Status:** DECIDED + IMPLEMENTED. This document records the original reasoning; the rebuild
landed it as the `mycellium-{mls,nostr,multidevice,app,cli,sdk}` workspace. Delivered:
MLS-over-Nostr via MDK (FS+PCS); relay transport; **multi-device** (the differentiator);
the headless app engine (contacts, conversations, SQLCipher-persisted history); a CLI;
the full key-lifecycle security — SAS device pairing, PCS device removal, account-key
rotation/migration (mutual attestation, no auto-accept), and live trust subscriptions;
**hardened NIP-05 verification** (rebinding/mismatch detection, not a badge); and a UniFFI
SDK (Kotlin/Swift bindings) as the bridge to native clients. Remaining: running general
relays + upstream Marmot/MDK contribution, and the native client UIs. The open decision
below is resolved (we adopted MLS-over-Nostr via MDK).

## TL;DR

Rebuild Mycellium as **a hardened, forward-secret secure-messaging client + relay on the
open Nostr network**, using [rust-nostr](https://rust-nostr.org). We are a real,
interoperable Nostr identity; our extra security is a capability-gated overlay that
upgrades Mycellium↔Mycellium chats and gracefully degrades to standard Nostr for everyone
else. We are **net contributors** to Nostr (run general relays, push our hardening upstream
as open NIPs, fund the commons) — because Mycellium's longevity is a strict subset of
Nostr's longevity. The aim is to be **"the Signal of Nostr": the trusted reference
implementation and steward of secure messaging on the open network**, not a proprietary
walled garden and not a parasite on volunteer infrastructure.

## Strategic decision: citizen of Nostr, not founder of a rival network

We considered two framings: **"Signal for Nostr"** (build *on* the existing Nostr
network, add hardened security, strengthen the commons — a *citizen*) vs **"Nostr for
Signal"** (build a new decentralized network purpose-built for secure messaging, borrowing
Nostr's architecture but with our own relays/commons — a *founder*). The founder path fits
messaging more natively, but forfeits the exact advantages we value: solved cold-start,
network effects, and mutualism — and it competes with Nostr instead of strengthening it.

**Decision: citizen.** Build on Nostr, contribute upstream, strengthen the network. This
also resolves an asymmetry — you *can* be "on Nostr" (open, permissionless), but you cannot
be "on Signal" (a closed walled garden, no federation by design), so the citizen path is the
only one that comes with a real ecosystem to join.

## Why Nostr is the right foundation

The key realization: **our directory was never a trust anchor.** Because records are
signed and the client already pins (TOFU), verifies out of band (safety numbers), and
rejects rollbacks (the `seq` guard), the directory is already just an *untrusted cache*.
So "make it distributed" reduces to "replicate an untrusted cache and detect lying" — which
is exactly what Nostr relays are. The fit is unusually clean:

| Mycellium concept | Nostr equivalent |
|---|---|
| Identity = secp256k1 key | npub (secp256k1) — one signature-scheme swap (ECDSA → Schnorr/BIP340) |
| `SignedRecord` (handle → wallet, queue, devices, seq) | replaceable event (kind 0 metadata + NIP-65 relay list); `seq` → `created_at` |
| Directory (the untrusted lookup service) | relays (dumb, interchangeable, anyone runs one) |
| Recipient-owned queue (store-and-forward) | relays as store-and-forward via NIP-17 gift-wrapped events |
| Circuit-relay / live delivery | relays (+ optional libp2p as a live-path optimization) |
| Client-side pin / verify / anti-rollback | unchanged — now generalized to *cross-relay* validation |

The "discover from one relay, validate against a few more" idea has a name: **equivocation
detection** (Certificate-Transparency-style accountability). Cross-checking a signed event's
`created_at`/seq across independent relays catches a relay serving a stale or forked record.
No consensus needed.

## The hybrid model: on the open network, hardened by our own rules

We are fully on public Nostr **and** enforce extra guarantees. Rules can only bind three
things we control — and that is enough:

1. **Our client** — defaults, enforcement, UX (demands verification, drives the hardened crypto).
2. **Our relays** — admission policy, rate limits, retention SLAs (a relay may reject
   events that don't meet our bar), *and they serve all of Nostr, not just us*.
3. **`@mycellium.eu` NIP-05** — the npub stays open and portable; the `alice@mycellium.eu`
   identity is one we issue/vet/attach policy to. Open identity, controlled namespace.

**Capability negotiation + graceful degradation** is the glue that lets "open" and
"hardened" coexist. We advertise a marker ("this npub is a Mycellium account, supports
hardened-DM vN, here are my device keys"). On a new chat:
- **Both Mycellium** → hardened path (forward-secret, per-device, verified).
- **One is vanilla Nostr** → fall back to standard NIP-17, and *mark the chat "standard
  encryption, not hardened."* (Like Signal's old "is this contact on Signal?".)

### Additional security we layer (all ride on open Nostr, invisible to it)
- **Forward secrecy / PCS** — Mycellium↔Mycellium uses **MLS-over-Nostr** (Marmot / NIP-EE)
  rather than NIP-44's static-key DMs. Relays just carry opaque blobs.
- **Key-change protection** — Nostr has none natively; we add TOFU pinning + safety-number
  verification on npubs and warn on rotation.
- **Multi-device done right** — per-device keys under the npub, published as a signed
  device-list, sealed per-device. Better than Nostr's nsec-sharing / NIP-46 norm.
- **Cross-relay equivocation detection + anti-rollback** — client pins latest
  `created_at`/seq per contact, cross-checks across relays.
- **Metadata hardening** — mandatory gift-wrap (NIP-59) for all DMs + padding/delay modes.
- **Spam/Sybil resistance** — PoW (NIP-13) and/or NIP-42 AUTH / membership on our relays.

## Ethos: mutualism, not parasitism

Free-riding on volunteer relays while hoarding our improvements would undermine our own
foundation. We must be a **keystone contributor**:

- **Infrastructure** — every Mycellium node (community box, pi, opted-in phone) runs a
  **general-purpose relay serving all of Nostr**. A growing Mycellium *adds* relay capacity
  to the commons instead of extracting from it.
- **Protocol** — Nostr's real weaknesses are our strengths. We fix them *at the protocol
  level as open NIPs*, not privately in our client: advance MLS-over-Nostr; propose NIPs for
  key-change protection, device-list/account-cluster multi-device, and cross-relay
  transparency/equivocation.
- **Code** — contribute upstream to `rust-nostr`; open-source our hardened relay so *other*
  operators run safer relays.
- **Economics** — wire Nostr's native value layer (Lightning/zaps) so value flows to relay
  operators; support paid/community-funded relays.
- **Citizenship** — be storage/bandwidth-light: NIP-65 outbox model (don't spam every
  relay), negentropy sync, ephemeral kinds for transient signaling, short retention for
  delivered messages.

## We are not blocked on anyone merging anything

Nostr is **permissionless**. We can deploy any event kind + behavior immediately; relays
store arbitrary kinds by default; clients that understand ours use it, others ignore it.
"Merging a NIP" is standardization so *other* clients adopt it — it affects **interop and
ecosystem benefit, not whether our thing runs**. So:
- Mycellium works day one, Mycellium↔Mycellium, on public relays, with zero approval.
- NIP acceptance is the **upside** (others adopt our hardening → Nostr gets stronger), not a gate.
- For forward secrecy we adopt the **existing** MLS-over-Nostr work — not even blocked on
  our own PR.

Caveats: some relays allowlist kinds (→ run our own + wrap in standard NIP-59 so the *outer*
event looks normal); a feature only interops with *other* clients once its NIP is adopted
(until then it's Mycellium↔Mycellium with graceful fallback).

## Naming (Zooko's triangle)

Nostr's answer: self-certifying **npub** + DNS-anchored human names via **NIP-05**
(`alice@mycellium.eu`). The name↔key binding is **Nostr's, not ours** — we adopt NIP-05 as-is,
we do not invent it. The npub is the canonical, portable, secure identity; the NIP-05 alias
under our own domain is the human-readable, membership/rules layer we legitimately control.
This replaces today's globally-unique-`alice` model.

What we *add* is **hardened verification of that binding**, which mainstream clients skip:
they resolve NIP-05 once and render a "verified" badge. We treat it as an *untrusted claim* —
resolve it, check the returned npub against the key we already pinned (TOFU), and detect
**rebinding** (`alice@mycellium.eu` now resolving to a different npub) or an unreachable/removed
record. A mismatch raises a trust event on the same pipeline as key rotation and device-list
changes ("this identity claim changed — re-verify out of band"). So: Nostr owns the binding;
we own detecting when it is lying or has changed.

## The moat: stewardship, not secret crypto

Contributing our hardening upstream does not weaken us — it trades a cloneable moat for a
compounding one. **Signal precedent:** the Signal protocol is open and used by WhatsApp et
al.; Signal is stronger for it because its edge is *trust, UX, execution, and being the
reference steward*. Mycellium's durable edge becomes the best client, the most trusted
implementation, the curated `@mycellium.eu` identity layer, well-run relays, and the
reputation of being the org that made Nostr's secure-messaging layer real.

## What this replaces vs keeps (no attachment to current code)

- **Replace:** the HTTP directory, the recipient-owned queue, the libp2p transport
  plumbing, the custom wire/clients → all become **rust-nostr + relays**.
- **Keep / port as the hardened overlay:** the trust model (pin/verify/anti-rollback, now
  cross-relay), and — deliberately — the **per-device-key cluster model** (our multi-device
  design is *better* than the Nostr norm; keep it as a hardening edge, publish it as a NIP).
- **Change:** identity signature ECDSA → Schnorr/BIP340 (true npubs).
- **Adopt over invent:** MLS-over-Nostr (Marmot / NIP-EE) for the forward-secret messaging
  crypto, rather than porting our own Double Ratchet.

## Honest limitations

- **Portable keys cut both ways:** a user can take their npub to another Nostr client and
  bypass our client's rules (e.g., plaintext NIP-04). We cannot cryptographically prevent
  this — "rules for our users" means "rules our client + relays + NIP-05 enforce," not rules
  binding on the identity everywhere. The security that *matters* (E2E, pinning) is
  client-side and fully under our control for anyone using our client.
- **Public presence leaks some metadata** (relay list, that you exist, rough presence);
  gift-wrap hides *message* metadata, not existence.
- **Availability/retention on public relays isn't guaranteed** → run our own for the
  reliability-critical inbox path, use public relays for redundancy/reach.

## The one open decision underneath all of this

The messaging-crypto path: **lead on MLS-over-Nostr (Marmot / NIP-EE)** — which is
simultaneously the strongest security answer *and* the most net-positive contribution to
the ecosystem — vs. porting our own Double Ratchet as a proprietary payload. The ethos
above points at MLS-over-Nostr. Next step: scope what leading on Marmot / NIP-EE involves.
