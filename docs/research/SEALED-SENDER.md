# Sealed-sender-style queue deposits — research note

*Design research for issue [#55](https://github.com/aristath/mycellium.eu/issues/55)
(parent [#48](https://github.com/aristath/mycellium.eu/issues/48)). **Documentation
only** — no protocol implementation starts until this note is resolved (per #55's
acceptance criteria).*

> **Status:** research. This surveys the design space, weighs abuse/blocking/replay
> trade-offs, and makes a recommendation. It does **not** claim anonymity — see
> [Non-goal](#goal-and-non-goal). Read alongside [`SECURITY.md`](../SECURITY.md#the-queue-observes)
> (what the queue observes today) and [`PRIVACY-MODES.md`](../PRIVACY-MODES.md)
> (the size/timing knobs that are the *other* half of queue-metadata reduction).

## Goal and non-goal

**Goal.** Remove the queue operator's ability to link **sender wallet → recipient
wallet** for a deposit. Today, a deposit is sender-authenticated, so the operator
learns *that wallet A messaged wallet B, and when*, for every message it relays.
The goal is that a well-behaved queue **cannot** attribute a deposit to a sender
wallet, while still bounding deposit spam and mailbox-bombing.

**Non-goal — this is not anonymity, and the note never implies it is.** Even a
perfect sealed-sender deposit still leaks, and other actors still attribute:

- **The recipient always learns the sender.** The E2E payload is a X3DH
  [`Envelope`](../../crates/mycellium-core/src/offline.rs) that *authenticates the
  sender to the recipient* (`from`, `sender_record`, `init.initiator_ik`). Hiding
  the sender from the recipient is a different, deliberately-unwanted property
  (it would break TOFU pinning and blocklists). Sealed sender hides the sender
  from the **queue**, not from **Bob**.
- **A network observer still sees origin.** The depositor's IP ↔ the queue
  endpoint, timing, and size are visible to anyone on the path (and to the queue
  at the TCP layer) regardless of what the request body authorizes. Defeating
  that needs mixing/Tor/cover traffic — explicitly **out of scope** here and in
  [`SECURITY.md`](../SECURITY.md#out-of-scope-by-design-or-not-yet).
- **Timing and size still correlate.** Padding (#51) and delay/batching (#52)
  blunt *size* and *when*; they are orthogonal to *who*. Sealed sender is the
  lever for *who* and only that.

The honest one-line framing (matching [`SECURITY.md`](../SECURITY.md#in-one-line-for-users)):
sealed sender would let Mycellium stop the queue from learning **who sent** a
queued message; it would **not** make Mycellium an anonymity system.

## The current model, precisely

Deposits land in a **per-recipient, wallet-addressed mailbox**
([`mycellium-queue`](../../crates/mycellium-queue/src/lib.rs)). Two facts matter:

1. **The deposit is sender-authenticated.** `deposit()` calls
   `let sender = self.authed(token, now)?` and then rate-limits per **sender
   wallet** (`self.allow(sender.0, "deposit", now)`). The token comes from a
   SIWE-style wallet login (`challenge` → `verify`), so the operator maps
   `token → sender wallet` and thus `sender wallet → (recipient wallet, slot,
   time)`. This is the linkage #55 targets.

2. **The blob body *also* names the sender, in cleartext.** The deposited blob is
   `serde_json::to_string(&MailItem::Direct(envelope))`
   ([`app/messaging.rs`](../../crates/mycellium-engine/src/app/messaging.rs)
   `QueueTarget::deposit`). The [`Envelope`](../../crates/mycellium-core/src/offline.rs)
   struct carries `from: Handle` and `sender_record: SignedRecord` **outside** the
   ratchet ciphertext — only the `message: RatchetMessage` field is encrypted. So a
   queue operator can read the sender's handle and full signed record straight out
   of the blob it stores.

**This is the load-bearing finding of the note.** Sealed sender in Mycellium is a
*two-part* change, and removing sender authentication alone (part 1) buys **nothing**
while part 2 stands:

- **Part 1 — authorize the deposit without identifying the sender.** Replace
  "log in as your wallet, then deposit" with an unlinkable capability. (This is the
  design-space survey below.)
- **Part 2 — seal the envelope header to the recipient.** Wrap the whole
  `Envelope` (including `from` and `sender_record`) in an anonymous
  box to the recipient's messaging key, so the outer blob the queue stores is
  fully opaque. X25519 sealed-box (ephemeral-static ECDH + AEAD) over the
  recipient's published `id_key` fits; the recipient's *wallet/messaging key is
  already public in the directory record*, so no new key exchange is needed.
  Without this, the queue reads the sender from the body no matter how the deposit
  was authorized.

Everything below assumes **part 2 ships too** — otherwise the feature is theatre.

### What the queue must keep doing

Sender auth is not only identity — it is the **anti-abuse hook**. Removing it must
preserve the three protections the queue relies on today, or abuse gets worse:

| Protection today | Mechanism | Constant |
|---|---|---|
| Per-sender deposit rate limit | fixed window keyed by sender wallet | `DEPOSIT_RATE_LIMIT = 30` / `RATE_WINDOW = 60 s` |
| Per-recipient mailbox cap | `mailbox.len() >= MAX_MAILBOX` rejects | `MAX_MAILBOX = 256` per (wallet, slot) |
| Body cap | server body limit | `MAX_BODY = 1 MiB` |
| Only the owner collects | `hex33(caller) == wallet_hex` | — |

Note the mailbox cap and body cap are **recipient-side** and survive *any* deposit
scheme unchanged — they already bound total damage per mailbox to 256 items
regardless of who fills it. The thing sealed sender puts at risk is the
**per-sender** rate limit, because "per sender" is exactly the identity we are
trying to erase.

## Design space

Each option is scored on: **sender privacy** (does the queue lose the linkage?),
**abuse resistance**, **blocking** (can a recipient stop a specific sender?),
**revocation**, **replay/flooding**, and **complexity**.

### Option A — Signal-style sealed sender (unauthenticated deposit + out-of-band abuse control)

**Mechanism.** Drop deposit authentication entirely. The sender presents no wallet
identity; the deposit is an anonymous POST of a sealed blob (part 2). In Signal,
abuse is held back by a **delivery token / sender certificate**: the server issues
the sender a short-lived certificate at login and the *recipient's* client, on open,
checks it — plus unsealed-sender rate limits and "message requests" gate strangers.

**Why Mycellium's per-recipient queue changes the calculus.** Signal has one central
server holding *all* mailboxes, so an anonymous flood is a server-wide DoS and the
sender certificate is really the abuse lever. Mycellium's queue is
**per-recipient and recipient-owned** (the endpoint lives in the recipient's signed
record; see [`DEPLOY.md`](../DEPLOY.md) and #63). That helps and hurts:

- *Helps:* damage is naturally sharded — flooding one wallet's queue can't touch
  another's, and `MAX_MAILBOX = 256` already caps a single mailbox. A recipient
  who is targeted can rotate their queue endpoint (#53) or run their own.
- *Hurts:* there is no central identity the operator can throttle. With sender auth
  gone and no replacement capability, *any* internet host can POST up to 256 items
  into any known wallet's mailbox as fast as the body cap allows — a trivial
  mailbox-bomb, repeated across the account and device slots. The `sender`-keyed
  rate limiter becomes dead code because there is no sender to key on.

**Abuse resistance:** *weak on its own.* Needs a replacement bound — proof-of-work
per deposit, or a coarse per-IP/per-recipient limit (fragile, IPs are cheap), or
one of the capability schemes below. Signal's own answer (delivery tokens) is
really Option C in disguise.

**Blocking:** *recipient-side only, post-hoc.* Because the sender is anonymous at
deposit, the queue can't enforce a block; the recipient's client drops messages
from blocked wallets **after** decrypting the sealed header. The item still
consumed a mailbox slot and bandwidth — blocking stops *reading*, not *depositing*.

**Revocation:** n/a (no credential).

**Replay/flooding:** an anonymous deposit is trivially replayable by any observer
who captured the blob; the queue can't dedupe by sender. Mitigated only by the
mailbox cap and the recipient discarding duplicate ratchet messages (the ratchet
already rejects replays on open, but they still cost a slot).

**Complexity:** low to build, high to make safe — the abuse story is unsolved
without bolting on another mechanism.

### Option B — Recipient-issued deposit capabilities (blind-signed tokens)

**Mechanism.** The **recipient** is the rate-limiter of last resort for their own
mailbox, so let the recipient mint the right to deposit. Bob periodically obtains a
batch of single-use **deposit tokens** and hands them to correspondents (in-band,
inside an existing E2E session, or embedded in his contact card / directory record).
A sender spends one token per deposit. The queue accepts a deposit iff it carries a
valid, unspent token — and, crucially, **cannot link the token to a sender**.

Two families make the token unlinkable:

- **Blind signatures (RSA / BLS).** The *queue* holds a per-recipient issuing key
  and blind-signs tokens that Bob requests; Bob unblinds and distributes them. At
  deposit, the sender presents an unblinded token + the queue's signature; the
  queue verifies but, by the blinding property, cannot correlate the presented
  token with any issuance. (Chaumian e-cash shape.) The queue enforces
  single-use via a spent-set.
- **Privacy Pass / anonymous credentials (VOPRF, e.g. RFC 9578).** The same
  unlinkable-token property with modern, better-analyzed primitives and batch
  issuance; redemption is a keyed verification the issuer can't link to issuance.

**Who issues matters.** If the *queue* is the blind-signer, the queue rate-limits
issuance (Bob can only get N tokens per window) and thus bounds his total inbound
volume, while never seeing who spends them. If *Bob* is the signer (his own key),
the queue can't bound issuance and Bob must self-limit — simpler crypto, weaker
global bound, and the queue must fetch/trust Bob's issuing pubkey.

**Sender privacy:** *strong* — the queue verifies a token, not a wallet, and
blinding severs issuance↔redemption. Combined with part 2, the linkage is gone.

**Abuse resistance:** *strong and recipient-controlled* — Bob decides who gets
tokens and how many; a stranger with no token simply can't deposit. This maps
cleanly onto Mycellium's "message requests"-free model: giving someone a token *is*
accepting them as a correspondent.

**Blocking:** *good.* Bob stops minting/handing tokens to a correspondent he's
blocking; existing unspent tokens are the residual exposure (bounded, single-use,
and revocable by rotating the issuing key — see below).

**Revocation:** *coarse but real.* Rotating the per-recipient issuing key
invalidates every outstanding token at once (all correspondents re-fetch). Per-token
revocation needs a revocation list, which reintroduces linkability risk — avoid;
prefer key rotation + short token lifetimes.

**Replay/flooding:** the queue's **spent-set** gives true single-use — a replayed
token is rejected as spent, which is *stronger* replay protection than today's
scheme (which has none at the deposit layer). The spent-set is per-recipient and
bounded by issuance rate, so its memory is controllable. Flooding requires spending
real tokens, which Bob rate-limited at issuance.

**Complexity:** *high.* New issuance endpoint, blind-signature/VOPRF primitive
(not currently in the RustCrypto set the project uses — `k256`/`ed25519`/`x25519`),
a spent-set with durability, token distribution plumbing in the clients, and a key
lifecycle. This is genuine research-grade protocol work.

### Option C — Queue-issued anonymous mailbox tokens (issue-authenticated, spend-anonymous)

**Mechanism.** Keep the wallet login, but split *authenticating* from *depositing*.
A sender logs in (as today) and redeems that login for a batch of **single-use
deposit tokens** that are **unlinkable to the login** — again via blind signatures /
Privacy Pass, but now the queue is issuer *and* verifier and the sender is the
holder. At deposit the sender presents a token, not a session bound to their wallet.
The queue rate-limits **issuance** per authenticated wallet (reusing the existing
`allow(sender, …)` window on the *issue* call), then can't tie the *spent* token
back to the wallet at deposit time.

This is essentially **Signal's delivery-token model** adapted to Mycellium: identity
gates how *many* tokens you get; spending them is anonymous.

**Sender privacy:** *strong for the linkage, with one honest caveat* — the queue
still sees *that a given wallet logged in and drew tokens*, just not *which deposit
each token became*. So the queue learns "A is an active sender" and "B received
mail", but not "A → B". For a single-tenant recipient-owned queue with few senders
and low volume, the anonymity set is small and timing can still correlate an
issuance burst with a deposit burst — a real residual leak worth stating plainly.

**Abuse resistance:** *strong* — issuance is rate-limited exactly as deposits are
today (30/window), so a sender's *total* deposit budget is unchanged; we've only
made the individual deposits unlinkable. No new anti-abuse story is needed; we
reuse the one that already works.

**Blocking:** *weak at the queue* (same as Option A — the queue can't tell whose
token it is, so it can't enforce a recipient's block), *fine at the recipient*
(post-decrypt, on the sealed header). If a recipient block *must* be
queue-enforceable, Option B is the only one that gives it, because there the
*recipient* controls issuance.

**Revocation:** rotate the queue's issuing key (global) or expire tokens on a short
TTL (the queue already prunes by time everywhere). No per-token revocation.

**Replay/flooding:** spent-set single-use, same as Option B.

**Complexity:** *medium-high* — the same blind-token primitive and spent-set as B,
but **no recipient-side issuance/distribution plumbing** and it **reuses the
existing login and rate limiter**. It is the smallest delta from today's queue that
actually severs the linkage.

### Option D — Hybrid: queue-issued tokens (C) with an optional recipient allow-gate (B)

**Mechanism.** Default to Option C (queue-issued anonymous tokens, reusing login +
rate limit) for the *anonymity + abuse* baseline, and let a recipient *optionally*
layer a B-style requirement — "my mailbox only accepts deposits carrying a token I
co-signed" — for correspondents who need **queue-enforced blocking**. Most users get
C's low delta; high-risk recipients opt into B's stronger control at higher cost.

This mirrors the tiered posture already in [`PRIVACY-MODES.md`](../PRIVACY-MODES.md)
(`normal` / `private` / `high-risk`): a cheap always-on default plus a costlier
opt-in for those who want it. Complexity is the union of B and C, so it is a
*later* phase, not a first step.

### Non-starter noted for completeness — proof-of-work only

Per-deposit PoW (#55 lists it) bounds flood *rate* without any identity, which is
attractive for its simplicity and pairs naturally with Option A. But PoW alone gives
**no blocking, no revocation, and no per-recipient budget** — a determined attacker
with compute still fills a 256-slot mailbox, and honest mobile senders pay a battery
cost. Useful only as a *secondary* throttle on an otherwise-unauthenticated path
(A+PoW), never as the primary control. Not recommended as the design.

## What every option leaks anyway

Stated up front so no option is oversold (cross-ref
[`SECURITY.md` → the queue observes](../SECURITY.md#the-queue-observes)):

| Leak | Still present after sealed sender? | Mitigation / owner |
|---|---|---|
| **Recipient wallet + slot** | **Yes** — the mailbox is wallet-addressed; the queue must know *where* to store. | Inherent to per-recipient queues. Rotating/owning your queue (#53, #63) limits *who* sees it. |
| **Deposit + collection timing** | **Yes** | #52 delay/batching blunts fine-grained correlation, not the fact of it. |
| **Approximate size** | **Yes** | #51 padding buckets. |
| **Network origin (sender IP)** | **Yes** — the request still comes from *somewhere*. | Out of scope; needs mixnet/Tor. Never implied solved. |
| **Sender identity to the recipient** | **Yes, by design** | The E2E envelope authenticates the sender to Bob; this is wanted (TOFU, blocklists). |
| **Sender → recipient linkage at the queue** | **No** (the point) — *iff* part 2 (sealed header) ships and, for C, modulo the issuance-burst timing caveat. | This note. |

## Recommendation

**Adopt Option C (queue-issued anonymous deposit tokens) as the target design, with
Option B available later as an opt-in for queue-enforced blocking (the Option D
hybrid). Gate everything behind Part 2 (sealing the envelope header), which should
be treated as a prerequisite and is independently valuable.**

Rationale: C severs the sender→recipient linkage with the **smallest change to the
queue** — it reuses the existing SIWE login and the existing per-wallet rate window,
adding only an issuance step and a spent-set — and it keeps today's proven anti-abuse
budget intact (issuance is throttled exactly like deposits are now). Its honest
weaknesses are (a) no queue-enforced blocking and (b) a small-anonymity-set /
issuance-timing correlation on low-volume single-tenant queues; both are acceptable
for a v1 and both are *documented*, not hidden. B is stronger on blocking and
revocation but pays for it with recipient-side issuance/distribution plumbing and a
per-recipient issuing-key lifecycle — worth offering to high-risk users, not worth
imposing on everyone.

Note that **Part 2 alone is a real, shippable privacy win** even before any token
work: today the queue reads the sender's handle and record out of the cleartext
`Envelope`. Sealing the header removes the *blob-body* leak immediately, leaving only
the *auth-token* leak for the token work to close. Ship it first.

### Phased path

1. **Phase 0 — Part 2, seal the envelope header (independent, ships first).**
   Wrap the full `Envelope` in an X25519 sealed-box to the recipient's published
   `id_key` before deposit, so the stored blob is fully opaque. No queue change; a
   `mycellium-core` sealing addition and an engine deposit/collect change. Closes
   the cleartext-sender leak in the blob body. Update
   [`SECURITY.md`](../SECURITY.md#the-queue-observes) to stop listing the sender as
   readable from the blob (it would remain readable only via the auth token).

2. **Phase 1 — anonymous deposit tokens (Option C).** Add an `/mailbox/token`
   (issue) endpoint: an authenticated wallet redeems its rate-limited budget for N
   blind-signed single-use tokens. Change `deposit()` to accept a **token** instead
   of `authed(token, …)` as the sender identity: verify the token signature, check
   and insert into a **spent-set**, then apply the recipient-side `MAX_MAILBOX` cap
   as today. The per-sender `allow(...)` window moves from `deposit` to the *issue*
   call. Clients fetch a token batch at login and spend one per deposit.

3. **Phase 2 (optional) — recipient allow-gate (Option D/B).** For recipients who
   want queue-enforced blocking, support a per-recipient issuing key so a mailbox
   can require recipient-co-signed tokens; add key rotation as the revocation lever.

### What changes, concretely

- **`mycellium-queue`** (`crates/mycellium-queue/src/lib.rs`):
  - New issue endpoint + `issue_tokens(token, n, now)` returning blind-signed tokens,
    rate-limited via the existing `allow(sender, "issue", now)`.
  - `deposit()` loses `let sender = self.authed(...)?`; instead verifies a token and
    consults a **spent-set** (a new durable map, pruned by token TTL like
    `challenges`/`tokens` already are). Recipient-side caps unchanged.
  - A per-queue issuing keypair (Phase 1) and, in Phase 2, per-recipient issuing
    keys with rotation. Persist analogous to the VAPID key handling.
  - A blind-signature / VOPRF primitive is a **new dependency** outside the current
    `k256`/`ed25519-dalek`/`x25519` set — vet it under the same "vetted primitives,
    never invented" bar as the rest of [`SECURITY.md`](../SECURITY.md#cryptographic-building-blocks).
- **Clients / engine** (`app/messaging.rs`, `QueueTarget`): fetch a token batch on
  `QueueTarget::open`, spend one per `deposit()`, refill when low; add the Phase-0
  sealed-box wrap around the `MailItem` before `serde_json::to_string`.
- **Docs:** update [`SECURITY.md`](../SECURITY.md#the-queue-observes) and
  [`PRIVACY-MODES.md`](../PRIVACY-MODES.md) once Phase 0/1 land, and keep the
  non-anonymity framing intact.

### Honest residual leakage after the recommended design

Even with C + Part 2 fully shipped, the queue still learns the **recipient**, the
**timing**, the **approximate size** (until #51), and the sender's **network
origin**; on a low-volume single-tenant queue it may correlate an issuance burst to
a deposit burst. The recipient still learns the sender (by design). This is a
narrowing of one specific leak — *who sent* — not anonymity, and the docs must
continue to say so.

## Cross-links

- [`SECURITY.md` → Metadata exposure / The queue observes](../SECURITY.md#the-queue-observes)
  — the leak this note addresses, stated as-built.
- [`PRIVACY-MODES.md`](../PRIVACY-MODES.md) — the *size* (#51) and *timing* (#52)
  levers; sealed sender is the orthogonal *who* lever.
- Issue [#48](https://github.com/aristath/mycellium.eu/issues/48) — privacy roadmap
  parent; [#55](https://github.com/aristath/mycellium.eu/issues/55) — this research
  issue; [#53](https://github.com/aristath/mycellium.eu/issues/53)/[#63](https://github.com/aristath/mycellium.eu/issues/63)
  — recipient-owned/rotatable queues that shrink the recipient-side leak.
