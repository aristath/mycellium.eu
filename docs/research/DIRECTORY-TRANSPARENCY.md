# Directory transparency: making handle bindings publicly auditable

*Design for issue #56 (parent #48). A verifiable, append-only transparency log over
the directory's `handle → signed record` bindings, so that a directory that
**equivocates** — serves different or stale bindings to different clients, or
silently rebinds a handle — can be **caught after the fact**. Documentation only; no
code ships with this doc.*

## What this does and does not do

Every directory record is already **wallet-signed and self-certifying**
([`record.rs`](../../crates/mycellium-core/src/record.rs),
[`SECURITY.md` § A dishonest directory](../SECURITY.md#what-we-defend-against)), so
the directory **cannot forge** a record: it can never bind your handle to a wallet
you don't control. That is a signature property and transparency does not change it.

What signatures **don't** stop is a directory that is honest about *authenticity* but
dishonest about *which single binding it is showing the world*. A compelled or
malicious operator can still:

- **Equivocate / split-view** — show client A one record for `bob` and client B a
  different one, each internally valid, so the two never agree on who `bob` is.
- **Roll back** — serve a stale record (lower `seq`) to a chosen victim, hiding that
  `bob` published a newer one (e.g. rotated a compromised device out).
- **Silently rebind** — accept an email-recovery re-bind (a **legitimate** flow; see
  [`SECURITY.md` § Recovery](../SECURITY.md#identity--trust-root)) that points `bob`
  at a new wallet, and reveal it only to the attacker's victim while hiding it from
  `bob` himself.

Transparency makes the directory's bindings **globally verifiable**: it commits the
operator to *one* append-only history that everyone checks against, so any of the
above becomes **detectable**. It is emphatically **detection, not prevention** — the
log does not stop a bad binding from being served for a moment; it guarantees the
misbehavior leaves **non-repudiable evidence** (a signed statement of two conflicting
histories) that self-monitoring clients and independent witnesses will surface. This
is the same posture as Certificate Transparency: CT never blocks a mis-issued
certificate, it makes mis-issuance *impossible to hide*.

It is also **complementary to, not a replacement for, the client-side pinning** in
#57/#58. TOFU pinning catches a key *swap* after first contact, per client, locally.
Transparency catches **first-contact substitution** (there is nothing pinned yet) and
makes the check **global** rather than one-device-at-a-time. The two compose: pinning
is the cheap always-on local guard; transparency is the auditable global backstop.

### Non-goals

- **Not confidentiality.** Directory records are already public
  ([`SECURITY.md` § The directory observes](../SECURITY.md#the-directory-observes));
  the log adds no new metadata leak beyond making the *already-public* bindings
  enumerable. (A prefix-tree design, below, can avoid publishing the full handle set
  in the clear — a modest privacy improvement over a naive public list.)
- **Not availability.** A directory can still withhold a record or refuse service;
  transparency doesn't force it to answer, only to be consistent when it does.
- **Not consensus / not a blockchain.** We do not need global ordering agreement, a
  token, or miners — only an append-only commitment plus gossip. If Mycellium later
  moves the directory on-chain (noted as the ultimate backing store in
  [`lib.rs`](../../crates/mycellium-directory/src/lib.rs)), the log becomes redundant
  with the chain's own history; until then this is the lightweight substitute.

## Prior art we build on

| Source | What we take |
|---|---|
| **Certificate Transparency** (RFC 6962) | Append-only Merkle **log tree**; **inclusion** + **consistency** proofs; Signed Tree Heads (STHs); gossip between clients + independent **monitors/auditors**. |
| **CONIKS** | Per-**identity** key binding in a **prefix (Merkle) tree** keyed by handle, giving efficient **absence / non-membership** proofs and cheap **self-monitoring** ("is my own binding what I last set it to?"). |
| **Google Key Transparency** | Productionized CONIKS: an ordered log **of** tree heads (a "log-backed map"), so the map's evolution is itself append-only and auditable, plus witnessing. |

Mycellium's need is exactly the CONIKS/KT problem — *bind a human-meaningful name to a
key, let the owner audit it, let third parties detect equivocation* — so the design
leans on KT's log-backed-map shape rather than a bare CT log.

## The log

### Entry shape

The unit of the log is a **binding entry**: an assertion that at a point in time the
directory considered a handle bound to a specific signed record. It contains only
hashes and metadata — never anything not already public.

```
BindingEntry {
    handle_id:    [u8; 32],   // user_id(handle) — the hashed id the directory keys on,
                              //   NOT the raw handle (see § Privacy of the leaf set)
    record_hash:  [u8; 32],   // SHA-256 over SignedRecord wire bytes (wire::encode)
    wallet:       [u8; 33],   // the bound wallet (secp256k1 compressed) — redundant
                              //   with the record but cheap and useful to auditors
    seq:          u64,        // the record's monotonic seq (anti-rollback, Layer 9.4)
    logged_at:    u64,        // directory unix seconds when appended
    prev_hash:    [u8; 32],   // record_hash of this handle's previous entry, or 0
}
```

`record_hash` binds the log to the **exact** self-signed `SignedRecord` the directory
holds. `prev_hash` chains a handle's own history so a rebind is explicitly a *link*
from the old binding to the new one, not an unrelated fact — this is what makes a
legitimate email-recovery rebind show up as a first-class, notifiable event
(§ Email recovery). The append is a pure directory-side action; entries are **not**
signed by the user (the user already signed the underlying record — signing the log
position too would need an online user on every append and buys nothing).

### Tree structure — a log-backed map

Two Merkle structures, following KT:

1. **Prefix tree (the "map"), keyed by `handle_id`.** A sparse Merkle / CONIKS-style
   tree whose leaf at path `handle_id` holds that handle's **current** binding entry.
   Because the key space is the fixed 256-bit `handle_id`, the tree gives:
   - an **inclusion** proof that `handle_id → entry` (a Merkle path to the leaf), and
   - an **absence** proof that a handle is *unbound* or that no *second* binding
     exists (a path to an empty leaf) — the property a plain log can't give cheaply.
2. **Log tree (the "history"), append-only.** Each time the map changes, its new root
   is appended as a leaf of a CT-style append-only log tree. This log is what
   **consistency** proofs run over: it proves the map only ever moved *forward*, never
   silently rewrote a past state.

The head published by the directory is a **Signed Tree Head (STH)**:

```
STH {
    tree_size:   u64,        // number of log entries (map revisions) so far
    log_root:    [u8; 32],   // root of the append-only log tree
    map_root:    [u8; 32],   // root of the current prefix/map tree
    timestamp:   u64,
    directory_sig: Signature // directory's own long-term Ed25519 key over the above
}
```

The STH is the single object the directory is **committed** to. Everything a client
verifies reduces to "this fact is consistent with an STH I (or a witness) accept."

### The three proofs

- **Inclusion proof** — *"my record is in the log the directory shows everyone."* A
  client fetches the Merkle path from its `handle_id` leaf up to `map_root`, plus the
  map-root-in-log path up to `log_root`, and checks both against a current STH. Cost:
  `O(log n)` hashes (~32 nodes × 32 B ≈ 1 KiB for millions of handles). A record that
  verifies by signature **and** proves inclusion is one the directory has publicly,
  irrevocably committed to.
- **Consistency proof** — *"the log was only appended to, never rewritten."* Given an
  older STH (`tree_size = m`) and a newer one (`tree_size = n ≥ m`), a CT consistency
  proof shows the size-`m` tree is a **prefix** of the size-`n` tree. Any client (or
  witness) that has ever seen an STH checks every later STH is consistent with it — a
  directory that tries to un-say a past binding cannot produce a valid consistency
  proof, and the mismatch is the evidence of tampering.
- **Absence / non-equivocation proof** — *"there is exactly **one** current binding
  for this handle, and it's the record I was served."* On lookup the client asks for
  (a) the record, and (b) an inclusion proof that `handle_id`'s **map leaf** is exactly
  `hash(served record)`. Because a prefix tree has a **single** leaf per key, the
  directory cannot present a valid map-inclusion proof for *two different* current
  records under one STH — split-view within a single tree is structurally impossible.
  Equivocation is therefore pushed out to the only place it can still hide: showing
  **different STHs** to different clients. That is what witnessing closes.

### Split-view resistance — gossip and witnesses

A prefix tree stops per-tree equivocation; it does **not**, by itself, stop the
directory from maintaining **two trees** and showing STH-A to Alice and STH-B to Bob.
The classic fix is to make the STH **hard to fork**:

- **Witness co-signing (primary).** A small set of **independent witnesses** (run by
  parties who are not the directory operator — see § Who runs what) each maintain the
  latest STH they've seen, verify every new STH is **consistent** with their previous
  one, and **co-sign** it. A client accepts an STH only if it carries a **threshold**
  (e.g. `k` of `n`) of witness co-signatures. To equivocate, the directory would have
  to get a threshold of independent witnesses to *each* sign **two** conflicting heads
  at the same size — a witness that does so is itself caught, because it signed two
  inconsistent STHs (non-repudiable). This is exactly the "witness / STH gossip"
  approach CT is moving to and what KT deploys.
- **Client gossip (secondary, cheap).** Clients (and monitors) occasionally exchange
  the STHs they've seen — piggybacked on traffic they already exchange, e.g. inside a
  session handshake or an out-of-band safety-number comparison (ties naturally into
  the #57/#58 verification UX). Two honest clients holding **inconsistent** STHs of
  the same log is proof of equivocation. Gossip needs no new infrastructure and raises
  the odds that a split view is noticed even before witnesses catch it.

### Self-monitoring — detecting a rebind of your **own** handle

This is the property users care about most, and the cheapest to provide. Each client
**monitors its own handle**:

1. The client remembers the `record_hash`/`seq`/`prev_hash` of the binding **it last
   published** for its handle.
2. Periodically (and on every login/heartbeat round-trip, which the client already
   makes — [`lib.rs` `heartbeat`](../../crates/mycellium-directory/src/lib.rs)) it
   fetches the current map leaf + inclusion proof for its `handle_id` under a
   witnessed STH.
3. If the logged current binding is **not** the one it last set — a different wallet,
   a higher `seq` it didn't publish, an unexpected `prev_hash` link — **someone
   rebound the handle without this device's action.** The client raises a loud,
   security-grade alert (the same class of UI as a #57/#58 key-change warning).

Crucially this works **even for a legitimate email recovery**: recovery *is* a rebind,
and the logged entry is precisely how the previous owner learns "my handle now points
at a new wallet." If that recovery was theirs (they still hold the email), it's
expected; if it wasn't, they've just detected an account takeover the instant it was
logged, rather than never. Monitoring is `O(log n)` bandwidth on a cadence the user
chooses; a mobile client can do it lazily (below).

## Mapping onto Mycellium's architecture

### Where it plugs in

The directory already has the two ingredients this needs:

- **Authoritative writes in one place.** Every binding change flows through
  [`Directory::publish`](../../crates/mycellium-directory/src/lib.rs) (record update)
  or [`Directory::auth_confirm`](../../crates/mycellium-directory/src/lib.rs)
  (email-recovery rebind). These are the **only** two call sites that mutate
  `bindings`/`records`, so they are the **only** two places that must also **append a
  `BindingEntry`** and recompute the STH. That is a tight, auditable surface.
- **Durable, transactional storage.** [`persist.rs`](../../crates/mycellium-directory/src/persist.rs)
  already write-throughs bindings/records/emails in `redb` transactions (e.g.
  `put_binding_and_record`). The log tree, map tree, and the latest STH become
  **additional tables written in the same transaction** as the binding — so a binding
  and its log entry are **atomically** consistent (no "recorded but not logged" or
  vice-versa window), exactly as the existing code already couples a binding and its
  email hash in one write.

Concretely, `publish`/`auth_confirm` gain a step after the durable put succeeds:
compute `record_hash`, form the `BindingEntry` (with `prev_hash` = the handle's prior
leaf), update the sparse map, append the new map root to the log tree, re-sign the
STH, and (phase 2) fan it out to witnesses for co-signing before it is served.

### New read endpoints

Alongside the existing `GET /records/{handle}`
([`http.rs`](../../crates/mycellium-directory/src/http.rs)):

- `GET /log/sth` → the current (witness-co-signed) STH.
- `GET /log/proof/{handle}` → map-inclusion (or absence) proof for `handle_id` under
  the current STH. Returned **alongside** the record on lookup so a client verifies in
  one round trip.
- `GET /log/consistency?from={m}&to={n}` → consistency proof between two tree sizes.
- `GET /log/entries?from=&to=` → raw entries, for **monitors/auditors** that mirror
  the whole log (not needed by thin clients).

### Who runs what

- **The directory** runs the log: it appends, maintains the trees, signs STHs. It is
  still **untrusted** — the whole point is that its misbehavior is catchable.
- **Witnesses** are run by parties distinct from the operator — candidates: other
  Mycellium directory operators (mutual witnessing), community/foundation infra, or
  privacy orgs. A witness is cheap: it stores only the latest STH it co-signed and
  verifies consistency on each new one. `k`-of-`n` threshold and the witness set are
  configuration a client ships with (like CT's trusted-log list).
- **Monitors** (optional, heavier) mirror the full log and scan for anomalies (e.g. a
  handle rebinding suspiciously often). Any user *is* a minimal monitor of their **own**
  handle for free; org-scale monitors are a later, external add-on.

### Thin (mobile) clients

Mobile clients do **not** mirror the log. They do the cheap subset:

- On lookup: verify the served record's **signature** (already happens) **plus** its
  **map-inclusion proof** against the latest **witness-co-signed STH** — ~1–2 KiB
  extra, a handful of hashes, negligible CPU.
- Keep the **last STH** they accepted and check each new one is **consistent** with it
  (a few KiB, `O(log n)`), so they'd catch a rollback of the whole log.
- **Self-monitor** their own handle on the login/heartbeat cadence they already run.

They lean on **witnesses** for split-view resistance (they can't gossip with the whole
network), which is exactly why witnessing is the load-bearing phase-2 mechanism for
thin clients. Bandwidth cost is dominated by the STH + one inclusion proof per lookup:
low single-digit KiB, comparable to the record itself.

### Interaction with email recovery — a legitimate rebind stays auditable

The email-recovery rebind in
[`auth_confirm`](../../crates/mycellium-directory/src/lib.rs) — a **new** device key
re-binding a handle after proving control of the registered email — **must remain
allowed**; it is the only recovery path when every device is lost
([`SECURITY.md`](../SECURITY.md#identity--trust-root)). Transparency does not block it;
it makes it **loud**:

- The rebind appends a `BindingEntry` whose `prev_hash` links it to the old binding
  and whose `wallet` differs — an explicit, logged "handle changed hands" event.
- The **previous** owner's self-monitoring (if they still have a device) sees the new
  leaf and is alerted. Peers, via #57/#58 TOFU, already see a new key and re-verify;
  now they *also* have a logged, witnessed record that the change was real and singular
  (not a targeted lie shown only to them).
- This is the intended design tension made honest: recovery is a feature, and its
  side-effect (a key change) is precisely the kind of event the log exists to publish.

## Threat coverage summary

| Threat | Without the log | With the log |
|---|---|---|
| Forge a record | Already impossible (wallet signature) | Unchanged |
| Serve **stale** record (rollback) to a victim | Possible; only caught if victim knows a newer `seq` exists | Caught: consistency proof + self-monitor see the higher `seq` was logged |
| **Split-view** (different record to A vs B) | Undetectable across clients | Structurally impossible within one STH; across STHs, caught by witnesses + gossip |
| **Silent rebind** of a handle | Only the affected peers notice a key change (TOFU), locally | Logged event; owner self-monitors and is alerted; globally visible |
| Legitimate email recovery | Happens; peers re-verify | Same, **plus** an auditable, notifiable log entry |
| Withhold a record entirely | Possible | **Still possible** — availability is out of scope |

## Phased plan

**Phase 0 — foundations (this doc + small core additions).** Define `BindingEntry`,
`record_hash` (reuse `wire::encode` + SHA-256), and the STH struct in
`mycellium-core`. No behavior change.

**Phase 1 — minimum viable transparency (single-operator).**
- Log tree + prefix/map tree + STH, maintained in
  [`persist.rs`](../../crates/mycellium-directory/src/persist.rs), written **in the
  same transaction** as each binding in `publish`/`auth_confirm`.
- STH signed by the directory's own key; `GET /log/sth`, `/log/proof/{handle}`,
  `/log/consistency`.
- Clients verify **inclusion** on lookup and **consistency** across STHs, and
  **self-monitor** their own handle on the existing heartbeat cadence.
- *Value already delivered:* rollback and same-tree split-view become impossible to
  hide **to any client that checks**; a user detects an unauthorized rebind of their
  own handle. The residual gap is a directory showing **different STHs** to different
  clients — mitigated only by gossip in this phase.

**Phase 2 — witnessing + gossip (multi-party non-equivocation).**
- Define the witness protocol (submit STH → verify consistency → co-sign) and a
  `k`-of-`n` witness set clients ship with.
- Directory obtains threshold co-signatures **before** serving an STH; clients reject
  under-signed STHs.
- Client-to-client STH gossip piggybacked on the #57/#58 verification exchange.
- *Value:* cross-STH split-view now requires corrupting a threshold of independent
  witnesses, each of which would itself be caught.

**Phase 3 (optional) — ecosystem.** Public monitors, a privacy-preserving leaf set
(publish `handle_id`, not raw handles, and lean on the prefix tree's absence proofs so
the full namespace need not be enumerable), and — if/when the directory moves on-chain
— folding the log into the chain's native history.

### Rough change footprint

- **`mycellium-core`** — new `transparency` module: `BindingEntry`, `Sth`,
  `record_hash`, Merkle map + log verification (proof **checking** is shared by every
  client and must be `no_std`-friendly, like the rest of core).
- **`mycellium-directory`** — tree maintenance + STH signing in `persist.rs`; append
  step in `publish`/`auth_confirm` ([`lib.rs`](../../crates/mycellium-directory/src/lib.rs));
  new read routes in [`http.rs`](../../crates/mycellium-directory/src/http.rs); phase-2
  witness client.
- **Clients / engine** — request + verify inclusion on lookup, track + check STH
  consistency, self-monitor own handle, surface a rebind/equivocation alert reusing the
  #57/#58 key-change warning UI. Thin-client path stays within a few KiB per lookup.

## See also

- [`SECURITY.md`](../SECURITY.md) — the directory threat model this refines
  (§ *A dishonest directory*, § *The directory observes*).
- **#57 / #58** — client-side TOFU wallet pinning and key-change warnings; the local,
  always-on complement whose UX this reuses for equivocation/rebind alerts.
- **#48** — the parent privacy / metadata / trust track
  ([roadmap](https://github.com/aristath/mycellium.eu/issues/48)); sibling design
  [`PRIVACY-MODES.md`](../PRIVACY-MODES.md) (#50).
- [`record.rs`](../../crates/mycellium-core/src/record.rs),
  [`directory/lib.rs`](../../crates/mycellium-directory/src/lib.rs),
  [`persist.rs`](../../crates/mycellium-directory/src/persist.rs) — the record format,
  the two binding write-paths, and the durable store this integrates with.
