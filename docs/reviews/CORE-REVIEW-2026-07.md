# Mycellium core review — 2026-07

A complete adversarial security + correctness review of the **core** (crypto,
protocol, engine, services, storage/transport) — clients excluded. Threat model:
a malicious peer, a malicious/compelled directory + queue, and an active network
attacker. Method: five parallel deep reviewers, one per area, each producing
findings with concrete exploit scenarios and `file:line`; the material findings
were then re-traced in-code.

## Headline

**The cryptographic *design* is sound.** X3DH (DH combination + identity binding +
contributory-key rejection), device pairing, record signing (complete coverage,
deterministic/injective encoding, verify-by-re-serialization), domain separation,
AEAD nonce derivation (key+nonce from a single-use message key — no reuse surface),
group sender-key crypto (authenticated sender, cross-group-replay resistant),
handle↔wallet binding, server publish-authorization + email-recovery, at-rest AEAD
(fresh nonce+salt per write), and end-to-end authentication of *relayed* peers were
all checked and hold up.

**The defects are localized implementation gaps**, clustering in four themes:

1. **The Double Ratchet `decrypt` is not fail-closed** — it can be panicked and
   permanently desynced by one unauthenticated packet (and desyncs under *ordinary*
   at-least-once queue re-delivery, no attacker needed).
2. **Sender-identity binding is enforced on the 1:1 offline path (`open_envelope`)
   but omitted on several sibling inbound paths** — self-sync, group-sync,
   group-invite, the live-chat responder, and group per-member key distribution.
3. **Anti-rollback is trusted from the untrusted directory** — the signed `seq`
   exists for exactly this, but no client pins it.
4. **Server availability/resource bounds** — an SSRF via client-supplied push
   endpoints, and unbounded mailbox/challenge growth.

Nothing found breaks the confidentiality of an established pairwise E2E channel, lets
a non-member forge authenticated group messages, or bypasses server auth (publish,
login, deposit, collect all verified sound).

## Findings by severity

Severity key: **HIGH** = exploitable in-threat-model or a correctness break that bites
real users; **MEDIUM** = member-/resource-driven DoS or attribution confusion;
**LOW/INFO** = hardening / defense-in-depth. All HIGH items below were re-traced
in-code (✓ verified) or are backed by a concrete reviewer trace.

### HIGH

1. **Ratchet remote panic (DoS)** — `crates/mycellium-core/src/ratchet.rs:175` ✓verified.
   A fresh initiator sits at `ckr: None, dhr: Some(responder_spk)`. The responder's
   signed pre-key is *public* (directory record). One `RatchetMessage` with
   `header.dh = responder_spk` makes `self.dhr != Some(header_dh)` false → the DH step
   is skipped → `ckr` stays `None` → `self.ckr.expect(...)` panics. No secret needed;
   ciphertext never checked.
   **Fix:** return `Err(DecryptFailed)` instead of `expect` on peer-steerable state.

2. **Ratchet state mutated without rollback on AEAD failure** —
   `ratchet.rs:168–181` ✓verified. `dh_ratchet` (advances `root`/`dhr`/`ckr`) and the
   `ckr`/`nr` advance commit *before* `aead_decrypt`, and its `Err` is returned with
   nothing rolled back (violates the Signal "discard state on failure" rule). (a)
   Attacker: one packet with a fresh valid `header.dh` + garbage advances the root off
   a DH the real peer never did → permanent desync. (b) **No attacker:** a re-delivered
   already-consumed message (`header.n < nr`) makes `skip_message_keys` a no-op, then
   consumes the current chain key and bumps `nr` → the next real message is lost. The
   queue is at-least-once, so duplicate delivery corrupts sessions.
   **Fix:** operate on a snapshot/clone of receive state, commit only after
   `aead_decrypt` succeeds; reject `header.n < nr` replays not covered by a stored key.

3. **Client-side anti-rollback missing (directory downgrade)** —
   `crates/mycellium-core/src/record.rs:90`, client lookups in
   `crates/mycellium-sdk/src/client.rs:530,576,607,1050`. `seq` monotonicity is enforced
   only server-side; no client pins the highest `seq` seen per peer. A malicious/compelled
   directory serves an *older, validly-signed, same-wallet* record — the "identity changed"
   guard only catches wallet *swaps*, so it doesn't fire. If the victim had published a
   newer record that *removed* a lost/compromised device, the rollback re-introduces it and
   senders `seal_to` it → the attacker decrypts. Also rolls `queue`/`queues`/relay back to
   an attacker endpoint.
   **Fix:** persist highest-seen `seq` per pinned handle; treat a regression like
   `IdentityChanged` (fail-closed).

4. **Self-sync accepts forged "sent-by-me" items from any peer** —
   `crates/mycellium-engine/src/app/messaging.rs:920–949` ✓verified. `handle_self_sync`
   discards the authenticated sender (`let (_from, …)`) yet writes `from_me: true` and
   applies `Edit`/`Delete` with `by_me: true`. Anyone who can seal a valid envelope to the
   victim (their own real identity passes `open_envelope`) can wrap it as
   `SelfSync { peer, envelope }` and deposit it (any wallet may deposit to any mailbox) to:
   fabricate outgoing messages in any transcript, or **edit/delete the victim's genuine
   outgoing messages** by id (`by_me:true` matches their real `from_me:true` entries). The
   `MailItem` doc *claims* this is authenticated device→device; the code doesn't enforce it.
   **Fix:** reject unless `env.sender_record.record.wallet == identity.wallet_public()`.

5. **Live-chat responder doesn't bind the X3DH init to the peer's record** —
   `crates/mycellium-engine/src/app/session.rs:58–84`. `handshake_responder` verifies the
   peer's record + name but never checks `init.initiator_ik == peer_record.record.primary().id_key`
   (the binding `open_envelope` does). An attacker fetches Victim's public record, connects to
   Bob's `listen`/`serve`, sends `[Victim's record][name][attacker init]`, and completes a
   session Bob labels "Victim" — and the printed **safety number** (from Victim's real wallet)
   *matches*, defeating the out-of-band defense. TCP `listen` has no transport auth; libp2p's
   Noise peer-id is also not cross-checked against `primary().device_key`.
   **Fix:** after verifying the record, `bail!` unless `init.initiator_ik == primary().id_key`.

6. **SSRF via client-supplied push endpoint** —
   `crates/mycellium-queue/src/push.rs:88,116` + `lib.rs:876`. The endpoint URL the queue POSTs
   to is client-controlled, validated only by an `https://` prefix + 2048-byte cap. No block on
   `169.254.169.254`, `127.0.0.1`, RFC1918, `metadata.google.internal`, `[::1]`. A free wallet
   subscribes ≤20 internal endpoints and self-deposits to fan out ~600 internal POSTs/min from the
   queue host (blind — `SendResult` isn't returned, which keeps it high not critical; `ureq` v2
   also follows redirects, enabling `https→http` downgrade to metadata).
   **Fix:** resolve + reject loopback/link-local/private/unspecified ranges (ideally a provider
   allowlist), pin the resolved IP (anti-rebind), build the agent with `.redirects(0)`.

7. **Unbounded mailbox creation (disk/memory exhaustion)** —
   `crates/mycellium-queue/src/lib.rs:324–353`. `deposit` mints a durable mailbox for *any*
   66-hex wallet + any slot, up to 256×1 MiB each, with **no global cap and no TTL** (only the
   per-sender 30/window rate limit, and wallets are free). ~43 GB/day/wallet, unbounded in
   aggregate. Contrast the pairing/rate maps, which *are* capped.
   **Fix:** global mailbox-count / total-bytes ceiling; consider refusing deposits to wallets that
   never logged in / have no subscription.

### MEDIUM

- **Group `skipped` message-key set grows unbounded** — `core/group.rs:146–166`. `MAX_SKIP`
  bounds only the per-call gap; a member sending at iterations 1024, 2049, 3074… banks ~1024 keys
  each, persisted into `GroupState`. **Fix:** cap total `skipped.len()`.
- **Group `sender_id` not bound to the authenticated pairwise sender** — `core/group.rs:203–207`,
  `engine/app/grouping.rs:158,200`. `sender_id` comes from the invite payload and `add_member`
  overwrites unconditionally; an attacker can clobber a real member's `signing_public` so that
  member's later (valid) messages fail `verify_strict` (silent denial), and inject attacker-chosen
  rosters. Not full impersonation (display uses the authenticated `from`). **Fix:** bind
  `sender_id` to `from`; refuse overwrites that change an existing id's key.
- **Group-sync bootstrap trusts any sender** — `engine/app/grouping.rs:593–636`. `handle_group_sync`
  discards `_from`; any peer can hand you a `GroupSyncPayload` → you bootstrap a fake group and
  `distribute_key` your sender key to attacker-chosen members. Guarded to *new* groups only.
  **Fix:** require `env.sender_record.record.wallet == identity.wallet_public()`.
- **GroupInvite for an existing group doesn't verify the inviter is a member** —
  `engine/app/grouping.rs:145–230`. Anyone who learns a `group_id` (it's cleartext in every group
  `MailItem`) can send a valid invite as themselves → inject their sender key (messages accepted +
  displayed) and add members you then leak your key to. The counterpart of the (correct) leave
  auth. **Fix:** require `stored.members.contains(from)` before roster mutation.
- **Group send paths skip the pin/`verified` trust check that 1:1 enforces** —
  `engine/app/messaging.rs:556`, `grouping.rs:82`. `group_send`/`distribute_key_to`/`group_leave`/
  invite-newcomer only do `lookup + verify()`, never `verified::level`. A compelled directory that
  swaps a member's wallet is refused on 1:1 but silently accepted for group key distribution → your
  sender key is sealed to the impersonator. **Fix:** route group per-member resolution through the
  same `level(...) != Changed` fail-closed check.
- **`FileStore` at-rest records aren't bound to their logical key** —
  `crates/mycellium-storage/src/filestore.rs:60–73`. One key for all entries, no AEAD associated
  data; the filename isn't authenticated. An at-rest *write* attacker can relocate a ciphertext
  between files (swap the stored `K_DIR`↔`K_QUEUE` blobs to redirect traffic) or roll back a record
  to an earlier captured ciphertext — the tag doesn't catch it. **Fix:** pass the logical key (and a
  version/counter) as AEAD AD; same idea for `store.rs`/`secrets.rs`.
- **HTTP client has no timeouts** — `crates/mycellium-http/src/lib.rs:38–54`. `ureq` default agent
  has no connect/read timeout; the byte cap bounds size, not time, so a slow-loris directory/queue
  pins the caller's thread indefinitely (the TCP transport got timeouts; this didn't). **Fix:** a
  shared agent with connect/read/write timeouts.
- **Unbounded login-challenge map** — `directory/lib.rs:278`, `queue/lib.rs:198`. Unauthenticated
  `challenge()` inserts per call with only TTL-based `retain` (nothing evicted while fresh); a flood
  accumulates for `CHALLENGE_TTL`=300 s with no size cap (unlike the pairing/rate maps). **Fix:** hard
  size ceiling matching the sibling maps.
- **Targeted mailbox-flooding blocks a victim's inbound** — `queue/lib.rs:343`. `MAX_MAILBOX` rejects
  (never evicts), so an attacker keeping a victim's `account` slot full bounces legitimate senders
  (`MailboxFull`). Self-heals on the victim's next collect. **Fix:** per-(sender,recipient) sub-limit
  or known-contact requirement.

### LOW / INFO

- **1:1 messages/receipts not idempotent** — `engine/app/messaging.rs:990,843`. `handle_direct`
  appends with no dedup on `app.id` and re-sends a receipt; a re-served blob (crash or malicious
  queue) duplicates transcript entries + receipts. (Group text is protected by the sender-key ratchet.)
  **Fix:** dedup Direct on `app.id`.
- **`send_receipt` has no pin check** — `messaging.rs:1024`. Post-swap an impersonator gets the "read"
  signal (metadata leak; inbound receipts are display-only).
- **`Record::primary()` panics on an empty device set** — `core/record.rs:96`. `verify()` rejects
  empty devices, but `primary()` is public and called pre-verify in places (`session.rs:28`,
  `cli/main.rs:745`). **Fix:** return `Option`, or guarantee verify precedes access.
- **secp256k1 ECDSA malleable (high-S)** — `core/identity.rs:90`. Not a forgery; only matters if
  signature bytes are ever used as a unique id. Device/group sigs use non-malleable `verify_strict`.
- **`Body::File`/`String` unbounded at the type layer** — `core/message.rs:41`. Transitively capped by
  the queue's 1 MiB body limit; add an explicit ceiling in `decode` for defense-in-depth.
- **HTTP redirects followed cross-scheme/host** — `http/lib.rs:38`. A hostile directory could 302 to
  `http://` (metadata-channel downgrade) or internal. **Fix:** `.redirects(0)` / same-scheme guard.
- **Passphrase + derived keys not zeroized** — `store.rs:143`, `secrets.rs:106,129`,
  `core/x3dh.rs:85`, `core/ratchet.rs` `mk`. `Identity` zeroizes; these intermediate buffers linger
  (core-dump/swap exposure). **Fix:** `zeroize::Zeroizing` (already a dep).
- **Plaintext dev secret store reachable via the short `new()` constructor** — `sdk/client.rs:174`.
  Not the default ergonomic path, but `MyceliumClient::new` silently wires it in with no runtime warning.
  **Fix:** warn on first use, `cfg`/feature-gate, or rename to `new_insecure_plaintext`.
- **Open Circuit-Relay by default** — `transport/libp2p_net.rs:98`. Every node relays for strangers
  (bounded by libp2p defaults). **Fix:** gate behind an explicit opt-in if undesired.
- **Deposit mutates memory before persisting** — `queue/lib.rs:346`. `push` before `put_mailbox`; on a
  storage error the blob is already in memory (the directory's `publish` persists first). Mirror that.
- **`Mutex::lock().unwrap()` poisoning** — `serve` + both http layers. No request-controlled panic found
  inside a critical section, but a poisoned lock would cause sustained 500s. **Fix:** recover the guard
  or `parking_lot::Mutex`.
- **No one-time pre-keys → first offline message replayable** — `core/x3dh.rs`/`offline.rs` (documented,
  deferred to "Layer 8.7"). App-layer id dedup is the only current defense; ties to the 1:1 idempotency
  item above.

## Verified SAFE (checked, not defects)

- **`open_envelope`** (`engine/wireops.rs:151`) — verifies the wallet-signed sender record, binds
  `from`→handle and `init.initiator_ik`→`primary().id_key` **before** decrypt; decrypt-then-unpad fails
  closed. This is the correct model the responder/self-sync paths omit.
- **Record signing** — complete field coverage, deterministic/injective postcard, `verify()`
  re-serializes (defeats varint malleability), domain-separated (`record-v2` vs `prekey-v1`), all bounds
  (`MAX_DEVICES`=32, id/name/queue caps) enforced post-signature.
- **Server auth** — publish (session wallet == record wallet + self-signature + permanent handle
  binding), email-recovery (same-email-hash proof + code only to that inbox + attempt cap), seq
  (`<=` rejected as Stale), login nonces (128-bit CSPRNG, wallet-bound, TTL, one-time), tokens (192-bit,
  per-action TTL), collect (owning wallet only). All with negative tests.
- **Group crypto** — `verify_strict` before any state change, replay (`target < iteration`) rejected,
  `MAX_SKIP` per-call cap, `group_ad(group_id)` binds ciphertext to its group; GroupLeave is
  authenticated + membership-checked (#24/#25).
- **Padding** (`wireops.rs unpad_bucket`) — bounds-safe (`get(0..4)`, `checked_add`, range filter), length
  prefix inside the AEAD.
- **Delivery ladder** — queue/outbox floor preserved on every path; scoring only reorders.
- **At-rest crypto** — fresh random nonce (12B) + salt (16B) per write; ChaCha20-Poly1305 + Argon2id
  (OWASP-min params) + HKDF-SHA512 storage subkey; fail-closed decrypt.
- **Transport** — frame length bounded (`> MAX_FRAME` rejected before alloc) on both TCP + libp2p;
  stalled-peer timeouts (tested); **relayed peers stay end-to-end Noise-authenticated** (the relay only
  forwards ciphertext; PeerId = Noise static-key hash).
- **Serve runtime** — body limit rejects over-cap before buffering; observe middleware logs only the
  matched-route template (never a handle/wallet/email); contentless push verified with a CI regression
  guard; persistence fails closed on durable-intent.
- **`history.rs` postcard back-compat** — REFUTED as a risk: `StoredMessage`/`GroupStoredMessage` were
  born with `expires_at`, so no persisted blob predates the field; no silent data loss. (`outbox.rs`
  correctly uses an `OldOutboxEntry` fallback — the right pattern if a field is appended later.)

## Recommended remediation order

1. **Ratchet `decrypt` fail-closed** (HIGH 1+2) — one change fixes both; also fixes a real
   duplicate-delivery correctness bug. Highest priority.
2. **Sender-identity binding** on `handle_self_sync`, `handshake_responder`, `handle_group_sync`,
   `handle_group_invite` (existing-group), and group per-member `verified::level` (HIGH 4+5, MEDIUM
   group items) — all the same small check the 1:1 path already demonstrates.
3. **Client-side `seq` pinning** (HIGH 3) — persist highest-seen `seq`, fail-closed on regression.
4. **Queue hardening** — SSRF host guard + `.redirects(0)` (HIGH 6); global mailbox/challenge ceilings
   (HIGH 7, MEDIUM) (services).
5. **At-rest AEAD AD**, **HTTP timeouts**, group `skipped` cap (MEDIUM).
6. LOW/INFO hardening.

The design is production-grade; closing items 1–4 brings the *implementation* up to the design's own
stated guarantees.
