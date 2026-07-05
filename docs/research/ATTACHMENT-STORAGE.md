# Out-of-band encrypted attachment storage

*Design for issue #61 (parent #48). A blob store that holds only ciphertext, so
large files can be sent without bloating the end-to-end message path — while the
store learns nothing but sizes, timing, and access patterns. Documentation only;
no code ships with this doc.*

## The problem today

Attachments are carried **inline** in the sealed message body. `Body::File { name,
mime, data }` (`crates/mycellium-core/src/message.rs`) puts the raw bytes inside
the same `AppMessage` that gets encrypted end-to-end and deposited into the
recipient's queue. Two consequences follow:

- **Large files don't work.** The whole file rides one X3DH/ratchet envelope, and
  the queue caps a deposit at `MAX_BODY = 1 MiB` (`crates/mycellium-queue/src/lib.rs`),
  with attachments kept to ~256 KiB in practice (the top padding bucket, see #51).
  A photo, a PDF, a short voice note routinely exceed that.
- **Every attachment bloats the message path.** Even a file that *fits* is stored
  and forwarded as one monolithic blob in the mailbox, re-sent on every retry,
  counted against the per-mailbox cap (`MAX_MAILBOX = 256`), and pushed through the
  ratchet as a single message. The queued blob is as big as the file.

Inline delivery is the right default for *small* attachments — it needs no extra
service, inherits the message path's forward secrecy and authenticity for free, and
leaks nothing beyond the padded size already covered by #51. This design keeps that
path unchanged and adds an **optional** out-of-band path for files above a
threshold.

## The scheme

Split the file from its key. The **ciphertext** goes to a blob store that never
sees the key; the **key** (plus enough metadata to fetch and verify) rides the
existing end-to-end message, which the store never sees.

Sending a large attachment:

1. **Generate a fresh random symmetric key** `K` (32 bytes, from the OS CSPRNG) —
   one per file, never reused, never derived from content (see
   [Why not convergent encryption](#dedup-and-why-not-convergent-encryption)).
2. **Chunk and encrypt.** Split the plaintext into fixed-size chunks (proposal:
   64 KiB). Encrypt each chunk with ChaCha20-Poly1305 (the message AEAD already in
   the stack — see [`SECURITY.md`](../SECURITY.md#cryptographic-building-blocks))
   under a per-chunk key/nonce derived from `K` via HKDF with the chunk index, so
   nonces never collide and chunks can't be reordered, dropped, or spliced between
   blobs without detection. The last chunk is padded to the chunk size (with a
   length prefix, exactly like #51's padded-payload framing) so the store can't
   read the exact file length off the final chunk.
3. **Content-address the ciphertext.** Compute `H = SHA-256(ciphertext)` over the
   full encrypted blob. The store addresses the blob by an opaque id; `H` is what
   the recipient checks (see [Integrity](#integrity-and-authenticity)).
4. **Upload the ciphertext** to the blob store (resumable/chunked, below). The
   store returns/accepts a blob id.
5. **Send a reference, not the bytes.** The end-to-end message carries a new
   `Body::FileRef` (below) with: the blob store URL + id, the key `K`, the content
   hash `H`, the total size, the chunk size, and the (optional) `mime`/`name`. This
   reference is small and fixed-shape, so it pads into a tiny bucket like any text
   message.

Receiving:

1. Read `Body::FileRef` from the decrypted message. Now the recipient holds `K`,
   `H`, the blob URL, and sizes.
2. **Fetch the ciphertext** from the store by id (resumable). Verify `SHA-256` of
   what arrived equals `H` **before** trusting a byte — a tampered or substituted
   blob is rejected here.
3. **Decrypt chunk by chunk** with `K`; any chunk that fails its AEAD tag aborts the
   whole file. Strip the last-chunk padding using its length prefix.
4. Save the plaintext exactly as inline attachments are saved today
   (`save_attachment` in `crates/mycellium-engine/src/app/util.rs`: sanitized to a
   basename, written under the downloads directory).

The key never touches the store; the store never touches the plaintext; neither the
store nor the queue ever holds both halves.

## Trust model

The blob store is a **separate** service from the directory and the queue, and it
sees only opaque ciphertext plus the shape of access to it. Keeping it separate is
what makes the metadata story hold: the store never learns the message-level
who-talks-to-whom linkage the queue has, because references are end-to-end sealed
and it never sees them.

**What the store CAN see:**

- **Blob sizes** — the ciphertext length, which is ≈ the plaintext length. This is
  the main residual leak. Mitigation: chunk to a fixed size and pad the final chunk,
  so a blob's size is always a multiple of the chunk size — coarse buckets in the
  spirit of #51, not the exact byte count. The chunk size is a privacy/overhead
  trade-off (bigger chunks = coarser size buckets = more padding waste).
- **Upload and download timing** — when a blob is written and when (and how often)
  it is fetched. A fetch shortly after an upload correlates a send with a
  receive *to the store operator*, though not with any identity unless the store is
  the same operator as the queue/directory (which we recommend against for exactly
  this reason).
- **Which IPs** upload and download a given blob — network-level, mitigated only by
  TLS + whatever the client's network posture provides (no mixnet; same caveat as
  the rest of the system, see [`SECURITY.md`](../SECURITY.md#a-network-observer)).
- **Repeated access to the same blob id** — e.g. a group of N recipients each
  fetching one shared blob reveals a fan-out of N downloads for one upload.

**What the store CANNOT see (if references stay E2E and it is a distinct operator):**

- **Content** — every byte is ChaCha20-Poly1305 ciphertext under a key it never has.
- **Filename / MIME** — those live in the sealed `FileRef`, not in the blob or its
  metadata. The store sees an opaque id and a byte length, nothing typed.
- **Who is talking to whom** — the reference (blob URL + key) travels inside the
  end-to-end message, so the store never learns sender or recipient identities. It
  sees IPs fetching an id, not wallets. This holds **only if** the store is operated
  separately from the queue/directory; co-locating them would let one operator join
  "wallet A deposited for wallet B" (queue) with "IP X uploaded blob, IP Y
  downloaded it" (store). **Recommend a distinct trust boundary**, or at minimum a
  distinct operator, mirroring the directory/queue split (Layer 6).

This is deliberately the *same honesty* as [`SECURITY.md`](../SECURITY.md): we
narrow specific leaks (content, filename, exact size, linkage) and we name the ones
that remain (bucketed size, timing, IP, per-blob fan-out). It is not anonymity.

## Integrity and authenticity

Two independent checks, both fail-closed:

- **Content-addressing (substitution / tampering).** The reference carries
  `H = SHA-256(ciphertext)`. The recipient recomputes it over the fetched bytes and
  refuses to decrypt on mismatch. A store that swaps blob `id → other ciphertext`,
  truncates, or flips bits is caught before any decryption, because it cannot
  produce ciphertext that hashes to `H` without the key.
- **Per-chunk AEAD (forgery / reorder / splice).** Each chunk is sealed with
  ChaCha20-Poly1305 under a key derived from `K` and the chunk index, so a chunk
  cannot be forged (no key), moved to another position (index in the KDF), dropped
  silently (chunk count is in the `FileRef`), or spliced in from another blob
  (different `K`). A single failed tag aborts the file.

Authenticity of the *sender* is inherited from the message path: the `FileRef`
itself arrives inside the ratchet-authenticated, TOFU-pinned envelope, so "this key
and this blob came from the peer I think I'm talking to" is exactly as strong as it
is for any other `Body`. The store contributes availability only, never authenticity
— it is fully untrusted for correctness, exactly like the queue.

## Lifecycle

The hard constraint: **the store cannot see references**, so it cannot know whether
a blob is still reachable by any message. It cannot reference-count. Everything
below works around that.

- **Retention / TTL.** Blobs expire on a store-set timer (proposal: default 30 days,
  configurable per deployment). The client learns the TTL at upload and knows the
  attachment may become unfetchable after it. This is the primary GC mechanism: the
  store simply drops blobs past their TTL, needing no knowledge of references.
- **Garbage collection of unreferenced blobs.** Because the store can't tell which
  blobs are still referenced, GC is **TTL-driven, not reference-driven**. Two client
  behaviors keep still-wanted files alive:
  - **Recipient pinning.** A recipient who wants to keep an attachment fetches and
    stores it **locally** (as today's `save_attachment` already does), so it no
    longer depends on the blob's survival. This is the normal case — download on
    receipt, done.
  - **Sender re-upload.** If a recipient is offline past the TTL and the blob
    expires before they fetch, the sender's client (whose outbox already persists
    undelivered mail) can re-upload on a failed fetch signal, or proactively refresh
    long-lived blobs. Simpler alternative: treat an expired blob like an expired
    disappearing message — the attachment is gone, the text reference remains,
    matching the "best-effort, like disappearing messages" posture the codebase
    already takes.
- **Resumable / chunked upload + download.** Because the blob is already chunked,
  uploads and downloads are naturally resumable: the client uploads chunk-at-a-time
  and can resume from the first missing chunk after an interruption, and downloads
  the same way. This is what makes large files practical on flaky links, and it is
  the concrete reason to prefer a chunked scheme over one-shot bodies.
- **Dedup, and why not convergent encryption.** See below.
- **Quotas / abuse.** Uploads must be authenticated and quota'd, or the store is a
  free anonymous file host. Reuse the queue's model: SIWE-style wallet login
  (`mycellium_core::login`), per-wallet rate limits and byte quotas
  (cf. `DEPOSIT_RATE_LIMIT`), a max blob size, and a max total footprint per wallet.
  Downloads by opaque id can stay open (the id is the capability, like the queue's
  pairing rendezvous) or be lightly rate-limited by IP to blunt scraping. Abuse
  reporting is inherently limited: the operator can act on a *blob id* (a takedown of
  opaque bytes) but cannot see content to moderate it — an honest limitation to state
  plainly, same as the queue's.

### Dedup, and why not convergent encryption

Convergent encryption (deriving `K` from the file's own hash, so identical files
encrypt to identical ciphertext and dedup for free) is **rejected here**. It turns
the store into an oracle: because equal plaintext ⇒ equal ciphertext ⇒ equal blob id,
the store — or anyone who can upload — can **confirm whether a user holds a specific
known file** by uploading a candidate and watching for a dedup hit, and can group
users who share a file. That is exactly the who-holds-what and equality leak this
whole design exists to prevent. We use a **fresh random key per file** instead, so
the same file sent twice produces two unrelated blobs and the store learns no
equality. The cost is no cross-user dedup — an acceptable price, and consistent with
the project's refusal to trade content/metadata privacy for server efficiency.

## Where it runs

Model it on the **recipient-owned queue** (see
[`DEPLOY.md`](../DEPLOY.md#recipient-owned-queues)). The blob store is
infrastructure the *recipient* chooses and the sender writes to, just like the
mailbox: which store to use is a field in the recipient's own signed record, so no
one else decides where a recipient's attachments live, and the three operating modes
carry over unchanged — **self-hosted**, **community/cooperative**, or
**provider-hosted**, trading control for effort with an explicit metadata boundary
each way.

**New service, or an extension of the queue?** Recommendation: **extend the queue
service to expose a blob endpoint, but keep the two logically distinct** (separate
routes, separate storage, separate quotas), for these reasons:

- **Reuse, not a new deployment.** Operators already run `mycellium-queue` with
  wallet login, rate limiting, `MYCELLIUM_DATA` durable/fail-closed storage, and TLS
  guidance. A blob endpoint reuses all of it — one service to deploy, one auth model,
  one ops story — which is the difference between attachments being adopted and being
  an extra box nobody stands up.
- **But be explicit about the co-location caveat.** The [trust model](#trust-model)
  warns that co-locating the store with the queue lets one operator join
  sender↔recipient linkage with upload/download patterns. So: allow but do not
  *require* co-location. The blob store must be **independently addressable** (its
  own URL field in the record, its own route prefix), so a privacy-sensitive
  recipient can point it at a **different** operator than their queue while everyone
  else enjoys the one-service simplicity. This is the queue/directory split applied
  one level down.

Concretely: a `POST /blob` (authenticated, quota'd, resumable chunk PUTs) and
`GET /blob/{id}` (by opaque id), living in `mycellium-queue` but behind their own
storage and their own record field, so they can be split out later without a
protocol change.

## Backward compatibility

- **Small attachments stay inline.** `Body::File` is unchanged and remains the path
  for files at or below a threshold (proposal: the ~256 KiB top padding bucket, so
  inline attachments never exceed what #51 already pads to). No new service is needed
  for the common small case; the behavior users have today is untouched.
- **Above the threshold, use `Body::FileRef`.** A new `Body` variant sits alongside
  `Body::File`:

  ```rust
  /// A reference to an out-of-band encrypted attachment (issue #61). The bytes
  /// live in a blob store as ciphertext; only this reference rides end-to-end.
  FileRef {
      /// File name (basename only), as `File`.
      name: String,
      /// MIME type, best-effort, as `File`.
      mime: String,
      /// Total plaintext size, bytes (for UI + integrity).
      size: u64,
      /// Blob store base URL + opaque blob id.
      store_url: String,
      blob_id: String,
      /// Fresh per-file symmetric key (32 bytes). Never reused, never derived
      /// from content. Held in a zeroize-on-drop type.
      key: [u8; 32],
      /// SHA-256 of the full ciphertext, checked before decrypt.
      content_hash: [u8; 32],
      /// Chunk size used, so the receiver can derive per-chunk keys/nonces.
      chunk_size: u32,
  }
  ```

- **Schema evolution is additive.** `Body` is a serde enum; adding a variant is
  backward-compatible for *encoding*. A receiver on an **older** build that doesn't
  know `FileRef` will fail to decode that one message — so gate sending behind a
  capability/version signal (or simply: only send `FileRef` to peers whose record
  advertises a blob-store-capable client), and fall back to inline `File` (or a plain
  text "attachment too large for this recipient") otherwise. The wire decoders are
  fuzzed and fail closed (see [`SECURITY.md`](../SECURITY.md)), so an unknown variant
  is a clean rejection, never a panic — but the UX should avoid triggering it.
- **`summary()` and `maybe_save_attachment`** gain a `FileRef` arm: the summary reads
  like the `File` one (`📎 name (size bytes)`), and save-on-receipt performs the
  fetch-verify-decrypt before writing to the downloads directory. To the user, a
  large attachment looks identical to a small one; only the transport differs.

## Recommendation and phased plan

**Recommend building this**, as an optional out-of-band path that leaves the inline
small-attachment path exactly as it is, with the blob store shipped as an
**independently-addressable extension of the queue service** and a **fresh random
key per file** (no convergent dedup). This unblocks large files, stops attachments
from bloating the message/queue path, and adds no new metadata beyond bucketed blob
sizes and access timing — all named honestly above and cross-referenced to #48/#51.

Phasing:

- **Phase 1 — core types.** Add `Body::FileRef` to
  `crates/mycellium-core/src/message.rs` with round-trip tests, plus the chunked
  AEAD encrypt/decrypt + content-hash helpers (reusing the ChaCha20-Poly1305 and
  HKDF-SHA256 already in `cipher.rs`). Padded final chunk framed like #51. No network
  yet — pure, testable, `no_std`-friendly crypto.
- **Phase 2 — the store service.** Add `POST /blob` (authenticated, resumable chunk
  PUTs, per-wallet quota + rate limit) and `GET /blob/{id}` to `mycellium-queue`,
  behind their own durable storage and a distinct record field/URL, with TTL-based
  GC. Fail-closed durable storage like the rest of the queue.
- **Phase 3 — engine/client integration.** Threshold logic (inline vs out-of-band)
  in the engine; upload-then-send on the sender side; fetch-verify-decrypt-then-save
  on the receiver side, extending `maybe_save_attachment` / `save_attachment` in
  `crates/mycellium-engine/src/app/util.rs`. Wire the capability check so `FileRef`
  is only sent to peers who can decode it. Mirror in `mycellium-wasm` (the browser
  client also consumes `Body::File` today).
- **Phase 4 — lifecycle polish.** Recipient pinning (already implicit in
  save-on-receipt), sender re-upload/refresh on expiry, per-deployment TTL/quota
  config, and abuse tooling (id-level takedown). Fold blob size buckets into the #51
  padding story so both paths report one coherent size-privacy posture.

Rough change surface: **core** — one `Body` variant + a chunked-AEAD module;
**queue service** — two routes + one storage table + quota/TTL; **clients** (engine,
wasm, and the native clients #67–#72 when they land) — threshold + upload/download
plumbing around the existing save-attachment machinery.

## Cross-references

- **#48** — the privacy / metadata / trust parent. This design narrows the
  large-attachment leak within that program.
- **#51** — size padding buckets. The chunked-blob size buckets here are the same
  idea applied to the out-of-band path; the two should report one size-privacy story.
- **#50 / [`PRIVACY-MODES.md`](../PRIVACY-MODES.md)** — the queued-delivery privacy
  modes; blob upload/download timing is a sibling timing surface (a `high-risk` mode
  might delay/batch fetches, out of scope here).
- **[`SECURITY.md`](../SECURITY.md)** — the system-wide metadata-exposure model this
  extends: [what the queue observes](../SECURITY.md#the-queue-observes) is the
  template for what the store observes.
- **[`DEPLOY.md`](../DEPLOY.md#recipient-owned-queues)** — the recipient-owned
  operating model the blob store reuses.
</content>
</invoke>
