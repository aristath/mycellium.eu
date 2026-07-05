# Native privacy modes for queued delivery

*Design for issue #50 (parent #48). Concrete, implementable behavior for the
metadata-minimization knobs on **queued** delivery — the store-and-forward path a
message takes when the recipient is offline or unreachable and it lands in their
untrusted ciphertext queue.*

## What this does and does not do

These modes trade **latency, bandwidth, and storage** for **less metadata leakage
to the queue operator and a network observer**. They tune what the queue can infer
from the blobs it holds: their *size* and their *timing*.

They are **not anonymity.** The queue authenticates the depositor, so it always
learns the **sender wallet ↔ recipient wallet** linkage for mail it routes (see
[`SECURITY.md`](SECURITY.md#the-queue-observes)). No mode hides *that* you are
talking or *to whom*. Sealed-sender-style deposits (#55) are the separate,
research-stage lever for the *who*; these modes only blunt *how big* and *when*.
Content is already end-to-end sealed in every mode.

Live, direct **P2P** delivery (the ratchet over a TCP/libp2p connection) is **not**
padded or delayed by these modes — it does not transit the queue, and adding
latency there would hurt the common case for no queue-metadata gain. The knobs
below apply only when a message is deposited into a queue.

## The three modes

| Knob | `normal` (default) | `private` | `high-risk` |
|---|---|---|---|
| **Size padding** | coarse buckets (§ Padding) | coarse buckets | pad every item to the **max bucket** (256 KiB) |
| **Deposit timing** | immediate | random delay **0–30 s**, batched | random delay **2–10 min**, batched |
| **Batching** | none | coalesce deposits in the window | coalesce aggressively across the window |
| **Queue TTL** | server default | server default | request **short** retention |
| **Retry/outbox** | standard | standard, delay re-applied | standard, delay re-applied |

- **`normal`** — what ships today plus always-on coarse size padding (padding is
  cheap and strictly beneficial, so even the default gets it). Immediate deposit;
  lowest latency.
- **`private`** — adds a short randomized send delay and batching, so a burst of
  messages doesn't produce a burst of same-timed deposits an observer can
  correlate. Sub-minute latency cost.
- **`high-risk`** — uniform maximum-size blobs and minutes-scale randomized,
  batched deposits, so neither size nor fine-grained timing distinguishes one
  message from another. Real latency + bandwidth cost, chosen deliberately.

## Padding buckets (#51)

Padding is applied to the **plaintext inside the sealed envelope**, so it is
covered by the envelope's AEAD — tampering fails closed, and the queue only ever
sees the padded *ciphertext* size. Buckets (of the pre-seal payload, bytes):

```
256, 1 024, 4 096, 16 384, 65 536, 262 144
```

A payload is padded up to the smallest bucket that fits it (`normal`/`private`);
`high-risk` pads every item to the largest bucket. Anything larger than the top
bucket (only possible for a max-size attachment near the queue's 1 MiB body cap)
rounds up to the next 64 KiB multiple, staying bounded by the queue's request
limit. Wire format of the padded payload: `[u32-LE real_len][payload][zero fill]`,
the whole thing sealed; on open, read `real_len` and return exactly those bytes.

## Delay / batching windows (#52)

Delays are **randomized within** the window (not a fixed offset, which would just
shift the correlatable spike). Deposits accumulated during a window are flushed
together via the existing outbox, which already persists undelivered mail — so a
delayed deposit **survives a restart** and is retried, never lost. Urgent `normal`
sends bypass the scheduler entirely.

## Scope of the setting

- **Per-contact, with a global default and a per-message override.** A global
  default mode applies to every conversation; a contact can pin a higher mode
  (e.g. `high-risk` for one sensitive correspondent) without slowing everyone
  else; a single message can be sent at a higher mode ad hoc.
- Rationale: privacy needs are relationship-specific, and a global-only switch
  pushes people to either over-pay latency everywhere or turn protection off.

## UX impact

- `normal` — invisible; no user-perceptible change beyond a few padding bytes.
- `private` — messages may show a brief "sending…" of up to ~30 s when queued
  (never when delivered live). Communicated with a subtle pending indicator.
- `high-risk` — queued messages can take minutes to leave the device; the UI must
  state this plainly (a per-contact badge + a one-time explanation), so the delay
  reads as protection, not a bug.

## Follow-up implementation issues

- **#51** — size padding (the buckets above). *Ships first; independent of timing.*
- **#52** — delayed + batched deposits (the windows above), over the outbox.
- Mode selection UI + the per-contact/global/per-message setting plumbing land
  with the native clients (#67–#72) that surface it; the engine/SDK carry the
  mode as a delivery parameter.
