# Native push / wake notifications for queued messages — design note

*Design research for issue [#71](https://github.com/aristath/mycellium.eu/issues/71)
(native push/wake for the native clients — parent tracker [#74](https://github.com/aristath/mycellium.eu/issues/74);
privacy parent [#48](https://github.com/aristath/mycellium.eu/issues/48)).
**Documentation only** — no code in this note. It extends, and never replaces,
the queue's already-shipping contentless Web Push.*

> **Status:** research/design. This describes how to extend the queue's proven
> **contentless Web Push (VAPID / RFC 8292)** to native mobile wake via **APNs**
> (Apple) and **FCM** (Google), plus a de-Googled path (UnifiedPush/ntfy). Read
> alongside the code it builds on — [`crates/mycellium-queue/src/push.rs`](../../crates/mycellium-queue/src/push.rs)
> (the contentless sender) and [`crates/mycellium-queue/src/lib.rs`](../../crates/mycellium-queue/src/lib.rs)
> (`subscribe`/`unsubscribe`/`subscriptions`/`remove_endpoints`, the deposit
> fan-out) — and the docs it cross-cuts: [`BROWSER.md` §Web Push](../BROWSER.md#web-push-waking-a-closed-app),
> [`NATIVE-CLIENTS.md` §3.4/§4](../NATIVE-CLIENTS.md), [`SECURITY.md` §the-queue-observes](../SECURITY.md),
> and [`DEPLOY.md` §Web Push / recipient-owned queues](../DEPLOY.md#web-push).

## 0. One-line framing (the honest version)

A native push wake tells the recipient's device *"go check your mailbox"* and
**nothing else** — no sender, no text, no peer name, no group name, no thread id,
no preview. The app wakes, calls `sync()`, drains the queue, and decrypts
locally; only then is a notification composed **on the device** from the
plaintext. This is the exact model already shipping for the PWA in
[`push.rs`](../../crates/mycellium-queue/src/push.rs); native is the same idea
carried over Apple's and Google's device-push transports instead of the browser
push services.

**What the push vendor still learns — state it plainly, never claim "nothing".**
Apple (APNs) and Google (FCM) each learn that *a device with a given push token
got a wake, and when*. That is real metadata: existence and **timing** of
activity for that device token, plus whatever the vendor already ties to the
token (the device, often an Apple/Google account, an IP). They do **not** learn
content, sender, recipient handle, or which conversation — the payload carries
none of it. The privacy claim is precise: *contentless*, not *invisible*. This
matches the Web Push honesty in [`BROWSER.md`](../BROWSER.md#web-push-waking-a-closed-app)
("the vendor push service learns nothing but 'some device got a ping'") — with
the important footnote that a *ping's timing is itself metadata the vendor holds*.

---

## 1. The flow, against the real deposit path

The queue already does the hard part for Web Push. Today, in
[`mailbox_post`](../../crates/mycellium-queue/src/lib.rs) (the `POST
/mailbox/{wallet}/{slot}` handler), after a successful `deposit(...)` the queue
fans out a **contentless** wake to every registered endpoint, off the request
thread so a slow push service never stalls the queue:

```
sender app ──seal per device──► POST /mailbox/{recipient_wallet}/{device_slot}
                                     │  (deposit: opaque, E2E-sealed blob)
                                     ▼
                          Queue::deposit() stores the blob
                                     │
                                     ▼   (std::thread::spawn — off the lock)
                    for endpoint in subscriptions(recipient_wallet):
                          vapid.send(endpoint, now)   ← bodyless POST, no payload
                          if SendResult::Gone → collect for remove_endpoints()
```

Native push slots into the **same fan-out point**. The only change is that a
subscription is no longer always a browser endpoint URL — it is a tagged union
(§2) that also covers an APNs token, an FCM token, or a UnifiedPush endpoint. The
fan-out dispatches each subscription to the right sender:

```
                    for sub in subscriptions(recipient_wallet):
                          match sub {
                            WebPush(endpoint)      → vapid.send(endpoint, now)      (unchanged)
                            Apns { token, topic }  → apns.wake(token, topic, now)   (new)
                            Fcm { token }          → fcm.wake(token, now)           (new)
                            UnifiedPush(endpoint)  → vapid.send(endpoint, now)      (VAPID-style POST)
                          }
                          on "gone/unregistered" → collect for removal
```

On the device side the wake resolves to exactly the path
[`NATIVE-CLIENTS.md` §3.4](../NATIVE-CLIENTS.md) already specifies:

```
OS delivers wake ──► app background task ──► MyceliumClient::sync()
                                                 │  (drains queue: device slot
                                                 │   + ACCOUNT_SLOT, decrypts,
                                                 │   persists to the inbound
                                                 │   retry store, never lost)
                                                 ▼
                                          for each new Message:
                                             EventListener::on_message(msg)
                                                 ▼
                                          app composes notification LOCALLY
                                          from the decrypted Message (§4 decrypt-
                                          then-display) and raises it
```

`sync()` already exists and already does the drain/decrypt/persist/`on_message`
work (see [`client.rs`](../../crates/mycellium-sdk/src/client.rs)): it collects
both the per-device slot (`wireops::device_slot(device_public)`) and the
`ACCOUNT_SLOT`, writes every blob to the durable inbound retry store *before*
processing so nothing is lost, and fires `on_message` per new message after
releasing the lock. **Native push adds no new receive logic — it only supplies a
new trigger for `sync()`.**

---

## 2. Subscription storage: from endpoint-only to a tagged union

### 2.1 Today

The queue stores, per recipient wallet, a plain list of browser push endpoints:

```rust
// lib.rs
subs: HashMap<String, Vec<String>>,   // wallet hex → Vec<endpoint URL>
pub const MAX_SUBS_PER_WALLET: usize = 20;
pub const MAX_ENDPOINT_LEN: usize = 2048;
```

Persisted in [`persist.rs`](../../crates/mycellium-queue/src/persist.rs) as the
`SUBS` table (`wallet → json Vec<String>`), written through `put_subs`. The wire
type is `SubscribeReq { endpoint: String }`; validation is
`is_push_endpoint` (bounded HTTPS URL with a host). Endpoint-only storage is
*intentional and sufficient for contentless Web Push* — the RFC 8291 `p256dh`/
`auth` keys are only needed to encrypt a payload, which is deliberately never
sent (documented at the top of `push.rs`).

### 2.2 Proposed: a versioned, tagged `Subscription`

Replace the endpoint-string with a tagged union, keeping web-push registrations
byte-compatible so existing PWA subscriptions keep working across the upgrade:

```rust
/// A wake target for one device. Versioned so the stored JSON can evolve.
#[serde(tag = "kind")]
enum Subscription {
    /// Existing browser Web Push (VAPID). The default when `kind` is absent,
    /// so records written before this change still deserialize.
    WebPush { endpoint: String },
    /// Apple Push Notification service. `topic` = the app bundle id.
    Apns { token: String, topic: String },
    /// Firebase Cloud Messaging (HTTP v1). `token` = the FCM registration token.
    Fcm { token: String },
    /// UnifiedPush / ntfy — a VAPID-style HTTPS endpoint (de-Googled Android).
    UnifiedPush { endpoint: String },
}
```

- **Storage.** `subs: HashMap<String, Vec<Subscription>>`, still capped at
  `MAX_SUBS_PER_WALLET` (oldest evicted, exactly as now). The `SUBS` redb table
  stores `wallet → json Vec<Subscription>` — same table, richer element type.
- **Back-compat / migration.** A bare string or a `{ "endpoint": ... }` object
  from the old format deserializes to `WebPush` (make `kind` default to
  `"web_push"` via `#[serde(default)]` on an untagged fallback, or run a one-shot
  load-time upcast in `Store::load`). No operator action, no lost PWA subs.
- **Per-device, not just per-wallet.** Web Push today keys only by wallet. Native
  tokens are inherently **per device**, and rotation/revocation is per device, so
  each `Subscription` should also carry the owning **device id** (the same
  `device_slot` hex the mailbox uses) so a `revoke_device` (§4) can drop exactly
  that device's token. Suggest `Subscription` gain a `device: String` field (or
  key `subs` by `(wallet, device)`); web-push entries may leave it empty for
  back-compat. This also lets the fan-out skip a device whose token is dead
  without touching siblings.
- **Validation.** Extend the current `is_push_endpoint` check per variant: APNs
  tokens are hex (device token) — bound length; FCM tokens are opaque bounded
  strings; UnifiedPush endpoints reuse the HTTPS-URL check. Reject unknown
  `kind`s so a malformed client can't wedge storage.

### 2.3 The `subscribe` API change (versioned, back-compat)

Today:

```rust
pub fn subscribe(&mut self, token: &str, endpoint: String, now: u64) -> Result<(), ApiError>
// route: POST /push/subscribe   body: { "endpoint": "https://…" }
```

Proposed — accept a versioned body that is a superset of today's:

```jsonc
// POST /push/subscribe   (v: 1 = the tagged form; a bare {endpoint} still works)
{ "v": 1, "sub": { "kind": "apns", "token": "…", "topic": "eu.mycellium.app" } }
{ "v": 1, "sub": { "kind": "fcm",  "token": "…" } }
{ "endpoint": "https://push.example/…" }          // legacy web-push, still accepted
```

`subscribe(token, Subscription, now)` authenticates the session
(`self.authed`, unchanged), validates the variant, dedups (idempotent, as now —
a device re-registering the same token is a no-op), caps the list, and
`put_subs`. `unsubscribe` takes the same tagged form and removes the matching
entry. `remove_endpoints` generalizes to `remove_subs(wallet, &[Subscription])`
for the "gone/unregistered" pruning path (§4). `subscriptions(wallet)` returns
`Vec<Subscription>` for the fan-out. The `POST /push/key` route (VAPID public
key) is unchanged and only relevant to the WebPush/UnifiedPush variants.

---

## 3. Provider integration

The queue becomes a **multi-transport contentless push sender**. Each transport
is a thin module beside `push.rs`, all reporting the same `SendResult`-style
`{ Ok | Gone | Failed }` so the fan-out and pruning logic stays uniform.

### 3.1 iOS / macOS — APNs (HTTP/2 + JWT provider auth)

- **Transport.** APNs is HTTP/2 to `api.push.apple.com` (prod) /
  `api.development.push.apple.com` (sandbox), path `/3/device/{token}`.
- **Auth.** Provider **JWT** (ES256) signed with an APNs **auth key** (`.p8`,
  a P-256 key) — structurally the *same* ES256/P-256 signing the VAPID code
  already does in `push.rs` (`p256::ecdsa`), so the crypto is familiar. The JWT
  header carries the key id (`kid`); claims carry the team id (`iss`) and `iat`.
  One token is reused for up to ~1h.
- **Headers.** `apns-topic` = the app bundle id (the `topic` in the union),
  `apns-push-type` = `background` for a silent content-available wake or `alert`
  for a generic "you have mail", `apns-priority` = 5 (background) / 10 (alert),
  `apns-expiration` to bound retry (mirrors the Web Push `TTL: 86400`).
- **Payload — contentless.** For a silent wake: `{"aps":{"content-available":1}}`
  and nothing else. For a visible generic notification (when the OS/entitlements
  require it): a **fixed** localized string ("You have a new message"), with
  **no** interpolated sender/preview/thread. Never any per-message data.
- **Gone handling.** A `410` with reason `Unregistered` (or `BadDeviceToken`)
  means drop that token — the exact analogue of the Web Push `404/410 → Gone`
  path already in `push.rs`.
- **Note on HTTP/2.** The current queue uses `ureq` (HTTP/1). APNs *requires*
  HTTP/2, so this needs an HTTP/2-capable client for the APNs module only (e.g.
  a small dependency), or a documented sidecar relay. Web Push and
  UnifiedPush stay on the existing HTTP/1 `ureq` path.

### 3.2 Android — FCM (HTTP v1 + service-account auth)

- **Transport.** FCM HTTP **v1**: `POST https://fcm.googleapis.com/v1/projects/{project_id}/messages:send`.
- **Auth.** An OAuth2 bearer token minted from a **service-account** JSON key
  (the legacy server-key API is deprecated — do not use it). The queue mints/
  refreshes a short-lived access token from the service-account credentials.
- **Payload — contentless.** A **data-only** message
  (`{"message":{"token":"…","data":{"w":"1"}}}` with a single opaque flag, no
  content) so the app's `onMessageReceived` runs and calls `sync()`. Avoid a
  `notification` block (the system would display it directly and, more to the
  point, could carry text) — keep display **local**, decrypt-then-display. Use
  high priority sparingly (Doze/battery — §6).
- **Gone handling.** `UNREGISTERED` / `INVALID_ARGUMENT` (404/400) → drop the
  token, same pruning path.

### 3.3 De-Googled Android — UnifiedPush / ntfy (recommended, feasible)

For users without Google Play Services, **UnifiedPush** is the clean fit and is
*almost free* here: a UnifiedPush distributor (e.g. **ntfy**, self-hostable) hands
the app a **plain HTTPS endpoint**, and delivery is a bodyless/near-bodyless
**POST to that endpoint** — i.e. structurally identical to a Web Push endpoint.
The queue can treat `UnifiedPush { endpoint }` almost exactly like `WebPush`,
reusing `Vapid::send` / the same HTTPS-POST wake (VAPID auth is accepted by
ntfy-style servers; a plain POST also works). This gives a **no-US-vendor,
no-Google** wake path and dovetails with the "push relay explicitly not hosted by
a US company" intent recorded in [`NATIVE-CLIENTS.md` §4](../NATIVE-CLIENTS.md).
Recommend UnifiedPush as the **default de-Googled path** and the reference for
the `UnifiedPush` variant; keep FCM as the mainstream-Android default.

### 3.4 Where provider credentials live

Provider credentials are **queue-operator config**, exactly like the existing
SMTP secrets and the persisted VAPID key — cross-link
[`DEPLOY.md`](../DEPLOY.md#web-push). Because the queue is
**recipient-owned** ([`DEPLOY.md` §recipient-owned-queues](../DEPLOY.md#recipient-owned-queues)),
each operator supplies **their own** credentials for whichever transports their
users need; a queue with no APNs key simply can't wake iOS devices registered to
it (fail soft — the message still queues, §6):

| Transport | Operator config (proposed env, mirrors SMTP/VAPID) | Secret |
|---|---|---|
| Web Push (VAPID) | `MYCELLIUM_DATA/vapid.key` (already; 0600, persisted) | P-256 seed |
| APNs | `MYCELLIUM_APNS_KEY` (`.p8`), `MYCELLIUM_APNS_KEY_ID`, `MYCELLIUM_APNS_TEAM_ID`, `MYCELLIUM_APNS_TOPIC`, `MYCELLIUM_APNS_ENV` (prod/sandbox) | `.p8` auth key |
| FCM | `MYCELLIUM_FCM_CREDENTIALS` (service-account JSON path) | service-account JSON |
| UnifiedPush | none at the queue (endpoint is client-supplied); operator may run an ntfy server | — |

Store secrets like the VAPID key: read from `MYCELLIUM_DATA` / env, restrict file
perms (0600), never log. A transport is **enabled iff its credentials are
present** — no credentials → that variant's fan-out is skipped, not an error.
Follow the existing **fail-closed durable-store** discipline (#45) but **fail-soft
per-transport**: a missing APNs key must not stop the queue from serving Web Push
and mail.

---

## 4. Privacy requirements (enumerate + enforce)

The issue is emphatic. The following are **hard invariants**, unit-testable at
the payload-construction boundary (§7):

1. **No plaintext, ever.** The push payload contains **no** message text or
   ciphertext.
2. **No sender.** No sender handle, sender wallet, sender name, or device id.
3. **No peer/relationship data.** No peer/contact name, no **group name**, no
   **thread/conversation id**, no message id, no preview/snippet, no unread
   count that could fingerprint a conversation.
4. **Payload is one of exactly two shapes:**
   - a **silent content-available wake** (`aps.content-available:1` / FCM
     data-only), the preferred form; or
   - a **generic fixed string** ("You have a new message") when a platform
     requires a visible alert. The string is a constant — never templated.
5. **Display is composed locally**, after `sync()` decrypts, from the resulting
   `Message` — the **decrypt-then-display** rule already stated in
   [`NATIVE-CLIENTS.md` §4](../NATIVE-CLIENTS.md#notifications-contentless-decrypt-then-display).
   The wake and the notification are separate steps; the wake never carries what
   the notification shows.

**What the vendor still learns (must be documented, not hidden):** Apple/Google
learn that *a device token received a wake and when* — presence + **timing** of
activity, tied to whatever they already associate with the token (device, often
an OS account, IP). They do not learn content, sender, recipient identity, or
conversation. This is a real, unavoidable metadata leak of the *mobile push
model itself*; the only ways to reduce it are batching/delay (blunts timing —
orthogonal, see the size/timing levers in [`PRIVACY-MODES.md`](../PRIVACY-MODES.md)
and #51/#52) and the de-Googled UnifiedPush path (§3.3), which moves the vendor
from Google/Apple to an operator-chosen (self-hostable) relay but does **not**
eliminate "a device got a wake, and when" from *that* relay.

**Tokens are sensitive metadata.** An APNs/FCM token identifies a device to a
vendor and, combined with the per-wallet mapping the queue holds, links *this
wallet ↔ this device ↔ this vendor account*. Treat the `subs` store as
**sensitive metadata stored apart from message content** — it already is
(separate `SUBS` table), and it must never be logged or exported with mail. This
extends the existing [`SECURITY.md` §the-queue-observes](../SECURITY.md) line
("Push subscriptions: the … endpoints registered per wallet — the push itself is
contentless") to name the new token types; that section should be updated when
this ships.

---

## 5. Lifecycle: registration, rotation, revocation

- **Registration.** On the app obtaining OS push permission and a token, it calls
  the SDK's `register_push(...)` (§6), which POSTs `/push/subscribe` with the
  tagged `Subscription`. Idempotent (dedup by token, as the current `subscribe`
  dedups by endpoint).
- **Rotation / refresh.** APNs and FCM tokens rotate (OS reissue, app reinstall,
  restore-to-new-device). The app re-registers on every token refresh callback;
  the queue should **replace** a device's prior token rather than accumulate —
  dedup by `(wallet, device)` so a rotated token supersedes the old one for that
  device (the `MAX_SUBS_PER_WALLET` eviction is a backstop, not the mechanism).
  Old tokens that linger get pruned lazily via the `Gone` path below.
- **Dead-token pruning (the `Gone` path).** The fan-out already prunes on
  `SendResult::Gone` (Web Push 404/410). Generalize: APNs `410 Unregistered`,
  FCM `UNREGISTERED` → `Gone` → `remove_subs`. This keeps the per-deposit fan-out
  bounded and stops repeatedly waking a dead token.
- **Revocation on device removal.** [`revoke_device`](../../crates/mycellium-engine/src/app/devices.rs)
  removes a device from the signed **directory** record. Its push token must also
  be dropped at the queue — hence per-device subscription keying (§2.2): revoking
  device *D* should `unsubscribe` *D*'s token. Since the queue is separate from
  the directory, this is a queue call the SDK makes alongside the directory
  update (best-effort; the `Gone` path is the eventual backstop if the call is
  missed).
- **User disables notifications.** The app calls `unregister_push(...)` →
  `/push/unsubscribe`, removing that device's token. Mail still queues and still
  arrives on the next foreground `sync()` (§6) — disabling notifications must
  never drop messages.
- **Per-platform permission + explanation.** iOS/macOS require an explicit
  `UNAuthorizationOptions` grant; Android 13+ requires the
  `POST_NOTIFICATIONS` runtime permission; UnifiedPush requires a distributor to
  be installed/selected. The app owns this UI and should show a **one-time
  honest explanation**: *"To wake the app for new messages we register a device
  token with your platform's push service (Apple/Google) or your chosen relay.
  The wake carries no sender or content; messages are decrypted on your device.
  The push provider can see that your device was woken and when."* Denied
  permission is a supported state (§6), not an error.

---

## 6. SDK surface

The native app never talks to APNs/FCM registration APIs on the SDK's behalf for
*content* — it only forwards the **token** the OS hands it. New
[`MyceliumClient`](../../crates/mycellium-sdk/src/client.rs) methods (UniFFI-
exported, `&self` like the rest):

```rust
/// Register this device's native push token with the account's queue, so the
/// queue can wake this device on deposit. Idempotent; replaces a prior token
/// for this device. `platform` selects the transport (apns | fcm | unifiedpush |
/// webpush). Logs the queue in with the device identity (as `sync` does).
pub fn register_push(&self, platform: PushPlatform, token: String) -> Result<(), SdkError>;

/// Remove this device's push registration from the queue (user disabled
/// notifications, or the device is being removed). Safe to call when none exists.
pub fn unregister_push(&self, platform: PushPlatform, token: String) -> Result<(), SdkError>;
```

where `PushPlatform` is an enum `{ Apns { topic }, Fcm, UnifiedPush { endpoint }, WebPush { endpoint } }`
(topic/endpoint carried where the transport needs it). Implementation mirrors the
existing queue calls in `sync()`/`deliver_app`: build a
`QueueClient::with_transport(queue_url, UreqTransport)`, `login(&identity)`,
POST the tagged `Subscription` to `/push/subscribe` (or `/push/unsubscribe`),
tagging the current `device_slot` so the queue keys it per device. `queue_url`
comes from the persisted `Config`; return `SdkError::NotRegistered` if unset,
like the other methods.

**Wake → `sync` → `on_message`.** No new receive path is needed — it already
exists:

```
OS push wake ──► app background handler ──► client.sync()
                                               │ (existing: drain device slot +
                                               │  ACCOUNT_SLOT, decrypt, persist
                                               │  to inbound retry store)
                                               ▼
                                   EventListener::on_message(msg)   (already fired by sync)
                                               ▼
                                   app raises a local, decrypt-then-display
                                   notification from `msg`
```

The app registers its listener once via the existing `set_listener(...)`; the
listener also carries `on_delivery` / `on_key_change` / `on_pairing`. This is the
"push path (the real target)" already sketched in
[`NATIVE-CLIENTS.md` §3.4](../NATIVE-CLIENTS.md) — this note just fills in how the
wake is produced and how the token gets to the queue. **Secure storage of the
identity that logs the queue in is #65** ([`NATIVE-CLIENTS.md` §Secure storage](../NATIVE-CLIENTS.md));
the push token itself is *device* metadata, not a secret key, but should still be
kept in app storage, not logged.

---

## 7. Reliability limits (document honestly)

The governing invariant: **push is an optimization, never the transport. If a
wake never fires, the message stays queued and appears on the next foreground
`sync()` or app open — it is never lost.** This is guaranteed by the existing
design: deposits persist server-side until collected, and `sync()` writes every
collected blob to the durable **inbound retry store before processing**
(`client.rs`), so a not-yet-decryptable or transiently-failing item is retried,
not dropped. Push failure degrades **latency**, never **delivery**.

Honest limits to document per platform:

- **Denied permission.** No token → no wake. Supported: the app falls back to
  foreground `sync()` on open/resume. No message loss.
- **iOS force-quit.** A user-swiped-away iOS app will **not** reliably receive
  background/`content-available` pushes; a visible `alert` push can still land,
  but only wakes on tap. Document that iOS force-quit degrades to
  open-time sync. (This is an OS policy, not a bug we can fix.)
- **Network failure / device offline.** The wake `Failed`; the token is kept
  (transient, like the current `SendResult::Failed`), and the message waits in
  the mailbox. Next sync collects it.
- **Provider outage (APNs/FCM down).** Fan-out `Failed`s are swallowed off the
  request thread (as today); mail is unaffected. Recovery = next sync.
- **Rate limits / budgets.** APNs/FCM throttle; Android Doze/battery-optimization
  can delay or coalesce data pushes; iOS budgets background pushes. Do **not**
  busy-wake — one wake per deposit, deduped, and rely on `sync()` draining
  *all* pending mail in one pass (it already collects everything in the slot).
  Consider server-side coalescing (one wake per short window per device) as a
  later optimization (ties to batching #52).
- **No credentials at the operator.** A queue without an APNs/FCM key can't wake
  those devices — fail soft (§3.4); those users rely on foreground sync until the
  operator configures it, or move to a queue that supports their platform
  (recipient-owned queues make this the user's choice).

---

## 8. Safe in-repo slice vs. what needs Apple/Google

Split the work by what can be **built and tested in this repo with no external
accounts** versus what fundamentally needs a real Apple/Google developer account
plus physical devices (delivery cannot run in headless CI — the same reality the
Web Push QA matrix documents in [`BROWSER.md` §interop matrix](../BROWSER.md#contentless-push-interoperability-matrix-manual-qa),
tracked by #30).

### 8.1 Safe in-repo (recommended first slice — no external accounts)

1. **Tagged-union subscription storage.** Turn `subs` into
   `HashMap<String, Vec<Subscription>>` with the versioned `Subscription` enum,
   per-device keying, back-compat deserialization of existing web-push subs, the
   `SUBS`-table upcast, and validation per variant. Fully unit-testable: the
   existing test `push_subscriptions_are_validated_capped_and_removable` in
   `lib.rs` extends directly to the new variants (validation, dedup, cap,
   removal), plus a **migration test** (old string/`{endpoint}` JSON → `WebPush`).
2. **`subscribe`/`unsubscribe`/`remove_subs`/`subscriptions` over the union**, and
   the fan-out `match` in `mailbox_post` dispatching per variant. Testable with a
   stub sender (assert the right transport is selected per subscription and the
   `Gone` path prunes the right entry).
3. **Contentless-payload construction, with unit tests** — the highest-value safe
   deliverable. Pure functions `apns_wake_payload(...)`, `fcm_wake_payload(...)`
   producing the JSON bodies, asserting the §4 invariants: **no** sender / text /
   peer / group / thread / preview fields present; body is either
   content-available/data-only or the exact fixed string. These tests are the
   enforcement mechanism for the privacy requirements and run in CI forever.
4. **JWT/auth *construction* (not delivery).** The APNs ES256 provider JWT and the
   FCM service-account access-token request can be built and unit-tested for
   shape/signing (reusing the `p256::ecdsa` path already in `push.rs`) without
   ever contacting Apple/Google — assert header/claims/signature structure.
5. **SDK `register_push`/`unregister_push`** wiring to `/push/subscribe` with the
   tagged body, covered by the SDK test harness (`tests/sdk.rs`) against an
   in-process queue router — no real device token needed (a synthetic token
   string exercises the full path to storage).

### 8.2 Needs real Apple/Google accounts + devices (external, manual)

- Actual **APNs delivery** (a real `.p8` auth key, an Apple Developer team, a
  provisioned bundle id, a physical iPhone/Mac) and actual **FCM delivery** (a
  Firebase project, service-account JSON, a physical Android device).
- End-to-end wake→`sync`→notification on device, background/force-quit behavior,
  token rotation in the wild, Doze/budget behavior.
- A **UnifiedPush** end-to-end run needs a distributor (ntfy) + device but is
  self-hostable and the least gated.

These extend the existing manual QA matrix in
[`BROWSER.md`](../BROWSER.md#contentless-push-interoperability-matrix-manual-qa)
(#30) — add APNs (native), FCM (native), UnifiedPush rows, "not yet verified"
until confirmed on real hardware.

### 8.3 Phased plan (aligns with the app roadmap #67–#72)

Following the [`NATIVE-CLIENTS.md` §7 roadmap](../NATIVE-CLIENTS.md) (Android
#67 first, then Apple #68/#69, desktop #70/#72):

- **Phase 0 — in-repo (this slice).** §8.1 items 1–5: tagged storage + migration,
  multi-transport fan-out, contentless-payload constructors + tests, auth-token
  construction, SDK register API. All in CI, no external accounts. *This is the
  recommended first PR and de-risks everything downstream.*
- **Phase 1 — FCM, with Android #67.** First real transport, on the first real
  app; drives FCM credentials/config (`DEPLOY.md`) and on-device verification.
  Ship UnifiedPush alongside (de-Googled default) since it reuses the Web Push
  sender.
- **Phase 2 — APNs, with Apple #68/#69.** Add the HTTP/2 APNs module and the
  provider-JWT path; verify on iOS/macOS hardware. (Web Push on Safari/macOS is
  the separate #30 track.)
- **Phase 3 — desktop (#70/#72).** Prefer a persistent foreground connection +
  OS notification facilities over a mobile push vendor, per
  [`NATIVE-CLIENTS.md` §4](../NATIVE-CLIENTS.md); native push is optional here.

---

## 9. Cross-references

- **This issue:** [#71](https://github.com/aristath/mycellium.eu/issues/71) — native push/wake.
- **Storage for the tokens:** [#65](https://github.com/aristath/mycellium.eu/issues/65)
  (OS secure storage — the identity that authenticates `register_push`; push
  tokens are device metadata kept in app storage, not the keystore).
- **Apps that consume this:** [#67](https://github.com/aristath/mycellium.eu/issues/67)
  (Android — first FCM/UnifiedPush target), [#68](https://github.com/aristath/mycellium.eu/issues/68)
  (iOS — APNs), [#69](https://github.com/aristath/mycellium.eu/issues/69) (macOS),
  [#70](https://github.com/aristath/mycellium.eu/issues/70) (Linux),
  [#72](https://github.com/aristath/mycellium.eu/issues/72) (Windows), tracker
  [#74](https://github.com/aristath/mycellium.eu/issues/74).
- **Privacy parent:** [#48](https://github.com/aristath/mycellium.eu/issues/48);
  timing/size levers in [`PRIVACY-MODES.md`](../PRIVACY-MODES.md) (#51 padding,
  #52 batching) reduce the *timing* the push vendor sees; sealed-sender
  [`SEALED-SENDER.md`](SEALED-SENDER.md) (#55) is orthogonal (it hides the sender
  from the queue, not the wake from the vendor).
- **Web Push (the model this extends):** [`push.rs`](../../crates/mycellium-queue/src/push.rs),
  [`BROWSER.md` §Web Push](../BROWSER.md#web-push-waking-a-closed-app),
  [`DEPLOY.md` §Web Push](../DEPLOY.md#web-push), QA matrix #30.
