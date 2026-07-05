# Native clients: architecture & implementation plan

*The shared blueprint for the five platform apps in the native-first roadmap
(#74): Android (#67), iOS (#68), macOS (#69), Linux (#70), Windows (#72). Every
app is a thin, platform-native UI over the **one** `mycellium-sdk`. This document
is the contract they all follow so they don't diverge — write it once here, apply
it five times.*

**Status: none of these apps exist yet.** This is the design each one implements,
not a description of running code. What *does* exist and is covered by tests is
the SDK surface they bind to (`crates/mycellium-sdk`, issue #64). Align with
[`ARCHITECTURE.md`](ARCHITECTURE.md#clients-native-first-the-product-target) and
the N1–N5 frontier in
[`PRODUCTION-READINESS.md`](PRODUCTION-READINESS.md#native-client-readiness-the-new-frontier);
where this doc adds detail it must not contradict them.

---

## 1. Shared architecture: one SDK, five thin UIs

The rule that keeps the apps from diverging: **no protocol, crypto, storage, or
network logic ever lives in app code.** An app renders state and forwards user
intent; everything else is behind the SDK boundary. Adding a platform means
writing a UI and wiring the platform integration points (§4) — never
reimplementing a single line of the protocol.

Every app binds to `mycellium-sdk`, which wraps the shared `mycellium-engine` +
`mycellium-core`. This is the same engine the CLI and the browser PWA drive; the
native apps are simply a third kind of shell over it (see the ports-and-adapters
model in [`ARCHITECTURE.md`](ARCHITECTURE.md#design-principle-ports-and-adapters)).

```
   ┌──────────────────────────────────────────────────────────────────────┐
   │  PLATFORM-NATIVE UI (per app — the only code that differs per OS)     │
   │  Android: Kotlin + Compose   Apple: Swift + SwiftUI   Desktop: (§2)   │
   └───────────────┬──────────────────────────────────────┬───────────────┘
                   │  language bindings                     │
        ┌──────────┴───────────┐                 ┌──────────┴───────────┐
        │ UniFFI-generated     │                 │ C-ABI (cdylib/       │
        │ Kotlin  /  Swift     │                 │ staticlib) — desktop │
        └──────────┬───────────┘                 └──────────┬───────────┘
                   └───────────────┬────────────────────────┘
                       ┌───────────┴────────────┐
                       │      mycellium-sdk       │  MyceliumClient object
                       │  (types.rs = the DTOs +  │  + EventListener callback
                       │   SdkError; client.rs =  │
                       │   the stateful façade)   │
                       └───────────┬────────────┘
                       ┌───────────┴────────────┐
                       │  mycellium-engine +      │  register / deliver ladder /
                       │  mycellium-core          │  history / groups / pairing
                       └───────────┬────────────┘
              ┌────────────────────┼─────────────────────┐
   ┌──────────┴─────┐   ┌──────────┴─────┐     ┌──────────┴─────────┐
   │ directory-client│   │ queue-client   │     │ transport (P2P,     │
   │ (names/records) │   │ (store-forward)│     │ #59/#60 — later)    │
   └─────────────────┘   └────────────────┘     └─────────────────────┘
```

The SDK boundary is deliberately narrow and binding-friendly: only the DTOs in
`crates/mycellium-sdk/src/types.rs` (`Message`, `Conversation`, `Contact`,
`Group`, `Account`, the `DeliveryState`/`TrustLevel` enums), the `SdkError` enum,
the `EventListener` callback trait, and the `MyceliumClient` object cross it.
Internal `anyhow`/engine errors are mapped to `SdkError` and never leak.

---

## 2. Binding strategy per platform

The SDK crate already declares `crate-type = ["lib", "cdylib", "staticlib"]` and
ships a `uniffi-bindgen` bin, so all three binding artifacts come from one build.

| Platform | Binding | Artifact | Build tool | UI stack (recommended) |
|---|---|---|---|---|
| **Android** (#67) | UniFFI → **Kotlin** | `.so` per ABI | `cargo-ndk` | Kotlin + **Jetpack Compose** |
| **iOS** (#68) | UniFFI → **Swift** | `.xcframework` (staticlib) | `xcodebuild -create-xcframework` | Swift + **SwiftUI** |
| **macOS** (#69) | UniFFI → **Swift** | same xcframework (add macOS slices) | same | Swift + **SwiftUI** |
| **Linux** (#70) | **C-ABI** (cdylib) | `.so` + generated header | `cargo build` | shared desktop stack (below) |
| **Windows** (#72) | **C-ABI** (cdylib) | `.dll` + header | `cargo build` | shared desktop stack (below) |

**Mobile / Apple — UniFFI, settled.** Android gets generated Kotlin; iOS and
macOS share one generated Swift module packaged as an `.xcframework`. This is the
path the SDK was designed for (`types.rs` uses `uniffi::Record`/`Enum`/`Error`,
`client.rs` is a `uniffi::Object`, and `EventListener` is a
`#[uniffi::export(callback_interface)]`). macOS reuses the iOS Swift binding
verbatim — the same SwiftUI codebase should target both with platform
conditionals, so #68 and #69 are largely one effort.

**Desktop — one shared stack across Linux and Windows.** Linux and Windows should
be a **single** desktop app, not two, sharing all UI code; only packaging differs.
The binding is the **C-ABI** (`cdylib`) — UniFFI does not emit a native desktop
binding, so desktop consumes the SDK through a small C header. Evaluated options:

- **Tauri (Rust core + web UI)** — *recommended.* The app process is already Rust,
  so it can depend on `mycellium-sdk` **directly as a crate** and skip the C-ABI
  entirely (the C-ABI stays the fallback for a non-Rust host). One codebase for
  Linux and Windows (and macOS if we ever want to fold it in), small binaries,
  mature packaging, and the SDK's blocking `ureq` transport fits a Rust host
  cleanly. Web UI, but the sandbox is real and no browser engine ships (uses the
  OS webview).
- **Slint** — strong native-Rust option, pure-Rust UI, small; less mature
  ecosystem, fewer widgets for a chat-dense UI.
- **egui** — fastest to prototype (immediate-mode, pure Rust), but the look is
  non-native and it's weak for text-heavy, accessible chat UIs. Good for an
  internal dev harness, not the shipping app.
- **Fully native (GTK/Qt on Linux, WinUI on Windows)** — best fidelity, but
  doubles the UI work and defeats the "one desktop app" goal. Rejected for MVP.

**Recommendation: Tauri, depending on the SDK crate directly on desktop.** Keep
the C-ABI (`#64` follow-up) as the seam for any future non-Rust desktop host, but
the shipping Linux/Windows app doesn't need to cross it.

---

## 3. The shared app flows (mapped to SDK calls)

Every client implements these flows against the same `MyceliumClient` methods.
Screens differ per platform; the call sequences must not.

### 3.1 Onboarding — create identity → email-verified register
- `MyceliumClient::new(data_dir)` — load-or-create the device identity and open
  the encrypted store. Idempotent; call once at launch.
- **Email verification** — prove control of an email before publishing a handle.
  *Gap to close (#64):* the directory client has `auth_start` / `auth_confirm` /
  `auth_status`, but the SDK does **not** yet expose them; today `register` only
  publishes the record. The apps must not talk to the directory directly, so the
  SDK needs `verify_email_start(email)` / `verify_email_confirm(code)` (or
  equivalent) added to the boundary. The apps design against that shape now.
- `register(dir_url, queue_url, handle, name)` — publish the signed record
  (merging into any existing record so sibling devices are never dropped) and
  persist config. On a fresh device with the same email this is also the
  **recovery** path (see `PRODUCTION-READINESS.md` T0.5).
- `account()` / `wallet_address()` — show who you are after registering.

### 3.2 Device pairing (QR)
Adding a second device to one account, seedless (see the ephemeral-ECDH channel
landed in the seedless-pairing work):
- **New device:** `pair_offer(queue_url)` → hex string → render as a **QR code**.
  Then poll `pair_poll(queue_url)` on an interval; a non-`None` result means the
  account was adopted (store re-keyed, record joined) — return the `Account`.
- **Existing device:** scan the QR, `pair_approve(offer, queue_url)` — this seals
  the account key to the new device. UI must confirm intent first (it shares the
  account key). `EventListener::on_pairing` fires `offered`/`approved`/`paired`
  for progress UI.

### 3.3 Conversation list + thread + compose/send
- `conversations()` → `Vec<Conversation>` (newest first) for the threads list.
- `thread(peer_handle)` → `Vec<Message>` (oldest first) for the open transcript.
- Compose: `send_text(peer, text)`; also `reply(peer, reply_to, text)`,
  `react(peer, target, emoji)`, `delete_message(peer, target)`,
  `send_file(peer, name, mime, data)` (≤256 KiB, carried inside the sealed
  envelope). Each returns the stored `Message` with a `DeliveryState`
  (`Sent`/`Queued`) so the UI can render a pending/sent tick optimistically.
- Groups mirror this: `groups()`, `group_thread(id)`, `group_send(id, text)`,
  `group_create(name, members)`, `group_add(id, member)`, `group_leave(id)`.

### 3.4 Receiving — foreground sync + the push path
- **Foreground:** call `sync()` → `Vec<Message>` on open, on resume, and (until
  #71) on a short interval or a live channel. `sync` drains the queue, decrypts,
  persists to history (durably, with a retry store so a not-yet-decryptable blob
  is retried, never lost), and **also fires `EventListener::on_message` for each**.
- **Push path (the real target):** register an `EventListener` via
  `set_listener(...)`. On a native push wake (#71), the app calls `sync()`; the
  SDK persists and pushes each new message through the listener, and the app
  raises a notification (decrypt-then-display — see §4). The listener also carries
  `on_delivery`, `on_key_change`, and `on_pairing`.

### 3.5 Contacts + verification
- `add_contact(nickname, handle)` — directory lookup + TOFU wallet pin.
- `contacts()` → each `Contact` carries a `TrustLevel`
  (`Unverified`/`Pinned`/`Verified`/`Changed`); `remove_contact(nickname)`.
- Out-of-band verification: `safety_number(peer)` (a short code to compare aloud),
  `mark_verified(peer)`, `trust_level(peer)`, plus contact cards —
  `contact_card()` (emit our own, QR-friendly hex) and `verify_card(card)` (scan a
  peer's; a wallet mismatch returns `SdkError::IdentityChanged`).
- A `Changed` trust level or an `IdentityChanged` error must surface as a **safety
  warning** in the UI (a possible impersonation or a legitimate recovery — the
  user re-verifies out of band).

### 3.6 Settings incl. privacy modes (#50)
- `get_setting(key)` / `set_setting(key, value)` for free-form app settings.
- **Privacy modes** (`normal` / `private` / `high-risk`, per
  [`PRIVACY-MODES.md`](PRIVACY-MODES.md)) are per-contact with a global default and
  a per-message override. The engine/SDK will carry the mode as a delivery
  parameter; the apps own the selection UI (a per-contact badge + a one-time
  explanation for `high-risk`, whose queued sends can take minutes). The
  `high-risk` "sending…" state maps to `DeliveryState::Queued` in the UI.

---

## 4. Platform integration points (NOT in the SDK — each app wires these)

These live outside the SDK because they are inherently OS-specific. The SDK
provides the seam; the app provides the OS glue.

- **Secure storage (#65 / N2).** Today the device secret is a `0600` sidecar file
  (`data_dir/identity.json`); the store under `data_dir/store` is encrypted by the
  identity. #65 slots an OS keystore **behind the same SDK API** — a coming
  `SecretStore` adapter — so the wallet/device secret lives in **Keychain**
  (iOS/macOS), **Keystore** (Android), **DPAPI** (Windows), **libsecret** (Linux).
  The app supplies the platform keystore handle at `new(...)` time; it never sees
  key material (only the public `wallet_address` ever crosses the boundary).
- **Native push / wake (#71 / N3).** APNs (Apple) and FCM (Android) via a push
  relay explicitly **not** hosted by a US company (the native counterpart to the
  PWA's contentless Web Push). The push carries **no** sender or content; on wake
  the app calls `sync()` and the SDK does the rest. Desktop uses a persistent
  connection / OS notification facilities instead of a mobile push vendor.
- **Background execution & app lifecycle.** iOS background-app-refresh / BGTask,
  Android `WorkManager` / foreground service, desktop tray + autostart. All they
  do is: on wake/resume → `sync()`. Respect OS budgets; never busy-poll on mobile.
- **Deep links.** `mycellium:` (or an https app-link) URLs to open a conversation
  or import a contact card — routed to `thread(peer)` / `verify_card(card)`.
- **Notifications (contentless, decrypt-then-display).** The push wake is
  contentless; the notification body is produced **locally** after `sync()`
  decrypts, from the resulting `Message`. Never put ciphertext or sender metadata
  in the push payload.

---

## 5. Repo / build topology

**Recommendation: keep the apps in this monorepo**, under a new `clients/` sibling
to the existing `clients/web` and `clients/rust`:

```
clients/
  web/        (exists — the PWA)
  rust/       (exists — e2e harness)
  android/    (#67) — Gradle project; consumes generated Kotlin + cargo-ndk .so
  apple/      (#68/#69) — Xcode project; consumes the Swift xcframework
  desktop/    (#70/#72) — Tauri app; depends on mycellium-sdk (or the C-ABI)
```

Rationale: the SDK's foreign contract (`types.rs`) and the apps that consume it
must version together — a monorepo makes an SDK change and its five binding
updates one atomic PR, and the existing workspace already forbids protocol/crypto
drift by construction. Split apps into their own repos only if platform release
cadence or store/CI constraints later force it.

**Bindings & release story.**
- **Generate, don't hand-write, bindings.** A `xtask` / CI job runs
  `uniffi-bindgen` to emit Kotlin and Swift into the app projects; the generated
  code is a build artifact, checked or regenerated, never edited.
- **Android:** `cargo-ndk` builds the `.so` for each ABI (`arm64-v8a`,
  `armeabi-v7a`, `x86_64`); Gradle bundles them + the generated Kotlin.
- **Apple:** build the staticlib per arch, `xcodebuild -create-xcframework` to
  package device + simulator (+ macOS) slices, ship the Swift module alongside.
- **Desktop:** Tauri bundles per-OS installers; the SDK is a normal crate dep.
- **Versioning:** the SDK crate version is the single source of truth; bindings
  and apps pin to it. A CI **smoke test that loads the *generated* Kotlin/Swift
  bindings** (called out as a remaining #64 follow-up in `client.rs`) gates every
  SDK release so a boundary change can't silently break a binding.

---

## 6. Per-platform status & first-milestone MVP

**Status today: all five are unstarted (#67/#68/#69/#70/#72).** The realistic
first milestone for each is **"usable 1:1 messaging"** — deliberately *not* groups,
attachments, or privacy modes at MVP.

### Shared prerequisites (block every app)
- **SDK method completeness (#64 / N1)** — mainly the **email-verify** methods
  (§3.1) the boundary is still missing, plus the generated-binding smoke tests.
- **OS secure storage (#65 / N2)** — required before a real user's key sits on a
  device; an MVP may ship on the `0600` sidecar for internal testing only.
- **Native push / wake (#71 / N3)** — foreground `sync()` works without it, so an
  MVP can demo with polling; a *usable* messenger needs it before general use.

### MVP checklist (identical shape per platform)
- [ ] App launches → `new(data_dir)` with the OS-appropriate `data_dir`.
- [ ] Onboarding: create identity → email-verify → `register`.
- [ ] Threads list (`conversations`) + open thread (`thread`).
- [ ] Compose + `send_text`; optimistic send with `DeliveryState`.
- [ ] Receive via foreground `sync()` + `EventListener` → local notification.
- [ ] Add a contact + show/compare a `safety_number`; surface `IdentityChanged`.
- [ ] Secure-storage-backed identity (#65) — or sidecar for internal builds.
- [ ] Second-device pairing via QR (`pair_offer`/`pair_approve`/`pair_poll`).

Per-platform notes: **Android/iOS** MVP additionally needs the push wake (#71) to
feel like a messenger; **macOS** rides the iOS Swift codebase, so it lands cheaply
right after iOS; **Linux/Windows** desktop share one Tauri codebase, so they land
together and can lean on a persistent foreground connection instead of #71 for MVP.

---

## 7. Phased plan & critical path

**Recommended first platform: Android.** Reasons: (1) UniFFI→Kotlin +
`cargo-ndk` is the lowest-friction, fully-supported binding path with no Apple
signing/provisioning gate; (2) it forces the two hardest shared prerequisites —
Keystore secure storage (#65) and FCM push (#71) — which then de-risk every later
platform; (3) sideload distribution lets us iterate without a store review loop.
iOS is a very close second and should start as soon as the SDK's foreign contract
is exercised by Android, since it shares that contract and drags macOS along for
almost free.

**Critical path:**

```
#64 SDK completeness (email-verify methods + binding smoke tests)
        │
        ├── #65 OS secure storage (SecretStore behind the same API)
        │
        ▼
  Android (#67)  ──proves the binding+integration model──┐
        │                                                 │
        ├── #71 native push/wake (FCM first, then APNs)    │
        ▼                                                  ▼
  iOS (#68) ──shares the Swift binding──▶ macOS (#69)     Desktop (#70 + #72)
                                                     one Tauri app, in parallel
```

**Phasing.**
1. **Phase 0 — unblock the SDK.** Land the missing email-verify methods and the
   generated-binding smoke tests (#64); stand up #65 behind the same API.
2. **Phase 1 — Android (#67).** First real app; drives #65 (Keystore) and #71
   (FCM) to done. Deliver the §6 MVP.
3. **Phase 2 — Apple (#68 → #69).** iOS on the shared Swift binding + APNs; macOS
   folds in on the same SwiftUI codebase.
4. **Phase 3 — Desktop (#70 + #72).** One Tauri app depending on the SDK crate;
   Linux and Windows ship together.
5. **Later — N5 direct P2P (#59/#60)** and the full privacy-mode UI (#50) layer on
   top once 1:1 messaging is solid across platforms.

The gating dependency throughout is the **SDK boundary**: freeze its shape early
(§3's method set is nearly there), and the five apps become parallelizable UI work
over a stable contract rather than five chances to reinvent the protocol.
