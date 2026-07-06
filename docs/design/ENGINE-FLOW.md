# Design: `engine::flow` — one orchestration, three thin clients

**Status:** in progress. **Goal:** collapse the messaging orchestration that is currently
**triplicated** across the CLI (`engine/app/*`), the SDK (`sdk/client.rs`), and wasm
(`wasm/lib.rs`) into a single platform-generic layer, with the three clients as thin
adapters. This removes the drift that has already produced capability gaps and latent
security bugs, and de-CLI-ifies the engine so it is a real library.

## Why (what the drift has cost)

The three implementations sit on the same already-generic substrate
(`core::{Platform, Storage, HttpTransport}` + the `history`/`groups`/`inbound`/`names`/
`verified`/`antirollback`/`wireops` modules, all `<S: Storage>`). Only the orchestration
on top diverged. Concrete gaps found in the divergence audit:

- **Delivery:** engine does the live ladder (direct TCP/libp2p + Circuit Relay +
  reachability scoring + outbox retry); **SDK and wasm are queue-deposit only.** So a
  directly-reachable peer gets live delivery from the CLI but never from the phones/browser.
- **wasm silently drops `SelfSync`, `GroupSync`, `GroupLeave`** — a wasm member who leaves
  is never rekeyed out; wasm can't be bootstrapped into a group; own-device sends never mirror.
- **Outbound group-leave is engine-only** — SDK/wasm do a bare local `groups::remove`, so
  other members never rekey when an SDK/wasm user leaves.
- **Security (now patched as stopgaps, to be unified):** `distribute_key`/`deliver_app`/
  `group_send` in SDK+wasm sealed to directory records without `verify()`; the
  `distribute_key` *pin* check (`verified::level != Changed`) is still engine-only because
  that free function has no store handle — it needs the shared `FlowCtx`.

## The target API

The engine's domain modules are already `<S: Storage>`; the coupling is entirely in
`app/*` along three axes: identity/config acquisition (the `load_identity()` + global
`ClientConfig` singleton + TTY passphrase), 128 `println!`s that *are* the outputs, and
hardcoded `FileStore`/`DirectoryClient`/`QueueClient`/`OsPlatform`. `wireops.rs` is the
proven precedent for the fix (takes `Platform` + explicit args, no env/print, compiles to
wasm). Generalize that across the layer:

```rust
// engine::flow
pub struct FlowConfig { pub dir_url: String, pub queue_url: String,
                        pub handle: String, pub name: String }

pub enum ItemOutcome { Handled, Retry }   // replaces Result<()>.is_ok() / Processed / bool

/// Injected net seam (the clients bind their own HttpTransport: ureq / xhr).
pub trait FlowNet {
    fn lookup(&self, h: &Handle) -> anyhow::Result<SignedRecord>;
    fn queue(&self, url: &str) -> QueueClient;         // login/deposit/collect
    // engine additionally layers presence + direct-push behind its own Delivery seam
}

/// The clients render however they like; the CLI prints, the SDK builds DTOs +
/// drives EventListener, wasm mostly no-ops (state already lands in its store).
pub trait FlowSink {
    fn stored(&mut self, thread: &str, msg: &StoredMessage, from_me: bool, group: bool);
    fn edited(&mut self, thread: &str, id: &str, text: &str, group: bool);
    fn deleted(&mut self, thread: &str, id: &str, group: bool);
    fn attachment(&mut self, id: &str, mime: &str, data: &[u8]);
    fn receipt(&mut self, from: &str, message_id: &str, read: bool);
    fn key_changed(&mut self, handle: &str);
    fn delivery(&mut self, id: &str, state: DeliveryState);
    fn note(&mut self, event: FlowNote);   // group joined/left/bootstrapped, warnings
}

pub struct FlowCtx<'a, S: Storage, P: Platform, N: FlowNet> {
    pub identity: &'a Identity, pub store: &'a mut S,
    pub platform: &'a mut P,    pub net: &'a N,
}

pub fn process_item<S,P,N>(ctx: &mut FlowCtx<S,P,N>, cfg: &FlowConfig,
                           sink: &mut dyn FlowSink, item: MailItem) -> ItemOutcome;
pub fn deliver_app<S,P,N>(ctx: &mut FlowCtx<S,P,N>, cfg: &FlowConfig,
                          sink: &mut dyn FlowSink, peer: &Handle,
                          app: AppMessage) -> anyhow::Result<SendOutcome>;
// SendOutcome { id: String, delivered: u32, state: DeliveryState }
```

Key principle: **identity + passphrase never enter `flow`.** The host resolves `Identity`
once (native `store::load_identity` / a mobile keystore / the browser) and passes it in —
removing the 30 `load_identity()` prompts and the `rpassword` dependency from the shared
layer in one move. The `ItemOutcome::{Handled,Retry}` unifies the three retry contracts
(engine `Result<()>.is_ok()`, SDK `Processed`, wasm `bool`). Follow-up sends the receive
path triggers (`send_receipt`, `distribute_key`) stay *inside* the flow — they're logic,
not presentation. The engine's live ladder stays behind a `Delivery` seam that the shared
queue floor calls; the queue path is what all three share.

## Phase order (each phase independently compiles + all client suites stay green)

1. **Groundwork** — generalize `deliver_scored`/`deliver_to_cluster_or_queue`/`flush_outbox`/
   `lookup_verified`/`process_item`/`handle_*` from concrete `FileStore` to `<S: Storage>`,
   and from hardcoded `OsPlatform` to `<P: Platform>`. Add `FlowNet`/`FlowSink`/`ItemOutcome`.
   No behavior change; the CLI still calls them. (Task #47)
2. **Receive-dispatch** — move `process_item` + the six `handle_*` into `flow`, emitting
   through `FlowSink` instead of `println!`. **This closes the wasm SelfSync/GroupSync/
   GroupLeave holes and unifies the security guards.** CLI sink prints today's exact strings;
   SDK sink builds `Message` DTOs; wasm sink is mostly no-ops. (Task #48)
3. **Send/deliver** — factor the "seal per device → deposit with `endpoints()` failover →
   record own copy → return `SendOutcome`" core into `flow`; the engine layers its live
   ladder + outbox over it. Gets live delivery + relay onto SDK/wasm and unifies the
   `verify()`+pin checks. (Task #49)
4. **Groups outbound** — shared `group_send`/`group_leave`/`distribute_key` (with the pin
   check, via `FlowCtx.store`) so leave notifies members + rekeys everywhere. (Task #49)
5. **Rewire clients as adapters + delete the dead copies.** Pairing/backup/register stay
   as thin per-client adapters (genuinely different storage/return glue); email-verify +
   push are SDK-only surfaces.

Verification per phase: `cargo test -p mycellium-cli --test e2e` (CLI), the desktop
`src-tauri` e2e (real SDK), and the wasm browser e2e (`clients/rust/e2e/wasm-*`).
