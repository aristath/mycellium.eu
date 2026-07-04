# Contributing

How to build, test, and find your way around Mycellium. For the design read
[`CONCEPT.md`](CONCEPT.md); for the map of crates [`ARCHITECTURE.md`](ARCHITECTURE.md);
to run everything [`QUICKSTART.md`](QUICKSTART.md).

## Setup

- **Rust** (stable). For the browser build add the target and bindgen tool:
  ```sh
  rustup target add wasm32-unknown-unknown
  cargo install wasm-bindgen-cli   # must match the pinned wasm-bindgen version
  ```
- **Chrome/Chromium** + Node, only for the browser e2e suites (`puppeteer-core`).

## Build & test

```sh
cargo test --workspace                      # ~129 native tests
cargo clippy --workspace --all-targets      # keep it warning-clean
cargo build -p mycellium-core --no-default-features   # the no_std core still builds

cargo test -p mycellium-cli --test e2e      # two-account e2e (TCP + libp2p + mailbox)

./clients/web/build.sh                       # compile the WASM engine
node clients/rust/e2e/pwa.test.mjs           # full browser PWA flow (needs the build)
```

The browser suites live in [`clients/rust/e2e`](../clients/rust/e2e) — `wasm-*.test.mjs`
drive the `Session` directly; `pwa.test.mjs` drives the real UI in headless Chrome.
They spin up a real directory + queue per run.

## Where things live

- **Protocol contract** → `mycellium-core` (`no_std`; identity, X3DH, ratchet,
  groups, wire, and the `Transport`/`Storage`/`Platform`/`HttpTransport` ports).
- **Behavior** → `mycellium-engine`. Domain modules (history, contacts, groups, …)
  are generic and compile to wasm; native orchestration is in `app/*` behind the
  `native` feature; shared platform-agnostic crypto is in `wireops`.
- **Shells** → `mycellium-cli` (terminal) and `mycellium-wasm` → `clients/web` (PWA).
  Both are thin: parse/translate input, call the engine.
- **Services** → `mycellium-directory` (+ `mycellium-server` bin) and
  `mycellium-queue`; adapters `mycellium-http` (native HTTP), `mycellium-transport`,
  `mycellium-storage`; support `mycellium-observe`.

## Conventions

- **Ports & adapters.** The core touches no OS. Anything host-specific goes behind a
  trait and is implemented per platform — that's what keeps the engine buildable for
  both native and WASM. New host capabilities become new ports, not `#[cfg]` sprawl.
- **Two builds must both stay green.** If you touch the engine, check it still
  compiles to wasm (`./clients/web/build.sh`) *and* native. Domain logic stays
  generic; put native-only code behind `native`.
- **No invented crypto.** Compose vetted primitives (RustCrypto); secret types
  `zeroize` on drop; `unsafe` is forbidden in the core.
- **Match the surrounding style.** Comment density, naming, and structure should read
  like the file you're editing. Keep commit messages short (subject line).
- **Tests travel with changes.** A protocol change needs a model/robustness test; a
  feature needs an e2e or browser test.

## Good first areas

The rough edges in [`IMPROVEMENTS.md`](IMPROVEMENTS.md) are sized and scoped — e.g.
routing group control messages through the outbox, merging the device list on browser
`register`, or GC'ing deleted attachments. The open frontier
([`PRODUCTION-READINESS.md`](PRODUCTION-READINESS.md)) is larger: NAT traversal, a
non-US push relay, and the security audit.

## Reporting security issues

Please report privately and allow time to fix before public disclosure — see
[`SECURITY.md`](SECURITY.md).
