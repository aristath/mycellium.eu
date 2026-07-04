# Browser & load end-to-end tests

Real-Chrome (Puppeteer) and load suites for the browser build. Each spins up a live
`mycellium-directory` + `mycellium-queue`, serves `clients/web` from a separate
origin, and runs the WASM engine (or the full PWA UI) against them. Build first:
`./clients/web/build.sh` and `cargo build`.

## Suites

| Suite | What it proves |
|-------|----------------|
| `wasm.test.mjs` | The WASM engine loads; identity + crypto helpers work in isolation. |
| `wasm-net.test.mjs` | The whole client stack in-browser: a real directory login + queue deposit/collect over the injected XHR transport, cross-origin. |
| `wasm-seal.test.mjs` | Two `Session`s do a real X3DH + Double Ratchet seal/open in the browser. |
| `wasm-message.test.mjs` | The message codec end to end — text, reply, react, delete, file. |
| `wasm-store.test.mjs` | Store `put`/`get`/`del`, **IndexedDB persistence across reload** (via the worker), and the engine's history module in-browser. |
| `wasm-group.test.mjs` | Group create, the bidirectional sender-key mesh, add-member, and leave. |
| `wasm-multidevice.test.mjs` | A second device adopts an account from a link payload; a message fans out to **both** devices. |
| `pwa.test.mjs` | The full **two-user UI flow**: signup, send/receive, reply, react, delete, image attachment, groups (create/add), settings rename, multi-device QR/link, and the offline indicator. |
| `browser.test.mjs` | A companion full-PWA UI run in system Chrome. |
| `load.test.mjs` | T2.4 load check — hammers the directory concurrently, confirms the worker pool drops nothing, reports throughput + latency percentiles. |

## Run

```sh
cargo build                       # from the repo root: build the debug binaries
./clients/web/build.sh            # compile the WASM engine into clients/web/pkg/
cd clients/rust/e2e
npm install                       # once (puppeteer-core; no browser download)
node pwa.test.mjs                 # or any suite above; `npm test` runs the default
```

Requires system Google Chrome at `/usr/bin/google-chrome` and Node 18+.

## Notes

- Interactions use JS-triggered clicks (`element.click()`) and value-setting, not
  Puppeteer's synthetic mouse/keyboard: a synthetic click that opens an overlay
  crashes *headless* Chrome (a headless-only quirk — the app is fine in a normal
  browser), and `waitForFunction` proved flaky here, so the tests poll the DOM via
  `evaluate`.
- The suites reach the engine two ways: through the UI (RPC to the Web Worker) and,
  for lower-level checks, through the test hook `window.mycellium` (the `Session`
  class + `rpc`) — which exists for tests and should be stripped from a production
  build.
- Web Push *delivery* can't be verified headlessly (it needs a real vendor round
  trip); the subscription wiring + VAPID key are checked instead.
