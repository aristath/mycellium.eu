# Browser end-to-end test

Drives the actual PWA in a real (system) Chrome against a live directory + queue
+ two `mycellium-client` instances. Verifies passwordless signup (name + email),
message delivery, the received-message UI (thread list, learned display names,
rendered bubbles), and the Web Push subscription wiring.

## Run

```sh
cargo build                       # from the repo root: build the debug binaries
cd clients/rust/e2e
npm install                       # once (uses puppeteer-core; no browser download)
npm test
```

Requires system Google Chrome at `/usr/bin/google-chrome` and Node 18+.

## Notes

- Sends are issued via a same-origin `fetch` from the page, not the "New message"
  modal — opening a modal disconnects *headless* Chrome (a headless-only quirk;
  modals work in a normal browser). The receive/render path is fully UI-driven.
- Web Push *delivery* can't be verified headlessly (needs a real vendor push
  round-trip to a device); the subscription wiring and VAPID key are checked.
