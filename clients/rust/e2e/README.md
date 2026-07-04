# Browser end-to-end test

Drives the actual PWA in a real (system) Chrome against a live directory + queue
+ two `mycellium-client` instances, entirely through the UI. Verifies:

- passwordless signup (name + email — no password, no seed phrase),
- composing + sending via the "New message" flow,
- delivery and the received-message UI (thread list, display names learned from
  the signed record, rendered conversation bubbles),
- replying via the message-action menu,
- adding a contact by email,
- **desktop notifications** — one *is* raised for a message you're not viewing,
  and *isn't* while you're looking at that conversation (the `Notification` API
  is mocked in-page to record what the app would pop),
- the Web Push subscription wiring (VAPID key, service worker).

## Run

```sh
cargo build                       # from the repo root: build the debug binaries
cd clients/rust/e2e
npm install                       # once (uses puppeteer-core; no browser download)
npm test
```

Requires system Google Chrome at `/usr/bin/google-chrome` and Node 18+.

## Notes

- Interactions use JS-triggered clicks (`element.click()`) and value-setting,
  not Puppeteer's synthetic mouse/keyboard. A synthetic mouse click that opens
  an overlay crashes *headless* Chrome (a headless-only quirk; the app is fine
  in a normal browser), and `waitForFunction` proved flaky here — so the test
  polls the DOM via `evaluate`.
- Web Push *delivery* can't be verified headlessly (needs a real vendor push
  round-trip to a device); the subscription wiring and VAPID key are checked.
