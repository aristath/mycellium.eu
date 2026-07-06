# Quickstart

Run the whole of Mycellium locally in a few minutes — the two services, the CLI,
and the browser PWA. For the design, see [`CONCEPT.md`](CONCEPT.md); for the map of
crates, [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Prerequisites

- **Rust** (stable) with the `wasm32-unknown-unknown` target for the browser build:
  `rustup target add wasm32-unknown-unknown` and `cargo install wasm-bindgen-cli`.
- **Chrome/Chromium** only if you want to run the browser e2e suites.

## 1. Start the shared services

They're untrusted infrastructure — a name registry and a store-and-forward mailbox.
In two terminals (or backgrounded):

```sh
cargo run -p mycellium-server -- --addr 127.0.0.1:8080    # directory
cargo run -p mycellium-queue  -- --addr 127.0.0.1:8090    # queue
```

Both run in-memory by default. To persist across restarts, set `MYCELLIUM_DATA`:

```sh
MYCELLIUM_DATA=./data/dir   cargo run -p mycellium-server -- --addr 127.0.0.1:8080
MYCELLIUM_DATA=./data/queue cargo run -p mycellium-queue  -- --addr 127.0.0.1:8090
```

Check them: `curl localhost:8080/health` and `curl localhost:8090/health` → `ok`.

## 2. Talk with the CLI

Each account points at the queue via `MYCELLIUM_QUEUE` and at the directory via
`--directory`. Use a separate `MYCELLIUM_HOME` per identity to keep them apart:

```sh
export MYCELLIUM_QUEUE=http://127.0.0.1:8090

# Alice
MYCELLIUM_HOME=~/.myc-alice mycellium identity-new
MYCELLIUM_HOME=~/.myc-alice mycellium register alice --addr 127.0.0.1:9001 --directory http://127.0.0.1:8080

# Bob
MYCELLIUM_HOME=~/.myc-bob mycellium identity-new
MYCELLIUM_HOME=~/.myc-bob mycellium register bob --addr 127.0.0.1:9002 --directory http://127.0.0.1:8080

# Alice queues a message for Bob; Bob drains his inbox.
MYCELLIUM_HOME=~/.myc-alice mycellium send bob --as alice --message "hi from the shell" --directory http://127.0.0.1:8080
MYCELLIUM_HOME=~/.myc-bob   mycellium inbox --as bob --directory http://127.0.0.1:8080
```

For a live, full-duplex session instead of the mailbox, use `listen` / `chat`
(add `--tui` for the full-screen UI). See the
[CLI README](../crates/mycellium-cli/README.md) for every command.

## 3. Run the browser PWA

```sh
./clients/web/build.sh                                   # compile the engine to WASM
python3 -m http.server 8000 --directory clients/web      # serve the static app
```

Open **`http://localhost:8000/?dir=http://localhost:8080&queue=http://localhost:8090`**,
pick a username, and you're messaging — identity, crypto, and delivery all run in
the page. Open a second browser profile (or an incognito window) to be a second
person. See [`BROWSER.md`](BROWSER.md) and [`clients/web/README.md`](../clients/web/README.md).

## 4. Run the tests

```sh
cargo test --workspace                        # ~244 native tests
cargo test -p mycellium-cli --test e2e        # two-account e2e over TCP + libp2p + mailbox
node clients/rust/e2e/pwa.test.mjs            # full browser PWA flow (needs step 3's build)
# or run any of the 11 standalone browser/load suites in clients/rust/e2e
```

## Next steps

- Deploy it for real: [`DEPLOY.md`](DEPLOY.md) and the [`GO-LIVE.md`](GO-LIVE.md) checklist.
- Understand the trust boundaries: [`SECURITY.md`](SECURITY.md).
- Hack on it: [`CONTRIBUTING.md`](CONTRIBUTING.md).
