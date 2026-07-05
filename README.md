# Mycellium

A peer-to-peer messenger where your message travels directly from your device to
the other person's — nothing sits in the middle of your conversation.

- **Design & rationale:** [`docs/CONCEPT.md`](docs/CONCEPT.md)
- **How it's built:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Per-crate docs:** each crate has its own `README.md` (linked below)

This README is how to build and run it.

## What's here

Split by responsibility (ports-and-adapters), so one engine can back many shells:

```
crates/
  mycellium-core/               the contract: identity (wallet → keys), records,
                                X3DH + Double Ratchet, group sender keys, wire,
                                login challenge, and the host-port *traits*
                                (Transport / Storage / Platform). no_std-capable.
  ── services (untrusted; hold only data they can't forge or read) ──
  mycellium-directory/          the name registry (library): login + signed
                                record store + presence
  mycellium-server/             deployable binary that serves the directory
  mycellium-queue/              per-recipient store-and-forward mailbox, keyed
                                by wallet, decoupled from the directory (lib+bin)
  ── adapters (implement the core ports / talk to the services) ──
  mycellium-transport/          Transport ports: framed TCP + libp2p (feature-gated)
  mycellium-storage/            Storage port: encrypted file KV + at-rest identity
  mycellium-http/               native (ureq) impl of core's HttpTransport
  mycellium-directory-client/   HTTP client of the directory (transport-injectable)
  mycellium-queue-client/       HTTP client of the queue (transport-injectable)
  mycellium-observe/            server metrics (/metrics) + structured access logs
  ── engine + shells ──
  mycellium-engine/             the headless peer: conversations, groups,
                                multi-device delivery, outbox retry, contacts
  mycellium-cli/                a shell: clap arg-parsing + terminal UI
  mycellium-wasm/               the engine compiled to WebAssembly (browser)
clients/
  rust/                         local Rust server + PWA (a native-backed client)
  web/                          the browser-native PWA — the engine runs as
                                WASM in the page, no local binary
```

Two ways to use it: the **CLI** (below) and a **browser PWA** ([`clients/web`](clients/web)) —
open a link, pick a username, and message someone with the whole client (identity,
X3DH + Double Ratchet, delivery, history) running as WebAssembly in the page. See
[the browser app](#browser-app-pwa).

Every crate links its own README: [core](crates/mycellium-core/README.md) ·
[directory](crates/mycellium-directory/README.md) ·
[server](crates/mycellium-server/README.md) ·
[queue](crates/mycellium-queue/README.md) ·
[transport](crates/mycellium-transport/README.md) ·
[storage](crates/mycellium-storage/README.md) ·
[directory-client](crates/mycellium-directory-client/README.md) ·
[queue-client](crates/mycellium-queue-client/README.md) ·
[http](crates/mycellium-http/README.md) ·
[observe](crates/mycellium-observe/README.md) ·
[engine](crates/mycellium-engine/README.md) ·
[cli](crates/mycellium-cli/README.md) ·
[wasm](crates/mycellium-wasm/README.md).
New to the project? Start with [`docs/QUICKSTART.md`](docs/QUICKSTART.md); for the
browser build see [`docs/BROWSER.md`](docs/BROWSER.md); to run it for real see
[`docs/DEPLOY.md`](docs/DEPLOY.md) and [`docs/GO-LIVE.md`](docs/GO-LIVE.md).

The core depends only on the `Transport`, `Storage`, and `Platform` traits, so
the same protocol runs from a microcontroller to a desktop. The CLI ships two
transports behind that trait — raw **TCP** and **libp2p** (TCP + Noise + Yamux,
PeerId derived from the device key). Add `--libp2p` to `register`/`listen`;
`chat` auto-detects which to use from the peer's published address. NAT
traversal (DHT/relay) is the remaining libp2p increment.

## Build & test

```sh
cargo test --workspace          # unit + real end-to-end tests
cargo test -p mycellium-cli --test e2e   # 2-account e2e: offline + live chat (TCP & libp2p)
cargo build --release           # optimized binaries
cargo build -p mycellium-core --no-default-features   # the no_std core, for embedded
```

The `e2e` suite spins up a real directory in-process and drives the actual
`mycellium-cli` binary through the whole flow — two accounts creating identities,
registering, and exchanging messages — asserting on the decrypted output, over
both transports and the offline mailbox. A separate `robustness` suite fuzzes
the wire decoders with garbage/truncated/bit-flipped bytes (never panics, never
accepts a tampered record) and checks the ratchet rejects replays and bounds
skips. A `model` suite checks correctness properties over random inputs — the
ratchet decrypts under many random two-way interleavings. ~160 workspace tests in
all, plus ten real-browser suites (WASM crypto, sealing, storage, networked
messaging, groups, multi-device pairing, and the full two-user PWA flow) under
[`clients/rust/e2e`](clients/rust/e2e). (The e2e suite throttles itself to a few
concurrent subprocess-heavy tests to stay reliable under parallel runs.)

## Browser app (PWA)

The consumer interface: a static Progressive Web App that runs the engine as
WebAssembly — no local binary, no `localhost` server. It talks directly to a
directory and queue; those servers only ever move opaque sealed blobs.

```sh
# Build the WASM engine + JS bindings (once):
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.100
./clients/web/build.sh                 # → clients/web/pkg

# Start a directory + queue (see below), serve clients/web over HTTPS, open it.
# First load: set your directory/queue URLs, pick a username, and chat.
```

Everything runs in the page: passwordless identity (persisted in IndexedDB, so it
survives reloads), record publishing, X3DH-sealed send, queue deposit/collect,
decryption, and history — plus desktop notifications, reply / react / delete, and
Web Push wiring. Six headless-Chrome suites in
[`clients/rust/e2e`](clients/rust/e2e) (`wasm*.test.mjs`, `pwa.test.mjs`) cover it
end to end, up to a two-user message delivered *browser → servers → browser*.

> HTTPS is required off `localhost` (service workers + Web Push). Deploy behind
> Caddy/nginx — see [`docs/DEPLOY.md`](docs/DEPLOY.md). Production readiness is
> tracked in [`docs/PRODUCTION-READINESS.md`](docs/PRODUCTION-READINESS.md).

## Run the end-to-end demo

Two users (Alice and Bob) exchange an end-to-end-encrypted message over a real
direct connection, brokered only by the directory.

```sh
# 1. Start the directory (login + lookup; never sees message content)
cargo run -p mycellium-server -- --addr 127.0.0.1:8078 &

# The account key is encrypted at rest; set a passphrase (or you'll be prompted).
export MYCELLIUM_PASSPHRASE="a strong passphrase"

# 2. Bob: create an identity, register a handle, and listen
MYCELLIUM_HOME=/tmp/bob   cargo run -p mycellium-cli -- identity-new
MYCELLIUM_HOME=/tmp/bob   cargo run -p mycellium-cli -- register bob --addr 127.0.0.1:9003 \
                          --directory http://127.0.0.1:8078
MYCELLIUM_HOME=/tmp/bob   cargo run -p mycellium-cli -- listen --addr 127.0.0.1:9003 &

# 3. Alice: create an identity, look Bob up, connect, and type messages
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- identity-new
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- chat bob --as alice \
                          --directory http://127.0.0.1:8078
```

You can keep a local address book of nicknames (each pins the peer's identity —
if their wallet later differs, Mycellium refuses, catching a swapped identity):

```sh
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- contact add b bob   # then use "b" anywhere
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- chat b --as alice
```

See who's online (announce yourself, then others can check):

```sh
MYCELLIUM_HOME=/tmp/bob   cargo run -p mycellium-cli -- announce --as bob --directory http://127.0.0.1:8078
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- presence bob --directory http://127.0.0.1:8078
```

Stay online to receive messages **pushed live** (bypassing the mailbox). While
you run `serve`, senders deliver directly to you; when you're not serving, they
fall back to your mailbox automatically — one delivery path, no config:

```sh
MYCELLIUM_HOME=/tmp/bob   cargo run -p mycellium-cli -- serve --addr 127.0.0.1:9003 --as bob \
                          --directory http://127.0.0.1:8078
# now `send`, `group send`, `broadcast`, and `forward` reach Bob live
```

Verify a peer's identity out of band any time (matching numbers = no impostor):

```sh
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- verify bob
```

Block a handle to drop its messages (and refuse its connections):

```sh
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- block spammer
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- blocked        # unblock with `unblock`
```

The chat is **full-duplex**: both terminals can type and both see the other's
messages arrive, decrypted, in real time (Ctrl-D to quit). Under the hood the
connection is split into read/write halves and the ratchet is shared under a
mutex; the responder starts replying once it has received the first message.

Add `--tui` to `chat` or `listen` for a **full-screen terminal interface**
(scrolling transcript + input box, colored sender labels):

```sh
MYCELLIUM_HOME=/tmp/bob   cargo run -p mycellium-cli -- listen --addr 127.0.0.1:9003 --tui
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- chat bob --as alice --tui \
                          --directory http://127.0.0.1:8078
```

Conversations are saved locally, **encrypted at rest** (key derived from your
identity). A chat replays earlier messages on connect, and you can review them
any time:

```sh
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- history bob
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- conversations   # all chats + last message
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- search harbor   # across all transcripts
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- clear-history bob
```

Back up and restore everything (identity + local data) — already encrypted at
rest, so the bundle is safe:

```sh
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- export ./mycellium-backup.bin
MYCELLIUM_HOME=/tmp/new   cargo run -p mycellium-cli -- import ./mycellium-backup.bin   # into a fresh home
```

### Multiple devices

Add as many devices as you like — there is **no seed phrase to copy**. A new
device **pairs** with your account over an authenticated, one-time channel: the
new device shows an offer (a QR/code), an existing device approves it, and the
account key is transferred without ever riding in a copyable payload. From then
on, messages fan out to every device, and what you send from one shows up on the
rest.

```sh
# On your first device you already ran `identity-new` + `register mary ...`.
# On the NEW device (a fresh MYCELLIUM_HOME), start pairing — it prints an offer:
MYCELLIUM_HOME=/tmp/mary-laptop cargo run -p mycellium-cli -- \
    pair mary --addr 127.0.0.1:9101 --queue http://127.0.0.1:8090 --directory http://127.0.0.1:8078

# On your EXISTING device, approve the offer it printed:
MYCELLIUM_HOME=/tmp/mary cargo run -p mycellium-cli -- \
    pair-approve <offer> --as mary --directory http://127.0.0.1:8078

# See and manage the cluster:
MYCELLIUM_HOME=/tmp/mary cargo run -p mycellium-cli -- devices mary
MYCELLIUM_HOME=/tmp/mary cargo run -p mycellium-cli -- revoke-device mary <short-id>

# Bring a newly paired device into groups you already joined (send + receive):
MYCELLIUM_HOME=/tmp/mary cargo run -p mycellium-cli -- group sync --as mary
```

A newly paired device starts fresh (no back-history) and has its **own** message
keys — so an account-key leak lets someone add a device going forward, but never
decrypts your past traffic.

### Group messaging

Groups use **sender keys**: create a group and each member gets your key over
their pairwise end-to-end channel; a group message is encrypted once and fans
out to everyone via their mailboxes.

```sh
# Alice creates a group and invites Bob and Carol
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- group create team \
                          --members bob,carol --as alice --directory http://127.0.0.1:8078

# Bob and Carol pick up the invite (and each other's keys) from their inbox
MYCELLIUM_HOME=/tmp/bob   cargo run -p mycellium-cli -- inbox --as bob   --directory http://127.0.0.1:8078
MYCELLIUM_HOME=/tmp/carol cargo run -p mycellium-cli -- inbox --as carol --directory http://127.0.0.1:8078

# Alice sends to the whole group; members read it from their inbox
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- group send team --as alice \
                          --message "hello team" --directory http://127.0.0.1:8078
MYCELLIUM_HOME=/tmp/bob   cargo run -p mycellium-cli -- inbox --as bob --directory http://127.0.0.1:8078

# Membership changes (add invites + re-keys; remove excludes and re-keys):
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- group add    team --member dave  --as alice ...
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- group remove team --member carol --as alice ...
MYCELLIUM_HOME=/tmp/bob   cargo run -p mycellium-cli -- group leave team --as bob   # notifies + re-keys
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- group info team
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- group list
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- group history team   # local transcript
```

Housekeeping: save a **draft** per peer, or **wipe** all local data:

```sh
mycellium draft set bob "half-written thought"   # show / clear too
mycellium wipe --yes                             # erase identity + messages (irreversible)
```

Group transcripts, like 1:1 history, are saved encrypted at rest.

### Offline delivery

When the peer isn't online, queue a message and let them fetch it later:

```sh
# Alice sends while Bob is offline (async X3DH against Bob's published keys)
MYCELLIUM_HOME=/tmp/alice cargo run -p mycellium-cli -- send bob --as alice \
                          --message "catch you later" --directory http://127.0.0.1:8078

# Bob later drains and decrypts his mailbox
MYCELLIUM_HOME=/tmp/bob   cargo run -p mycellium-cli -- inbox --as bob \
                          --directory http://127.0.0.1:8078
```

The directory stores only the opaque, end-to-end-encrypted envelope — it can't
read it, and only Bob can collect his own mailbox.

Messages carry an id, so you can **reply** or **react** to one (works for
`send` and `group send`):

```sh
# Reply to message #ab12cd with text; or react to it with an emoji
mycellium send alice --as bob --message "sure" --reply-to ab12cd
mycellium send alice --as bob --react 👍 --to ab12cd
# Edit or unsend an earlier message; forward one to someone else
mycellium send alice --as bob --edit ab12cd --message "typo fixed"
mycellium send alice --as bob --delete ab12cd
mycellium forward ab12cd --from alice --to carol --as bob
# Send a file (saved to the recipient's downloads folder)
mycellium send alice --as bob --file ./photo.png
# Disappearing messages: per-message, or a per-conversation default
mycellium send alice --as bob --message "secret" --expire 10m
mycellium expire set alice 1h     # new messages to alice default to 1h (clear/show too)
```

Disappearing messages are best-effort: our client deletes on schedule, but it
can't stop a modified peer client from keeping a copy.

### Recovery

There is no seed phrase to lose. If you still have a device, add more by
[pairing](#multiple-devices). If you lose every device, recover through the
directory's **email verification**: prove control of a registered email and
re-bind your handle. (Trade-off: an email rebind points your handle at a **new**
wallet, so peers re-verify your safety number — see [`docs/SECURITY.md`](docs/SECURITY.md).)

What happens under the hood: Alice looks up Bob's **self-signed record**, opens a
**direct TCP line**, both sides **verify each other's records**, run **X3DH** to
agree a shared secret, initialise the **Double Ratchet**, and exchange messages
the directory can neither read nor forge.

## Status

Feature-complete for its scope, ~160 workspace tests (unit, real-binary e2e,
fuzz/robustness, randomized model) plus ten real-browser suites, clippy-clean,
`no_std` core. See [`docs/PRODUCTION-READINESS.md`](docs/PRODUCTION-READINESS.md)
for the path to a public launch.

**Done:** seedless identity — a random secp256k1 wallet + per-device + messaging
keys, no seed phrase (email-verified recovery); the untrusted signed directory
(permanent handles, anti-rollback, rate-limited mailbox, presence); X3DH + Double
Ratchet E2E; group sender keys (create / send / add / self-leave / info / history
with re-keying); 1:1 chat over **TCP** and **libp2p** (full-duplex, line or
`--tui`); **live push delivery** with mailbox fallback (`serve`); typed messages
(reply, react, file, edit, delete, forward, broadcast); disappearing messages;
encrypted history with search / conversations / clear; contacts with TOFU pinning;
out-of-band safety numbers (`verify`); block list; drafts; encrypted-at-rest
account key (Argon2id + ChaCha20-Poly1305); export / import backup; and `wipe`.

**Multi-device** (Layer 11) is implemented: an account runs on many devices, each
with its own keys, wallet-signed into one record. A new device **pairs** in over
an authenticated, single-use channel (`pair` / `pair-approve` — the account key
never rides in a copyable payload); a message fans out per recipient device and
mirrors to your own devices; groups fan out to each member's devices.

**Browser build** (Layer 11.1): the same engine runs as WebAssembly in an
installable PWA ([`clients/web`](clients/web)) — 1:1 + groups, attachments,
notifications + Web Push, multi-device linking by QR or link, all client-side. The
directory and queue now **persist** (embedded redb), send real verification email
with account **recovery**, terminate TLS, rate-limit, and expose `/metrics` + logs.

**Deferred frontier:** NAT traversal (DHT/relay), a non-US mobile push relay, and
an independent security audit before a public launch.
