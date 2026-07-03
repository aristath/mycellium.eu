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
  mycellium-core/               the contract: identity (seed → keys), records,
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
  mycellium-directory-client/   HTTP client of the directory
  mycellium-queue-client/       HTTP client of the queue
  ── engine + shell ──
  mycellium-engine/             the headless peer: conversations, groups,
                                multi-device delivery, outbox retry, contacts
  mycellium-cli/                a shell: clap arg-parsing + terminal UI
```

Every crate links its own README: [core](crates/mycellium-core/README.md) ·
[directory](crates/mycellium-directory/README.md) ·
[server](crates/mycellium-server/README.md) ·
[queue](crates/mycellium-queue/README.md) ·
[transport](crates/mycellium-transport/README.md) ·
[storage](crates/mycellium-storage/README.md) ·
[directory-client](crates/mycellium-directory-client/README.md) ·
[queue-client](crates/mycellium-queue-client/README.md) ·
[engine](crates/mycellium-engine/README.md) ·
[cli](crates/mycellium-cli/README.md).

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
ratchet decrypts under many random two-way interleavings, and Shamir sharing
round-trips for random thresholds/subsets. ~105 tests in all. (The e2e suite
throttles itself to a few concurrent subprocess-heavy tests to stay reliable
under parallel runs.)

## Run the end-to-end demo

Two users (Alice and Bob) exchange an end-to-end-encrypted message over a real
direct connection, brokered only by the directory.

```sh
# 1. Start the directory (login + lookup; never sees message content)
cargo run -p mycellium-server -- --addr 127.0.0.1:8078 &

# The seed is encrypted at rest; set a passphrase (or you'll be prompted).
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

Your seed is your account; add as many devices as you like. On a **fresh**
device home, `link-device` adopts the account with the seed (no ceremony — the
seed is the authority) and adds itself to your record. From then on, messages
fan out to every device, and what you send from one device shows up on the rest.

```sh
# On your first device you already ran `identity-new` + `register mary ...`.
# On a new device (fresh MYCELLIUM_HOME), link it with the same seed:
MYCELLIUM_PHRASE="<your 24 words>" \
MYCELLIUM_HOME=/tmp/mary-laptop cargo run -p mycellium-cli -- \
    link-device mary --addr 127.0.0.1:9101 --directory http://127.0.0.1:8078

# See and manage the cluster:
MYCELLIUM_HOME=/tmp/mary cargo run -p mycellium-cli -- devices mary
MYCELLIUM_HOME=/tmp/mary cargo run -p mycellium-cli -- revoke-device mary <short-id>

# Bring a newly linked device into groups you already joined (send + receive):
MYCELLIUM_HOME=/tmp/mary cargo run -p mycellium-cli -- group sync --as mary
```

A newly linked device starts fresh (no back-history) and has its **own** message
keys — so a seed leak lets someone add a device going forward, but never
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

### Social recovery

Split your identity across guardians so a lost seed can be reconstructed from a
threshold of them:

```sh
mycellium guardian-split --shares 3 --threshold 2      # hand one share to each guardian
# ...later, on a new device, with any 2 of the 3 shares:
mycellium guardian-recover --share <s1> --share <s2>   # restores and re-encrypts the identity
```

No single guardian can impersonate you; any two together can restore you.

What happens under the hood: Alice looks up Bob's **self-signed record**, opens a
**direct TCP line**, both sides **verify each other's records**, run **X3DH** to
agree a shared secret, initialise the **Double Ratchet**, and exchange messages
the directory can neither read nor forge.

## Status

Proof of concept — feature-complete for its scope, ~105 tests (unit, real-binary
e2e, fuzz/robustness, randomized model), clippy-clean, `no_std` core.

**Done:** identity from a 24-word seed → BIP-44 wallet + device + messaging keys;
the untrusted signed directory (permanent handles, anti-rollback, rate-limited
mailbox, presence); X3DH + Double Ratchet E2E; group sender keys (create / send /
add / remove / leave / info / history with re-keying); 1:1 chat over **TCP** and
**libp2p** (full-duplex, line or `--tui`); **live push delivery** with mailbox
fallback (`serve`); typed messages (reply, react, file, edit, delete, forward,
broadcast); disappearing messages; encrypted history with search / conversations
/ clear; contacts with TOFU pinning; out-of-band safety numbers (`verify`); block
list; drafts; encrypted-at-rest seed (Argon2id + ChaCha20-Poly1305); export /
import backup; `wipe`; and **social recovery** (`guardian-split` / `-recover`).

**Multi-device** (Layer 11) is implemented: an account runs on many devices,
each with its own keys, wallet-signed into one record. `link-device` adds a
device with just the seed; a message fans out per recipient device and mirrors
to your own devices; groups fan out to each member's devices. **Deferred
frontier:** NAT traversal (DHT/relay) and phone/email recovery factors.
