# mycellium-cli

> The terminal shell over the Mycellium engine: clap argument parsing plus an interactive chat/listen UI.

**Layer:** shell · **Depends on:** mycellium-engine (+ clap for parsing, ratatui for the terminal UI, and the core/transport/storage/directory-client crates it re-exports)

## What it does

A thin shell over the headless `mycellium-engine`. It owns only two things:
argument parsing (the clap `Cli`/`Command` enums) and presentation — the
interactive full-duplex `chat`/`listen` sessions and record/transcript
rendering. No protocol logic lives here; every command dispatches straight into
`mycellium_engine::app`, which does the orchestration.

## Commands

**Identity & devices**

| Command | Does |
|---------|------|
| `identity-new` | Create a new identity (random wallet key, no seed phrase), stored locally. |
| `identity-show` | Show this device's public identity. |
| `register <handle> --addr <a> [--libp2p]` | Claim a handle and publish your signed record. |
| `pair <handle> --addr <a> --queue <url> [--libp2p]` | On a **fresh** device: print a one-time pairing offer and adopt the account once approved. |
| `pair-approve <offer> --as <handle>` | On an **existing** device: approve a new device's offer (seals the account key to it). |
| `devices <handle>` | List the devices in an account's cluster. |
| `revoke-device <handle> <device_id>` | Remove a device from your cluster. |

**Messaging**

| Command | Does |
|---------|------|
| `send <peer> --as <me> [--message/--react/--to/--file/--edit/--delete/--reply-to/--expire]` | Queue an offline message (reply, react, attach, edit, unsend, disappear). |
| `chat <peer> --as <me> [--tui]` | Look a peer up, open a direct line, chat live. |
| `listen --addr <a> [--libp2p] [--tui]` | Wait for a peer to connect and chat. |
| `serve --addr <a> --as <me>` | Stay online and receive live-pushed messages. |
| `inbox --as <me>` | Fetch and decrypt queued offline messages. |
| `outbox` | Retry undelivered messages; show what's still waiting. |
| `broadcast --to a,b --as <me> --message <m>` | Send one message to several peers. |
| `forward <message_id> --from <p> --to <p> --as <me>` | Forward a stored message to another peer. |
| `announce --as <me>` / `presence <peer>` | Heartbeat the directory / check if a handle is online. |
| `verify <peer> [--confirm]` | Show the safety number + trust state (unverified / pinned / verified / **changed**); `--confirm` marks the peer verified after you compare it out of band. |
| `card <handle>` | Print your own contact card (a QR + code) for a peer to scan and verify you. |
| `verify-card <card>` | Verify a peer from their contact card — compares it against the directory record; a mismatch fails closed. |

**Groups**

| Command | Does |
|---------|------|
| `group create <name> --members a,b --as <me>` | Create a group and invite members (auto-includes the creator). |
| `group send <group> --as <me> [--message/--react/--to/--file/--edit/--delete/--reply-to/--expire]` | Send a message to the group (fans out to every member). |
| `group add <group> --member <h> --as <me>` | Invite another member to an existing group. |
| `group remove <group> --member <h> --as <me>` | Remove a member and re-key the rest. |
| `group history <group>` / `group info <group>` | Show a group's transcript / name, id, and members. |
| `group leave <group> --as <me>` | Leave a group (notifies the others to re-key). |
| `group sync --as <me>` | Bootstrap your other devices into your groups. |
| `group list` | List the groups this device knows about. |

**Contacts & organization**

| Command | Does |
|---------|------|
| `contact add <nickname> <handle>` / `list` / `remove <nickname>` | Manage the local nickname address book (TOFU-pinned). |
| `history <peer>` / `clear-history <peer>` | Show or delete a peer's stored transcript. |
| `conversations` | List all conversations with a last-message preview. |
| `search <query>` | Search all local 1:1 and group transcripts. |
| `draft set/show/clear <peer> [text]` | Save/show/clear a per-peer draft. |
| `expire set/clear/show <target> [duration]` | Per-conversation default disappearing-message timer. |
| `block <h>` / `unblock <h>` / `blocked` | Manage the blocklist. |

**Backup & recovery**

| Command | Does |
|---------|------|
| `export <path>` / `import <path>` | Back up / restore identity + local data. |
| `wipe --yes` | Erase ALL local data. Irreversible. |

Account recovery after losing every device is via the directory's **email
verification** (re-bind your handle to a new wallet), not a seed phrase or
guardian shares — see [`docs/SECURITY.md`](../../docs/SECURITY.md).

**Notes**

- Every command that talks to the directory takes `--directory <url>`
  (default `http://127.0.0.1:8080`); the tables omit it per row.
- `chat`/`listen` render a line-mode session by default; pass `--tui` for the
  full-screen ratatui UI.
- `register`, `pair`, `listen`, and `chat` accept `--libp2p` to advertise
  (or dial) a libp2p multiaddr carrying a PeerId instead of a raw host:port.
- Contacts are **TOFU-pinned**: `contact add` binds the nickname to the peer's
  current identity on first add, and re-adding a nickname bound to a different
  identity is refused.
- Adding a device uses **pairing** (`pair` on the new device, `pair-approve` on
  an existing one): the account key moves over an authenticated, single-use
  channel, never as a copyable seed. `export`/`import` move a portable, encrypted
  backup bundle between machines.

**Environment variables**

- `MYCELLIUM_QUEUE` — your queue endpoint, recorded in your signed record so
  senders can reach you (empty = pure P2P, live-push only).
- `MYCELLIUM_NAME` — your display name.
- `MYCELLIUM_HOME` — where identity + local data are stored.
- `MYCELLIUM_PASSPHRASE` — unlocks the stored identity.

## Quick start

```sh
# 1. Start the shared services (directory + queue).
mycellium-server --addr 127.0.0.1:8080 &
mycellium-queue  --addr 127.0.0.1:8090 &

# 2. Point the client at its queue, then create + register an identity.
export MYCELLIUM_QUEUE=http://127.0.0.1:8090
mycellium identity-new
mycellium register ari --addr 127.0.0.1:9001 --directory http://127.0.0.1:8080

# 3. Queue an offline message to a peer, then drain your own inbox.
mycellium send bob --as ari --message "hi from the shell" --directory http://127.0.0.1:8080
mycellium inbox --as ari --directory http://127.0.0.1:8080
```

```sh
# A group workflow: create, send, then read the transcript back.
mycellium group create book-club --members bob,carol --as ari
mycellium group send book-club --as ari --message "first chapter tonight?"
mycellium group history book-club
```

## How it fits

This crate is just *one* shell over `mycellium-engine` — the terminal one. Every
piece of behavior it exposes is an engine call, so a future GUI, mobile, or PWA
front-end can drive the exact same headless engine without reimplementing any
protocol logic.
