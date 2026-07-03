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
| `identity-new` | Create a new 24-word-seed identity, stored locally. |
| `identity-show` | Show this device's public identity. |
| `register <handle> --addr <a> [--libp2p] [--directory]` | Claim a handle and publish your signed record. |
| `link-device <handle> --addr <a> [--libp2p]` | Adopt an existing account on a fresh device (reads `MYCELLIUM_PHRASE` or stdin). |
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
| `forward <message_id> --from <p> --to <p> --as <me>` | Forward a stored message. |
| `announce --as <me>` / `presence <peer>` | Heartbeat the directory / check if a handle is online. |
| `verify <peer>` | Show the safety number for out-of-band identity verification. |

**Groups** — `group create <name> --members a,b --as <me>`, `group send <group> --as <me> [--message …]`, `group add/remove <group> --member <h> --as <me>`, `group history/info <group>`, `group leave <group> --as <me>`, `group sync --as <me>`, `group list`.

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
| `guardian-split --shares <n> --threshold <t>` | Split your identity into t-of-n social-recovery shares. |
| `guardian-recover --share <s> …` | Recover an identity from guardian shares. |
| `export <path>` / `import <path>` | Back up / restore identity + local data. |
| `wipe --yes` | Erase ALL local data. Irreversible. |

## Quick start

```sh
# 1. Start the shared services (directory + queue) — see mycellium-server.
mycellium-server --directory-addr 127.0.0.1:8080 &

# 2. Point the client at its queue, then create + register an identity.
export MYCELLIUM_QUEUE=http://127.0.0.1:8081
mycellium identity-new
mycellium register ari --addr 127.0.0.1:9001 --directory http://127.0.0.1:8080

# 3. Queue an offline message to a peer, then drain your own inbox.
mycellium send bob --as ari --message "hi from the shell"
mycellium inbox --as ari
```

## How it fits

This crate is just *one* shell over `mycellium-engine` — the terminal one. Every
piece of behavior it exposes is an engine call, so a future GUI, mobile, or PWA
front-end can drive the exact same headless engine without reimplementing any
protocol logic.
