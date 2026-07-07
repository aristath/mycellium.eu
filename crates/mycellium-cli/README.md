# mycellium-cli

`mycellium` — a thin, runnable messenger CLI over
[`mycellium-app`](../mycellium-app), the headless MLS-over-Nostr (Marmot)
engine. The CLI only parses arguments, holds the on-disk config (this device's
key + relay URLs), and drives the engine.

## Data & config

State lives under `--data-dir` (default `$HOME/.mycellium`, or
`$MYCELLIUM_DATA_DIR`): a `config.json` (this device's `nsec` + relay URLs)
alongside the two SQLCipher-encrypted databases `mycellium-app` maintains (MLS
state + app data).

## Quick start

```sh
# Create an identity + config (defaults to a public relay; --relay is repeatable).
mycellium account new --relay wss://relay.damus.io

# Announce this device to the relays (KeyPackage + device list).
mycellium publish

# Add a contact by npub, hex pubkey, or nip05 handle, then list contacts.
mycellium contact add npub1... alice
mycellium contacts

# Open an interactive 1:1 conversation: type a line to send, Ctrl-D to quit.
mycellium chat alice

# Drain incoming messages non-interactively for a few seconds.
mycellium inbox --seconds 10
```

## Commands

- `account new [--relay <url>]... [--force]`, `account show`
- `publish` — publish this device's KeyPackage + account device list
- `contact add <npub|hex|nip05> [name]`, `contacts`
- `chat <contact>` — interactive 1:1 conversation
- `inbox [--seconds N]` — connect, drain, and print incoming messages
- `relays` — show the configured relay URLs

A global `--data-dir`/`-d` selects the profile directory for any command.
