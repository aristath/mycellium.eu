# mycellium-engine

> The headless Mycellium peer — all orchestration, no presentation.

**Layer:** engine (headless) · **Depends on:** mycellium-core + the transport / storage / directory-client / queue-client adapters

## What it does

The engine composes the core protocol (X3DH, Double Ratchet, group sender keys)
with the host-port adapters and owns the actual messaging behaviour: it
registers identities, runs 1:1 conversations, drives the delivery ladder,
fans messages out across a cluster of devices and self-syncs them, runs groups,
and keeps contacts, blocklist, drafts, disappearing-message timers, encrypted
history, and the outbox. It reaches names and signed records through
`DirectoryClient` and deposits/collects ciphertext through `QueueClient`; it
carries no argument parsing and no terminal UI. That split is deliberate — the
same engine can back a CLI, a GUI, or a mobile shell, all driving the functions
in [`app`](src/app).

## Modules

`app/*` is the orchestration a shell invokes; the top-level modules are the
domain state it operates on (each generic over `mycellium_core::storage`).

| Module | Owns |
|--------|------|
| `app/session` | Live-connection handshakes: `handshake_initiator` / `handshake_responder` build a `Session` (ratchet + AEAD `ad` + peer name). |
| `app/messaging` | The heart: `send`, `broadcast`, `forward`, `serve`, `inbox`, `deliver`, `QueueTarget`, `flush_outbox`, `outbox_show`, `process_item`, `handle_direct`, `handle_self_sync`, `send_receipt`, `seal_to`, `open_envelope`. |
| `app/grouping` | Groups over sender keys: `group_create` / `_add` / `_remove` / `_send` / `_leave` / `_sync` / `_list` / `_info` / `_history`, `distribute_key`, and the `handle_group_*` receivers. |
| `app/devices` | Identity + cluster: `identity_new` / `_show`, `register`, `link_device`, `list_devices`, `revoke_device`, `update_devices`, `guardian_split` / `_recover`, `build_record`, `this_device`, `device_slot`, `my_group_id`. |
| `app/directory_ops` | `announce`, `verify`, `presence`, and `lookup_verified` (nickname → handle → TOFU wallet-pin check). |
| `app/organize` | Contacts, blocklist, drafts, expiry, and read-side views: `conversations`, `search`, `show_history`, `clear_history`. |
| `app/backup` | `export_backup` / `import_backup` (a portable `Backup` bundle) and `wipe`. |
| `app/util` | Shared helpers: `own_queue`, `open_history`, `build_message`, `resolve_expiry`, `associated_data`, `text_message`, attachments, hex, durations. |
| `contacts` | Encrypted address book, nickname → handle, wallet **pinned** on first add (TOFU); `resolve`, `by_handle`. |
| `blocklist` | Handles whose messages we silently drop; `block` / `unblock` / `is_blocked`. |
| `draft` | Per-conversation draft text. |
| `expiry` | Per-conversation default disappearing-message TTL. |
| `groups` | The `MailItem` enum, `GroupInvitePayload` / `GroupSyncPayload`, and `StoredGroup` (roster + `sender_handles` + serialized `GroupState`). |
| `history` | `StoredMessage` / `GroupStoredMessage` transcripts with edit/delete and active (unexpired) loads. |
| `outbox` | The parked-message store: `OutboxEntry`, `enqueue` / `load` / `save`, and `is_expired` (bounded by `MAX_ATTEMPTS` / `TTL_SECS`). |
| `platform` | `OsPlatform`, the Full-tier `Platform` (OS CSPRNG + wall clock). |

## Delivery model

Every message is fanned out **one sealed copy per recipient device** (`seal_to`
does an offline X3DH into an `Envelope`), so each device in a cluster receives
its own ciphertext. `deliver` walks a three-rung ladder for each device:

1. **Live push** — if the directory reports the peer online, connect over TCP
   and push the `MailItem` frame directly (also how `serve` receives).
2. **Recipient's queue** — else deposit into their mailbox via a `QueueTarget`,
   opened against the queue endpoint *they* publish in their record and keyed by
   *their* wallet (per-device slot from `device_slot`, or the shared
   `ACCOUNT_SLOT` for account-wide items).
3. **Local outbox** — if neither works (offline **and** no reachable queue), the
   sealed item is parked with `outbox::enqueue` for retry.

`flush_outbox` runs opportunistically on every `send` and `inbox` (and on an
explicit `outbox_show`): it re-resolves each recipient's current record,
re-attempts the ladder, drops delivered and expired entries, and bumps
`attempts` on the rest. **Self-sync** mirrors your own outbound messages to your
other devices as `MailItem::SelfSync` (and group text / receipts fan out to the
whole cluster too), so a conversation reads consistently everywhere. `inbox`
drains your own queue (this device's slot + `ACCOUNT_SLOT`) and dispatches each
item through `process_item`.

## How it fits

The `mycellium-cli` is a thin shell over this crate — it parses arguments and
calls the `app` functions, nothing more. The engine reaches names, records, and
presence through `directory-client`, and moves messages through `queue-client`;
its own queue endpoint comes from the `MYCELLIUM_QUEUE` environment variable
(empty = pure P2P), recorded in its signed record so senders can find it.
