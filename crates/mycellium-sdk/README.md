# mycellium-sdk

> The stable native SDK boundary around `mycellium-engine`, exported to Android, Apple, and desktop clients with UniFFI.

**Layer:** shell boundary · **Depends on:** mycellium-core, mycellium-engine, mycellium-storage, mycellium-http, directory/queue clients, uniffi

## What it does

`mycellium-sdk` wraps the headless engine in a small, stateful,
foreign-friendly API. Kotlin, Swift, and desktop bindings see simple DTOs,
callbacks, and the `MyceliumClient` object; engine internals and `anyhow`
errors are mapped to `SdkError` before crossing the boundary.

The SDK owns the application flows native clients need:

- account creation and email-verified registration
- 1:1 messaging, replies, reactions, deletes, file messages, history, and sync
- contacts, contact cards, safety numbers, and verified trust state
- seedless device pairing through queue rendezvous
- groups, group sync, member add/leave, and group transcripts
- contentless push registration for Web Push, APNs, FCM, and UnifiedPush
- store backup and import
- event callbacks for incoming messages and pairing progress

## Secrets and storage

Persistent message/config state lives under the `data_dir` passed to the
constructor, in the encrypted `data_dir/store` file store. The high-value
identity secret is kept separately behind a `SecretStore` supplied by the
platform app.

- Production apps should call `MyceliumClient::new_with_secret_store(data_dir, store)`.
- Android/Apple/desktop shells provide OS-backed stores such as Keystore,
  Keychain, DPAPI, or libsecret.
- `MyceliumClient::new(data_dir)` is a development convenience that uses a
  plaintext-file secret store and should not be used in production apps.

The SDK never returns private key material across the boundary. Public account
identity is exposed through `account()` and `wallet_address()`.

## Public surface

Main object:

- `MyceliumClient::new_with_secret_store(data_dir, secret_store)`
- `MyceliumClient::new(data_dir)` for local development only
- `account()` and `wallet_address()`

Registration:

- `start_email_verification(directory_url, handle, email)`
- `confirm_email_verification(directory_url, pending, code)`
- `register(directory_url, queue_url, handle, name)`

Messaging and sync:

- `send_text(peer, text)`, `reply(peer, reply_to, text)`,
  `react(peer, target, emoji)`, `delete_message(peer, target)`
- `send_file(peer, name, mime, bytes)`
- `sync()`, `conversations()`, `thread(peer)`
- `set_listener(listener)` for inbound message and pairing events

Contacts and trust:

- `add_contact(nickname, handle)`, `contacts()`, `remove_contact(nickname)`
- `safety_number(peer)`, `mark_verified(peer)`, `trust_level(peer)`
- `contact_card()`, `verify_card(card)`

Device, groups, push, backup:

- `pair_offer(queue_url)`, `pair_poll(queue_url)`, `pair_approve(offer, queue_url)`
- `group_create(name, members)`, `group_add(group_id, member)`,
  `group_send(group_id, text)`, `group_leave(group_id)`, `groups()`,
  `group_thread(group_id)`
- `register_push(platform, token)`, `unregister_push(platform, token)`
- `export_backup()`, `import_backup(bytes)`

## Bindings

Generate Kotlin and Swift bindings with:

```sh
crates/mycellium-sdk/bindings/generate.sh
```

The script builds the SDK cdylib, runs `cargo run -p mycellium-sdk --bin
uniffi-bindgen`, and asserts that Kotlin and Swift artifacts are emitted under
`crates/mycellium-sdk/bindings/generated/`. It also emits the C header/modulemap
used by desktop integrations.

## Testing

```sh
cargo test -p mycellium-sdk
crates/mycellium-sdk/bindings/generate.sh
```

The crate's Rust tests cover the native SDK behavior directly. The binding
generation script doubles as a smoke test for the UniFFI surface.
