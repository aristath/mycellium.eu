# Mycellium — desktop client (Linux #70 + Windows #72)

One cross-platform desktop app built with **Tauri v2**, per the shared blueprint
in [`docs/NATIVE-CLIENTS.md`](../../docs/NATIVE-CLIENTS.md) (read that first).
Linux and Windows are a **single** codebase — only packaging differs.

Unlike the mobile clients, the desktop app is **Rust all the way down**: the Tauri
backend depends on the `mycellium-sdk` crate **directly** (a path dependency), so
there is **no UniFFI and no C-ABI** — the backend calls the SDK's Rust API in
process. macOS could later be folded into the same app; today the targets are
Linux and Windows.

> **Build-verified on Linux.** `cargo build` compiles the Tauri backend (links
> webkit2gtk-4.1 / gtk+-3.0 / libsoup-3.0 and the SDK), and `cargo test` runs a
> real messaging round-trip (two accounts, in-process directory + queue, email
> verification, alice→bob, `sync()` on bob). The GUI itself needs a display and
> the OS webview, so it isn't launched in CI — the build + the round-trip test are
> the acceptance here.

## Architecture

```
clients/desktop/
├── README.md
├── .gitignore                 target/, gen/, Cargo.lock
├── src/                       frontend — vanilla HTML/CSS/JS, NO build step
│   ├── index.html             Setup · Onboarding · Conversations · Thread · Contacts
│   ├── styles.css
│   └── app.js                 every action → window.__TAURI__.core.invoke(cmd, args)
└── src-tauri/                 the backend — its OWN Cargo project (not in the workspace)
    ├── Cargo.toml             tauri v2, mycellium-sdk (path dep), keyring v3, tokio
    ├── build.rs               tauri_build::build()
    ├── tauri.conf.json        identifier eu.mycellium.desktop, single window, frontendDist ../src
    ├── icons/                 app icons (png/ico/icns)
    └── src/
        ├── main.rs            managed state + #[tauri::command] wrappers over the SDK
        └── keyring_store.rs   KeyringSecretStore — the #65 desktop SecretStore adapter
```

The backend is **deliberately not a member of the root Cargo workspace** (like the
other clients). It path-depends on the SDK (`mycellium-sdk = { path =
"../../../crates/mycellium-sdk" }`); keeping it isolated stops Tauri's heavy
dependency tree (wry / webkit / gtk) from touching the server/CLI builds.

## Command surface

`src/main.rs` holds one `MyceliumClient` in Tauri managed state (a `Mutex`) and
exposes these `#[tauri::command]`s, each wrapping the matching SDK call:

| Command | SDK call |
|---|---|
| `setup(dirUrl, queueUrl)` | builds the client via `new_with_secret_store` + keyring; stashes the URLs |
| `start_email_verification(handle, email)` | `start_email_verification` |
| `confirm_email_verification(pending, code)` | `confirm_email_verification` |
| `register(handle, name)` | `register` |
| `account()` | `account` |
| `send_text(peer, text)` | `send_text` |
| `sync()` | `sync` |
| `conversations()` | `conversations` |
| `thread(peer)` | `thread` |
| `add_contact(nickname, handle)` | `add_contact` |
| `contacts()` | `contacts` |
| `safety_number(peer)` | `safety_number` |
| `mark_verified(peer)` | `mark_verified` |

**Threading.** Every SDK method blocks (encrypted `FileStore` I/O + blocking
`ureq` directory/queue calls). Commands are `async` and run each SDK call on
`tokio::task::spawn_blocking`, so the webview/UI thread never stalls. The SDK's
`uniffi::Record` DTOs aren't `serde`-serializable, so the backend maps them to
plain serializable DTOs at the command boundary and turns `SdkError` into a
frontend-facing string.

## Secure storage — how this satisfies #65 on desktop

The production client is built with the SDK's **production** constructor:

```rust
MyceliumClient::new_with_secret_store(data_dir, Box::new(KeyringSecretStore::new(...)))
```

`KeyringSecretStore` (in `keyring_store.rs`) is the desktop `SecretStore` adapter.
The SDK's `SecretStore` trait is `#[uniffi::export(callback_interface)]`, but that
only *adds* a foreign-callback adapter — it stays an ordinary Rust trait, so a
native Rust type `impl`s it directly (as the SDK's own file stores do).
`KeyringSecretStore` therefore compiles as a first-class Rust `SecretStore`, **no
FFI involved**. It is backed by the cross-platform [`keyring`] crate v3:

- **Linux** — the Secret Service (GNOME Keyring / KWallet via libsecret).
- **Windows** — the Windows Credential Manager (DPAPI-protected).
- **macOS** — the login Keychain.

Only the small, high-value identity secret goes through it (the bulk store stays
in the encrypted `FileStore`). The keyring *service* name is **namespaced** by the
data dir so two accounts on one machine never collide. Secrets are stored as raw
bytes via keyring's `set_secret`/`get_secret` — no base64 round-trip. It **fails
closed**: `load` returns `None` only for a genuinely absent entry
(`keyring::Error::NoEntry`); any other keyring error is surfaced as an `SdkError`,
so the SDK never mistakes an unreadable identity for "no identity" and silently
mints a fresh one.

**The headless test can't exercise the OS keyring.** A CI/headless box has no
running Secret Service / Credential Manager, so `tests/e2e.rs` uses the SDK's dev
`MyceliumClient::new` (a plaintext-file store) instead. `cargo build` still
compiles the keyring adapter; the test proves the messaging path the app drives on
top of it.

## Build & run

### Linux

Requires Rust + the Tauri system deps (found via pkg-config):
`webkit2gtk-4.1`, `gtk+-3.0`, `libsoup-3.0` (Fedora:
`webkit2gtk4.1-devel gtk3-devel libsoup3-devel`; Debian/Ubuntu:
`libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev`).

```sh
cd clients/desktop/src-tauri

# Compile the backend (links webkit/gtk + the SDK). The build.rs needs
# tauri.conf.json and the frontend dir (../src) to exist.
cargo build

# Run the messaging round-trip test (spins up an in-process directory + queue).
cargo test

# Lint / format.
cargo clippy -- -D warnings
cargo fmt
```

To **launch the app** a developer runs it with the Tauri CLI (needs a display and
the OS webview):

```sh
cargo install tauri-cli --version '^2'   # once
cd clients/desktop
cargo tauri dev                          # dev run against src/ (hot-reloads static files)
cargo tauri build                        # release bundle (.deb / .rpm / AppImage)
```

`cargo tauri dev` (or a plain `cargo run` inside `src-tauri`) opens the single
window, which starts on the **Setup** screen: enter a directory + queue URL,
verify an email to claim a handle, then chat.

### Windows

The same crate builds on Windows with no code changes:

- Install the **Rust MSVC toolchain** and **WebView2** runtime (preinstalled on
  Windows 10/11; otherwise install the Evergreen runtime).
- `cargo build` / `cargo tauri build` produce an `.exe` / MSI / NSIS installer.
- `KeyringSecretStore` automatically uses the Windows Credential Manager (the
  `keyring` `windows-native` backend is selected by the target-specific dependency
  in `Cargo.toml`).

## What it does

1:1 messaging MVP, every screen backed by real SDK calls:

- **Setup** — directory + queue URLs → `setup` (builds the keyring-backed client).
- **Onboarding** — handle + email → `start_email_verification` → enter the code →
  `confirm_email_verification` → `register`.
- **Conversations** — the threads list from `conversations()`.
- **Thread** — `thread(peer)` transcript + a compose box → `send_text`, with the
  per-message `DeliveryState` shown.
- **Contacts / verify** — `add_contact`, `contacts()`, plus `safety_number` and
  `mark_verified` affordances.
- Inbound mail surfaces by polling `sync()` on a 4s timer.

[`keyring`]: https://crates.io/crates/keyring
