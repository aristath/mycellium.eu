//! Mycellium desktop client (Linux #70 + Windows #72) — a Tauri v2 shell.
//!
//! Unlike the mobile clients, the desktop app is Rust all the way down: the Tauri
//! backend depends on `mycellium-sdk` **directly as a crate** — no UniFFI, no
//! C-ABI. This file is the whole backend: it holds one [`MyceliumClient`] in Tauri
//! managed state and exposes a thin set of `#[tauri::command]`s that wrap the SDK
//! and hand serializable DTOs to the vanilla-JS frontend in `../src`.
//!
//! **Threading.** Every SDK method blocks (encrypted `FileStore` I/O + blocking
//! `ureq` directory/queue calls). Commands are `async` and run each SDK call on
//! `tokio::task::spawn_blocking`, so the webview/UI thread never stalls. The
//! `MyceliumClient` is `Send + Sync` (its interior is a `Mutex`), so an `Arc` clone
//! is moved into the blocking task.
//!
//! **Secrets (#65).** The production client is built with
//! [`MyceliumClient::new_with_secret_store`] backed by [`KeyringSecretStore`], so
//! the account root key lives in the OS secret store, never in plaintext on disk.

// On Windows release builds, don't pop a console window behind the GUI.
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod keyring_store;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{Manager, State};

use mycellium_sdk::{
    Account, Contact, Conversation, DeliveryState, EmailVerification, Group, Message,
    MyceliumClient, SdkError, TrustLevel,
};

use keyring_store::KeyringSecretStore;

/// The keyring service label all desktop identities are namespaced under (#65).
const KEYRING_SERVICE: &str = "eu.mycellium.desktop";

// ---------------------------------------------------------------------------
// Managed state
// ---------------------------------------------------------------------------

/// Everything the backend owns for the lifetime of the app window.
struct AppState {
    /// The per-user data directory (holds `store/`; the identity secret lives in
    /// the OS keyring, not here).
    data_dir: PathBuf,
    /// The client + the directory/queue URLs it was set up with. `None` until the
    /// first successful [`setup`].
    session: Mutex<Session>,
}

#[derive(Default)]
struct Session {
    client: Option<Arc<MyceliumClient>>,
    dir_url: String,
    queue_url: String,
}

impl AppState {
    fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            session: Mutex::new(Session::default()),
        }
    }

    /// Clone the live client, or a friendly error if `setup` hasn't run yet.
    fn client(&self) -> Result<Arc<MyceliumClient>, String> {
        self.session
            .lock()
            .unwrap()
            .client
            .clone()
            .ok_or_else(|| "not set up yet — enter the directory and queue URLs first".to_string())
    }

    /// The configured directory + queue URLs.
    fn urls(&self) -> (String, String) {
        let s = self.session.lock().unwrap();
        (s.dir_url.clone(), s.queue_url.clone())
    }
}

// ---------------------------------------------------------------------------
// Serializable DTOs (the SDK's `uniffi::Record` types aren't `serde`, so we map
// them to plain, Tauri-serializable structs at the command boundary).
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AccountDto {
    handle: String,
    name: String,
    wallet_address: String,
}
impl From<Account> for AccountDto {
    fn from(a: Account) -> Self {
        Self {
            handle: a.handle,
            name: a.name,
            wallet_address: a.wallet_address,
        }
    }
}

#[derive(Serialize)]
struct MessageDto {
    id: String,
    thread: String,
    from_me: bool,
    sender: String,
    text: String,
    sent_at: u64,
    delivery: String,
}
impl From<Message> for MessageDto {
    fn from(m: Message) -> Self {
        Self {
            id: m.id,
            thread: m.thread,
            from_me: m.from_me,
            sender: m.sender,
            text: m.text,
            sent_at: m.sent_at,
            delivery: delivery_str(m.delivery).to_string(),
        }
    }
}

#[derive(Serialize)]
struct ConversationDto {
    peer: String,
    display_name: String,
    last_preview: String,
    last_at: u64,
}
impl From<Conversation> for ConversationDto {
    fn from(c: Conversation) -> Self {
        Self {
            peer: c.peer,
            display_name: c.display_name,
            last_preview: c.last_preview,
            last_at: c.last_at,
        }
    }
}

#[derive(Serialize)]
struct GroupDto {
    id: String,
    name: String,
    members: Vec<String>,
}
impl From<Group> for GroupDto {
    fn from(g: Group) -> Self {
        Self {
            id: g.id,
            name: g.name,
            members: g.members,
        }
    }
}

#[derive(Serialize)]
struct ContactDto {
    nickname: String,
    handle: String,
    trust: String,
}
impl From<Contact> for ContactDto {
    fn from(c: Contact) -> Self {
        Self {
            nickname: c.nickname,
            handle: c.handle,
            trust: trust_str(c.trust).to_string(),
        }
    }
}

#[derive(Serialize)]
struct EmailVerificationDto {
    pending: String,
    dev_code: Option<String>,
}
impl From<EmailVerification> for EmailVerificationDto {
    fn from(e: EmailVerification) -> Self {
        Self {
            pending: e.pending,
            dev_code: e.dev_code,
        }
    }
}

fn delivery_str(d: DeliveryState) -> &'static str {
    match d {
        DeliveryState::Sent => "sent",
        DeliveryState::Queued => "queued",
        DeliveryState::Delivered => "delivered",
        DeliveryState::Failed => "failed",
    }
}

fn trust_str(t: TrustLevel) -> &'static str {
    match t {
        TrustLevel::Unverified => "unverified",
        TrustLevel::Pinned => "pinned",
        TrustLevel::Verified => "verified",
        TrustLevel::Changed => "changed",
    }
}

/// Run a blocking SDK closure off the UI thread and normalize both the join error
/// and the [`SdkError`] into a single frontend-facing string.
async fn blocking<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, SdkError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("internal task error: {e}"))?
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Commands (each mirrors one SDK call)
// ---------------------------------------------------------------------------

/// Build (or re-open) the client against `dir_url`/`queue_url`, holding the
/// identity secret in the OS keyring. Returns this device's account.
#[tauri::command]
async fn setup(
    state: State<'_, AppState>,
    dir_url: String,
    queue_url: String,
) -> Result<AccountDto, String> {
    let data_dir = state.data_dir.clone();
    let data_dir_str = data_dir.to_string_lossy().to_string();

    let client = blocking(move || {
        std::fs::create_dir_all(&data_dir).map_err(|e| SdkError::Storage { msg: e.to_string() })?;
        // Production path (#65): the account root key lives in the OS secret store,
        // namespaced by the data dir so multiple accounts never collide.
        let store = KeyringSecretStore::new(KEYRING_SERVICE, &data_dir_str);
        MyceliumClient::new_with_secret_store(data_dir_str.clone(), Box::new(store))
    })
    .await?;

    let account = client.account();
    {
        let mut s = state.session.lock().unwrap();
        s.client = Some(client);
        s.dir_url = dir_url;
        s.queue_url = queue_url;
    }
    Ok(account.into())
}

/// Onboarding step 1: begin an email-verified claim of `handle`.
#[tauri::command]
async fn start_email_verification(
    state: State<'_, AppState>,
    handle: String,
    email: String,
) -> Result<EmailVerificationDto, String> {
    let client = state.client()?;
    let (dir_url, _) = state.urls();
    blocking(move || client.start_email_verification(dir_url, handle, email))
        .await
        .map(Into::into)
}

/// Onboarding step 2: confirm the emailed (or dev-mode) code for `pending`.
#[tauri::command]
async fn confirm_email_verification(
    state: State<'_, AppState>,
    pending: String,
    code: String,
) -> Result<(), String> {
    let client = state.client()?;
    let (dir_url, _) = state.urls();
    blocking(move || client.confirm_email_verification(dir_url, pending, code)).await
}

/// Publish this identity's directory record under `handle`/`name`.
#[tauri::command]
async fn register(
    state: State<'_, AppState>,
    handle: String,
    name: String,
) -> Result<AccountDto, String> {
    let client = state.client()?;
    let (dir_url, queue_url) = state.urls();
    let c = client.clone();
    blocking(move || c.register(dir_url, queue_url, handle, name)).await?;
    Ok(client.account().into())
}

/// This device's account (handle/name empty until registered).
#[tauri::command]
async fn account(state: State<'_, AppState>) -> Result<AccountDto, String> {
    let client = state.client()?;
    blocking(move || Ok(client.account())).await.map(Into::into)
}

/// Send a text message to `peer`.
#[tauri::command]
async fn send_text(
    state: State<'_, AppState>,
    peer: String,
    text: String,
) -> Result<MessageDto, String> {
    let client = state.client()?;
    blocking(move || client.send_text(peer, text))
        .await
        .map(Into::into)
}

/// Drain the queue and return the newly received inbound messages.
#[tauri::command]
async fn sync(state: State<'_, AppState>) -> Result<Vec<MessageDto>, String> {
    let client = state.client()?;
    let msgs = blocking(move || client.sync()).await?;
    Ok(msgs.into_iter().map(Into::into).collect())
}

/// The conversation list, newest first.
#[tauri::command]
async fn conversations(state: State<'_, AppState>) -> Result<Vec<ConversationDto>, String> {
    let client = state.client()?;
    let convos = blocking(move || client.conversations()).await?;
    Ok(convos.into_iter().map(Into::into).collect())
}

/// The transcript with `peer`, oldest first.
#[tauri::command]
async fn thread(state: State<'_, AppState>, peer: String) -> Result<Vec<MessageDto>, String> {
    let client = state.client()?;
    let msgs = blocking(move || client.thread(peer)).await?;
    Ok(msgs.into_iter().map(Into::into).collect())
}

/// Add an address-book contact (TOFU-pinned).
#[tauri::command]
async fn add_contact(
    state: State<'_, AppState>,
    nickname: String,
    handle: String,
) -> Result<(), String> {
    let client = state.client()?;
    blocking(move || client.add_contact(nickname, handle)).await
}

/// The saved contacts, each with its current trust level.
#[tauri::command]
async fn contacts(state: State<'_, AppState>) -> Result<Vec<ContactDto>, String> {
    let client = state.client()?;
    let list = blocking(move || Ok(client.contacts())).await?;
    Ok(list.into_iter().map(Into::into).collect())
}

/// The out-of-band safety number to compare with `peer`.
#[tauri::command]
async fn safety_number(state: State<'_, AppState>, peer: String) -> Result<String, String> {
    let client = state.client()?;
    blocking(move || client.safety_number(peer)).await
}

/// Mark `peer` verified out of band (pin the wallet the directory serves now).
#[tauri::command]
async fn mark_verified(state: State<'_, AppState>, peer: String) -> Result<(), String> {
    let client = state.client()?;
    blocking(move || client.mark_verified(peer)).await
}

// ---- message kinds (reply / react / delete / attach) ----------------------

/// Reply to message `reply_to` in the conversation with `peer`.
#[tauri::command]
async fn reply(
    state: State<'_, AppState>,
    peer: String,
    reply_to: String,
    text: String,
) -> Result<MessageDto, String> {
    let client = state.client()?;
    blocking(move || client.reply(peer, reply_to, text))
        .await
        .map(Into::into)
}

/// React to message `target` (in the conversation with `peer`) with an emoji.
#[tauri::command]
async fn react(
    state: State<'_, AppState>,
    peer: String,
    target: String,
    emoji: String,
) -> Result<MessageDto, String> {
    let client = state.client()?;
    blocking(move || client.react(peer, target, emoji))
        .await
        .map(Into::into)
}

/// Delete message `target` for everyone in the conversation with `peer`.
#[tauri::command]
async fn delete_message(
    state: State<'_, AppState>,
    peer: String,
    target: String,
) -> Result<(), String> {
    let client = state.client()?;
    blocking(move || client.delete_message(peer, target)).await
}

/// Send a file attachment (`data` bytes) to `peer`. Carried end-to-end inside the
/// sealed envelope like any other message.
#[tauri::command]
async fn send_file(
    state: State<'_, AppState>,
    peer: String,
    name: String,
    mime: String,
    data: Vec<u8>,
) -> Result<MessageDto, String> {
    let client = state.client()?;
    blocking(move || client.send_file(peer, name, mime, data))
        .await
        .map(Into::into)
}

// ---- groups ---------------------------------------------------------------

/// Create a group with `members` (handles) and return the new group id.
#[tauri::command]
async fn group_create(
    state: State<'_, AppState>,
    name: String,
    members: Vec<String>,
) -> Result<String, String> {
    let client = state.client()?;
    blocking(move || client.group_create(name, members)).await
}

/// Add `member` to a group and re-distribute keys with the updated roster.
#[tauri::command]
async fn group_add(
    state: State<'_, AppState>,
    group_id: String,
    member: String,
) -> Result<(), String> {
    let client = state.client()?;
    blocking(move || client.group_add(group_id, member)).await
}

/// Send a text message to a group.
#[tauri::command]
async fn group_send(
    state: State<'_, AppState>,
    group_id: String,
    text: String,
) -> Result<MessageDto, String> {
    let client = state.client()?;
    blocking(move || client.group_send(group_id, text))
        .await
        .map(Into::into)
}

/// Leave a group locally (stop participating; drops its keys + state).
#[tauri::command]
async fn group_leave(state: State<'_, AppState>, group_id: String) -> Result<(), String> {
    let client = state.client()?;
    blocking(move || {
        client.group_leave(group_id)?;
        Ok(())
    })
    .await
}

/// The groups this account belongs to.
#[tauri::command]
async fn groups(state: State<'_, AppState>) -> Result<Vec<GroupDto>, String> {
    let client = state.client()?;
    let list = blocking(move || Ok(client.groups())).await?;
    Ok(list.into_iter().map(Into::into).collect())
}

/// A group's transcript, oldest first.
#[tauri::command]
async fn group_thread(
    state: State<'_, AppState>,
    group_id: String,
) -> Result<Vec<MessageDto>, String> {
    let client = state.client()?;
    let msgs = blocking(move || client.group_thread(group_id)).await?;
    Ok(msgs.into_iter().map(Into::into).collect())
}

// ---- verification (contact cards) -----------------------------------------

/// This account's contact card (hex) to show a peer out of band.
#[tauri::command]
async fn contact_card(state: State<'_, AppState>) -> Result<String, String> {
    let client = state.client()?;
    blocking(move || client.contact_card()).await
}

/// Verify a peer's contact `card`: on a match, mark the handle verified and
/// return it; a mismatch surfaces as an identity-changed error.
#[tauri::command]
async fn verify_card(state: State<'_, AppState>, card: String) -> Result<String, String> {
    let client = state.client()?;
    blocking(move || client.verify_card(card)).await
}

// ---- seedless device pairing ----------------------------------------------

/// **New device**: mint a one-time pairing offer (hex — render it as a QR).
#[tauri::command]
async fn pair_offer(state: State<'_, AppState>, queue_url: String) -> Result<String, String> {
    let client = state.client()?;
    blocking(move || client.pair_offer(queue_url)).await
}

/// **New device**: poll the rendezvous once; returns the adopted account on
/// success, or `None` to keep polling.
#[tauri::command]
async fn pair_poll(
    state: State<'_, AppState>,
    queue_url: String,
) -> Result<Option<AccountDto>, String> {
    let client = state.client()?;
    let adopted = blocking(move || client.pair_poll(queue_url)).await?;
    Ok(adopted.map(Into::into))
}

/// **Existing device**: seal this account's key to a pairing `offer` and relay it
/// through the rendezvous so a new device can adopt the account.
#[tauri::command]
async fn pair_approve(
    state: State<'_, AppState>,
    offer: String,
    queue_url: String,
) -> Result<(), String> {
    let client = state.client()?;
    blocking(move || client.pair_approve(offer, queue_url)).await
}

// ---- backup / restore -----------------------------------------------------

/// A portable snapshot of the encrypted store (still encrypted at rest).
#[tauri::command]
async fn export_backup(state: State<'_, AppState>) -> Result<Vec<u8>, String> {
    let client = state.client()?;
    blocking(move || Ok(client.export_backup())).await
}

/// Restore a store snapshot produced by `export_backup` into this account.
#[tauri::command]
async fn import_backup(state: State<'_, AppState>, bytes: Vec<u8>) -> Result<(), String> {
    let client = state.client()?;
    blocking(move || client.import_backup(bytes)).await
}

// ---------------------------------------------------------------------------

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Resolve a per-user data dir (created lazily on first `setup`).
            let data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::env::temp_dir().join("mycellium-desktop"));
            app.manage(AppState::new(data_dir));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            setup,
            start_email_verification,
            confirm_email_verification,
            register,
            account,
            send_text,
            sync,
            conversations,
            thread,
            add_contact,
            contacts,
            safety_number,
            mark_verified,
            reply,
            react,
            delete_message,
            send_file,
            group_create,
            group_add,
            group_send,
            group_leave,
            groups,
            group_thread,
            contact_card,
            verify_card,
            pair_offer,
            pair_poll,
            pair_approve,
            export_backup,
            import_backup,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Mycellium desktop app");
}
