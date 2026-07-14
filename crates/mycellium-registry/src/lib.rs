//! Account registry and live-device discovery core.
//!
//! This crate deliberately does not store or relay messages. It only owns the
//! registry-side account UX:
//!
//! - login identity indexes
//! - one-time login tokens
//! - account metadata
//! - pointers to encrypted account blobs and signed public records
//! - stable user-id lookup for current signed public records
//!
//! Live presence and introduction are implemented in [`rendezvous`]. Neither
//! the HTTP surface nor its QUIC control protocol can carry message payloads.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mycellium_core::userid::UserId;

pub mod email;
pub mod http;
pub mod recovery;
mod redb_store;
pub mod rendezvous;

pub use redb_store::RedbRegistryStore;

/// Registry result type.
pub type Result<T> = std::result::Result<T, RegistryError>;

/// Registry error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryError {
    kind: RegistryErrorKind,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryErrorKind {
    InvalidInput,
    Conflict,
    Internal,
}

impl RegistryError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            kind: RegistryErrorKind::Internal,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: RegistryErrorKind::InvalidInput,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            kind: RegistryErrorKind::Conflict,
            message: message.into(),
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RegistryError {}

/// Stable registry account identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccountId(String);

impl AccountId {
    /// Generate a fresh random account id.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|_| RegistryError::new("randomness failed"))?;
        Ok(Self(hex(&bytes)))
    }

    /// Borrow as string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for AccountId {
    type Err = RegistryError;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(RegistryError::invalid("invalid account id"));
        }
        Ok(Self(s.to_ascii_lowercase()))
    }
}

/// Supported login identity kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginIdentityKind {
    /// Email magic-link login.
    Email,
}

impl LoginIdentityKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
        }
    }
}

/// Hash of a login identity value.
///
/// The registry should not need plaintext email/phone/etc after verification
/// flow handling.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LoginIdentityHash(String);

impl LoginIdentityHash {
    /// Hash an email address after minimal normalization.
    pub fn email(email: &str) -> Result<Self> {
        let normalized = normalize_email(email)?;
        Ok(hash_login_identity(LoginIdentityKind::Email, &normalized))
    }

    /// Borrow as string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Account metadata stored by the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Stable account id.
    pub id: AccountId,
    /// Creation timestamp, unix seconds.
    pub created_at: i64,
    /// Last account metadata update, unix seconds.
    pub updated_at: i64,
    /// Optional non-unique display handle.
    pub display_handle: Option<String>,
}

impl Account {
    /// New account metadata.
    pub fn new(id: AccountId, now: i64) -> Self {
        Self {
            id,
            created_at: now,
            updated_at: now,
            display_handle: None,
        }
    }
}

/// Stored login identity binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginIdentity {
    /// Login method kind.
    pub kind: LoginIdentityKind,
    /// Hashed normalized login value.
    pub value_hash: LoginIdentityHash,
    /// Bound account.
    pub account_id: AccountId,
    /// Verification timestamp, unix seconds.
    pub verified_at: i64,
}

/// One-time login token stored by hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginToken {
    /// Login method kind.
    pub kind: LoginIdentityKind,
    /// Hashed normalized login value.
    pub value_hash: LoginIdentityHash,
    /// Existing account, if known when the token was created.
    pub account_id: Option<AccountId>,
    /// Expiry timestamp, unix seconds.
    pub expires_at: i64,
}

/// Token returned to the caller so it can be sent over the selected surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginChallenge {
    /// Plain token. Store only its hash server-side.
    pub token: String,
    /// Expiry timestamp, unix seconds.
    pub expires_at: i64,
}

/// Account returned after a login confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLogin {
    /// Logged-in account id.
    pub account_id: AccountId,
    /// Whether this confirmation created the account.
    pub created: bool,
}

/// Session stored by token hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Session account.
    pub account_id: AccountId,
    /// Hash of the sole current bearer token for this account.
    pub token_hash: String,
    /// Expiry timestamp, unix seconds.
    pub expires_at: i64,
}

/// Plain session token returned to a verified client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionToken {
    /// Plain token. Store only its hash server-side.
    pub token: String,
    /// Session account.
    pub account_id: AccountId,
    /// Expiry timestamp, unix seconds.
    pub expires_at: i64,
}

/// Reference to opaque account bytes stored outside the metadata index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    /// Blob id.
    pub id: String,
    /// Blob size in bytes.
    pub size: u64,
    /// SHA-256 of the blob bytes.
    pub sha256: String,
}

/// Result of atomically advancing an account blob pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlobSwap {
    /// The pointer was advanced; `previous` is now unreferenced by this slot.
    Applied { previous: Option<BlobRef> },
    /// Another writer changed the pointer after it was read.
    Mismatch { current: Option<BlobRef> },
}

/// One rate-limit bucket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitBucket {
    /// Number of hits in the current window.
    pub count: u64,
    /// Window expiry timestamp, unix seconds.
    pub expires_at: i64,
}

/// Which account blob pointer is being stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBlobKind {
    /// Encrypted wallet/account backup.
    Backup,
    /// Registry-sealed 32-byte protocol identity root.
    Recovery,
    /// Latest signed public record.
    PublicRecord,
}

impl AccountBlobKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Backup => "backup",
            Self::Recovery => "recovery",
            Self::PublicRecord => "public_record",
        }
    }
}

/// Minimal registry metadata store.
pub trait RegistryStore {
    /// Save a one-time login token by token hash.
    fn put_login_token(&self, token_hash: &str, token: &LoginToken) -> Result<()>;

    /// Atomically consume a one-time login token.
    fn take_login_token(&self, token_hash: &str) -> Result<Option<LoginToken>>;

    /// Get account id for an already-verified login identity hash.
    fn account_id_by_login(
        &self,
        kind: LoginIdentityKind,
        hash: &LoginIdentityHash,
    ) -> Result<Option<AccountId>>;

    /// Get or create an account for a verified login identity.
    fn get_or_create_account_for_login(
        &self,
        kind: LoginIdentityKind,
        hash: &LoginIdentityHash,
        new_account: Account,
        verified_at: i64,
    ) -> Result<AccountLogin>;

    /// Get account metadata.
    fn account(&self, id: &AccountId) -> Result<Option<Account>>;

    /// Atomically advance an opaque blob pointer if it still equals `expected`.
    fn compare_and_swap_blob_ref(
        &self,
        account_id: &AccountId,
        kind: AccountBlobKind,
        expected: Option<&BlobRef>,
        next: &BlobRef,
    ) -> Result<BlobSwap>;

    /// Load an opaque blob pointer.
    fn blob_ref(&self, account_id: &AccountId, kind: AccountBlobKind) -> Result<Option<BlobRef>>;

    /// Atomically publish a signed public-record pointer and bind its stable
    /// protocol user id to the owning account.
    fn compare_and_swap_public_record_ref(
        &self,
        account_id: &AccountId,
        user_id: &UserId,
        expected: Option<&BlobRef>,
        next: &BlobRef,
    ) -> Result<BlobSwap>;

    /// Resolve a stable protocol user id to the account holding its current
    /// signed public record.
    fn account_id_by_user_id(&self, user_id: &UserId) -> Result<Option<AccountId>>;

    /// Atomically replace the account's sole current session.
    fn replace_session(&self, session: &Session) -> Result<()>;

    /// Load a session by token hash.
    fn session(&self, token_hash: &str) -> Result<Option<Session>>;

    /// Increment a rate-limit bucket, resetting it if the old window expired.
    fn bump_rate_limit(&self, key: &str, now: i64, window_secs: i64) -> Result<RateLimitBucket>;

    /// Remove up to `limit` expired login tokens, sessions, and rate buckets.
    fn purge_expired(&self, now: i64, limit: usize) -> Result<usize>;
}

/// Filesystem blob store for opaque account bytes.
#[derive(Clone, Debug)]
pub struct FileBlobStore {
    root: PathBuf,
}

impl FileBlobStore {
    /// Create a blob store rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Store opaque account bytes.
    pub fn put(
        &self,
        account_id: &AccountId,
        kind: AccountBlobKind,
        bytes: &[u8],
    ) -> Result<BlobRef> {
        let sha256 = sha256_hex(bytes);
        let id = format!("{}-{sha256}", kind.as_str());
        let path = self.path(account_id, &id)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| RegistryError::new(format!("create blob dir failed: {err}")))?;
            restrict_dir(parent)?;
        }
        let blob = BlobRef {
            id,
            size: bytes.len() as u64,
            sha256,
        };
        match std::fs::read(&path) {
            Ok(existing)
                if existing.len() as u64 == blob.size && sha256_hex(&existing) == blob.sha256 =>
            {
                restrict_file(&path)?;
                return Ok(blob);
            }
            Ok(_) => {
                // The content-addressed path is repairable because the caller
                // supplied the exact bytes its name commits to.
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(RegistryError::new(format!("read blob failed: {err}"))),
        }
        let tmp = path.with_extension(format!("tmp-{}", random_hex_8()?));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .map_err(|err| RegistryError::new(format!("create blob failed: {err}")))?;
        restrict_file(&tmp)?;
        file.write_all(bytes)
            .map_err(|err| RegistryError::new(format!("write blob failed: {err}")))?;
        file.sync_all()
            .map_err(|err| RegistryError::new(format!("sync blob failed: {err}")))?;
        drop(file);
        std::fs::rename(&tmp, &path)
            .map_err(|err| RegistryError::new(format!("commit blob failed: {err}")))?;
        sync_directory(path.parent().expect("blob path has a parent"))?;
        Ok(blob)
    }

    /// Read opaque account bytes by reference.
    pub fn get(&self, account_id: &AccountId, blob: &BlobRef) -> Result<Option<Vec<u8>>> {
        let path = self.path(account_id, &blob.id)?;
        match std::fs::read(path) {
            Ok(bytes) => {
                if bytes.len() as u64 != blob.size || sha256_hex(&bytes) != blob.sha256 {
                    return Err(RegistryError::new("blob integrity check failed"));
                }
                Ok(Some(bytes))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(RegistryError::new(format!("read blob failed: {err}"))),
        }
    }

    /// Remove a blob that is no longer referenced by registry metadata.
    pub fn remove(&self, account_id: &AccountId, blob: &BlobRef) -> Result<()> {
        let path = self.path(account_id, &blob.id)?;
        match std::fs::remove_file(&path) {
            Ok(()) => sync_directory(path.parent().expect("blob path has a parent")),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(RegistryError::new(format!("remove blob failed: {err}"))),
        }
    }

    /// Remove stale blobs of one account slot, keeping only `current`.
    ///
    /// Blob ids include their slot kind, so this never touches recovery data
    /// while pruning backups or public records. The account directory is tiny;
    /// cleanup cost does not grow with the global user count.
    pub fn prune_kind_except(
        &self,
        account_id: &AccountId,
        kind: AccountBlobKind,
        current: &BlobRef,
    ) -> Result<()> {
        let current_path = self.path(account_id, &current.id)?;
        let Some(directory) = current_path.parent() else {
            return Err(RegistryError::new("blob path has no parent"));
        };
        let prefix = format!("{}-", kind.as_str());
        let entries = std::fs::read_dir(directory)
            .map_err(|err| RegistryError::new(format!("read blob dir failed: {err}")))?;
        for entry in entries {
            let entry = entry
                .map_err(|err| RegistryError::new(format!("read blob entry failed: {err}")))?;
            let file_type = entry
                .file_type()
                .map_err(|err| RegistryError::new(format!("read blob type failed: {err}")))?;
            if !file_type.is_file() || entry.path() == current_path {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&prefix) {
                std::fs::remove_file(entry.path()).map_err(|err| {
                    RegistryError::new(format!("remove stale blob failed: {err}"))
                })?;
            }
        }
        sync_directory(directory)
    }

    fn path(&self, account_id: &AccountId, blob_id: &str) -> Result<PathBuf> {
        if !blob_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        {
            return Err(RegistryError::new("invalid blob id"));
        }
        let id = account_id.as_str();
        Ok(self
            .root
            .join("users")
            .join(&id[0..3])
            .join(&id[3..6])
            .join(&id[6..9])
            .join(id)
            .join(format!("{blob_id}.data")))
    }
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|err| RegistryError::new(format!("secure blob dir failed: {err}")))
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|err| RegistryError::new(format!("secure blob failed: {err}")))
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    let directory = std::fs::File::open(path)
        .map_err(|err| RegistryError::new(format!("open blob dir for sync failed: {err}")))?;
    directory
        .sync_all()
        .map_err(|err| RegistryError::new(format!("sync blob dir failed: {err}")))
}

/// Small registry service with no HTTP or email-provider assumptions.
pub struct Registry<S> {
    store: S,
}

impl<S: RegistryStore> Registry<S> {
    /// Create a registry service over a metadata store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Start email login. The caller sends `challenge.token` to the user.
    pub fn request_email_login(
        &self,
        email: &str,
        now: i64,
        ttl_secs: i64,
    ) -> Result<LoginChallenge> {
        if ttl_secs <= 0 {
            return Err(RegistryError::invalid("login ttl must be positive"));
        }
        let value_hash = LoginIdentityHash::email(email)?;
        let account_id = self
            .store
            .account_id_by_login(LoginIdentityKind::Email, &value_hash)?;
        let token = random_token()?;
        let token_hash = token_hash(&token);
        self.store.put_login_token(
            &token_hash,
            &LoginToken {
                kind: LoginIdentityKind::Email,
                value_hash,
                account_id,
                expires_at: now.saturating_add(ttl_secs),
            },
        )?;
        Ok(LoginChallenge {
            token,
            expires_at: now.saturating_add(ttl_secs),
        })
    }

    /// Confirm a login token and return the account.
    pub fn confirm_login(&self, token: &str, now: i64) -> Result<AccountLogin> {
        let Some(login) = self.store.take_login_token(&token_hash(token))? else {
            return Err(RegistryError::invalid("invalid login token"));
        };
        if login.expires_at <= now {
            return Err(RegistryError::invalid("expired login token"));
        }
        if let Some(account_id) = login.account_id {
            return Ok(AccountLogin {
                account_id,
                created: false,
            });
        }
        let account = Account::new(AccountId::generate()?, now);
        self.store
            .get_or_create_account_for_login(login.kind, &login.value_hash, account, now)
    }

    /// Create a bearer session for a verified account.
    pub fn create_session(
        &self,
        account_id: AccountId,
        now: i64,
        ttl_secs: i64,
    ) -> Result<SessionToken> {
        if ttl_secs <= 0 {
            return Err(RegistryError::invalid("session ttl must be positive"));
        }
        let token = random_token()?;
        let expires_at = now.saturating_add(ttl_secs);
        self.store.replace_session(&Session {
            account_id: account_id.clone(),
            token_hash: token_hash(&token),
            expires_at,
        })?;
        Ok(SessionToken {
            token,
            account_id,
            expires_at,
        })
    }

    /// Resolve a bearer session token.
    pub fn account_for_session(&self, token: &str, now: i64) -> Result<Option<AccountId>> {
        let Some(session) = self.store.session(&token_hash(token))? else {
            return Ok(None);
        };
        if session.expires_at <= now {
            return Ok(None);
        }
        Ok(Some(session.account_id))
    }

    /// Borrow the underlying store.
    pub fn store(&self) -> &S {
        &self.store
    }
}

fn normalize_email(email: &str) -> Result<String> {
    let email = email.trim().to_ascii_lowercase();
    if email.is_empty()
        || email.len() > 320
        || !email.contains('@')
        || email.bytes().any(|b| b.is_ascii_control())
    {
        return Err(RegistryError::invalid("invalid email"));
    }
    Ok(email)
}

fn hash_login_identity(kind: LoginIdentityKind, normalized: &str) -> LoginIdentityHash {
    let mut hasher = Sha256::new();
    hasher.update(b"mycellium-registry-login-identity-v1:");
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(normalized.as_bytes());
    LoginIdentityHash(hex(&hasher.finalize()))
}

fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"mycellium-registry-login-token-v1:");
    hasher.update(token.as_bytes());
    hex(&hasher.finalize())
}

fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| RegistryError::new("randomness failed"))?;
    Ok(hex(&bytes))
}

fn random_hex_8() -> Result<String> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).map_err(|_| RegistryError::new("randomness failed"))?;
    Ok(hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn encode_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|err| RegistryError::new(format!("encode failed: {err}")))
}

fn decode_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|err| RegistryError::new(format!("decode failed: {err}")))
}

fn key(parts: &[&str]) -> String {
    parts.join(":")
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| RegistryError::new(format!("create directory failed: {err}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "mycellium-registry-{name}-{}",
            random_hex_8().unwrap()
        ));
        path
    }

    #[test]
    fn email_login_creates_and_reuses_account_without_plaintext_email() {
        let dir = tmpdir("login");
        let store = RedbRegistryStore::open(dir.join("registry.redb")).unwrap();
        let registry = Registry::new(store);

        let challenge = registry
            .request_email_login("Ari@example.COM", 100, 600)
            .unwrap();
        let login = registry.confirm_login(&challenge.token, 110).unwrap();
        assert!(login.created);

        let second = registry
            .request_email_login("ari@example.com", 200, 600)
            .unwrap();
        let second_login = registry.confirm_login(&second.token, 210).unwrap();
        assert!(!second_login.created);
        assert_eq!(login.account_id, second_login.account_id);

        let bytes = std::fs::read(dir.join("registry.redb")).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("ari@example.com"));
    }

    #[test]
    fn login_token_is_one_time() {
        let dir = tmpdir("one-time");
        let store = RedbRegistryStore::open(dir.join("registry.redb")).unwrap();
        let registry = Registry::new(store);

        let challenge = registry.request_email_login("a@b.test", 100, 600).unwrap();
        registry.confirm_login(&challenge.token, 101).unwrap();

        let err = registry.confirm_login(&challenge.token, 102).unwrap_err();
        assert_eq!(err.to_string(), "invalid login token");
    }

    #[test]
    fn login_token_is_expired_at_its_exact_expiry_instant() {
        let dir = tmpdir("login-expiry-boundary");
        let store = RedbRegistryStore::open(dir.join("registry.redb")).unwrap();
        let registry = Registry::new(store);

        let challenge = registry.request_email_login("a@b.test", 100, 60).unwrap();
        let err = registry.confirm_login(&challenge.token, 160).unwrap_err();
        assert_eq!(err.to_string(), "expired login token");
    }

    #[test]
    fn session_is_expired_at_its_exact_expiry_instant() {
        let dir = tmpdir("session-expiry-boundary");
        let store = RedbRegistryStore::open(dir.join("registry.redb")).unwrap();
        let registry = Registry::new(store);
        let account_id = AccountId::generate().unwrap();
        let session = registry
            .create_session(account_id.clone(), 100, 60)
            .unwrap();

        assert_eq!(
            registry.account_for_session(&session.token, 159).unwrap(),
            Some(account_id)
        );
        assert_eq!(
            registry.account_for_session(&session.token, 160).unwrap(),
            None
        );
    }

    #[test]
    fn creating_a_session_immediately_revokes_the_previous_one() {
        let dir = tmpdir("session-replacement");
        let store = RedbRegistryStore::open(dir.join("registry.redb")).unwrap();
        let registry = Registry::new(store);
        let account_id = AccountId::generate().unwrap();
        let first = registry
            .create_session(account_id.clone(), 100, 900)
            .unwrap();
        let second = registry
            .create_session(account_id.clone(), 101, 900)
            .unwrap();

        assert_eq!(
            registry.account_for_session(&first.token, 102).unwrap(),
            None
        );
        assert_eq!(
            registry.account_for_session(&second.token, 102).unwrap(),
            Some(account_id)
        );
    }

    #[test]
    fn file_blob_store_round_trips_account_bytes() {
        let dir = tmpdir("blob");
        let blobs = FileBlobStore::new(&dir);
        let account_id = AccountId::generate().unwrap();
        let blob = blobs
            .put(&account_id, AccountBlobKind::Backup, b"encrypted bytes")
            .unwrap();

        assert_eq!(
            blobs.get(&account_id, &blob).unwrap().unwrap(),
            b"encrypted bytes"
        );
        assert!(dir.join("users").exists());
    }

    #[test]
    fn content_addressed_blob_is_repaired_from_known_bytes() {
        let dir = tmpdir("blob-repair");
        let blobs = FileBlobStore::new(&dir);
        let account_id = AccountId::generate().unwrap();
        let bytes = b"authenticated encrypted backup";
        let blob = blobs
            .put(&account_id, AccountBlobKind::Backup, bytes)
            .unwrap();
        let path = blobs.path(&account_id, &blob.id).unwrap();
        std::fs::write(&path, b"damaged").unwrap();
        assert!(blobs.get(&account_id, &blob).is_err());

        assert_eq!(
            blobs
                .put(&account_id, AccountBlobKind::Backup, bytes)
                .unwrap(),
            blob
        );
        assert_eq!(blobs.get(&account_id, &blob).unwrap().unwrap(), bytes);
    }

    #[test]
    fn blob_pruning_is_scoped_to_one_account_slot() {
        let dir = tmpdir("blob-prune");
        let blobs = FileBlobStore::new(&dir);
        let account_id = AccountId::generate().unwrap();
        let old = blobs
            .put(&account_id, AccountBlobKind::Backup, b"old backup")
            .unwrap();
        let current = blobs
            .put(&account_id, AccountBlobKind::Backup, b"current backup")
            .unwrap();
        let recovery = blobs
            .put(&account_id, AccountBlobKind::Recovery, b"recovery")
            .unwrap();

        blobs
            .prune_kind_except(&account_id, AccountBlobKind::Backup, &current)
            .unwrap();
        assert!(blobs.get(&account_id, &old).unwrap().is_none());
        assert_eq!(
            blobs.get(&account_id, &current).unwrap().unwrap(),
            b"current backup"
        );
        assert_eq!(
            blobs.get(&account_id, &recovery).unwrap().unwrap(),
            b"recovery"
        );
    }

    #[test]
    fn redb_stores_blob_refs_and_rate_buckets() {
        let dir = tmpdir("metadata");
        let store = RedbRegistryStore::open(dir.join("registry.redb")).unwrap();
        let account_id = AccountId::generate().unwrap();
        let blob = BlobRef {
            id: "backup-abc".into(),
            size: 3,
            sha256: "abc".into(),
        };

        store
            .compare_and_swap_blob_ref(&account_id, AccountBlobKind::Backup, None, &blob)
            .unwrap();
        assert_eq!(
            store
                .blob_ref(&account_id, AccountBlobKind::Backup)
                .unwrap(),
            Some(blob)
        );

        assert_eq!(
            store.bump_rate_limit("login:ip:test", 100, 60).unwrap(),
            RateLimitBucket {
                count: 1,
                expires_at: 160
            }
        );
        assert_eq!(
            store.bump_rate_limit("login:ip:test", 120, 60).unwrap(),
            RateLimitBucket {
                count: 2,
                expires_at: 160
            }
        );
        assert_eq!(
            store.bump_rate_limit("login:ip:test", 161, 60).unwrap(),
            RateLimitBucket {
                count: 1,
                expires_at: 221
            }
        );
    }

    #[test]
    fn indexed_expiry_cleanup_is_bounded_and_preserves_live_replacements() {
        let dir = tmpdir("expiry-cleanup");
        let store = RedbRegistryStore::open(dir.join("registry.redb")).unwrap();
        let registry = Registry::new(store);

        let expired_login = registry
            .request_email_login("old@test.eu", 100, 10)
            .unwrap();
        let live_login = registry
            .request_email_login("live@test.eu", 100, 200)
            .unwrap();

        let expired_account = AccountId::generate().unwrap();
        let expired_session = registry.create_session(expired_account, 100, 10).unwrap();
        let live_account = AccountId::generate().unwrap();
        let live_session = registry
            .create_session(live_account.clone(), 100, 200)
            .unwrap();
        // Replacing a short session must remove its old expiry entry. Cleanup
        // at t=150 must leave the replacement alive.
        let replacement_account = AccountId::generate().unwrap();
        let replaced = registry
            .create_session(replacement_account.clone(), 100, 10)
            .unwrap();
        let replacement = registry
            .create_session(replacement_account.clone(), 101, 200)
            .unwrap();
        assert!(registry
            .account_for_session(&replaced.token, 102)
            .unwrap()
            .is_none());

        registry
            .store()
            .bump_rate_limit("expired-rate", 100, 10)
            .unwrap();
        registry
            .store()
            .bump_rate_limit("live-rate", 100, 200)
            .unwrap();

        assert_eq!(registry.store().purge_expired(150, 2).unwrap(), 2);
        assert_eq!(registry.store().purge_expired(150, 2).unwrap(), 1);
        assert_eq!(registry.store().purge_expired(150, 2).unwrap(), 0);

        assert!(registry
            .store()
            .take_login_token(&token_hash(&expired_login.token))
            .unwrap()
            .is_none());
        assert!(registry
            .store()
            .take_login_token(&token_hash(&live_login.token))
            .unwrap()
            .is_some());
        assert!(registry
            .account_for_session(&expired_session.token, 105)
            .unwrap()
            .is_none());
        assert_eq!(
            registry
                .account_for_session(&live_session.token, 150)
                .unwrap(),
            Some(live_account)
        );
        assert_eq!(
            registry
                .account_for_session(&replacement.token, 150)
                .unwrap(),
            Some(replacement_account)
        );
        assert_eq!(
            registry
                .store()
                .bump_rate_limit("expired-rate", 150, 10)
                .unwrap()
                .count,
            1
        );
        assert_eq!(
            registry
                .store()
                .bump_rate_limit("live-rate", 150, 200)
                .unwrap()
                .count,
            2
        );
    }

    #[test]
    fn blob_pointer_compare_and_swap_has_one_winner() {
        use std::sync::{Arc, Barrier};

        let dir = tmpdir("blob-cas");
        let store = Arc::new(RedbRegistryStore::open(dir.join("registry.redb")).unwrap());
        let account_id = AccountId::generate().unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for suffix in ["a", "b"] {
            let store = Arc::clone(&store);
            let account_id = account_id.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                let blob = BlobRef {
                    id: format!("backup-{suffix}"),
                    size: 1,
                    sha256: suffix.into(),
                };
                barrier.wait();
                store
                    .compare_and_swap_blob_ref(&account_id, AccountBlobKind::Backup, None, &blob)
                    .unwrap()
            }));
        }
        barrier.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, BlobSwap::Applied { .. }))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, BlobSwap::Mismatch { .. }))
                .count(),
            1
        );
    }
}
