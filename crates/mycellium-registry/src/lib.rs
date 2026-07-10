//! Minimal account registry core.
//!
//! This crate deliberately does not store or relay messages. It only owns the
//! registry-side account UX:
//!
//! - login identity indexes
//! - one-time login tokens
//! - account metadata
//! - pointers to encrypted account blobs and signed public records

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod http;
mod redb_store;

pub use redb_store::RedbRegistryStore;

/// Registry result type.
pub type Result<T> = std::result::Result<T, RegistryError>;

/// Registry error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryError {
    message: String,
}

impl RegistryError {
    fn new(message: impl Into<String>) -> Self {
        Self {
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
            return Err(RegistryError::new("invalid account id"));
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
    /// Latest signed public record.
    PublicRecord,
}

impl AccountBlobKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Backup => "backup",
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

    /// Store an opaque blob pointer.
    fn put_blob_ref(
        &self,
        account_id: &AccountId,
        kind: AccountBlobKind,
        blob: &BlobRef,
    ) -> Result<()>;

    /// Load an opaque blob pointer.
    fn blob_ref(&self, account_id: &AccountId, kind: AccountBlobKind) -> Result<Option<BlobRef>>;

    /// Save a session by token hash.
    fn put_session(&self, token_hash: &str, session: &Session) -> Result<()>;

    /// Load a session by token hash.
    fn session(&self, token_hash: &str) -> Result<Option<Session>>;

    /// Increment a rate-limit bucket, resetting it if the old window expired.
    fn bump_rate_limit(&self, key: &str, now: i64, window_secs: i64) -> Result<RateLimitBucket>;
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
        }
        let tmp = path.with_extension(format!("tmp-{}", random_hex_8()?));
        std::fs::write(&tmp, bytes)
            .map_err(|err| RegistryError::new(format!("write blob failed: {err}")))?;
        std::fs::rename(&tmp, &path)
            .map_err(|err| RegistryError::new(format!("commit blob failed: {err}")))?;
        Ok(BlobRef {
            id,
            size: bytes.len() as u64,
            sha256,
        })
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
            return Err(RegistryError::new("login ttl must be positive"));
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
            return Err(RegistryError::new("invalid login token"));
        };
        if login.expires_at < now {
            return Err(RegistryError::new("expired login token"));
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
            return Err(RegistryError::new("session ttl must be positive"));
        }
        let token = random_token()?;
        let expires_at = now.saturating_add(ttl_secs);
        self.store.put_session(
            &token_hash(&token),
            &Session {
                account_id: account_id.clone(),
                expires_at,
            },
        )?;
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
        if session.expires_at < now {
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
        return Err(RegistryError::new("invalid email"));
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
            .put_blob_ref(&account_id, AccountBlobKind::Backup, &blob)
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
}
