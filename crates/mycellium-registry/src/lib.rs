//! Account registry service/client.
//!
//! The registry is an account lifecycle service. It reserves handles, authenticates
//! recovery, stores OPAQUE password files, stores wallet backups encrypted under
//! OPAQUE export keys, and serves the latest signed public record. It never stores
//! messages, queues messages, or participates in message delivery.

use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use axum::body::to_bytes;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Method, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as HyperBuilder;
use hyper_util::service::TowerToHyperService;
use mycellium_core::identity::Handle;
use mycellium_core::record::SignedRecord;
use mycellium_core::{userid::user_id, wire};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use reqwest::blocking::Client;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::Semaphore;
use tower::limit::ConcurrencyLimitLayer;
use tower::{service_fn, ServiceBuilder, ServiceExt};
use zeroize::Zeroizing;

const SCHEMA_VERSION: i64 = 5;
const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;
const SERVER_SECRET_ENV: &str = "MYCELLIUM_REGISTRY_SECRET";
const REGISTRY_DB_FILE: &str = "registry.sqlite";
const REGISTRY_DIR_MARKER: &str = ".mycellium-registry";
const REGISTRY_SOCKET_FILE: &str = "registry.sock";
const EDGE_CLIENT_KEY_HEADER: &str = "x-mycellium-edge-client-key";
const OPAQUE_SETUP_KEY: &str = "opaque_server_setup_v2";
const SERVER_ID: &[u8] = b"mycellium-registry-v2";
const BACKUP_PURPOSE: &str = "mycellium-registry-wallet-backup-v2";
const OPAQUE_SETUP_SEAL_DOMAIN: &[u8] = b"mycellium-registry-opaque-setup-v2\0";
const REGISTRATION_TTL_SECS: i64 = 600;
const CREATION_GRANT_TTL_SECS: i64 = 900;
const HANDLE_REGISTRATION_COOLDOWN_SECS: i64 = 300;
const LOGIN_TTL_SECS: i64 = 300;
const AUTH_TOKEN_TTL_SECS: i64 = 300;
const RATE_WINDOW_SECS: i64 = 60;
const LOOKUP_AGGREGATE_LIMIT: i64 = 120;
const LOOKUP_HANDLE_LIMIT: i64 = 20;
const MAX_CONCURRENT_REQUESTS: usize = 128;
const MAX_ACTIVE_CONNECTIONS: usize = 256;
const MAX_PENDING_REGISTRATIONS: i64 = 10_000;
const ACCOUNT_CREATION_WINDOW_SECS: i64 = 3600;
const ACCOUNT_CREATION_WINDOW_LIMIT: i64 = 5_000;
const BODY_READ_TIMEOUT_SECS: u64 = 10;
#[cfg(not(test))]
const HEADER_READ_TIMEOUT_SECS: u64 = 5;
#[cfg(test)]
const HEADER_READ_TIMEOUT_SECS: u64 = 1;
const CONNECTION_LIFETIME_TIMEOUT_SECS: u64 = 30;
const RECOVERY_SECRET_BYTES: usize = 32;
const RECOVERY_SECRET_PREFIX: &str = "myc-r1-";
pub const RECOVERY_SECRET_MIN_CHARS: usize =
    RECOVERY_SECRET_PREFIX.len() + RECOVERY_SECRET_BYTES * 2;

struct MycelliumOpaque;

impl CipherSuite for MycelliumOpaque {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

pub type SecretString = Zeroizing<String>;

pub struct RecoverySecret(SecretString);

impl RecoverySecret {
    pub fn parse(secret: impl Into<String>) -> Result<Self> {
        let secret = secret.into();
        if secret.trim() != secret {
            bail!("recovery secret must not contain surrounding whitespace");
        }
        validate_recovery_secret_value(&secret)?;
        Ok(Self(Zeroizing::new(secret)))
    }

    pub fn generate() -> Result<Self> {
        Self::parse(format!(
            "{RECOVERY_SECRET_PREFIX}{}",
            random_hex(RECOVERY_SECRET_BYTES)?
        ))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

pub struct OpaqueExportKey(Zeroizing<Vec<u8>>);

impl OpaqueExportKey {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl AsRef<[u8]> for OpaqueExportKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::ops::Deref for OpaqueExportKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

pub struct WalletSecret(Zeroizing<[u8; 32]>);

impl WalletSecret {
    fn new(secret: [u8; 32]) -> Self {
        Self(Zeroizing::new(secret))
    }

    pub fn expose_secret(&self) -> [u8; 32] {
        *self.0
    }
}

impl AsRef<[u8; 32]> for WalletSecret {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryErrorKind {
    AuthenticationFailed,
    RateLimited,
    NotFound,
    MethodNotAllowed,
    Conflict,
    InvalidRequest,
    Forbidden,
    PayloadTooLarge,
    Internal,
}

impl RegistryErrorKind {
    fn status(self) -> StatusCode {
        match self {
            Self::AuthenticationFailed => StatusCode::UNAUTHORIZED,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::Conflict => StatusCode::CONFLICT,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "authentication_failed",
            Self::RateLimited => "rate_limited",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::Conflict => "conflict",
            Self::InvalidRequest => "invalid_request",
            Self::Forbidden => "forbidden",
            Self::PayloadTooLarge => "payload_too_large",
            Self::Internal => "internal_error",
        }
    }
}

#[derive(Debug)]
struct RegistryError {
    kind: RegistryErrorKind,
    message: String,
}

struct RateLimit {
    action: &'static str,
    bucket: String,
    limit: i64,
}

enum RegistryRoute {
    RegistrationStart,
    Create,
    AuthStart,
    AuthFinish,
    Recover,
    Record,
    WalletRotate,
    RecoveryRegistrationStart,
    RecoveryRegistrationFinish,
    Lookup { handle: String },
    Error(RegistryErrorKind),
}

struct ClassifiedRequest {
    route: RegistryRoute,
    rate_limits: Vec<RateLimit>,
}

impl RateLimit {
    fn new(action: &'static str, bucket: impl Into<String>, limit: i64) -> Self {
        Self {
            action,
            bucket: bucket.into(),
            limit,
        }
    }
}

impl ClassifiedRequest {
    fn new(route: RegistryRoute, rate_limits: Vec<RateLimit>) -> Self {
        Self { route, rate_limits }
    }

    fn error(kind: RegistryErrorKind) -> Self {
        Self::new(RegistryRoute::Error(kind), vec![fallback_rate_limit()])
    }
}

impl RegistryError {
    fn new(kind: RegistryErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for RegistryError {}

fn registry_error(kind: RegistryErrorKind, message: impl Into<String>) -> anyhow::Error {
    RegistryError::new(kind, message).into()
}

fn authentication_failed() -> anyhow::Error {
    registry_error(
        RegistryErrorKind::AuthenticationFailed,
        "authentication failed",
    )
}

fn invalid_request(message: impl Into<String>) -> anyhow::Error {
    registry_error(RegistryErrorKind::InvalidRequest, message)
}

fn forbidden(message: impl Into<String>) -> anyhow::Error {
    registry_error(RegistryErrorKind::Forbidden, message)
}

fn conflict(message: impl Into<String>) -> anyhow::Error {
    registry_error(RegistryErrorKind::Conflict, message)
}

fn not_found(message: impl Into<String>) -> anyhow::Error {
    registry_error(RegistryErrorKind::NotFound, message)
}

fn rate_limited() -> anyhow::Error {
    registry_error(RegistryErrorKind::RateLimited, "rate limited")
}

fn payload_too_large() -> anyhow::Error {
    registry_error(
        RegistryErrorKind::PayloadTooLarge,
        "request body is too large",
    )
}

#[derive(Serialize, Deserialize)]
pub struct AccountRegistrationStartRequest {
    pub handle: String,
    pub registration_request: String,
    pub creation_grant: SecretString,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRegistrationStartResponse {
    pub account_id: String,
    pub handle: String,
    pub registration_id: String,
    pub registration_response: String,
}

#[derive(Serialize, Deserialize)]
pub struct AccountCreateRequest {
    pub account_id: String,
    pub handle: String,
    pub registration_id: String,
    pub registration_upload: String,
    pub wallet_backup: WalletBackupEnvelope,
    pub signed_record: String,
}

#[derive(Serialize, Deserialize)]
pub struct AccountAuthStartRequest {
    pub handle: String,
    pub purpose: AuthPurpose,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_hash: Option<String>,
    pub credential_request: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountAuthStartResponse {
    pub account_id: String,
    pub handle: String,
    pub login_id: String,
    pub purpose: AuthPurpose,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_hash: Option<String>,
    pub credential_response: String,
}

#[derive(Serialize, Deserialize)]
pub struct AccountAuthFinishRequest {
    pub handle: String,
    pub login_id: String,
    pub credential_finalization: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountAuthToken {
    pub handle: String,
    pub auth_token: SecretString,
    pub purpose: AuthPurpose,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_hash: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AccountRecoverRequest {
    pub auth_token: SecretString,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRecoveryResponse {
    pub account_id: String,
    pub handle: String,
    pub wallet_public: String,
    pub recovery_revision: u64,
    pub wallet_backup: WalletBackupEnvelope,
    pub signed_record: String,
}

#[derive(Serialize, Deserialize)]
pub struct AccountUpdateRecordRequest {
    pub auth_token: SecretString,
    pub signed_record: String,
}

#[derive(Serialize, Deserialize)]
pub struct AccountRotateWalletRequest {
    pub auth_token: SecretString,
    pub signed_record: String,
    pub wallet_backup: WalletBackupEnvelope,
}

#[derive(Serialize, Deserialize)]
pub struct RecoveryRegistrationStartRequest {
    pub auth_token: SecretString,
    pub registration_request: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryRegistrationStartResponse {
    pub account_id: String,
    pub handle: String,
    pub wallet_public: String,
    pub recovery_revision: u64,
    pub operation_id: String,
    pub operation_token: SecretString,
    pub registration_response: String,
}

#[derive(Serialize, Deserialize)]
pub struct RecoveryRegistrationFinishRequest {
    pub operation_id: String,
    pub operation_token: SecretString,
    pub registration_upload: String,
    pub wallet_backup: WalletBackupEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountPublicRecord {
    pub account_id: String,
    pub handle: String,
    pub wallet_public: String,
    pub signed_record: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletBackupEnvelope {
    pub version: u32,
    pub purpose: String,
    pub account_id: String,
    pub handle: String,
    pub wallet_public: String,
    pub recovery_revision: u64,
    pub kdf: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthPurpose {
    Recover,
    PublishRecord,
    RotateRecovery,
    RotateWallet,
}

impl AuthPurpose {
    fn as_str(&self) -> &'static str {
        match self {
            AuthPurpose::Recover => "recover",
            AuthPurpose::PublishRecord => "publish_record",
            AuthPurpose::RotateRecovery => "rotate_recovery",
            AuthPurpose::RotateWallet => "rotate_wallet",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

pub fn verify_signed_record(handle: &str, encoded: &str) -> Result<SignedRecord> {
    let handle = validate_handle(handle)?;
    let bytes = input_hex(encoded, "signed record")?;
    let record: SignedRecord =
        wire::decode(&bytes).map_err(|_| invalid_request("bad signed record"))?;
    validate_record(handle.as_str(), &record)?;
    Ok(record)
}

pub fn record_operation_hash(handle: &str, signed_record: &str) -> Result<String> {
    validate_handle(handle)?;
    verify_signed_record(handle, signed_record)?;
    Ok(hash_parts(&[
        b"mycellium-registry-operation-record-v2".as_slice(),
        handle.as_bytes(),
        signed_record.as_bytes(),
    ]))
}

pub fn wallet_backup_metadata(
    account_id: &str,
    handle: &str,
    wallet_public: &str,
    recovery_revision: u64,
) -> WalletBackupEnvelope {
    WalletBackupEnvelope {
        version: 2,
        purpose: BACKUP_PURPOSE.to_string(),
        account_id: account_id.to_string(),
        handle: handle.to_string(),
        wallet_public: wallet_public.to_string(),
        recovery_revision,
        kdf: "opaque-export-key-hkdf-sha256".to_string(),
        nonce: String::new(),
        ciphertext: String::new(),
    }
}

pub fn seal_wallet_backup(
    export_key: &[u8],
    mut envelope: WalletBackupEnvelope,
    wallet_secret: &[u8; 32],
) -> Result<WalletBackupEnvelope> {
    validate_backup_metadata(&envelope)?;
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).context("could not gather randomness")?;
    envelope.nonce = hex(&nonce);
    envelope.ciphertext.clear();
    let aad = backup_aad(&envelope)?;
    let key = backup_key(export_key, &aad)?;
    let ciphertext = ChaCha20Poly1305::new(&key)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: wallet_secret,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("could not seal wallet backup"))?;
    envelope.ciphertext = hex(&ciphertext);
    Ok(envelope)
}

pub fn open_wallet_backup(
    export_key: &[u8],
    envelope: &WalletBackupEnvelope,
    expected: &WalletBackupEnvelope,
) -> Result<WalletSecret> {
    validate_backup_for_account(envelope, expected)?;
    let nonce = input_fixed_hex::<12>(&envelope.nonce, "backup nonce")?;
    let ciphertext = input_hex(&envelope.ciphertext, "backup ciphertext")?;
    let aad = backup_aad(envelope)?;
    let key = backup_key(export_key, &aad)?;
    let plaintext = Zeroizing::new(
        ChaCha20Poly1305::new(&key)
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("could not open wallet backup"))?,
    );
    let wallet_secret = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| invalid_request("wallet backup is malformed"))?;
    Ok(WalletSecret::new(wallet_secret))
}

pub struct AccountStore {
    data_dir: PathBuf,
    path: PathBuf,
    server_secret: Zeroizing<Vec<u8>>,
}

impl AccountStore {
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self> {
        let secret = server_secret_from_env()?;
        Self::open_with_policy(data_dir, secret)
    }

    pub fn open_with_secret(
        data_dir: impl AsRef<Path>,
        server_secret: impl AsRef<[u8]>,
    ) -> Result<Self> {
        Self::open_with_policy(data_dir, Zeroizing::new(server_secret.as_ref().to_vec()))
    }

    pub fn open_with_options(data_dir: impl AsRef<Path>, server_secret: Vec<u8>) -> Result<Self> {
        Self::open_with_policy(data_dir, Zeroizing::new(server_secret))
    }

    fn open_with_policy(
        data_dir: impl AsRef<Path>,
        server_secret: Zeroizing<Vec<u8>>,
    ) -> Result<Self> {
        validate_server_secret(&server_secret)?;
        let paths = RegistryPaths::prepare(data_dir.as_ref())?;
        let store = Self {
            data_dir: paths.data_dir,
            path: paths.db_path,
            server_secret,
        };
        store.with_conn(|conn| {
            init_conn(conn)?;
            let _ = load_or_create_server_setup(conn, &store.server_secret)?;
            Ok(())
        })?;
        harden_sqlite_files(&store.path)?;
        Ok(store)
    }

    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = open_conn(&self.path)?;
        f(&conn)
    }

    pub fn start_registration(
        &self,
        req: AccountRegistrationStartRequest,
    ) -> Result<AccountRegistrationStartResponse> {
        let handle = validate_handle(&req.handle)?;
        let registration_request = RegistrationRequest::<MycelliumOpaque>::deserialize(&input_hex(
            &req.registration_request,
            "registration request",
        )?)
        .map_err(|_| invalid_request("bad registration request"))?;
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            prune_ephemeral(&tx)?;
            if account_exists(&tx, handle.as_str())?
                || pending_registration_exists_for_handle(&tx, handle.as_str())?
            {
                return Err(conflict("account unavailable"));
            }
            ensure_handle_not_cooling_down(&tx, handle.as_str())?;
            ensure_pending_registration_capacity(&tx)?;
            claim_creation_grant(&tx, &req.creation_grant, handle.as_str())?;
            let account_id = random_hex(32)?;
            let registration_id = random_hex(32)?;
            let setup = load_or_create_server_setup(&tx, &self.server_secret)?;
            let response = ServerRegistration::<MycelliumOpaque>::start(
                &setup,
                registration_request,
                account_id.as_bytes(),
            )
            .map_err(|_| invalid_request("bad registration request"))?;
            tx.execute(
                "INSERT INTO pending_registrations
                 (registration_id, account_id, handle, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    registration_id,
                    account_id,
                    handle.as_str(),
                    now_secs() + REGISTRATION_TTL_SECS,
                    now_secs()
                ],
            )
            .map_err(|err| {
                if is_unique_violation(&err) {
                    conflict("account unavailable")
                } else {
                    err.into()
                }
            })?;
            tx.commit()?;
            Ok(AccountRegistrationStartResponse {
                account_id,
                handle: handle.as_str().to_string(),
                registration_id,
                registration_response: hex(response.message.serialize().as_slice()),
            })
        })
    }

    pub fn create(&self, req: AccountCreateRequest) -> Result<AccountPublicRecord> {
        let handle = validate_handle(&req.handle)?;
        let record = verify_signed_record(handle.as_str(), &req.signed_record)?;
        let seq = checked_seq(record.record.seq)?;
        let wallet_public = hex(&record.record.wallet.0);
        validate_backup_for_account(
            &req.wallet_backup,
            &wallet_backup_metadata(&req.account_id, handle.as_str(), &wallet_public, 1),
        )?;
        let upload = RegistrationUpload::<MycelliumOpaque>::deserialize(&input_hex(
            &req.registration_upload,
            "registration upload",
        )?)
        .map_err(|_| invalid_request("bad registration upload"))?;
        let password_file = ServerRegistration::finish(upload);
        let opaque_password_file = hex(password_file.serialize().as_slice());
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            prune_ephemeral(&tx)?;
            let pending = load_pending_registration(&tx, &req.registration_id)?
                .ok_or_else(|| conflict("registration expired"))?;
            if pending.account_id != req.account_id || pending.handle != handle.as_str() {
                return Err(conflict("registration binding mismatch"));
            }
            if account_exists(&tx, handle.as_str())? {
                return Err(conflict("account unavailable"));
            }
            let now = now_secs();
            tx.execute(
                "INSERT INTO accounts
                 (account_id, handle, state, wallet_public, recovery_revision,
                  opaque_password_file, wallet_backup, signed_record, signed_record_seq,
                  created_at, updated_at)
                 VALUES (?1, ?2, 'active', ?3, 1, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    req.account_id,
                    handle.as_str(),
                    wallet_public,
                    opaque_password_file,
                    serde_json::to_string(&req.wallet_backup)?,
                    req.signed_record,
                    seq,
                    now,
                    now
                ],
            )
            .map_err(|err| {
                if is_unique_violation(&err) {
                    conflict("account unavailable")
                } else {
                    err.into()
                }
            })?;
            tx.execute(
                "DELETE FROM pending_registrations WHERE registration_id = ?1",
                params![req.registration_id],
            )?;
            increment_signup_counter(&tx, now)?;
            tx.commit()?;
            self.public_record(handle.as_str())?
                .ok_or_else(|| not_found("account vanished after create"))
        })
    }

    pub fn start_auth(&self, req: AccountAuthStartRequest) -> Result<AccountAuthStartResponse> {
        let handle = validate_handle(&req.handle)?;
        validate_operation_binding(&req.purpose, req.operation_hash.as_deref())?;
        let credential_request = CredentialRequest::<MycelliumOpaque>::deserialize(
            &input_hex(&req.credential_request, "credential request")
                .map_err(|_| authentication_failed())?,
        )
        .map_err(|_| authentication_failed())?;
        self.with_conn(|conn| {
            prune_ephemeral(conn)?;
            let account =
                load_account_by_handle(conn, handle.as_str())?.ok_or_else(authentication_failed)?;
            let password_file = ServerRegistration::<MycelliumOpaque>::deserialize(
                &from_hex(&account.opaque_password_file).map_err(|_| authentication_failed())?,
            )
            .map_err(|_| authentication_failed())?;
            let setup = load_or_create_server_setup(conn, &self.server_secret)?;
            let context = auth_context(
                &account.account_id,
                handle.as_str(),
                &req.purpose,
                req.operation_hash.as_deref(),
            );
            let params = server_login_params(handle.as_str(), &context);
            let mut rng = OsRng;
            let login = ServerLogin::start(
                &mut rng,
                &setup,
                Some(password_file),
                credential_request,
                account.account_id.as_bytes(),
                params,
            )
            .map_err(|_| authentication_failed())?;
            let login_id = random_hex(32)?;
            conn.execute(
                "INSERT INTO auth_logins
                 (login_id, account_id, handle, purpose, operation_hash, server_login_state,
                  expires_at, consumed_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
                params![
                    login_id,
                    account.account_id,
                    handle.as_str(),
                    req.purpose.as_str(),
                    req.operation_hash,
                    hex(login.state.serialize().as_slice()),
                    now_secs() + LOGIN_TTL_SECS,
                    now_secs()
                ],
            )?;
            Ok(AccountAuthStartResponse {
                account_id: account.account_id,
                handle: handle.as_str().to_string(),
                login_id,
                purpose: req.purpose,
                operation_hash: req.operation_hash,
                credential_response: hex(login.message.serialize().as_slice()),
            })
        })
    }

    pub fn finish_auth(&self, req: AccountAuthFinishRequest) -> Result<AccountAuthToken> {
        let handle = validate_handle(&req.handle)?;
        let login = self.with_conn(|conn| claim_login(conn, &req.login_id, handle.as_str()))?;
        let finalization = CredentialFinalization::<MycelliumOpaque>::deserialize(
            &input_hex(&req.credential_finalization, "credential finalization")
                .map_err(|_| authentication_failed())?,
        )
        .map_err(|_| authentication_failed())?;
        let server_login = ServerLogin::<MycelliumOpaque>::deserialize(
            &from_hex(&login.server_login_state).map_err(|_| authentication_failed())?,
        )
        .map_err(|_| authentication_failed())?;
        let context = auth_context(
            &login.account_id,
            &login.handle,
            &login.purpose,
            login.operation_hash.as_deref(),
        );
        let params = server_login_params(&login.handle, &context);
        server_login
            .finish(finalization, params)
            .map_err(|_| authentication_failed())?;
        let token = Zeroizing::new(random_hex(32)?);
        let token_hash = hash_token(&token);
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO auth_tokens
                 (token_hash, account_id, handle, purpose, operation_hash,
                  expires_at, consumed_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
                params![
                    token_hash,
                    login.account_id,
                    login.handle,
                    login.purpose.as_str(),
                    login.operation_hash,
                    now_secs() + AUTH_TOKEN_TTL_SECS,
                    now_secs()
                ],
            )?;
            Ok(())
        })?;
        Ok(AccountAuthToken {
            handle: handle.as_str().to_string(),
            auth_token: token,
            purpose: login.purpose,
            operation_hash: login.operation_hash,
        })
    }

    pub fn recover(&self, req: AccountRecoverRequest) -> Result<AccountRecoveryResponse> {
        let auth =
            self.with_conn(|conn| claim_auth(conn, &req.auth_token, AuthPurpose::Recover, None))?;
        self.with_conn(|conn| {
            let account = load_account_by_id(conn, &auth.account_id)?
                .ok_or_else(|| not_found("account not found"))?;
            account.into_recovery_response()
        })
    }

    pub fn update_record(&self, req: AccountUpdateRecordRequest) -> Result<AccountPublicRecord> {
        let auth = self.with_conn(|conn| {
            claim_auth_for_purpose(conn, &req.auth_token, AuthPurpose::PublishRecord)
        })?;
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            let account = load_account_by_id(&tx, &auth.account_id)?
                .ok_or_else(|| not_found("account not found"))?;
            let record = verify_signed_record(account.handle.as_str(), &req.signed_record)?;
            let operation_hash =
                record_operation_hash(account.handle.as_str(), &req.signed_record)?;
            if auth.operation_hash.as_deref() != Some(operation_hash.as_str()) {
                return Err(authentication_failed());
            }
            let seq = checked_seq(record.record.seq)?;
            if account.wallet_public != hex(&record.record.wallet.0) {
                return Err(conflict("wallet rotation requires rotate-wallet"));
            }
            if seq <= account.signed_record_seq {
                return Err(conflict(format!("stale record for '{}'", account.handle)));
            }
            let rows = tx.execute(
                "UPDATE accounts
                 SET signed_record = ?1, signed_record_seq = ?2, updated_at = ?3
                 WHERE account_id = ?4 AND signed_record_seq < ?2",
                params![req.signed_record, seq, now_secs(), account.account_id],
            )?;
            ensure_one_row(rows, "stale record")?;
            tx.commit()?;
            self.public_record(&account.handle)?
                .ok_or_else(|| not_found("account vanished after update"))
        })
    }

    pub fn rotate_wallet(&self, req: AccountRotateWalletRequest) -> Result<AccountPublicRecord> {
        let auth = self.with_conn(|conn| {
            claim_auth_for_purpose(conn, &req.auth_token, AuthPurpose::RotateWallet)
        })?;
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            let account = load_account_by_id(&tx, &auth.account_id)?
                .ok_or_else(|| not_found("account not found"))?;
            let record = verify_signed_record(account.handle.as_str(), &req.signed_record)?;
            let operation_hash =
                record_operation_hash(account.handle.as_str(), &req.signed_record)?;
            if auth.operation_hash.as_deref() != Some(operation_hash.as_str()) {
                return Err(authentication_failed());
            }
            let seq = checked_seq(record.record.seq)?;
            let wallet_public = hex(&record.record.wallet.0);
            if seq <= account.signed_record_seq {
                return Err(conflict(format!("stale record for '{}'", account.handle)));
            }
            validate_backup_for_account(
                &req.wallet_backup,
                &wallet_backup_metadata(
                    &account.account_id,
                    &account.handle,
                    &wallet_public,
                    account.recovery_revision,
                ),
            )?;
            let rows = tx.execute(
                "UPDATE accounts
                 SET wallet_public = ?1, wallet_backup = ?2, signed_record = ?3,
                     signed_record_seq = ?4, updated_at = ?5
                 WHERE account_id = ?6 AND signed_record_seq < ?4
                   AND recovery_revision = ?7",
                params![
                    wallet_public,
                    serde_json::to_string(&req.wallet_backup)?,
                    req.signed_record,
                    seq,
                    now_secs(),
                    account.account_id,
                    account.recovery_revision
                ],
            )?;
            ensure_one_row(rows, "stale record")?;
            tx.commit()?;
            self.public_record(&account.handle)?
                .ok_or_else(|| not_found("account vanished after wallet rotation"))
        })
    }

    pub fn start_recovery_rotation(
        &self,
        req: RecoveryRegistrationStartRequest,
    ) -> Result<RecoveryRegistrationStartResponse> {
        let auth = self.with_conn(|conn| {
            claim_auth(conn, &req.auth_token, AuthPurpose::RotateRecovery, None)
        })?;
        let registration_request = RegistrationRequest::<MycelliumOpaque>::deserialize(&input_hex(
            &req.registration_request,
            "registration request",
        )?)
        .map_err(|_| invalid_request("bad registration request"))?;
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            prune_ephemeral(&tx)?;
            let account = load_account_by_id(&tx, &auth.account_id)?
                .ok_or_else(|| not_found("account not found"))?;
            tx.execute(
                "DELETE FROM registry_operations
                 WHERE account_id = ?1 AND purpose = ?2",
                params![account.account_id, AuthPurpose::RotateRecovery.as_str()],
            )?;
            let setup = load_or_create_server_setup(&tx, &self.server_secret)?;
            let response = ServerRegistration::<MycelliumOpaque>::start(
                &setup,
                registration_request,
                account.account_id.as_bytes(),
            )
            .map_err(|_| invalid_request("bad registration request"))?;
            let operation_id = random_hex(32)?;
            let operation_token = Zeroizing::new(random_hex(32)?);
            tx.execute(
                "INSERT INTO registry_operations
                 (operation_id, operation_token_hash, account_id, handle, purpose,
                  operation_hash, expected_record_seq, expected_recovery_revision,
                  expires_at, consumed_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, ?7, NULL, ?8)",
                params![
                    operation_id,
                    hash_token(&operation_token),
                    account.account_id,
                    account.handle,
                    AuthPurpose::RotateRecovery.as_str(),
                    account.recovery_revision,
                    now_secs() + REGISTRATION_TTL_SECS,
                    now_secs()
                ],
            )?;
            tx.commit()?;
            Ok(RecoveryRegistrationStartResponse {
                account_id: account.account_id,
                handle: auth.handle,
                wallet_public: account.wallet_public,
                recovery_revision: account.recovery_revision + 1,
                operation_id,
                operation_token,
                registration_response: hex(response.message.serialize().as_slice()),
            })
        })
    }

    pub fn finish_recovery_rotation(
        &self,
        req: RecoveryRegistrationFinishRequest,
    ) -> Result<AccountPublicRecord> {
        let operation = self.with_conn(|conn| {
            claim_operation(
                conn,
                &req.operation_id,
                &req.operation_token,
                AuthPurpose::RotateRecovery,
            )
        })?;
        let upload = RegistrationUpload::<MycelliumOpaque>::deserialize(&input_hex(
            &req.registration_upload,
            "registration upload",
        )?)
        .map_err(|_| invalid_request("bad registration upload"))?;
        let password_file = ServerRegistration::finish(upload);
        let opaque_password_file = hex(password_file.serialize().as_slice());
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            prune_ephemeral(&tx)?;
            let expected_revision = operation
                .expected_recovery_revision
                .ok_or_else(|| conflict("recovery rotation binding mismatch"))?;
            let account = load_account_by_id(&tx, &operation.account_id)?
                .ok_or_else(|| not_found("account not found"))?;
            if account.handle != operation.handle || account.recovery_revision != expected_revision
            {
                return Err(conflict("recovery rotation binding mismatch"));
            }
            let next_revision = expected_revision + 1;
            validate_backup_for_account(
                &req.wallet_backup,
                &wallet_backup_metadata(
                    &account.account_id,
                    &account.handle,
                    &account.wallet_public,
                    next_revision,
                ),
            )?;
            let rows = tx.execute(
                "UPDATE accounts
                 SET recovery_revision = ?1, opaque_password_file = ?2,
                     wallet_backup = ?3, updated_at = ?4
                 WHERE account_id = ?5 AND recovery_revision = ?6",
                params![
                    next_revision,
                    opaque_password_file,
                    serde_json::to_string(&req.wallet_backup)?,
                    now_secs(),
                    account.account_id,
                    expected_revision
                ],
            )?;
            ensure_one_row(rows, "recovery rotation conflict")?;
            tx.commit()?;
            self.public_record(&account.handle)?
                .ok_or_else(|| not_found("account vanished after recovery rotation"))
        })
    }

    pub fn public_record(&self, handle: &str) -> Result<Option<AccountPublicRecord>> {
        let handle = validate_handle(handle)?;
        self.with_conn(|conn| {
            Ok(load_account_by_handle(conn, handle.as_str())?.map(AccountRow::into_public_record))
        })
    }

    pub fn issue_creation_grant(
        &self,
        handle: Option<&str>,
        ttl_secs: Option<i64>,
    ) -> Result<SecretString> {
        let handle = handle
            .map(validate_handle)
            .transpose()?
            .map(|handle| handle.as_str().to_string());
        let ttl_secs = ttl_secs.unwrap_or(CREATION_GRANT_TTL_SECS);
        if ttl_secs <= 0 || ttl_secs > 86_400 {
            bail!("creation grant ttl must be between 1 and 86400 seconds");
        }
        let grant = random_secret_hex(32)?;
        let grant_hash = hash_token(&grant);
        self.with_conn(|conn| {
            prune_ephemeral(conn)?;
            conn.execute(
                "INSERT INTO creation_grants
                 (grant_hash, handle, expires_at, consumed_at, created_at)
                 VALUES (?1, ?2, ?3, NULL, ?4)",
                params![grant_hash, handle, now_secs() + ttl_secs, now_secs()],
            )?;
            Ok(())
        })?;
        Ok(grant)
    }

    fn rate_limit_peer_for_request(&self, request: &Request<Body>) -> Result<String> {
        let edge_client_key = request.headers().get(EDGE_CLIENT_KEY_HEADER);
        match request.extensions().get::<RegistryConnectionPeer>() {
            Some(RegistryConnectionPeer::Unix) => {
                let value = edge_client_key
                    .ok_or_else(|| forbidden("trusted edge client identity is required"))?;
                let value = validate_edge_client_key(value)?;
                Ok(rate_limit_peer_key(
                    &self.server_secret,
                    b"edge-client",
                    value.as_bytes(),
                ))
            }
            Some(RegistryConnectionPeer::Tcp(remote)) => {
                if edge_client_key.is_some() {
                    return Err(forbidden(
                        "trusted edge client identity is accepted only on the private registry socket",
                    ));
                }
                Ok(rate_limit_peer_key(
                    &self.server_secret,
                    b"tcp-ip",
                    remote.ip().to_string().as_bytes(),
                ))
            }
            None => {
                if edge_client_key.is_some() {
                    return Err(forbidden(
                        "trusted edge client identity is accepted only on the private registry socket",
                    ));
                }
                Ok(rate_limit_peer_key(
                    &self.server_secret,
                    b"tcp-ip",
                    b"127.0.0.1",
                ))
            }
        }
    }
}

pub fn serve_tcp_dev(addr: &str, data_dir: impl AsRef<Path>) -> Result<()> {
    let parsed: SocketAddr = addr.parse().context("bad listen address")?;
    if !is_loopback_ip(parsed.ip()) {
        bail!(
            "the development TCP registry only binds to loopback; production registry must use a private Unix socket behind a trusted HTTPS edge"
        );
    }
    let app = registry_router(Arc::new(AccountStore::open(data_dir)?));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = TcpListener::bind(parsed)
            .await
            .map_err(|err| anyhow!("listen: {err}"))?;
        println!("development registry listening on http://{parsed}");
        run_tcp_listener(listener, app, std::future::pending::<()>()).await
    })
}

#[cfg(unix)]
pub fn serve_unix(data_dir: impl AsRef<Path>) -> Result<()> {
    if data_dir.as_ref() == Path::new(":memory:") {
        bail!("production registry serving requires a persistent data directory");
    }
    let store = Arc::new(AccountStore::open(data_dir)?);
    let socket_path = registry_socket_path(&store.data_dir);
    prepare_unix_socket_path(&socket_path)?;
    let app = registry_router(store);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = UnixListener::bind(&socket_path)
            .map_err(|err| anyhow!("listen on {}: {err}", socket_path.display()))?;
        set_private_file(&socket_path)?;
        println!(
            "registry listening on unix socket {}",
            socket_path.display()
        );
        run_unix_listener(listener, app, std::future::pending::<()>()).await
    })
}

#[cfg(not(unix))]
pub fn serve_unix(_data_dir: impl AsRef<Path>) -> Result<()> {
    bail!("production registry serving requires Unix filesystem and socket permissions")
}

fn registry_router(store: Arc<AccountStore>) -> Router {
    let state = RegistryState { store };
    Router::new()
        .fallback(registry_entry_handler)
        .layer(ServiceBuilder::new().layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS)))
        .with_state(state)
}

#[derive(Clone)]
struct RegistryState {
    store: Arc<AccountStore>,
}

#[derive(Clone)]
enum RegistryConnectionPeer {
    Tcp(SocketAddr),
    Unix,
}

async fn run_tcp_listener<S>(listener: TcpListener, app: Router, shutdown: S) -> Result<()>
where
    S: Future<Output = ()> + Send,
{
    let permits = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, remote) = accepted.map_err(|err| anyhow!("accept: {err}"))?;
                spawn_registry_connection(
                    stream,
                    RegistryConnectionPeer::Tcp(remote),
                    app.clone(),
                    Arc::clone(&permits),
                );
            }
        }
    }
}

#[cfg(unix)]
async fn run_unix_listener<S>(listener: UnixListener, app: Router, shutdown: S) -> Result<()>
where
    S: Future<Output = ()> + Send,
{
    let permits = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, _remote) = accepted.map_err(|err| anyhow!("accept: {err}"))?;
                spawn_registry_connection(
                    stream,
                    RegistryConnectionPeer::Unix,
                    app.clone(),
                    Arc::clone(&permits),
                );
            }
        }
    }
}

fn spawn_registry_connection<I>(
    stream: I,
    peer: RegistryConnectionPeer,
    app: Router,
    permits: Arc<Semaphore>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(permit) = permits.try_acquire_owned() else {
        drop(stream);
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        serve_registry_connection(stream, peer, app).await;
    });
}

async fn serve_registry_connection<I>(stream: I, peer: RegistryConnectionPeer, app: Router)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |mut request: Request<Incoming>| {
        let app = app.clone();
        let peer = peer.clone();
        async move {
            request.extensions_mut().insert(peer);
            let request = request.map(Body::new);
            let response = match app.oneshot(request).await {
                Ok(response) => response,
                Err(err) => match err {},
            };
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    let service = TowerToHyperService::new(service);
    let io = TokioIo::new(stream);
    let mut builder = HyperBuilder::new(TokioExecutor::new()).http1_only();
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Some(Duration::from_secs(HEADER_READ_TIMEOUT_SECS)))
        .keep_alive(false)
        .max_headers(64);
    let served = builder.serve_connection(io, service);
    let _ = tokio::time::timeout(
        Duration::from_secs(CONNECTION_LIFETIME_TIMEOUT_SECS),
        served,
    )
    .await;
}

async fn registry_entry_handler(
    State(state): State<RegistryState>,
    request: Request<Body>,
) -> Response {
    let peer = match state.store.rate_limit_peer_for_request(&request) {
        Ok(peer) => peer,
        Err(err) => return error_response_for_error(&err),
    };
    let method = request.method().clone();
    let uri = request.uri().clone();
    let classified = classify_registry_request(&method, &uri);
    let ClassifiedRequest { route, rate_limits } = classified;
    let store = state.store.clone();
    let allowed = tokio::task::spawn_blocking(move || {
        store.with_conn(|conn| allow_request(conn, &peer, &rate_limits))
    })
    .await;
    match allowed {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return error_response_for_error(&err),
        Err(_) => return error_response_kind(RegistryErrorKind::Internal),
    }

    match route {
        RegistryRoute::RegistrationStart => {
            json_blocking_response(request, move |req| state.store.start_registration(req)).await
        }
        RegistryRoute::Create => {
            json_blocking_response(request, move |req| state.store.create(req)).await
        }
        RegistryRoute::AuthStart => {
            json_blocking_response(request, move |req| state.store.start_auth(req)).await
        }
        RegistryRoute::AuthFinish => {
            json_blocking_response(request, move |req| state.store.finish_auth(req)).await
        }
        RegistryRoute::Recover => {
            json_blocking_response(request, move |req| state.store.recover(req)).await
        }
        RegistryRoute::Record => {
            json_blocking_response(request, move |req| state.store.update_record(req)).await
        }
        RegistryRoute::WalletRotate => {
            json_blocking_response(request, move |req| state.store.rotate_wallet(req)).await
        }
        RegistryRoute::RecoveryRegistrationStart => {
            json_blocking_response(request, move |req| state.store.start_recovery_rotation(req))
                .await
        }
        RegistryRoute::RecoveryRegistrationFinish => {
            json_blocking_response(request, move |req| {
                state.store.finish_recovery_rotation(req)
            })
            .await
        }
        RegistryRoute::Lookup { handle } => {
            blocking_response(move || {
                state
                    .store
                    .public_record(&handle)
                    .and_then(|account| account.ok_or_else(|| not_found("account not found")))
            })
            .await
        }
        RegistryRoute::Error(kind) => error_response_kind(kind),
    }
}

async fn blocking_response<T, F>(f: F) -> Response
where
    T: Serialize + Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => into_http_response(result),
        Err(_) => error_response_kind(RegistryErrorKind::Internal),
    }
}

async fn json_blocking_response<T, R, F>(request: Request<Body>, f: F) -> Response
where
    T: DeserializeOwned + Send + 'static,
    R: Serialize + Send + 'static,
    F: FnOnce(T) -> Result<R> + Send + 'static,
{
    match parse_registry_json(request).await {
        Ok(req) => blocking_response(move || f(req)).await,
        Err(err) => error_response_for_error(&err),
    }
}

async fn parse_registry_json<T: DeserializeOwned>(request: Request<Body>) -> Result<T> {
    let Some(content_type) = request.headers().get(header::CONTENT_TYPE) else {
        return Err(invalid_request("content type must be application/json"));
    };
    let content_type = content_type
        .to_str()
        .map_err(|_| invalid_request("content type must be application/json"))?;
    let media_type = content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(invalid_request("content type must be application/json"));
    }
    let bytes = tokio::time::timeout(
        Duration::from_secs(BODY_READ_TIMEOUT_SECS),
        to_bytes(request.into_body(), MAX_BODY_BYTES),
    )
    .await
    .map_err(|_| payload_too_large())?
    .map_err(|_| payload_too_large())?;
    if bytes.is_empty() {
        return Err(invalid_request("request body is required"));
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid_request("bad json"))
}

fn into_http_response<T: Serialize>(result: Result<T>) -> Response {
    match result {
        Ok(value) => with_no_store(Json(value).into_response()),
        Err(err) => error_response_for_error(&err),
    }
}

fn error_response_for_error(err: &anyhow::Error) -> Response {
    if let Some(err) = err.downcast_ref::<RegistryError>() {
        error_response_kind(err.kind)
    } else {
        error_response_kind(RegistryErrorKind::Internal)
    }
}

fn error_response_kind(kind: RegistryErrorKind) -> Response {
    with_no_store(
        (
            kind.status(),
            Json(ErrorResponse {
                error: kind.code().to_string(),
            }),
        )
            .into_response(),
    )
}

fn with_no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

pub struct RegistrationClientState {
    handle: String,
    account_id: String,
    registration_id: String,
    state: ClientRegistration<MycelliumOpaque>,
}

pub struct LoginClientState {
    account_id: String,
    handle: String,
    login_id: String,
    purpose: AuthPurpose,
    operation_hash: Option<String>,
    state: ClientLogin<MycelliumOpaque>,
}

pub struct RecoveryRotationClientState {
    account_id: String,
    handle: String,
    wallet_public: String,
    recovery_revision: u64,
    operation_id: String,
    operation_token: SecretString,
    state: ClientRegistration<MycelliumOpaque>,
}

pub fn account_registration_start(
    base: &str,
    handle: &str,
    secret: &RecoverySecret,
    creation_grant: &SecretString,
) -> Result<(RegistrationClientState, AccountRegistrationStartResponse)> {
    let mut rng = OsRng;
    let start = ClientRegistration::<MycelliumOpaque>::start(&mut rng, secret.as_bytes())
        .map_err(|_| anyhow!("could not start account registration"))?;
    let response: AccountRegistrationStartResponse = post_json(
        base,
        "/v2/accounts/registration/start",
        &AccountRegistrationStartRequest {
            handle: handle.to_string(),
            registration_request: hex(start.message.serialize().as_slice()),
            creation_grant: secret_copy(creation_grant),
        },
    )?;
    if response.handle != handle {
        bail!("registry returned registration for the wrong handle");
    }
    Ok((
        RegistrationClientState {
            handle: handle.to_string(),
            account_id: response.account_id.clone(),
            registration_id: response.registration_id.clone(),
            state: start.state,
        },
        response,
    ))
}

pub fn account_registration_finish(
    state: RegistrationClientState,
    response: &AccountRegistrationStartResponse,
    secret: &RecoverySecret,
    wallet_public: &str,
    wallet_secret: &[u8; 32],
) -> Result<(String, WalletBackupEnvelope)> {
    if response.account_id != state.account_id
        || response.handle != state.handle
        || response.registration_id != state.registration_id
    {
        bail!("registration state mismatch");
    }
    let registration_response = RegistrationResponse::<MycelliumOpaque>::deserialize(
        &from_hex(&response.registration_response)
            .map_err(|_| anyhow!("bad registry registration response"))?,
    )
    .map_err(|_| anyhow!("bad registry registration response"))?;
    let mut rng = OsRng;
    let finish = state
        .state
        .finish(
            &mut rng,
            secret.as_bytes(),
            registration_response,
            registration_finish_params(&state.handle),
        )
        .map_err(|_| anyhow!("could not finish account registration"))?;
    let envelope = seal_wallet_backup(
        finish.export_key.as_slice(),
        wallet_backup_metadata(&state.account_id, &state.handle, wallet_public, 1),
        wallet_secret,
    )?;
    Ok((hex(finish.message.serialize().as_slice()), envelope))
}

pub fn create_account(base: &str, req: &AccountCreateRequest) -> Result<AccountPublicRecord> {
    let record: AccountPublicRecord = post_json(base, "/v2/accounts", req)?;
    if record.handle != req.handle || record.account_id != req.account_id {
        bail!("registry returned account for the wrong handle");
    }
    Ok(record)
}

pub fn account_auth_start(
    base: &str,
    handle: &str,
    secret: &RecoverySecret,
    purpose: AuthPurpose,
    operation_hash: Option<String>,
) -> Result<(LoginClientState, AccountAuthStartResponse)> {
    validate_operation_binding(&purpose, operation_hash.as_deref())?;
    let mut rng = OsRng;
    let start = ClientLogin::<MycelliumOpaque>::start(&mut rng, secret.as_bytes())
        .map_err(|_| anyhow!("could not start account login"))?;
    let response: AccountAuthStartResponse = post_json(
        base,
        "/v2/accounts/auth/start",
        &AccountAuthStartRequest {
            handle: handle.to_string(),
            purpose: purpose.clone(),
            operation_hash: operation_hash.clone(),
            credential_request: hex(start.message.serialize().as_slice()),
        },
    )?;
    if response.handle != handle
        || response.purpose != purpose
        || response.operation_hash != operation_hash
    {
        bail!("registry returned login for the wrong account operation");
    }
    Ok((
        LoginClientState {
            account_id: response.account_id.clone(),
            handle: handle.to_string(),
            login_id: response.login_id.clone(),
            purpose,
            operation_hash,
            state: start.state,
        },
        response,
    ))
}

pub fn account_auth_finish(
    base: &str,
    state: LoginClientState,
    response: &AccountAuthStartResponse,
    secret: &RecoverySecret,
) -> Result<(AccountAuthToken, OpaqueExportKey)> {
    if state.handle != response.handle
        || state.login_id != response.login_id
        || state.purpose != response.purpose
        || state.operation_hash != response.operation_hash
    {
        bail!("login state mismatch");
    }
    let credential_response = CredentialResponse::<MycelliumOpaque>::deserialize(
        &from_hex(&response.credential_response).map_err(|_| anyhow!("bad login response"))?,
    )
    .map_err(|_| anyhow!("bad login response"))?;
    let context = auth_context(
        &state.account_id,
        &state.handle,
        &state.purpose,
        state.operation_hash.as_deref(),
    );
    let finish = state
        .state
        .finish(
            &mut OsRng,
            secret.as_bytes(),
            credential_response,
            client_login_finish_params(&state.handle, &context),
        )
        .map_err(|_| anyhow!("authentication failed"))?;
    let token: AccountAuthToken = post_json(
        base,
        "/v2/accounts/auth/finish",
        &AccountAuthFinishRequest {
            handle: state.handle.clone(),
            login_id: state.login_id,
            credential_finalization: hex(finish.message.serialize().as_slice()),
        },
    )?;
    if token.handle != state.handle
        || token.purpose != state.purpose
        || token.operation_hash != state.operation_hash
    {
        bail!("registry returned auth token for the wrong account operation");
    }
    Ok((
        token,
        OpaqueExportKey::new(finish.export_key.as_slice().to_vec()),
    ))
}

pub fn account_auth(
    base: &str,
    handle: &str,
    secret: &RecoverySecret,
    purpose: AuthPurpose,
    operation_hash: Option<String>,
) -> Result<(AccountAuthToken, OpaqueExportKey)> {
    let (state, response) = account_auth_start(base, handle, secret, purpose, operation_hash)?;
    account_auth_finish(base, state, &response, secret)
}

pub fn recover_account(
    base: &str,
    handle: &str,
    auth: &AccountAuthToken,
) -> Result<AccountRecoveryResponse> {
    if auth.handle != handle || auth.purpose != AuthPurpose::Recover {
        bail!("recovery auth token does not match requested handle");
    }
    let response: AccountRecoveryResponse = post_json(
        base,
        "/v2/accounts/recover",
        &AccountRecoverRequest {
            auth_token: secret_copy(&auth.auth_token),
        },
    )?;
    if response.handle != handle {
        bail!("registry returned recovery for the wrong handle");
    }
    validate_backup_for_account(
        &response.wallet_backup,
        &wallet_backup_metadata(
            &response.account_id,
            &response.handle,
            &response.wallet_public,
            response.recovery_revision,
        ),
    )?;
    verify_signed_record(handle, &response.signed_record)?;
    Ok(response)
}

pub fn update_account_record(
    base: &str,
    handle: &str,
    req: &AccountUpdateRecordRequest,
) -> Result<AccountPublicRecord> {
    let response: AccountPublicRecord = post_json(base, "/v2/accounts/record", req)?;
    if response.handle != handle {
        bail!("registry returned account for the wrong handle");
    }
    Ok(response)
}

pub fn rotate_account_wallet(
    base: &str,
    handle: &str,
    req: &AccountRotateWalletRequest,
) -> Result<AccountPublicRecord> {
    let response: AccountPublicRecord = post_json(base, "/v2/accounts/wallet/rotate", req)?;
    if response.handle != handle {
        bail!("registry returned account for the wrong handle");
    }
    Ok(response)
}

pub fn recovery_rotation_start(
    base: &str,
    auth: &AccountAuthToken,
    new_secret: &RecoverySecret,
) -> Result<(
    RecoveryRotationClientState,
    RecoveryRegistrationStartResponse,
)> {
    if auth.purpose != AuthPurpose::RotateRecovery {
        bail!("recovery rotation auth token does not match requested operation");
    }
    let mut rng = OsRng;
    let start = ClientRegistration::<MycelliumOpaque>::start(&mut rng, new_secret.as_bytes())
        .map_err(|_| anyhow!("could not start recovery rotation"))?;
    let response: RecoveryRegistrationStartResponse = post_json(
        base,
        "/v2/accounts/recovery/registration/start",
        &RecoveryRegistrationStartRequest {
            auth_token: secret_copy(&auth.auth_token),
            registration_request: hex(start.message.serialize().as_slice()),
        },
    )?;
    if response.handle != auth.handle || response.recovery_revision == 0 {
        bail!("registry returned recovery rotation for the wrong account");
    }
    Ok((
        RecoveryRotationClientState {
            account_id: response.account_id.clone(),
            handle: response.handle.clone(),
            wallet_public: response.wallet_public.clone(),
            recovery_revision: response.recovery_revision,
            operation_id: response.operation_id.clone(),
            operation_token: secret_copy(&response.operation_token),
            state: start.state,
        },
        response,
    ))
}

pub fn recovery_rotation_finish(
    base: &str,
    auth: AccountAuthToken,
    state: RecoveryRotationClientState,
    response: &RecoveryRegistrationStartResponse,
    new_secret: &RecoverySecret,
    wallet_secret: &[u8; 32],
) -> Result<AccountPublicRecord> {
    if auth.handle != state.handle || auth.purpose != AuthPurpose::RotateRecovery {
        bail!("recovery rotation auth token does not match requested operation");
    }
    if response.account_id != state.account_id
        || response.handle != state.handle
        || response.wallet_public != state.wallet_public
        || response.recovery_revision != state.recovery_revision
        || response.operation_id != state.operation_id
        || response.operation_token != state.operation_token
    {
        bail!("recovery rotation state mismatch");
    }
    let registration_response = RegistrationResponse::<MycelliumOpaque>::deserialize(
        &from_hex(&response.registration_response)
            .map_err(|_| anyhow!("bad registry registration response"))?,
    )
    .map_err(|_| anyhow!("bad registry registration response"))?;
    let mut rng = OsRng;
    let finish = state
        .state
        .finish(
            &mut rng,
            new_secret.as_bytes(),
            registration_response,
            registration_finish_params(&state.handle),
        )
        .map_err(|_| anyhow!("could not finish recovery rotation"))?;
    let wallet_backup = seal_wallet_backup(
        finish.export_key.as_slice(),
        wallet_backup_metadata(
            &state.account_id,
            &state.handle,
            &state.wallet_public,
            state.recovery_revision,
        ),
        wallet_secret,
    )?;
    let record: AccountPublicRecord = post_json(
        base,
        "/v2/accounts/recovery/registration/finish",
        &RecoveryRegistrationFinishRequest {
            operation_id: state.operation_id,
            operation_token: state.operation_token,
            registration_upload: hex(finish.message.serialize().as_slice()),
            wallet_backup,
        },
    )?;
    if record.handle != state.handle || record.account_id != state.account_id {
        bail!("registry returned recovery rotation for the wrong account");
    }
    Ok(record)
}

pub fn lookup_account(base: &str, handle: &str) -> Result<AccountPublicRecord> {
    let path = format!("/v2/accounts/{handle}");
    let response: AccountPublicRecord = get_json(base, &path)?;
    if response.handle != handle {
        bail!("registry returned account for the wrong handle");
    }
    verify_signed_record(handle, &response.signed_record)?;
    Ok(response)
}

fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
    base: &str,
    path: &str,
    value: &T,
) -> Result<R> {
    let client = http_client()?;
    let response = client.post(registry_url(base, path)?).json(value).send()?;
    decode_response(response)
}

fn get_json<R: for<'de> Deserialize<'de>>(base: &str, path: &str) -> Result<R> {
    let client = http_client()?;
    let response = client.get(registry_url(base, path)?).send()?;
    decode_response(response)
}

fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?)
}

fn registry_url(base: &str, path: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(base).context("bad registry URL")?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(url.host_str()) => {}
        "http" => bail!("registry URL must use https outside localhost"),
        _ => bail!("registry URL must use https"),
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        bail!("registry URL must not include a path, query, or fragment");
    }
    url.set_path(path.trim_start_matches('/'));
    Ok(url.to_string())
}

fn decode_response<R: for<'de> Deserialize<'de>>(
    mut response: reqwest::blocking::Response,
) -> Result<R> {
    let status = response.status();
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        bail!("registry response is too large");
    }
    if !status.is_success() {
        if let Ok(err) = serde_json::from_slice::<ErrorResponse>(&bytes) {
            bail!(err.error);
        }
        bail!("registry returned HTTP {status}");
    }
    serde_json::from_slice::<R>(&bytes).context("bad registry response")
}

#[derive(Clone)]
struct AccountRow {
    account_id: String,
    handle: String,
    wallet_public: String,
    recovery_revision: u64,
    opaque_password_file: String,
    wallet_backup: WalletBackupEnvelope,
    signed_record: String,
    signed_record_seq: i64,
}

impl AccountRow {
    fn into_public_record(self) -> AccountPublicRecord {
        AccountPublicRecord {
            account_id: self.account_id,
            handle: self.handle,
            wallet_public: self.wallet_public,
            signed_record: self.signed_record,
        }
    }

    fn into_recovery_response(self) -> Result<AccountRecoveryResponse> {
        Ok(AccountRecoveryResponse {
            account_id: self.account_id,
            handle: self.handle,
            wallet_public: self.wallet_public,
            recovery_revision: self.recovery_revision,
            wallet_backup: self.wallet_backup,
            signed_record: self.signed_record,
        })
    }
}

struct PendingRegistration {
    account_id: String,
    handle: String,
}

struct LoginRow {
    account_id: String,
    handle: String,
    purpose: AuthPurpose,
    operation_hash: Option<String>,
    server_login_state: String,
    expires_at: i64,
}

struct AuthRow {
    account_id: String,
    handle: String,
    operation_hash: Option<String>,
}

struct OperationRow {
    account_id: String,
    handle: String,
    expected_recovery_revision: Option<u64>,
}

fn open_conn(path: &Path) -> Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.set_transaction_behavior(TransactionBehavior::Immediate);
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = FULL;
        "#,
    )?;
    Ok(conn)
}

fn init_conn(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version == 0 && table_exists(conn, "accounts")? {
        bail!(
            "registry database has an incompatible pre-v2 schema; create a fresh registry database"
        );
    }
    if version != 0 && version != SCHEMA_VERSION {
        bail!("registry database schema version {version} is not supported");
    }
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS registry_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY,
            handle TEXT NOT NULL UNIQUE,
            state TEXT NOT NULL CHECK (state IN ('active', 'disabled')),
            wallet_public TEXT NOT NULL,
            recovery_revision INTEGER NOT NULL CHECK (recovery_revision >= 1),
            opaque_password_file TEXT NOT NULL,
            wallet_backup TEXT NOT NULL,
            signed_record TEXT NOT NULL,
            signed_record_seq INTEGER NOT NULL CHECK (signed_record_seq >= 0),
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS pending_registrations (
            registration_id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL UNIQUE,
            handle TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS creation_grants (
            grant_hash TEXT PRIMARY KEY,
            handle TEXT,
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS handle_cooldowns (
            handle TEXT PRIMARY KEY,
            until INTEGER NOT NULL,
            reason TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auth_logins (
            login_id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            handle TEXT NOT NULL,
            purpose TEXT NOT NULL,
            operation_hash TEXT,
            server_login_state TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auth_tokens (
            token_hash TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            handle TEXT NOT NULL,
            purpose TEXT NOT NULL,
            operation_hash TEXT,
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS registry_operations (
            operation_id TEXT PRIMARY KEY,
            operation_token_hash TEXT NOT NULL UNIQUE,
            account_id TEXT NOT NULL,
            handle TEXT NOT NULL,
            purpose TEXT NOT NULL,
            operation_hash TEXT,
            expected_record_seq INTEGER,
            expected_recovery_revision INTEGER,
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS rate_buckets (
            peer TEXT NOT NULL,
            action TEXT NOT NULL,
            bucket TEXT NOT NULL,
            window_start INTEGER NOT NULL,
            count INTEGER NOT NULL CHECK (count >= 0),
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (peer, action, bucket, window_start)
        );

        CREATE TABLE IF NOT EXISTS signup_counters (
            action TEXT NOT NULL,
            bucket TEXT NOT NULL,
            window_start INTEGER NOT NULL,
            count INTEGER NOT NULL CHECK (count >= 0),
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (action, bucket, window_start)
        );

        CREATE INDEX IF NOT EXISTS idx_accounts_handle ON accounts(handle);
        CREATE INDEX IF NOT EXISTS idx_creation_grants_expiry ON creation_grants(expires_at);
        CREATE INDEX IF NOT EXISTS idx_handle_cooldowns_until ON handle_cooldowns(until);
        CREATE INDEX IF NOT EXISTS idx_auth_logins_expiry ON auth_logins(expires_at);
        CREATE INDEX IF NOT EXISTS idx_auth_tokens_expiry ON auth_tokens(expires_at);
        CREATE INDEX IF NOT EXISTS idx_registry_operations_expiry ON registry_operations(expires_at);
        CREATE INDEX IF NOT EXISTS idx_rate_buckets_expiry ON rate_buckets(window_start);
        CREATE INDEX IF NOT EXISTS idx_signup_counters_expiry ON signup_counters(window_start);
        PRAGMA user_version = 5;
        "#,
    )?;
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn prune_ephemeral(conn: &Connection) -> Result<()> {
    let now = now_secs();
    conn.execute(
        "INSERT INTO handle_cooldowns (handle, until, reason, updated_at)
         SELECT handle, ?2, 'expired_pending_registration', ?1
         FROM pending_registrations
         WHERE expires_at < ?1
         ON CONFLICT(handle) DO UPDATE SET
             until = MAX(handle_cooldowns.until, excluded.until),
             reason = excluded.reason,
             updated_at = excluded.updated_at",
        params![now, now + HANDLE_REGISTRATION_COOLDOWN_SECS],
    )?;
    conn.execute(
        "DELETE FROM pending_registrations WHERE expires_at < ?1",
        params![now],
    )?;
    conn.execute(
        "DELETE FROM creation_grants WHERE expires_at < ?1 OR consumed_at IS NOT NULL",
        params![now],
    )?;
    conn.execute(
        "DELETE FROM handle_cooldowns WHERE until < ?1",
        params![now],
    )?;
    conn.execute(
        "DELETE FROM auth_logins WHERE expires_at < ?1 OR consumed_at IS NOT NULL",
        params![now],
    )?;
    conn.execute(
        "DELETE FROM auth_tokens WHERE expires_at < ?1 OR consumed_at IS NOT NULL",
        params![now],
    )?;
    conn.execute(
        "DELETE FROM registry_operations WHERE expires_at < ?1 OR consumed_at IS NOT NULL",
        params![now],
    )?;
    conn.execute(
        "DELETE FROM rate_buckets WHERE window_start < ?1",
        params![now.saturating_sub(RATE_WINDOW_SECS * 2)],
    )?;
    conn.execute(
        "DELETE FROM signup_counters WHERE window_start < ?1",
        params![now.saturating_sub(ACCOUNT_CREATION_WINDOW_SECS * 2)],
    )?;
    Ok(())
}

fn account_exists(conn: &Connection, handle: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM accounts WHERE handle = ?1",
            params![handle],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn pending_registration_exists_for_handle(conn: &Connection, handle: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM pending_registrations WHERE handle = ?1 AND expires_at >= ?2",
            params![handle, now_secs()],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn ensure_handle_not_cooling_down(conn: &Connection, handle: &str) -> Result<()> {
    let cooling_down = conn
        .query_row(
            "SELECT 1 FROM handle_cooldowns WHERE handle = ?1 AND until >= ?2",
            params![handle, now_secs()],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if cooling_down {
        return Err(conflict("account unavailable"));
    }
    Ok(())
}

fn ensure_pending_registration_capacity(conn: &Connection) -> Result<()> {
    let pending: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pending_registrations WHERE expires_at >= ?1",
        params![now_secs()],
        |row| row.get(0),
    )?;
    if pending >= MAX_PENDING_REGISTRATIONS {
        return Err(rate_limited());
    }
    Ok(())
}

fn claim_creation_grant(conn: &Connection, grant: &str, handle: &str) -> Result<()> {
    let grant_hash = hash_token(grant);
    let now = now_secs();
    let rows = conn.execute(
        "UPDATE creation_grants
         SET consumed_at = ?1
         WHERE grant_hash = ?2
           AND consumed_at IS NULL
           AND expires_at >= ?1
           AND (handle IS NULL OR handle = ?3)",
        params![now, grant_hash, handle],
    )?;
    ensure_one_row_kind(
        rows,
        RegistryErrorKind::AuthenticationFailed,
        "creation grant is invalid",
    )
}

fn increment_signup_counter(conn: &Connection, now: i64) -> Result<()> {
    let window_start = now - now.rem_euclid(ACCOUNT_CREATION_WINDOW_SECS);
    let existing: Option<i64> = conn
        .query_row(
            "SELECT count FROM signup_counters
             WHERE action = 'account-create' AND bucket = 'global' AND window_start = ?1",
            params![window_start],
            |row| row.get(0),
        )
        .optional()?;
    match existing {
        Some(count) if count >= ACCOUNT_CREATION_WINDOW_LIMIT => Err(rate_limited()),
        Some(_) => {
            let rows = conn.execute(
                "UPDATE signup_counters
                 SET count = count + 1, updated_at = ?1
                 WHERE action = 'account-create'
                   AND bucket = 'global'
                   AND window_start = ?2
                   AND count < ?3",
                params![now, window_start, ACCOUNT_CREATION_WINDOW_LIMIT],
            )?;
            ensure_one_row_kind(rows, RegistryErrorKind::RateLimited, "rate limited")
        }
        None => {
            conn.execute(
                "INSERT INTO signup_counters
                 (action, bucket, window_start, count, updated_at)
                 VALUES ('account-create', 'global', ?1, 1, ?2)",
                params![window_start, now],
            )?;
            Ok(())
        }
    }
}

fn load_pending_registration(
    conn: &Connection,
    registration_id: &str,
) -> Result<Option<PendingRegistration>> {
    conn.query_row(
        "SELECT account_id, handle FROM pending_registrations
         WHERE registration_id = ?1 AND expires_at >= ?2",
        params![registration_id, now_secs()],
        |row| {
            Ok(PendingRegistration {
                account_id: row.get(0)?,
                handle: row.get(1)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn load_account_by_handle(conn: &Connection, handle: &str) -> Result<Option<AccountRow>> {
    load_account(conn, "handle", handle)
}

fn load_account_by_id(conn: &Connection, account_id: &str) -> Result<Option<AccountRow>> {
    load_account(conn, "account_id", account_id)
}

fn load_account(conn: &Connection, column: &str, value: &str) -> Result<Option<AccountRow>> {
    let sql = format!(
        "SELECT account_id, handle, wallet_public, recovery_revision, opaque_password_file,
                wallet_backup, signed_record, signed_record_seq
         FROM accounts WHERE {column} = ?1 AND state = 'active'"
    );
    conn.query_row(&sql, params![value], |row| {
        let recovery_revision_i64: i64 = row.get(3)?;
        let wallet_backup_json: String = row.get(5)?;
        let wallet_backup = serde_json::from_str(&wallet_backup_json).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(err))
        })?;
        Ok(AccountRow {
            account_id: row.get(0)?,
            handle: row.get(1)?,
            wallet_public: row.get(2)?,
            recovery_revision: recovery_revision_i64 as u64,
            opaque_password_file: row.get(4)?,
            wallet_backup,
            signed_record: row.get(6)?,
            signed_record_seq: row.get(7)?,
        })
    })
    .optional()
    .map_err(Into::into)
}

fn load_login(conn: &Connection, login_id: &str, handle: &str) -> Result<Option<LoginRow>> {
    conn.query_row(
        "SELECT account_id, handle, purpose, operation_hash, server_login_state, expires_at
         FROM auth_logins WHERE login_id = ?1 AND handle = ?2",
        params![login_id, handle],
        |row| {
            Ok(LoginRow {
                account_id: row.get(0)?,
                handle: row.get(1)?,
                purpose: parse_purpose(row.get::<_, String>(2)?)?,
                operation_hash: row.get(3)?,
                server_login_state: row.get(4)?,
                expires_at: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn claim_login(conn: &Connection, login_id: &str, handle: &str) -> Result<LoginRow> {
    let tx = conn.unchecked_transaction()?;
    prune_ephemeral(&tx)?;
    let login = load_login(&tx, login_id, handle)?.ok_or_else(authentication_failed)?;
    let rows = tx.execute(
        "UPDATE auth_logins
         SET consumed_at = ?1
         WHERE login_id = ?2
           AND handle = ?3
           AND consumed_at IS NULL",
        params![now_secs(), login_id, handle],
    )?;
    ensure_one_row_kind(
        rows,
        RegistryErrorKind::AuthenticationFailed,
        "authentication failed",
    )?;
    tx.commit()?;
    if login.expires_at < now_secs() {
        return Err(authentication_failed());
    }
    Ok(login)
}

fn claim_auth(
    conn: &Connection,
    token: &str,
    purpose: AuthPurpose,
    operation_hash: Option<&str>,
) -> Result<AuthRow> {
    let row = claim_auth_row(conn, token)?;
    if row.4 < now_secs() || row.2 != purpose.as_str() || row.3.as_deref() != operation_hash {
        return Err(authentication_failed());
    }
    Ok(AuthRow {
        account_id: row.0,
        handle: row.1,
        operation_hash: row.3,
    })
}

fn claim_auth_for_purpose(conn: &Connection, token: &str, purpose: AuthPurpose) -> Result<AuthRow> {
    let row = claim_auth_row(conn, token)?;
    if row.4 < now_secs() || row.2 != purpose.as_str() {
        return Err(authentication_failed());
    }
    Ok(AuthRow {
        account_id: row.0,
        handle: row.1,
        operation_hash: row.3,
    })
}

fn claim_auth_row(
    conn: &Connection,
    token: &str,
) -> Result<(String, String, String, Option<String>, i64)> {
    let tx = conn.unchecked_transaction()?;
    prune_ephemeral(&tx)?;
    let token_hash = hash_token(token);
    let row = tx
        .query_row(
            "SELECT account_id, handle, purpose, operation_hash, expires_at
             FROM auth_tokens
             WHERE token_hash = ?1
               AND consumed_at IS NULL",
            params![token_hash],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(authentication_failed)?;
    let rows = tx.execute(
        "UPDATE auth_tokens
         SET consumed_at = ?1
         WHERE token_hash = ?2
           AND consumed_at IS NULL",
        params![now_secs(), token_hash],
    )?;
    ensure_one_row_kind(
        rows,
        RegistryErrorKind::AuthenticationFailed,
        "authentication failed",
    )?;
    tx.commit()?;
    Ok(row)
}

fn claim_operation(
    conn: &Connection,
    operation_id: &str,
    operation_token: &str,
    purpose: AuthPurpose,
) -> Result<OperationRow> {
    let tx = conn.unchecked_transaction()?;
    prune_ephemeral(&tx)?;
    let token_hash = hash_token(operation_token);
    let row = tx
        .query_row(
            "SELECT account_id, handle, expected_recovery_revision, expires_at
             FROM registry_operations
             WHERE operation_id = ?1
               AND operation_token_hash = ?2
               AND purpose = ?3
               AND consumed_at IS NULL",
            params![operation_id, token_hash, purpose.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| conflict("operation expired"))?;
    tx.execute(
        "UPDATE registry_operations
         SET consumed_at = ?1
         WHERE operation_id = ?2
           AND operation_token_hash = ?3
           AND consumed_at IS NULL",
        params![now_secs(), operation_id, token_hash],
    )
    .map_err(Into::<anyhow::Error>::into)
    .and_then(|rows| {
        ensure_one_row_kind(rows, RegistryErrorKind::Conflict, "operation expired")?;
        Ok(())
    })?;
    tx.commit()?;
    if row.3 < now_secs() {
        return Err(conflict("operation expired"));
    }
    Ok(OperationRow {
        account_id: row.0,
        handle: row.1,
        expected_recovery_revision: row.2.map(|value| value as u64),
    })
}

fn allow_request(conn: &Connection, peer: &str, limits: &[RateLimit]) -> Result<()> {
    let tx = conn.unchecked_transaction()?;
    prune_ephemeral(&tx)?;
    let now = now_secs();
    let window_start = now - now.rem_euclid(RATE_WINDOW_SECS);

    for limit in limits {
        apply_rate_limit(&tx, peer, limit, window_start, now)?;
    }

    tx.commit()?;
    Ok(())
}

fn apply_rate_limit(
    conn: &Connection,
    peer: &str,
    limit: &RateLimit,
    window_start: i64,
    now: i64,
) -> Result<()> {
    let existing: Option<i64> = conn
        .query_row(
            "SELECT count FROM rate_buckets
             WHERE peer = ?1 AND action = ?2 AND bucket = ?3 AND window_start = ?4",
            params![peer, limit.action, limit.bucket.as_str(), window_start],
            |row| row.get(0),
        )
        .optional()?;
    match existing {
        Some(count) if count >= limit.limit => return Err(rate_limited()),
        Some(_) => {
            let rows = conn.execute(
                "UPDATE rate_buckets
                 SET count = count + 1, updated_at = ?1
                 WHERE peer = ?2 AND action = ?3 AND bucket = ?4 AND window_start = ?5
                   AND count < ?6",
                params![
                    now,
                    peer,
                    limit.action,
                    limit.bucket.as_str(),
                    window_start,
                    limit.limit
                ],
            )?;
            ensure_one_row_kind(rows, RegistryErrorKind::RateLimited, "rate limited")?;
        }
        None => {
            conn.execute(
                "INSERT INTO rate_buckets
                 (peer, action, bucket, window_start, count, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)",
                params![peer, limit.action, limit.bucket.as_str(), window_start, now],
            )?;
        }
    }
    Ok(())
}

fn ensure_one_row(rows: usize, message: &str) -> Result<()> {
    ensure_one_row_kind(rows, RegistryErrorKind::Conflict, message)
}

fn ensure_one_row_kind(rows: usize, kind: RegistryErrorKind, message: &str) -> Result<()> {
    if rows != 1 {
        return Err(registry_error(kind, message));
    }
    Ok(())
}

fn classify_registry_request(method: &Method, uri: &Uri) -> ClassifiedRequest {
    let path = uri.path();
    if uri.query().is_some() || path.contains('%') {
        return ClassifiedRequest::error(RegistryErrorKind::InvalidRequest);
    }
    match path {
        "/v2/accounts/registration/start" => post_route(
            method,
            RegistryRoute::RegistrationStart,
            "registration-start",
            10,
        ),
        "/v2/accounts" => post_route(method, RegistryRoute::Create, "create", 5),
        "/v2/accounts/auth/start" => post_route(method, RegistryRoute::AuthStart, "auth-start", 30),
        "/v2/accounts/auth/finish" => {
            post_route(method, RegistryRoute::AuthFinish, "auth-finish", 30)
        }
        "/v2/accounts/recover" => post_route(method, RegistryRoute::Recover, "recover", 10),
        "/v2/accounts/record" => post_route(method, RegistryRoute::Record, "record", 20),
        "/v2/accounts/wallet/rotate" => {
            post_route(method, RegistryRoute::WalletRotate, "wallet-rotate", 5)
        }
        "/v2/accounts/recovery/registration/start" => post_route(
            method,
            RegistryRoute::RecoveryRegistrationStart,
            "recovery-rotation-start",
            5,
        ),
        "/v2/accounts/recovery/registration/finish" => post_route(
            method,
            RegistryRoute::RecoveryRegistrationFinish,
            "recovery-rotation-finish",
            5,
        ),
        path if path.starts_with("/v2/accounts/") => lookup_route(method, path),
        _ => ClassifiedRequest::error(RegistryErrorKind::NotFound),
    }
}

fn post_route(
    method: &Method,
    route: RegistryRoute,
    action: &'static str,
    limit: i64,
) -> ClassifiedRequest {
    if method != Method::POST {
        return ClassifiedRequest::error(RegistryErrorKind::MethodNotAllowed);
    }
    ClassifiedRequest::new(route, vec![RateLimit::new(action, "*", limit)])
}

fn lookup_route(method: &Method, path: &str) -> ClassifiedRequest {
    if method != Method::GET {
        return ClassifiedRequest::error(RegistryErrorKind::MethodNotAllowed);
    }
    let Some(handle) = path.strip_prefix("/v2/accounts/") else {
        return ClassifiedRequest::error(RegistryErrorKind::NotFound);
    };
    if handle.is_empty() || handle.contains('/') {
        return ClassifiedRequest::error(RegistryErrorKind::InvalidRequest);
    }
    let Ok(handle) = Handle::new(handle.to_string()) else {
        return ClassifiedRequest::error(RegistryErrorKind::InvalidRequest);
    };
    ClassifiedRequest::new(
        RegistryRoute::Lookup {
            handle: handle.as_str().to_string(),
        },
        lookup_rate_limits(handle.as_str()),
    )
}

fn lookup_rate_limits(handle: &str) -> Vec<RateLimit> {
    let mut limits = vec![RateLimit::new("lookup", "*", LOOKUP_AGGREGATE_LIMIT)];
    limits.push(RateLimit::new(
        "lookup-handle",
        lookup_bucket(handle),
        LOOKUP_HANDLE_LIMIT,
    ));
    limits
}

fn lookup_bucket(handle: &str) -> String {
    hash_parts(&[
        b"mycellium-registry-lookup-rate-bucket-v1".as_slice(),
        handle.as_bytes(),
    ])
}

fn fallback_rate_limit() -> RateLimit {
    RateLimit::new("all", "*", 240)
}

fn load_or_create_server_setup(
    conn: &Connection,
    server_secret: &[u8],
) -> Result<ServerSetup<MycelliumOpaque>> {
    if let Some(sealed) = conn
        .query_row(
            "SELECT value FROM registry_meta WHERE key = ?1",
            params![OPAQUE_SETUP_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        let bytes = open_server_secret_blob(server_secret, OPAQUE_SETUP_SEAL_DOMAIN, &sealed)?;
        return ServerSetup::<MycelliumOpaque>::deserialize(bytes.as_slice())
            .map_err(|_| anyhow!("could not open opaque server setup"));
    }
    let mut rng = OsRng;
    let setup = ServerSetup::<MycelliumOpaque>::new(&mut rng);
    let sealed = seal_server_secret_blob(
        server_secret,
        OPAQUE_SETUP_SEAL_DOMAIN,
        setup.serialize().as_slice(),
    )?;
    conn.execute(
        "INSERT INTO registry_meta (key, value) VALUES (?1, ?2)",
        params![OPAQUE_SETUP_KEY, sealed],
    )?;
    Ok(setup)
}

fn seal_server_secret_blob(
    server_secret: &[u8],
    domain: &[u8],
    plaintext: &[u8],
) -> Result<String> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).context("could not gather randomness")?;
    let key = server_secret_key(server_secret, domain);
    let ciphertext = ChaCha20Poly1305::new(&key)
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: domain,
            },
        )
        .map_err(|_| anyhow!("could not seal registry secret"))?;
    Ok(format!("{}:{}", hex(&nonce), hex(&ciphertext)))
}

fn open_server_secret_blob(
    server_secret: &[u8],
    domain: &[u8],
    sealed: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let (nonce, ciphertext) = sealed
        .split_once(':')
        .ok_or_else(|| anyhow!("bad sealed registry secret"))?;
    let nonce = decode_fixed::<12>(nonce, "registry secret nonce")?;
    let ciphertext = from_hex(ciphertext)?;
    let key = server_secret_key(server_secret, domain);
    ChaCha20Poly1305::new(&key)
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: domain,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("could not open registry secret"))
}

fn server_secret_key(server_secret: &[u8], domain: &[u8]) -> Key {
    let hk = Hkdf::<Sha256>::new(Some(domain), server_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"registry-server-secret-aead", key.as_mut())
        .expect("32 is a valid HKDF-SHA256 output length");
    Key::clone_from_slice(key.as_slice())
}

fn backup_key(export_key: &[u8], aad: &[u8]) -> Result<Key> {
    let hk = Hkdf::<Sha256>::new(Some(BACKUP_PURPOSE.as_bytes()), export_key);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(aad, key.as_mut())
        .map_err(|_| anyhow!("could not derive backup key"))?;
    Ok(Key::clone_from_slice(key.as_slice()))
}

fn backup_aad(envelope: &WalletBackupEnvelope) -> Result<Vec<u8>> {
    let mut aad = envelope.clone();
    aad.nonce.clear();
    aad.ciphertext.clear();
    serde_json::to_vec(&aad).context("could not encode backup metadata")
}

fn validate_backup_for_account(
    envelope: &WalletBackupEnvelope,
    expected: &WalletBackupEnvelope,
) -> Result<()> {
    validate_backup_metadata(envelope)?;
    if envelope.version != expected.version
        || envelope.purpose != expected.purpose
        || envelope.account_id != expected.account_id
        || envelope.handle != expected.handle
        || envelope.wallet_public != expected.wallet_public
        || envelope.recovery_revision != expected.recovery_revision
        || envelope.kdf != expected.kdf
    {
        return Err(invalid_request("wallet backup metadata mismatch"));
    }
    if envelope.nonce.is_empty() || envelope.ciphertext.is_empty() {
        return Err(invalid_request("wallet backup is incomplete"));
    }
    input_fixed_hex::<12>(&envelope.nonce, "backup nonce")?;
    let _ = input_hex(&envelope.ciphertext, "backup ciphertext")?;
    Ok(())
}

fn validate_backup_metadata(envelope: &WalletBackupEnvelope) -> Result<()> {
    if envelope.version != 2
        || envelope.purpose != BACKUP_PURPOSE
        || envelope.kdf != "opaque-export-key-hkdf-sha256"
    {
        return Err(invalid_request("unsupported wallet backup envelope"));
    }
    validate_handle(&envelope.handle)?;
    if envelope.account_id.len() != 64 || input_hex(&envelope.account_id, "account id").is_err() {
        return Err(invalid_request("wallet backup account id is invalid"));
    }
    if envelope.wallet_public.len() != 66
        || input_hex(&envelope.wallet_public, "wallet public key").is_err()
    {
        return Err(invalid_request(
            "wallet backup wallet public key is invalid",
        ));
    }
    if envelope.recovery_revision == 0 {
        return Err(invalid_request(
            "wallet backup recovery revision is invalid",
        ));
    }
    Ok(())
}

fn validate_record(handle: &str, record: &SignedRecord) -> Result<()> {
    record
        .verify()
        .map_err(|_| invalid_request("signed record failed verification"))?;
    if record.record.devices.iter().any(|d| d.peer_id.0.is_empty()) {
        return Err(invalid_request(
            "signed record contains an empty device address",
        ));
    }
    if record.record.handle != user_id(handle) {
        return Err(invalid_request(format!(
            "signed record does not belong to '{handle}'"
        )));
    }
    if record.record.name != handle {
        return Err(invalid_request(
            "signed record handle/display binding mismatch",
        ));
    }
    Ok(())
}

fn checked_seq(seq: u64) -> Result<i64> {
    i64::try_from(seq).map_err(|_| invalid_request("signed record sequence is too large"))
}

fn validate_handle(handle: &str) -> Result<Handle> {
    Handle::new(handle.to_string()).map_err(|_| invalid_request("invalid handle"))
}

pub fn validate_recovery_secret(secret: &str) -> Result<()> {
    if secret.trim() != secret {
        bail!("recovery secret must not contain surrounding whitespace");
    }
    validate_recovery_secret_value(secret)
}

fn validate_recovery_secret_value(secret: &str) -> Result<()> {
    let Some(hex_secret) = secret.strip_prefix(RECOVERY_SECRET_PREFIX) else {
        bail!("recovery secret must be generated by mycellium");
    };
    if hex_secret.len() != RECOVERY_SECRET_BYTES * 2 || !hex_secret.is_ascii() {
        bail!("recovery secret is malformed");
    }
    let bytes = from_hex(hex_secret).map_err(|_| anyhow!("recovery secret is malformed"))?;
    if bytes.len() != RECOVERY_SECRET_BYTES {
        bail!("recovery secret is malformed");
    }
    validate_secret_diversity(&bytes, "recovery secret")?;
    Ok(())
}

pub fn generate_recovery_secret() -> Result<RecoverySecret> {
    RecoverySecret::generate()
}

fn validate_operation_binding(purpose: &AuthPurpose, operation_hash: Option<&str>) -> Result<()> {
    match purpose {
        AuthPurpose::PublishRecord | AuthPurpose::RotateWallet => {
            let Some(hash) = operation_hash else {
                return Err(invalid_request("operation hash is required"));
            };
            if hash.len() != 64 || input_hex(hash, "operation hash").is_err() {
                return Err(invalid_request("operation hash is invalid"));
            }
        }
        AuthPurpose::Recover | AuthPurpose::RotateRecovery => {
            if operation_hash.is_some() {
                return Err(invalid_request(
                    "operation hash is not used for this purpose",
                ));
            }
        }
    }
    Ok(())
}

fn registration_finish_params(
    handle: &str,
) -> ClientRegistrationFinishParameters<'_, '_, MycelliumOpaque> {
    ClientRegistrationFinishParameters::new(
        Identifiers {
            client: Some(handle.as_bytes()),
            server: Some(SERVER_ID),
        },
        None,
    )
}

fn server_login_params<'a>(handle: &'a str, context: &'a [u8]) -> ServerLoginParameters<'a, 'a> {
    ServerLoginParameters {
        context: Some(context),
        identifiers: Identifiers {
            client: Some(handle.as_bytes()),
            server: Some(SERVER_ID),
        },
    }
}

fn client_login_finish_params<'a>(
    handle: &'a str,
    context: &'a [u8],
) -> ClientLoginFinishParameters<'a, 'a, 'a, MycelliumOpaque> {
    ClientLoginFinishParameters::new(
        Some(context),
        Identifiers {
            client: Some(handle.as_bytes()),
            server: Some(SERVER_ID),
        },
        None,
    )
}

fn auth_context(
    account_id: &str,
    handle: &str,
    purpose: &AuthPurpose,
    operation_hash: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"mycellium-registry-auth-v2\0");
    out.extend_from_slice(account_id.as_bytes());
    out.push(0);
    out.extend_from_slice(handle.as_bytes());
    out.push(0);
    out.extend_from_slice(purpose.as_str().as_bytes());
    out.push(0);
    if let Some(operation_hash) = operation_hash {
        out.extend_from_slice(operation_hash.as_bytes());
    }
    out
}

fn parse_purpose(value: String) -> rusqlite::Result<AuthPurpose> {
    match value.as_str() {
        "recover" => Ok(AuthPurpose::Recover),
        "publish_record" => Ok(AuthPurpose::PublishRecord),
        "rotate_recovery" => Ok(AuthPurpose::RotateRecovery),
        "rotate_wallet" => Ok(AuthPurpose::RotateWallet),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn hash_token(token: &str) -> String {
    hash_parts(&[
        b"mycellium-registry-auth-token-v2".as_slice(),
        token.as_bytes(),
    ])
}

fn rate_limit_peer_key(server_secret: &[u8], source: &[u8], value: &[u8]) -> String {
    keyed_hash_parts(
        server_secret,
        b"mycellium-registry-rate-limit-peer-v1",
        &[source, value],
    )
}

fn validate_edge_client_key(value: &header::HeaderValue) -> Result<&str> {
    let value = value
        .to_str()
        .map_err(|_| invalid_request("bad trusted edge client identity"))?;
    if value.is_empty() || value.len() > 256 {
        return Err(invalid_request(
            "trusted edge client identity must be between 1 and 256 bytes",
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b',' && byte != b';')
    {
        return Err(invalid_request(
            "trusted edge client identity contains invalid characters",
        ));
    }
    Ok(value)
}

fn secret_copy(secret: &SecretString) -> SecretString {
    Zeroizing::new(secret.as_str().to_string())
}

fn input_hex(s: &str, label: &str) -> Result<Vec<u8>> {
    from_hex(s).map_err(|_| invalid_request(format!("bad {label}")))
}

fn input_fixed_hex<const N: usize>(s: &str, label: &str) -> Result<[u8; N]> {
    let bytes = input_hex(s, label)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_request(format!("{label} has an invalid size")))
}

fn hash_parts(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    hex(&h.finalize())
}

fn keyed_hash_parts(key: &[u8], domain: &[u8], parts: &[&[u8]]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts keys of any nonzero length");
    mac.update(&(domain.len() as u64).to_be_bytes());
    mac.update(domain);
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    hex(&mac.finalize().into_bytes())
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut out = Zeroizing::new(vec![0u8; bytes]);
    getrandom::getrandom(&mut out).context("could not gather randomness")?;
    Ok(hex(&out))
}

fn random_secret_hex(bytes: usize) -> Result<SecretString> {
    Ok(Zeroizing::new(random_hex(bytes)?))
}

fn validate_server_secret(secret: &[u8]) -> Result<()> {
    if secret.len() < 32 {
        bail!("registry server secret must be at least 32 bytes");
    }
    validate_secret_diversity(secret, "registry server secret")
}

fn validate_secret_diversity(secret: &[u8], label: &str) -> Result<()> {
    let distinct = secret
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if distinct < 8 {
        bail!("{label} has insufficient byte diversity");
    }
    Ok(())
}

fn server_secret_from_env() -> Result<Zeroizing<Vec<u8>>> {
    let secret = Zeroizing::new(
        std::env::var(SERVER_SECRET_ENV)
            .with_context(|| format!("{SERVER_SECRET_ENV} must be set for the registry"))?,
    );
    if secret.len() < 64 || !secret.len().is_multiple_of(2) {
        bail!(
            "{SERVER_SECRET_ENV} must be at least 64 hex characters from a random 32-byte secret"
        );
    }
    if !secret.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("{SERVER_SECRET_ENV} must be hex; generate it with: openssl rand -hex 32");
    }
    let bytes = Zeroizing::new(from_hex(&secret)?);
    validate_server_secret(&bytes)?;
    Ok(bytes)
}

struct RegistryPaths {
    data_dir: PathBuf,
    db_path: PathBuf,
}

impl RegistryPaths {
    fn prepare(data_dir: &Path) -> Result<Self> {
        ensure_supported_storage_platform()?;
        let data_dir = normalize_data_dir(data_dir)?;
        let leaf_existed = prepare_data_dir(&data_dir)?;
        ensure_registry_marker(&data_dir, leaf_existed)?;
        set_private_dir(&data_dir)?;
        verify_private_dir(&data_dir)?;
        let db_path = data_dir.join(REGISTRY_DB_FILE);
        harden_sqlite_sidecars(&db_path)?;
        if std::fs::symlink_metadata(&db_path)
            .is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound)
        {
            create_private_file(&db_path)?;
        }
        harden_required_private_file(&db_path, "registry database file")?;
        Ok(Self { data_dir, db_path })
    }
}

fn harden_sqlite_files(path: &Path) -> Result<()> {
    harden_required_private_file(path, "registry database file")?;
    harden_sqlite_sidecars(path)
}

fn prepare_data_dir(data_dir: &Path) -> Result<bool> {
    reject_unsafe_data_dir_leaf(data_dir)?;
    let mut current = PathBuf::new();
    let mut components = data_dir.components().peekable();
    let mut leaf_existed = false;
    while let Some(component) = components.next() {
        current.push(component.as_os_str());
        if current.as_os_str().is_empty() {
            continue;
        }
        let is_leaf = components.peek().is_none();
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if is_leaf {
                    verify_data_dir_leaf(&current, &metadata)?;
                    verify_effective_owner(&current, "registry data directory", &metadata)?;
                    leaf_existed = true;
                } else {
                    verify_safe_ancestor_dir(&current, &metadata)?;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                create_private_dir(&current)?;
                set_private_dir(&current)?;
                verify_private_dir(&current)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(leaf_existed)
}

fn harden_sqlite_sidecars(path: &Path) -> Result<()> {
    for suffix in ["wal", "shm"] {
        let sidecar = sqlite_sidecar_path(path, suffix);
        harden_optional_private_file(&sidecar, "registry sqlite sidecar")?;
    }
    Ok(())
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(format!("-{suffix}"));
    PathBuf::from(sidecar)
}

fn normalize_data_dir(path: &Path) -> Result<PathBuf> {
    if path == Path::new(":memory:") {
        let dir = format!("mycellium-registry-test-{}", random_hex(16)?);
        return Ok(std::env::temp_dir().join(dir));
    }
    let path = normalize_registry_path_components(path, "registry data directory")?;
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(std::env::current_dir()?.join(path))
}

fn normalize_registry_path_components(path: &Path, label: &str) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                bail!("{label} must not contain parent directory components")
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str())
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        bail!("{label} is required");
    }
    Ok(normalized)
}

fn registry_socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join(REGISTRY_SOCKET_FILE)
}

fn reject_unsafe_data_dir_leaf(path: &Path) -> Result<()> {
    let rejected = [
        Path::new("/"),
        Path::new("/tmp"),
        Path::new("/var/tmp"),
        Path::new("/dev"),
        Path::new("/proc"),
        Path::new("/sys"),
        Path::new("/run"),
        Path::new("/var"),
        Path::new("/var/lib"),
        Path::new("/usr"),
        Path::new("/etc"),
        Path::new("/home"),
    ];
    if rejected.contains(&path) {
        bail!(
            "registry data directory '{}' must be a dedicated registry directory",
            path.display()
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        if path == Path::new(&home) {
            bail!(
                "registry data directory '{}' must not be the account home directory",
                path.display()
            );
        }
    }
    Ok(())
}

fn ensure_registry_marker(data_dir: &Path, leaf_existed: bool) -> Result<()> {
    let marker = data_dir.join(REGISTRY_DIR_MARKER);
    match std::fs::symlink_metadata(&marker) {
        Ok(metadata) => {
            verify_regular_file_metadata(&marker, "registry directory marker", &metadata)?;
            set_private_file(&marker)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && !leaf_existed => {
            create_private_marker(&marker)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "existing registry data directory '{}' is missing the registry marker",
                data_dir.display()
            )
        }
        Err(err) => Err(err.into()),
    }
}

fn create_private_marker(path: &Path) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(b"mycellium-registry\n")?;
    Ok(())
}

fn create_private_file(path: &Path) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let _file = options.open(path)?;
    Ok(())
}

fn harden_required_private_file(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    verify_regular_file_metadata(path, label, &metadata)?;
    set_private_file(path)
}

fn harden_optional_private_file(path: &Path, label: &str) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            verify_regular_file_metadata(path, label, &metadata)?;
            set_private_file(path)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn verify_regular_file_metadata(
    path: &Path,
    label: &str,
    metadata: &std::fs::Metadata,
) -> Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        bail!("{label} '{}' must not be a symlink", path.display());
    }
    if !file_type.is_file() {
        bail!("{label} '{}' must be a regular file", path.display());
    }
    verify_effective_owner(path, label, metadata)?;
    verify_single_link(path, label, metadata)?;
    Ok(())
}

fn verify_data_dir_leaf(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        bail!(
            "registry data directory '{}' must not be a symlink",
            path.display()
        );
    }
    if !file_type.is_dir() {
        bail!(
            "registry data directory '{}' must be a directory",
            path.display()
        );
    }
    Ok(())
}

fn verify_safe_ancestor_dir(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        bail!(
            "registry data directory ancestor '{}' must not be a symlink",
            path.display()
        );
    }
    if !file_type.is_dir() {
        bail!(
            "registry data directory ancestor '{}' must be a directory",
            path.display()
        );
    }
    verify_ancestor_permissions(path, metadata)
}

#[cfg(unix)]
fn ensure_supported_storage_platform() -> Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_supported_storage_platform() -> Result<()> {
    bail!("registry persistent storage requires Unix ownership and permission enforcement")
}

#[cfg(unix)]
fn verify_effective_owner(path: &Path, label: &str, metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let expected_uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != expected_uid {
        bail!(
            "{label} '{}' must be owned by the effective registry uid",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_effective_owner(_path: &Path, _label: &str, _metadata: &std::fs::Metadata) -> Result<()> {
    ensure_supported_storage_platform()
}

#[cfg(unix)]
fn verify_single_link(path: &Path, label: &str, metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if metadata.nlink() != 1 {
        bail!("{label} '{}' must not be hard-linked", path.display());
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_single_link(_path: &Path, _label: &str, _metadata: &std::fs::Metadata) -> Result<()> {
    ensure_supported_storage_platform()
}

#[cfg(unix)]
fn prepare_unix_socket_path(path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                bail!("registry socket '{}' must not be a symlink", path.display());
            }
            if !file_type.is_socket() {
                bail!(
                    "registry socket '{}' already exists and is not a socket",
                    path.display()
                );
            }
            verify_effective_owner(path, "registry socket", &metadata)?;
            std::fs::remove_file(path)?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn verify_ancestor_permissions(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mode = metadata.permissions().mode();
    if mode & 0o022 == 0 {
        return Ok(());
    }
    let sticky = mode & 0o1000 != 0;
    let root_owned = metadata.uid() == 0;
    if sticky && root_owned {
        return Ok(());
    }
    bail!(
        "registry data directory ancestor '{}' must not be group/world writable",
        path.display()
    )
}

#[cfg(not(unix))]
fn verify_ancestor_permissions(_path: &Path, _metadata: &std::fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn verify_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if path.as_os_str().is_empty() || path == Path::new(":memory:") {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(path)?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        bail!(
            "registry database directory '{}' must not be a symlink",
            path.display()
        );
    }
    if !file_type.is_dir() {
        bail!(
            "registry database directory '{}' must be a directory",
            path.display()
        );
    }
    verify_effective_owner(path, "registry database directory", &metadata)?;
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "registry database directory '{}' must not be group/world accessible",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_dir(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path == Path::new(":memory:") {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(path)?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        bail!(
            "registry database directory '{}' must not be a symlink",
            path.display()
        );
    }
    if !file_type.is_dir() {
        bail!(
            "registry database directory '{}' must be a directory",
            path.display()
        );
    }
    Ok(())
}

fn is_unique_violation(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(code, _)
            if code.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "::1"))
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble(b >> 4));
        out.push(nibble(b & 0x0f));
    }
    out
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        bail!("hex string has an odd length");
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn decode_fixed<const N: usize>(s: &str, label: &str) -> Result<[u8; N]> {
    let bytes = from_hex(s).map_err(|_| anyhow!("bad {label}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{label} has an invalid size"))
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("invalid hex"),
    }
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycellium_core::identity::Identity;
    use mycellium_core::platform::Platform;
    use mycellium_core::record::{Device, Record, SignedPreKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    const TEST_SECRET: &[u8] = b"test registry server secret has enough entropy";
    const RECOVERY: &str =
        "myc-r1-000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const NEXT_RECOVERY: &str =
        "myc-r1-202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    struct TestPlatform;

    impl Platform for TestPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(23).wrapping_add(5);
            }
        }

        fn now_unix_secs(&self) -> u64 {
            10
        }
    }

    struct OffsetPlatform(u8);

    impl Platform for OffsetPlatform {
        fn fill_random(&mut self, buf: &mut [u8]) {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(19).wrapping_add(self.0);
            }
            self.0 = self.0.wrapping_add(41);
        }

        fn now_unix_secs(&self) -> u64 {
            10
        }
    }

    fn signed_record_for_identity(
        handle: &str,
        seq: u64,
        identity: &Identity,
        peer_id: Vec<u8>,
    ) -> String {
        let record = Record {
            handle: user_id(handle),
            name: handle.to_string(),
            wallet: identity.wallet_public(),
            devices: vec![Device {
                device_key: identity.device_public(),
                peer_id: mycellium_core::identity::PeerId(peer_id),
                id_key: identity.messaging_public(),
                signed_pre_key: SignedPreKey::create(identity.signed_pre_key_public(), identity),
            }],
            seq,
        };
        hex(&wire::encode(&SignedRecord::sign(record, identity)))
    }

    fn signed_record_with_name(handle: &str, name: &str, seq: u64, identity: &Identity) -> String {
        let record = Record {
            handle: user_id(handle),
            name: name.to_string(),
            wallet: identity.wallet_public(),
            devices: vec![Device {
                device_key: identity.device_public(),
                peer_id: mycellium_core::identity::PeerId(b"127.0.0.1:9001".to_vec()),
                id_key: identity.messaging_public(),
                signed_pre_key: SignedPreKey::create(identity.signed_pre_key_public(), identity),
            }],
            seq,
        };
        hex(&wire::encode(&SignedRecord::sign(record, identity)))
    }

    fn create_req_for_store(
        store: &AccountStore,
        handle: &str,
        secret: &str,
        identity: &Identity,
    ) -> AccountCreateRequest {
        let secret = RecoverySecret::parse(secret.to_string()).unwrap();
        let (state, response) = registration_for_store(store, handle, &secret);
        let wallet_public = hex(&identity.wallet_public().0);
        let (registration_upload, wallet_backup) = account_registration_finish(
            state,
            &response,
            &secret,
            &wallet_public,
            &identity.wallet_secret(),
        )
        .unwrap();
        AccountCreateRequest {
            account_id: response.account_id,
            handle: handle.to_string(),
            registration_id: response.registration_id,
            registration_upload,
            wallet_backup,
            signed_record: signed_record_for_identity(
                handle,
                1,
                identity,
                b"127.0.0.1:9001".to_vec(),
            ),
        }
    }

    fn registration_for_store(
        store: &AccountStore,
        handle: &str,
        secret: &RecoverySecret,
    ) -> (RegistrationClientState, AccountRegistrationStartResponse) {
        let mut rng = OsRng;
        let start =
            ClientRegistration::<MycelliumOpaque>::start(&mut rng, secret.as_bytes()).unwrap();
        let creation_grant = store.issue_creation_grant(Some(handle), None).unwrap();
        let response = store
            .start_registration(AccountRegistrationStartRequest {
                handle: handle.into(),
                registration_request: hex(start.message.serialize().as_slice()),
                creation_grant,
            })
            .unwrap();
        let state = RegistrationClientState {
            handle: handle.to_string(),
            account_id: response.account_id.clone(),
            registration_id: response.registration_id.clone(),
            state: start.state,
        };
        (state, response)
    }

    fn auth_for(
        store: &AccountStore,
        handle: &str,
        secret: &str,
        purpose: AuthPurpose,
        operation_hash: Option<String>,
    ) -> AccountAuthToken {
        auth_with_export(store, handle, secret, purpose, operation_hash).0
    }

    fn auth_with_export(
        store: &AccountStore,
        handle: &str,
        secret: &str,
        purpose: AuthPurpose,
        operation_hash: Option<String>,
    ) -> (AccountAuthToken, OpaqueExportKey) {
        try_auth_with_export(store, handle, secret, purpose, operation_hash).unwrap()
    }

    fn try_auth_with_export(
        store: &AccountStore,
        handle: &str,
        secret: &str,
        purpose: AuthPurpose,
        operation_hash: Option<String>,
    ) -> Result<(AccountAuthToken, OpaqueExportKey)> {
        let secret = RecoverySecret::parse(secret.to_string())?;
        let mut rng = OsRng;
        let start = ClientLogin::<MycelliumOpaque>::start(&mut rng, secret.as_bytes()).unwrap();
        let response = store.start_auth(AccountAuthStartRequest {
            handle: handle.into(),
            purpose: purpose.clone(),
            operation_hash: operation_hash.clone(),
            credential_request: hex(start.message.serialize().as_slice()),
        })?;
        let account_id = response.account_id.clone();
        let credential_response = CredentialResponse::<MycelliumOpaque>::deserialize(&from_hex(
            &response.credential_response,
        )?)
        .map_err(|_| anyhow!("bad credential response"))?;
        let context = auth_context(&account_id, handle, &purpose, operation_hash.as_deref());
        let finish = start
            .state
            .finish(
                &mut rng,
                secret.as_bytes(),
                credential_response,
                client_login_finish_params(handle, &context),
            )
            .map_err(|_| anyhow!("client login failed"))?;
        let token = store.finish_auth(AccountAuthFinishRequest {
            handle: handle.into(),
            login_id: response.login_id,
            credential_finalization: hex(finish.message.serialize().as_slice()),
        })?;
        Ok((
            token,
            OpaqueExportKey::new(finish.export_key.as_slice().to_vec()),
        ))
    }

    fn registry_test_app() -> (Arc<AccountStore>, Router) {
        let store = Arc::new(AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap());
        let app = registry_router(Arc::clone(&store));
        (store, app)
    }

    fn registration_start_request(
        store: &AccountStore,
        handle: &str,
        secret: &str,
    ) -> AccountRegistrationStartRequest {
        let secret = RecoverySecret::parse(secret.to_string()).unwrap();
        let mut rng = OsRng;
        let start =
            ClientRegistration::<MycelliumOpaque>::start(&mut rng, secret.as_bytes()).unwrap();
        let creation_grant = store.issue_creation_grant(Some(handle), None).unwrap();
        AccountRegistrationStartRequest {
            handle: handle.to_string(),
            registration_request: hex(start.message.serialize().as_slice()),
            creation_grant,
        }
    }

    fn json_request(method: Method, uri: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    fn allow_test_request(conn: &Connection, peer: &str, method: Method, uri: &str) -> Result<()> {
        let uri = uri.parse::<Uri>().unwrap();
        let classified = classify_registry_request(&method, &uri);
        let peer = rate_limit_peer_key(TEST_SECRET, b"tcp-ip", peer.as_bytes());
        allow_request(conn, &peer, &classified.rate_limits)
    }

    #[cfg(unix)]
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    struct TempDir {
        path: PathBuf,
    }

    #[cfg(unix)]
    impl TempDir {
        fn new(prefix: &str, mode: u32) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let path = std::env::temp_dir().join(format!(
                "{prefix}-{}-{}",
                std::process::id(),
                random_hex(8).unwrap()
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    #[cfg(unix)]
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(unix)]
    struct CurrentDirGuard {
        original: PathBuf,
    }

    #[cfg(unix)]
    impl CurrentDirGuard {
        fn enter(path: &Path) -> Self {
            let original = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self { original }
        }
    }

    #[cfg(unix)]
    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    #[cfg(unix)]
    fn file_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn test_tcp_peer_key() -> String {
        rate_limit_peer_key(TEST_SECRET, b"tcp-ip", b"127.0.0.1")
    }

    #[cfg(unix)]
    fn expect_store_open_error(result: Result<AccountStore>) -> anyhow::Error {
        match result {
            Ok(_) => panic!("registry store unexpectedly opened"),
            Err(err) => err,
        }
    }

    async fn assert_registry_error(response: Response, status: StatusCode, code: &str) {
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let body = to_bytes(response.into_body(), MAX_RESPONSE_BYTES as usize)
            .await
            .unwrap();
        let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(err.error, code);
    }

    #[test]
    fn store_round_trips_create_recover_lookup() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        let req = create_req_for_store(&store, "alice", RECOVERY, &identity);
        let created = store.create(req).unwrap();
        assert_eq!(created.handle, "alice");
        let public = store.public_record("alice").unwrap().unwrap();
        assert_eq!(public, created);

        let auth = auth_for(&store, "alice", RECOVERY, AuthPurpose::Recover, None);
        let recovered = store
            .recover(AccountRecoverRequest {
                auth_token: auth.auth_token,
            })
            .unwrap();
        assert_eq!(recovered.handle, "alice");
        assert_eq!(recovered.signed_record, created.signed_record);
    }

    #[tokio::test]
    async fn http_missing_lookup_is_typed_not_found() {
        let (_store, app) = registry_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v2/accounts/nosuchhandle")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_registry_error(response, StatusCode::NOT_FOUND, "not_found").await;
    }

    #[tokio::test]
    async fn http_method_mismatch_is_registry_error() {
        let (_store, app) = registry_test_app();
        for (method, uri) in [
            (Method::GET, "/v2/accounts"),
            (Method::PUT, "/v2/accounts/alice"),
            (Method::OPTIONS, "/v2/accounts/alice"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_registry_error(
                response,
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
            )
            .await;
        }
    }

    #[tokio::test]
    async fn http_invalid_encoded_lookup_path_is_registry_error() {
        let (_store, app) = registry_test_app();
        for uri in ["/v2/accounts/%FF", "/v2/accounts/%2F"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_registry_error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
        }
    }

    #[tokio::test]
    async fn http_head_lookup_is_method_not_allowed() {
        let (_store, app) = registry_test_app();
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::HEAD)
                    .uri("/v2/accounts/samehandle")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    #[tokio::test]
    async fn http_distinct_lookup_hits_aggregate_limit() {
        let (_store, app) = registry_test_app();
        for i in 0..LOOKUP_AGGREGATE_LIMIT {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(format!("/v2/accounts/h{i:03}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v2/accounts/h999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_registry_error(response, StatusCode::TOO_MANY_REQUESTS, "rate_limited").await;
    }

    #[tokio::test]
    async fn http_encoded_lookup_does_not_bypass_per_handle_limit() {
        let (store, app) = registry_test_app();
        for _ in 0..LOOKUP_HANDLE_LIMIT {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/v2/accounts/samehandle")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/v2/accounts/samehandle")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_registry_error(response, StatusCode::TOO_MANY_REQUESTS, "rate_limited").await;

        for uri in [
            "/v2/accounts/%73amehandle",
            "/v2/accounts/s%61mehandle",
            "/v2/accounts/samehandl%65",
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_registry_error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
        }

        store
            .with_conn(|conn| {
                let peer = test_tcp_peer_key();
                let handle_bucket_count: i64 = conn.query_row(
                    "SELECT count FROM rate_buckets
                     WHERE peer = ?1 AND action = ?2",
                    params![peer, "lookup-handle"],
                    |row| row.get(0),
                )?;
                assert_eq!(handle_bucket_count, LOOKUP_HANDLE_LIMIT);
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test]
    async fn tcp_requests_reject_trusted_edge_identity_headers() {
        let (_store, app) = registry_test_app();
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/v2/accounts/alice")
            .header(EDGE_CLIENT_KEY_HEADER, "client-a")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(RegistryConnectionPeer::Tcp(
            "127.0.0.1:9999".parse().unwrap(),
        ));

        let response = app.oneshot(request).await.unwrap();
        assert_registry_error(response, StatusCode::FORBIDDEN, "forbidden").await;
    }

    #[tokio::test]
    async fn unix_requests_require_trusted_edge_identity() {
        let (_store, app) = registry_test_app();
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/v2/accounts/alice")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(RegistryConnectionPeer::Unix);

        let response = app.oneshot(request).await.unwrap();
        assert_registry_error(response, StatusCode::FORBIDDEN, "forbidden").await;
    }

    #[tokio::test]
    async fn unix_edge_identity_produces_distinct_hashed_rate_buckets() {
        let (store, app) = registry_test_app();
        for edge_key in ["client-a", "client-b"] {
            let mut request = Request::builder()
                .method(Method::GET)
                .uri("/v2/accounts/alice")
                .header(EDGE_CLIENT_KEY_HEADER, edge_key)
                .body(Body::empty())
                .unwrap();
            request
                .extensions_mut()
                .insert(RegistryConnectionPeer::Unix);
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }

        store
            .with_conn(|conn| {
                let distinct_peers: i64 = conn.query_row(
                    "SELECT COUNT(DISTINCT peer) FROM rate_buckets WHERE action = ?1",
                    params!["lookup"],
                    |row| row.get(0),
                )?;
                assert_eq!(distinct_peers, 2);

                let plaintext_peers: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM rate_buckets WHERE peer IN (?1, ?2)",
                    params!["client-a", "client-b"],
                    |row| row.get(0),
                )?;
                assert_eq!(plaintext_peers, 0);
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test]
    async fn tcp_dev_listener_closes_incomplete_headers() {
        let (_store, app) = registry_test_app();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(run_tcp_listener(
            listener,
            app,
            std::future::pending::<()>(),
        ));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /v2/accounts/alice HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(
            Duration::from_secs(HEADER_READ_TIMEOUT_SECS + 3),
            stream.read(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(read, 0);
        server.abort();
    }

    #[tokio::test]
    async fn http_malformed_json_is_registry_error() {
        let (_store, app) = registry_test_app();
        let response = app
            .oneshot(json_request(
                Method::POST,
                "/v2/accounts/auth/start",
                b"{".to_vec(),
            ))
            .await
            .unwrap();

        assert_registry_error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
    }

    #[tokio::test]
    async fn http_oversized_json_is_registry_error() {
        let (_store, app) = registry_test_app();
        let response = app
            .oneshot(json_request(
                Method::POST,
                "/v2/accounts/auth/start",
                vec![b' '; MAX_BODY_BYTES + 1],
            ))
            .await
            .unwrap();

        assert_registry_error(response, StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large").await;
    }

    #[tokio::test]
    async fn http_duplicate_registration_start_is_typed_conflict() {
        let (store, app) = registry_test_app();
        let first =
            serde_json::to_vec(&registration_start_request(&store, "alice", RECOVERY)).unwrap();
        let second =
            serde_json::to_vec(&registration_start_request(&store, "alice", NEXT_RECOVERY))
                .unwrap();

        let first_response = app
            .clone()
            .oneshot(json_request(
                Method::POST,
                "/v2/accounts/registration/start",
                first,
            ))
            .await
            .unwrap();
        assert_eq!(first_response.status(), StatusCode::OK);
        assert_eq!(
            first_response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );

        let second_response = app
            .oneshot(json_request(
                Method::POST,
                "/v2/accounts/registration/start",
                second,
            ))
            .await
            .unwrap();

        assert_registry_error(second_response, StatusCode::CONFLICT, "conflict").await;
    }

    #[test]
    fn backup_opens_only_with_matching_metadata() {
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        let export_key = [7u8; 64];
        let metadata = wallet_backup_metadata(
            &hex(&[1u8; 32]),
            "alice",
            &hex(&identity.wallet_public().0),
            1,
        );
        let sealed =
            seal_wallet_backup(&export_key, metadata.clone(), &identity.wallet_secret()).unwrap();
        let opened = open_wallet_backup(&export_key, &sealed, &metadata).unwrap();
        assert_eq!(opened.expose_secret(), identity.wallet_secret());
        let mut wrong = metadata.clone();
        wrong.handle = "bob".into();
        assert!(open_wallet_backup(&export_key, &sealed, &wrong).is_err());
    }

    #[test]
    fn create_is_bound_to_pending_registration() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        let mut req = create_req_for_store(&store, "alice", RECOVERY, &identity);
        req.handle = "bob".into();
        let err = store.create(req).unwrap_err();
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::InvalidRequest
        );
    }

    #[test]
    fn create_rejects_display_name_that_is_not_handle() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        let mut req = create_req_for_store(&store, "alice", RECOVERY, &identity);
        req.signed_record = signed_record_with_name("alice", "Alice Display", 1, &identity);
        let err = store.create(req).unwrap_err();
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::InvalidRequest
        );
    }

    #[test]
    fn malformed_signed_record_is_invalid_request() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        let mut req = create_req_for_store(&store, "alice", RECOVERY, &identity);
        req.signed_record = "zz".into();
        let err = store.create(req).unwrap_err();
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::InvalidRequest
        );
    }

    #[test]
    fn malformed_backup_fields_are_invalid_request() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        let mut bad_nonce = create_req_for_store(&store, "alice", RECOVERY, &identity);
        bad_nonce.wallet_backup.nonce = "zz".into();
        let err = store.create(bad_nonce).unwrap_err();
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::InvalidRequest
        );

        let mut p = OffsetPlatform(37);
        let identity = Identity::generate(&mut p).unwrap();
        let mut bad_ciphertext = create_req_for_store(&store, "bob", NEXT_RECOVERY, &identity);
        bad_ciphertext.wallet_backup.ciphertext = "zz".into();
        let err = store.create(bad_ciphertext).unwrap_err();
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::InvalidRequest
        );
    }

    #[test]
    fn malformed_registration_upload_is_invalid_request() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        let mut req = create_req_for_store(&store, "alice", RECOVERY, &identity);
        req.registration_upload = "zz".into();
        let err = store.create(req).unwrap_err();
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::InvalidRequest
        );
    }

    #[test]
    fn duplicate_registration_start_does_not_evict_pending_registration() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut rng = OsRng;
        let first_secret = RecoverySecret::parse(RECOVERY.to_string()).unwrap();
        let second_secret = RecoverySecret::parse(NEXT_RECOVERY.to_string()).unwrap();
        let first_grant = store.issue_creation_grant(Some("alice"), None).unwrap();
        let second_grant = store.issue_creation_grant(Some("alice"), None).unwrap();
        let first = ClientRegistration::<MycelliumOpaque>::start(&mut rng, first_secret.as_bytes())
            .unwrap();
        let first_response = store
            .start_registration(AccountRegistrationStartRequest {
                handle: "alice".into(),
                registration_request: hex(first.message.serialize().as_slice()),
                creation_grant: first_grant,
            })
            .unwrap();
        let second =
            ClientRegistration::<MycelliumOpaque>::start(&mut rng, second_secret.as_bytes())
                .unwrap();
        let err = match store.start_registration(AccountRegistrationStartRequest {
            handle: "alice".into(),
            registration_request: hex(second.message.serialize().as_slice()),
            creation_grant: second_grant,
        }) {
            Ok(_) => panic!("duplicate pending registration unexpectedly succeeded"),
            Err(err) => err,
        };
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::Conflict
        );

        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        let wallet_public = hex(&identity.wallet_public().0);
        let state = RegistrationClientState {
            handle: "alice".to_string(),
            account_id: first_response.account_id.clone(),
            registration_id: first_response.registration_id.clone(),
            state: first.state,
        };
        let (registration_upload, wallet_backup) = account_registration_finish(
            state,
            &first_response,
            &first_secret,
            &wallet_public,
            &identity.wallet_secret(),
        )
        .unwrap();

        store
            .create(AccountCreateRequest {
                account_id: first_response.account_id,
                handle: "alice".into(),
                registration_id: first_response.registration_id,
                registration_upload,
                wallet_backup,
                signed_record: signed_record_for_identity(
                    "alice",
                    1,
                    &identity,
                    b"127.0.0.1:9001".to_vec(),
                ),
            })
            .unwrap();
    }

    #[test]
    fn creation_grant_is_single_use() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let alice_secret = RecoverySecret::parse(RECOVERY.to_string()).unwrap();
        let bob_secret = RecoverySecret::parse(NEXT_RECOVERY.to_string()).unwrap();
        let grant = store.issue_creation_grant(None, None).unwrap();
        let mut rng = OsRng;
        let alice = ClientRegistration::<MycelliumOpaque>::start(&mut rng, alice_secret.as_bytes())
            .unwrap();
        store
            .start_registration(AccountRegistrationStartRequest {
                handle: "alice".into(),
                registration_request: hex(alice.message.serialize().as_slice()),
                creation_grant: secret_copy(&grant),
            })
            .unwrap();

        let bob =
            ClientRegistration::<MycelliumOpaque>::start(&mut rng, bob_secret.as_bytes()).unwrap();
        let err = match store.start_registration(AccountRegistrationStartRequest {
            handle: "bob".into(),
            registration_request: hex(bob.message.serialize().as_slice()),
            creation_grant: grant,
        }) {
            Ok(_) => panic!("consumed creation grant unexpectedly succeeded"),
            Err(err) => err,
        };
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::AuthenticationFailed
        );
    }

    #[test]
    fn creation_grant_is_handle_bound() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let secret = RecoverySecret::parse(RECOVERY.to_string()).unwrap();
        let grant = store.issue_creation_grant(Some("alice"), None).unwrap();
        let mut rng = OsRng;
        let start =
            ClientRegistration::<MycelliumOpaque>::start(&mut rng, secret.as_bytes()).unwrap();
        let err = match store.start_registration(AccountRegistrationStartRequest {
            handle: "bob".into(),
            registration_request: hex(start.message.serialize().as_slice()),
            creation_grant: grant,
        }) {
            Ok(_) => panic!("handle-bound creation grant unexpectedly succeeded"),
            Err(err) => err,
        };
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::AuthenticationFailed
        );
    }

    #[test]
    fn update_requires_operation_bound_auth() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        store
            .create(create_req_for_store(&store, "alice", RECOVERY, &identity))
            .unwrap();
        let signed = signed_record_for_identity("alice", 2, &identity, b"127.0.0.1:9002".to_vec());
        let op = record_operation_hash("alice", &signed).unwrap();
        let auth = auth_for(
            &store,
            "alice",
            RECOVERY,
            AuthPurpose::PublishRecord,
            Some(op),
        );
        assert!(store
            .update_record(AccountUpdateRecordRequest {
                auth_token: auth.auth_token,
                signed_record: signed,
            })
            .is_ok());
    }

    #[test]
    fn failed_auth_finish_consumes_login_attempt() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        store
            .create(create_req_for_store(&store, "alice", RECOVERY, &identity))
            .unwrap();

        let mut rng = OsRng;
        let start = ClientLogin::<MycelliumOpaque>::start(&mut rng, RECOVERY.as_bytes()).unwrap();
        let response = store
            .start_auth(AccountAuthStartRequest {
                handle: "alice".into(),
                purpose: AuthPurpose::Recover,
                operation_hash: None,
                credential_request: hex(start.message.serialize().as_slice()),
            })
            .unwrap();

        assert!(store
            .finish_auth(AccountAuthFinishRequest {
                handle: "alice".into(),
                login_id: response.login_id.clone(),
                credential_finalization: "00".into(),
            })
            .is_err());

        let credential_response = CredentialResponse::<MycelliumOpaque>::deserialize(
            &from_hex(&response.credential_response).unwrap(),
        )
        .unwrap();
        let context = auth_context(&response.account_id, "alice", &AuthPurpose::Recover, None);
        let finish = start
            .state
            .finish(
                &mut rng,
                RECOVERY.as_bytes(),
                credential_response,
                client_login_finish_params("alice", &context),
            )
            .unwrap();
        let err = match store.finish_auth(AccountAuthFinishRequest {
            handle: "alice".into(),
            login_id: response.login_id,
            credential_finalization: hex(finish.message.serialize().as_slice()),
        }) {
            Ok(_) => panic!("consumed login unexpectedly succeeded"),
            Err(err) => err,
        };
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::AuthenticationFailed
        );
    }

    #[test]
    fn failed_record_update_consumes_auth_token() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        store
            .create(create_req_for_store(&store, "alice", RECOVERY, &identity))
            .unwrap();

        let signed = signed_record_for_identity("alice", 2, &identity, b"127.0.0.1:9002".to_vec());
        let op = record_operation_hash("alice", &signed).unwrap();
        let auth = auth_for(
            &store,
            "alice",
            RECOVERY,
            AuthPurpose::PublishRecord,
            Some(op),
        );

        assert!(store
            .update_record(AccountUpdateRecordRequest {
                auth_token: secret_copy(&auth.auth_token),
                signed_record: "zz".into(),
            })
            .is_err());
        let err = store
            .update_record(AccountUpdateRecordRequest {
                auth_token: auth.auth_token,
                signed_record: signed,
            })
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::AuthenticationFailed
        );
    }

    #[test]
    fn malformed_wallet_rotation_backup_consumes_auth_token() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        store
            .create(create_req_for_store(&store, "alice", RECOVERY, &identity))
            .unwrap();

        let mut next_platform = OffsetPlatform(151);
        let next_identity = Identity::generate(&mut next_platform).unwrap();
        let signed =
            signed_record_for_identity("alice", 2, &next_identity, b"127.0.0.1:9012".to_vec());
        let op = record_operation_hash("alice", &signed).unwrap();
        let (auth, export_key) = auth_with_export(
            &store,
            "alice",
            RECOVERY,
            AuthPurpose::RotateWallet,
            Some(op),
        );
        let account_id = store.public_record("alice").unwrap().unwrap().account_id;
        let wallet_public = hex(&next_identity.wallet_public().0);
        let mut backup = seal_wallet_backup(
            &export_key,
            wallet_backup_metadata(&account_id, "alice", &wallet_public, 1),
            &next_identity.wallet_secret(),
        )
        .unwrap();
        backup.nonce = "zz".into();

        let err = store
            .rotate_wallet(AccountRotateWalletRequest {
                auth_token: secret_copy(&auth.auth_token),
                signed_record: signed.clone(),
                wallet_backup: backup,
            })
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::InvalidRequest
        );

        let backup = seal_wallet_backup(
            &export_key,
            wallet_backup_metadata(&account_id, "alice", &wallet_public, 1),
            &next_identity.wallet_secret(),
        )
        .unwrap();
        let err = store
            .rotate_wallet(AccountRotateWalletRequest {
                auth_token: auth.auth_token,
                signed_record: signed,
                wallet_backup: backup,
            })
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::AuthenticationFailed
        );
    }

    #[test]
    fn wallet_rotation_changes_wallet_and_rejects_stale_record() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        store
            .create(create_req_for_store(&store, "alice", RECOVERY, &identity))
            .unwrap();

        let mut next_platform = OffsetPlatform(91);
        let next_identity = Identity::generate(&mut next_platform).unwrap();
        assert_ne!(identity.wallet_public(), next_identity.wallet_public());

        let stale =
            signed_record_for_identity("alice", 1, &next_identity, b"127.0.0.1:9010".to_vec());
        let stale_op = record_operation_hash("alice", &stale).unwrap();
        let stale_auth = auth_for(
            &store,
            "alice",
            RECOVERY,
            AuthPurpose::RotateWallet,
            Some(stale_op),
        );
        let stale_backup = seal_wallet_backup(
            &[9u8; 64],
            wallet_backup_metadata(
                &store.public_record("alice").unwrap().unwrap().account_id,
                "alice",
                &hex(&next_identity.wallet_public().0),
                1,
            ),
            &next_identity.wallet_secret(),
        )
        .unwrap();
        assert!(store
            .rotate_wallet(AccountRotateWalletRequest {
                auth_token: stale_auth.auth_token,
                signed_record: stale,
                wallet_backup: stale_backup,
            })
            .is_err());

        let signed =
            signed_record_for_identity("alice", 2, &next_identity, b"127.0.0.1:9011".to_vec());
        let op = record_operation_hash("alice", &signed).unwrap();
        let (auth, export_key) = auth_with_export(
            &store,
            "alice",
            RECOVERY,
            AuthPurpose::RotateWallet,
            Some(op),
        );
        let account_id = store.public_record("alice").unwrap().unwrap().account_id;
        let wallet_public = hex(&next_identity.wallet_public().0);
        let backup = seal_wallet_backup(
            &export_key,
            wallet_backup_metadata(&account_id, "alice", &wallet_public, 1),
            &next_identity.wallet_secret(),
        )
        .unwrap();
        let rotated = store
            .rotate_wallet(AccountRotateWalletRequest {
                auth_token: auth.auth_token,
                signed_record: signed,
                wallet_backup: backup,
            })
            .unwrap();
        assert_eq!(rotated.wallet_public, wallet_public);
    }

    #[test]
    fn recovery_secret_rotation_invalidates_old_secret() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        store
            .create(create_req_for_store(&store, "alice", RECOVERY, &identity))
            .unwrap();

        let auth = auth_for(&store, "alice", RECOVERY, AuthPurpose::RotateRecovery, None);
        let mut rng = OsRng;
        let start =
            ClientRegistration::<MycelliumOpaque>::start(&mut rng, NEXT_RECOVERY.as_bytes())
                .unwrap();
        let response = store
            .start_recovery_rotation(RecoveryRegistrationStartRequest {
                auth_token: secret_copy(&auth.auth_token),
                registration_request: hex(start.message.serialize().as_slice()),
            })
            .unwrap();
        assert_eq!(response.handle, "alice");
        assert_eq!(response.recovery_revision, 2);
        let replay_start =
            ClientRegistration::<MycelliumOpaque>::start(&mut rng, NEXT_RECOVERY.as_bytes())
                .unwrap();
        assert!(store
            .start_recovery_rotation(RecoveryRegistrationStartRequest {
                auth_token: secret_copy(&auth.auth_token),
                registration_request: hex(replay_start.message.serialize().as_slice()),
            })
            .is_err());

        let registration_response = RegistrationResponse::<MycelliumOpaque>::deserialize(
            &from_hex(&response.registration_response).unwrap(),
        )
        .unwrap();
        let finish = start
            .state
            .finish(
                &mut rng,
                NEXT_RECOVERY.as_bytes(),
                registration_response,
                registration_finish_params("alice"),
            )
            .unwrap();
        let backup = seal_wallet_backup(
            finish.export_key.as_slice(),
            wallet_backup_metadata(
                &response.account_id,
                &response.handle,
                &response.wallet_public,
                response.recovery_revision,
            ),
            &identity.wallet_secret(),
        )
        .unwrap();
        store
            .finish_recovery_rotation(RecoveryRegistrationFinishRequest {
                operation_id: response.operation_id,
                operation_token: response.operation_token,
                registration_upload: hex(finish.message.serialize().as_slice()),
                wallet_backup: backup,
            })
            .unwrap();

        assert!(
            try_auth_with_export(&store, "alice", RECOVERY, AuthPurpose::Recover, None).is_err()
        );
        let auth = auth_for(&store, "alice", NEXT_RECOVERY, AuthPurpose::Recover, None);
        let recovered = store
            .recover(AccountRecoverRequest {
                auth_token: auth.auth_token,
            })
            .unwrap();
        assert_eq!(recovered.recovery_revision, 2);
    }

    #[test]
    fn failed_recovery_rotation_finish_consumes_operation() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        let mut p = TestPlatform;
        let identity = Identity::generate(&mut p).unwrap();
        store
            .create(create_req_for_store(&store, "alice", RECOVERY, &identity))
            .unwrap();

        let auth = auth_for(&store, "alice", RECOVERY, AuthPurpose::RotateRecovery, None);
        let mut rng = OsRng;
        let start =
            ClientRegistration::<MycelliumOpaque>::start(&mut rng, NEXT_RECOVERY.as_bytes())
                .unwrap();
        let response = store
            .start_recovery_rotation(RecoveryRegistrationStartRequest {
                auth_token: auth.auth_token,
                registration_request: hex(start.message.serialize().as_slice()),
            })
            .unwrap();
        let empty_backup = wallet_backup_metadata(
            &response.account_id,
            &response.handle,
            &response.wallet_public,
            response.recovery_revision,
        );
        assert!(store
            .finish_recovery_rotation(RecoveryRegistrationFinishRequest {
                operation_id: response.operation_id.clone(),
                operation_token: secret_copy(&response.operation_token),
                registration_upload: "00".into(),
                wallet_backup: empty_backup,
            })
            .is_err());

        let registration_response = RegistrationResponse::<MycelliumOpaque>::deserialize(
            &from_hex(&response.registration_response).unwrap(),
        )
        .unwrap();
        let finish = start
            .state
            .finish(
                &mut rng,
                NEXT_RECOVERY.as_bytes(),
                registration_response,
                registration_finish_params("alice"),
            )
            .unwrap();
        let backup = seal_wallet_backup(
            finish.export_key.as_slice(),
            wallet_backup_metadata(
                &response.account_id,
                &response.handle,
                &response.wallet_public,
                response.recovery_revision,
            ),
            &identity.wallet_secret(),
        )
        .unwrap();
        let err = store
            .finish_recovery_rotation(RecoveryRegistrationFinishRequest {
                operation_id: response.operation_id,
                operation_token: response.operation_token,
                registration_upload: hex(finish.message.serialize().as_slice()),
                wallet_backup: backup,
            })
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<RegistryError>().unwrap().kind,
            RegistryErrorKind::Conflict
        );
    }

    #[test]
    fn rate_bucket_enforces_limit_boundary() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        store
            .with_conn(|conn| {
                let path = "/v2/accounts/wallet/rotate";
                for _ in 0..5 {
                    allow_test_request(conn, "127.0.0.1", Method::POST, path)?;
                }
                let err = allow_test_request(conn, "127.0.0.1", Method::POST, path).unwrap_err();
                assert_eq!(
                    err.downcast_ref::<RegistryError>().unwrap().kind,
                    RegistryErrorKind::RateLimited
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn lookup_rate_limit_enforces_per_handle_boundary() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        store
            .with_conn(|conn| {
                let peer = test_tcp_peer_key();
                let path = "/v2/accounts/samehandle";
                for _ in 0..LOOKUP_HANDLE_LIMIT {
                    allow_test_request(conn, "127.0.0.1", Method::GET, path)?;
                }

                let err = allow_test_request(conn, "127.0.0.1", Method::GET, path).unwrap_err();
                assert_eq!(
                    err.downcast_ref::<RegistryError>().unwrap().kind,
                    RegistryErrorKind::RateLimited
                );

                let aggregate_count: i64 = conn.query_row(
                    "SELECT count FROM rate_buckets
                     WHERE peer = ?1 AND action = ?2 AND bucket = ?3",
                    params![peer, "lookup", "*"],
                    |row| row.get(0),
                )?;
                assert_eq!(aggregate_count, LOOKUP_HANDLE_LIMIT);

                let plaintext_buckets: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM rate_buckets WHERE bucket = ?1",
                    params!["samehandle"],
                    |row| row.get(0),
                )?;
                assert_eq!(plaintext_buckets, 0);

                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn lookup_rate_limit_enforces_aggregate_boundary_before_handle_bucket() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        store
            .with_conn(|conn| {
                let peer = test_tcp_peer_key();
                for i in 0..LOOKUP_AGGREGATE_LIMIT {
                    allow_test_request(
                        conn,
                        "127.0.0.1",
                        Method::GET,
                        &format!("/v2/accounts/h{i:03}"),
                    )?;
                }

                let err = allow_test_request(conn, "127.0.0.1", Method::GET, "/v2/accounts/h999")
                    .unwrap_err();
                assert_eq!(
                    err.downcast_ref::<RegistryError>().unwrap().kind,
                    RegistryErrorKind::RateLimited
                );

                let aggregate_count: i64 = conn.query_row(
                    "SELECT count FROM rate_buckets
                     WHERE peer = ?1 AND action = ?2 AND bucket = ?3",
                    params![peer, "lookup", "*"],
                    |row| row.get(0),
                )?;
                assert_eq!(aggregate_count, LOOKUP_AGGREGATE_LIMIT);

                let handle_bucket_count: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM rate_buckets
                     WHERE peer = ?1 AND action = ?2",
                    params![test_tcp_peer_key(), "lookup-handle"],
                    |row| row.get(0),
                )?;
                assert_eq!(handle_bucket_count, LOOKUP_AGGREGATE_LIMIT);

                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn malformed_unicode_hex_does_not_panic() {
        assert!(from_hex("€a").is_err());
    }

    #[test]
    fn recovery_secret_rejects_surrounding_whitespace() {
        assert!(RecoverySecret::parse(format!("{RECOVERY}\n")).is_err());
        assert!(RecoverySecret::parse(format!(" {RECOVERY}")).is_err());
        assert!(RecoverySecret::parse(RECOVERY.to_string()).is_ok());
    }

    #[test]
    fn raw_http_registry_rejects_non_loopback_binds() {
        let err = serve_tcp_dev("0.0.0.0:0", ":memory:").unwrap_err();
        assert!(
            err.to_string().contains("only binds to loopback"),
            "{err:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn relative_data_dirs_reject_world_writable_effective_parent() {
        let _cwd_lock = CWD_LOCK.lock().unwrap();
        let dir = TempDir::new("mycellium-registry-world-cwd", 0o777);
        let _cwd = CurrentDirGuard::enter(dir.path());

        for path in ["registry", "./registry"] {
            let err = expect_store_open_error(AccountStore::open_with_secret(path, TEST_SECRET));
            assert!(
                err.to_string().contains("must not be group/world writable"),
                "{path}: {err:?}"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn relative_data_dir_creates_private_tree_and_database() {
        let _cwd_lock = CWD_LOCK.lock().unwrap();
        let dir = TempDir::new("mycellium-registry-private-cwd", 0o700);
        let _cwd = CurrentDirGuard::enter(dir.path());

        let store = AccountStore::open_with_secret("./data/registry", TEST_SECRET).unwrap();
        assert_eq!(store.data_dir, dir.path().join("data/registry"));
        assert!(store.path.is_absolute());
        assert_eq!(store.path, dir.path().join("data/registry/registry.sqlite"));
        assert_eq!(
            registry_socket_path(&store.data_dir),
            dir.path().join("data/registry/registry.sock")
        );
        drop(store);

        assert_eq!(file_mode(&dir.path().join("data")), 0o700);
        assert_eq!(file_mode(&dir.path().join("data/registry")), 0o700);
        assert_eq!(
            file_mode(&dir.path().join("data/registry").join(REGISTRY_DIR_MARKER)),
            0o600
        );
        assert_eq!(
            file_mode(&dir.path().join("data/registry/registry.sqlite")),
            0o600
        );
    }

    #[test]
    #[cfg(unix)]
    fn data_dir_rejects_parent_components() {
        let dir = TempDir::new("mycellium-registry-parent-components", 0o700);
        for path in [
            PathBuf::from("data/../registry"),
            dir.path().join("registry/../escaped"),
        ] {
            let err = expect_store_open_error(AccountStore::open_with_secret(&path, TEST_SECRET));
            assert!(
                err.to_string()
                    .contains("must not contain parent directory components"),
                "{}: {err:?}",
                path.display()
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn private_directory_creation_ignores_permissive_umask() {
        let _cwd_lock = CWD_LOCK.lock().unwrap();
        let dir = TempDir::new("mycellium-registry-umask", 0o700);
        let _cwd = CurrentDirGuard::enter(dir.path());
        let old_umask = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0));
        let result = AccountStore::open_with_secret("data/registry", TEST_SECRET);
        rustix::process::umask(old_umask);

        let store = result.unwrap();
        drop(store);
        assert_eq!(file_mode(&dir.path().join("data")), 0o700);
        assert_eq!(file_mode(&dir.path().join("data/registry")), 0o700);
    }

    #[test]
    fn registry_sqlite_uses_full_synchronous_mode() {
        let store = AccountStore::open_with_secret(":memory:", TEST_SECRET).unwrap();
        store
            .with_conn(|conn| {
                let synchronous: i64 =
                    conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
                assert_eq!(synchronous, 2);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn existing_data_dir_without_registry_marker_is_rejected() {
        let dir = TempDir::new("mycellium-registry-unmarked", 0o700);
        let data_dir = dir.path().join("registry");
        std::fs::create_dir(&data_dir).unwrap();
        set_private_dir(&data_dir).unwrap();

        let err = expect_store_open_error(AccountStore::open_with_secret(&data_dir, TEST_SECRET));
        assert!(
            err.to_string().contains("missing the registry marker"),
            "{err:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn broad_data_dir_leaves_are_rejected_before_hardening() {
        for path in [Path::new("/"), Path::new("/tmp")] {
            let err = expect_store_open_error(AccountStore::open_with_secret(path, TEST_SECRET));
            assert!(
                err.to_string()
                    .contains("must be a dedicated registry directory"),
                "{}: {err:?}",
                path.display()
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn registry_database_file_rejects_symlink() {
        let dir = TempDir::new("mycellium-registry-symlink-db", 0o700);
        let data_dir = dir.path().join("registry");
        std::fs::create_dir(&data_dir).unwrap();
        set_private_dir(&data_dir).unwrap();
        create_private_marker(&data_dir.join(REGISTRY_DIR_MARKER)).unwrap();
        let link = data_dir.join(REGISTRY_DB_FILE);
        std::os::unix::fs::symlink(data_dir.join("target.sqlite"), &link).unwrap();

        let err = expect_store_open_error(AccountStore::open_with_secret(&data_dir, TEST_SECRET));
        assert!(err.to_string().contains("must not be a symlink"), "{err:?}");
    }

    #[test]
    #[cfg(unix)]
    fn registry_data_dir_rejects_symlink_ancestor() {
        let dir = TempDir::new("mycellium-registry-symlink-ancestor", 0o700);
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        set_private_dir(&target).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = expect_store_open_error(AccountStore::open_with_secret(
            link.join("registry"),
            TEST_SECRET,
        ));
        assert!(
            err.to_string().contains("ancestor")
                && err.to_string().contains("must not be a symlink"),
            "{err:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn registry_sqlite_sidecar_rejects_symlink() {
        let dir = TempDir::new("mycellium-registry-symlink-sidecar", 0o700);
        let data_dir = dir.path().join("registry");
        std::fs::create_dir(&data_dir).unwrap();
        set_private_dir(&data_dir).unwrap();
        create_private_marker(&data_dir.join(REGISTRY_DIR_MARKER)).unwrap();
        let db = data_dir.join(REGISTRY_DB_FILE);
        create_private_file(&db).unwrap();
        std::os::unix::fs::symlink(data_dir.join("target-wal"), sqlite_sidecar_path(&db, "wal"))
            .unwrap();

        let err = expect_store_open_error(AccountStore::open_with_secret(&data_dir, TEST_SECRET));
        assert!(err.to_string().contains("must not be a symlink"), "{err:?}");
    }
}
