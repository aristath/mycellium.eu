use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{
    decode_json, encode_json, ensure_parent, key, Account, AccountBlobKind, AccountId,
    AccountLogin, BlobRef, BlobSwap, LoginIdentity, LoginIdentityHash, LoginIdentityKind,
    LoginToken, RateLimitBucket, RegistryError, RegistryStore, Result, Session,
};
use mycellium_core::userid::UserId;

const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("accounts");
const LOGIN_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("login_index");
const LOGIN_TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("login_tokens");
const LOGIN_TOKEN_EXPIRY: TableDefinition<&str, &[u8]> =
    TableDefinition::new("login_token_expiry_v1");
const BLOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("blobs");
const RATES: TableDefinition<&str, &[u8]> = TableDefinition::new("rates");
// `sessions` was keyed by token hash and allowed several simultaneous sessions.
// These v2 tables retain exactly one current token per account and a reverse
// index containing exactly one entry per account.
const ACCOUNT_SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("account_sessions_v2");
const SESSION_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("session_index_v2");
const SESSION_EXPIRY: TableDefinition<&str, &[u8]> = TableDefinition::new("session_expiry_v1");
const USER_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("user_index");
const RATE_EXPIRY: TableDefinition<&str, &[u8]> = TableDefinition::new("rate_expiry_v1");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("registry_meta_v1");
const EXPIRY_INDEX_MARKER: &str = "expiry_indexes_v1";

/// `redb` implementation of the registry metadata store.
pub struct RedbRegistryStore {
    db: Database,
}

impl RedbRegistryStore {
    /// Open or create a registry metadata database.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        ensure_parent(path.as_ref())?;
        let db = Database::create(path)
            .map_err(|err| RegistryError::new(format!("open redb failed: {err}")))?;
        let store = Self { db };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> Result<()> {
        let tx = self
            .db
            .begin_write()
            .map_err(|err| RegistryError::new(format!("begin write failed: {err}")))?;
        {
            tx.open_table(ACCOUNTS)
                .map_err(|err| RegistryError::new(format!("open accounts failed: {err}")))?;
            tx.open_table(LOGIN_INDEX)
                .map_err(|err| RegistryError::new(format!("open login index failed: {err}")))?;
            tx.open_table(LOGIN_TOKENS)
                .map_err(|err| RegistryError::new(format!("open login tokens failed: {err}")))?;
            tx.open_table(LOGIN_TOKEN_EXPIRY).map_err(|err| {
                RegistryError::new(format!("open login token expiry failed: {err}"))
            })?;
            tx.open_table(BLOBS)
                .map_err(|err| RegistryError::new(format!("open blobs failed: {err}")))?;
            tx.open_table(RATES)
                .map_err(|err| RegistryError::new(format!("open rates failed: {err}")))?;
            tx.open_table(ACCOUNT_SESSIONS).map_err(|err| {
                RegistryError::new(format!("open account sessions failed: {err}"))
            })?;
            tx.open_table(SESSION_INDEX)
                .map_err(|err| RegistryError::new(format!("open session index failed: {err}")))?;
            tx.open_table(SESSION_EXPIRY)
                .map_err(|err| RegistryError::new(format!("open session expiry failed: {err}")))?;
            tx.open_table(USER_INDEX)
                .map_err(|err| RegistryError::new(format!("open user index failed: {err}")))?;
            tx.open_table(RATE_EXPIRY)
                .map_err(|err| RegistryError::new(format!("open rate expiry failed: {err}")))?;
            tx.open_table(META)
                .map_err(|err| RegistryError::new(format!("open registry meta failed: {err}")))?;
        }

        let needs_expiry_backfill = {
            let meta = tx
                .open_table(META)
                .map_err(|err| RegistryError::new(format!("open registry meta failed: {err}")))?;
            let missing = meta
                .get(EXPIRY_INDEX_MARKER)
                .map_err(|err| RegistryError::new(format!("read schema marker failed: {err}")))?
                .is_none();
            missing
        };
        if needs_expiry_backfill {
            let login_entries = {
                let tokens = tx.open_table(LOGIN_TOKENS).map_err(|err| {
                    RegistryError::new(format!("open login tokens failed: {err}"))
                })?;
                let mut entries = Vec::new();
                for entry in tokens
                    .iter()
                    .map_err(|err| RegistryError::new(format!("scan login tokens failed: {err}")))?
                {
                    let (key, value) = entry.map_err(|err| {
                        RegistryError::new(format!("read login token failed: {err}"))
                    })?;
                    let token: LoginToken = decode_json(value.value())?;
                    entries.push((key.value().to_string(), token.expires_at));
                }
                entries
            };
            let session_entries = {
                let sessions = tx.open_table(ACCOUNT_SESSIONS).map_err(|err| {
                    RegistryError::new(format!("open account sessions failed: {err}"))
                })?;
                let mut entries = Vec::new();
                for entry in sessions.iter().map_err(|err| {
                    RegistryError::new(format!("scan account sessions failed: {err}"))
                })? {
                    let (account, value) = entry.map_err(|err| {
                        RegistryError::new(format!("read account session failed: {err}"))
                    })?;
                    let session: Session = decode_json(value.value())?;
                    entries.push((
                        account.value().to_string(),
                        session.token_hash,
                        session.expires_at,
                    ));
                }
                entries
            };
            let rate_entries = {
                let rates = tx
                    .open_table(RATES)
                    .map_err(|err| RegistryError::new(format!("open rates failed: {err}")))?;
                let mut entries = Vec::new();
                for entry in rates
                    .iter()
                    .map_err(|err| RegistryError::new(format!("scan rate buckets failed: {err}")))?
                {
                    let (key, value) = entry.map_err(|err| {
                        RegistryError::new(format!("read rate bucket failed: {err}"))
                    })?;
                    let bucket: RateLimitBucket = decode_json(value.value())?;
                    entries.push((key.value().to_string(), bucket.expires_at));
                }
                entries
            };
            {
                let mut expiry = tx.open_table(LOGIN_TOKEN_EXPIRY).map_err(|err| {
                    RegistryError::new(format!("open login token expiry failed: {err}"))
                })?;
                for (token_hash, expires_at) in login_entries {
                    expiry
                        .insert(expiry_key(expires_at, &token_hash).as_str(), b"".as_slice())
                        .map_err(|err| {
                            RegistryError::new(format!("backfill login expiry failed: {err}"))
                        })?;
                }
            }
            {
                let mut expiry = tx.open_table(SESSION_EXPIRY).map_err(|err| {
                    RegistryError::new(format!("open session expiry failed: {err}"))
                })?;
                for (account, token_hash, expires_at) in session_entries {
                    expiry
                        .insert(
                            expiry_key(expires_at, &account).as_str(),
                            token_hash.as_bytes(),
                        )
                        .map_err(|err| {
                            RegistryError::new(format!("backfill session expiry failed: {err}"))
                        })?;
                }
            }
            {
                let mut expiry = tx
                    .open_table(RATE_EXPIRY)
                    .map_err(|err| RegistryError::new(format!("open rate expiry failed: {err}")))?;
                for (rate_key, expires_at) in rate_entries {
                    expiry
                        .insert(expiry_key(expires_at, &rate_key).as_str(), b"".as_slice())
                        .map_err(|err| {
                            RegistryError::new(format!("backfill rate expiry failed: {err}"))
                        })?;
                }
            }
            tx.open_table(META)
                .map_err(|err| RegistryError::new(format!("open registry meta failed: {err}")))?
                .insert(EXPIRY_INDEX_MARKER, b"1".as_slice())
                .map_err(|err| RegistryError::new(format!("write schema marker failed: {err}")))?;
        }
        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit init failed: {err}")))
    }
}

impl RegistryStore for RedbRegistryStore {
    fn put_login_token(&self, token_hash: &str, token: &LoginToken) -> Result<()> {
        let tx = self
            .db
            .begin_write()
            .map_err(|err| RegistryError::new(format!("begin write failed: {err}")))?;
        {
            let mut table = tx
                .open_table(LOGIN_TOKENS)
                .map_err(|err| RegistryError::new(format!("open login tokens failed: {err}")))?;
            let value = encode_json(token)?;
            table
                .insert(token_hash, value.as_slice())
                .map_err(|err| RegistryError::new(format!("write login token failed: {err}")))?;
            let mut expiry = tx.open_table(LOGIN_TOKEN_EXPIRY).map_err(|err| {
                RegistryError::new(format!("open login token expiry failed: {err}"))
            })?;
            expiry
                .insert(
                    expiry_key(token.expires_at, token_hash).as_str(),
                    b"".as_slice(),
                )
                .map_err(|err| {
                    RegistryError::new(format!("write login token expiry failed: {err}"))
                })?;
        }
        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit login token failed: {err}")))
    }

    fn take_login_token(&self, token_hash: &str) -> Result<Option<LoginToken>> {
        let tx = self
            .db
            .begin_write()
            .map_err(|err| RegistryError::new(format!("begin write failed: {err}")))?;
        let token: LoginToken = {
            let mut table = tx
                .open_table(LOGIN_TOKENS)
                .map_err(|err| RegistryError::new(format!("open login tokens failed: {err}")))?;
            let Some(value) = table
                .remove(token_hash)
                .map_err(|err| RegistryError::new(format!("remove login token failed: {err}")))?
            else {
                return Ok(None);
            };
            decode_json(value.value())?
        };
        tx.open_table(LOGIN_TOKEN_EXPIRY)
            .map_err(|err| RegistryError::new(format!("open login token expiry failed: {err}")))?
            .remove(expiry_key(token.expires_at, token_hash).as_str())
            .map_err(|err| {
                RegistryError::new(format!("remove login token expiry failed: {err}"))
            })?;
        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit token consume failed: {err}")))?;
        Ok(Some(token))
    }

    fn account_id_by_login(
        &self,
        kind: LoginIdentityKind,
        hash: &LoginIdentityHash,
    ) -> Result<Option<AccountId>> {
        let tx = self
            .db
            .begin_read()
            .map_err(|err| RegistryError::new(format!("begin read failed: {err}")))?;
        let table = tx
            .open_table(LOGIN_INDEX)
            .map_err(|err| RegistryError::new(format!("open login index failed: {err}")))?;
        let Some(value) = table
            .get(login_key(kind, hash).as_str())
            .map_err(|err| RegistryError::new(format!("read login index failed: {err}")))?
        else {
            return Ok(None);
        };
        let id = std::str::from_utf8(value.value())
            .map_err(|_| RegistryError::new("stored account id is not utf-8"))?;
        Ok(Some(id.parse()?))
    }

    fn get_or_create_account_for_login(
        &self,
        kind: LoginIdentityKind,
        hash: &LoginIdentityHash,
        new_account: Account,
        verified_at: i64,
    ) -> Result<AccountLogin> {
        let tx = self
            .db
            .begin_write()
            .map_err(|err| RegistryError::new(format!("begin write failed: {err}")))?;
        let outcome = {
            let login_key = login_key(kind, hash);
            let mut login_index = tx
                .open_table(LOGIN_INDEX)
                .map_err(|err| RegistryError::new(format!("open login index failed: {err}")))?;
            let existing = {
                let value = login_index
                    .get(login_key.as_str())
                    .map_err(|err| RegistryError::new(format!("read login index failed: {err}")))?;
                match value {
                    Some(value) => {
                        let id = std::str::from_utf8(value.value())
                            .map_err(|_| RegistryError::new("stored account id is not utf-8"))?;
                        Some(id.parse()?)
                    }
                    None => None,
                }
            };

            if let Some(account_id) = existing {
                AccountLogin {
                    account_id,
                    created: false,
                }
            } else {
                let account_id = new_account.id.clone();
                login_index
                    .insert(login_key.as_str(), account_id.as_str().as_bytes())
                    .map_err(|err| {
                        RegistryError::new(format!("write login index failed: {err}"))
                    })?;
                drop(login_index);

                let mut accounts = tx
                    .open_table(ACCOUNTS)
                    .map_err(|err| RegistryError::new(format!("open accounts failed: {err}")))?;
                let account_bytes = encode_json(&new_account)?;
                accounts
                    .insert(account_id.as_str(), account_bytes.as_slice())
                    .map_err(|err| RegistryError::new(format!("write account failed: {err}")))?;
                drop(accounts);

                let identity = LoginIdentity {
                    kind,
                    value_hash: hash.clone(),
                    account_id: account_id.clone(),
                    verified_at,
                };
                let identity_key = key(&["login_identity", account_id.as_str(), kind.as_str()]);
                let mut blobs = tx
                    .open_table(BLOBS)
                    .map_err(|err| RegistryError::new(format!("open blobs failed: {err}")))?;
                let identity_bytes = encode_json(&identity)?;
                blobs
                    .insert(identity_key.as_str(), identity_bytes.as_slice())
                    .map_err(|err| {
                        RegistryError::new(format!("write login identity failed: {err}"))
                    })?;

                AccountLogin {
                    account_id,
                    created: true,
                }
            }
        };
        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit account login failed: {err}")))?;
        Ok(outcome)
    }

    fn account(&self, id: &AccountId) -> Result<Option<Account>> {
        let tx = self
            .db
            .begin_read()
            .map_err(|err| RegistryError::new(format!("begin read failed: {err}")))?;
        let table = tx
            .open_table(ACCOUNTS)
            .map_err(|err| RegistryError::new(format!("open accounts failed: {err}")))?;
        let Some(value) = table
            .get(id.as_str())
            .map_err(|err| RegistryError::new(format!("read account failed: {err}")))?
        else {
            return Ok(None);
        };
        Ok(Some(decode_json(value.value())?))
    }

    fn compare_and_swap_blob_ref(
        &self,
        account_id: &AccountId,
        kind: AccountBlobKind,
        expected: Option<&BlobRef>,
        next: &BlobRef,
    ) -> Result<BlobSwap> {
        let tx = self
            .db
            .begin_write()
            .map_err(|err| RegistryError::new(format!("begin write failed: {err}")))?;
        let previous = {
            let mut table = tx
                .open_table(BLOBS)
                .map_err(|err| RegistryError::new(format!("open blobs failed: {err}")))?;
            let current = table
                .get(blob_key(account_id, kind).as_str())
                .map_err(|err| RegistryError::new(format!("read blob ref failed: {err}")))?
                .map(|value| decode_json::<BlobRef>(value.value()))
                .transpose()?;
            if current.as_ref() != expected {
                return Ok(BlobSwap::Mismatch { current });
            }
            let blob_bytes = encode_json(next)?;
            table
                .insert(blob_key(account_id, kind).as_str(), blob_bytes.as_slice())
                .map_err(|err| RegistryError::new(format!("write blob ref failed: {err}")))?;
            current
        };
        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit blob ref failed: {err}")))?;
        Ok(BlobSwap::Applied { previous })
    }

    fn blob_ref(&self, account_id: &AccountId, kind: AccountBlobKind) -> Result<Option<BlobRef>> {
        let tx = self
            .db
            .begin_read()
            .map_err(|err| RegistryError::new(format!("begin read failed: {err}")))?;
        let table = tx
            .open_table(BLOBS)
            .map_err(|err| RegistryError::new(format!("open blobs failed: {err}")))?;
        let Some(value) = table
            .get(blob_key(account_id, kind).as_str())
            .map_err(|err| RegistryError::new(format!("read blob ref failed: {err}")))?
        else {
            return Ok(None);
        };
        Ok(Some(decode_json(value.value())?))
    }

    fn compare_and_swap_public_record_ref(
        &self,
        account_id: &AccountId,
        user_id: &UserId,
        previous_user_id: Option<&UserId>,
        expected: Option<&BlobRef>,
        next: &BlobRef,
    ) -> Result<BlobSwap> {
        let tx = self
            .db
            .begin_write()
            .map_err(|err| RegistryError::new(format!("begin write failed: {err}")))?;
        let previous = {
            let mut blobs = tx
                .open_table(BLOBS)
                .map_err(|err| RegistryError::new(format!("open blobs failed: {err}")))?;
            let current = blobs
                .get(blob_key(account_id, AccountBlobKind::PublicRecord).as_str())
                .map_err(|err| RegistryError::new(format!("read blob ref failed: {err}")))?
                .map(|value| decode_json::<BlobRef>(value.value()))
                .transpose()?;
            if current.as_ref() != expected {
                return Ok(BlobSwap::Mismatch { current });
            }

            let mut users = tx
                .open_table(USER_INDEX)
                .map_err(|err| RegistryError::new(format!("open user index failed: {err}")))?;
            if let Some(existing) = users
                .get(user_id.as_str())
                .map_err(|err| RegistryError::new(format!("read user index failed: {err}")))?
            {
                if existing.value() != account_id.as_str().as_bytes() {
                    return Err(RegistryError::conflict(
                        "protocol user id is already bound to another account",
                    ));
                }
            }
            users
                .insert(user_id.as_str(), account_id.as_str().as_bytes())
                .map_err(|err| RegistryError::new(format!("write user index failed: {err}")))?;
            if let Some(previous_user_id) = previous_user_id.filter(|previous| *previous != user_id)
            {
                let remove_previous = users
                    .get(previous_user_id.as_str())
                    .map_err(|err| {
                        RegistryError::new(format!("read previous user index failed: {err}"))
                    })?
                    .is_some_and(|existing| existing.value() == account_id.as_str().as_bytes());
                if remove_previous {
                    users.remove(previous_user_id.as_str()).map_err(|err| {
                        RegistryError::new(format!("remove previous user index failed: {err}"))
                    })?;
                }
            }
            drop(users);

            let blob_bytes = encode_json(next)?;
            blobs
                .insert(
                    blob_key(account_id, AccountBlobKind::PublicRecord).as_str(),
                    blob_bytes.as_slice(),
                )
                .map_err(|err| RegistryError::new(format!("write blob ref failed: {err}")))?;
            current
        };
        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit public record failed: {err}")))?;
        Ok(BlobSwap::Applied { previous })
    }

    fn account_id_by_user_id(&self, user_id: &UserId) -> Result<Option<AccountId>> {
        let tx = self
            .db
            .begin_read()
            .map_err(|err| RegistryError::new(format!("begin read failed: {err}")))?;
        let users = tx
            .open_table(USER_INDEX)
            .map_err(|err| RegistryError::new(format!("open user index failed: {err}")))?;
        let Some(account_id) = users
            .get(user_id.as_str())
            .map_err(|err| RegistryError::new(format!("read user index failed: {err}")))?
        else {
            return Ok(None);
        };
        let account_id = std::str::from_utf8(account_id.value())
            .map_err(|_| RegistryError::new("stored account id is not utf-8"))?;
        Ok(Some(account_id.parse()?))
    }

    fn replace_session(&self, session: &Session) -> Result<()> {
        let tx = self
            .db
            .begin_write()
            .map_err(|err| RegistryError::new(format!("begin write failed: {err}")))?;
        {
            let mut account_sessions = tx.open_table(ACCOUNT_SESSIONS).map_err(|err| {
                RegistryError::new(format!("open account sessions failed: {err}"))
            })?;
            let previous = account_sessions
                .get(session.account_id.as_str())
                .map_err(|err| RegistryError::new(format!("read account session failed: {err}")))?
                .map(|value| decode_json::<Session>(value.value()))
                .transpose()?;
            let session_bytes = encode_json(session)?;
            account_sessions
                .insert(session.account_id.as_str(), session_bytes.as_slice())
                .map_err(|err| {
                    RegistryError::new(format!("write account session failed: {err}"))
                })?;
            drop(account_sessions);

            let mut index = tx
                .open_table(SESSION_INDEX)
                .map_err(|err| RegistryError::new(format!("open session index failed: {err}")))?;
            if let Some(previous) = previous {
                index.remove(previous.token_hash.as_str()).map_err(|err| {
                    RegistryError::new(format!("revoke previous session failed: {err}"))
                })?;
                tx.open_table(SESSION_EXPIRY)
                    .map_err(|err| {
                        RegistryError::new(format!("open session expiry failed: {err}"))
                    })?
                    .remove(expiry_key(previous.expires_at, session.account_id.as_str()).as_str())
                    .map_err(|err| {
                        RegistryError::new(format!("remove previous session expiry failed: {err}"))
                    })?;
            }
            index
                .insert(
                    session.token_hash.as_str(),
                    session.account_id.as_str().as_bytes(),
                )
                .map_err(|err| RegistryError::new(format!("write session index failed: {err}")))?;
            tx.open_table(SESSION_EXPIRY)
                .map_err(|err| RegistryError::new(format!("open session expiry failed: {err}")))?
                .insert(
                    expiry_key(session.expires_at, session.account_id.as_str()).as_str(),
                    session.token_hash.as_bytes(),
                )
                .map_err(|err| RegistryError::new(format!("write session expiry failed: {err}")))?;
        }
        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit session failed: {err}")))
    }

    fn session(&self, token_hash: &str) -> Result<Option<Session>> {
        let tx = self
            .db
            .begin_read()
            .map_err(|err| RegistryError::new(format!("begin read failed: {err}")))?;
        let index = tx
            .open_table(SESSION_INDEX)
            .map_err(|err| RegistryError::new(format!("open session index failed: {err}")))?;
        let Some(account_id) = index
            .get(token_hash)
            .map_err(|err| RegistryError::new(format!("read session index failed: {err}")))?
        else {
            return Ok(None);
        };
        let account_id = std::str::from_utf8(account_id.value())
            .map_err(|_| RegistryError::new("stored account id is not utf-8"))?;
        let sessions = tx
            .open_table(ACCOUNT_SESSIONS)
            .map_err(|err| RegistryError::new(format!("open account sessions failed: {err}")))?;
        let Some(value) = sessions
            .get(account_id)
            .map_err(|err| RegistryError::new(format!("read account session failed: {err}")))?
        else {
            return Ok(None);
        };
        let session: Session = decode_json(value.value())?;
        if session.token_hash != token_hash {
            return Ok(None);
        }
        Ok(Some(session))
    }

    fn bump_rate_limit(&self, key: &str, now: i64, window_secs: i64) -> Result<RateLimitBucket> {
        if key.is_empty() || window_secs <= 0 {
            return Err(RegistryError::new("invalid rate-limit bucket"));
        }
        let tx = self
            .db
            .begin_write()
            .map_err(|err| RegistryError::new(format!("begin write failed: {err}")))?;
        let bucket = {
            let mut table = tx
                .open_table(RATES)
                .map_err(|err| RegistryError::new(format!("open rates failed: {err}")))?;
            let current = {
                let value = table
                    .get(key)
                    .map_err(|err| RegistryError::new(format!("read rate failed: {err}")))?;
                match value {
                    Some(value) => Some(decode_json::<RateLimitBucket>(value.value())?),
                    None => None,
                }
            };
            let previous_expiry = current.as_ref().map(|bucket| bucket.expires_at);
            let next = match current {
                Some(mut bucket) if bucket.expires_at > now => {
                    bucket.count = bucket.count.saturating_add(1);
                    bucket
                }
                _ => RateLimitBucket {
                    count: 1,
                    expires_at: now.saturating_add(window_secs),
                },
            };
            let bytes = encode_json(&next)?;
            table
                .insert(key, bytes.as_slice())
                .map_err(|err| RegistryError::new(format!("write rate failed: {err}")))?;
            let mut expiry = tx
                .open_table(RATE_EXPIRY)
                .map_err(|err| RegistryError::new(format!("open rate expiry failed: {err}")))?;
            if let Some(previous_expiry) = previous_expiry {
                expiry
                    .remove(expiry_key(previous_expiry, key).as_str())
                    .map_err(|err| {
                        RegistryError::new(format!("remove previous rate expiry failed: {err}"))
                    })?;
            }
            expiry
                .insert(expiry_key(next.expires_at, key).as_str(), b"".as_slice())
                .map_err(|err| RegistryError::new(format!("write rate expiry failed: {err}")))?;
            next
        };
        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit rate failed: {err}")))?;
        Ok(bucket)
    }

    fn purge_expired(&self, now: i64, limit: usize) -> Result<usize> {
        if limit == 0 {
            return Ok(0);
        }
        let tx = self
            .db
            .begin_write()
            .map_err(|err| RegistryError::new(format!("begin cleanup failed: {err}")))?;
        let mut removed = 0usize;

        {
            let mut expiry = tx.open_table(LOGIN_TOKEN_EXPIRY).map_err(|err| {
                RegistryError::new(format!("open login token expiry failed: {err}"))
            })?;
            let mut due = Vec::new();
            for entry in expiry
                .iter()
                .map_err(|err| RegistryError::new(format!("scan login expiry failed: {err}")))?
            {
                let (key, _) = entry.map_err(|err| {
                    RegistryError::new(format!("read login expiry failed: {err}"))
                })?;
                if expiry_timestamp(key.value())? > now {
                    break;
                }
                due.push((
                    key.value().to_string(),
                    expiry_subject(key.value())?.to_string(),
                ));
                if removed + due.len() >= limit {
                    break;
                }
            }
            let mut tokens = tx
                .open_table(LOGIN_TOKENS)
                .map_err(|err| RegistryError::new(format!("open login tokens failed: {err}")))?;
            for (index_key, token_hash) in due {
                tokens.remove(token_hash.as_str()).map_err(|err| {
                    RegistryError::new(format!("remove expired login token failed: {err}"))
                })?;
                expiry.remove(index_key.as_str()).map_err(|err| {
                    RegistryError::new(format!("remove login expiry failed: {err}"))
                })?;
                removed += 1;
            }
        }

        if removed < limit {
            let mut expiry = tx
                .open_table(SESSION_EXPIRY)
                .map_err(|err| RegistryError::new(format!("open session expiry failed: {err}")))?;
            let mut due = Vec::new();
            for entry in expiry
                .iter()
                .map_err(|err| RegistryError::new(format!("scan session expiry failed: {err}")))?
            {
                let (key, token_hash) = entry.map_err(|err| {
                    RegistryError::new(format!("read session expiry failed: {err}"))
                })?;
                let expires_at = expiry_timestamp(key.value())?;
                if expires_at > now {
                    break;
                }
                let token_hash = std::str::from_utf8(token_hash.value())
                    .map_err(|_| RegistryError::new("stored session token hash is not utf-8"))?;
                due.push((
                    key.value().to_string(),
                    expiry_subject(key.value())?.to_string(),
                    token_hash.to_string(),
                    expires_at,
                ));
                if removed + due.len() >= limit {
                    break;
                }
            }
            let mut sessions = tx.open_table(ACCOUNT_SESSIONS).map_err(|err| {
                RegistryError::new(format!("open account sessions failed: {err}"))
            })?;
            let mut index = tx
                .open_table(SESSION_INDEX)
                .map_err(|err| RegistryError::new(format!("open session index failed: {err}")))?;
            for (index_key, account, token_hash, expires_at) in due {
                let current = sessions
                    .get(account.as_str())
                    .map_err(|err| {
                        RegistryError::new(format!("read session during cleanup failed: {err}"))
                    })?
                    .map(|value| decode_json::<Session>(value.value()))
                    .transpose()?;
                if current.as_ref().is_some_and(|session| {
                    session.token_hash == token_hash && session.expires_at == expires_at
                }) {
                    sessions.remove(account.as_str()).map_err(|err| {
                        RegistryError::new(format!("remove expired session failed: {err}"))
                    })?;
                    index.remove(token_hash.as_str()).map_err(|err| {
                        RegistryError::new(format!("remove expired session index failed: {err}"))
                    })?;
                }
                expiry.remove(index_key.as_str()).map_err(|err| {
                    RegistryError::new(format!("remove session expiry failed: {err}"))
                })?;
                removed += 1;
            }
        }

        if removed < limit {
            let mut expiry = tx
                .open_table(RATE_EXPIRY)
                .map_err(|err| RegistryError::new(format!("open rate expiry failed: {err}")))?;
            let mut due = Vec::new();
            for entry in expiry
                .iter()
                .map_err(|err| RegistryError::new(format!("scan rate expiry failed: {err}")))?
            {
                let (key, _) = entry
                    .map_err(|err| RegistryError::new(format!("read rate expiry failed: {err}")))?;
                let expires_at = expiry_timestamp(key.value())?;
                if expires_at > now {
                    break;
                }
                due.push((
                    key.value().to_string(),
                    expiry_subject(key.value())?.to_string(),
                    expires_at,
                ));
                if removed + due.len() >= limit {
                    break;
                }
            }
            let mut rates = tx
                .open_table(RATES)
                .map_err(|err| RegistryError::new(format!("open rates failed: {err}")))?;
            for (index_key, rate_key, expires_at) in due {
                let current = rates
                    .get(rate_key.as_str())
                    .map_err(|err| {
                        RegistryError::new(format!("read rate during cleanup failed: {err}"))
                    })?
                    .map(|value| decode_json::<RateLimitBucket>(value.value()))
                    .transpose()?;
                if current
                    .as_ref()
                    .is_some_and(|bucket| bucket.expires_at == expires_at)
                {
                    rates.remove(rate_key.as_str()).map_err(|err| {
                        RegistryError::new(format!("remove expired rate failed: {err}"))
                    })?;
                }
                expiry.remove(index_key.as_str()).map_err(|err| {
                    RegistryError::new(format!("remove rate expiry failed: {err}"))
                })?;
                removed += 1;
            }
        }

        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit cleanup failed: {err}")))?;
        Ok(removed)
    }
}

fn expiry_key(expires_at: i64, subject: &str) -> String {
    format!("{:020}:{subject}", expires_at.max(0) as u64)
}

fn expiry_timestamp(key: &str) -> Result<i64> {
    let (timestamp, _) = key
        .split_once(':')
        .ok_or_else(|| RegistryError::new("invalid expiry index key"))?;
    timestamp
        .parse::<i64>()
        .map_err(|_| RegistryError::new("invalid expiry index timestamp"))
}

fn expiry_subject(key: &str) -> Result<&str> {
    let (_, subject) = key
        .split_once(':')
        .ok_or_else(|| RegistryError::new("invalid expiry index key"))?;
    if subject.is_empty() {
        return Err(RegistryError::new("empty expiry index subject"));
    }
    Ok(subject)
}

fn login_key(kind: LoginIdentityKind, hash: &LoginIdentityHash) -> String {
    key(&["login", kind.as_str(), hash.as_str()])
}

fn blob_key(account_id: &AccountId, kind: AccountBlobKind) -> String {
    key(&["blob", account_id.as_str(), kind.as_str()])
}
