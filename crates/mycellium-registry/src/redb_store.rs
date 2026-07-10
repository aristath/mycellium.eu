use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::{
    decode_json, encode_json, ensure_parent, key, Account, AccountBlobKind, AccountId,
    AccountLogin, BlobRef, LoginIdentity, LoginIdentityHash, LoginIdentityKind, LoginToken,
    RateLimitBucket, RegistryError, RegistryStore, Result, Session,
};

const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("accounts");
const LOGIN_INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("login_index");
const LOGIN_TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("login_tokens");
const BLOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("blobs");
const RATES: TableDefinition<&str, &[u8]> = TableDefinition::new("rates");
const SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("sessions");

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
            tx.open_table(BLOBS)
                .map_err(|err| RegistryError::new(format!("open blobs failed: {err}")))?;
            tx.open_table(RATES)
                .map_err(|err| RegistryError::new(format!("open rates failed: {err}")))?;
            tx.open_table(SESSIONS)
                .map_err(|err| RegistryError::new(format!("open sessions failed: {err}")))?;
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
        }
        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit login token failed: {err}")))
    }

    fn take_login_token(&self, token_hash: &str) -> Result<Option<LoginToken>> {
        let tx = self
            .db
            .begin_write()
            .map_err(|err| RegistryError::new(format!("begin write failed: {err}")))?;
        let token = {
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

    fn put_blob_ref(
        &self,
        account_id: &AccountId,
        kind: AccountBlobKind,
        blob: &BlobRef,
    ) -> Result<()> {
        let tx = self
            .db
            .begin_write()
            .map_err(|err| RegistryError::new(format!("begin write failed: {err}")))?;
        {
            let mut table = tx
                .open_table(BLOBS)
                .map_err(|err| RegistryError::new(format!("open blobs failed: {err}")))?;
            let blob_bytes = encode_json(blob)?;
            table
                .insert(blob_key(account_id, kind).as_str(), blob_bytes.as_slice())
                .map_err(|err| RegistryError::new(format!("write blob ref failed: {err}")))?;
        }
        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit blob ref failed: {err}")))
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

    fn put_session(&self, token_hash: &str, session: &Session) -> Result<()> {
        let tx = self
            .db
            .begin_write()
            .map_err(|err| RegistryError::new(format!("begin write failed: {err}")))?;
        {
            let mut table = tx
                .open_table(SESSIONS)
                .map_err(|err| RegistryError::new(format!("open sessions failed: {err}")))?;
            let session_bytes = encode_json(session)?;
            table
                .insert(token_hash, session_bytes.as_slice())
                .map_err(|err| RegistryError::new(format!("write session failed: {err}")))?;
        }
        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit session failed: {err}")))
    }

    fn session(&self, token_hash: &str) -> Result<Option<Session>> {
        let tx = self
            .db
            .begin_read()
            .map_err(|err| RegistryError::new(format!("begin read failed: {err}")))?;
        let table = tx
            .open_table(SESSIONS)
            .map_err(|err| RegistryError::new(format!("open sessions failed: {err}")))?;
        let Some(value) = table
            .get(token_hash)
            .map_err(|err| RegistryError::new(format!("read session failed: {err}")))?
        else {
            return Ok(None);
        };
        Ok(Some(decode_json(value.value())?))
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
            next
        };
        tx.commit()
            .map_err(|err| RegistryError::new(format!("commit rate failed: {err}")))?;
        Ok(bucket)
    }
}

fn login_key(kind: LoginIdentityKind, hash: &LoginIdentityHash) -> String {
    key(&["login", kind.as_str(), hash.as_str()])
}

fn blob_key(account_id: &AccountId, kind: AccountBlobKind) -> String {
    key(&["blob", account_id.as_str(), kind.as_str()])
}
