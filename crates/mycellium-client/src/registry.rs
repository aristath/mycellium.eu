//! Small native client for registry account UX.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use mycellium_core::record::SignedRecord;
use mycellium_core::userid::UserId;
use mycellium_core::wire;
use serde::{Deserialize, Serialize};
use ureq::{Agent, Error};
use zeroize::Zeroize;

/// Production registry used unless a native shell overrides it.
pub const DEFAULT_REGISTRY_URL: &str = "https://registry.mycellium.eu";
pub const LOGIN_LINK_PREFIX: &str = "mycellium://login?";

/// Extract the one-time token from a Mycellium login link.
pub fn login_token_from_link(link: &str) -> Result<String> {
    let query = link
        .trim()
        .strip_prefix(LOGIN_LINK_PREFIX)
        .ok_or_else(|| anyhow!("invalid Mycellium login link"))?;
    let tokens: Vec<&str> = query
        .split('&')
        .filter_map(|part| part.strip_prefix("token="))
        .collect();
    let [token] = tokens.as_slice() else {
        bail!("invalid Mycellium login link");
    };
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid Mycellium login link");
    }
    Ok(token.to_ascii_lowercase())
}

/// A registry session issued after a login identity is verified.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySession {
    pub registry_url: String,
    pub account_id: String,
    pub session_token: String,
    pub session_expires_at: i64,
}

impl RegistrySession {
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.session_expires_at
    }
}

/// Result of confirming a one-time login code.
#[derive(Clone, PartialEq, Eq)]
pub struct ConfirmedLogin {
    pub session: RegistrySession,
    pub created: bool,
}

#[derive(Clone)]
pub struct RegistryClient {
    base_url: String,
    agent: Agent,
}

impl RegistryClient {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into().trim().trim_end_matches('/').to_string();
        if !(base_url.starts_with("https://") || base_url.starts_with("http://")) {
            bail!("registry URL must start with https:// or http://");
        }
        let agent = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .build()
            .new_agent();
        Ok(Self { base_url, agent })
    }

    pub fn request_email_login(&self, email: &str) -> Result<i64> {
        #[derive(Serialize)]
        struct Request<'a> {
            email: &'a str,
        }
        #[derive(Deserialize)]
        struct Response {
            expires_at: i64,
        }

        let mut response = self
            .agent
            .post(format!("{}/login/email/request", self.base_url))
            .send_json(&Request { email })
            .map_err(|error| registry_error("request login email", error))?;
        let body: Response = response
            .body_mut()
            .read_json()
            .context("registry returned an invalid login response")?;
        Ok(body.expires_at)
    }

    pub fn confirm_login(&self, token: &str) -> Result<ConfirmedLogin> {
        #[derive(Serialize)]
        struct Request<'a> {
            token: &'a str,
        }
        #[derive(Deserialize)]
        struct Response {
            account_id: String,
            created: bool,
            session_token: String,
            session_expires_at: i64,
        }

        let mut response = self
            .agent
            .post(format!("{}/login/confirm", self.base_url))
            .send_json(&Request { token })
            .map_err(|error| registry_error("confirm login code", error))?;
        let body: Response = response
            .body_mut()
            .read_json()
            .context("registry returned an invalid account response")?;
        Ok(ConfirmedLogin {
            session: RegistrySession {
                registry_url: self.base_url.clone(),
                account_id: body.account_id,
                session_token: body.session_token,
                session_expires_at: body.session_expires_at,
            },
            created: body.created,
        })
    }

    pub fn put_recovery(&self, session: &RegistrySession, wallet_secret: &[u8; 32]) -> Result<()> {
        self.agent
            .put(self.account_url(session, "recovery")?)
            .header("authorization", &bearer(session))
            .send(&wallet_secret[..])
            .map_err(|error| registry_error("store identity recovery", error))?;
        Ok(())
    }

    pub fn get_recovery(&self, session: &RegistrySession) -> Result<Option<[u8; 32]>> {
        let mut response = match self
            .agent
            .get(self.account_url(session, "recovery")?)
            .header("authorization", &bearer(session))
            .call()
        {
            Ok(response) => response,
            Err(Error::StatusCode(404)) => return Ok(None),
            Err(error) => return Err(registry_error("load identity recovery", error)),
        };
        let mut bytes = response
            .body_mut()
            .with_config()
            .limit(64)
            .read_to_vec()
            .context("could not read identity recovery response")?;
        let secret = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("registry returned invalid identity recovery material"))?;
        bytes.zeroize();
        Ok(Some(secret))
    }

    pub fn put_record(&self, session: &RegistrySession, record: &SignedRecord) -> Result<()> {
        self.agent
            .put(self.account_url(session, "record")?)
            .header("authorization", &bearer(session))
            .send(wire::encode(record))
            .map_err(|error| registry_error("publish active device", error))?;
        Ok(())
    }

    pub fn get_record(&self, account_id: &str) -> Result<Option<SignedRecord>> {
        self.get_record_at(format!("{}/accounts/{account_id}/record", self.base_url))
    }

    /// Load the current signed record for a stable protocol user id.
    pub fn get_record_for_user(&self, user_id: &str) -> Result<Option<SignedRecord>> {
        let user_id =
            UserId::new(user_id.to_string()).map_err(|_| anyhow!("invalid protocol user id"))?;
        let record = self.get_record_at(format!(
            "{}/users/{}/record",
            self.base_url,
            user_id.as_str()
        ))?;
        if record
            .as_ref()
            .is_some_and(|record| record.record.user_id != user_id)
        {
            bail!("registry returned a record for another identity");
        }
        Ok(record)
    }

    fn get_record_at(&self, url: String) -> Result<Option<SignedRecord>> {
        let mut response = match self.agent.get(url).call() {
            Ok(response) => response,
            Err(Error::StatusCode(404)) => return Ok(None),
            Err(error) => return Err(registry_error("load active device", error)),
        };
        let bytes = response
            .body_mut()
            .with_config()
            .limit(1024 * 1024 + 1)
            .read_to_vec()
            .context("could not read active-device response")?;
        let record: SignedRecord = wire::decode(&bytes)
            .map_err(|_| anyhow!("registry returned an invalid signed record"))?;
        record
            .verify()
            .map_err(|_| anyhow!("registry returned a record with an invalid signature"))?;
        Ok(Some(record))
    }

    fn account_url(&self, session: &RegistrySession, suffix: &str) -> Result<String> {
        if session.registry_url.trim_end_matches('/') != self.base_url {
            bail!("registry session belongs to a different registry");
        }
        Ok(format!(
            "{}/accounts/{}/{suffix}",
            self.base_url, session.account_id
        ))
    }
}

fn bearer(session: &RegistrySession) -> String {
    format!("Bearer {}", session.session_token)
}

fn registry_error(action: &str, error: Error) -> anyhow::Error {
    let detail = match error {
        Error::StatusCode(400) => "the request was invalid",
        Error::StatusCode(401) => "your login expired; log in again",
        Error::StatusCode(403) => "this login belongs to another account",
        Error::StatusCode(404) => "the registry does not support this operation",
        Error::StatusCode(409) => "a newer or different identity is already active",
        Error::StatusCode(413) => "the request was too large",
        Error::StatusCode(429) => "too many attempts; wait before trying again",
        Error::StatusCode(_) => "the registry rejected the request",
        Error::Timeout(_) => "the registry took too long to respond",
        _ => "the registry could not be reached",
    };
    anyhow!("could not {action}: {detail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_expiry_is_inclusive() {
        let session = RegistrySession {
            registry_url: DEFAULT_REGISTRY_URL.into(),
            account_id: "a".into(),
            session_token: "secret".into(),
            session_expires_at: 10,
        };
        assert!(!session.is_expired(9));
        assert!(session.is_expired(10));
    }

    #[test]
    fn registry_url_is_normalized_once() {
        let client = RegistryClient::new("https://registry.example/").unwrap();
        assert_eq!(client.base_url, "https://registry.example");
        assert!(RegistryClient::new("registry.example").is_err());
    }

    #[test]
    fn login_links_accept_one_exact_token() {
        let token = "ab".repeat(32);
        assert_eq!(
            login_token_from_link(&format!("mycellium://login?token={token}")).unwrap(),
            token
        );
        assert!(login_token_from_link("https://example.test/?token=no").is_err());
        assert!(login_token_from_link(
            "mycellium://login?token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&token=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        .is_err());
    }
}
