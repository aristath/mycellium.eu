//! A thin HTTP client for the directory (login, publish, lookup).

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use mycellium_core::identity::{Handle, Identity, Signature, WalletPublicKey};
use mycellium_core::record::SignedRecord;
use mycellium_core::userid::user_id;

/// Talks to a running `mycellium-directory` over HTTP.
///
/// This adapter is the single boundary where a **plaintext username becomes a
/// directory id**: every handle is hashed with [`user_id`] before it goes on the
/// wire, so the directory only ever sees and stores opaque ids — never a name.
pub struct DirectoryClient {
    base: String,
}

/// The directory id (hash) for a plaintext handle.
fn id(handle: &Handle) -> String {
    user_id(handle.as_str()).as_str().to_string()
}

#[derive(Serialize)]
struct ChallengeReq {
    wallet: WalletPublicKey,
}

#[derive(Deserialize)]
struct ChallengeResp {
    nonce: String,
}

#[derive(Serialize)]
struct VerifyReq {
    wallet: WalletPublicKey,
    nonce: String,
    signature: Signature,
}

#[derive(Deserialize)]
struct VerifyResp {
    token: String,
}

impl DirectoryClient {
    /// Point the client at a directory base URL, e.g. `http://127.0.0.1:8080`.
    pub fn new(base: impl Into<String>) -> Self {
        DirectoryClient {
            base: base.into().trim_end_matches('/').to_string(),
        }
    }

    /// Full SIWE-style login: fetch a challenge, sign it, exchange for a token.
    pub fn login(&self, identity: &Identity) -> Result<String> {
        let wallet = identity.wallet_public();

        let challenge: ChallengeResp = ureq::post(&format!("{}/login/challenge", self.base))
            .send_json(ChallengeReq { wallet })
            .context("challenge request failed")?
            .into_json()?;

        let signature = identity.sign(&mycellium_core::login::challenge_message(&challenge.nonce));

        let verified: VerifyResp = ureq::post(&format!("{}/login/verify", self.base))
            .send_json(VerifyReq {
                wallet,
                nonce: challenge.nonce,
                signature,
            })
            .context("verify request failed")?
            .into_json()?;

        Ok(verified.token)
    }

    /// Publish a signed record under `handle` using a session `token`.
    pub fn publish(&self, token: &str, handle: &Handle, record: &SignedRecord) -> Result<()> {
        ureq::request("PUT", &format!("{}/records/{}", self.base, id(handle)))
            .set("Authorization", &format!("Bearer {token}"))
            .send_json(record)
            .context("publish request failed")?;
        Ok(())
    }

    /// Look up the signed record for `handle`.
    pub fn lookup(&self, handle: &Handle) -> Result<SignedRecord> {
        let record: SignedRecord = ureq::get(&format!("{}/records/{}", self.base, id(handle)))
            .call()
            .map_err(|e| anyhow!("lookup failed: {e}"))?
            .into_json()?;
        Ok(record)
    }

    /// Begin an email-verified username claim. Returns `(pending_token,
    /// dev_code)` — `dev_code` is set only when the directory runs in dev mode
    /// (no SMTP), so the local flow works without a real inbox.
    pub fn auth_start(&self, token: &str, username: &str, email: &str) -> Result<(String, Option<String>)> {
        #[derive(Serialize)]
        struct Req<'a> {
            username: &'a str,
            email: &'a str,
        }
        #[derive(Deserialize)]
        struct Resp {
            pending: String,
            dev_code: Option<String>,
        }
        // The directory binds the *id*, never the plaintext username.
        let uid = user_id(username);
        let resp: Resp = ureq::post(&format!("{}/auth/start", self.base))
            .set("Authorization", &format!("Bearer {token}"))
            .send_json(Req { username: uid.as_str(), email })
            .map_err(|e| anyhow!("auth start failed: {e}"))?
            .into_json()?;
        Ok((resp.pending, resp.dev_code))
    }

    /// Confirm a verification code (typed or from the one-tap link). Returns the
    /// verified username.
    pub fn auth_confirm(&self, pending: &str, code: &str) -> Result<String> {
        #[derive(Serialize)]
        struct Req<'a> {
            pending: &'a str,
            code: &'a str,
        }
        #[derive(Deserialize)]
        struct Resp {
            username: String,
        }
        let resp: Resp = ureq::post(&format!("{}/auth/confirm", self.base))
            .send_json(Req { pending, code })
            .map_err(|e| anyhow!("verification failed: {e}"))?
            .into_json()?;
        Ok(resp.username)
    }

    /// Poll a pending claim: `(verified, username)`.
    pub fn auth_status(&self, pending: &str) -> Result<(bool, String)> {
        #[derive(Serialize)]
        struct Req<'a> {
            pending: &'a str,
        }
        #[derive(Deserialize)]
        struct Resp {
            verified: bool,
            username: String,
        }
        let resp: Resp = ureq::post(&format!("{}/auth/status", self.base))
            .send_json(Req { pending })
            .map_err(|e| anyhow!("status check failed: {e}"))?
            .into_json()?;
        Ok((resp.verified, resp.username))
    }

    /// Announce that we're online (heartbeat).
    pub fn announce(&self, token: &str, handle: &Handle) -> Result<()> {
        ureq::post(&format!("{}/presence/{}", self.base, id(handle)))
            .set("Authorization", &format!("Bearer {token}"))
            .call()
            .context("presence heartbeat failed")?;
        Ok(())
    }

    /// Query whether a handle is currently online.
    pub fn presence(&self, handle: &Handle) -> Result<bool> {
        #[derive(Deserialize)]
        struct Presence {
            online: bool,
        }
        let resp: Presence = ureq::get(&format!("{}/presence/{}", self.base, id(handle)))
            .call()
            .map_err(|e| anyhow!("presence query failed: {e}"))?
            .into_json()?;
        Ok(resp.online)
    }

}
