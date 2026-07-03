//! A thin HTTP client for the directory (login, publish, lookup).

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use mycellium_core::identity::{Handle, Identity, Signature, WalletPublicKey};
use mycellium_core::record::SignedRecord;

/// Talks to a running `mycellium-directory` over HTTP.
pub struct DirectoryClient {
    base: String,
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
        ureq::request("PUT", &format!("{}/records/{}", self.base, handle.as_str()))
            .set("Authorization", &format!("Bearer {token}"))
            .send_json(record)
            .context("publish request failed")?;
        Ok(())
    }

    /// Look up the signed record for `handle`.
    pub fn lookup(&self, handle: &Handle) -> Result<SignedRecord> {
        let record: SignedRecord = ureq::get(&format!("{}/records/{}", self.base, handle.as_str()))
            .call()
            .map_err(|e| anyhow!("lookup failed: {e}"))?
            .into_json()?;
        Ok(record)
    }

    /// Deposit an opaque envelope blob into `handle`'s offline mailbox.
    /// (Transitional: the mailbox is moving to `mycellium-queue`.)
    pub fn deposit(&self, token: &str, handle: &Handle, slot: &str, blob: &str) -> Result<()> {
        ureq::post(&format!("{}/mailbox/{}/{}", self.base, handle.as_str(), slot))
            .set("Authorization", &format!("Bearer {token}"))
            .send_string(blob)
            .context("deposit failed")?;
        Ok(())
    }

    /// Announce that we're online (heartbeat).
    pub fn announce(&self, token: &str, handle: &Handle) -> Result<()> {
        ureq::post(&format!("{}/presence/{}", self.base, handle.as_str()))
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
        let resp: Presence = ureq::get(&format!("{}/presence/{}", self.base, handle.as_str()))
            .call()
            .map_err(|e| anyhow!("presence query failed: {e}"))?
            .into_json()?;
        Ok(resp.online)
    }

    /// Drain one slot of this identity's offline mailbox.
    /// (Transitional: the mailbox is moving to `mycellium-queue`.)
    pub fn collect(&self, token: &str, handle: &Handle, slot: &str) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct Messages {
            messages: Vec<String>,
        }
        let resp: Messages = ureq::get(&format!("{}/mailbox/{}/{}", self.base, handle.as_str(), slot))
            .set("Authorization", &format!("Bearer {token}"))
            .call()
            .map_err(|e| anyhow!("collect failed: {e}"))?
            .into_json()?;
        Ok(resp.messages)
    }
}
