//! A thin HTTP client for the message queue (login, deposit, collect).
//!
//! The queue is keyed by **wallet**, not handle: you deposit a blob for a
//! recipient wallet, and you may only collect your own. Separate from the
//! directory client, because the queue is a separate service.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use mycellium_core::identity::{Identity, Signature, WalletPublicKey};

/// Talks to a running `mycellium-queue` over HTTP.
pub struct QueueClient {
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

impl QueueClient {
    /// Point the client at a queue base URL, e.g. `http://127.0.0.1:8090`.
    pub fn new(base: impl Into<String>) -> Self {
        QueueClient { base: base.into().trim_end_matches('/').to_string() }
    }

    /// SIWE-style login: fetch a challenge, sign it, exchange for a token.
    pub fn login(&self, identity: &Identity) -> Result<String> {
        let wallet = identity.wallet_public();
        let challenge: ChallengeResp = ureq::post(&format!("{}/login/challenge", self.base))
            .send_json(ChallengeReq { wallet })
            .context("queue challenge failed")?
            .into_json()?;
        let signature = identity.sign(&mycellium_core::login::challenge_message(&challenge.nonce));
        let verified: VerifyResp = ureq::post(&format!("{}/login/verify", self.base))
            .send_json(VerifyReq { wallet, nonce: challenge.nonce, signature })
            .context("queue verify failed")?
            .into_json()?;
        Ok(verified.token)
    }

    /// Deposit an opaque blob into `recipient_wallet_hex`'s mailbox `slot`.
    pub fn deposit(&self, token: &str, recipient_wallet_hex: &str, slot: &str, blob: &str) -> Result<()> {
        ureq::post(&format!("{}/mailbox/{}/{}", self.base, recipient_wallet_hex, slot))
            .set("Authorization", &format!("Bearer {token}"))
            .send_string(blob)
            .context("queue deposit failed")?;
        Ok(())
    }

    /// Drain one slot of your own (`wallet_hex`) mailbox.
    pub fn collect(&self, token: &str, wallet_hex: &str, slot: &str) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct Messages {
            messages: Vec<String>,
        }
        let resp: Messages = ureq::get(&format!("{}/mailbox/{}/{}", self.base, wallet_hex, slot))
            .set("Authorization", &format!("Bearer {token}"))
            .call()
            .map_err(|e| anyhow!("queue collect failed: {e}"))?
            .into_json()?;
        Ok(resp.messages)
    }
}

/// Lowercase hex of a compressed wallet key — the queue's mailbox key.
pub fn wallet_hex(wallet: &WalletPublicKey) -> String {
    let mut out = String::with_capacity(66);
    for b in wallet.0 {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    out
}
