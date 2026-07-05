//! A thin HTTP client for the message queue (login, deposit, collect).
//!
//! The queue is keyed by **wallet**, not handle: you deposit a blob for a
//! recipient wallet, and you may only collect your own. Separate from the
//! directory client, because the queue is a separate service.
//!
//! The HTTP transport is injectable (native `ureq` by default; browser `fetch`
//! otherwise), so this logic is shared across native and WebAssembly.

use anyhow::{anyhow, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use mycellium_core::http::{HttpResponse, HttpTransport};
use mycellium_core::identity::{Identity, Signature, WalletPublicKey};

/// Talks to a running `mycellium-queue` over HTTP.
pub struct QueueClient {
    base: String,
    transport: Box<dyn HttpTransport>,
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
    /// Point the client at a queue base URL using the native `ureq` transport,
    /// e.g. `http://127.0.0.1:8090`.
    #[cfg(feature = "native")]
    pub fn new(base: impl Into<String>) -> Self {
        Self::with_transport(base, Box::new(mycellium_http::UreqTransport))
    }

    /// Point the client at a base URL with an explicit HTTP transport (browser).
    pub fn with_transport(base: impl Into<String>, transport: Box<dyn HttpTransport>) -> Self {
        QueueClient {
            base: base.into().trim_end_matches('/').to_string(),
            transport,
        }
    }

    /// SIWE-style login: fetch a challenge, sign it, exchange for a token.
    pub fn login(&self, identity: &Identity) -> Result<String> {
        let wallet = identity.wallet_public();
        let challenge: ChallengeResp = self.json(
            "POST",
            "/login/challenge",
            None,
            Some(&ChallengeReq { wallet }),
        )?;
        let signature = identity.sign(&mycellium_core::login::challenge_message(&challenge.nonce));
        let verified: VerifyResp = self.json(
            "POST",
            "/login/verify",
            None,
            Some(&VerifyReq {
                wallet,
                nonce: challenge.nonce,
                signature,
            }),
        )?;
        Ok(verified.token)
    }

    /// Deposit an opaque blob into `recipient_wallet_hex`'s mailbox `slot`.
    pub fn deposit(
        &self,
        token: &str,
        recipient_wallet_hex: &str,
        slot: &str,
        blob: &str,
    ) -> Result<()> {
        let path = format!("/mailbox/{recipient_wallet_hex}/{slot}");
        self.call(
            "POST",
            &path,
            Some(token),
            Some("text/plain; charset=utf-8"),
            Some(blob.as_bytes()),
        )?;
        Ok(())
    }

    /// The queue's VAPID public key (for the browser's `applicationServerKey`).
    pub fn push_key(&self) -> Result<String> {
        #[derive(Deserialize)]
        struct Resp {
            key: String,
        }
        let resp: Resp = self.json::<(), _>("GET", "/push/key", None, None)?;
        Ok(resp.key)
    }

    /// Register a browser push endpoint for the logged-in wallet.
    pub fn push_subscribe(&self, token: &str, endpoint: &str) -> Result<()> {
        #[derive(Serialize)]
        struct Req<'a> {
            endpoint: &'a str,
        }
        let _: serde_json::Value = self.json(
            "POST",
            "/push/subscribe",
            Some(token),
            Some(&Req { endpoint }),
        )?;
        Ok(())
    }

    /// Drain one slot of your own (`wallet_hex`) mailbox.
    pub fn collect(&self, token: &str, wallet_hex: &str, slot: &str) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct Messages {
            messages: Vec<String>,
        }
        let resp: Messages = self.json::<(), _>(
            "GET",
            &format!("/mailbox/{wallet_hex}/{slot}"),
            Some(token),
            None,
        )?;
        Ok(resp.messages)
    }

    /// Relay a sealed pairing message into rendezvous `rid` (unauthenticated —
    /// the id is the capability, the payload is end-to-end sealed).
    pub fn pair_post(&self, rid: &str, msg: &str) -> Result<()> {
        #[derive(Serialize)]
        struct Req<'a> {
            msg: &'a str,
        }
        let _: serde_json::Value =
            self.json("POST", &format!("/pair/{rid}"), None, Some(&Req { msg }))?;
        Ok(())
    }

    /// Drain any pairing messages relayed to rendezvous `rid`.
    pub fn pair_fetch(&self, rid: &str) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct Resp {
            msgs: Vec<String>,
        }
        let resp: Resp = self.json::<(), _>("GET", &format!("/pair/{rid}"), None, None)?;
        Ok(resp.msgs)
    }

    fn json<B: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&B>,
    ) -> Result<R> {
        let payload = body.map(serde_json::to_vec).transpose()?;
        let content_type = payload.as_ref().map(|_| "application/json");
        let resp = self.call(method, path, token, content_type, payload.as_deref())?;
        serde_json::from_slice(&resp.body).map_err(|e| anyhow!("bad response from {path}: {e}"))
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse> {
        let url = format!("{}{path}", self.base);
        let auth = token.map(|t| format!("Bearer {t}"));
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(ct) = content_type {
            headers.push(("Content-Type", ct));
        }
        if let Some(a) = &auth {
            headers.push(("Authorization", a));
        }
        let resp = self
            .transport
            .request(method, &url, &headers, body)
            .map_err(|e| anyhow!("{path}: {e}"))?;
        if resp.status >= 400 {
            return Err(anyhow!("{path}: HTTP {}", resp.status));
        }
        Ok(resp)
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
