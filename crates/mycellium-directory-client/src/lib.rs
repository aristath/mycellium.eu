//! A thin HTTP client for the directory (login, publish, lookup).
//!
//! The HTTP transport is injectable: native builds use `ureq` (the `native`
//! feature, on by default); the browser build injects a `fetch`/XHR transport.
//! The request logic here is identical across both.

use anyhow::{anyhow, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use mycellium_core::http::{HttpResponse, HttpTransport};
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
    transport: Box<dyn HttpTransport>,
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
    /// Point the client at a directory base URL using the native `ureq`
    /// transport, e.g. `http://127.0.0.1:8080`.
    #[cfg(feature = "native")]
    pub fn new(base: impl Into<String>) -> Self {
        Self::with_transport(base, Box::new(mycellium_http::UreqTransport))
    }

    /// Point the client at a base URL with an explicit HTTP transport (used by
    /// the browser/WASM build).
    pub fn with_transport(base: impl Into<String>, transport: Box<dyn HttpTransport>) -> Self {
        DirectoryClient {
            base: base.into().trim_end_matches('/').to_string(),
            transport,
        }
    }

    /// Full SIWE-style login: fetch a challenge, sign it, exchange for a token.
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

    /// Publish a signed record under `handle` using a session `token`.
    pub fn publish(&self, token: &str, handle: &Handle, record: &SignedRecord) -> Result<()> {
        let payload = serde_json::to_vec(record)?;
        self.call(
            "PUT",
            &format!("/records/{}", id(handle)),
            Some(token),
            Some("application/json"),
            Some(&payload),
        )?;
        Ok(())
    }

    /// Look up the signed record for `handle`.
    pub fn lookup(&self, handle: &Handle) -> Result<SignedRecord> {
        self.json::<(), _>("GET", &format!("/records/{}", id(handle)), None, None)
    }

    /// Begin an email-verified username claim. Returns `(pending_token,
    /// dev_code)` — `dev_code` is set only when the directory runs in dev mode
    /// (no SMTP), so the local flow works without a real inbox.
    pub fn auth_start(
        &self,
        token: &str,
        username: &str,
        email: &str,
    ) -> Result<(String, Option<String>)> {
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
        let resp: Resp = self.json(
            "POST",
            "/auth/start",
            Some(token),
            Some(&Req {
                username: uid.as_str(),
                email,
            }),
        )?;
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
        let resp: Resp = self.json("POST", "/auth/confirm", None, Some(&Req { pending, code }))?;
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
        let resp: Resp = self.json("POST", "/auth/status", None, Some(&Req { pending }))?;
        Ok((resp.verified, resp.username))
    }

    /// Announce that we're online (heartbeat).
    pub fn announce(&self, token: &str, handle: &Handle) -> Result<()> {
        self.call(
            "POST",
            &format!("/presence/{}", id(handle)),
            Some(token),
            None,
            None,
        )?;
        Ok(())
    }

    /// Query whether a handle is currently online.
    pub fn presence(&self, handle: &Handle) -> Result<bool> {
        #[derive(Deserialize)]
        struct Presence {
            online: bool,
        }
        let resp: Presence =
            self.json::<(), _>("GET", &format!("/presence/{}", id(handle)), None, None)?;
        Ok(resp.online)
    }

    /// Perform a request and parse a JSON response body.
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

    /// Perform a request, returning the raw response (error on HTTP >= 400).
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
