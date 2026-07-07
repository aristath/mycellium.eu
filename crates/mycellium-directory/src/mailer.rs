//! Verification-code email delivery (Tier 0.4).
//!
//! Sends the signup/recovery code by **real SMTP** when configured (self-hosted;
//! never a US email/SMS gateway). Development auth is an explicit config mode
//! that logs and returns the code so local testing needs no inbox.

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

/// Email-auth delivery mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthConfig {
    /// Development mode: log and return the verification code.
    Dev,
    /// Production mode: send the code through SMTP.
    Smtp(SmtpConfig),
}

/// SMTP settings for verification-code delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub from: String,
    pub user: Option<String>,
    pub pass: Option<String>,
}

/// Deliver a verification code to `to`. Best-effort — logs on failure so a
/// flaky SMTP server never fails the request path (the caller can resend).
pub fn send_verification(config: &AuthConfig, to: &str, code: &str) {
    match config {
        AuthConfig::Dev => {
            tracing::info!(%to, %code, "dev verification code (dev auth mode)");
        }
        AuthConfig::Smtp(smtp) => {
            if let Err(e) = smtp_send(smtp, to, code) {
                tracing::warn!(%to, error = %e, "verification email delivery failed");
            }
        }
    }
}

fn smtp_send(config: &SmtpConfig, to: &str, code: &str) -> Result<(), String> {
    let email = Message::builder()
        .from(config.from.parse().map_err(|_| "bad SMTP from address")?)
        .to(to.parse().map_err(|_| "bad recipient address")?)
        .subject("Your Mycellium verification code")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "Your Mycellium verification code is:\n\n    {code}\n\nIt expires in 15 minutes. If you didn't request this, ignore this email."
        ))
        .map_err(|e| e.to_string())?;

    // Port 465 = implicit TLS; anything else = STARTTLS (587).
    let transport = if config.port == 465 {
        SmtpTransport::relay(&config.host).map_err(|e| e.to_string())?
    } else {
        SmtpTransport::starttls_relay(&config.host).map_err(|e| e.to_string())?
    };
    let mut builder = transport.port(config.port);
    if let (Some(user), Some(pass)) = (&config.user, &config.pass) {
        builder = builder.credentials(Credentials::new(user.clone(), pass.clone()));
    }
    builder.build().send(&email).map_err(|e| e.to_string())?;
    Ok(())
}
