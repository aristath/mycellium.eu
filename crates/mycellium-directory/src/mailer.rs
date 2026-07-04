//! Verification-code email delivery (Tier 0.4).
//!
//! Sends the signup/recovery code by **real SMTP** when configured (self-hosted;
//! never a US email/SMS gateway), otherwise a **dev fallback** that logs the code
//! — the HTTP layer also returns it in dev mode so local testing needs no inbox.
//!
//! Configure via env:
//! - `MYCELLIUM_SMTP_HOST` (set = production mode), `MYCELLIUM_SMTP_PORT`
//!   (default 587; 465 uses implicit TLS), `MYCELLIUM_SMTP_FROM`
//!   (e.g. `Mycellium <noreply@example.com>`), `MYCELLIUM_SMTP_USER`,
//!   `MYCELLIUM_SMTP_PASS`.

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

/// Dev mode = no SMTP configured. In dev the code is logged and returned to the
/// caller instead of emailed.
pub fn is_dev() -> bool {
    std::env::var("MYCELLIUM_SMTP_HOST").map(|h| h.trim().is_empty()).unwrap_or(true)
}

/// Deliver a verification code to `to`. Best-effort — logs on failure so a
/// flaky SMTP server never fails the request path (the caller can resend).
pub fn send_verification(to: &str, code: &str) {
    if is_dev() {
        eprintln!("[mycellium-directory] verification code for {to}: {code}");
        return;
    }
    if let Err(e) = smtp_send(to, code) {
        eprintln!("[mycellium-directory] email to {to} failed: {e}");
    }
}

fn smtp_send(to: &str, code: &str) -> Result<(), String> {
    let host = env("MYCELLIUM_SMTP_HOST").ok_or("no MYCELLIUM_SMTP_HOST")?;
    let from = env("MYCELLIUM_SMTP_FROM").ok_or("no MYCELLIUM_SMTP_FROM")?;
    let port: u16 = env("MYCELLIUM_SMTP_PORT").and_then(|p| p.parse().ok()).unwrap_or(587);

    let email = Message::builder()
        .from(from.parse().map_err(|_| "bad MYCELLIUM_SMTP_FROM")?)
        .to(to.parse().map_err(|_| "bad recipient address")?)
        .subject("Your Mycellium verification code")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "Your Mycellium verification code is:\n\n    {code}\n\nIt expires in 15 minutes. If you didn't request this, ignore this email."
        ))
        .map_err(|e| e.to_string())?;

    // Port 465 = implicit TLS; anything else = STARTTLS (587).
    let transport = if port == 465 {
        SmtpTransport::relay(&host).map_err(|e| e.to_string())?
    } else {
        SmtpTransport::starttls_relay(&host).map_err(|e| e.to_string())?
    };
    let mut builder = transport.port(port);
    if let (Some(user), Some(pass)) = (env("MYCELLIUM_SMTP_USER"), env("MYCELLIUM_SMTP_PASS")) {
        builder = builder.credentials(Credentials::new(user, pass));
    }
    builder.build().send(&email).map_err(|e| e.to_string())?;
    Ok(())
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}
