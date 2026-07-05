//! Verification-code email delivery (Tier 0.4).
//!
//! Sends the signup/recovery code by **real SMTP** when configured (self-hosted;
//! never a US email/SMS gateway). An **explicit** dev fallback (`MYCELLIUM_DEV_AUTH=1`)
//! logs the code — the HTTP layer also returns it in that mode so local testing
//! needs no inbox. Startup fails closed if neither is set (issue #47), so a
//! production SMTP misconfiguration can't silently enable the dev path.
//!
//! Configure via env:
//! - `MYCELLIUM_SMTP_HOST` (set = production mode), `MYCELLIUM_SMTP_PORT`
//!   (default 587; 465 uses implicit TLS), `MYCELLIUM_SMTP_FROM`
//!   (e.g. `Mycellium <noreply@example.com>`), `MYCELLIUM_SMTP_USER`,
//!   `MYCELLIUM_SMTP_PASS`.

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

/// **Explicit** development auth mode: `MYCELLIUM_DEV_AUTH=1`. In this mode the
/// verification code is logged and returned to the caller, so local testing needs
/// no inbox. It must be turned on deliberately — a missing SMTP config alone no
/// longer silently enables it, so a production misconfiguration fails closed
/// rather than quietly weakening auth (issue #47).
pub fn is_dev() -> bool {
    std::env::var("MYCELLIUM_DEV_AUTH")
        .map(|v| v.trim() == "1")
        .unwrap_or(false)
}

/// Whether real SMTP delivery is configured (a non-empty host).
pub fn smtp_configured() -> bool {
    std::env::var("MYCELLIUM_SMTP_HOST")
        .map(|h| !h.trim().is_empty())
        .unwrap_or(false)
}

/// Validate the email-auth configuration at startup: either real SMTP is
/// configured (production), or explicit dev mode is on. Neither is a
/// misconfiguration that would silently run the dev auth path, so fail closed.
pub fn require_valid_config() -> Result<(), String> {
    valid_config(smtp_configured(), is_dev())
}

/// The env-free decision: config is valid iff SMTP is set or dev mode is explicit.
fn valid_config(smtp: bool, dev: bool) -> Result<(), String> {
    if smtp || dev {
        Ok(())
    } else {
        Err(
            "email auth is not configured: set MYCELLIUM_SMTP_HOST for production, \
             or MYCELLIUM_DEV_AUTH=1 for local development"
                .into(),
        )
    }
}

/// Deliver a verification code to `to`. Best-effort — logs on failure so a
/// flaky SMTP server never fails the request path (the caller can resend).
pub fn send_verification(to: &str, code: &str) {
    if is_dev() {
        eprintln!("[mycellium-directory] DEV verification code for {to}: {code}");
        return;
    }
    if !smtp_configured() {
        // Startup validation should prevent reaching here; fail loudly, never
        // silently drop to a dev-style path.
        eprintln!("[mycellium-directory] cannot email {to}: SMTP unconfigured and dev mode off");
        return;
    }
    if let Err(e) = smtp_send(to, code) {
        eprintln!("[mycellium-directory] email to {to} failed: {e}");
    }
}

fn smtp_send(to: &str, code: &str) -> Result<(), String> {
    let host = env("MYCELLIUM_SMTP_HOST").ok_or("no MYCELLIUM_SMTP_HOST")?;
    let from = env("MYCELLIUM_SMTP_FROM").ok_or("no MYCELLIUM_SMTP_FROM")?;
    let port: u16 = env("MYCELLIUM_SMTP_PORT")
        .and_then(|p| p.parse().ok())
        .unwrap_or(587);

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

#[cfg(test)]
mod tests {
    use super::valid_config;

    #[test]
    fn config_is_valid_only_with_smtp_or_explicit_dev() {
        assert!(valid_config(true, false).is_ok()); // production SMTP
        assert!(valid_config(false, true).is_ok()); // explicit dev mode
        assert!(valid_config(true, true).is_ok());
        // Neither: a misconfiguration must fail closed, not run dev auth silently.
        assert!(valid_config(false, false).is_err());
    }
}
