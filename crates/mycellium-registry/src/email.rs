//! Email delivery for registry login tokens.
//!
//! The registry only needs one thing from email: deliver a short-lived login
//! token after the account owner proves control of a login identity.

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde::Serialize;

use crate::http::EmailLoginSender;
use crate::{RegistryError, Result};

const DEFAULT_SUBJECT: &str = "Your Mycellium login code";

/// Email sender selected from registry configuration.
pub enum ConfiguredEmailSender {
    /// Print login tokens to stderr for local development.
    Log(LogEmailLoginSender),
    /// Send login tokens through Brevo's transactional email API.
    Brevo(BrevoEmailLoginSender),
    /// Send login tokens through a generic SMTP server.
    Smtp(SmtpEmailLoginSender),
}

impl EmailLoginSender for ConfiguredEmailSender {
    fn send_login_token(&self, email: &str, token: &str, expires_at: i64) -> Result<()> {
        match self {
            Self::Log(sender) => sender.send_login_token(email, token, expires_at),
            Self::Brevo(sender) => sender.send_login_token(email, token, expires_at),
            Self::Smtp(sender) => sender.send_login_token(email, token, expires_at),
        }
    }
}

/// Development sender that logs tokens locally.
#[derive(Clone, Debug, Default)]
pub struct LogEmailLoginSender;

impl EmailLoginSender for LogEmailLoginSender {
    fn send_login_token(&self, email: &str, token: &str, expires_at: i64) -> Result<()> {
        eprintln!("mycellium login email for {email}: token={token} expires_at={expires_at}");
        Ok(())
    }
}

/// Brevo transactional-email API sender.
pub struct BrevoEmailLoginSender {
    api_key: String,
    endpoint: String,
    from: Mailbox,
    subject: String,
    login_url_template: Option<String>,
}

impl BrevoEmailLoginSender {
    /// Build a sender from explicit Brevo settings.
    pub fn new(config: BrevoEmailConfig) -> Result<Self> {
        let from = config
            .from
            .parse::<Mailbox>()
            .map_err(|err| RegistryError::new(format!("invalid email from address: {err}")))?;
        Ok(Self {
            api_key: config.api_key,
            endpoint: config
                .endpoint
                .unwrap_or_else(|| "https://api.brevo.com/v3/smtp/email".to_string()),
            from,
            subject: config
                .subject
                .unwrap_or_else(|| DEFAULT_SUBJECT.to_string()),
            login_url_template: config.login_url_template,
        })
    }
}

impl EmailLoginSender for BrevoEmailLoginSender {
    fn send_login_token(&self, email: &str, token: &str, expires_at: i64) -> Result<()> {
        let recipient = email
            .parse::<Mailbox>()
            .map_err(|err| RegistryError::new(format!("invalid email recipient: {err}")))?;
        let payload = BrevoSendEmailRequest::login_token(
            &self.from,
            &recipient,
            &self.subject,
            token,
            expires_at,
            self.login_url_template.as_deref(),
        );
        ureq::post(&self.endpoint)
            .header("api-key", &self.api_key)
            .header("accept", "application/json")
            .send_json(&payload)
            .map_err(|err| RegistryError::new(format!("send Brevo login email failed: {err}")))?;
        Ok(())
    }
}

/// Brevo API configuration.
pub struct BrevoEmailConfig {
    /// Brevo transactional API key.
    pub api_key: String,
    /// Optional API endpoint override for tests or proxies.
    pub endpoint: Option<String>,
    /// Sender mailbox, for example `Mycellium <login@example.com>`.
    pub from: String,
    /// Optional message subject override.
    pub subject: Option<String>,
    /// Optional link template. `{token}` is replaced with the login token.
    pub login_url_template: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BrevoSendEmailRequest {
    sender: BrevoEmailAddress,
    to: Vec<BrevoEmailAddress>,
    subject: String,
    text_content: String,
}

impl BrevoSendEmailRequest {
    fn login_token(
        from: &Mailbox,
        to: &Mailbox,
        subject: &str,
        token: &str,
        expires_at: i64,
        login_url_template: Option<&str>,
    ) -> Self {
        Self {
            sender: BrevoEmailAddress::from_mailbox(from),
            to: vec![BrevoEmailAddress::from_mailbox(to)],
            subject: subject.to_string(),
            text_content: login_email_body(token, expires_at, login_url_template),
        }
    }
}

#[derive(Debug, Serialize)]
struct BrevoEmailAddress {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

impl BrevoEmailAddress {
    fn from_mailbox(mailbox: &Mailbox) -> Self {
        Self {
            email: mailbox.email.to_string(),
            name: mailbox.name.clone(),
        }
    }
}

/// Generic SMTP login-token sender.
pub struct SmtpEmailLoginSender {
    mailer: SmtpTransport,
    from: Mailbox,
    subject: String,
    login_url_template: Option<String>,
}

impl SmtpEmailLoginSender {
    /// Build a sender from explicit SMTP settings.
    pub fn new(config: SmtpEmailConfig) -> Result<Self> {
        let from = config
            .from
            .parse::<Mailbox>()
            .map_err(|err| RegistryError::new(format!("invalid email from address: {err}")))?;
        let mut builder = SmtpTransport::relay(&config.host)
            .map_err(|err| RegistryError::new(format!("invalid smtp host: {err}")))?
            .port(config.port);
        builder = match (config.username, config.password) {
            (Some(username), Some(password)) => {
                builder.credentials(Credentials::new(username, password))
            }
            (None, None) => builder,
            _ => {
                return Err(RegistryError::new(
                    "SMTP username and password must be configured together",
                ))
            }
        };
        Ok(Self {
            mailer: builder.build(),
            from,
            subject: config
                .subject
                .unwrap_or_else(|| DEFAULT_SUBJECT.to_string()),
            login_url_template: config.login_url_template,
        })
    }
}

impl EmailLoginSender for SmtpEmailLoginSender {
    fn send_login_token(&self, email: &str, token: &str, expires_at: i64) -> Result<()> {
        let message = Message::builder()
            .from(self.from.clone())
            .to(email
                .parse::<Mailbox>()
                .map_err(|err| RegistryError::new(format!("invalid email recipient: {err}")))?)
            .subject(&self.subject)
            .body(login_email_body(
                token,
                expires_at,
                self.login_url_template.as_deref(),
            ))
            .map_err(|err| RegistryError::new(format!("build login email failed: {err}")))?;
        self.mailer
            .send(&message)
            .map_err(|err| RegistryError::new(format!("send login email failed: {err}")))?;
        Ok(())
    }
}

/// SMTP configuration.
pub struct SmtpEmailConfig {
    /// SMTP host, for example `smtp-relay.brevo.com`.
    pub host: String,
    /// SMTP port. Port 587 is the default.
    pub port: u16,
    /// SMTP username, if the server requires authentication.
    pub username: Option<String>,
    /// SMTP password, if the server requires authentication.
    pub password: Option<String>,
    /// Sender mailbox, for example `Mycellium <login@example.com>`.
    pub from: String,
    /// Optional message subject override.
    pub subject: Option<String>,
    /// Optional link template. `{token}` is replaced with the login token.
    pub login_url_template: Option<String>,
}

/// Build the configured sender from environment variables.
pub fn configured_email_sender_from_env() -> Result<ConfiguredEmailSender> {
    match env_required("MYCELLIUM_REGISTRY_EMAIL_TRANSPORT")?.as_str() {
        "log" => Ok(ConfiguredEmailSender::Log(LogEmailLoginSender)),
        "brevo" => Ok(ConfiguredEmailSender::Brevo(BrevoEmailLoginSender::new(
            BrevoEmailConfig {
                api_key: env_secret_required("MYCELLIUM_REGISTRY_BREVO_API_KEY")?,
                endpoint: env_optional("MYCELLIUM_REGISTRY_BREVO_ENDPOINT"),
                from: env_required("MYCELLIUM_REGISTRY_EMAIL_FROM")?,
                subject: env_optional("MYCELLIUM_REGISTRY_EMAIL_SUBJECT"),
                login_url_template: env_optional("MYCELLIUM_REGISTRY_LOGIN_URL_TEMPLATE"),
            },
        )?)),
        "smtp" => Ok(ConfiguredEmailSender::Smtp(SmtpEmailLoginSender::new(
            SmtpEmailConfig {
                host: env_required("MYCELLIUM_REGISTRY_SMTP_HOST")?,
                port: env_optional("MYCELLIUM_REGISTRY_SMTP_PORT")
                    .map(|port| {
                        port.parse::<u16>().map_err(|_| {
                            RegistryError::new("MYCELLIUM_REGISTRY_SMTP_PORT must be a port number")
                        })
                    })
                    .transpose()?
                    .unwrap_or(587),
                username: env_optional("MYCELLIUM_REGISTRY_SMTP_USERNAME"),
                password: env_secret_optional("MYCELLIUM_REGISTRY_SMTP_PASSWORD"),
                from: env_required("MYCELLIUM_REGISTRY_EMAIL_FROM")?,
                subject: env_optional("MYCELLIUM_REGISTRY_EMAIL_SUBJECT"),
                login_url_template: env_optional("MYCELLIUM_REGISTRY_LOGIN_URL_TEMPLATE"),
            },
        )?)),
        other => Err(RegistryError::new(format!(
            "unsupported MYCELLIUM_REGISTRY_EMAIL_TRANSPORT: {other}"
        ))),
    }
}

fn env_required(name: &str) -> Result<String> {
    env_optional(name).ok_or_else(|| RegistryError::new(format!("{name} is required")))
}

fn env_secret_required(name: &str) -> Result<String> {
    env_secret_optional(name).ok_or_else(|| RegistryError::new(format!("{name} is required")))
}

fn env_optional(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_secret_optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn login_email_body(token: &str, _expires_at: i64, login_url_template: Option<&str>) -> String {
    let mut body = format!(
        "Use this Mycellium login code to continue:\n\n{token}\n\nThis code is short-lived and can only be used once.\nIf you did not request it, you can ignore this email.\n"
    );
    if let Some(template) = login_url_template {
        body.push_str("\nLogin link:\n");
        body.push_str(&template.replace("{token}", token));
        body.push('\n');
    }
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_email_body_includes_token_and_optional_link() {
        let body = login_email_body("abc123", 42, Some("mycellium://login?token={token}"));

        assert!(body.contains("abc123"));
        assert!(body.contains("short-lived"));
        assert!(body.contains("mycellium://login?token=abc123"));
    }

    #[test]
    fn brevo_payload_uses_transactional_static_content_shape() {
        let from = "Mycellium <login@example.com>".parse::<Mailbox>().unwrap();
        let to = "ari@example.com".parse::<Mailbox>().unwrap();
        let payload = BrevoSendEmailRequest::login_token(
            &from,
            &to,
            "Login",
            "abc123",
            42,
            Some("mycellium://login?token={token}"),
        );
        let json = serde_json::to_value(payload).unwrap();

        assert_eq!(json["sender"]["email"], "login@example.com");
        assert_eq!(json["sender"]["name"], "Mycellium");
        assert_eq!(json["to"][0]["email"], "ari@example.com");
        assert_eq!(json["subject"], "Login");
        assert!(json["textContent"].as_str().unwrap().contains("abc123"));
        assert!(json["textContent"]
            .as_str()
            .unwrap()
            .contains("mycellium://login?token=abc123"));
    }
}
