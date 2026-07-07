//! The `mycellium-names` server binary: load the registry, wire the router, serve.
//!
//! Configured entirely from the environment so it drops cleanly into a container
//! or systemd unit:
//!
//! - `MYCELLIUM_NAMES_DOMAIN` — the domain names are issued under (default
//!   `mycellium.eu`); it is also the URL the NIP-98 auth signature is pinned to.
//! - `MYCELLIUM_NAMES_DB`     — SQLite path (default `names.sqlite`).
//! - `MYCELLIUM_NAMES_BIND`   — listen address (default `127.0.0.1:8080`); put a
//!   TLS-terminating reverse proxy in front for public `https://` traffic.

use std::sync::Arc;

use anyhow::Context;
use mycellium_names::{router, Policy, Registry};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let domain = env_or("MYCELLIUM_NAMES_DOMAIN", "mycellium.eu");
    let db_path = env_or("MYCELLIUM_NAMES_DB", "names.sqlite");
    let bind = env_or("MYCELLIUM_NAMES_BIND", "127.0.0.1:8080");

    let policy = Policy {
        domain: domain.clone(),
        ..Policy::default()
    };
    let registry = Arc::new(
        Registry::open(&db_path, policy)
            .with_context(|| format!("opening registry at {db_path}"))?,
    );

    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    println!("mycellium-names: serving @{domain} names on http://{bind} (db: {db_path})");
    axum::serve(listener, router(registry))
        .await
        .context("server error")?;
    Ok(())
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
