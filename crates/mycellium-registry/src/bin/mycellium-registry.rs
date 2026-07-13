use std::net::SocketAddr;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("MYCELLIUM_REGISTRY_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse::<SocketAddr>()?;
    let data_dir = std::env::var_os("MYCELLIUM_REGISTRY_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".mycellium-registry"));

    let email_sender = mycellium_registry::email::configured_email_sender_from_env()?;
    let recovery_cipher = mycellium_registry::recovery::RecoveryCipher::from_env()?;
    let app = mycellium_registry::http::redb_router_with_email_sender(
        data_dir,
        email_sender,
        recovery_cipher,
    )?;
    let listener = tokio::net::TcpListener::bind(bind).await?;

    eprintln!("mycellium-registry listening on http://{bind}");
    axum::serve(listener, app).await?;
    Ok(())
}
