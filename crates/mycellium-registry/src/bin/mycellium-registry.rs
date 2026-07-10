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

    let app = mycellium_registry::http::redb_router(data_dir)?;
    let listener = tokio::net::TcpListener::bind(bind).await?;

    eprintln!("mycellium-registry listening on http://{bind}");
    axum::serve(listener, app).await?;
    Ok(())
}
