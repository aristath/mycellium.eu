use std::net::SocketAddr;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bind = std::env::var("MYCELLIUM_REGISTRY_BIND")
        .unwrap_or_else(|_| "[::1]:8787".to_string())
        .parse::<SocketAddr>()?;
    let data_dir = std::env::var_os("MYCELLIUM_REGISTRY_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".mycellium-registry"));
    std::fs::create_dir_all(&data_dir)?;

    let email_sender = mycellium_registry::email::configured_email_sender_from_env()?;
    let recovery_cipher = mycellium_registry::recovery::RecoveryCipher::from_env()?;
    let state = mycellium_registry::http::redb_state_with_email_sender(
        &data_dir,
        email_sender,
        recovery_cipher,
    )?;
    let app = mycellium_registry::http::router(state.clone());
    let maintenance_state = state.clone();
    let listener = tokio::net::TcpListener::bind(bind).await?;

    eprintln!("mycellium-registry listening on http://{bind}");
    tokio::try_join!(
        async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(anyhow::Error::from)
        },
        async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let state = maintenance_state.clone();
                match tokio::task::spawn_blocking(move || {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|duration| duration.as_secs() as i64)
                        .unwrap_or(0);
                    const BATCH: usize = 10_000;
                    loop {
                        let removed = state.purge_expired(now, BATCH)?;
                        if removed < BATCH {
                            break Ok::<(), anyhow::Error>(());
                        }
                    }
                })
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => eprintln!("registry cleanup failed: {error}"),
                    Err(error) => eprintln!("registry cleanup task failed: {error}"),
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        },
    )?;
    Ok(())
}
