use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bind = std::env::var("MYCELLIUM_REGISTRY_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse::<SocketAddr>()?;
    let data_dir = std::env::var_os("MYCELLIUM_REGISTRY_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".mycellium-registry"));
    std::fs::create_dir_all(&data_dir)?;

    let configured_rendezvous_bind = std::env::var("MYCELLIUM_REGISTRY_RENDEZVOUS_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8788".to_string())
        .parse::<SocketAddr>()?;
    let rendezvous_bind = concrete_rendezvous_bind(configured_rendezvous_bind)?;
    let rendezvous_secret =
        mycellium_registry::rendezvous::load_or_create_identity(&data_dir.join("rendezvous.key"))?;
    let rendezvous_peer = mycellium_registry::rendezvous::peer_id_for_secret(rendezvous_secret)?;
    let rendezvous_public_base = std::env::var("MYCELLIUM_REGISTRY_RENDEZVOUS_PUBLIC_ADDR")
        .unwrap_or_else(|_| format!("/ip4/127.0.0.1/udp/{}/quic-v1", rendezvous_bind.port()));
    let rendezvous_public =
        mycellium_registry::rendezvous::public_address(&rendezvous_public_base, rendezvous_peer)?;

    let email_sender = mycellium_registry::email::configured_email_sender_from_env()?;
    let recovery_cipher = mycellium_registry::recovery::RecoveryCipher::from_env()?;
    let state = mycellium_registry::http::redb_state_with_email_sender(
        &data_dir,
        email_sender,
        recovery_cipher,
    )?
    .with_rendezvous_address(rendezvous_public.clone());
    let app = mycellium_registry::http::router(state.clone());
    let maintenance_state = state.clone();
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let rendezvous_listen = mycellium_registry::rendezvous::quic_listen_address(rendezvous_bind);

    eprintln!("mycellium-registry listening on http://{bind}");
    eprintln!("mycellium-registry rendezvous binding on {rendezvous_bind}");
    eprintln!("mycellium-registry rendezvous public address: {rendezvous_public}");
    tokio::try_join!(
        async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(anyhow::Error::from)
        },
        mycellium_registry::rendezvous::serve(state, rendezvous_secret, rendezvous_listen,),
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

fn concrete_rendezvous_bind(configured: SocketAddr) -> anyhow::Result<SocketAddr> {
    if !configured.ip().is_unspecified() {
        return Ok(configured);
    }
    let Some(pod_ip) = std::env::var_os("BUNNYNET_MC_PODIP") else {
        return Ok(configured);
    };
    let pod_ip = pod_ip
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("BUNNYNET_MC_PODIP is not valid text"))?
        .parse::<IpAddr>()
        .map_err(|_| anyhow::anyhow!("BUNNYNET_MC_PODIP is not a valid IP address"))?;
    Ok(SocketAddr::new(pod_ip, configured.port()))
}
