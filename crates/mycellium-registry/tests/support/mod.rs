use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use mycellium_registry::http::{self, EmailLoginSender};
use mycellium_registry::recovery::RecoveryCipher;
use mycellium_registry::rendezvous;
use mycellium_registry::Result;

#[derive(Clone, Default)]
pub struct CapturedEmails {
    tokens: Arc<Mutex<HashMap<String, VecDeque<String>>>>,
}

impl CapturedEmails {
    pub fn take_token(&self, email: &str) -> String {
        self.tokens
            .lock()
            .expect("captured-email lock poisoned")
            .get_mut(email)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| panic!("no login token was sent to {email}"))
    }
}

impl EmailLoginSender for CapturedEmails {
    fn send_login_token(&self, email: &str, token: &str, _expires_at: i64) -> Result<()> {
        self.tokens
            .lock()
            .expect("captured-email lock poisoned")
            .entry(email.to_string())
            .or_default()
            .push_back(token.to_string());
        Ok(())
    }
}

pub struct TestRegistry {
    pub base_url: String,
    pub emails: CapturedEmails,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TestRegistry {
    pub fn start(data_dir: &Path, recovery_key: [u8; 32]) -> Self {
        std::fs::create_dir_all(data_dir).expect("create registry test directory");
        let data_dir = data_dir.to_path_buf();
        let emails = CapturedEmails::default();
        let thread_emails = emails.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("build registry test runtime");
            runtime.block_on(async move {
                let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind registry HTTP listener");
                let http_address = http_listener.local_addr().expect("HTTP listener address");

                // libp2p does not expose its assigned port until after the
                // swarm starts, so reserve a loopback UDP port before startup.
                let reserved =
                    std::net::UdpSocket::bind("127.0.0.1:0").expect("reserve registry QUIC port");
                let rendezvous_socket = reserved.local_addr().expect("QUIC listener address");
                drop(reserved);

                let rendezvous_secret =
                    rendezvous::load_or_create_identity(&data_dir.join("rendezvous.key"))
                        .expect("load rendezvous identity");
                let rendezvous_peer = rendezvous::peer_id_for_secret(rendezvous_secret)
                    .expect("derive rendezvous peer id");
                let public_address = rendezvous::public_address(
                    &format!("/ip4/127.0.0.1/udp/{}/quic-v1", rendezvous_socket.port()),
                    rendezvous_peer,
                )
                .expect("build rendezvous public address");
                let state = http::redb_state_with_email_sender(
                    &data_dir,
                    thread_emails,
                    RecoveryCipher::new(recovery_key),
                )
                .expect("open registry state")
                .with_rendezvous_address(public_address);
                let app = http::router(state.clone());
                let rendezvous_listen = rendezvous::quic_listen_address(rendezvous_socket);

                let http_task = tokio::spawn(async move {
                    axum::serve(http_listener, app)
                        .await
                        .expect("registry HTTP server failed");
                });
                let rendezvous_task = tokio::spawn(async move {
                    rendezvous::serve(state, rendezvous_secret, rendezvous_listen)
                        .await
                        .expect("registry rendezvous failed");
                });
                ready_tx
                    .send(format!("http://{http_address}"))
                    .expect("announce registry test server");

                let _ = shutdown_rx.await;
                http_task.abort();
                rendezvous_task.abort();
                let _ = http_task.await;
                let _ = rendezvous_task.await;
            });
        });

        let base_url = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("registry test server did not start");
        Self {
            base_url,
            emails,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        }
    }
}

impl Drop for TestRegistry {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
