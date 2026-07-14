use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use mycellium_registry::http::{self, EmailLoginSender};
use mycellium_registry::recovery::RecoveryCipher;
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
                let http_listener = tokio::net::TcpListener::bind("[::1]:0")
                    .await
                    .expect("bind registry HTTP listener");
                let http_address = http_listener.local_addr().expect("HTTP listener address");

                let state = http::redb_state_with_email_sender(
                    &data_dir,
                    thread_emails,
                    RecoveryCipher::new(recovery_key),
                )
                .expect("open registry state");
                let app = http::router(state.clone());

                let http_task = tokio::spawn(async move {
                    axum::serve(http_listener, app)
                        .await
                        .expect("registry HTTP server failed");
                });
                ready_tx
                    .send(format!("http://{http_address}"))
                    .expect("announce registry test server");

                let _ = shutdown_rx.await;
                http_task.abort();
                let _ = http_task.await;
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
