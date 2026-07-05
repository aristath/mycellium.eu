//! Endpoint failover (#54): when a recipient advertises multiple queue
//! endpoints, a deposit tries the primary `queue` first and falls over to each
//! entry in `queues` until one accepts — so a message survives a down primary
//! instead of being parked in the sender's outbox.
//!
//! Spins up one *real* in-process queue as the working backup and leaves a
//! second port dead as the (unreachable) primary, then drives the engine's
//! [`QueueTarget`] deposit path end-to-end and confirms the message actually
//! landed in the backup mailbox.

use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use mycellium_core::identity::{Handle, Identity};
use mycellium_core::record::Record;
use mycellium_engine::app::{seal_to, QueueTarget};
use mycellium_engine::groups::MailItem;
use mycellium_engine::platform::OsPlatform;
use mycellium_engine::wireops::{device_slot, this_device};
use mycellium_queue_client::{wallet_hex, QueueClient};

/// A free TCP port (bind to :0, read the assigned port, release it).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Block until `port` accepts connections, or panic after a timeout.
fn wait_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("port {port} never opened");
}

#[test]
fn deposit_fails_over_from_down_primary_to_backup() {
    // A live queue plays the *backup*; a second free-but-unbound port plays the
    // *down primary*.
    let backup_port = free_port();
    let backup_addr = format!("127.0.0.1:{backup_port}");
    let serve_addr = backup_addr.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async {
            let _ = mycellium_queue::serve(&serve_addr).await;
        });
    });
    wait_port(backup_port);
    let backup_url = format!("http://{backup_addr}");
    let dead_url = format!("http://127.0.0.1:{}", free_port());

    let mut p = OsPlatform;
    let alice = Identity::generate(&mut p).unwrap(); // sender
    let bob = Identity::generate(&mut p).unwrap(); // recipient
    let me = Handle::new("alice").unwrap();
    let bob_device = this_device(&bob, "");

    // Bob's record advertises the DOWN primary first, then the live backup.
    let bob_record = Record {
        handle: Handle::new("bob").unwrap(),
        name: String::new(),
        wallet: bob.wallet_public(),
        queue: dead_url,
        queues: vec![backup_url.clone()],
        devices: vec![bob_device.clone()],
        seq: 1,
    };

    // Opening the target skips the unreachable primary and keeps the backup.
    let target =
        QueueTarget::open(&alice, &bob_record).expect("must fail over to the live backup endpoint");

    // Deposit a real sealed message; failover makes it succeed via the backup.
    let envelope = seal_to(&alice, &me, &bob_device, b"hi over the backup").unwrap();
    let item = MailItem::Direct(envelope);
    let slot = device_slot(&bob_device.device_key);
    assert!(
        target.deposit(&slot, &item),
        "deposit must succeed by failing over to the backup queue"
    );

    // It really landed in the backup mailbox — delivered, not parked.
    let q = QueueClient::new(&backup_url);
    let token = q.login(&bob).unwrap();
    let blobs = q
        .collect(&token, &wallet_hex(&bob.wallet_public()), &slot)
        .unwrap();
    assert_eq!(
        blobs.len(),
        1,
        "the failed-over message must be waiting in the backup mailbox"
    );
}
