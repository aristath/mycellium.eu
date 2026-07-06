//! Real end-to-end tests: a live directory (in-process) plus the actual
//! `mycellium-cli` binary, driven through the full two-account flow — create
//! identities, register, and exchange messages — asserting on decrypted output.
//!
//! Covers offline delivery and live chat over both the TCP and libp2p transports.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{ChildStdout, Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mycellium_transport::libp2p_net::{self, Libp2pNode};

/// Path to the built CLI binary (Cargo sets this for integration tests).
const CLI: &str = env!("CARGO_BIN_EXE_mycellium-cli");
const PASS: &str = "test-passphrase";

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Cap how many subprocess-heavy e2e tests run at once, so the harness running
/// them all in parallel doesn't cause resource contention / port races.
static E2E_SEMAPHORE: Semaphore = Semaphore::new(4);

struct Semaphore {
    count: std::sync::Mutex<usize>,
    cv: std::sync::Condvar,
}
impl Semaphore {
    const fn new(n: usize) -> Self {
        Semaphore {
            count: std::sync::Mutex::new(n),
            cv: std::sync::Condvar::new(),
        }
    }
}

struct Throttle;
fn throttle() -> Throttle {
    let mut count = E2E_SEMAPHORE.count.lock().unwrap();
    while *count == 0 {
        count = E2E_SEMAPHORE.cv.wait(count).unwrap();
    }
    *count -= 1;
    Throttle
}
impl Drop for Throttle {
    fn drop(&mut self) {
        *E2E_SEMAPHORE.count.lock().unwrap() += 1;
        E2E_SEMAPHORE.cv.notify_one();
    }
}

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

/// One shared message queue for the whole test binary. It's keyed by wallet, so
/// tests (each with fresh identities) never collide. Its URL is exported as
/// `MYCELLIUM_QUEUE` so every spawned CLI inherits it — records carry it, and
/// send/inbox deposit/collect against it (the queue is decoupled from the
/// directory).
static QUEUE_URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
fn ensure_queue() {
    QUEUE_URL.get_or_init(|| {
        let port = free_port();
        let addr = format!("127.0.0.1:{port}");
        let serve_addr = addr.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            rt.block_on(async {
                let _ = mycellium_queue::serve(&serve_addr).await;
            });
        });
        wait_port(port);
        let url = format!("http://{addr}");
        std::env::set_var("MYCELLIUM_QUEUE", &url);
        url
    });
}

/// Start a directory on a fresh port, in a background thread. Returns its URL.
/// Also ensures the shared queue is up (and `MYCELLIUM_QUEUE` exported).
fn start_directory() -> String {
    // The directory fails closed without SMTP unless dev auth is explicit (#47).
    std::env::set_var("MYCELLIUM_DEV_AUTH", "1");
    ensure_queue();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let serve_addr = addr.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async {
            let _ = mycellium_directory::serve(&serve_addr).await;
        });
    });
    wait_port(port);
    format!("http://{addr}")
}

/// A unique, isolated data directory for one account.
fn home(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "mycellium-e2e-{}-{}-{}",
        tag,
        std::process::id(),
        n
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// Run the CLI to completion with a given home, returning its output.
fn cli(home: &PathBuf, args: &[&str]) -> Output {
    cli_pass(home, PASS, args)
}

/// Like [`cli`], but with an explicit passphrase.
fn cli_pass(home: &PathBuf, pass: &str, args: &[&str]) -> Output {
    Command::new(CLI)
        .args(args)
        .env("MYCELLIUM_HOME", home)
        .env("MYCELLIUM_PASSPHRASE", pass)
        .stdin(Stdio::null())
        .output()
        .expect("failed to run mycellium-cli")
}

/// The last whitespace-token of the first line starting with `label`.
fn field(stdout: &[u8], label: &str) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .find(|l| l.trim_start().starts_with(label))
        .and_then(|l| l.split_whitespace().last())
        .unwrap_or_else(|| panic!("no `{label}` line in output"))
        .to_string()
}

/// The safety-number value from a chat/listen output line.
fn safety_number(stdout: &str) -> String {
    stdout
        .lines()
        .find(|l| l.trim_start().starts_with("safety number:"))
        .and_then(|l| l.split(": ").nth(1))
        .map(|s| s.trim().to_string())
        .expect("no safety-number line")
}

/// Assert a command succeeded, surfacing stderr on failure.
fn ok(output: &Output, what: &str) {
    assert!(
        output.status.success(),
        "{what} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Create two registered identities. Returns (alice_home, bob_home).
fn two_accounts(dir: &str, bob_addr: &str, libp2p: bool) -> (PathBuf, PathBuf) {
    let alice = home("alice");
    let bob = home("bob");
    ok(&cli(&alice, &["identity-new"]), "alice identity-new");
    ok(&cli(&bob, &["identity-new"]), "bob identity-new");

    let mut reg = vec!["register", "bob", "--addr", bob_addr, "--directory", dir];
    if libp2p {
        reg.push("--libp2p");
    }
    ok(&cli(&bob, &reg), "bob register");
    (alice, bob)
}

#[test]
fn live_push_delivery_when_online() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");

    // Bob registers a serve address and stays online with `serve`.
    let bob_port = free_port();
    let bob_addr = format!("127.0.0.1:{bob_port}");
    let bob = home("bob-serve");
    ok(&cli(&bob, &["identity-new"]), "bob id");
    ok(
        &cli(
            &bob,
            &["register", "bob", "--addr", &bob_addr, "--directory", &dir],
        ),
        "bob register",
    );

    let mut bob_serve = Command::new(CLI)
        .args([
            "serve",
            "--addr",
            &bob_addr,
            "--as",
            "bob",
            "--directory",
            &dir,
        ])
        .env("MYCELLIUM_HOME", &bob)
        .env("MYCELLIUM_PASSPHRASE", PASS)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn bob serve");
    let bob_out = tail(bob_serve.stdout.take().unwrap());
    wait_port(bob_port);

    // Alice sends; since Bob is online, it's pushed live to his `serve`.
    ok(
        &cli(
            &alice,
            &[
                "send",
                "bob",
                "--as",
                "alice",
                "--message",
                "live hello",
                "--directory",
                &dir,
            ],
        ),
        "send",
    );
    let got = wait_contains(&bob_out, "from alice: live hello", 20);

    let _ = bob_serve.kill();
    let _ = bob_serve.wait();
    assert!(
        got,
        "bob's serve did not receive the live message:\n{}",
        bob_out.lock().unwrap()
    );
}

#[test]
fn full_duplex_mail_over_libp2p() {
    let _throttle = throttle();
    let dir = start_directory();

    // Bob registers a libp2p multiaddr and stays online with `serve --libp2p`,
    // so a NATed/libp2p recipient is reachable for a *live* mail push (#59) — not
    // forced down to the queue as before.
    let bob_port = free_port();
    let bob_addr = format!("127.0.0.1:{bob_port}");
    let bob = home("bob-serve-libp2p");
    ok(&cli(&bob, &["identity-new"]), "bob id");
    ok(
        &cli(
            &bob,
            &[
                "register",
                "bob",
                "--addr",
                &bob_addr,
                "--libp2p",
                "--directory",
                &dir,
            ],
        ),
        "bob register libp2p",
    );

    let alice = account(&dir, "alice");

    let mut bob_serve = Command::new(CLI)
        .args([
            "serve",
            "--addr",
            &bob_addr,
            "--as",
            "bob",
            "--libp2p",
            "--directory",
            &dir,
        ])
        .env("MYCELLIUM_HOME", &bob)
        .env("MYCELLIUM_PASSPHRASE", PASS)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn bob serve libp2p");
    let bob_out = tail(bob_serve.stdout.take().unwrap());
    wait_port(bob_port);

    // Alice sends; Bob is online and advertises a multiaddr, so the message is
    // dialed live over libp2p into his `serve` and decrypted there.
    let sent = cli(
        &alice,
        &[
            "send",
            "bob",
            "--as",
            "alice",
            "--message",
            "live over libp2p",
            "--directory",
            &dir,
        ],
    );
    ok(&sent, "send");
    // The send reports a live *direct* path (delivered, none queued) — proving it
    // went over libp2p, not parked in the outbox/queue.
    let so = String::from_utf8_lossy(&sent.stdout);
    assert!(
        so.contains("[1 direct, 0 queued]"),
        "send should report a live direct libp2p delivery: {so}"
    );
    assert!(
        !so.contains("queued for retry"),
        "libp2p live delivery must not be parked in the outbox: {so}"
    );

    let got = wait_contains(&bob_out, "from alice: live over libp2p", 20);

    let _ = bob_serve.kill();
    let _ = bob_serve.wait();
    assert!(
        got,
        "bob's libp2p serve did not receive the live message:\n{}",
        bob_out.lock().unwrap()
    );
}

/// Poll the directory (via `devices <handle>`) until the handle's advertised
/// address contains `needle` (e.g. `/p2p-circuit`), or time out. A bounded wait
/// for an async re-publish, run with `home` (any home works — `devices` reads the
/// directory, not local identity).
fn wait_directory_addr(home: &PathBuf, handle: &str, needle: &str, dir: &str, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        let out = cli(home, &["devices", handle, "--directory", dir]);
        if String::from_utf8_lossy(&out.stdout).contains(needle) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Circuit Relay v2 into the delivery ladder (#59): a recipient reachable ONLY
/// through a relay gets a **live relayed** push through `deliver()`, reported as
/// `DeliveryPath::Relay` — not parked in the queue/outbox, and not a direct dial.
///
/// Mirrors `full_duplex_mail_over_libp2p`, but through a relay:
/// - An in-process relay node (its relay-server behaviour forwards for others)
///   is bound to loopback and reachable by both CLI subprocesses.
/// - Bob `serve`s relay-only: NO direct listen address, and an empty queue, so
///   his ONLY reachable path is the circuit (non-vacuous — if the relayed dial
///   didn't work the message would land in Alice's outbox and both asserts fail).
/// - Alice `send`s and must report a live `[… relay]` delivery, and Bob's serve
///   must print the decrypted message.
#[test]
fn relayed_live_delivery_through_a_relay() {
    let _throttle = throttle();
    let dir = start_directory();

    // In-process relay R: a public node forwarding for others. Its background
    // swarm task (spawned in `new`) forwards circuit traffic on its own — we just
    // keep it alive for the duration. `listen_addr()` blocks until it is bound,
    // so once we have `relay_addr` the relay is listening.
    let relay_listen = libp2p_net::listen_multiaddr("127.0.0.1:0").unwrap();
    let mut relay = Libp2pNode::new([42u8; 32], Some(relay_listen)).expect("relay node");
    let relay_base = relay.listen_addr().expect("relay listen addr");
    let relay_addr = format!("{relay_base}/p2p/{}", relay.peer_id());

    // Bob registers a libp2p account (his initial direct addr is never listened
    // on — it is overwritten by the circuit address once he reserves).
    let bob_port = free_port();
    let bob_addr = format!("127.0.0.1:{bob_port}");
    let bob = home("bob-relay");
    ok(&cli(&bob, &["identity-new"]), "bob id");
    ok(
        &cli(
            &bob,
            &[
                "register",
                "bob",
                "--addr",
                &bob_addr,
                "--libp2p",
                "--directory",
                &dir,
            ],
        ),
        "bob register libp2p",
    );

    let alice = account(&dir, "alice");

    // Bob serves relay-only: reserve on R, re-publish his circuit address, accept
    // relayed streams. Empty MYCELLIUM_QUEUE ⇒ no queue fallback in his record ⇒
    // the relay circuit is his only reachable path.
    let mut bob_serve = Command::new(CLI)
        .args([
            "serve",
            "--addr",
            &bob_addr,
            "--as",
            "bob",
            "--libp2p",
            "--relay",
            &relay_addr,
            "--directory",
            &dir,
        ])
        .env("MYCELLIUM_HOME", &bob)
        .env("MYCELLIUM_PASSPHRASE", PASS)
        .env("MYCELLIUM_QUEUE", "")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn bob serve relay");
    let bob_out = tail(bob_serve.stdout.take().unwrap());

    // Bounded wait until Bob has reserved + re-published his circuit address —
    // only then does Alice know a (relay) route to Bob.
    let published = wait_directory_addr(&alice, "bob", "/p2p-circuit", &dir, 30);
    if !published {
        let _ = bob_serve.kill();
        let _ = bob_serve.wait();
        panic!(
            "bob never published a circuit address:\n{}",
            bob_out.lock().unwrap()
        );
    }

    // Alice sends; Bob is online and advertises only a circuit address, so the
    // message is dialed live THROUGH the relay into his serve and decrypted there.
    let sent = cli(
        &alice,
        &[
            "send",
            "bob",
            "--as",
            "alice",
            "--message",
            "live over relay",
            "--directory",
            &dir,
        ],
    );
    ok(&sent, "send");
    let so = String::from_utf8_lossy(&sent.stdout);
    // The send reports a live *relay* path — proving it went over the circuit,
    // not a direct dial and not parked in the outbox/queue.
    assert!(
        so.contains("[1 relay]"),
        "send should report a live relayed delivery: {so}"
    );
    assert!(
        !so.contains("queued for retry"),
        "relayed live delivery must not be parked in the outbox: {so}"
    );
    assert!(
        !so.contains("direct"),
        "delivery was through a relay, not a direct dial: {so}"
    );

    let got = wait_contains(&bob_out, "from alice: live over relay", 20);

    let _ = bob_serve.kill();
    let _ = bob_serve.wait();
    relay.drain(50);
    assert!(
        got,
        "bob's relay serve did not receive the live message:\n{}",
        bob_out.lock().unwrap()
    );
}

/// Read the offer token the new device's `pair` prints, from its live stdout,
/// then keep draining stdout so the still-running child never hits a broken pipe.
fn read_pair_offer(child: &mut std::process::Child) -> String {
    use std::io::{BufRead, BufReader};
    let stdout = child.stdout.take().expect("pair stdout piped");
    let mut reader = BufReader::new(stdout);
    let mut offer = None;
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if let Some(pos) = line.find("pair-approve ") {
            let rest = &line[pos + "pair-approve ".len()..];
            offer = Some(
                rest.split_whitespace()
                    .next()
                    .expect("offer token")
                    .to_string(),
            );
            break;
        }
        line.clear();
    }
    std::thread::spawn(move || {
        let mut junk = String::new();
        while reader.read_line(&mut junk).unwrap_or(0) > 0 {
            junk.clear();
        }
    });
    offer.expect("`pair` did not print an offer")
}

/// Pair a fresh device into `handle`'s account (approved from the `existing`
/// device) and return the new device's home — the seedless replacement for the
/// old `link-device` setup in multi-device tests.
fn pair_device(existing: &PathBuf, handle: &str, tag: &str, dir: &str) -> PathBuf {
    let queue = QUEUE_URL.get().expect("queue up").clone();
    let new_home = home(tag);
    let addr = format!("127.0.0.1:{}", free_port());
    let mut pair = Command::new(CLI)
        .args([
            "pair",
            handle,
            "--addr",
            &addr,
            "--queue",
            &queue,
            "--directory",
            dir,
        ])
        .env("MYCELLIUM_HOME", &new_home)
        .env("MYCELLIUM_PASSPHRASE", PASS)
        .env("MYCELLIUM_QUEUE", &queue)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pair");
    let offer = read_pair_offer(&mut pair);
    ok(
        &cli(
            existing,
            &["pair-approve", &offer, "--as", handle, "--directory", dir],
        ),
        "pair-approve",
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(status) = pair.try_wait().expect("try_wait") {
            assert!(status.success(), "pair-into-{tag} did not succeed");
            break;
        }
        if std::time::Instant::now() > deadline {
            let _ = pair.kill();
            panic!("pair-into-{tag} did not complete");
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    new_home
}

#[test]
fn pairing_joins_a_second_device() {
    let _throttle = throttle();
    let dir = start_directory();
    let queue = QUEUE_URL.get().expect("queue up").clone();
    let alice = account(&dir, "alice"); // device 1, registered

    // Device 2 is a fresh home. `pair` blocks polling the rendezvous, so run it
    // in the background and read the offer it prints.
    let alice2 = home("alice2");
    let d2_addr = format!("127.0.0.1:{}", free_port());
    let mut pair = Command::new(CLI)
        .args([
            "pair",
            "alice",
            "--addr",
            &d2_addr,
            "--queue",
            &queue,
            "--directory",
            &dir,
        ])
        .env("MYCELLIUM_HOME", &alice2)
        .env("MYCELLIUM_PASSPHRASE", PASS)
        .env("MYCELLIUM_QUEUE", &queue)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pair");

    let offer = read_pair_offer(&mut pair);

    // Device 1 approves — this seals its account key to the offer and relays it.
    ok(
        &cli(
            &alice,
            &["pair-approve", &offer, "--as", "alice", "--directory", &dir],
        ),
        "pair-approve",
    );

    // The new device should adopt the account and finish within a few poll cycles.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Some(status) = pair.try_wait().expect("try_wait") {
            if !status.success() {
                use std::io::Read;
                let mut err = String::new();
                if let Some(mut e) = pair.stderr.take() {
                    let _ = e.read_to_string(&mut err);
                }
                panic!("pair did not succeed: {err}");
            }
            break;
        }
        if std::time::Instant::now() > deadline {
            let _ = pair.kill();
            panic!("pair did not complete after approval");
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // Alice's record now lists two devices.
    let devices = cli(&alice, &["devices", "alice", "--directory", &dir]);
    let out = String::from_utf8_lossy(&devices.stdout);
    let count = out.lines().filter(|l| l.starts_with("  ")).count();
    assert_eq!(
        count, 2,
        "cluster should have 2 devices after pairing:\n{out}"
    );
}

#[test]
fn revoked_device_stops_receiving() {
    let _throttle = throttle();
    let dir = start_directory();
    let john = account(&dir, "john");

    let mary_a = home("rev-a");
    ok(&cli(&mary_a, &["identity-new"]), "identity-new");
    ok(
        &cli(
            &mary_a,
            &[
                "register",
                "mary",
                "--addr",
                "127.0.0.1:6401",
                "--directory",
                &dir,
            ],
        ),
        "register",
    );
    let mary_b = pair_device(&mary_a, "mary", "rev-b", &dir);

    // Revoke device B (by short id) — it's the listed device that ISN'T device A
    // (A registered at :6401; B paired in on a random port).
    let devs = cli(&mary_a, &["devices", "mary", "--directory", &dir]);
    let text = String::from_utf8_lossy(&devs.stdout);
    let b_id = text
        .lines()
        .filter(|l| l.starts_with("  "))
        .find(|l| !l.contains("6401"))
        .and_then(|l| l.split_whitespace().next())
        .expect("device B id")
        .to_string();
    ok(
        &cli(
            &mary_a,
            &["revoke-device", "mary", &b_id, "--directory", &dir],
        ),
        "revoke-device",
    );

    // A message sent after the revoke reaches A but not the revoked B.
    ok(
        &cli(
            &john,
            &[
                "send",
                "mary",
                "--as",
                "john",
                "--message",
                "after revoke",
                "--directory",
                &dir,
            ],
        ),
        "send",
    );
    let a = cli(&mary_a, &["inbox", "--as", "mary", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&a.stdout).contains("after revoke"),
        "device A missed it: {}",
        String::from_utf8_lossy(&a.stdout)
    );
    let b = cli(&mary_b, &["inbox", "--as", "mary", "--directory", &dir]);
    assert!(
        !String::from_utf8_lossy(&b.stdout).contains("after revoke"),
        "revoked device B still received it: {}",
        String::from_utf8_lossy(&b.stdout)
    );
}

#[test]
fn read_receipt_reaches_sender_cluster() {
    let _throttle = throttle();
    let dir = start_directory();
    let john = account(&dir, "john");

    // Mary: device A registers, device B links.
    let mary_a = home("rcpt-a");
    ok(&cli(&mary_a, &["identity-new"]), "identity-new");
    ok(
        &cli(
            &mary_a,
            &[
                "register",
                "mary",
                "--addr",
                "127.0.0.1:6301",
                "--directory",
                &dir,
            ],
        ),
        "register",
    );
    let _mary_b = pair_device(&mary_a, "mary", "rcpt-b", &dir);

    // Mary sends from device A; John reads it, returning a receipt to the cluster.
    ok(
        &cli(
            &mary_a,
            &[
                "send",
                "john",
                "--as",
                "mary",
                "--message",
                "did you get this",
                "--directory",
                &dir,
            ],
        ),
        "send",
    );
    ok(
        &cli(&john, &["inbox", "--as", "john", "--directory", &dir]),
        "john inbox",
    );

    // Device A (which sent) sees the read receipt.
    let a = cli(&mary_a, &["inbox", "--as", "mary", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&a.stdout).contains("read your message"),
        "sender device missed receipt: {}",
        String::from_utf8_lossy(&a.stdout)
    );
}

#[test]
fn bootstrapped_device_can_send_to_group() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");

    let mary_a = home("gsend-a");
    ok(&cli(&mary_a, &["identity-new"]), "identity-new");
    ok(
        &cli(
            &mary_a,
            &[
                "register",
                "mary",
                "--addr",
                "127.0.0.1:6601",
                "--directory",
                &dir,
            ],
        ),
        "register",
    );
    ok(
        &cli(
            &alice,
            &[
                "group",
                "create",
                "team",
                "--members",
                "mary",
                "--as",
                "alice",
                "--directory",
                &dir,
            ],
        ),
        "create",
    );
    ok(
        &cli(&mary_a, &["inbox", "--as", "mary", "--directory", &dir]),
        "mary-a invite",
    );
    ok(
        &cli(&alice, &["inbox", "--as", "alice", "--directory", &dir]),
        "alice mesh",
    );

    let mary_b = pair_device(&mary_a, "mary", "gsend-b", &dir);

    // Sync groups to B; B bootstraps and announces its own key to the members.
    ok(
        &cli(
            &mary_a,
            &["group", "sync", "--as", "mary", "--directory", &dir],
        ),
        "group sync",
    );
    ok(
        &cli(&mary_b, &["inbox", "--as", "mary", "--directory", &dir]),
        "mary-b bootstrap",
    );
    ok(
        &cli(&alice, &["inbox", "--as", "alice", "--directory", &dir]),
        "alice learns B key",
    );
    ok(
        &cli(&mary_a, &["inbox", "--as", "mary", "--directory", &dir]),
        "mary-a learns B key",
    );

    // B sends to the group; both Alice and Mary's phone can read it.
    ok(
        &cli(
            &mary_b,
            &[
                "group",
                "send",
                "team",
                "--as",
                "mary",
                "--message",
                "sent from my laptop",
                "--directory",
                &dir,
            ],
        ),
        "b group send",
    );
    let a = cli(&alice, &["inbox", "--as", "alice", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&a.stdout).contains("sent from my laptop"),
        "alice can't read B's group message: {}",
        String::from_utf8_lossy(&a.stdout)
    );
    let ma = cli(&mary_a, &["inbox", "--as", "mary", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&ma.stdout).contains("sent from my laptop"),
        "mary's phone can't read B's group message: {}",
        String::from_utf8_lossy(&ma.stdout)
    );
}

#[test]
fn new_device_bootstraps_into_group() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");

    // Mary device A creates her account and joins Alice's group.
    let mary_a = home("gsync-a");
    ok(&cli(&mary_a, &["identity-new"]), "identity-new");
    ok(
        &cli(
            &mary_a,
            &[
                "register",
                "mary",
                "--addr",
                "127.0.0.1:6501",
                "--directory",
                &dir,
            ],
        ),
        "register",
    );
    ok(
        &cli(
            &alice,
            &[
                "group",
                "create",
                "team",
                "--members",
                "mary",
                "--as",
                "alice",
                "--directory",
                &dir,
            ],
        ),
        "create",
    );
    ok(
        &cli(&mary_a, &["inbox", "--as", "mary", "--directory", &dir]),
        "mary-a invite",
    );
    ok(
        &cli(&alice, &["inbox", "--as", "alice", "--directory", &dir]),
        "alice mesh",
    );

    // Link device B *after* the group exists — it has no group state yet.
    let mary_b = pair_device(&mary_a, "mary", "gsync-b", &dir);

    // Sync groups from A to the cluster; B bootstraps into "team".
    ok(
        &cli(
            &mary_a,
            &["group", "sync", "--as", "mary", "--directory", &dir],
        ),
        "group sync",
    );
    ok(
        &cli(&mary_b, &["inbox", "--as", "mary", "--directory", &dir]),
        "mary-b bootstrap",
    );

    // Alice's later group message is readable on the newly-linked device B.
    ok(
        &cli(
            &alice,
            &[
                "group",
                "send",
                "team",
                "--as",
                "alice",
                "--message",
                "seen on laptop",
                "--directory",
                &dir,
            ],
        ),
        "alice send",
    );
    let b = cli(&mary_b, &["inbox", "--as", "mary", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&b.stdout).contains("seen on laptop"),
        "device B can't read group after sync: {}",
        String::from_utf8_lossy(&b.stdout)
    );

    // And a message from Mary's own phone (device A) also shows on B.
    ok(
        &cli(
            &mary_a,
            &[
                "group",
                "send",
                "team",
                "--as",
                "mary",
                "--message",
                "from my phone",
                "--directory",
                &dir,
            ],
        ),
        "mary-a send",
    );
    let b2 = cli(&mary_b, &["inbox", "--as", "mary", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&b2.stdout).contains("from my phone"),
        "device B can't read own cluster's msg: {}",
        String::from_utf8_lossy(&b2.stdout)
    );
}

#[test]
fn group_reaches_all_member_devices() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");

    // Bob: device A registers, device B links.
    let bob_a = home("grp-a");
    ok(&cli(&bob_a, &["identity-new"]), "identity-new");
    ok(
        &cli(
            &bob_a,
            &[
                "register",
                "bob",
                "--addr",
                "127.0.0.1:6201",
                "--directory",
                &dir,
            ],
        ),
        "register",
    );
    let bob_b = pair_device(&bob_a, "bob", "grp-b", &dir);

    // Alice creates the group; both Bob devices pick up the sender key.
    ok(
        &cli(
            &alice,
            &[
                "group",
                "create",
                "team",
                "--members",
                "bob",
                "--as",
                "alice",
                "--directory",
                &dir,
            ],
        ),
        "group create",
    );
    ok(
        &cli(&bob_a, &["inbox", "--as", "bob", "--directory", &dir]),
        "bob-a invite",
    );
    ok(
        &cli(&bob_b, &["inbox", "--as", "bob", "--directory", &dir]),
        "bob-b invite",
    );

    // Alice sends to the group; both of Bob's devices receive it.
    ok(
        &cli(
            &alice,
            &[
                "group",
                "send",
                "team",
                "--as",
                "alice",
                "--message",
                "hello team",
                "--directory",
                &dir,
            ],
        ),
        "group send",
    );
    let a = cli(&bob_a, &["inbox", "--as", "bob", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&a.stdout).contains("hello team"),
        "device A missed group msg: {}",
        String::from_utf8_lossy(&a.stdout)
    );
    let b = cli(&bob_b, &["inbox", "--as", "bob", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&b.stdout).contains("hello team"),
        "device B missed group msg: {}",
        String::from_utf8_lossy(&b.stdout)
    );
}

#[test]
fn sent_messages_sync_to_own_devices() {
    let _throttle = throttle();
    let dir = start_directory();
    let _john = account(&dir, "john");

    // Mary: device A registers, device B pairs in (seedless).
    let mary_a = home("sync-a");
    ok(&cli(&mary_a, &["identity-new"]), "identity-new");
    ok(
        &cli(
            &mary_a,
            &[
                "register",
                "mary",
                "--addr",
                "127.0.0.1:6101",
                "--directory",
                &dir,
            ],
        ),
        "register",
    );
    let mary_b = pair_device(&mary_a, "mary", "sync-b", &dir);

    // Mary sends to John from device A.
    ok(
        &cli(
            &mary_a,
            &[
                "send",
                "john",
                "--as",
                "mary",
                "--message",
                "from my phone",
                "--directory",
                &dir,
            ],
        ),
        "send",
    );

    // Device B mirrors the sent message, and it lands in Mary's transcript with John.
    let inbox_b = cli(&mary_b, &["inbox", "--as", "mary", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&inbox_b.stdout).contains("from my phone"),
        "device B did not sync: {}",
        String::from_utf8_lossy(&inbox_b.stdout)
    );
    let hist = cli(&mary_b, &["history", "john"]);
    assert!(
        String::from_utf8_lossy(&hist.stdout).contains("from my phone"),
        "not in device B history: {}",
        String::from_utf8_lossy(&hist.stdout)
    );
}

#[test]
fn message_reaches_all_recipient_devices() {
    let _throttle = throttle();
    let dir = start_directory();
    let john = account(&dir, "john");

    // Mary: device A registers the account, device B links to it.
    let mary_a = home("mary-a");
    ok(&cli(&mary_a, &["identity-new"]), "identity-new");
    ok(
        &cli(
            &mary_a,
            &[
                "register",
                "mary",
                "--addr",
                "127.0.0.1:6001",
                "--directory",
                &dir,
            ],
        ),
        "register",
    );
    let mary_b = pair_device(&mary_a, "mary", "mary-b", &dir);

    // John sends once to "mary" — his client fans out to her whole cluster.
    ok(
        &cli(
            &john,
            &[
                "send",
                "mary",
                "--as",
                "john",
                "--message",
                "hi cluster",
                "--directory",
                &dir,
            ],
        ),
        "send",
    );

    // Both of Mary's devices receive it.
    let a = cli(&mary_a, &["inbox", "--as", "mary", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&a.stdout).contains("hi cluster"),
        "device A missed it: {}",
        String::from_utf8_lossy(&a.stdout)
    );
    let b = cli(&mary_b, &["inbox", "--as", "mary", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&b.stdout).contains("hi cluster"),
        "device B missed it: {}",
        String::from_utf8_lossy(&b.stdout)
    );
}

#[test]
fn offline_send_and_receive() {
    let _throttle = throttle();
    let dir = start_directory();
    let (alice, bob) = two_accounts(&dir, "127.0.0.1:1", false); // addr unused offline

    ok(
        &cli(
            &alice,
            &[
                "send",
                "bob",
                "--as",
                "alice",
                "--message",
                "hello e2e",
                "--directory",
                &dir,
            ],
        ),
        "alice send",
    );

    let inbox = cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]);
    ok(&inbox, "bob inbox");
    let out = String::from_utf8_lossy(&inbox.stdout);
    assert!(
        out.contains("from alice: hello e2e"),
        "inbox output was: {out}"
    );

    // A second drain must be empty (the mailbox drained).
    let again = cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]);
    assert!(String::from_utf8_lossy(&again.stdout).contains("no new messages"));
}

/// Create an identity and register it (offline-reachable). Returns its home.
fn account(dir: &str, name: &str) -> PathBuf {
    let h = home(name);
    ok(&cli(&h, &["identity-new"]), "identity-new");
    ok(
        &cli(
            &h,
            &[
                "register",
                name,
                "--addr",
                "127.0.0.1:1",
                "--directory",
                dir,
            ],
        ),
        "register",
    );
    h
}

#[test]
fn broadcast_reaches_each_recipient() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");
    let carol = account(&dir, "carol");

    ok(
        &cli(
            &alice,
            &[
                "broadcast",
                "--to",
                "bob,carol",
                "--as",
                "alice",
                "--message",
                "town hall at 5",
                "--directory",
                &dir,
            ],
        ),
        "broadcast",
    );

    let b = cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&b.stdout).contains("town hall at 5"),
        "bob missed broadcast"
    );
    let c = cli(&carol, &["inbox", "--as", "carol", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&c.stdout).contains("town hall at 5"),
        "carol missed broadcast"
    );
}

#[test]
fn group_message_reaches_all_members() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");
    let carol = account(&dir, "carol");

    // Alice creates the group and invites Bob and Carol (sends them her key).
    ok(
        &cli(
            &alice,
            &[
                "group",
                "create",
                "team",
                "--members",
                "bob,carol",
                "--as",
                "alice",
                "--directory",
                &dir,
            ],
        ),
        "group create",
    );

    // Bob and Carol process the invite (learning Alice's sender key).
    ok(
        &cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]),
        "bob inbox",
    );
    ok(
        &cli(&carol, &["inbox", "--as", "carol", "--directory", &dir]),
        "carol inbox",
    );

    // Alice sends to the group; it fans out to every member.
    ok(
        &cli(
            &alice,
            &[
                "group",
                "send",
                "team",
                "--as",
                "alice",
                "--message",
                "hello team",
                "--directory",
                &dir,
            ],
        ),
        "group send",
    );

    // Both members receive and decrypt it.
    let bob_in = cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]);
    let b = String::from_utf8_lossy(&bob_in.stdout);
    assert!(
        b.contains("[team] alice: hello team"),
        "bob did not get the group message: {b}"
    );

    let carol_in = cli(&carol, &["inbox", "--as", "carol", "--directory", &dir]);
    let c = String::from_utf8_lossy(&carol_in.stdout);
    assert!(
        c.contains("[team] alice: hello team"),
        "carol did not get the group message: {c}"
    );

    // Groups are listed locally.
    let list = cli(&bob, &["group", "list"]);
    assert!(
        String::from_utf8_lossy(&list.stdout).contains("team"),
        "bob's group list missing 'team'"
    );

    // The transcript is recorded for both the sender and the receivers.
    let alice_hist = cli(&alice, &["group", "history", "team"]);
    assert!(
        String::from_utf8_lossy(&alice_hist.stdout).contains("alice: hello team"),
        "sender's group history missing the message",
    );
    let bob_hist = cli(&bob, &["group", "history", "team"]);
    assert!(
        String::from_utf8_lossy(&bob_hist.stdout).contains("alice: hello team"),
        "receiver's group history missing the message",
    );
}

#[test]
fn group_leave_and_info() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    ok(
        &cli(
            &alice,
            &[
                "group",
                "create",
                "team",
                "--members",
                "bob",
                "--as",
                "alice",
                "--directory",
                &dir,
            ],
        ),
        "create",
    );
    ok(
        &cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]),
        "bob inbox",
    );

    // Info lists members.
    let info = cli(&bob, &["group", "info", "team"]);
    assert!(
        String::from_utf8_lossy(&info.stdout).contains("members:"),
        "info missing members"
    );

    // Bob leaves; the group is gone from his list.
    ok(
        &cli(
            &bob,
            &["group", "leave", "team", "--as", "bob", "--directory", &dir],
        ),
        "leave",
    );
    let list = cli(&bob, &["group", "list"]);
    assert!(
        !String::from_utf8_lossy(&list.stdout).contains("team"),
        "group still listed after leaving"
    );
}

#[test]
fn draft_and_wipe() {
    let _throttle = throttle();
    // Drafts round-trip; wipe erases everything.
    let home = home("wipe");
    ok(&cli(&home, &["identity-new"]), "identity-new");
    ok(
        &cli(&home, &["draft", "set", "bob", "half-written thought"]),
        "draft set",
    );
    let show = cli(&home, &["draft", "show", "bob"]);
    assert!(
        String::from_utf8_lossy(&show.stdout).contains("half-written thought"),
        "draft not saved"
    );

    // Wipe requires --yes.
    let refused = cli(&home, &["wipe"]);
    assert!(
        !refused.status.success(),
        "wipe without --yes should refuse"
    );
    ok(&cli(&home, &["wipe", "--yes"]), "wipe --yes");

    // Identity is gone.
    let after = cli(&home, &["identity-show"]);
    assert!(
        !after.status.success(),
        "identity should be gone after wipe"
    );
}

#[test]
fn group_add_reaches_new_member() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");
    let dave = account(&dir, "dave");

    ok(
        &cli(
            &alice,
            &[
                "group",
                "create",
                "team",
                "--members",
                "bob",
                "--as",
                "alice",
                "--directory",
                &dir,
            ],
        ),
        "create",
    );
    ok(
        &cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]),
        "bob inbox",
    );

    // Add Dave later, then Dave joins from his inbox.
    ok(
        &cli(
            &alice,
            &[
                "group",
                "add",
                "team",
                "--member",
                "dave",
                "--as",
                "alice",
                "--directory",
                &dir,
            ],
        ),
        "group add",
    );
    ok(
        &cli(&dave, &["inbox", "--as", "dave", "--directory", &dir]),
        "dave inbox",
    );

    // A message sent after Dave joined reaches him.
    ok(
        &cli(
            &alice,
            &[
                "group",
                "send",
                "team",
                "--as",
                "alice",
                "--message",
                "welcome dave",
                "--directory",
                &dir,
            ],
        ),
        "group send",
    );
    let dave_in = cli(&dave, &["inbox", "--as", "dave", "--directory", &dir]);
    let d = String::from_utf8_lossy(&dave_in.stdout);
    assert!(
        d.contains("[team] alice: welcome dave"),
        "dave did not receive after being added: {d}"
    );
}

#[test]
fn group_leave_excludes_the_leaver() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");
    let carol = account(&dir, "carol");

    ok(
        &cli(
            &alice,
            &[
                "group",
                "create",
                "team",
                "--members",
                "bob,carol",
                "--as",
                "alice",
                "--directory",
                &dir,
            ],
        ),
        "create",
    );
    ok(
        &cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]),
        "bob inbox",
    );
    ok(
        &cli(&carol, &["inbox", "--as", "carol", "--directory", &dir]),
        "carol inbox",
    );

    // Carol *leaves* (authenticated self-removal — there is no "kick"). Alice
    // processes it and re-keys, then Bob picks up Alice's fresh key.
    ok(
        &cli(
            &carol,
            &[
                "group",
                "leave",
                "team",
                "--as",
                "carol",
                "--directory",
                &dir,
            ],
        ),
        "carol leave",
    );
    ok(
        &cli(&alice, &["inbox", "--as", "alice", "--directory", &dir]),
        "alice inbox after leave",
    );
    ok(
        &cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]),
        "bob inbox after leave",
    );

    // A message after the re-key reaches Bob but never Carol.
    ok(
        &cli(
            &alice,
            &[
                "group",
                "send",
                "team",
                "--as",
                "alice",
                "--message",
                "after leave",
                "--directory",
                &dir,
            ],
        ),
        "group send",
    );

    let bob_in = cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]);
    let b = String::from_utf8_lossy(&bob_in.stdout);
    assert!(
        b.contains("[team] alice: after leave"),
        "bob (still a member) should receive: {b}"
    );

    let carol_in = cli(&carol, &["inbox", "--as", "carol", "--directory", &dir]);
    let c = String::from_utf8_lossy(&carol_in.stdout);
    assert!(
        !c.contains("after leave"),
        "carol left, so she must NOT receive later messages: {c}"
    );
}

#[test]
fn clear_history_removes_a_conversation() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    ok(
        &cli(
            &bob,
            &[
                "send",
                "alice",
                "--as",
                "bob",
                "--message",
                "hi there",
                "--directory",
                &dir,
            ],
        ),
        "send",
    );
    ok(
        &cli(&alice, &["inbox", "--as", "alice", "--directory", &dir]),
        "inbox",
    );
    assert!(String::from_utf8_lossy(&cli(&alice, &["history", "bob"]).stdout).contains("hi there"));

    ok(&cli(&alice, &["clear-history", "bob"]), "clear");
    let after = cli(&alice, &["history", "bob"]);
    assert!(
        !String::from_utf8_lossy(&after.stdout).contains("hi there"),
        "history not cleared"
    );
}

#[test]
fn forward_relays_a_message() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");
    let carol = account(&dir, "carol");

    // Bob sends Alice a message; Alice reads it and learns its id.
    ok(
        &cli(
            &bob,
            &[
                "send",
                "alice",
                "--as",
                "bob",
                "--message",
                "the plan",
                "--directory",
                &dir,
            ],
        ),
        "bob send",
    );
    let alice_in = cli(&alice, &["inbox", "--as", "alice", "--directory", &dir]);
    let a = String::from_utf8_lossy(&alice_in.stdout);
    let id = a
        .split("(#")
        .nth(1)
        .and_then(|s| s.split(')').next())
        .map(|s| s.trim().to_string())
        .expect("id");

    // Alice forwards it to Carol.
    ok(
        &cli(
            &alice,
            &[
                "forward",
                &id,
                "--from",
                "bob",
                "--to",
                "carol",
                "--as",
                "alice",
                "--directory",
                &dir,
            ],
        ),
        "forward",
    );
    let carol_in = cli(&carol, &["inbox", "--as", "carol", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&carol_in.stdout).contains("Fwd from bob: the plan"),
        "carol did not receive the forward: {}",
        String::from_utf8_lossy(&carol_in.stdout),
    );
}

#[test]
fn edit_and_delete_apply_to_transcript() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    // Send and note the id.
    let out = cli(
        &alice,
        &[
            "send",
            "bob",
            "--as",
            "alice",
            "--message",
            "helo",
            "--directory",
            &dir,
        ],
    );
    let so = String::from_utf8_lossy(&out.stdout);
    let id = so
        .split("(#")
        .nth(1)
        .and_then(|s| s.split(')').next())
        .map(|s| s.trim().to_string())
        .expect("id");
    ok(
        &cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]),
        "inbox1",
    );

    // Edit it.
    ok(
        &cli(
            &alice,
            &[
                "send",
                "bob",
                "--as",
                "alice",
                "--edit",
                &id,
                "--message",
                "hello",
                "--directory",
                &dir,
            ],
        ),
        "edit",
    );
    ok(
        &cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]),
        "inbox2",
    );
    let h1 = cli(&bob, &["history", "alice"]);
    assert!(
        String::from_utf8_lossy(&h1.stdout).contains("hello (edited)"),
        "edit not applied: {}",
        String::from_utf8_lossy(&h1.stdout)
    );

    // Delete (unsend) it.
    ok(
        &cli(
            &alice,
            &[
                "send",
                "bob",
                "--as",
                "alice",
                "--delete",
                &id,
                "--directory",
                &dir,
            ],
        ),
        "delete",
    );
    ok(
        &cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]),
        "inbox3",
    );
    let h2 = cli(&bob, &["history", "alice"]);
    assert!(
        !String::from_utf8_lossy(&h2.stdout).contains("hello"),
        "message not deleted: {}",
        String::from_utf8_lossy(&h2.stdout)
    );
}

#[test]
fn export_and_import_round_trip() {
    let _throttle = throttle();
    // No directory needed — this is all local state.
    let alice = home("backup-alice");
    ok(&cli(&alice, &["identity-new"]), "identity-new");
    let wallet = field(&cli(&alice, &["identity-show"]).stdout, "wallet:");
    // Create some local state (a block entry — needs no network).
    ok(&cli(&alice, &["block", "spammer"]), "block");

    // Export, then import into a fresh home.
    let backup = std::env::temp_dir().join(format!("mycellium-backup-{}.bin", std::process::id()));
    ok(
        &cli(&alice, &["export", backup.to_str().unwrap()]),
        "export",
    );

    let restored = home("backup-restored");
    ok(
        &cli(&restored, &["import", backup.to_str().unwrap()]),
        "import",
    );

    // Same identity and the same local state come back.
    let restored_wallet = field(&cli(&restored, &["identity-show"]).stdout, "wallet:");
    assert_eq!(wallet, restored_wallet, "restored identity must match");
    let blocked = cli(&restored, &["blocked"]);
    assert!(
        String::from_utf8_lossy(&blocked.stdout).contains("spammer"),
        "block list not restored"
    );

    let _ = std::fs::remove_file(&backup);
}

#[test]
fn conversations_lists_peers() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    ok(
        &cli(
            &bob,
            &[
                "send",
                "alice",
                "--as",
                "bob",
                "--message",
                "dinner tonight?",
                "--directory",
                &dir,
            ],
        ),
        "send",
    );
    ok(
        &cli(&alice, &["inbox", "--as", "alice", "--directory", &dir]),
        "inbox",
    );

    let convos = cli(&alice, &["conversations"]);
    let out = String::from_utf8_lossy(&convos.stdout);
    assert!(out.contains("bob"), "conversations missing bob: {out}");
    assert!(
        out.contains("dinner tonight?"),
        "conversations missing preview: {out}"
    );
}

#[test]
fn search_finds_across_transcripts() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    ok(
        &cli(
            &alice,
            &[
                "send",
                "bob",
                "--as",
                "alice",
                "--message",
                "meet me at the harbor",
                "--directory",
                &dir,
            ],
        ),
        "send",
    );
    ok(
        &cli(
            &alice,
            &[
                "send",
                "bob",
                "--as",
                "alice",
                "--message",
                "unrelated chatter",
                "--directory",
                &dir,
            ],
        ),
        "send2",
    );
    ok(
        &cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]),
        "bob inbox",
    );

    // Case-insensitive search finds the matching line and not the other.
    let found = cli(&bob, &["search", "HARBOR"]);
    let out = String::from_utf8_lossy(&found.stdout);
    assert!(
        out.contains("meet me at the harbor"),
        "search missed the match: {out}"
    );
    assert!(
        !out.contains("unrelated chatter"),
        "search returned a non-match: {out}"
    );

    let none = cli(&bob, &["search", "zzz-nothing"]);
    assert!(String::from_utf8_lossy(&none.stdout).contains("no matches"));
}

#[test]
fn disappearing_message_expires() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    // One long-lived message and one that expires almost immediately.
    ok(
        &cli(
            &alice,
            &[
                "send",
                "bob",
                "--as",
                "alice",
                "--message",
                "stays",
                "--expire",
                "1h",
                "--directory",
                &dir,
            ],
        ),
        "send stays",
    );
    ok(
        &cli(
            &alice,
            &[
                "send",
                "bob",
                "--as",
                "alice",
                "--message",
                "poof",
                "--expire",
                "1s",
                "--directory",
                &dir,
            ],
        ),
        "send poof",
    );

    std::thread::sleep(Duration::from_secs(2));

    let bob_in = cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]);
    let b = String::from_utf8_lossy(&bob_in.stdout);
    assert!(b.contains("stays"), "long-TTL message should arrive: {b}");
    assert!(!b.contains("poof"), "expired message must be dropped: {b}");

    // Per-conversation default is stored and shown.
    ok(&cli(&alice, &["expire", "set", "bob", "1h"]), "expire set");
    let show = cli(&alice, &["expire", "show", "bob"]);
    assert!(
        String::from_utf8_lossy(&show.stdout).contains("3600s"),
        "default TTL not shown"
    );
}

#[test]
fn file_attachment_transfers() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    // Write a file for Alice to send.
    let src = home("attach-src");
    std::fs::create_dir_all(&src).unwrap();
    let file_path = src.join("note.txt");
    let contents = "the quick brown fox\n";
    std::fs::write(&file_path, contents).unwrap();

    ok(
        &cli(
            &alice,
            &[
                "send",
                "bob",
                "--as",
                "alice",
                "--file",
                file_path.to_str().unwrap(),
                "--directory",
                &dir,
            ],
        ),
        "send file",
    );

    // Bob receives it; it lands in his downloads and matches the original.
    let bob_in = cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]);
    let out = String::from_utf8_lossy(&bob_in.stdout);
    assert!(
        out.contains("📎 note.txt"),
        "bob inbox missing attachment: {out}"
    );

    let saved = bob.join("downloads").join("note.txt");
    let got = std::fs::read_to_string(&saved).expect("attachment saved");
    assert_eq!(got, contents, "attachment content mismatch");
}

#[test]
fn verify_shows_matching_safety_numbers() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    // Each side's `verify` of the other yields the same safety number.
    let a = cli(&alice, &["verify", "bob", "--directory", &dir]);
    let b = cli(&bob, &["verify", "alice", "--directory", &dir]);
    let extract = |out: &[u8]| -> String {
        String::from_utf8_lossy(out)
            .lines()
            .find(|l| l.trim_start().starts_with("safety number:"))
            .and_then(|l| l.split(": ").nth(1))
            .map(|s| s.trim().to_string())
            .expect("safety number line")
    };
    assert_eq!(
        extract(&a.stdout),
        extract(&b.stdout),
        "safety numbers must match"
    );
}

#[test]
fn contact_card_verifies_a_peer() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    // Bob prints his contact card.
    let card_out = cli(&bob, &["card", "bob"]);
    let out = String::from_utf8_lossy(&card_out.stdout);
    let card = out
        .lines()
        .find(|l| l.contains("verify-card "))
        .and_then(|l| l.split("verify-card ").nth(1))
        .map(|s| s.trim().to_string())
        .expect("card line in output");

    // Alice verifies it — it matches the directory record → verified.
    let v = cli(&alice, &["verify-card", &card, "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&v.stdout).contains("verified 'bob'"),
        "card should verify: {}",
        String::from_utf8_lossy(&v.stdout)
    );
    // And bob now reads as verified for alice.
    let vb = cli(&alice, &["verify", "bob", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&vb.stdout).contains("✓ verified"),
        "bob should now be verified"
    );
}

#[test]
fn verify_confirm_marks_a_peer_verified() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let _bob = account(&dir, "bob");

    // Before confirming, a first-seen peer reads as unverified.
    let before = cli(&alice, &["verify", "bob", "--directory", &dir]);
    let b = String::from_utf8_lossy(&before.stdout);
    assert!(
        b.contains("unverified"),
        "first contact should be unverified: {b}"
    );

    // Confirm after (notionally) comparing the number out of band.
    let confirmed = cli(&alice, &["verify", "bob", "--confirm", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&confirmed.stdout).contains("marked 'bob' as verified"),
        "confirm should mark verified",
    );

    // Now it reads as verified, both in `verify` and the contact-less state.
    let after = cli(&alice, &["verify", "bob", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&after.stdout).contains("✓ verified"),
        "peer should now be verified: {}",
        String::from_utf8_lossy(&after.stdout)
    );
}

#[test]
fn presence_reflects_announcements() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    // Bob hasn't announced: offline.
    let before = cli(&alice, &["presence", "bob", "--directory", &dir]);
    assert!(String::from_utf8_lossy(&before.stdout).contains("bob is offline"));

    // Bob announces, then Alice sees him online.
    ok(
        &cli(&bob, &["announce", "--as", "bob", "--directory", &dir]),
        "announce",
    );
    let after = cli(&alice, &["presence", "bob", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&after.stdout).contains("bob is online"),
        "bob should be online: {}",
        String::from_utf8_lossy(&after.stdout),
    );
}

#[test]
fn blocked_sender_is_dropped() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    // Alice blocks Bob.
    ok(&cli(&alice, &["block", "bob"]), "block");
    assert!(String::from_utf8_lossy(&cli(&alice, &["blocked"]).stdout).contains("bob"));

    // Bob sends anyway; Alice's inbox drops it (nothing shown).
    ok(
        &cli(
            &bob,
            &[
                "send",
                "alice",
                "--as",
                "bob",
                "--message",
                "let me in",
                "--directory",
                &dir,
            ],
        ),
        "send",
    );
    let alice_in = cli(&alice, &["inbox", "--as", "alice", "--directory", &dir]);
    let a = String::from_utf8_lossy(&alice_in.stdout);
    assert!(
        !a.contains("let me in"),
        "blocked message should not appear: {a}"
    );

    // After unblocking, a new message gets through.
    ok(&cli(&alice, &["unblock", "bob"]), "unblock");
    ok(
        &cli(
            &bob,
            &[
                "send",
                "alice",
                "--as",
                "bob",
                "--message",
                "now allowed",
                "--directory",
                &dir,
            ],
        ),
        "send2",
    );
    let alice_in2 = cli(&alice, &["inbox", "--as", "alice", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&alice_in2.stdout).contains("now allowed"),
        "unblocked message should arrive",
    );
}

#[test]
fn read_receipts_return_to_sender() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    // Alice sends and notes the message id from the output.
    let send_out = cli(
        &alice,
        &[
            "send",
            "bob",
            "--as",
            "alice",
            "--message",
            "ping",
            "--directory",
            &dir,
        ],
    );
    let so = String::from_utf8_lossy(&send_out.stdout);
    let id = so
        .split("(#")
        .nth(1)
        .and_then(|s| s.split(')').next())
        .map(|s| s.trim().to_string())
        .expect("message id");

    // Bob reads it (which sends a read receipt back).
    ok(
        &cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]),
        "bob inbox",
    );

    // Alice sees the receipt on her next inbox.
    let alice_in = cli(&alice, &["inbox", "--as", "alice", "--directory", &dir]);
    let a = String::from_utf8_lossy(&alice_in.stdout);
    assert!(
        a.contains(&format!("bob read your message #{id}")),
        "alice missing receipt: {a}"
    );
}

#[test]
fn contacts_resolve_nicknames() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    // Alice adds Bob under the nickname "b" (pinning his identity).
    ok(
        &cli(&alice, &["contact", "add", "b", "bob", "--directory", &dir]),
        "contact add",
    );
    let list = cli(&alice, &["contact", "list"]);
    assert!(
        String::from_utf8_lossy(&list.stdout).contains("b → bob"),
        "contact not listed"
    );

    // Sending to the nickname reaches Bob.
    ok(
        &cli(
            &alice,
            &[
                "send",
                "b",
                "--as",
                "alice",
                "--message",
                "via nickname",
                "--directory",
                &dir,
            ],
        ),
        "send by nickname",
    );
    let bob_in = cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]);
    let b = String::from_utf8_lossy(&bob_in.stdout);
    assert!(
        b.contains("from alice: via nickname"),
        "bob did not receive nickname-addressed message: {b}"
    );
}

#[test]
fn typed_messages_reply_and_react() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");
    let bob = account(&dir, "bob");

    // Alice sends a plain message; Bob reads it and learns its id.
    ok(
        &cli(
            &alice,
            &[
                "send",
                "bob",
                "--as",
                "alice",
                "--message",
                "original",
                "--directory",
                &dir,
            ],
        ),
        "send",
    );
    let bob_in = cli(&bob, &["inbox", "--as", "bob", "--directory", &dir]);
    let b = String::from_utf8_lossy(&bob_in.stdout);
    assert!(b.contains("from alice: original"), "bob inbox: {b}");
    let id = b
        .split("(#")
        .nth(1)
        .and_then(|s| s.split(')').next())
        .map(|s| s.trim().to_string())
        .expect("message id in output");
    assert!(!id.is_empty());

    // Bob reacts to and replies to that message.
    ok(
        &cli(
            &bob,
            &[
                "send",
                "alice",
                "--as",
                "bob",
                "--react",
                "👍",
                "--to",
                &id,
                "--directory",
                &dir,
            ],
        ),
        "react",
    );
    ok(
        &cli(
            &bob,
            &[
                "send",
                "alice",
                "--as",
                "bob",
                "--message",
                "sure",
                "--reply-to",
                &id,
                "--directory",
                &dir,
            ],
        ),
        "reply",
    );

    let alice_in = cli(&alice, &["inbox", "--as", "alice", "--directory", &dir]);
    let a = String::from_utf8_lossy(&alice_in.stdout);
    assert!(
        a.contains(&format!("reacted 👍 to {id}")),
        "alice missing reaction: {a}"
    );
    assert!(
        a.contains(&format!("↪ (re {id}) sure")),
        "alice missing reply: {a}"
    );
}

#[test]
fn history_is_persisted_after_a_chat() {
    let _throttle = throttle();
    let dir = start_directory();
    let bob_port = free_port();
    let bob_addr = format!("127.0.0.1:{bob_port}");
    let (alice, bob) = two_accounts(&dir, &bob_addr, false);

    let mut bob_listener = Command::new(CLI)
        .args(["listen", "--addr", &bob_addr])
        .env("MYCELLIUM_HOME", &bob)
        .env("MYCELLIUM_PASSPHRASE", PASS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn bob listen");
    wait_port(bob_port);

    let mut alice_chat = Command::new(CLI)
        .args(["chat", "bob", "--as", "alice", "--directory", &dir])
        .env("MYCELLIUM_HOME", &alice)
        .env("MYCELLIUM_PASSPHRASE", PASS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn alice chat");

    let mut alice_in = alice_chat.stdin.take().unwrap();
    let mut bob_in = bob_listener.stdin.take().unwrap();
    let alice_out = tail(alice_chat.stdout.take().unwrap());
    let bob_out = tail(bob_listener.stdout.take().unwrap());

    writeln!(alice_in, "history ping").unwrap();
    alice_in.flush().unwrap();
    assert!(wait_contains(&bob_out, "alice: history ping", 20));
    writeln!(bob_in, "history pong").unwrap();
    bob_in.flush().unwrap();
    assert!(wait_contains(&alice_out, "bob: history pong", 20));

    let _ = alice_chat.kill();
    let _ = alice_chat.wait();
    let _ = bob_listener.kill();
    let _ = bob_listener.wait();

    // Both sides persisted the transcript; `history` shows it, decrypted.
    let alice_hist = cli(&alice, &["history", "bob"]);
    ok(&alice_hist, "alice history");
    let a = String::from_utf8_lossy(&alice_hist.stdout);
    assert!(
        a.contains("you: history ping"),
        "alice history missing sent: {a}"
    );
    assert!(
        a.contains("bob: history pong"),
        "alice history missing received: {a}"
    );

    let bob_hist = cli(&bob, &["history", "alice"]);
    ok(&bob_hist, "bob history");
    let b = String::from_utf8_lossy(&bob_hist.stdout);
    assert!(
        b.contains("you: history pong"),
        "bob history missing sent: {b}"
    );
    assert!(
        b.contains("alice: history ping"),
        "bob history missing received: {b}"
    );
}

#[test]
fn full_duplex_over_tcp() {
    let _throttle = throttle();
    full_duplex(false);
}

#[test]
fn full_duplex_over_libp2p() {
    let _throttle = throttle();
    full_duplex(true);
}

/// Accumulate a child's stdout into a shared string, line by line.
fn tail(stdout: ChildStdout) -> Arc<Mutex<String>> {
    let buf = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&buf);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            sink.lock().unwrap().push_str(&line);
            line.clear();
        }
    });
    buf
}

/// Poll `buf` until it contains `needle`, or time out.
fn wait_contains(buf: &Arc<Mutex<String>>, needle: &str, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if buf.lock().unwrap().contains(needle) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Full-duplex: both peers send AND receive over one live connection.
fn full_duplex(libp2p: bool) {
    let dir = start_directory();
    let bob_port = free_port();
    let bob_addr = format!("127.0.0.1:{bob_port}");
    let (alice, bob) = two_accounts(&dir, &bob_addr, libp2p);

    let mut listen_args = vec!["listen", "--addr", &bob_addr];
    if libp2p {
        listen_args.push("--libp2p");
    }
    let mut bob_listener = Command::new(CLI)
        .args(&listen_args)
        .env("MYCELLIUM_HOME", &bob)
        .env("MYCELLIUM_PASSPHRASE", PASS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn bob listen");
    wait_port(bob_port);

    let mut alice_chat = Command::new(CLI)
        .args(["chat", "bob", "--as", "alice", "--directory", &dir])
        .env("MYCELLIUM_HOME", &alice)
        .env("MYCELLIUM_PASSPHRASE", PASS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn alice chat");

    // Keep both stdins open so neither side quits (Ctrl-D) mid-conversation.
    let mut alice_in = alice_chat.stdin.take().unwrap();
    let mut bob_in = bob_listener.stdin.take().unwrap();
    let alice_out = tail(alice_chat.stdout.take().unwrap());
    let bob_out = tail(bob_listener.stdout.take().unwrap());

    let tag = if libp2p { "libp2p" } else { "tcp" };
    // Alice speaks first (the responder can only reply after receiving).
    writeln!(alice_in, "ping from alice {tag}").unwrap();
    alice_in.flush().unwrap();
    let bob_got = wait_contains(&bob_out, &format!("alice: ping from alice {tag}"), 20);

    writeln!(bob_in, "pong from bob {tag}").unwrap();
    bob_in.flush().unwrap();
    let alice_got = wait_contains(&alice_out, &format!("bob: pong from bob {tag}"), 20);

    // Both directions delivered, and the safety numbers agree.
    let a = alice_out.lock().unwrap().clone();
    let b = bob_out.lock().unwrap().clone();
    let _ = alice_chat.kill();
    let _ = alice_chat.wait();
    let _ = bob_listener.kill();
    let _ = bob_listener.wait();

    assert!(
        bob_got,
        "bob never received alice's message.\nbob stdout:\n{b}"
    );
    assert!(
        alice_got,
        "alice never received bob's reply.\nalice stdout:\n{a}"
    );
    assert_eq!(
        safety_number(&a),
        safety_number(&b),
        "safety numbers disagree"
    );
}

#[test]
fn wrong_passphrase_is_rejected() {
    let _throttle = throttle();
    let h = home("pw");
    ok(&cli(&h, &["identity-new"]), "identity-new");

    // The same identity cannot be unlocked with a different passphrase.
    let out = cli_pass(&h, "not-the-passphrase", &["identity-show"]);
    assert!(!out.status.success(), "wrong passphrase must fail");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("passphrase"),
        "expected a passphrase error, got: {}",
        String::from_utf8_lossy(&out.stderr),
    );

    // The correct passphrase still works.
    ok(
        &cli(&h, &["identity-show"]),
        "identity-show with correct passphrase",
    );
}

#[test]
fn handle_squatting_is_rejected() {
    let _throttle = throttle();
    let dir = start_directory();
    let bob = home("bob");
    let mallory = home("mallory");
    ok(&cli(&bob, &["identity-new"]), "bob identity-new");
    ok(&cli(&mallory, &["identity-new"]), "mallory identity-new");

    ok(
        &cli(
            &bob,
            &[
                "register",
                "bob",
                "--addr",
                "127.0.0.1:1",
                "--directory",
                &dir,
            ],
        ),
        "bob registers 'bob'",
    );

    // Mallory holds a different key, so she cannot claim the same handle.
    let out = cli(
        &mallory,
        &[
            "register",
            "bob",
            "--addr",
            "127.0.0.1:2",
            "--directory",
            &dir,
        ],
    );
    assert!(
        !out.status.success(),
        "squatting a taken handle must be rejected"
    );
}

#[test]
fn outbox_parks_undeliverable_then_delivers_on_retry() {
    let _throttle = throttle();
    let dir = start_directory();
    let alice = account(&dir, "alice");

    // Carol registers a serve address but publishes NO queue (empty MYCELLIUM_QUEUE),
    // and is offline — so there is nowhere for a message to land.
    let carol_port = free_port();
    let carol_addr = format!("127.0.0.1:{carol_port}");
    let carol = home("carol-noq");
    ok(&cli(&carol, &["identity-new"]), "carol id");
    ok(
        &Command::new(CLI)
            .args([
                "register",
                "carol",
                "--addr",
                &carol_addr,
                "--directory",
                &dir,
            ])
            .env("MYCELLIUM_HOME", &carol)
            .env("MYCELLIUM_PASSPHRASE", PASS)
            .env("MYCELLIUM_QUEUE", "") // no queue in her record
            .stdin(Stdio::null())
            .output()
            .expect("carol register"),
        "carol register",
    );

    // Undeliverable → parked in Alice's outbox.
    let sent = cli(
        &alice,
        &[
            "send",
            "carol",
            "--as",
            "alice",
            "--message",
            "ping later",
            "--directory",
            &dir,
        ],
    );
    ok(&sent, "send");
    assert!(
        String::from_utf8_lossy(&sent.stdout).contains("queued for retry"),
        "message should be queued: {}",
        String::from_utf8_lossy(&sent.stdout),
    );

    // The outbox lists it as waiting for Carol.
    let waiting = cli(&alice, &["outbox", "--directory", &dir]);
    assert!(
        String::from_utf8_lossy(&waiting.stdout).contains("carol"),
        "outbox should list carol: {}",
        String::from_utf8_lossy(&waiting.stdout),
    );

    // Carol comes online with `serve` (announces presence before it binds).
    let mut carol_serve = Command::new(CLI)
        .args([
            "serve",
            "--addr",
            &carol_addr,
            "--as",
            "carol",
            "--directory",
            &dir,
        ])
        .env("MYCELLIUM_HOME", &carol)
        .env("MYCELLIUM_PASSPHRASE", PASS)
        .env("MYCELLIUM_QUEUE", "")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn carol serve");
    let carol_out = tail(carol_serve.stdout.take().unwrap());
    wait_port(carol_port);

    // Retrying the outbox now finds Carol online → live delivery.
    let flushed = cli(&alice, &["outbox", "--directory", &dir]);
    let got = wait_contains(&carol_out, "from alice: ping later", 20);

    let _ = carol_serve.kill();
    let _ = carol_serve.wait();
    assert!(
        got,
        "carol's serve did not receive the retried message:\n{}",
        carol_out.lock().unwrap()
    );
    assert!(
        String::from_utf8_lossy(&flushed.stdout).contains("delivered 1"),
        "outbox should report a delivery: {}",
        String::from_utf8_lossy(&flushed.stdout),
    );
}
