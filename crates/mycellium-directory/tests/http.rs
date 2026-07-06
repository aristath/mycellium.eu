//! HTTP-layer tests: hit a running directory with a real client and check the
//! request parsing, status codes, and auth extraction — the parts the
//! library-level `Directory` tests don't exercise.

use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use mycellium_core::identity::Identity;
use mycellium_core::platform::Platform;

/// OS-backed entropy for generating a test identity.
struct OsPlatform;
impl Platform for OsPlatform {
    fn fill_random(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("OS RNG");
    }
    fn now_unix_secs(&self) -> u64 {
        0
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start() -> String {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let serve = addr.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async {
            let _ =
                mycellium_directory::serve(&serve, mycellium_directory::ServeConfig::dev()).await;
        });
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    format!("http://{addr}")
}

/// The HTTP status of a ureq call, treating 4xx/5xx (which ureq returns as
/// `Err`) as their code.
fn status(result: Result<ureq::Response, ureq::Error>) -> u16 {
    match result {
        Ok(resp) => resp.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(other) => panic!("transport error: {other}"),
    }
}

#[test]
fn health_ok() {
    let base = start();
    assert_eq!(status(ureq::get(&format!("{base}/health")).call()), 200);
}

#[test]
fn valid_challenge_returns_a_nonce() {
    let base = start();
    let id = Identity::generate(&mut OsPlatform).unwrap();
    let wallet = serde_json::to_value(id.wallet_public()).unwrap();

    let resp = ureq::post(&format!("{base}/login/challenge"))
        .send_json(serde_json::json!({ "wallet": wallet }))
        .expect("challenge should succeed");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("nonce").and_then(|n| n.as_str()).is_some());
}

#[test]
fn malformed_json_is_rejected() {
    let base = start();
    let result = ureq::post(&format!("{base}/login/challenge"))
        .set("Content-Type", "application/json")
        .send_string("this is not json");
    assert!(
        (400..500).contains(&status(result)),
        "malformed body should be a 4xx"
    );
}

#[test]
fn unknown_record_is_404() {
    let base = start();
    assert_eq!(
        status(ureq::get(&format!("{base}/records/nobody")).call()),
        404
    );
}

#[test]
fn publish_without_auth_is_401() {
    let base = start();
    let result = ureq::request("PUT", &format!("{base}/records/alice")).send_string("{}");
    assert_eq!(status(result), 401);
}

#[test]
fn unknown_route_is_404() {
    let base = start();
    assert_eq!(status(ureq::get(&format!("{base}/nope")).call()), 404);
}
