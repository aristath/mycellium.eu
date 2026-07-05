// End-to-end messaging round-trip over the real `mycellium-sdk` Swift binding.
//
// This is the Swift analogue of the Rust `crates/mycellium-sdk/tests/sdk.rs`
// integration test, exercised through the exact same generated UniFFI surface a
// real Apple app uses. It runs on Linux against a **live** dev directory + queue
// (which the Swift process cannot start in-process, unlike the Rust test), so
// start those first (see README / build-rust.sh):
//
//   cargo build --release -p mycellium-server -p mycellium-queue
//   MYCELLIUM_DEV_AUTH=1 ./target/release/mycellium-server --addr 127.0.0.1:19080 &
//   ./target/release/mycellium-queue --addr 127.0.0.1:19090 &
//
// Endpoints are overridable via MYCELLIUM_DIR_URL / MYCELLIUM_QUEUE_URL
// (defaults http://127.0.0.1:19080 and http://127.0.0.1:19090).

import XCTest
import Foundation
// On Linux, URLSession/URLRequest live in a separate module.
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import MyceliumSDK
@testable import MyceliumSecrets

final class MessagingRoundTripTests: XCTestCase {

    private var dirUrl: String {
        ProcessInfo.processInfo.environment["MYCELLIUM_DIR_URL"] ?? "http://127.0.0.1:19080"
    }
    private var queueUrl: String {
        ProcessInfo.processInfo.environment["MYCELLIUM_QUEUE_URL"] ?? "http://127.0.0.1:19090"
    }

    /// A unique, isolated data dir for one client, cleaned up on teardown.
    private var tempDirs: [URL] = []
    private func makeDataDir(_ tag: String) -> String {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("mycellium-swift-test-\(tag)-\(ProcessInfo.processInfo.processIdentifier)-\(UUID().uuidString)")
        tempDirs.append(base)
        return base.path
    }

    override func tearDown() {
        for d in tempDirs { try? FileManager.default.removeItem(at: d) }
        tempDirs.removeAll()
        super.tearDown()
    }

    /// Register a fresh client under a fresh handle: email-verify (dev mode
    /// echoes the code), confirm, then publish the directory record.
    private func makeRegistered(tag: String, handle: String) throws -> MyceliumClient {
        let client = try MyceliumClient(dataDir: makeDataDir(tag))

        let verification = try client.startEmailVerification(
            dirUrl: dirUrl, handle: handle, email: "\(handle)@example.com"
        )
        // In dev-auth mode the directory echoes the code back; a real inbox
        // supplies it in production (devCode == nil).
        guard let code = verification.devCode else {
            throw XCTSkip("directory is not in dev-auth mode (no devCode); set MYCELLIUM_DEV_AUTH=1")
        }
        try client.confirmEmailVerification(
            dirUrl: dirUrl, pending: verification.pending, code: code
        )
        try client.register(dirUrl: dirUrl, queueUrl: queueUrl, handle: handle, name: handle)
        return client
    }

    func testTextRoundTrip() throws {
        try requireLiveServers()

        // Unique handles per run so reruns against a persistent directory don't
        // collide. Lowercase alphanumeric; short random suffix.
        let suffix = String(UUID().uuidString.prefix(8)).lowercased().filter { $0.isLetter || $0.isNumber }
        let aliceHandle = "alice\(suffix)"
        let bobHandle = "bob\(suffix)"

        let alice = try makeRegistered(tag: "alice", handle: aliceHandle)
        let bob = try makeRegistered(tag: "bob", handle: bobHandle)

        // Sanity: accounts reflect the registered handle.
        XCTAssertEqual(alice.account().handle, aliceHandle)
        XCTAssertEqual(bob.account().handle, bobHandle)

        let body = "hello bob — round-trip \(suffix)"
        let sent = try alice.sendText(peerHandle: bobHandle, text: body)
        XCTAssertTrue(sent.fromMe, "our own copy should be marked fromMe")
        XCTAssertEqual(sent.text, body)

        // Poll bob.sync() until the message decrypts and lands (queue delivery
        // is asynchronous). Bounded so a real failure fails fast.
        var received: Message?
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline {
            let fresh = try bob.sync()
            if let hit = fresh.first(where: { $0.text == body }) {
                received = hit
                break
            }
            Thread.sleep(forTimeInterval: 0.25)
        }

        let msg = try XCTUnwrap(received, "bob never received alice's message via sync()")
        XCTAssertFalse(msg.fromMe, "an inbound message must not be marked fromMe")
        XCTAssertEqual(msg.sender, aliceHandle)

        // And it is persisted in bob's transcript for alice's thread.
        let thread = try bob.thread(peerHandle: aliceHandle)
        XCTAssertTrue(
            thread.contains { $0.text == body && !$0.fromMe },
            "the received message should appear in bob.thread(alice)"
        )

        // The conversation list should surface alice as a peer for bob.
        let convos = try bob.conversations()
        XCTAssertTrue(
            convos.contains { $0.peer == aliceHandle },
            "alice should appear in bob's conversation list"
        )
    }

    /// The `EventListener` callback fires for inbound messages during `sync()`.
    func testListenerReceivesInbound() throws {
        try requireLiveServers()

        let suffix = String(UUID().uuidString.prefix(8)).lowercased().filter { $0.isLetter || $0.isNumber }
        let aliceHandle = "cara\(suffix)"
        let bobHandle = "dave\(suffix)"

        let alice = try makeRegistered(tag: "cara", handle: aliceHandle)
        let bob = try makeRegistered(tag: "dave", handle: bobHandle)

        let recorder = Recorder()
        bob.setListener(listener: recorder)

        let body = "listener check \(suffix)"
        _ = try alice.sendText(peerHandle: bobHandle, text: body)

        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline {
            _ = try bob.sync()
            if recorder.texts().contains(body) { break }
            Thread.sleep(forTimeInterval: 0.25)
        }
        XCTAssertTrue(recorder.texts().contains(body), "onMessage never fired for the inbound message")
    }

    /// The Linux/dev `FileSecretStore` satisfies the `SecretStore` contract:
    /// store → load round-trips, delete removes, absent loads return nil, and
    /// two namespaces are isolated.
    func testFileSecretStoreRoundTrip() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("mycellium-secrets-\(UUID().uuidString)")
        tempDirs.append(base)

        let a = FileSecretStore(baseDirectory: base, namespace: "acct-a")
        let b = FileSecretStore(baseDirectory: base, namespace: "acct-b")

        XCTAssertNil(try a.load(key: "identity"), "absent key must load as nil")

        let secretA = Data([1, 2, 3, 4, 5])
        let secretB = Data([9, 8, 7])
        try a.store(key: "identity", secret: secretA)
        try b.store(key: "identity", secret: secretB)

        // Namespaces are isolated — no collision (the Android bug, avoided).
        XCTAssertEqual(try a.load(key: "identity"), secretA)
        XCTAssertEqual(try b.load(key: "identity"), secretB)

        try a.delete(key: "identity")
        XCTAssertNil(try a.load(key: "identity"), "deleted key must load as nil")
        XCTAssertEqual(try b.load(key: "identity"), secretB, "delete in one namespace must not touch the other")

        // delete of an absent key is a no-op.
        XCTAssertNoThrow(try a.delete(key: "identity"))
    }

    // MARK: - helpers

    /// Skip (rather than fail) when the dev servers aren't up, so `swift test`
    /// is friendly locally; CI starts them and expects the round-trip to run.
    private func requireLiveServers() throws {
        guard reachable(dirUrl, path: "/health"), reachable(queueUrl, path: "/health") else {
            throw XCTSkip(
                "dev directory/queue not reachable at \(dirUrl) / \(queueUrl) — start them first (see README)"
            )
        }
    }

    private func reachable(_ base: String, path: String) -> Bool {
        guard let url = URL(string: base + path) else { return false }
        let sem = DispatchSemaphore(value: 0)
        let ok = Flag()
        var req = URLRequest(url: url)
        req.timeoutInterval = 3
        let task = URLSession.shared.dataTask(with: req) { _, response, _ in
            if let http = response as? HTTPURLResponse, (200..<500).contains(http.statusCode) {
                ok.set()
            }
            sem.signal()
        }
        task.resume()
        _ = sem.wait(timeout: .now() + 4)
        return ok.value
    }
}

/// A tiny thread-safe boolean flag (used by the reachability probe's callback).
private final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    func set() { lock.lock(); flag = true; lock.unlock() }
    var value: Bool { lock.lock(); defer { lock.unlock() }; return flag }
}

/// Records every message handed to `onMessage`, for asserting on callbacks.
private final class Recorder: EventListener {
    private let lock = NSLock()
    private var got: [Message] = []

    func onMessage(message: Message) {
        lock.lock(); got.append(message); lock.unlock()
    }
    func onDelivery(messageId: String, state: DeliveryState) {}
    func onKeyChange(handle: String) {}
    func onPairing(event: String) {}

    func texts() -> [String] {
        lock.lock(); defer { lock.unlock() }
        return got.map { $0.text }
    }
}
