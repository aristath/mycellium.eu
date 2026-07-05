// Process-wide holder for the one `MyceliumClient` (issues #68/#69).
//
// Apple-only. This file is part of the Xcode SwiftUI app target, NOT the
// SwiftPM package — it is excluded from `swift build`/`swift test` on Linux.
//
// The client is a stateful handle to this account on this device; the app
// builds exactly one and shares it (the Rust object guards its own interior
// state with a Mutex, so it is safe to call from any thread).
//
// It is built with the PRODUCTION constructor `MyceliumClient.newWithSecretStore`
// backed by `KeychainSecretStore` (issue #65). The plaintext dev constructor
// `MyceliumClient(dataDir:)` is deliberately never used here.

import Foundation
import MyceliumSDK
import MyceliumSecrets

/// Lazily builds and shares the single `MyceliumClient`. `get()` BLOCKS
/// (`newWithSecretStore` opens the encrypted store and touches the Keychain),
/// so call it off the main thread — the view-model does, on a background task.
enum ClientHolder {

    private static let lock = NSLock()
    nonisolated(unsafe) private static var client: MyceliumClient?

    /// The app-private data directory for the encrypted store (Application
    /// Support, which is backed up unless excluded — the SDK's `store` is
    /// keyed from the identity, and the identity itself lives in the Keychain).
    private static var dataDir: String {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = base.appendingPathComponent("Mycellium", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.path
    }

    static func get() throws -> MyceliumClient {
        lock.lock(); defer { lock.unlock() }
        if let client { return client }
        let built = try MyceliumClient.newWithSecretStore(
            dataDir: dataDir,
            // Single-account app -> empty namespace. Give a distinct namespace
            // per account if the app ever holds more than one (account switching).
            secrets: KeychainSecretStore(namespace: "")
        )
        client = built
        return built
    }
}
