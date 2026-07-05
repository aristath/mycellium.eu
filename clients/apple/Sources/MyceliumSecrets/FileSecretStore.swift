// A file-based `SecretStore` fallback for platforms without an OS keychain —
// i.e. Linux (CI, `swift test`) and headless dev.
//
// **Dev / non-Apple only.** It writes each secret **unencrypted** to a file
// (best-effort `0600` on Unix), one file per key, under a per-namespace
// directory. It provides no at-rest confidentiality: anyone who can read the
// file reads the account key. It exists so this package builds and its
// messaging round-trip test runs on Linux, where `KeychainSecretStore`
// (Security framework) does not exist. Apple apps MUST use
// `KeychainSecretStore` instead (see KeychainSecretStore.swift, issue #65).
//
// This mirrors the SDK's own `PlaintextFileSecretStore` Rust default, and honors
// the same fail-closed contract: `load` returns `nil` only when the file is
// genuinely absent; any other read failure throws.

import Foundation
import MyceliumSDK

/// A plaintext, per-namespace, file-backed `SecretStore`. Dev/test only.
public final class FileSecretStore: SecretStore {

    private let dir: URL

    /// - Parameters:
    ///   - baseDirectory: the parent directory for the store.
    ///   - namespace: isolates one account's secrets under
    ///     `baseDirectory/<namespace>/`. Empty for a single-account store; a
    ///     distinct value per account otherwise, so two accounts' `"identity"`
    ///     files never collide (the same collision the Android store originally
    ///     hit, avoided here by namespacing the directory).
    public init(baseDirectory: URL, namespace: String = "") {
        if namespace.isEmpty {
            self.dir = baseDirectory
        } else {
            // Percent-encode the namespace to a safe single path component.
            let safe = namespace.addingPercentEncoding(
                withAllowedCharacters: .alphanumerics
            ) ?? "ns"
            self.dir = baseDirectory.appendingPathComponent(safe, isDirectory: true)
        }
    }

    // MARK: SecretStore

    public func store(key: String, secret: Data) throws {
        try ensureDir()
        let url = try fileURL(for: key)
        do {
            try secret.write(to: url, options: [.atomic])
            restrict(url)
        } catch {
            throw SdkError.Storage(msg: "file secret write failed: \(error.localizedDescription)")
        }
    }

    public func load(key: String) throws -> Data? {
        let url = try fileURL(for: key)
        if !FileManager.default.fileExists(atPath: url.path) {
            return nil // the ONLY nil return: genuinely absent.
        }
        do {
            return try Data(contentsOf: url)
        } catch {
            // Present but unreadable -> fail closed, not "absent".
            throw SdkError.Storage(msg: "file secret read failed: \(error.localizedDescription)")
        }
    }

    public func delete(key: String) throws {
        let url = try fileURL(for: key)
        do {
            try FileManager.default.removeItem(at: url)
        } catch CocoaError.fileNoSuchFile {
            // no-op if absent
        } catch let error as NSError where error.domain == NSCocoaErrorDomain
            && error.code == NSFileNoSuchFileError {
            // no-op if absent (older error shape)
        } catch {
            throw SdkError.Storage(msg: "file secret delete failed: \(error.localizedDescription)")
        }
    }

    // MARK: -

    private func ensureDir() throws {
        do {
            try FileManager.default.createDirectory(
                at: dir, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw SdkError.Storage(msg: "file secret dir create failed: \(error.localizedDescription)")
        }
    }

    /// Reject keys that aren't a single safe filename component, so a key can
    /// never escape the store directory. SDK keys are internal ("identity"),
    /// so this is a guard, not a general path sanitiser.
    private func fileURL(for key: String) throws -> URL {
        if key.isEmpty || key == "." || key == ".." || key.contains("/") || key.contains("\\") {
            throw SdkError.InvalidInput(msg: "invalid secret key")
        }
        return dir.appendingPathComponent(key, isDirectory: false)
    }

    private func restrict(_ url: URL) {
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: url.path
        )
    }
}
