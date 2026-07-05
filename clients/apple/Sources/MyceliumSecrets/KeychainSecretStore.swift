// The Apple (iOS + macOS) adapter for the SDK's `SecretStore` seam (issue #65).
//
// Compiled only where the `Security` framework exists (Apple platforms). On
// Linux this whole file drops out and `FileSecretStore` is used instead — see
// FileSecretStore.swift.

#if canImport(Security)

import Foundation
import Security
import MyceliumSDK

/// Stores the account's root secret in the **iOS/macOS Keychain**.
///
/// Unlike Android's KeyStore (which stores *keys*, forcing an envelope-wrap of
/// the secret), the Apple Keychain stores arbitrary secret *items* directly, so
/// this maps each SDK secret to one generic-password item:
///
///   - `kSecClass`            = `kSecClassGenericPassword`
///   - `kSecAttrService`      = `"<serviceBase>.<namespace>"`  (see below)
///   - `kSecAttrAccount`      = the SDK key (today `"identity"`)
///   - `kSecValueData`        = the secret bytes
///   - `kSecAttrAccessible`   = `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
///
/// `WhenUnlockedThisDeviceOnly` keeps the item hardware-protected while the
/// device is locked and — crucially — **excludes it from iCloud Keychain and
/// device-transfer backups**, so the account root key never leaves the device
/// via restore (mirrors the Android `allowBackup=false` decision). Losing the
/// device is recoverable *without* exporting any secret: the account re-binds
/// from a fresh device by email verification (#6).
///
/// ## Namespacing (the Android collision bug, avoided)
/// The Android store originally used a single store directory, so two accounts
/// in one process both wrote their `"identity"` secret to the same path and
/// collided. Here the Keychain item is keyed by `(service, account)`, and the
/// `service` carries a per-account **namespace** suffix. A single-account app
/// leaves `namespace` empty; an app that holds more than one account (account
/// switching, or an in-process test with two clients) passes a distinct
/// namespace per account so their `"identity"` items never overwrite each other.
///
/// ## Fail-closed contract (matches the SDK trait doc)
/// `load` returns `nil` **only** for a genuinely absent item
/// (`errSecItemNotFound`). Any other Keychain error — a real read failure, a
/// locked/unavailable keychain — throws `SdkError.Storage`, so the SDK never
/// mistakes an unreadable identity for "no identity" and silently generates a
/// fresh one that would orphan the account.
///
/// ## Residual limits (stated plainly)
/// This raises the bar from "read a file" to "defeat the platform key store",
/// but does not protect a jailbroken device with the screen unlocked, nor an
/// in-process attacker while unlocked. To gate reads behind Face ID / Touch ID
/// (a "lock the app" UX) add a `SecAccessControl` with `.userPresence` to the
/// accessible attribute — deliberately omitted here so background `sync()` works.
public final class KeychainSecretStore: SecretStore {

    private let service: String

    /// - Parameters:
    ///   - namespace: isolates this account's items. Empty for a single-account
    ///     app; a distinct value per account otherwise (see the type doc).
    ///   - serviceBase: the Keychain service prefix; defaults to the app's
    ///     reverse-DNS identity namespace.
    ///   - accessGroup: optional Keychain access group for app-group sharing
    ///     (e.g. a Notification Service Extension). `nil` uses the app's default.
    public init(
        namespace: String = "",
        serviceBase: String = "eu.mycellium.identity",
        accessGroup: String? = nil
    ) {
        self.service = namespace.isEmpty ? serviceBase : "\(serviceBase).\(namespace)"
        self.accessGroup = accessGroup
    }

    private let accessGroup: String?

    // MARK: SecretStore

    public func store(key: String, secret: Data) throws {
        // Upsert: try to update an existing item first; add it if none exists.
        // (SecItemAdd fails with errSecDuplicateItem if one is already present.)
        let query = baseQuery(for: key)
        let attributes: [String: Any] = [
            kSecValueData as String: secret,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        if updateStatus != errSecItemNotFound {
            throw SdkError.Storage(msg: "keychain update failed (OSStatus \(updateStatus))")
        }

        // No existing item — add a fresh one.
        var addQuery = query
        addQuery[kSecValueData as String] = secret
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw SdkError.Storage(msg: "keychain add failed (OSStatus \(addStatus))")
        }
    }

    public func load(key: String) throws -> Data? {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else {
                // Present but unreadable as data -> fail closed, not "absent".
                throw SdkError.Storage(msg: "keychain item is not data")
            }
            return data
        case errSecItemNotFound:
            // The ONLY nil return: genuinely no such secret yet.
            return nil
        default:
            // A real read failure (locked keychain, etc.) -> fail closed.
            throw SdkError.Storage(msg: "keychain read failed (OSStatus \(status))")
        }
    }

    public func delete(key: String) throws {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        // Deleting an absent item is a no-op success (matches the trait).
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SdkError.Storage(msg: "keychain delete failed (OSStatus \(status))")
        }
    }

    // MARK: -

    /// The identity query for one SDK `key`: class + service (namespaced) +
    /// account, plus the access group when one is configured.
    private func baseQuery(for key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        return query
    }
}

#endif
