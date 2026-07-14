import Foundation
import MycelliumMobile
import Testing

@Test func freshClientStartsAtEmailLogin() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("mycellium-swift-\(UUID().uuidString)")
    let client = try MobileClient.open(
        dataDir: root.path,
        identitySecret: nil,
        registryUrl: "https://registry.mycellium.eu"
    )
    #expect(client.state() == .needsLogin)
}

@Test func malformedSecureIdentityFailsClosed() throws {
    for secret in [Data(repeating: 1, count: 63), Data(repeating: 1, count: 65), Data(repeating: 0, count: 64)] {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("mycellium-swift-malformed-\(UUID().uuidString)")
        #expect(throws: (any Error).self) {
            try MobileClient.open(
                dataDir: root.path,
                identitySecret: secret,
                registryUrl: "http://127.0.0.1:1"
            )
        }
    }
}

@Test func unauthenticatedOperationsFailLocally() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("mycellium-swift-inputs-\(UUID().uuidString)")
    let client = try MobileClient.open(
        dataDir: root.path,
        identitySecret: nil,
        registryUrl: "http://127.0.0.1:1"
    )

    #expect(throws: (any Error).self) { try client.requestEmailLogin(email: "   ") }
    #expect(throws: (any Error).self) { try client.confirmEmailLogin(code: "   ") }
    #expect(throws: (any Error).self) {
        try client.saveProfile(handle: "valid_handle", displayName: "Valid Name")
    }
    #expect(throws: (any Error).self) {
        try client.addContact(connectionCard: "not-a-card", nickname: nil)
    }
    #expect(throws: (any Error).self) {
        try client.sendText(userId: "invalid-user", text: "hello")
    }
    #expect(throws: (any Error).self) { try client.pendingCount() }
    #expect(throws: (any Error).self) { try client.refreshConnectivity() }
}
