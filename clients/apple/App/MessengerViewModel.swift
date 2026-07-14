import Foundation

struct MessengerState {
    var initialized = false
    var busy = false
    var clientState: ClientState = .needsLogin
    var loginRequested = false
    var error: String?
    var notice: String?
    var conversations: [ConversationInfo] = []
    var contacts: [ContactInfo] = []
    var profile: ProfileInfo?
    var pendingCount: UInt64 = 0
    var selectedUserId: String?
    var selectedTitle = ""
    var messages: [MessageInfo] = []
    var security: ContactSecurityInfo?
}

private struct ClientSnapshot: Sendable {
    let clientState: ClientState
    let conversations: [ConversationInfo]
    let contacts: [ContactInfo]
    let profile: ProfileInfo?
    let pendingCount: UInt64
}

@MainActor
final class MessengerViewModel: ObservableObject {
    @Published private(set) var state = MessengerState()
    private var client: MobileClient?
    private var eventTask: Task<Void, Never>?

    init() {
        Task { await bootstrap() }
    }

    deinit { eventTask?.cancel() }

    func requestLogin(email: String) {
        guard !email.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            fail("Enter your email address")
            return
        }
        perform { client in
            _ = try client.requestEmailLogin(email: email.trimmingCharacters(in: .whitespacesAndNewlines))
            await MainActor.run {
                self.state.loginRequested = true
                self.state.notice = "Check your email for the login code"
            }
        }
    }

    func confirmLogin(code: String) {
        guard !code.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            fail("Enter the code from your email")
            return
        }
        perform { client in
            let result = try client.confirmEmailLogin(code: code.trimmingCharacters(in: .whitespacesAndNewlines))
            if var secret = result.identitySecret {
                defer { secret.resetBytes(in: 0..<secret.count) }
                try KeychainIdentityStore().save(secret)
            }
            await MainActor.run {
                self.state.loginRequested = false
                self.state.notice = result.created ? "Account created" : "This device is active"
            }
            try await self.refresh(client)
        }
    }

    func confirmLogin(link: URL) {
        perform { client in
            let result = try client.confirmEmailLoginLink(link: link.absoluteString)
            if var secret = result.identitySecret {
                defer { secret.resetBytes(in: 0..<secret.count) }
                try KeychainIdentityStore().save(secret)
            }
            await MainActor.run {
                self.state.loginRequested = false
                self.state.notice = result.created ? "Account created" : "This device is active"
            }
            try await self.refresh(client)
        }
    }

    func saveProfile(handle: String, displayName: String) {
        perform { client in
            _ = try client.saveProfile(handle: handle, displayName: displayName)
            await MainActor.run { self.state.notice = "Profile saved" }
            try await self.refresh(client)
        }
    }

    func addContact(card: String, nickname: String) {
        perform { client in
            let cleanName = nickname.trimmingCharacters(in: .whitespacesAndNewlines)
            let contact = try client.addContact(
                connectionCard: card.trimmingCharacters(in: .whitespacesAndNewlines),
                nickname: cleanName.isEmpty ? nil : cleanName
            )
            await MainActor.run { self.state.notice = "\(contact.nickname) added" }
            try await self.refresh(client)
        }
    }

    func removeContact(_ contact: ContactInfo) {
        perform { client in
            try client.removeContact(nickname: contact.nickname)
            await MainActor.run {
                self.state.security = nil
                self.state.selectedUserId = nil
                self.state.notice = "Person removed"
            }
            try await self.refresh(client)
        }
    }

    func openConversation(userId: String, title: String) {
        state.selectedUserId = userId
        state.selectedTitle = title
        state.security = nil
        refreshMessages()
    }

    func closeConversation() {
        state.selectedUserId = nil
        state.selectedTitle = ""
        state.messages = []
    }

    func sendMessage(_ text: String) {
        guard let userId = state.selectedUserId else { return }
        perform { client in
            let delivery = try client.sendText(userId: userId, text: text)
            await MainActor.run {
                self.state.notice = delivery == .delivered
                    ? "Delivered"
                    : "Direct connection unavailable. This device will keep trying."
            }
            try await self.refresh(client)
            try await self.refreshMessages(client)
        }
    }

    func retryPending() {
        perform { client in
            let waiting = try client.retryPending()
            await MainActor.run {
                self.state.notice = waiting == 0 ? "Pending messages delivered" : "\(waiting) still pending"
            }
            try await self.refresh(client)
        }
    }

    func showSecurity(userId: String) {
        perform { client in
            let security = try client.contactSecurity(userId: userId)
            await MainActor.run { self.state.security = security }
        }
    }

    func dismissSecurity() { state.security = nil }

    func verifyContact(userId: String) {
        perform { client in
            try client.verifyContact(userId: userId)
            await MainActor.run {
                self.state.security = nil
                self.state.notice = "Identity verified"
            }
            try await self.refresh(client)
        }
    }

    func acceptIdentityChange(userId: String) {
        perform { client in
            try client.acceptIdentityChange(userId: userId)
            await MainActor.run {
                self.state.security = nil
                self.state.notice = "New identity accepted"
            }
            try await self.refresh(client)
        }
    }

    func setContactBlocked(userId: String, blocked: Bool) {
        perform { client in
            try client.setContactBlocked(userId: userId, blocked: blocked)
            let security = try client.contactSecurity(userId: userId)
            await MainActor.run {
                self.state.security = security
                self.state.notice = blocked ? "Person blocked" : "Person unblocked"
            }
        }
    }

    func restartLogin() {
        state.loginRequested = false
        state.error = nil
        state.notice = nil
    }

    func clearBanner() {
        state.error = nil
        state.notice = nil
    }

    func onForeground() {
        guard let client else { return }
        Task {
            _ = try? await Task.detached { try client.refreshConnectivity() }.value
            _ = try? await Task.detached { try client.refreshDeviceStatus() }.value
            try? await refresh(client)
        }
    }

    private func bootstrap() async {
        do {
            let opened = try await Task.detached {
                let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                let directory = base.appendingPathComponent("Mycellium", isDirectory: true)
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                var values = URLResourceValues()
                values.isExcludedFromBackup = true
                var mutableDirectory = directory
                try mutableDirectory.setResourceValues(values)
                let secret = try KeychainIdentityStore().load()
                return try MobileClient.open(
                    dataDir: directory.path,
                    identitySecret: secret,
                    registryUrl: nil
                )
            }.value
            client = opened
            try await refresh(opened)
            state.initialized = true
            startEventPolling(opened)
        } catch {
            fail(error.localizedDescription)
            state.initialized = true
        }
    }

    private func perform(
        _ operation: @escaping @Sendable (MobileClient) async throws -> Void
    ) {
        guard !state.busy, let client else { return }
        state.busy = true
        state.error = nil
        state.notice = nil
        Task {
            do {
                try await Task.detached { try await operation(client) }.value
            } catch {
                fail(error.localizedDescription)
            }
            state.busy = false
        }
    }

    private func refresh(_ client: MobileClient) async throws {
        let snapshot = try await Task.detached {
            let clientState = client.state()
            let available = clientState == .ready || clientState == .replaced
            return try ClientSnapshot(
                clientState: clientState,
                conversations: available ? client.conversations() : [],
                contacts: available ? client.contacts() : [],
                profile: available ? client.profile() : nil,
                pendingCount: available ? client.pendingCount() : 0
            )
        }.value
        state.clientState = snapshot.clientState
        state.conversations = snapshot.conversations
        state.contacts = snapshot.contacts.sorted {
            $0.nickname.localizedCaseInsensitiveCompare($1.nickname) == .orderedAscending
        }
        state.profile = snapshot.profile
        state.pendingCount = snapshot.pendingCount
    }

    private func refreshMessages() {
        guard let client else { return }
        Task { try? await refreshMessages(client) }
    }

    private func refreshMessages(_ client: MobileClient) async throws {
        guard let userId = state.selectedUserId else { return }
        let messages = try await Task.detached { try client.messages(userId: userId) }.value
        guard state.selectedUserId == userId else { return }
        state.messages = messages
    }

    private func startEventPolling(_ client: MobileClient) {
        eventTask?.cancel()
        eventTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                let events = await Task.detached { client.pollEvents() }.value
                guard let latest = events.last else { continue }
                if latest.kind == .error {
                    state.error = latest.message
                } else {
                    state.notice = latest.message
                }
                try? await refresh(client)
                try? await refreshMessages(client)
            }
        }
    }

    private func fail(_ message: String) {
        state.error = message
        state.notice = nil
        state.busy = false
    }
}
