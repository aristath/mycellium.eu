// Drives every screen against the real SDK (Apple-only; mirrors the Android
// `MessengerViewModel`). All SDK methods BLOCK, so each call runs on a
// background task; results are published on the main actor. An `EventListener`
// is registered so inbound messages surface live (the SDK fires `onMessage`
// during `sync()`), and a light poll calls `sync()` on an interval until native
// push (#71) replaces it.
//
// This file is part of the Xcode SwiftUI app target, NOT the SwiftPM package.

import Foundation
import SwiftUI
import MyceliumSDK

/// State-driven router — no navigation library, matching the Android app.
enum Screen { case loading, setup, onboarding, conversations, thread, contacts }

/// Two-step onboarding: collect handle+email, then enter the emailed code.
enum OnboardingStage { case details, code }

struct OnboardingState {
    var stage: OnboardingStage = .details
    var handle: String = ""
    var email: String = ""
    var pending: String = ""
    /// Populated only when the directory runs in dev mode (no SMTP); shown as a
    /// hint so local flows work without a real inbox.
    var devCode: String?
}

@MainActor
final class MessengerViewModel: ObservableObject {

    @Published var screen: Screen = .loading
    @Published var busy = false
    @Published var error: String?
    @Published var dirUrl = ""
    @Published var queueUrl = ""
    @Published var account: Account?
    @Published var onboarding = OnboardingState()
    @Published var conversations: [Conversation] = []
    @Published var openPeer: String?
    @Published var thread: [Message] = []
    @Published var contacts: [Contact] = []
    /// A safety number to compare out of band, plus the peer it belongs to.
    @Published var safetyNumber: (peer: String, number: String)?

    private var listener: UiEventListener?
    private var pollTask: Task<Void, Never>?

    private let dirKey = "dir_url"
    private let queueKey = "queue_url"
    private let pollInterval: UInt64 = 12_000_000_000 // 12s in ns

    // MARK: Bootstrap

    /// First launch: build the client (off main), install the listener, read
    /// persisted config + account, and route to the right screen.
    func bootstrap() {
        screen = .loading
        busy = true
        runSdk { client in
            let l = UiEventListener(self)
            client.setListener(listener: l)
            let account = client.account()
            let dir = client.getSetting(key: self.dirKey) ?? ""
            let queue = client.getSetting(key: self.queueKey) ?? ""
            await MainActor.run {
                self.listener = l
                self.account = account
                self.dirUrl = dir
                self.queueUrl = queue
                let registered = !account.handle.isEmpty
                self.screen = registered ? .conversations
                    : (!dir.isEmpty && !queue.isEmpty ? .onboarding : .setup)
            }
            if !account.handle.isEmpty {
                let convos = try client.conversations()
                await MainActor.run { self.conversations = convos }
                await MainActor.run { self.startPolling() }
            }
        }
    }

    // MARK: Setup

    func saveSetup(dir: String, queue: String) {
        let d = dir.trimmingCharacters(in: .whitespaces)
        let q = queue.trimmingCharacters(in: .whitespaces)
        guard !d.isEmpty, !q.isEmpty else { error = "Both URLs are required"; return }
        runSdk { client in
            client.setSetting(key: self.dirKey, value: d)
            client.setSetting(key: self.queueKey, value: q)
            await MainActor.run {
                self.dirUrl = d; self.queueUrl = q; self.screen = .onboarding
            }
        }
    }

    // MARK: Onboarding

    /// Step 1: start the email-verified claim of the handle.
    func startEmailVerification() {
        let handle = onboarding.handle.trimmingCharacters(in: .whitespaces)
        let email = onboarding.email.trimmingCharacters(in: .whitespaces)
        guard !handle.isEmpty, !email.isEmpty else {
            error = "Handle and email are required"; return
        }
        let dir = dirUrl
        runSdk { client in
            let v = try client.startEmailVerification(dirUrl: dir, handle: handle, email: email)
            await MainActor.run {
                self.onboarding.stage = .code
                self.onboarding.pending = v.pending
                self.onboarding.devCode = v.devCode
            }
        }
    }

    /// Step 2: confirm the code, then publish the directory record.
    func confirmAndRegister(code: String) {
        let trimmed = code.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { error = "Enter the verification code"; return }
        let dir = dirUrl, queue = queueUrl
        let handle = onboarding.handle.trimmingCharacters(in: .whitespaces)
        let pending = onboarding.pending
        runSdk { client in
            try client.confirmEmailVerification(dirUrl: dir, pending: pending, code: trimmed)
            // Display name defaults to the handle; a fuller UI could collect one.
            try client.register(dirUrl: dir, queueUrl: queue, handle: handle, name: handle)
            let account = client.account()
            let convos = try client.conversations()
            await MainActor.run {
                self.account = account
                self.conversations = convos
                self.screen = .conversations
                self.startPolling()
            }
        }
    }

    // MARK: Conversations + thread

    func refreshConversations() {
        runSdk { client in
            let convos = try client.conversations()
            await MainActor.run { self.conversations = convos }
        }
    }

    func openThread(peer: String) {
        runSdk { client in
            let messages = try client.thread(peerHandle: peer)
            await MainActor.run {
                self.openPeer = peer; self.thread = messages; self.screen = .thread
            }
        }
    }

    func sendText(_ text: String) {
        guard let peer = openPeer else { return }
        let body = text.trimmingCharacters(in: .whitespaces)
        guard !body.isEmpty else { return }
        runSdk { client in
            _ = try client.sendText(peerHandle: peer, text: body)
            let messages = try client.thread(peerHandle: peer)
            await MainActor.run { self.thread = messages }
        }
    }

    /// Foreground receive: drain the queue, decrypt, persist, refresh the view.
    func syncNow() {
        runSdk { client in
            _ = try client.sync()
            try await self.refreshVisible(client)
        }
    }

    // MARK: Contacts + verification

    func openContacts() {
        runSdk { client in
            let contacts = client.contacts()
            await MainActor.run { self.contacts = contacts; self.screen = .contacts }
        }
    }

    func addContact(nickname: String, handle: String) {
        let nick = nickname.trimmingCharacters(in: .whitespaces)
        let h = handle.trimmingCharacters(in: .whitespaces)
        guard !nick.isEmpty, !h.isEmpty else {
            error = "Nickname and handle are required"; return
        }
        runSdk { client in
            try client.addContact(nickname: nick, handle: h)
            let contacts = client.contacts()
            await MainActor.run { self.contacts = contacts }
        }
    }

    func showSafetyNumber(peer: String) {
        runSdk { client in
            let number = try client.safetyNumber(peerHandle: peer)
            await MainActor.run { self.safetyNumber = (peer, number) }
        }
    }

    func markVerified(peer: String) {
        runSdk { client in
            try client.markVerified(peerHandle: peer)
            let contacts = client.contacts()
            await MainActor.run { self.contacts = contacts; self.safetyNumber = nil }
        }
    }

    func clearSafetyNumber() { safetyNumber = nil }

    // MARK: Navigation

    func back() {
        switch screen {
        case .thread, .contacts:
            screen = .conversations; openPeer = nil
        default: break
        }
    }

    func dismissError() { error = nil }

    /// Called on scenePhase .active: pull anything that arrived while away.
    func onForeground() {
        if account?.handle.isEmpty == false { syncNow() }
    }

    // MARK: Live events + polling

    /// Light foreground poll until native push (#71) lands. Never busy-polls.
    private func startPolling() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: self?.pollInterval ?? 12_000_000_000)
                guard let self else { return }
                let s = await self.screen
                if s == .conversations || s == .thread {
                    do {
                        let client = try ClientHolder.get()
                        _ = try client.sync()
                        try await self.refreshVisible(client)
                    } catch {
                        // Transient network errors while polling are non-fatal.
                    }
                }
            }
        }
    }

    /// Refresh whichever list the user is currently looking at.
    private func refreshVisible(_ client: MyceliumClient) async throws {
        let s = await screen
        if s == .thread, let peer = await openPeer {
            let messages = try client.thread(peerHandle: peer)
            let convos = try client.conversations()
            await MainActor.run { self.thread = messages; self.conversations = convos }
        } else {
            let convos = try client.conversations()
            await MainActor.run { self.conversations = convos }
        }
    }

    // Called by the EventListener (from a Rust thread) to refresh the UI.
    func onInboundEvent() {
        runSdk { client in try await self.refreshVisible(client) }
    }

    func onKeyChanged(_ handle: String) {
        Task { @MainActor in
            self.error = "Safety warning: the key for \"\(handle)\" changed. Re-verify out of band."
        }
    }

    // MARK: SDK call plumbing

    /// Run a blocking SDK block off the main actor, toggling `busy` and mapping
    /// any `SdkError` to a user-facing `error`.
    private func runSdk(_ block: @escaping (MyceliumClient) async throws -> Void) {
        Task { @MainActor in self.busy = true }
        Task.detached {
            do {
                let client = try ClientHolder.get()
                try await block(client)
            } catch {
                let message = describe(error)
                await MainActor.run { self.error = message }
            }
            await MainActor.run { self.busy = false }
        }
    }
}

/// Bridges the SDK's `EventListener` (called from a Rust thread) to the
/// view-model. Marshals a UI refresh back onto the main actor.
final class UiEventListener: EventListener {
    private weak var vm: MessengerViewModel?
    init(_ vm: MessengerViewModel) { self.vm = vm }

    func onMessage(message: Message) { Task { await vm?.onInboundEvent() } }
    func onDelivery(messageId: String, state: DeliveryState) { Task { await vm?.onInboundEvent() } }
    func onKeyChange(handle: String) { Task { await vm?.onKeyChanged(handle) } }
    func onPairing(event: String) { /* QR pairing progress — out of MVP scope */ }
}

/// Map an `SdkError` variant to a concise, user-facing message.
func describe(_ error: Error) -> String {
    guard let e = error as? SdkError else {
        return (error as NSError).localizedDescription
    }
    switch e {
    case .NotRegistered: return "You need to register first."
    case .Network(let msg): return "Network error: \(msg)"
    case .Storage(let msg): return "Storage error: \(msg)"
    case .Crypto(let msg): return "Security error: \(msg)"
    case .InvalidInput(let msg): return "Invalid input: \(msg)"
    case .IdentityChanged(let handle):
        return "Safety warning: the identity for \"\(handle)\" changed. Re-verify out of band."
    }
}
