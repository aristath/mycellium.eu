// The SwiftUI screens (Apple-only; issues #68/#69), mirroring the Android app's
// flows: Setup → Onboarding → Conversations → Thread/compose, plus Contacts /
// verify. Each screen calls the real SDK methods through `MessengerViewModel`.
//
// Part of the Xcode app target, NOT the SwiftPM package (imports SwiftUI).

import SwiftUI
import MyceliumSDK

/// State-driven router: renders the screen the view-model currently selects.
struct RootView: View {
    @EnvironmentObject var vm: MessengerViewModel

    var body: some View {
        ZStack {
            switch vm.screen {
            case .loading: ProgressView("Loading…")
            case .setup: SetupView()
            case .onboarding: OnboardingView()
            case .conversations: ConversationsView()
            case .thread: ThreadView()
            case .contacts: ContactsView()
            }
            if vm.busy { ProgressView().padding().background(.thinMaterial).cornerRadius(8) }
        }
        .alert(
            "Error",
            isPresented: Binding(get: { vm.error != nil }, set: { if !$0 { vm.dismissError() } })
        ) {
            Button("OK", role: .cancel) { vm.dismissError() }
        } message: {
            Text(vm.error ?? "")
        }
    }
}

// MARK: - Setup

struct SetupView: View {
    @EnvironmentObject var vm: MessengerViewModel
    @State private var dir = ""
    @State private var queue = ""

    var body: some View {
        NavigationView {
            Form {
                Section("Directory + Queue") {
                    TextField("Directory URL (https://…)", text: $dir)
                        .textContentType(.URL).autocorrectionDisabled()
                    TextField("Queue URL (https://…)", text: $queue)
                        .textContentType(.URL).autocorrectionDisabled()
                }
                Button("Continue") { vm.saveSetup(dir: dir, queue: queue) }
                    .disabled(dir.isEmpty || queue.isEmpty)
            }
            .navigationTitle("Set up Mycellium")
            .onAppear { dir = vm.dirUrl; queue = vm.queueUrl }
        }
    }
}

// MARK: - Onboarding

struct OnboardingView: View {
    @EnvironmentObject var vm: MessengerViewModel
    @State private var code = ""

    var body: some View {
        NavigationView {
            Form {
                if vm.onboarding.stage == .details {
                    Section("Claim your handle") {
                        TextField("Handle (e.g. alice)", text: Binding(
                            get: { vm.onboarding.handle },
                            set: { vm.onboarding.handle = $0 }
                        )).autocorrectionDisabled()
                        TextField("Email", text: Binding(
                            get: { vm.onboarding.email },
                            set: { vm.onboarding.email = $0 }
                        )).keyboardType(.emailAddress).autocorrectionDisabled()
                    }
                    Button("Send verification code") { vm.startEmailVerification() }
                } else {
                    Section("Enter the code we emailed you") {
                        if let dev = vm.onboarding.devCode {
                            Text("Dev mode code: \(dev)").font(.footnote).foregroundStyle(.secondary)
                        }
                        TextField("Verification code", text: $code)
                            .keyboardType(.numberPad)
                    }
                    Button("Verify & register") { vm.confirmAndRegister(code: code) }
                }
            }
            .navigationTitle("Welcome")
        }
    }
}

// MARK: - Conversations

struct ConversationsView: View {
    @EnvironmentObject var vm: MessengerViewModel

    var body: some View {
        NavigationView {
            List(vm.conversations, id: \.peer) { convo in
                Button {
                    vm.openThread(peer: convo.peer)
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(convo.displayName.isEmpty ? convo.peer : convo.displayName)
                            .font(.headline)
                        Text(convo.lastPreview).font(.subheadline)
                            .foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
            .overlay {
                if vm.conversations.isEmpty {
                    ContentUnavailableViewCompat(
                        title: "No conversations yet",
                        subtitle: "Add a contact and send a message to get started."
                    )
                }
            }
            .navigationTitle("Chats")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { vm.openContacts() } label: { Image(systemName: "person.2") }
                }
                ToolbarItem(placement: .navigation) {
                    Button { vm.syncNow() } label: { Image(systemName: "arrow.clockwise") }
                }
            }
            .refreshable { vm.syncNow() }
        }
    }
}

// MARK: - Thread + compose

struct ThreadView: View {
    @EnvironmentObject var vm: MessengerViewModel
    @State private var draft = ""

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Button { vm.back() } label: { Image(systemName: "chevron.left") }
                Text(vm.openPeer ?? "").font(.headline)
                Spacer()
                if let peer = vm.openPeer {
                    Button("Safety #") { vm.showSafetyNumber(peer: peer) }
                }
            }
            .padding()

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 8) {
                    ForEach(vm.thread, id: \.id) { msg in
                        MessageRow(msg: msg)
                    }
                }
                .padding(.horizontal)
            }

            HStack {
                TextField("Message", text: $draft, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                Button {
                    let text = draft; draft = ""
                    vm.sendText(text)
                } label: { Image(systemName: "paperplane.fill") }
                    .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding()
        }
        .sheet(isPresented: Binding(
            get: { vm.safetyNumber != nil },
            set: { if !$0 { vm.clearSafetyNumber() } }
        )) {
            if let sn = vm.safetyNumber {
                SafetyNumberSheet(peer: sn.peer, number: sn.number)
                    .environmentObject(vm)
            }
        }
    }
}

struct MessageRow: View {
    let msg: Message
    var body: some View {
        HStack {
            if msg.fromMe { Spacer() }
            VStack(alignment: msg.fromMe ? .trailing : .leading, spacing: 2) {
                Text(msg.text)
                    .padding(8)
                    .background(msg.fromMe ? Color.accentColor.opacity(0.2) : Color.gray.opacity(0.15))
                    .cornerRadius(10)
                if msg.fromMe {
                    Text(msg.deliveryBadge).font(.caption2).foregroundStyle(.secondary)
                }
            }
            if !msg.fromMe { Spacer() }
        }
    }
}

// MARK: - Contacts + verify

struct ContactsView: View {
    @EnvironmentObject var vm: MessengerViewModel
    @State private var nickname = ""
    @State private var handle = ""

    var body: some View {
        NavigationView {
            List {
                Section("Add a contact") {
                    TextField("Nickname", text: $nickname).autocorrectionDisabled()
                    TextField("Handle", text: $handle).autocorrectionDisabled()
                    Button("Add") {
                        vm.addContact(nickname: nickname, handle: handle)
                        nickname = ""; handle = ""
                    }
                }
                Section("Contacts") {
                    ForEach(vm.contacts, id: \.handle) { c in
                        HStack {
                            VStack(alignment: .leading) {
                                Text(c.nickname).font(.headline)
                                Text(c.handle).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(c.trust.label).font(.caption)
                                .foregroundStyle(c.trust == .changed ? .red : .secondary)
                            Button("Verify") { vm.showSafetyNumber(peer: c.handle) }
                                .buttonStyle(.borderless)
                        }
                    }
                }
            }
            .navigationTitle("Contacts")
            .toolbar {
                ToolbarItem(placement: .navigation) {
                    Button { vm.back() } label: { Image(systemName: "chevron.left") }
                }
            }
            .sheet(isPresented: Binding(
                get: { vm.safetyNumber != nil },
                set: { if !$0 { vm.clearSafetyNumber() } }
            )) {
                if let sn = vm.safetyNumber {
                    SafetyNumberSheet(peer: sn.peer, number: sn.number)
                        .environmentObject(vm)
                }
            }
        }
    }
}

/// Shows the safety number to compare out of band, with a "mark verified" action.
struct SafetyNumberSheet: View {
    @EnvironmentObject var vm: MessengerViewModel
    let peer: String
    let number: String

    var body: some View {
        VStack(spacing: 16) {
            Text("Safety number with \(peer)").font(.headline)
            Text(number)
                .font(.system(.body, design: .monospaced))
                .multilineTextAlignment(.center)
                .padding()
            Text("Compare this with \(peer) over a trusted channel. If it matches, mark them verified.")
                .font(.footnote).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Mark verified") { vm.markVerified(peer: peer) }
                .buttonStyle(.borderedProminent)
            Button("Close") { vm.clearSafetyNumber() }
        }
        .padding()
    }
}

/// Minimal stand-in so this compiles on the widest OS range (ContentUnavailableView
/// is iOS 17+/macOS 14+; this keeps the deployment target lower).
struct ContentUnavailableViewCompat: View {
    let title: String
    let subtitle: String
    var body: some View {
        VStack(spacing: 8) {
            Text(title).font(.headline)
            Text(subtitle).font(.subheadline).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
    }
}
