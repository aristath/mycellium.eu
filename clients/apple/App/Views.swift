import SwiftUI
import UIKit

struct RootView: View {
    @EnvironmentObject private var model: MessengerViewModel

    var body: some View {
        ZStack(alignment: .top) {
            Color.myCanvas.ignoresSafeArea()
            Group {
                if !model.state.initialized {
                    LaunchView()
                } else if model.state.clientState == .ready {
                    if model.state.selectedUserId != nil {
                        ConversationView()
                    } else {
                        MainShellView()
                    }
                } else {
                    AccountView()
                }
            }
            if let message = model.state.error ?? model.state.notice {
                Banner(message: message, error: model.state.error != nil)
                    .padding(.horizontal, 16)
                    .padding(.top, 8)
                    .transition(.move(edge: .top).combined(with: .opacity))
                    .onTapGesture { model.clearBanner() }
                    .task(id: message) {
                        try? await Task.sleep(for: .seconds(4))
                        model.clearBanner()
                    }
            }
        }
        .tint(.myMoss)
        .foregroundStyle(Color.myText)
        .animation(.easeOut(duration: 0.22), value: model.state.error)
        .animation(.easeOut(duration: 0.22), value: model.state.notice)
    }
}

private struct LaunchView: View {
    var body: some View {
        VStack(spacing: 24) {
            NodeMark(size: 72)
            ProgressView().tint(.myMoss)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct AccountView: View {
    @EnvironmentObject private var model: MessengerViewModel
    @State private var email = ""
    @State private var code = ""
    @State private var displayName = ""
    @State private var handle = ""
    @FocusState private var focus: Field?

    private enum Field { case email, code, displayName, handle }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                NodeMark()
                Spacer().frame(height: 42)
                if model.state.clientState == .needsProfile {
                    profileForm
                } else {
                    loginForm
                }
                Spacer().frame(height: 52)
                Text("PRIVATE BY STRUCTURE")
                    .font(.caption.monospaced().weight(.semibold))
                    .tracking(1)
                    .foregroundStyle(Color.myMoss)
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 30)
            .frame(maxWidth: 560, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .scrollDismissesKeyboard(.interactively)
        .background(Color.myCanvas)
    }

    @ViewBuilder
    private var loginForm: some View {
        if model.state.clientState == .replaced {
            StatusCard(
                title: "This device was replaced",
                bodyText: "Messages remain here, but sending is disabled. Log in again to make this device active.",
                accent: .mySpore
            )
            Spacer().frame(height: 28)
        }
        Text(model.state.loginRequested ? "Enter your login code" : "Continue with email")
            .font(.system(size: 32, weight: .light, design: .rounded))
        Spacer().frame(height: 10)
        Text(model.state.loginRequested
             ? "We sent a one-time code to your email."
             : "Your email opens your account on this device.")
            .foregroundStyle(Color.myMuted)
        Spacer().frame(height: 32)
        if model.state.loginRequested {
            TextField("Login code", text: $code)
                .textContentType(.oneTimeCode)
                .textInputAutocapitalization(.never)
                .focused($focus, equals: .code)
                .submitLabel(.go)
                .onSubmit { model.confirmLogin(code: code) }
                .fieldStyle()
            Spacer().frame(height: 16)
            PrimaryAction(title: "Open my account", busy: model.state.busy) {
                model.confirmLogin(code: code)
            }
            Button("Use another email") { model.restartLogin() }
                .buttonStyle(.plain)
                .foregroundStyle(Color.myMoss)
                .frame(maxWidth: .infinity)
                .padding(.top, 16)
        } else {
            TextField("Email address", text: $email)
                .keyboardType(.emailAddress)
                .textContentType(.emailAddress)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .focused($focus, equals: .email)
                .submitLabel(.send)
                .onSubmit { model.requestLogin(email: email) }
                .fieldStyle()
            Spacer().frame(height: 16)
            PrimaryAction(title: "Email me a code", busy: model.state.busy) {
                model.requestLogin(email: email)
            }
        }
    }

    @ViewBuilder
    private var profileForm: some View {
        Text("What should people call you?")
            .font(.system(size: 32, weight: .light, design: .rounded))
        Spacer().frame(height: 10)
        Text("Your name is shown in conversations. Your handle is a short, non-unique label.")
            .foregroundStyle(Color.myMuted)
        Spacer().frame(height: 32)
        TextField("Display name", text: $displayName)
            .textContentType(.name)
            .focused($focus, equals: .displayName)
            .submitLabel(.next)
            .onSubmit { focus = .handle }
            .fieldStyle()
        Spacer().frame(height: 12)
        TextField("Handle", text: Binding(
            get: { handle },
            set: { value in
                handle = String(value.lowercased().filter {
                    $0.isLetter || $0.isNumber || $0 == "_"
                }.prefix(32))
            }
        ))
        .textInputAutocapitalization(.never)
        .autocorrectionDisabled()
        .focused($focus, equals: .handle)
        .submitLabel(.done)
        .onSubmit { model.saveProfile(handle: handle, displayName: displayName) }
        .fieldStyle()
        Text("Lowercase letters, numbers, and underscores")
            .font(.caption)
            .foregroundStyle(Color.myMuted)
            .padding(.top, 6)
        Spacer().frame(height: 18)
        PrimaryAction(title: "Continue", busy: model.state.busy) {
            model.saveProfile(handle: handle, displayName: displayName)
        }
    }
}

private struct MainShellView: View {
    @EnvironmentObject private var model: MessengerViewModel
    @State private var selection = 0

    var body: some View {
        TabView(selection: $selection) {
            NavigationStack { MessagesView() }
                .tabItem { Label("Messages", systemImage: "bubble.left") }
                .tag(0)
            NavigationStack { PeopleView() }
                .tabItem { Label("People", systemImage: "person.2") }
                .tag(1)
            NavigationStack { ProfileView() }
                .tabItem { Label("You", systemImage: "person") }
                .tag(2)
        }
        .toolbarBackground(Color.mySidebar, for: .tabBar)
        .toolbarBackground(.visible, for: .tabBar)
        .background(Color.myCanvas)
    }
}

private struct MessagesView: View {
    @EnvironmentObject private var model: MessengerViewModel

    var body: some View {
        Group {
            if model.state.conversations.isEmpty {
                EmptyState(
                    symbol: "bubble.left",
                    title: "No conversations yet",
                    detail: "Add someone in People, then open their conversation."
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(model.state.conversations, id: \.userId) { conversation in
                            Button {
                                model.openConversation(
                                    userId: conversation.userId,
                                    title: conversation.displayName
                                )
                            } label: {
                                ConversationRow(conversation: conversation)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(16)
                }
            }
        }
        .navigationTitle("Messages")
        .scrollContentBackground(.hidden)
        .background(Color.myCanvas)
    }
}

private struct ConversationRow: View {
    let conversation: ConversationInfo

    var body: some View {
        HStack(spacing: 14) {
            InitialAvatar(name: conversation.displayName)
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(conversation.displayName).font(.headline)
                    Spacer()
                    Text(date(conversation.timestamp), style: .time)
                        .font(.caption.monospaced())
                        .foregroundStyle(Color.myMuted)
                }
                Text((conversation.fromMe ? "You: " : "") + conversation.preview)
                    .font(.subheadline)
                    .foregroundStyle(Color.myMuted)
                    .lineLimit(1)
            }
        }
        .padding(16)
        .background(Color.mySurface, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

private struct PeopleView: View {
    @EnvironmentObject private var model: MessengerViewModel
    @State private var adding = false

    var body: some View {
        Group {
            if model.state.contacts.isEmpty {
                EmptyState(
                    symbol: "person.2",
                    title: "Your people appear here",
                    detail: "Add a connection card shared by someone you know."
                )
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(model.state.contacts, id: \.userId) { contact in
                            ContactRow(contact: contact)
                        }
                    }
                    .padding(16)
                }
            }
        }
        .navigationTitle("People")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { adding = true } label: { Image(systemName: "plus") }
            }
        }
        .sheet(isPresented: $adding) { AddPersonSheet(isPresented: $adding) }
        .sheet(item: Binding(
            get: { model.state.security.map(SecurityItem.init) },
            set: { if $0 == nil { model.dismissSecurity() } }
        )) { item in
            SecuritySheet(security: item.value)
                .presentationDetents([.medium, .large])
        }
        .background(Color.myCanvas)
    }
}

private struct ContactRow: View {
    @EnvironmentObject private var model: MessengerViewModel
    let contact: ContactInfo

    var body: some View {
        HStack(spacing: 14) {
            InitialAvatar(name: contact.nickname)
            Button {
                model.openConversation(userId: contact.userId, title: contact.nickname)
            } label: {
                VStack(alignment: .leading, spacing: 3) {
                    Text(contact.nickname).font(.headline).foregroundStyle(Color.myText)
                    Text("@\(contact.handle)").font(.subheadline).foregroundStyle(Color.myMuted)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .buttonStyle(.plain)
            Button { model.showSecurity(userId: contact.userId) } label: {
                Image(systemName: contact.verified ? "checkmark.shield.fill" : "shield")
                    .foregroundStyle(contact.verified ? Color.myMoss : Color.myMuted)
                    .frame(width: 36, height: 36)
            }
            .buttonStyle(.plain)
        }
        .padding(16)
        .background(Color.mySurface, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

private struct ProfileView: View {
    @EnvironmentObject private var model: MessengerViewModel
    @State private var editing = false

    var body: some View {
        ScrollView {
            if let profile = model.state.profile {
                VStack(alignment: .leading, spacing: 0) {
                    HStack(spacing: 16) {
                        NodeMark(size: 52)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(profile.displayName).font(.title2.weight(.semibold))
                            Text("@\(profile.handle)").foregroundStyle(Color.myMuted)
                        }
                        Spacer()
                        Button("Edit") { editing = true }
                    }
                    Spacer().frame(height: 28)
                    Text("YOUR CONNECTION CARD")
                        .font(.caption.monospaced().weight(.semibold))
                        .tracking(1)
                        .foregroundStyle(Color.myMoss)
                    Spacer().frame(height: 10)
                    VStack(alignment: .leading, spacing: 14) {
                        Text("Share this card so someone can add the exact identity—not just your handle.")
                            .font(.subheadline)
                            .foregroundStyle(Color.myMuted)
                        Text(profile.connectionCard)
                            .font(.caption.monospaced())
                            .lineLimit(5)
                            .textSelection(.enabled)
                        HStack(spacing: 10) {
                            Button {
                                UIPasteboard.general.string = profile.connectionCard
                            } label: {
                                Label("Copy", systemImage: "doc.on.doc")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.bordered)
                            ShareLink(item: profile.connectionCard) {
                                Label("Share", systemImage: "square.and.arrow.up")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.borderedProminent)
                        }
                    }
                    .padding(18)
                    .background(Color.mySurface, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                    Spacer().frame(height: 24)
                    StatusCard(
                        title: model.state.pendingCount == 0
                            ? "Nothing pending"
                            : "\(model.state.pendingCount) pending",
                        bodyText: model.state.pendingCount == 0
                            ? "Messages delivered directly have left this device."
                            : "These messages remain encrypted here until a direct connection exists.",
                        accent: model.state.pendingCount == 0 ? .myMoss : .mySpore
                    )
                    if model.state.pendingCount > 0 {
                        Button { model.retryPending() } label: {
                            Label("Try now", systemImage: "arrow.clockwise")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .disabled(model.state.busy)
                        .padding(.top, 12)
                    }
                    Spacer().frame(height: 28)
                    Text("USER ID")
                        .font(.caption.monospaced().weight(.semibold))
                        .foregroundStyle(Color.myMuted)
                    Text(profile.userId)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
                .padding(20)
            }
        }
        .navigationTitle("You")
        .sheet(isPresented: $editing) {
            if let profile = model.state.profile {
                ProfileEditSheet(profile: profile, isPresented: $editing)
            }
        }
        .background(Color.myCanvas)
    }
}

private struct ProfileEditSheet: View {
    @EnvironmentObject private var model: MessengerViewModel
    let profile: ProfileInfo
    @Binding var isPresented: Bool
    @State private var displayName: String
    @State private var handle: String

    init(profile: ProfileInfo, isPresented: Binding<Bool>) {
        self.profile = profile
        self._isPresented = isPresented
        self._displayName = State(initialValue: profile.displayName)
        self._handle = State(initialValue: profile.handle)
    }

    var body: some View {
        NavigationStack {
            Form {
                TextField("Display name", text: $displayName)
                TextField("Handle", text: $handle)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .onChange(of: handle) { _, value in
                        handle = String(value.lowercased().filter {
                            $0.isLetter || $0.isNumber || $0 == "_"
                        }.prefix(64))
                    }
            }
            .navigationTitle("Edit profile")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { isPresented = false }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        model.saveProfile(handle: handle, displayName: displayName)
                        isPresented = false
                    }
                    .disabled(
                        model.state.busy
                            || handle.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                            || displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    )
                }
            }
        }
    }
}

private struct ConversationView: View {
    @EnvironmentObject private var model: MessengerViewModel
    @State private var draft = ""
    @FocusState private var composing: Bool

    var body: some View {
        NavigationStack {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 8) {
                        if model.state.messages.isEmpty {
                            Text("Messages stay on your devices.")
                                .foregroundStyle(Color.myMuted)
                                .padding(.top, 80)
                        }
                        ForEach(Array(model.state.messages.enumerated()), id: \.offset) { index, message in
                            MessageBubble(message: message).id(index)
                        }
                    }
                    .padding(14)
                }
                .onChange(of: model.state.messages.count) { _, count in
                    if count > 0 { withAnimation { proxy.scrollTo(count - 1, anchor: .bottom) } }
                }
            }
            .safeAreaInset(edge: .bottom) {
                HStack(alignment: .bottom, spacing: 8) {
                    TextField("Message", text: $draft, axis: .vertical)
                        .lineLimit(1...5)
                        .focused($composing)
                        .submitLabel(.send)
                        .onSubmit(send)
                        .fieldStyle()
                    Button(action: send) {
                        Image(systemName: "arrow.up")
                            .font(.headline.weight(.bold))
                            .foregroundStyle(Color.myCanvas)
                            .frame(width: 48, height: 48)
                            .background(Color.myMoss, in: Circle())
                    }
                    .buttonStyle(.plain)
                    .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.state.busy)
                }
                .padding(10)
                .background(.ultraThinMaterial)
            }
            .navigationTitle(model.state.selectedTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button { model.closeConversation() } label: {
                        Image(systemName: "chevron.left")
                    }
                }
            }
            .background(Color.myCanvas)
        }
    }

    private func send() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        draft = ""
        model.sendMessage(text)
    }
}

private struct MessageBubble: View {
    let message: MessageInfo

    var body: some View {
        HStack {
            if message.fromMe { Spacer(minLength: 52) }
            VStack(alignment: .leading, spacing: 5) {
                Text(message.text)
                Text(date(message.timestamp), style: .time)
                    .font(.caption2.monospaced())
                    .foregroundStyle(Color.myMuted)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(
                message.fromMe ? Color.myMoss.opacity(0.22) : Color.myRaised,
                in: UnevenRoundedRectangle(
                    topLeadingRadius: 18,
                    bottomLeadingRadius: message.fromMe ? 18 : 4,
                    bottomTrailingRadius: message.fromMe ? 4 : 18,
                    topTrailingRadius: 18
                )
            )
            if !message.fromMe { Spacer(minLength: 52) }
        }
        .frame(maxWidth: .infinity)
    }
}

private struct AddPersonSheet: View {
    @EnvironmentObject private var model: MessengerViewModel
    @Binding var isPresented: Bool
    @State private var nickname = ""
    @State private var card = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name on this device (optional)", text: $nickname)
                    TextField("Connection card", text: $card, axis: .vertical)
                        .lineLimit(5...10)
                        .font(.caption.monospaced())
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                } footer: {
                    Text("Paste the exact card they shared with you.")
                }
            }
            .scrollContentBackground(.hidden)
            .background(Color.myCanvas)
            .navigationTitle("Add someone")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { isPresented = false }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        model.addContact(card: card, nickname: nickname)
                        isPresented = false
                    }
                    .disabled(card.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.state.busy)
                }
            }
        }
        .presentationDetents([.medium, .large])
    }
}

private struct SecurityItem: Identifiable {
    let value: ContactSecurityInfo
    var id: String { value.userId }
}

private struct SecuritySheet: View {
    @EnvironmentObject private var model: MessengerViewModel
    @Environment(\.dismiss) private var dismiss
    let security: ContactSecurityInfo

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 18) {
                Image(systemName: security.identityChanged ? "exclamationmark.shield.fill" : "checkmark.shield")
                    .font(.system(size: 34))
                    .foregroundStyle(security.identityChanged ? Color.myDanger : Color.myMoss)
                Text(security.identityChanged ? "Identity changed" : security.trust)
                    .font(.title2.weight(.semibold))
                Text(security.identityChanged
                     ? "Do not accept this change until you verify the number with this person another way."
                     : "Compare this number with the person using another trusted channel.")
                    .foregroundStyle(Color.myMuted)
                Text("SAFETY NUMBER")
                    .font(.caption.monospaced().weight(.semibold))
                    .foregroundStyle(Color.myMoss)
                Text(security.safetyNumber)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                Button(security.blocked ? "Unblock this person" : "Block this person") {
                    model.setContactBlocked(userId: security.userId, blocked: !security.blocked)
                }
                .buttonStyle(.bordered)
                .tint(security.blocked ? .myMoss : .myDanger)
                .disabled(model.state.busy)
                Spacer()
                Button {
                    if security.identityChanged {
                        model.acceptIdentityChange(userId: security.userId)
                    } else {
                        model.verifyContact(userId: security.userId)
                    }
                    dismiss()
                } label: {
                    Text(security.identityChanged ? "Accept new identity" : "Numbers match")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(security.identityChanged ? .myDanger : .myMoss)
                .disabled(model.state.busy)
            }
            .padding(24)
            .navigationTitle("Security")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { dismiss() }
                }
            }
            .background(Color.myCanvas)
        }
    }
}

private struct EmptyState: View {
    let symbol: String
    let title: String
    let detail: String

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: symbol).font(.system(size: 34)).foregroundStyle(Color.myMoss)
            Text(title).font(.title3.weight(.semibold))
            Text(detail).font(.subheadline).foregroundStyle(Color.myMuted).multilineTextAlignment(.center)
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.myCanvas)
    }
}

private struct Banner: View {
    let message: String
    let error: Bool

    var body: some View {
        Text(message)
            .font(.subheadline.weight(.medium))
            .foregroundStyle(Color.myText)
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(error ? Color.myDanger.opacity(0.95) : Color.myRaised.opacity(0.98))
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            .shadow(color: .black.opacity(0.25), radius: 16, y: 6)
    }
}

private struct PrimaryAction: View {
    let title: String
    let busy: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Group {
                if busy { ProgressView().tint(.myCanvas) } else { Text(title) }
            }
            .font(.headline)
            .frame(maxWidth: .infinity)
            .frame(height: 50)
        }
        .buttonStyle(.borderedProminent)
        .disabled(busy)
    }
}

private extension View {
    func fieldStyle() -> some View {
        self
            .padding(.horizontal, 14)
            .frame(minHeight: 52)
            .background(Color.mySurface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(Color.myBorder, lineWidth: 1)
            }
    }
}

private func date(_ seconds: UInt64) -> Date {
    Date(timeIntervalSince1970: TimeInterval(seconds))
}
