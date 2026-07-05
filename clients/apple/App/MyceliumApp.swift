// The SwiftUI app entry point (Apple-only; issues #68/#69).
//
// This file is part of the Xcode app target, NOT the SwiftPM package — it
// imports SwiftUI and will not compile on Linux, which is expected. See
// README.md for how a Mac developer builds this app.

import SwiftUI

@main
struct MyceliumApp: App {
    @StateObject private var vm = MessengerViewModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(vm)
                .task { vm.bootstrap() }
                .onChange(of: scenePhase) { phase in
                    if phase == .active { vm.onForeground() }
                }
        }
    }
}
