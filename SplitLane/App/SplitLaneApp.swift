import SplitLaneCore
import SwiftUI

@main
struct SplitLaneApp: App {

    @State private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(appState)
                .frame(minWidth: 780, minHeight: 520)
                .task {
                    SplitLaneLog.app.notice("SplitLane starting")
                    await appState.bootstrap()
                }
        }
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}
