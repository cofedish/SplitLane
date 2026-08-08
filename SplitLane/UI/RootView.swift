import SplitLaneCore
import SwiftUI

/// Sidebar sections.
///
/// Named `SidebarSection` rather than `Section` because the latter shadows `SwiftUI.Section`
/// throughout the module, which turns every `Section("Title") { ... }` in a Form into an
/// "extra trailing closure" error far away from the cause.
enum SidebarSection: String, CaseIterable, Identifiable {
    case overview = "Overview"
    case applications = "Applications"
    case proxy = "Proxy"
    case activity = "Activity"
    case settings = "Settings"

    var id: String { rawValue }

    var systemImage: String {
        switch self {
        case .overview: "square.split.2x1"
        case .applications: "app.badge.checkmark"
        case .proxy: "network"
        case .activity: "waveform.path.ecg"
        case .settings: "gearshape"
        }
    }
}

struct RootView: View {

    @Environment(AppState.self) private var appState
    @State private var selection: SidebarSection = .overview

    var body: some View {
        NavigationSplitView {
            List(SidebarSection.allCases, selection: $selection) { section in
                Label(section.rawValue, systemImage: section.systemImage)
                    .tag(section)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 240)
            .safeAreaInset(edge: .bottom) { LaneStatusFooter() }
        } detail: {
            switch selection {
            case .overview: OverviewView()
            case .applications: ApplicationsView()
            case .proxy: ProxyView()
            case .activity: ActivityView()
            case .settings: SettingsView()
            }
        }
    }
}

/// Persistent indicator of whether the lane is actually armed.
///
/// Deliberately always visible. The most dangerous state in this product is "the user believes
/// their apps are proxied and they are not", so provider state is not something to go looking for
/// on a status screen.
private struct LaneStatusFooter: View {

    @Environment(AppState.self) private var appState

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(indicatorColor)
                .frame(width: 8, height: 8)
            Text(appState.configurationService.providerState.summary)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
    }

    private var indicatorColor: Color {
        if appState.hasArmedRulesWithoutProvider { return .red }
        return appState.isProviderRunning ? .green : .secondary
    }
}
