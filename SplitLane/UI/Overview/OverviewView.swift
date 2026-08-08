import SplitLaneCore
import SwiftUI

struct OverviewView: View {

    @Environment(AppState.self) private var appState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {

                // The leak warning comes first, before anything reassuring. A user who thinks
                // their traffic is proxied when it is not is worse off than one who knows.
                if appState.hasArmedRulesWithoutProvider {
                    Banner(
                        style: .error,
                        title: "Selected apps are not being proxied",
                        message: """
                        \(appState.configuration.proxiedRules.count) app(s) are set to the proxy lane, \
                        but the SplitLane extension is not running. Their traffic is going out directly.
                        """
                    )
                }

                LaneDiagram(
                    proxiedCount: appState.configuration.proxiedRules.count,
                    isArmed: appState.isProviderRunning,
                    upstream: appState.proxy.endpoint.displayString
                )

                StatusCard(
                    title: "System Extension",
                    value: appState.extensionManager.state.summary,
                    actionTitle: appState.extensionManager.state.isUsable ? nil : "Install",
                    action: installExtension
                )

                StatusCard(
                    title: "Proxy Lane",
                    value: appState.configurationService.providerState.summary,
                    actionTitle: appState.isProviderRunning ? "Stop" : "Start",
                    action: toggleProxy
                )

                if let status = appState.configurationService.lastStatus {
                    CountersView(status: status)
                }

                DisclosureGroup("Known limitations") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("DNS lookups are not proxied. A network observer can still see which "
                             + "hostnames a proxied app contacts.")
                        Text("UDP (including QUIC/HTTP3) from selected apps is refused, not proxied, "
                             + "so it cannot leak. Apps without a TCP fallback will not work.")
                        Text("If the extension stops, selected apps fall back to direct routing.")
                    }
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .padding(.top, 6)
                }
                .padding(.top, 4)
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle("Overview")
        .task { await appState.refreshStatus() }
    }

    // Named methods rather than inline closures inside the tuple: a bare `Task { … }` there
    // infers as `() -> Task<…>` instead of `() -> Void` and the resulting error points at
    // SwiftUI's initialiser rather than at this line.
    private func startProxy() {
        Task { try? await appState.configurationService.start() }
    }

    private func stopProxy() {
        appState.configurationService.stop()
    }

    private func toggleProxy() {
        if appState.isProviderRunning { stopProxy() } else { startProxy() }
    }

    private func installExtension() {
        appState.extensionManager.activate()
    }
}

private struct LaneDiagram: View {
    let proxiedCount: Int
    let isArmed: Bool
    let upstream: String

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Lanes").font(.headline)

            HStack(spacing: 16) {
                LaneTile(
                    title: "Proxy Lane",
                    detail: "\(proxiedCount) app\(proxiedCount == 1 ? "" : "s")",
                    subtitle: upstream,
                    tint: isArmed ? .accentColor : .secondary,
                    isActive: isArmed
                )
                LaneTile(
                    title: "Direct Lane",
                    detail: "Everything else",
                    subtitle: "Untouched",
                    tint: .secondary,
                    isActive: true
                )
            }
        }
    }
}

private struct LaneTile: View {
    let title: String
    let detail: String
    let subtitle: String
    let tint: Color
    let isActive: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.subheadline.weight(.semibold))
            Text(detail).font(.title3)
            Text(subtitle).font(.caption).foregroundStyle(.secondary)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(isActive ? 0.12 : 0.05), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(tint.opacity(0.3)))
    }
}

private struct StatusCard: View {
    let title: String
    let value: String
    /// Nil hides the button. Kept separate from `action` because an optional
    /// `(String, () -> Void)` tuple inside a ViewBuilder ternary is more than the type checker
    /// will infer, and the resulting error points at `ScrollView` rather than at the call.
    let actionTitle: String?
    let action: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.subheadline.weight(.semibold))
                Text(value).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            if let actionTitle {
                Button(actionTitle, action: action)
            }
        }
        .padding(14)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct CountersView: View {
    let status: ProviderStatus

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Since start").font(.headline)
            HStack(spacing: 24) {
                Counter(label: "Proxied", value: status.proxiedFlowCount)
                Counter(label: "Direct", value: status.directFlowCount)
                Counter(label: "Blocked", value: status.blockedFlowCount)
                Counter(label: "Active", value: UInt64(status.activeProxiedFlows))
            }
            if let error = status.lastError {
                Text("Last error: \(error)")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
    }

    private struct Counter: View {
        let label: String
        let value: UInt64

        var body: some View {
            VStack(alignment: .leading, spacing: 2) {
                Text("\(value)").font(.title3.monospacedDigit())
                Text(label).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

/// Inline message banner.
struct Banner: View {
    enum Style {
        case error, warning, info

        var color: Color {
            switch self {
            case .error: .red
            case .warning: .orange
            case .info: .accentColor
            }
        }

        var symbol: String {
            switch self {
            case .error: "exclamationmark.triangle.fill"
            case .warning: "exclamationmark.circle.fill"
            case .info: "info.circle.fill"
            }
        }
    }

    let style: Style
    let title: String
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: style.symbol).foregroundStyle(style.color)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.subheadline.weight(.semibold))
                Text(message).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(12)
        .background(style.color.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(style.color.opacity(0.35)))
    }
}
