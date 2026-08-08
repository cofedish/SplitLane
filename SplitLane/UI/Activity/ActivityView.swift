import SplitLaneCore
import SwiftUI

/// Live connection metadata.
///
/// Counters, not a connection list, for now. The provider currently reports aggregate statistics
/// through `requestStatus`; streaming per-connection events needs a push channel that
/// `sendProviderMessage` does not provide, and that is M13 work. Showing empty scaffolding that
/// looks like a live list would be worse than showing what is genuinely known.
struct ActivityView: View {

    @Environment(AppState.self) private var appState
    @State private var isAutoRefreshing = true

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let status = appState.configurationService.lastStatus {
                Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 10) {
                    GridRow {
                        Text("Active proxied flows").foregroundStyle(.secondary)
                        Text("\(status.activeProxiedFlows)").monospacedDigit()
                    }
                    GridRow {
                        Text("Proxied since start").foregroundStyle(.secondary)
                        Text("\(status.proxiedFlowCount)").monospacedDigit()
                    }
                    GridRow {
                        Text("Direct since start").foregroundStyle(.secondary)
                        Text("\(status.directFlowCount)").monospacedDigit()
                    }
                    GridRow {
                        Text("Blocked (UDP)").foregroundStyle(.secondary)
                        Text("\(status.blockedFlowCount)").monospacedDigit()
                    }
                    GridRow {
                        Text("Configuration generation").foregroundStyle(.secondary)
                        Text("\(status.configurationGeneration)").monospacedDigit()
                    }
                }

                if status.blockedFlowCount > 0 {
                    Banner(
                        style: .info,
                        title: "UDP traffic is being refused",
                        message: """
                        \(status.blockedFlowCount) UDP flow(s) from selected apps were refused so they \
                        could not bypass the proxy. Apps normally retry over TCP. If a selected app is \
                        not working, this is the likely cause.
                        """
                    )
                }
            } else {
                ContentUnavailableView(
                    "No activity yet",
                    systemImage: "waveform.path.ecg",
                    description: Text(appState.isProviderRunning
                        ? "Waiting for the first flow."
                        : "Start the proxy lane to see activity.")
                )
            }

            Text("Per-connection history is not recorded yet. Live routing decisions are visible "
                 + "in the log:")
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("log stream --predicate 'subsystem == \"dev.cofe.splitlane\"' --info")
                .font(.caption.monospaced())
                .textSelection(.enabled)
                .padding(8)
                .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 6))

            Spacer()
        }
        .padding(24)
        .frame(maxWidth: .infinity, alignment: .leading)
        .navigationTitle("Activity")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Refresh", systemImage: "arrow.clockwise") {
                    Task { await appState.refreshStatus() }
                }
            }
        }
        .task {
            // Polling only while this screen is visible. The provider is not asked anything when
            // nobody is looking.
            while isAutoRefreshing, !Task.isCancelled {
                await appState.refreshStatus()
                try? await Task.sleep(for: .seconds(2))
            }
        }
        .onDisappear { isAutoRefreshing = false }
    }
}
