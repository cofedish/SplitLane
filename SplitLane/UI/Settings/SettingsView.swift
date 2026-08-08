import SplitLaneCore
import SwiftUI

struct SettingsView: View {

    @Environment(AppState.self) private var appState

    var body: some View {
        Form {
            Section("Routing") {
                Toggle("Enable routing", isOn: Binding(
                    get: { appState.configuration.isRoutingEnabled },
                    set: { enabled in Task { await appState.setRoutingEnabled(enabled) } }
                ))
                Text("When off, every application uses the direct lane, including ones assigned to "
                     + "the proxy lane. The extension keeps running.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Diagnostics") {
                Toggle("Log direct routing decisions", isOn: Binding(
                    get: { appState.configuration.logsDirectFlows },
                    set: { enabled in Task { await appState.setDirectFlowLogging(enabled) } }
                ))
                Text("The extension is consulted for every connection on this Mac, so this is very "
                     + "high volume. Useful when diagnosing why an app is not matching a rule.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("System Extension") {
                LabeledContent("Status") {
                    Text(appState.extensionManager.state.summary)
                }
                HStack {
                    Button("Install / Update") { appState.extensionManager.activate() }
                    Button("Remove") { appState.extensionManager.deactivate() }
                }
                if case .awaitingApproval = appState.extensionManager.state {
                    Text("Open System Settings → General → Login Items & Extensions → "
                         + "Network Extensions and enable SplitLane.")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }

            Section("About") {
                LabeledContent("Extension identifier") {
                    Text(ExtensionManager.extensionIdentifier)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
                LabeledContent("Configuration schema") {
                    Text("\(ConfigurationVersion.currentSchema)")
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Settings")
    }
}
