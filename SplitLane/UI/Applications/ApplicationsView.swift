import SplitLaneCore
import SwiftUI

struct ApplicationsView: View {

    @Environment(AppState.self) private var appState
    @State private var selection: Set<AppRule.ID> = []
    @State private var inspectionFailures: [String] = []

    var body: some View {
        VStack(spacing: 0) {
            if !inspectionFailures.isEmpty {
                Banner(
                    style: .warning,
                    title: "Some applications could not be added",
                    message: inspectionFailures.joined(separator: "\n")
                )
                .padding([.horizontal, .top], 16)
            }

            if appState.rules.isEmpty {
                ContentUnavailableView {
                    Label("No applications", systemImage: "app.dashed")
                } description: {
                    Text("Add an application to route its traffic through the proxy lane. "
                         + "Everything you do not add stays on the direct lane, untouched.")
                } actions: {
                    Button("Add Application…", action: addApplications)
                }
            } else {
                List(selection: $selection) {
                    ForEach(appState.rules) { rule in
                        ApplicationRow(rule: rule)
                            .tag(rule.id)
                    }
                }
                .listStyle(.inset)
            }
        }
        .navigationTitle("Applications")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Add Application…", systemImage: "plus", action: addApplications)
            }
            ToolbarItem(placement: .destructiveAction) {
                Button("Remove", systemImage: "minus") {
                    let doomed = selection
                    selection = []
                    Task { await appState.removeRules(doomed) }
                }
                .disabled(selection.isEmpty)
            }
        }
    }

    private func addApplications() {
        let urls = ApplicationInspector.presentPicker()
        guard !urls.isEmpty else { return }
        inspectionFailures = appState.addApplications(from: urls)
    }
}

private struct ApplicationRow: View {

    @Environment(AppState.self) private var appState
    let rule: AppRule

    var body: some View {
        HStack(spacing: 12) {
            if let path = rule.identity.bundlePath {
                Image(nsImage: ApplicationInspector.icon(forBundlePath: path))
                    .resizable()
                    .frame(width: 30, height: 30)
            } else {
                Image(systemName: "app.dashed").font(.title2).frame(width: 30, height: 30)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(rule.identity.displayName).font(.body)

                HStack(spacing: 6) {
                    Text(laneLabel)
                        .font(.caption)
                        .foregroundStyle(rule.action == .proxy ? Color.accentColor : .secondary)

                    // Flagged because a rule on an ad-hoc-signed binary is trivially impersonated
                    // by any other local binary (F-2).
                    if rule.identity.isAdHocSigned {
                        Label("Unsigned", systemImage: "exclamationmark.shield")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                    }

                    // The value SplitLane routes on differs from the one shown in Finder, which is
                    // worth knowing before wondering why a rule does not match.
                    if rule.identity.hasIdentifierMismatch {
                        Label("ID mismatch", systemImage: "questionmark.circle")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                    }
                }

                Text(rule.identity.signingIdentifier)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)
            }

            Spacer()

            Toggle("", isOn: Binding(
                get: { rule.action == .proxy && rule.isEnabled },
                set: { isOn in
                    Task { await appState.setAction(isOn ? .proxy : .direct, for: rule.id) }
                }
            ))
            .labelsHidden()
            .toggleStyle(.switch)
        }
        .padding(.vertical, 4)
        .contextMenu {
            Picker("Match", selection: Binding(
                get: { rule.matchMode },
                set: { mode in Task { await appState.setMatchMode(mode, for: rule.id) } }
            )) {
                Text("App and its helpers").tag(AppRule.MatchMode.bundleFamily)
                Text("Exact identifier only").tag(AppRule.MatchMode.exact)
            }
        }
    }

    private var laneLabel: String {
        guard rule.isEnabled else { return "Direct Lane" }
        return switch rule.action {
        case .proxy: "Proxy Lane"
        case .direct: "Direct Lane"
        case .block: "Blocked"
        }
    }
}
