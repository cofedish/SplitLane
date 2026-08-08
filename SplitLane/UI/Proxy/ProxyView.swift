import SplitLaneCore
import SwiftUI

struct ProxyView: View {

    @Environment(AppState.self) private var appState

    @State private var host: String = ""
    @State private var port: String = ""
    @State private var username: String = ""
    @State private var password: String = ""
    @State private var isTesting = false
    @State private var testResult: ProxyTestResult?

    var body: some View {
        Form {
            Section("Upstream") {
                LabeledContent("Protocol") { Text(appState.proxy.type.displayName) }
                TextField("Host", text: $host)
                TextField("Port", text: $port)
            }

            Section("Authentication") {
                TextField("Username", text: $username)
                SecureField("Password", text: $password)

                if !username.isEmpty, !isLoopbackHost {
                    // RFC 1929 sends credentials in the clear. Irrelevant on loopback, not
                    // irrelevant anywhere else (F-6).
                    Label(
                        "SOCKS5 sends these unencrypted. Avoid over an untrusted network.",
                        systemImage: "exclamationmark.triangle"
                    )
                    .font(.caption)
                    .foregroundStyle(.orange)
                }
            }

            Section {
                HStack {
                    Button("Save") { Task { await save() } }
                        .disabled(!isValid)

                    Button("Test Connection") { Task { await test() } }
                        .disabled(isTesting || !appState.isProviderRunning)

                    if isTesting { ProgressView().controlSize(.small) }
                }

                if !appState.isProviderRunning {
                    Text("Testing runs inside the extension, so it needs the proxy lane to be "
                         + "running. The app's own connection would not prove anything about the "
                         + "extension's.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if let testResult {
                    TestResultRow(result: testResult)
                }

                if let error = appState.configurationError {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
            }

            Section("Behaviour") {
                LabeledContent("On proxy failure") {
                    // Not a toggle. ADR 0003: silent fallback turns a visible error into an
                    // invisible leak, so it is stated as a property, not offered as an option.
                    Text("Connection fails (never falls back to direct)")
                        .foregroundStyle(.secondary)
                }
                LabeledContent("UDP from selected apps") {
                    Text("Refused so it cannot bypass the proxy")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Proxy")
        .onAppear(perform: loadFields)
    }

    private var isLoopbackHost: Bool { NetworkAddress.isLoopbackHost(host) }

    private var isValid: Bool {
        guard let portValue = UInt16(port), portValue > 0 else { return false }
        return !host.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private func loadFields() {
        host = appState.proxy.endpoint.host
        port = String(appState.proxy.endpoint.port)
        username = appState.proxy.credential?.username ?? ""
        // The stored password is intentionally not prefilled: reading it back into a view just to
        // display dots puts a secret somewhere it does not need to be. Leaving the field empty
        // means "unchanged".
        password = ""
    }

    private func save() async {
        guard let portValue = UInt16(port) else { return }
        await appState.updateProxy(
            host: host.trimmingCharacters(in: .whitespaces),
            port: portValue,
            username: username.isEmpty ? nil : username,
            password: password.isEmpty ? nil : password
        )
        password = ""
    }

    private func test() async {
        isTesting = true
        defer { isTesting = false }
        testResult = await appState.testProxyConnection()
    }
}

private struct TestResultRow: View {
    let result: ProxyTestResult

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: result.succeeded ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(result.succeeded ? .green : .red)

            VStack(alignment: .leading, spacing: 2) {
                if result.succeeded {
                    Text("Connected")
                    if let latency = result.latency {
                        Text("Handshake completed in \(Int(latency * 1000)) ms"
                             + (result.negotiatedMethod.map { " · \($0)" } ?? ""))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Text("Failed")
                    Text(result.errorDescription ?? "Unknown error")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}
