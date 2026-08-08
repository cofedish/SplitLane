import Foundation
import SplitLaneCore
import SwiftUI

/// The single source of truth the UI binds to.
///
/// Views read this and call its methods. They do not touch NetworkExtension, the Keychain, or the
/// SOCKS5 layer — all of that lives behind the services this type owns. That boundary is what
/// keeps the networking testable and the views trivial.
@MainActor
@Observable
final class AppState {

    // MARK: - Services

    let extensionManager = ExtensionManager()
    let configurationService = ConfigurationService()

    // MARK: - Configuration

    private(set) var configuration: RuntimeConfiguration = .empty

    /// Set when the last save or validation failed.
    private(set) var configurationError: String?

    // MARK: - Derived state

    var rules: [AppRule] { configuration.rules }

    var proxy: SplitLaneCore.ProxyConfiguration { configuration.proxy }

    var isProviderRunning: Bool { configurationService.providerState.isRunning }

    /// True when a rule says traffic should be proxied but nothing is actually enforcing it.
    ///
    /// This is the F-4 case: with no provider running there is no rule for the kernel to consult,
    /// so selected apps are silently DIRECT. It is surfaced as an error state rather than left to
    /// look like a working "ON" toggle.
    var hasArmedRulesWithoutProvider: Bool {
        !configuration.proxiedRules.isEmpty && !isProviderRunning
    }

    // MARK: - Lifecycle

    func bootstrap() async {
        await configurationService.load()
        if let loaded = loadPersistedConfiguration() {
            configuration = loaded
        }
        await refreshStatus()
    }

    func refreshStatus() async {
        await configurationService.requestStatus()
    }

    // MARK: - Rules

    /// Adds applications chosen through the standard picker.
    ///
    /// Returns the identities that could not be inspected, so the UI can say which and why rather
    /// than silently adding fewer apps than the user selected.
    @discardableResult
    func addApplications(from urls: [URL]) -> [String] {
        var failures: [String] = []
        var updated = configuration

        for url in urls {
            do {
                let identity = try ApplicationInspector.inspect(bundleURL: url)
                guard !updated.rules.contains(where: { $0.id == identity.id }) else { continue }
                updated.rules.append(AppRule(identity: identity))
            } catch {
                failures.append(error.localizedDescription)
            }
        }

        if updated.rules.count != configuration.rules.count {
            Task { await apply(updated) }
        }
        return failures
    }

    func setAction(_ action: RouteAction, for ruleID: AppRule.ID) async {
        var updated = configuration
        guard let index = updated.rules.firstIndex(where: { $0.id == ruleID }) else { return }
        updated.rules[index].action = action
        updated.rules[index].isEnabled = true
        await apply(updated)
    }

    func setMatchMode(_ mode: AppRule.MatchMode, for ruleID: AppRule.ID) async {
        var updated = configuration
        guard let index = updated.rules.firstIndex(where: { $0.id == ruleID }) else { return }
        updated.rules[index].matchMode = mode
        await apply(updated)
    }

    func removeRules(_ ruleIDs: Set<AppRule.ID>) async {
        var updated = configuration
        updated.rules.removeAll { ruleIDs.contains($0.id) }
        await apply(updated)
    }

    func setRoutingEnabled(_ enabled: Bool) async {
        var updated = configuration
        updated.isRoutingEnabled = enabled
        await apply(updated)
    }

    func setDirectFlowLogging(_ enabled: Bool) async {
        var updated = configuration
        updated.logsDirectFlows = enabled
        await apply(updated)
    }

    // MARK: - Proxy

    /// Updates the upstream, storing any password in the Keychain first.
    func updateProxy(
        host: String,
        port: UInt16,
        username: String?,
        password: String?
    ) async {
        var updated = configuration
        updated.proxy.endpoint = ProxyEndpoint(host: host, port: port)

        if let username, !username.isEmpty {
            do {
                // The password goes to the Keychain here; only the reference is persisted.
                if let password, !password.isEmpty {
                    updated.proxy.credential = try KeychainService.credentialReference(
                        username: username,
                        password: password
                    )
                } else if updated.proxy.credential?.username != username {
                    updated.proxy.credential = CredentialReference(username: username)
                }
            } catch {
                configurationError = error.localizedDescription
                return
            }
        } else {
            if let existing = configuration.proxy.credential {
                try? KeychainService.deletePassword(account: existing.username)
            }
            updated.proxy.credential = nil
        }

        await apply(updated)
    }

    func testProxyConnection() async -> ProxyTestResult {
        await configurationService.testProxyConnection()
    }

    // MARK: - Applying

    /// Validates, bumps the generation, persists and hot-reloads.
    ///
    /// Every mutation funnels through here, so there is exactly one place where a configuration
    /// can become live and exactly one place that can reject an invalid one.
    private func apply(_ candidate: RuntimeConfiguration) async {
        var next = candidate
        next.version = configuration.version.nextGeneration()

        do {
            try ConfigurationValidator.validate(next)
            try await configurationService.save(next)
            configuration = next
            persist(next)
            configurationError = nil
        } catch {
            configurationError = error.localizedDescription
            SplitLaneLog.configuration.error(
                "Failed to apply configuration: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    // MARK: - Local persistence

    /// A local copy of the configuration, so the UI can render before the provider exists.
    ///
    /// `providerConfiguration` remains authoritative for routing; this is display state only,
    /// which is why UserDefaults is acceptable here — and why it must never hold a credential.
    private static let defaultsKey = "dev.cofe.splitlane.configuration"

    private func persist(_ configuration: RuntimeConfiguration) {
        guard let data = try? JSONEncoder().encode(configuration) else { return }
        UserDefaults.standard.set(data, forKey: Self.defaultsKey)
    }

    private func loadPersistedConfiguration() -> RuntimeConfiguration? {
        guard let data = UserDefaults.standard.data(forKey: Self.defaultsKey) else { return nil }
        return try? JSONDecoder().decode(RuntimeConfiguration.self, from: data)
    }
}
