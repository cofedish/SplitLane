import Foundation
// NetworkExtension has not been audited for Sendable, so `loadAllFromPreferences()` returning
// `[NETransparentProxyManager]` across an async boundary is a Swift 6 error. `@preconcurrency`
// is the sanctioned way to say "this framework predates the annotations" rather than a way to
// silence a real data race: every manager here is created, read and mutated on the main actor,
// which this whole type is isolated to.
@preconcurrency import NetworkExtension
import SplitLaneCore

/// Owns the `NETransparentProxyManager` configuration and talks to the running provider.
///
/// Configuration reaches the provider two ways, both verified present in the SDK:
///
/// - `providerConfiguration` — authoritative and persistent, delivered by the system when the
///   provider starts, so there is never a window where it runs without configuration.
/// - `sendProviderMessage` — live reload, so toggling an app does not require reinstalling
///   anything or dropping existing connections.
///
/// No App Group is involved. For a macOS *system* extension the container paths differ between the
/// root-run provider and the user-run app, and the failure mode is silent: the app writes, the
/// extension reads nothing, and neither reports an error. See ADR 0005.
@MainActor
@Observable
final class ConfigurationService {

    enum ProviderState: Equatable {
        case notConfigured
        case disabled
        case disconnected
        case connecting
        case connected
        case failed(String)

        var summary: String {
            switch self {
            case .notConfigured: "Not configured"
            case .disabled: "Disabled"
            case .disconnected: "Stopped"
            case .connecting: "Starting…"
            case .connected: "Running"
            case .failed(let reason): "Failed: \(reason)"
            }
        }

        var isRunning: Bool { self == .connected }
    }

    private(set) var providerState: ProviderState = .notConfigured
    private(set) var lastStatus: ProviderStatus?
    private(set) var lastError: String?

    private var manager: NETransparentProxyManager?
    private var stateObserver: NSObjectProtocol?

    /// **UNVERIFIED** (docs/NETWORKING.md §1.5): that `NETransparentProxyManager.connection` casts
    /// to `NETunnelProviderSession`. It should — the connection backing a provider-based
    /// configuration is one — but it is asserted nowhere in the headers. If the cast fails, live
    /// reload degrades to a session restart, which is correct but drops in-flight flows. Settled
    /// at M3.
    private var session: NETunnelProviderSession? {
        manager?.connection as? NETunnelProviderSession
    }

    // MARK: - Loading

    /// Loads the existing configuration, or reports that none exists yet.
    func load() async {
        do {
            let managers = try await NETransparentProxyManager.loadAllFromPreferences()
            guard let existing = managers.first else {
                providerState = .notConfigured
                return
            }
            manager = existing
            observeConnectionState()
            updateState()
            SplitLaneLog.configuration.notice("Loaded existing proxy configuration")
        } catch {
            providerState = .failed(error.localizedDescription)
            SplitLaneLog.configuration.error(
                "Failed to load preferences: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    // MARK: - Saving

    /// Validates, persists and (when the provider is running) hot-reloads a configuration.
    func save(_ configuration: RuntimeConfiguration) async throws {
        let encoded = try ConfigurationCodec.encode(configuration)

        let manager = self.manager ?? NETransparentProxyManager()
        self.manager = manager

        let protocolConfiguration = (manager.protocolConfiguration as? NETunnelProviderProtocol)
            ?? NETunnelProviderProtocol()
        protocolConfiguration.providerBundleIdentifier = ExtensionManager.extensionIdentifier
        protocolConfiguration.providerConfiguration = encoded
        // Required by NEVPNProtocol even though a transparent proxy establishes no tunnel.
        protocolConfiguration.serverAddress = configuration.proxy.endpoint.displayString

        // The password travels as a Keychain persistent reference, never inside
        // providerConfiguration (F-5).
        if let credential = configuration.proxy.credential,
           let encodedReference = credential.persistentReference,
           let reference = Data(base64Encoded: encodedReference) {
            protocolConfiguration.passwordReference = reference
        } else {
            protocolConfiguration.passwordReference = nil
        }

        manager.protocolConfiguration = protocolConfiguration
        manager.localizedDescription = "SplitLane"
        manager.isEnabled = true

        try await manager.saveToPreferences()
        // Re-load after saving: the system rewrites parts of the configuration, and a stale
        // in-memory manager fails the next save with a "configuration modified" error.
        try await manager.loadFromPreferences()

        observeConnectionState()
        updateState()

        SplitLaneLog.configuration.notice(
            "Saved configuration generation \(configuration.version.generation, privacy: .public)"
        )

        if providerState.isRunning {
            await reload(generation: configuration.version.generation)
        }
    }

    // MARK: - Lifecycle

    func start() async throws {
        guard let session else {
            throw NSError(domain: "dev.cofe.splitlane", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "No proxy configuration to start"
            ])
        }
        try session.startTunnel(options: nil)
        SplitLaneLog.configuration.notice("Requested proxy start")
    }

    func stop() {
        session?.stopTunnel()
        SplitLaneLog.configuration.notice("Requested proxy stop")
    }

    // MARK: - Provider messaging

    /// Asks the provider to re-read its configuration.
    func reload(generation: UInt64) async {
        _ = await send(.reloadConfiguration(generation: generation))
    }

    func requestStatus() async {
        if case .status(let status)? = await send(.requestStatus) {
            lastStatus = status
            lastError = status.lastError
        }
    }

    /// Tests the upstream from inside the provider.
    ///
    /// The app's own reachability check would prove nothing about the provider's: different
    /// process, different user, different sandbox.
    func testProxyConnection() async -> ProxyTestResult {
        if case .proxyTestResult(let result)? = await send(.testProxyConnection) {
            return result
        }
        return ProxyTestResult(
            succeeded: false,
            errorDescription: "The provider is not running, so it could not test the proxy"
        )
    }

    private func send(_ message: ProviderMessage) async -> ProviderResponse? {
        guard let session, providerState.isRunning else { return nil }

        do {
            let data = try ProviderMessageCodec.encode(message)
            return await withCheckedContinuation { continuation in
                do {
                    let resumed = ResumeOnce()
                    try session.sendProviderMessage(data) { response in
                        guard resumed.claim() else { return }
                        guard let response else {
                            continuation.resume(returning: nil)
                            return
                        }
                        continuation.resume(
                            returning: try? ProviderMessageCodec.decodeResponse(response)
                        )
                    }
                } catch {
                    SplitLaneLog.ipc.error(
                        "sendProviderMessage failed: \(error.localizedDescription, privacy: .public)"
                    )
                    continuation.resume(returning: nil)
                }
            }
        } catch {
            SplitLaneLog.ipc.error("Failed to encode provider message")
            return nil
        }
    }

    // MARK: - State

    private func observeConnectionState() {
        if let stateObserver {
            NotificationCenter.default.removeObserver(stateObserver)
        }
        guard let connection = manager?.connection else { return }

        stateObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in self?.updateState() }
        }
    }

    private func updateState() {
        guard let manager else {
            providerState = .notConfigured
            return
        }
        guard manager.isEnabled else {
            // An existing-but-disabled configuration is indistinguishable from a working one from
            // the app's side unless this is checked explicitly, and it is a common way for
            // "the proxy does nothing" to happen.
            providerState = .disabled
            return
        }

        providerState = switch manager.connection.status {
        case .invalid: .notConfigured
        case .disconnected: .disconnected
        case .connecting, .reasserting: .connecting
        case .connected: .connected
        case .disconnecting: .connecting
        @unknown default: .disconnected
        }
    }
}

/// Guards a continuation against a completion handler that fires more than once.
private final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false

    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}
