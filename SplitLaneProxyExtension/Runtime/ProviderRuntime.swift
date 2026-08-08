import Foundation
import SplitLaneCore

/// Holds the provider's mutable state: the current configuration snapshot and the counters.
///
/// The snapshot is replaced wholesale, never mutated. A lock is held only for the duration of a
/// pointer swap or a read, so `handleNewFlow` never waits on anything meaningful — which matters,
/// because the provider is consulted for every matching flow on the system.
///
/// A class with an `NSLock` rather than an actor: `handleNewFlow(_:)` is a synchronous
/// NetworkExtension callback that must return `Bool` immediately, and an actor would force the
/// routing decision to become `async`. Hopping off the NE queue to decide whether to touch a flow
/// at all would add latency to every connection on the machine.
final class ProviderRuntime: @unchecked Sendable {

    private let lock = NSLock()

    private var _engine: RuleEngine
    private var _statistics: Statistics
    private var _startedAt: Date?
    private var _lastError: String?
    private var _activeFlows: Set<UUID> = []

    struct Statistics: Sendable {
        var directFlows: UInt64 = 0
        var proxiedFlows: UInt64 = 0
        var blockedFlows: UInt64 = 0
    }

    init(configuration: RuntimeConfiguration = .empty) {
        self._engine = RuleEngine(configuration: configuration)
        self._statistics = Statistics()
    }

    // MARK: - Configuration

    /// Atomically replaces the routing snapshot.
    ///
    /// Flows already in flight keep the snapshot they started with — they hold their own reference
    /// — so a reload never reroutes a live connection halfway through.
    func apply(_ configuration: RuntimeConfiguration) {
        let engine = RuleEngine(configuration: configuration)
        lock.lock()
        _engine = engine
        lock.unlock()

        SplitLaneLog.configuration.notice(
            """
            Applied configuration generation \(configuration.version.generation, privacy: .public) \
            with \(engine.snapshot.activeRuleCount, privacy: .public) active rules
            """
        )
    }

    /// The current snapshot. Cheap: one lock acquisition and a struct copy.
    var engine: RuleEngine {
        lock.lock()
        defer { lock.unlock() }
        return _engine
    }

    var proxyConfiguration: SplitLaneCore.ProxyConfiguration {
        lock.lock()
        defer { lock.unlock() }
        return _engine.snapshot.proxy
    }

    var configurationGeneration: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return _engine.snapshot.version.generation
    }

    // MARK: - Lifecycle

    func markStarted() {
        lock.lock()
        _startedAt = Date()
        lock.unlock()
    }

    func markStopped() {
        lock.lock()
        _startedAt = nil
        _activeFlows.removeAll()
        lock.unlock()
    }

    // MARK: - Accounting

    func record(_ decision: RouteDecision) {
        lock.lock()
        switch decision.action {
        case .direct: _statistics.directFlows &+= 1
        case .proxy: _statistics.proxiedFlows &+= 1
        case .block: _statistics.blockedFlows &+= 1
        }
        lock.unlock()
    }

    func flowDidStart(_ id: UUID) {
        lock.lock()
        _activeFlows.insert(id)
        lock.unlock()
    }

    func flowDidEnd(_ id: UUID) {
        lock.lock()
        _activeFlows.remove(id)
        lock.unlock()
    }

    /// Records the most recent failure for display.
    ///
    /// Takes an error *category*, not a message, so nothing server-supplied and nothing
    /// credential-adjacent can reach the UI through this path.
    func recordFailure(_ category: ConnectionErrorCategory) {
        lock.lock()
        _lastError = category.localizedDescription
        lock.unlock()
    }

    func resetStatistics() {
        lock.lock()
        _statistics = Statistics()
        _lastError = nil
        lock.unlock()
    }

    var status: ProviderStatus {
        lock.lock()
        defer { lock.unlock() }
        return ProviderStatus(
            configurationGeneration: _engine.snapshot.version.generation,
            isRoutingEnabled: _engine.snapshot.isRoutingEnabled,
            activeRuleCount: _engine.snapshot.activeRuleCount,
            activeProxiedFlows: _activeFlows.count,
            directFlowCount: _statistics.directFlows,
            proxiedFlowCount: _statistics.proxiedFlows,
            blockedFlowCount: _statistics.blockedFlows,
            lastError: _lastError,
            startedAt: _startedAt
        )
    }
}
