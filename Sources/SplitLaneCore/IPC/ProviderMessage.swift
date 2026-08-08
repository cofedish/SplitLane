import Foundation

/// A request from the host app to the provider.
///
/// Carried by `NETunnelProviderSession.sendProviderMessage`, which moves opaque `Data`, so these
/// are `Codable` and versioned. There is no polling anywhere: the app sends when something
/// changes, and the provider answers.
public enum ProviderMessage: Codable, Sendable, Hashable {

    /// Re-read `providerConfiguration` and swap the runtime snapshot atomically.
    ///
    /// The generation is included so the provider can ignore a message that arrives after a newer
    /// one has already been applied — provider messages are not ordered with respect to
    /// preference writes.
    case reloadConfiguration(generation: UInt64)

    /// Report provider state, active flow counts and the last error.
    case requestStatus

    /// Verify the upstream proxy is reachable and speaks SOCKS5.
    ///
    /// Run inside the provider rather than the app because the app's own connection to the proxy
    /// proves nothing about the provider's: they are different processes, running as different
    /// users, with different sandboxes.
    case testProxyConnection

    /// Reset counters shown in the UI.
    case resetStatistics

    /// Turn DIRECT-decision logging on or off at runtime, without a configuration round-trip.
    case setDirectFlowLogging(enabled: Bool)
}

/// The provider's reply.
public enum ProviderResponse: Codable, Sendable, Hashable {
    case acknowledged
    case status(ProviderStatus)
    case proxyTestResult(ProxyTestResult)
    case failure(reason: String)
}

/// A snapshot of what the provider is doing.
public struct ProviderStatus: Codable, Sendable, Hashable {

    /// Generation of the configuration currently in force. If this trails what the app persisted,
    /// a reload was missed.
    public let configurationGeneration: UInt64

    public let isRoutingEnabled: Bool

    /// Number of rules that can currently route traffic.
    public let activeRuleCount: Int

    /// TCP flows currently relayed through the proxy.
    public let activeProxiedFlows: Int

    /// Flows handed back to the kernel since start. Counted rather than enumerated: the provider
    /// is consulted for every matching flow on the system, so enumerating DIRECT decisions is
    /// high-volume and low-value (G-12).
    public let directFlowCount: UInt64

    public let proxiedFlowCount: UInt64

    /// Selected-app UDP flows refused. A non-zero value here explains "the app is broken since I
    /// enabled it" (F-3).
    public let blockedFlowCount: UInt64

    /// Most recent proxy-side failure, already redacted for display.
    public let lastError: String?

    public let startedAt: Date?

    public init(
        configurationGeneration: UInt64,
        isRoutingEnabled: Bool,
        activeRuleCount: Int,
        activeProxiedFlows: Int,
        directFlowCount: UInt64,
        proxiedFlowCount: UInt64,
        blockedFlowCount: UInt64,
        lastError: String? = nil,
        startedAt: Date? = nil
    ) {
        self.configurationGeneration = configurationGeneration
        self.isRoutingEnabled = isRoutingEnabled
        self.activeRuleCount = activeRuleCount
        self.activeProxiedFlows = activeProxiedFlows
        self.directFlowCount = directFlowCount
        self.proxiedFlowCount = proxiedFlowCount
        self.blockedFlowCount = blockedFlowCount
        self.lastError = lastError
        self.startedAt = startedAt
    }
}

/// Outcome of a proxy reachability test.
public struct ProxyTestResult: Codable, Sendable, Hashable {
    public let succeeded: Bool
    /// Round-trip time for connect plus handshake.
    public let latency: TimeInterval?
    /// Failure description, already safe to display — never contains credentials.
    public let errorDescription: String?
    /// Which authentication method the server selected, when the handshake got that far.
    public let negotiatedMethod: String?

    public init(
        succeeded: Bool,
        latency: TimeInterval? = nil,
        errorDescription: String? = nil,
        negotiatedMethod: String? = nil
    ) {
        self.succeeded = succeeded
        self.latency = latency
        self.errorDescription = errorDescription
        self.negotiatedMethod = negotiatedMethod
    }
}

/// Wire coding for provider messages.
public enum ProviderMessageCodec {

    public static func encode(_ message: ProviderMessage) throws -> Data {
        try JSONEncoder().encode(message)
    }

    public static func decodeMessage(_ data: Data) throws -> ProviderMessage {
        try JSONDecoder().decode(ProviderMessage.self, from: data)
    }

    public static func encode(_ response: ProviderResponse) throws -> Data {
        try JSONEncoder().encode(response)
    }

    public static func decodeResponse(_ data: Data) throws -> ProviderResponse {
        try JSONDecoder().decode(ProviderResponse.self, from: data)
    }
}
