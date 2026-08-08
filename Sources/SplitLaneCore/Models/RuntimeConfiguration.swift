import Foundation

/// Schema and generation stamp carried by every configuration.
///
/// The original specification named `ConfigurationVersion` without saying what it meant, which
/// leaves an app and an extension of different vintages to misread each other's dictionaries
/// silently (G-9). The semantics here are explicit:
///
/// - ``schemaVersion`` is the wire format. A provider that understands version *n* **refuses**
///   a configuration stamped *n+1* rather than guessing at fields it does not know.
/// - ``generation`` is a monotonic counter bumped on every user-visible change, used to detect
///   and discard out-of-order reload messages.
public struct ConfigurationVersion: Codable, Sendable, Hashable, Comparable {

    /// Wire format understood by this build.
    public static let currentSchema = 1

    public let schemaVersion: Int
    public let generation: UInt64

    public init(schemaVersion: Int = ConfigurationVersion.currentSchema, generation: UInt64 = 0) {
        self.schemaVersion = schemaVersion
        self.generation = generation
    }

    /// Whether a provider built against ``currentSchema`` can safely interpret this.
    public var isReadable: Bool { schemaVersion <= Self.currentSchema }

    public func nextGeneration() -> ConfigurationVersion {
        ConfigurationVersion(schemaVersion: Self.currentSchema, generation: generation &+ 1)
    }

    public static func < (lhs: ConfigurationVersion, rhs: ConfigurationVersion) -> Bool {
        (lhs.schemaVersion, lhs.generation) < (rhs.schemaVersion, rhs.generation)
    }
}

/// The complete, immutable configuration the provider routes against.
///
/// The provider holds exactly one of these. Reload replaces the whole value in a single store;
/// nothing is mutated in place, so a flow that started under generation *n* keeps reading a
/// coherent generation *n* for its lifetime.
public struct RuntimeConfiguration: Codable, Sendable, Hashable {

    public var version: ConfigurationVersion
    public var rules: [AppRule]
    public var proxy: ProxyConfiguration

    /// Master switch. When false the provider routes everything DIRECT while staying installed
    /// and running — a paused state that is honest about being paused, unlike an uninstalled
    /// extension that merely looks the same from the outside.
    public var isRoutingEnabled: Bool

    /// Whether to emit a log line for DIRECT decisions.
    ///
    /// Off by default: the provider is consulted for every matching flow on the system, so
    /// logging each DIRECT decision is high volume and low value (G-12). Counters are always
    /// maintained; enumeration is the diagnostic mode.
    public var logsDirectFlows: Bool

    public init(
        version: ConfigurationVersion = ConfigurationVersion(),
        rules: [AppRule] = [],
        proxy: ProxyConfiguration = .default,
        isRoutingEnabled: Bool = true,
        logsDirectFlows: Bool = false
    ) {
        self.version = version
        self.rules = rules
        self.proxy = proxy
        self.isRoutingEnabled = isRoutingEnabled
        self.logsDirectFlows = logsDirectFlows
    }

    public static let empty = RuntimeConfiguration()

    /// Rules currently routing to the PROXY lane.
    public var proxiedRules: [AppRule] {
        rules.filter { $0.isEnabled && $0.action == .proxy }
    }
}
