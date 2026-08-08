import Foundation

/// Precomputed, immutable lookup tables for one configuration generation.
///
/// Built once per reload, read on every flow. The provider is consulted for *every* flow on the
/// system that matches its network rules — including the overwhelming majority it will hand
/// straight back — so the hot path must not allocate, must not touch disk, and must not evaluate
/// code signatures. All of that work happens here, once.
public struct RuleSnapshot: Sendable {

    /// Rules keyed by exact signing identifier.
    private let exactRules: [String: AppRule]

    /// Rules that additionally match dotted descendants, same keying.
    private let familyRules: [String: AppRule]

    public let proxy: ProxyConfiguration
    public let version: ConfigurationVersion
    public let isRoutingEnabled: Bool
    public let logsDirectFlows: Bool

    /// Maximum number of ancestors examined when resolving an identifier.
    ///
    /// A pathological signing identifier with hundreds of labels must not turn one flow into
    /// hundreds of dictionary probes on the hot path. Eight is well beyond any real bundle
    /// hierarchy — Chromium's deepest helper is four labels past its parent — while keeping the
    /// worst case flat.
    ///
    /// Deriving this bound from the configured rules instead was tried and is wrong: the walk
    /// length depends on how deep the *flow's* identifier is relative to the rule, not on the
    /// rule's own depth, so a one-label rule would stop after one step and never match its own
    /// grandchildren. `RuleEngineTests.ancestorWalkIsBounded` covers it.
    static let ancestorWalkLimit = 8

    public init(configuration: RuntimeConfiguration) {
        var exact: [String: AppRule] = [:]
        var family: [String: AppRule] = [:]

        for rule in configuration.rules where rule.isEnabled {
            let key = rule.identity.signingIdentifier
            // The validator rejects empty identifiers, but the snapshot is the last line before
            // the hot path: an empty key here would match every unidentified system flow.
            guard !key.isEmpty else { continue }

            switch rule.matchMode {
            case .exact:
                exact[key] = rule
            case .bundleFamily:
                exact[key] = rule
                family[key] = rule
            }
        }

        self.exactRules = exact
        self.familyRules = family
        self.proxy = configuration.proxy
        self.version = configuration.version
        self.isRoutingEnabled = configuration.isRoutingEnabled
        self.logsDirectFlows = configuration.logsDirectFlows
    }

    public static let empty = RuleSnapshot(configuration: .empty)

    /// Number of rules that can route traffic. Diagnostic only.
    public var activeRuleCount: Int { exactRules.count }

    // MARK: - Lookup

    /// Finds the most specific rule matching a signing identifier.
    ///
    /// Exact match first, then dot-separated ancestors longest-first, so a specific rule for
    /// `com.example.App.helper` wins over a general rule for `com.example.App`.
    func rule(for signingIdentifier: String) -> (rule: AppRule, isExact: Bool)? {
        if let exact = exactRules[signingIdentifier] {
            return (exact, true)
        }
        guard !familyRules.isEmpty else { return nil }

        // Walk ancestors by trimming trailing labels: a.b.c.d -> a.b.c -> a.b -> a
        //
        // Cutting on the '.' boundary is the security-relevant part. A raw
        // `hasPrefix("com.openai.codex")` would also match `com.openai.codexal`, which would let
        // an unrelated application walk into the proxy lane (ADR 0006).
        var cursor = Substring(signingIdentifier)
        var steps = 0

        while steps < Self.ancestorWalkLimit, let dot = cursor.lastIndex(of: ".") {
            cursor = cursor[cursor.startIndex..<dot]
            steps += 1
            if let match = familyRules[String(cursor)] {
                return (match, false)
            }
        }
        return nil
    }
}

/// Decides which lane a flow belongs in.
///
/// Pure and synchronous by design: no I/O, no locking, no async. Concurrency is handled one level
/// up by ``ProviderRuntime``, which swaps whole snapshots; this type only ever reads one.
public struct RuleEngine: Sendable {

    public let snapshot: RuleSnapshot

    public init(snapshot: RuleSnapshot) {
        self.snapshot = snapshot
    }

    public init(configuration: RuntimeConfiguration) {
        self.snapshot = RuleSnapshot(configuration: configuration)
    }

    /// The routing decision for a flow.
    ///
    /// Order matters, and each early return encodes a rule from the threat model:
    ///
    /// 1. Routing disabled → DIRECT. A paused SplitLane must be inert, not half-active.
    /// 2. Local destination → DIRECT, for every app. Loop defence (docs/NETWORKING.md §3).
    /// 3. Empty identifier → DIRECT. System-process flows carry no identity (G-6).
    /// 4. No rule → DIRECT. The product's default.
    /// 5. Selected + UDP → BLOCK. Fail closed rather than let QUIC escape (ADR 0004).
    /// 6. Selected + TCP → PROXY.
    public func decide(for flow: FlowDescriptor) -> RouteDecision {
        guard snapshot.isRoutingEnabled else {
            return .directDefault
        }

        guard !flow.hasLocalDestination else {
            return RouteDecision(action: .direct, reason: .localDestination)
        }

        let identifier = flow.sourceSigningIdentifier
        guard !identifier.isEmpty else {
            return RouteDecision(action: .direct, reason: .unidentifiedSource)
        }

        guard let (rule, isExact) = snapshot.rule(for: identifier) else {
            return .directDefault
        }

        let reason: RouteDecision.Reason = isExact
            ? .exactRule(signingIdentifier: identifier)
            : .bundleFamilyRule(
                ruleIdentifier: rule.identity.signingIdentifier,
                matchedIdentifier: identifier
              )

        switch rule.effectiveAction {
        case .direct:
            return RouteDecision(action: .direct, reason: reason, matchedRuleID: rule.id)

        case .block:
            return RouteDecision(action: .block, reason: reason, matchedRuleID: rule.id)

        case .proxy:
            // A selected app's UDP is refused, not passed through. Returning DIRECT here would be
            // the silent QUIC bypass the whole design exists to prevent; the app sees the failure
            // and falls back to TCP, which is proxied correctly.
            if flow.flowProtocol == .udp {
                return RouteDecision(action: .block, reason: .udpNotSupported, matchedRuleID: rule.id)
            }
            return RouteDecision(action: .proxy, reason: reason, matchedRuleID: rule.id)
        }
    }
}
