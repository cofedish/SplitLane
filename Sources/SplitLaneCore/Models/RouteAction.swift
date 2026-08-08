import Foundation

/// Which lane a flow belongs in.
public enum RouteAction: String, Codable, Sendable, Hashable, CaseIterable {
    /// Hand the flow back to the kernel untouched. This is the default for every application
    /// the user has not selected, and it is what makes "unselected apps are untouched" literally
    /// true: `handleNewFlow` returns `false` and no socket is recreated.
    case direct

    /// Relay the flow through the configured upstream proxy.
    case proxy

    /// Refuse the flow. Used for selected-app traffic SplitLane cannot carry safely — currently
    /// UDP, which would otherwise escape the proxy silently (ADR 0004).
    case block
}

/// The outcome of a routing decision, carrying enough context to log it and to explain it in the
/// UI without re-deriving anything.
public struct RouteDecision: Sendable, Hashable {

    /// Why a flow ended up in the lane it did. Purely diagnostic — routing never branches on it.
    public enum Reason: Sendable, Hashable {
        /// No rule matched; the DIRECT default applied.
        case noMatchingRule
        /// A rule matched this exact signing identifier.
        case exactRule(signingIdentifier: String)
        /// A rule matched an ancestor of this identifier — typically a helper process such as
        /// `com.example.App.helper.Renderer` matching a rule for `com.example.App` (ADR 0006).
        case bundleFamilyRule(ruleIdentifier: String, matchedIdentifier: String)
        /// The destination is loopback or link-local. Never proxied, for any app: this is the
        /// third layer of proxy-loop defence (docs/NETWORKING.md §3).
        case localDestination
        /// The flow carried no source application identity. `NEFlowMetaData` documents that
        /// `sourceAppSigningIdentifier` "may be empty in cases where the flow originates from a
        /// system process".
        case unidentifiedSource
        /// A selected application's UDP flow, refused so it cannot bypass the proxy.
        case udpNotSupported
    }

    public let action: RouteAction
    public let reason: Reason
    /// The rule that produced a `.proxy` decision, if any. Nil for DIRECT and for blocks that are
    /// protocol-driven rather than rule-driven.
    public let matchedRuleID: AppRule.ID?

    public init(action: RouteAction, reason: Reason, matchedRuleID: AppRule.ID? = nil) {
        self.action = action
        self.reason = reason
        self.matchedRuleID = matchedRuleID
    }

    public static let directDefault = RouteDecision(action: .direct, reason: .noMatchingRule)
}
