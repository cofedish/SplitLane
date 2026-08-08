import Foundation

/// A user-configured routing rule: "this application belongs in this lane".
public struct AppRule: Codable, Sendable, Hashable, Identifiable {

    /// How strictly the rule's signing identifier must match the one on a flow.
    public enum MatchMode: String, Codable, Sendable, Hashable, CaseIterable {
        /// Match only the exact signing identifier.
        case exact

        /// Match the identifier and any dot-separated descendant of it.
        ///
        /// This is the default, and it is not a convenience. Electron and Chromium applications
        /// do essentially all of their networking from helper processes
        /// (`com.example.App.helper.Renderer`), not from the main bundle identifier. Under
        /// `.exact`, selecting such an app produces a rule that never matches a single flow —
        /// the app works perfectly and is completely unproxied. See ADR 0006.
        case bundleFamily
    }

    public var id: String { identity.signingIdentifier }

    public var identity: AppIdentity

    /// Lane assignment. `.direct` is a meaningful value: it records an app the user explicitly
    /// looked at and left alone, which the UI shows differently from an app it has never seen.
    public var action: RouteAction

    public var matchMode: MatchMode

    /// Whether the rule participates in routing at all. A disabled rule is retained so toggling an
    /// app off and on again does not lose its captured identity.
    public var isEnabled: Bool

    public init(
        identity: AppIdentity,
        action: RouteAction = .proxy,
        matchMode: MatchMode = .bundleFamily,
        isEnabled: Bool = true
    ) {
        self.identity = identity
        self.action = action
        self.matchMode = matchMode
        self.isEnabled = isEnabled
    }

    /// The lane this rule actually routes to right now.
    public var effectiveAction: RouteAction { isEnabled ? action : .direct }
}
