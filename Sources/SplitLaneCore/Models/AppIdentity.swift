import Foundation

/// Everything SplitLane knows about an application the user picked.
///
/// The routing key is ``signingIdentifier``, because that is the only application identity
/// `NEFlowMetaData` actually hands the provider at flow time. `bundleIdentifier` and `path` are
/// captured for display and for detecting drift; they are deliberately *not* used for matching.
///
/// `NEFlowMetaData.h` describes the signing identifier as "almost always equivalent to the bundle
/// identifier" — "almost always" is why both are stored separately rather than assumed equal.
/// See ADR 0002.
public struct AppIdentity: Codable, Sendable, Hashable, Identifiable {

    /// Stable identity of this record. Equal to ``signingIdentifier``, which is unique per rule
    /// because `ConfigurationValidator` rejects duplicates.
    public var id: String { signingIdentifier }

    /// Code signing identifier, read from `SecStaticCode` at pick time and compared against
    /// `NEFlowMetaData.sourceAppSigningIdentifier` at flow time. The routing key.
    public let signingIdentifier: String

    /// Apple Team Identifier, when the app is team-signed. Nil for ad-hoc or unsigned binaries.
    ///
    /// Not used for matching in the MVP. It is captured now because the M6.5 hardening
    /// (`FlowIdentityVerifier`) pins both identifier and team, and retrofitting the field later
    /// would mean every existing rule needs re-picking. See F-2 in docs/THREAT_MODEL.md.
    public let teamIdentifier: String?

    /// `CFBundleIdentifier` from the app's Info.plist.
    public let bundleIdentifier: String?

    /// User-facing name.
    public let displayName: String

    /// Filesystem location at pick time. Display and re-inspection only — an app that moves keeps
    /// working, which is correct, because its signing identity did not change.
    public let bundlePath: String?

    /// True when the binary carried no team signature. Surfaced in the UI because a rule for an
    /// ad-hoc-signed binary is trivially impersonable by any other local binary (F-2).
    public var isAdHocSigned: Bool { teamIdentifier == nil }

    /// True when the signing identifier and bundle identifier disagree. Worth showing the user:
    /// it means the value they see in Finder is not the value SplitLane routes on.
    public var hasIdentifierMismatch: Bool {
        guard let bundleIdentifier else { return false }
        return bundleIdentifier != signingIdentifier
    }

    public init(
        signingIdentifier: String,
        teamIdentifier: String? = nil,
        bundleIdentifier: String? = nil,
        displayName: String,
        bundlePath: String? = nil
    ) {
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.bundleIdentifier = bundleIdentifier
        self.displayName = displayName
        self.bundlePath = bundlePath
    }
}
