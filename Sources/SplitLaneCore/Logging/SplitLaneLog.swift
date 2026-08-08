import Foundation
import OSLog

/// Structured logging for SplitLane.
///
/// One subsystem, fixed categories, so a developer can filter to exactly the layer they care
/// about:
///
/// ```
/// log stream --predicate 'subsystem == "dev.cofe.splitlane" AND category == "routing"' --info
/// ```
///
/// ## What must never be logged
///
/// Proxy passwords, credentials of any kind, traffic payload, tokens, Keychain references. There
/// is no debug flag that turns these on — the safe way to guarantee a secret is not in the log is
/// for no code path to put it there. ``redacted(_:)`` exists for the cases where a value might
/// contain one.
///
/// Destinations, ports, source applications, routing decisions, connection states, error
/// categories, durations and byte counts *are* logged: they are what makes a routing bug
/// diagnosable, and the user already knows where their own applications connect.
///
/// Note that OSLog treats interpolated strings as private by default and elides them in captured
/// logs. Values meant to be visible are marked `privacy: .public` explicitly, which also makes
/// the decision to expose each one reviewable in the diff.
public enum SplitLaneLog {

    public static let subsystem = "dev.cofe.splitlane"

    /// Host application lifecycle.
    public static let app = Logger(subsystem: subsystem, category: "app")
    /// System extension installation and activation, host side.
    public static let extensionLifecycle = Logger(subsystem: subsystem, category: "extension")
    /// Provider start, stop and network settings.
    public static let provider = Logger(subsystem: subsystem, category: "provider")
    /// Per-flow routing decisions. The highest-volume category.
    public static let routing = Logger(subsystem: subsystem, category: "routing")
    /// Configuration load, validation and reload.
    public static let configuration = Logger(subsystem: subsystem, category: "configuration")
    /// SOCKS5 handshake.
    public static let socks5 = Logger(subsystem: subsystem, category: "socks5")
    /// TCP relay lifecycle and byte accounting.
    public static let relay = Logger(subsystem: subsystem, category: "relay")
    /// Host/provider messaging.
    public static let ipc = Logger(subsystem: subsystem, category: "ipc")
    /// Code signing and identity verification.
    public static let security = Logger(subsystem: subsystem, category: "security")

    /// Reduces a value to a shape that cannot carry a secret: its length and a short digest.
    ///
    /// For when something must be correlated across log lines without being disclosed.
    public static func redacted(_ value: String) -> String {
        value.isEmpty ? "<empty>" : "<redacted:\(value.utf8.count)b>"
    }
}

/// Short, stable strings for log lines.
///
/// Separate from the `localizedDescription` values, which are written for users and may be
/// reworded. Log strings are grepped, so they stay put.
extension RouteDecision.Reason {
    public var logDescription: String {
        switch self {
        case .noMatchingRule: "no-rule"
        case .exactRule: "exact-rule"
        case .bundleFamilyRule(let ruleIdentifier, _): "family-rule(\(ruleIdentifier))"
        case .localDestination: "local-destination"
        case .unidentifiedSource: "unidentified-source"
        case .udpNotSupported: "udp-not-supported"
        }
    }
}

extension SOCKS5Error {
    /// Stable category token for log filtering and metrics. Never includes server-supplied text.
    public var logCategory: String {
        switch self {
        case .unexpectedVersion: "unexpected-version"
        case .noAcceptableAuthenticationMethod: "no-acceptable-method"
        case .unsupportedAuthenticationMethod: "unsupported-method"
        case .authenticationRequired: "auth-required"
        case .authenticationFailed: "auth-failed"
        case .credentialTooLong: "credential-too-long"
        case .requestRejected: "request-rejected"
        case .unknownReplyCode: "unknown-reply-code"
        case .unsupportedAddressType: "unsupported-address-type"
        case .incompleteResponse: "incomplete-response"
        case .malformedResponse: "malformed-response"
        case .domainNameTooLong: "domain-too-long"
        case .invalidDestinationAddress: "invalid-destination"
        case .timedOut: "timed-out"
        case .cancelled: "cancelled"
        case .transportFailure: "transport-failure"
        case .protocolViolation: "protocol-violation"
        }
    }
}
