import Foundation

/// Lifecycle state of a single connection.
public enum ConnectionState: String, Codable, Sendable, Hashable, CaseIterable {
    /// Decision made, upstream handshake not finished.
    case connecting
    /// Relaying.
    case active
    /// Finished normally.
    case closed
    /// Ended with an error. For a selected application this means the connection failed rather
    /// than fell back — fail-closed (ADR 0003).
    case failed
    /// Refused before it began: selected-app UDP.
    case blocked

    public var isTerminal: Bool {
        switch self {
        case .connecting, .active: false
        case .closed, .failed, .blocked: true
        }
    }
}

/// Error categories shown in the Activity list.
///
/// A closed vocabulary rather than free text, so the UI can group and explain failures instead of
/// echoing a message. The categories map onto distinct user actions: start the proxy, fix the
/// credentials, or accept that this app cannot be proxied yet.
public enum ConnectionErrorCategory: String, Codable, Sendable, Hashable, CaseIterable {
    case upstreamUnreachable
    case authenticationFailed
    case authenticationUnsupported
    case rejectedByProxy
    case timedOut
    case udpNotSupported
    case flowError
    case cancelled
    case internalError

    public var localizedDescription: String {
        switch self {
        case .upstreamUnreachable: "Proxy unreachable"
        case .authenticationFailed: "Proxy rejected credentials"
        case .authenticationUnsupported: "No shared authentication method"
        case .rejectedByProxy: "Proxy refused the connection"
        case .timedOut: "Timed out"
        case .udpNotSupported: "UDP is not proxied yet — connection refused"
        case .flowError: "Flow error"
        case .cancelled: "Cancelled"
        case .internalError: "Internal error"
        }
    }

    /// Maps a SOCKS5 failure onto a user-facing category.
    public init(_ error: SOCKS5Error) {
        switch error {
        case .transportFailure, .incompleteResponse:
            self = .upstreamUnreachable
        case .authenticationFailed, .credentialTooLong:
            self = .authenticationFailed
        case .noAcceptableAuthenticationMethod, .unsupportedAuthenticationMethod, .authenticationRequired:
            self = .authenticationUnsupported
        case .requestRejected, .unknownReplyCode:
            self = .rejectedByProxy
        case .timedOut:
            self = .timedOut
        case .cancelled:
            self = .cancelled
        case .unexpectedVersion, .malformedResponse, .unsupportedAddressType,
             .domainNameTooLong, .invalidDestinationAddress, .protocolViolation:
            self = .internalError
        }
    }
}

/// One connection, as shown in Activity.
///
/// Metadata only. No payload is ever captured, and there is nowhere in this type to put any —
/// which is deliberate, because "we only log a little of the traffic" is not a property that
/// survives contact with a feature request.
public struct ConnectionEvent: Codable, Sendable, Hashable, Identifiable {

    public let id: UUID
    public let timestamp: Date

    /// Display name of the source app when a rule matched it; nil for unattributed flows.
    public let applicationName: String?

    /// The identifier the flow actually carried. Worth showing verbatim: for Electron apps this
    /// is the helper process, not the bundle the user picked, and seeing that is what explains
    /// bundle-family matching (ADR 0006).
    public let signingIdentifier: String

    /// Hostname when the flow provided one, otherwise the IP literal.
    public let destinationHost: String
    public let destinationPort: UInt16
    public let networkProtocol: FlowProtocol
    public let route: RouteAction

    public var state: ConnectionState
    public var bytesSent: UInt64
    public var bytesReceived: UInt64
    public var error: ConnectionErrorCategory?

    /// Set when the connection reaches a terminal state.
    public var duration: TimeInterval?

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        applicationName: String? = nil,
        signingIdentifier: String,
        destinationHost: String,
        destinationPort: UInt16,
        networkProtocol: FlowProtocol,
        route: RouteAction,
        state: ConnectionState = .connecting,
        bytesSent: UInt64 = 0,
        bytesReceived: UInt64 = 0,
        error: ConnectionErrorCategory? = nil,
        duration: TimeInterval? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.applicationName = applicationName
        self.signingIdentifier = signingIdentifier
        self.destinationHost = destinationHost
        self.destinationPort = destinationPort
        self.networkProtocol = networkProtocol
        self.route = route
        self.state = state
        self.bytesSent = bytesSent
        self.bytesReceived = bytesReceived
        self.error = error
        self.duration = duration
    }

    public var destinationDisplayString: String {
        destinationHost.contains(":") ? "[\(destinationHost)]:\(destinationPort)"
                                      : "\(destinationHost):\(destinationPort)"
    }
}
