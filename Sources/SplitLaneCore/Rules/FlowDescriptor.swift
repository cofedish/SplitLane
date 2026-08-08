import Foundation

/// Transport of a flow, as far as `NENetworkRule` is able to distinguish.
public enum FlowProtocol: String, Codable, Sendable, Hashable, CaseIterable {
    case tcp
    case udp
}

/// The facts about a flow that the routing decision depends on.
///
/// This is a plain value with no NetworkExtension types in it, which is what lets `RuleEngine` be
/// exercised exhaustively by `swift test` with no Xcode, no entitlement, and no approved system
/// extension. The extension builds one of these from `NEAppProxyFlow` and hands it over; that
/// translation is the only NE-aware code in the routing path.
public struct FlowDescriptor: Sendable, Hashable {

    /// `NEFlowMetaData.sourceAppSigningIdentifier`.
    ///
    /// Documented as possibly empty for system-process flows, so the empty case is a real input,
    /// not a defensive afterthought.
    public let sourceSigningIdentifier: String

    /// `NEAppProxyFlow.remoteHostname`. Nil for BSD-socket clients that connect to a literal IP.
    /// When present it is preferred for SOCKS5 `ATYP=DOMAIN` so the upstream resolves the name
    /// from its own vantage point (docs/NETWORKING.md §6).
    public let remoteHostname: String?

    /// Remote IP literal from the flow endpoint, when known.
    public let remoteAddress: String?

    public let remotePort: UInt16

    public let flowProtocol: FlowProtocol

    /// Audit token bytes from `NEFlowMetaData.sourceAppAuditToken`.
    ///
    /// Unused by the MVP rule engine — carried so the M6.5 `FlowIdentityVerifier` can pin the
    /// team identifier without changing this type's shape (F-2).
    public let sourceAuditToken: Data?

    public init(
        sourceSigningIdentifier: String,
        remoteHostname: String? = nil,
        remoteAddress: String? = nil,
        remotePort: UInt16,
        flowProtocol: FlowProtocol,
        sourceAuditToken: Data? = nil
    ) {
        self.sourceSigningIdentifier = sourceSigningIdentifier
        self.remoteHostname = remoteHostname
        self.remoteAddress = remoteAddress
        self.remotePort = remotePort
        self.flowProtocol = flowProtocol
        self.sourceAuditToken = sourceAuditToken
    }

    /// True when the destination is on this machine or this link.
    ///
    /// Checks the address first because it is authoritative; the hostname is consulted only when
    /// no address is available, since a name is what the application asked for rather than where
    /// the packet goes.
    public var hasLocalDestination: Bool {
        if let remoteAddress, NetworkAddress.isLocalDestination(remoteAddress) { return true }
        if remoteAddress == nil, let remoteHostname, NetworkAddress.isLoopbackHost(remoteHostname) {
            return true
        }
        return false
    }
}
