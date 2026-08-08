import Foundation
import Network
import NetworkExtension
import SplitLaneCore

/// Translates NetworkExtension flow objects into ``FlowDescriptor`` values and asks the
/// ``RuleEngine`` where they belong.
///
/// This is the only place in the codebase that knows about both NetworkExtension and the routing
/// model. Keeping the translation here is what lets `RuleEngine` stay a pure function that
/// `swift test` can exercise exhaustively without an entitlement, a system extension, or a Mac
/// that has been through the approval flow.
enum FlowRouter {

    /// Builds a descriptor from a flow.
    static func descriptor(for flow: NEAppProxyFlow, flowProtocol: FlowProtocol) -> FlowDescriptor {
        let metadata = flow.metaData
        let remote = remoteEndpointComponents(for: flow)

        return FlowDescriptor(
            sourceSigningIdentifier: metadata.sourceAppSigningIdentifier,
            remoteHostname: flow.remoteHostname,
            remoteAddress: remote.address,
            remotePort: remote.port,
            flowProtocol: flowProtocol,
            sourceAuditToken: metadata.sourceAppAuditToken
        )
    }

    /// Routes a flow.
    static func route(_ flow: NEAppProxyFlow, flowProtocol: FlowProtocol, using engine: RuleEngine)
        -> (decision: RouteDecision, descriptor: FlowDescriptor)
    {
        let descriptor = descriptor(for: flow, flowProtocol: flowProtocol)
        return (engine.decide(for: descriptor), descriptor)
    }

    // MARK: - Endpoint extraction

    /// Pulls the host and port out of a flow's remote endpoint.
    ///
    /// TCP flows expose `remoteFlowEndpoint`; UDP flows carry theirs in the initial endpoint
    /// handed to `handleNewUDPFlow`, so the UDP path passes it in separately.
    static func remoteEndpointComponents(for flow: NEAppProxyFlow) -> (address: String?, port: UInt16) {
        guard let tcpFlow = flow as? NEAppProxyTCPFlow else { return (nil, 0) }
        return components(of: tcpFlow.remoteFlowEndpoint)
    }

    /// Decomposes an `nw_endpoint_t` into a printable address and a port.
    ///
    /// Only literal addresses are reported as addresses. A hostname endpoint returns a nil
    /// address so the caller falls back to `remoteHostname`, and so the routing layer never
    /// mistakes a name for an address when deciding whether a destination is loopback.
    static func components(of endpoint: Network.NWEndpoint) -> (address: String?, port: UInt16) {
        switch endpoint {
        case .hostPort(let host, let port):
            let portValue = port.rawValue
            switch host {
            case .ipv4(let address):
                return (printable(address), portValue)
            case .ipv6(let address):
                return (printable(address), portValue)
            case .name(let name, _):
                return (NetworkAddress.isIPLiteral(name) ? name : nil, portValue)
            @unknown default:
                return (nil, portValue)
            }
        case .service, .unix, .url, .opaque:
            // Bonjour services, Unix sockets, URLs and opaque endpoints carry no routable address
            // for our purposes. Returning nil lets the caller fall back to `remoteHostname`.
            return (nil, 0)
        @unknown default:
            return (nil, 0)
        }
    }

    /// Renders an `IPv4Address`/`IPv6Address` without the interface-scope suffix.
    ///
    /// `IPv6Address.debugDescription` appends `%en0` for scoped addresses; the scope is not part
    /// of the address for classification purposes and would defeat a literal comparison.
    private static func printable<Address: IPAddress>(_ address: Address) -> String {
        let text = "\(address)"
        guard let percent = text.firstIndex(of: "%") else { return text }
        return String(text[text.startIndex..<percent])
    }

    // MARK: - Network settings

    /// The rules that decide which flows reach the provider at all.
    ///
    /// Both TCP and UDP are included, outbound only, with nil remote and local networks.
    ///
    /// **Loopback is excluded automatically**, and that is the mechanism that prevents a proxy
    /// loop. `NENetworkRule.h`: "If both remoteNetwork and localNetwork are nil then the rule will
    /// match all traffic of the given protocol and direction, except for loopback traffic." So the
    /// extension's own connection to 127.0.0.1:10808 is outside the intercept set by construction,
    /// not by convention. No explicit exclusion rule is added, because adding one would imply we
    /// are relying on something we are not.
    ///
    /// UDP must be included even though SplitLane cannot proxy it yet: excluded traffic never
    /// reaches the provider and would leave selected-app QUIC to escape DIRECT. Including it is
    /// what makes fail-closed possible (ADR 0004). Unselected apps are unaffected — they get
    /// `false` and the identical DIRECT path.
    ///
    /// A port-53 rule is prohibited by `NETransparentProxyNetworkSettings`, so DNS is structurally
    /// outside the intercept set. See `docs/NETWORKING.md §4`.
    static func makeNetworkSettings() -> NETransparentProxyNetworkSettings {
        // The tunnel remote address is required by the superclass but carries no meaning for a
        // transparent proxy: no tunnel is established and no address is assigned.
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        settings.includedNetworkRules = [
            NENetworkRule(
                remoteNetworkEndpoint: nil,
                remotePrefix: 0,
                localNetworkEndpoint: nil,
                localPrefix: 0,
                protocol: .TCP,
                direction: .outbound
            ),
            NENetworkRule(
                remoteNetworkEndpoint: nil,
                remotePrefix: 0,
                localNetworkEndpoint: nil,
                localPrefix: 0,
                protocol: .UDP,
                direction: .outbound
            ),
        ]

        return settings
    }
}
