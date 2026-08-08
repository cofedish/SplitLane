import Foundation
import NetworkExtension
import SplitLaneCore

/// Handles UDP flows from selected applications.
///
/// SplitLane cannot proxy UDP yet — that needs SOCKS5 UDP ASSOCIATE — so a selected app's UDP is
/// **refused**, never passed through.
///
/// Letting it through would be a silent bypass: QUIC/HTTP3 traffic from an app the user believes
/// is proxied would go straight out DIRECT, and nothing would indicate it. Refusing pushes the
/// app onto its TCP fallback, which SplitLane relays correctly. Chromium, Electron and
/// `URLSession` all implement that fallback. An app that does not will lose connectivity when
/// selected, which is surfaced in the UI rather than hidden. See ADR 0004 and F-3.
///
/// DNS is unaffected: `NETransparentProxyNetworkSettings` prohibits port-53 rules, so DNS never
/// reaches the provider and cannot be blocked here even by accident (`docs/NETWORKING.md §4`).
enum UDPFlowHandler {

    /// Refuses a UDP flow.
    ///
    /// The flow is closed **without being opened**. Opening it first would establish a datagram
    /// path only to tear it down, which is wasted setup and a wider window in which a datagram
    /// could slip out.
    ///
    /// - Returns: `true` — the provider claims the flow so the system does not route it DIRECT.
    ///   Returning `false` here is exactly the leak this function exists to prevent.
    @discardableResult
    static func refuse(_ flow: NEAppProxyUDPFlow, descriptor: FlowDescriptor) -> Bool {
        let error = NSError(
            domain: NEAppProxyErrorDomain,
            code: NEAppProxyFlowError.refused.rawValue,
            userInfo: [NSLocalizedDescriptionKey: "SplitLane does not proxy UDP yet"]
        )
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)

        SplitLaneLog.routing.notice(
            """
            BLOCK udp app=\(descriptor.sourceSigningIdentifier, privacy: .public) \
            dst=\(descriptor.remoteHostname ?? descriptor.remoteAddress ?? "unknown", privacy: .public):\
            \(descriptor.remotePort, privacy: .public) reason=udp-not-supported
            """
        )
        return true
    }
}
