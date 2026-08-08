import Foundation
import NetworkExtension
import SplitLaneCore

// IMPORTANT: this file must NOT `import Network`.
//
// NetworkExtension re-exports Network, and both modules define a type called `NWEndpoint`. In any
// file that pulls in both, the bare name is ambiguous *and* so is the qualified
// `NetworkExtension.NWEndpoint` — the compiler reports "ambiguous type name 'NWEndpoint' in
// module 'NetworkExtension'". Keeping Network out of this one file is what makes the UDP override
// expressible at all.

/// UDP flow handling.
///
/// ## Why this override targets a deprecated API
///
/// Handling UDP is not optional: without it, a selected application's QUIC/HTTP3 traffic reaches
/// the provider, gets no decision, and goes out DIRECT — a silent bypass of the proxy, which is
/// the precise failure this product exists to prevent (ADR 0004).
///
/// Three things were verified against the installed macOS 15.5 SDK before settling on this shape:
///
/// 1. `handleNewUDPFlow(_:initialRemoteFlowEndpoint:)`, the macOS 15 replacement, is imported into
///    Swift as an **extension** member of `NEAppProxyProvider`, not a class member. Swift cannot
///    override it — `swift-api-digester` shows it with no owning class, and attempting the
///    override fails with "method does not override any method from its superclass".
/// 2. Declaring its Objective-C selector directly is also impossible: the modern signature takes
///    `Network.NWEndpoint`, a Swift-only enum, so `@objc` rejects it with "the type of the
///    parameter cannot be represented in Objective-C".
/// 3. The deprecated `handleNewUDPFlow(_:initialRemoteEndpoint:)` *is* a real class member and can
///    be overridden — but **only in Swift 5 language mode**. Under Swift 6 it disappears from the
///    class entirely. This is why the extension target builds with `-swift-version 5`
///    (`-strict-concurrency=complete` is still on). See ADR 0008.
///
/// ## UNVERIFIED — must be settled at M9
///
/// That macOS still dispatches UDP flows to the deprecated selector on 15.x. The assumption is
/// that the framework's implementation of the new selector forwards to the old one for source
/// compatibility, which is Apple's usual pattern. **If it does not, selected-app UDP escapes
/// DIRECT and the fail-closed guarantee is silently broken.** The M9 experiment is: select a
/// QUIC-capable app, generate UDP/443 traffic, and confirm a `BLOCK udp` line appears in the
/// routing log. If nothing appears, the fallback is an Objective-C shim implementing the modern
/// selector and forwarding into Swift.
extension TransparentProxyProvider {

    /// Routes a UDP flow. Selected applications are refused; everyone else is untouched.
    ///
    /// Marked deprecated to match the API it overrides, which also suppresses the deprecation
    /// warnings for `NWEndpoint`/`NWHostEndpoint` inside the body rather than leaving four
    /// recurring warnings in a build the project expects to be clean.
    @available(macOS, deprecated: 15.0)
    override func handleNewUDPFlow(_ flow: NEAppProxyUDPFlow, initialRemoteEndpoint remoteEndpoint: NWEndpoint) -> Bool {
        let engine = runtime.engine
        let components = Self.legacyComponents(of: remoteEndpoint)

        // A UDP flow's destination arrives in the initial endpoint rather than on the flow, so the
        // descriptor is assembled here instead of by FlowRouter.descriptor(for:).
        let descriptor = FlowDescriptor(
            sourceSigningIdentifier: flow.metaData.sourceAppSigningIdentifier,
            remoteHostname: flow.remoteHostname,
            remoteAddress: components.address,
            remotePort: components.port,
            flowProtocol: .udp,
            sourceAuditToken: flow.metaData.sourceAppAuditToken
        )

        let decision = engine.decide(for: descriptor)
        runtime.record(decision)

        switch decision.action {
        case .direct:
            if engine.snapshot.logsDirectFlows { log(decision, descriptor, logsDirect: true) }
            return false

        case .block, .proxy:
            // `.proxy` cannot occur for UDP — RuleEngine converts it to `.block` — but handling
            // both identically means a future change to that mapping cannot quietly turn into a
            // DIRECT bypass.
            runtime.recordFailure(.udpNotSupported)
            return UDPFlowHandler.refuse(flow, descriptor: descriptor)
        }
    }

    /// Decomposes a legacy `NWEndpoint` into an address and a port.
    ///
    /// Only IP literals are reported as addresses; a name is left to `remoteHostname`, so the
    /// loopback check in `RuleEngine` never mistakes a hostname for an address.
    @available(macOS, deprecated: 15.0)
    static func legacyComponents(of endpoint: NWEndpoint) -> (address: String?, port: UInt16) {
        guard let host = endpoint as? NWHostEndpoint else { return (nil, 0) }
        let port = UInt16(host.port) ?? 0
        return (NetworkAddress.isIPLiteral(host.hostname) ? host.hostname : nil, port)
    }
}
