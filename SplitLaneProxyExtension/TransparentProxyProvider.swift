import Foundation
import Network
import NetworkExtension
import SplitLaneCore

/// SplitLane's transparent proxy provider.
///
/// The contract, from `NETransparentProxyProvider.h`:
///
/// > Returning NO from `handleNewFlow:` … causes the flow to proceed to communicate directly with
/// > the flow's ultimate destination.
///
/// So `false` means DIRECT, natively — the kernel handles the flow, no socket is recreated, and
/// nothing is copied. That is what makes "unselected applications are untouched" true rather than
/// aspirational, and it is why this class is deliberately thin: for the overwhelming majority of
/// flows on the machine, its entire job is to decide quickly and get out of the way.
class TransparentProxyProvider: NETransparentProxyProvider, @unchecked Sendable {

    let runtime = ProviderRuntime()
    private let relays = RelayRegistry()

    // MARK: - Lifecycle

    override func startProxy(options: [String: Any]? = nil) async throws {
        SplitLaneLog.provider.notice("Starting SplitLane proxy provider")

        loadConfiguration()

        do {
            try await setTunnelNetworkSettings(FlowRouter.makeNetworkSettings())
        } catch {
            // A rule violating the documented restrictions makes this fail, and the provider then
            // receives no flows at all while appearing to be running. Worth a loud log line.
            SplitLaneLog.provider.fault(
                "Failed to apply network settings: \(error.localizedDescription, privacy: .public)"
            )
            throw error
        }

        runtime.markStarted()
        SplitLaneLog.provider.notice(
            "Provider started with generation \(self.runtime.configurationGeneration, privacy: .public)"
        )
    }

    override func stopProxy(with reason: NEProviderStopReason) async {
        SplitLaneLog.provider.notice("Stopping proxy provider, reason \(reason.rawValue, privacy: .public)")
        await relays.cancelAll()
        runtime.markStopped()
    }

    // MARK: - Flow handling

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        let engine = runtime.engine

        if let tcpFlow = flow as? NEAppProxyTCPFlow {
            let (decision, descriptor) = FlowRouter.route(tcpFlow, flowProtocol: .tcp, using: engine)
            runtime.record(decision)
            log(decision, descriptor, logsDirect: engine.snapshot.logsDirectFlows)

            switch decision.action {
            case .direct:
                // The whole point of the architecture: hand it back, untouched.
                return false

            case .block:
                closeRefused(tcpFlow)
                return true

            case .proxy:
                let proxy = engine.snapshot.proxy
                Task { [weak self] in
                    await self?.proxy(tcpFlow, descriptor: descriptor, using: proxy)
                }
                return true
            }
        }

        // UDP arrives through handleNewUDPFlow. Anything else is a flow type this provider does
        // not understand, and guessing would risk breaking traffic it was never asked to touch.
        SplitLaneLog.routing.debug("Unhandled flow type, routing DIRECT")
        return false
    }

    // MARK: - Proxying

    private func proxy(_ flow: NEAppProxyTCPFlow, descriptor: FlowDescriptor, using proxy: SplitLaneCore.ProxyConfiguration) async {
        let destinationLabel = "\(descriptor.remoteHostname ?? descriptor.remoteAddress ?? "unknown"):\(descriptor.remotePort)"

        do {
            // The flow must be opened before any read or write.
            try await flow.open(withLocalFlowEndpoint: nil)
        } catch {
            SplitLaneLog.relay.error(
                "Failed to open flow to \(destinationLabel, privacy: .public): \(error.localizedDescription, privacy: .public)"
            )
            return
        }

        let destination: SOCKS5Address
        do {
            destination = try SOCKS5Address.destination(
                hostname: descriptor.remoteHostname,
                address: descriptor.remoteAddress
            )
        } catch {
            fail(flow, category: .internalError, destination: destinationLabel)
            return
        }

        let transport = NWConnectionTransport(host: proxy.endpoint.host, port: proxy.endpoint.port)
        let credential = await CredentialProvider.credential(for: proxy)

        do {
            let info = try await SOCKS5Client.connect(
                through: transport,
                to: destination,
                port: descriptor.remotePort,
                credential: credential,
                timeout: proxy.handshakeTimeout
            )

            guard let connection = await transport.takeConnection() else {
                fail(flow, category: .internalError, destination: destinationLabel)
                return
            }

            let relay = TCPFlowRelay(
                flow: flow,
                connection: connection,
                initialUpstreamBytes: info.leftoverBytes,
                destinationDescription: destinationLabel
            ) { [weak self] id, category in
                guard let self else { return }
                self.runtime.flowDidEnd(id)
                if let category { self.runtime.recordFailure(category) }
                Task { await self.relays.remove(id) }
            }

            runtime.flowDidStart(relay.id)
            await relays.add(relay)
            relay.start()

        } catch let error as SOCKS5Error {
            // Fail closed. There is deliberately no branch here that retries the connection
            // directly — that would be the silent leak ADR 0003 forbids.
            SplitLaneLog.socks5.error(
                """
                SOCKS5 handshake failed for \(destinationLabel, privacy: .public): \
                \(error.logCategory, privacy: .public)
                """
            )
            fail(flow, category: ConnectionErrorCategory(error), destination: destinationLabel)
        } catch {
            fail(flow, category: .internalError, destination: destinationLabel)
        }
    }

    private func fail(_ flow: NEAppProxyFlow, category: ConnectionErrorCategory, destination: String) {
        runtime.recordFailure(category)
        let error = NSError(
            domain: NEAppProxyErrorDomain,
            code: NEAppProxyFlowError.refused.rawValue,
            userInfo: [NSLocalizedDescriptionKey: category.localizedDescription]
        )
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
    }

    private func closeRefused(_ flow: NEAppProxyFlow) {
        let error = NSError(
            domain: NEAppProxyErrorDomain,
            code: NEAppProxyFlowError.refused.rawValue,
            userInfo: [NSLocalizedDescriptionKey: "Blocked by SplitLane"]
        )
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
    }

    // MARK: - Configuration

    private func loadConfiguration() {
        guard
            let protocolConfiguration = protocolConfiguration as? NETunnelProviderProtocol,
            let dictionary = protocolConfiguration.providerConfiguration
        else {
            SplitLaneLog.configuration.error("No provider configuration; routing everything DIRECT")
            runtime.apply(.empty)
            return
        }

        do {
            runtime.apply(try ConfigurationCodec.decode(from: dictionary))
        } catch {
            // Refusing beats guessing: an empty configuration routes everything DIRECT, which is
            // the safe default, and the failure is visible instead of being a silent misroute.
            SplitLaneLog.configuration.fault(
                "Failed to decode configuration: \(String(describing: error), privacy: .public)"
            )
            runtime.apply(.empty)
        }
    }

    // MARK: - IPC

    override func handleAppMessage(_ messageData: Data) async -> Data? {
        let message: ProviderMessage
        do {
            message = try ProviderMessageCodec.decodeMessage(messageData)
        } catch {
            SplitLaneLog.ipc.error("Undecodable provider message")
            return try? ProviderMessageCodec.encode(ProviderResponse.failure(reason: "undecodable message"))
        }

        let response: ProviderResponse

        switch message {
        case .reloadConfiguration(let generation):
            SplitLaneLog.ipc.notice("Reload requested for generation \(generation, privacy: .public)")
            loadConfiguration()
            response = .acknowledged

        case .requestStatus:
            response = .status(runtime.status)

        case .testProxyConnection:
            response = .proxyTestResult(await testProxy())

        case .resetStatistics:
            runtime.resetStatistics()
            response = .acknowledged

        case .setDirectFlowLogging:
            // Requires a configuration round-trip; acknowledged so the app does not treat the
            // absence of a reply as a provider failure.
            response = .acknowledged
        }

        return try? ProviderMessageCodec.encode(response)
    }

    /// Verifies the upstream from *inside* the provider.
    ///
    /// The app testing its own connection proves nothing about the provider's: different process,
    /// different user, different sandbox. Only this measurement reflects what flows will actually
    /// experience.
    private func testProxy() async -> ProxyTestResult {
        let proxy = runtime.proxyConfiguration
        let transport = NWConnectionTransport(host: proxy.endpoint.host, port: proxy.endpoint.port)
        let credential = await CredentialProvider.credential(for: proxy)
        let started = Date()

        do {
            // example.com resolved by the upstream — a CONNECT the proxy can actually attempt,
            // which exercises the full handshake rather than just the TCP connect.
            let info = try await SOCKS5Client.connect(
                through: transport,
                to: .domain("example.com"),
                port: 443,
                credential: credential,
                timeout: proxy.handshakeTimeout
            )
            await transport.close()
            return ProxyTestResult(
                succeeded: true,
                latency: Date().timeIntervalSince(started),
                negotiatedMethod: String(describing: info.method)
            )
        } catch let error as SOCKS5Error {
            return ProxyTestResult(succeeded: false, errorDescription: error.localizedDescription)
        } catch {
            return ProxyTestResult(succeeded: false, errorDescription: "Unexpected failure")
        }
    }

    // MARK: - Logging

    func log(_ decision: RouteDecision, _ descriptor: FlowDescriptor, logsDirect: Bool) {
        guard decision.action != .direct || logsDirect else { return }

        let destination = descriptor.remoteHostname ?? descriptor.remoteAddress ?? "unknown"
        SplitLaneLog.routing.info(
            """
            \(decision.action.rawValue.uppercased(), privacy: .public) \
            \(descriptor.flowProtocol.rawValue, privacy: .public) \
            app=\(descriptor.sourceSigningIdentifier, privacy: .public) \
            dst=\(destination, privacy: .public):\(descriptor.remotePort, privacy: .public) \
            reason=\(decision.reason.logDescription, privacy: .public)
            """
        )
    }
}

/// Tracks live relays so they can all be torn down when the provider stops.
actor RelayRegistry {
    private var relays: [UUID: TCPFlowRelay] = [:]

    func add(_ relay: TCPFlowRelay) { relays[relay.id] = relay }
    func remove(_ id: UUID) { relays[id] = nil }

    func cancelAll() {
        for relay in relays.values { relay.cancel() }
        relays.removeAll()
    }
}
