import Foundation
import Network
import NetworkExtension
import SplitLaneCore

/// Relays one TCP flow between the application and the SOCKS5 upstream.
///
/// ## Backpressure
///
/// Strictly ping-pong in each direction: exactly one read is outstanding, and the next read is
/// only issued after the matching write completes. Memory per flow is therefore bounded by one
/// buffer per direction, whatever the speed mismatch between the app and the proxy.
///
/// The tempting alternative — read eagerly and queue — is an unbounded memory sink inside a root
/// process, driven by any application that can write faster than the upstream drains. It is not
/// an optimisation worth having.
///
/// ## Isolation
///
/// Each relay owns its own state on its own serial queue and reports completion exactly once. A
/// failure in one relay cannot affect another and cannot reach the provider: a crash here would
/// take down routing for every selected application at once, so error containment is a security
/// property rather than a robustness nicety.
final class TCPFlowRelay: @unchecked Sendable {

    let id = UUID()

    private let flow: NEAppProxyTCPFlow
    private let connection: NWConnection
    private let queue: DispatchQueue
    private let onFinish: @Sendable (UUID, ConnectionErrorCategory?) -> Void

    private let finished = OneShotFlag()
    private var bytesSent: UInt64 = 0
    private var bytesReceived: UInt64 = 0
    private let startedAt = Date()

    /// Bytes the SOCKS5 server coalesced after its CONNECT reply.
    ///
    /// A server may pack its reply and the first upstream bytes into one segment. Dropping them
    /// would truncate the first response in a way that looks intermittent and unreproducible.
    private let initialUpstreamBytes: [UInt8]

    private let destinationDescription: String

    init(
        flow: NEAppProxyTCPFlow,
        connection: NWConnection,
        initialUpstreamBytes: [UInt8],
        destinationDescription: String,
        onFinish: @escaping @Sendable (UUID, ConnectionErrorCategory?) -> Void
    ) {
        self.flow = flow
        self.connection = connection
        self.initialUpstreamBytes = initialUpstreamBytes
        self.destinationDescription = destinationDescription
        self.onFinish = onFinish
        self.queue = DispatchQueue(
            label: "dev.cofe.splitlane.relay.\(id.uuidString.prefix(8))",
            qos: .userInitiated
        )
    }

    /// Starts both directions.
    func start() {
        SplitLaneLog.relay.debug(
            "Relay \(self.id.uuidString.prefix(8), privacy: .public) started to \(self.destinationDescription, privacy: .public)"
        )

        // Hand over anything that arrived glued to the handshake before the first upstream read.
        if !initialUpstreamBytes.isEmpty {
            writeToFlow(Data(initialUpstreamBytes))
        } else {
            readFromUpstream()
        }
        readFromFlow()
    }

    /// Tears the relay down. Idempotent; safe from any queue.
    func cancel(_ category: ConnectionErrorCategory? = .cancelled) {
        finish(category)
    }

    // MARK: - Application → upstream

    private func readFromFlow() {
        flow.readData { [weak self] data, error in
            guard let self else { return }

            if let error {
                self.handleFlowError(error, direction: "read")
                return
            }
            // NEAppProxyTCPFlow signals EOF with nil or empty data and no error.
            guard let data, !data.isEmpty else {
                self.halfCloseUpstream()
                return
            }

            self.connection.send(content: data, completion: .contentProcessed { [weak self] sendError in
                guard let self else { return }
                if let sendError {
                    SplitLaneLog.relay.error(
                        "Relay \(self.id.uuidString.prefix(8), privacy: .public) upstream send failed: \(sendError.debugDescription, privacy: .public)"
                    )
                    self.finish(.upstreamUnreachable)
                    return
                }
                self.queue.async {
                    self.bytesSent &+= UInt64(data.count)
                }
                // Only now is the next read issued. This is the backpressure.
                self.readFromFlow()
            })
        }
    }

    /// The app finished sending. Half-close the upstream write side and keep reading replies.
    private func halfCloseUpstream() {
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                        completion: .contentProcessed { _ in })
    }

    // MARK: - Upstream → application

    private func readFromUpstream() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }

            if let error {
                SplitLaneLog.relay.error(
                    "Relay \(self.id.uuidString.prefix(8), privacy: .public) upstream receive failed: \(error.debugDescription, privacy: .public)"
                )
                self.finish(.upstreamUnreachable)
                return
            }

            if let data, !data.isEmpty {
                self.queue.async {
                    self.bytesReceived &+= UInt64(data.count)
                }
                self.writeToFlow(data, upstreamIsComplete: isComplete)
                return
            }

            if isComplete {
                // Upstream is done. Half-close the app's read side; the app may still be sending.
                self.flow.closeReadWithError(nil)
                self.finishIfBothSidesDone()
            } else {
                self.readFromUpstream()
            }
        }
    }

    private func writeToFlow(_ data: Data, upstreamIsComplete: Bool = false) {
        flow.write(data) { [weak self] error in
            guard let self else { return }
            if let error {
                self.handleFlowError(error, direction: "write")
                return
            }
            if upstreamIsComplete {
                self.flow.closeReadWithError(nil)
                self.finishIfBothSidesDone()
                return
            }
            self.readFromUpstream()
        }
    }

    // MARK: - Completion

    private func handleFlowError(_ error: Error, direction: String) {
        let nsError = error as NSError
        // A flow the app simply closed is a normal ending, not a failure. Reporting it as an error
        // would fill the Activity list with red for every completed connection.
        let isNormalClosure = nsError.domain == NEAppProxyErrorDomain
            && (nsError.code == NEAppProxyFlowError.aborted.rawValue
                || nsError.code == NEAppProxyFlowError.peerReset.rawValue)

        if isNormalClosure {
            finish(nil)
        } else {
            SplitLaneLog.relay.error(
                "Relay \(self.id.uuidString.prefix(8), privacy: .public) flow \(direction, privacy: .public) failed: \(nsError.code, privacy: .public)"
            )
            finish(.flowError)
        }
    }

    private func finishIfBothSidesDone() {
        finish(nil)
    }

    private func finish(_ category: ConnectionErrorCategory?) {
        guard finished.claim() else { return }

        connection.cancel()
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)

        let duration = Date().timeIntervalSince(startedAt)
        queue.async { [self] in
            SplitLaneLog.relay.debug(
                """
                Relay \(self.id.uuidString.prefix(8), privacy: .public) finished \
                to \(self.destinationDescription, privacy: .public) \
                sent=\(self.bytesSent, privacy: .public) received=\(self.bytesReceived, privacy: .public) \
                duration=\(String(format: "%.3f", duration), privacy: .public)s \
                error=\(category?.rawValue ?? "none", privacy: .public)
                """
            )
        }
        onFinish(id, category)
    }
}

/// A claim-once flag.
///
/// Completion can be reached from either direction concurrently — an upstream failure and a flow
/// EOF can race — and the relay must be torn down exactly once.
final class OneShotFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false

    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}
