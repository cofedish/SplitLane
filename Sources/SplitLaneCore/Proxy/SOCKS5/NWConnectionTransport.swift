import Foundation
import Network

/// A ``SOCKS5Transport`` backed by `Network.framework`.
///
/// This lives in SplitLaneCore rather than the extension on purpose. `Network` is not
/// `NetworkExtension`: it needs no entitlement and no system extension, so the integration tests
/// can exercise the *real* transport against a real SOCKS5 server in Docker. If this type lived
/// in the extension target, the only thing ever tested would be a mock.
///
/// One `NWConnection` per instance, single-use. The bridging from callbacks to `async` uses
/// continuations that are each resumed exactly once, guarded by an actor.
public actor NWConnectionTransport: SOCKS5Transport {

    private let endpoint: NWEndpoint
    private let parameters: NWParameters
    private var connection: NWConnection?
    private var isClosed = false

    /// Bytes received while nothing was awaiting them.
    ///
    /// `NWConnection.receive` delivers what it has, which can be more than the handshake step is
    /// ready for; the surplus is held here and returned by the next `receive()`.
    private var pendingBytes: [UInt8] = []

    public init(host: String, port: UInt16, parameters: NWParameters = .tcp) {
        self.endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .any
        )
        self.parameters = parameters
    }

    public func connect() async throws {
        guard connection == nil else {
            throw SOCKS5Error.protocolViolation("connect() called twice")
        }
        let connection = NWConnection(to: endpoint, using: parameters)
        self.connection = connection

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                // `stateUpdateHandler` fires repeatedly; the flag makes resumption exactly-once.
                let resumed = ResumeGuard()
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        if resumed.claim() { continuation.resume() }
                    case .failed(let error):
                        if resumed.claim() {
                            continuation.resume(throwing: SOCKS5Error.transportFailure(error.debugDescription))
                        }
                    case .cancelled:
                        if resumed.claim() { continuation.resume(throwing: SOCKS5Error.cancelled) }
                    case .waiting(let error):
                        // `.waiting` means the path is unavailable — for a loopback SOCKS5 server
                        // that is "nothing is listening". Treated as failure rather than waited
                        // out, because the handshake timeout should not be spent on a port that
                        // is already known to be refusing.
                        if resumed.claim() {
                            continuation.resume(throwing: SOCKS5Error.transportFailure(error.debugDescription))
                        }
                    case .setup, .preparing:
                        break
                    @unknown default:
                        break
                    }
                }
                connection.start(queue: Self.queue)
            }
        } onCancel: {
            connection.forceCancel()
        }
    }

    public func send(_ bytes: [UInt8]) async throws {
        guard let connection, !isClosed else {
            throw SOCKS5Error.transportFailure("send on a closed connection")
        }
        guard !bytes.isEmpty else { return }

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: Data(bytes), completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: SOCKS5Error.transportFailure(error.debugDescription))
                } else {
                    continuation.resume()
                }
            })
        }
    }

    public func receive() async throws -> [UInt8] {
        if !pendingBytes.isEmpty {
            defer { pendingBytes = [] }
            return pendingBytes
        }
        guard let connection, !isClosed else {
            throw SOCKS5Error.transportFailure("receive on a closed connection")
        }

        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<[UInt8], Error>) in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: SOCKS5Error.transportFailure(error.debugDescription))
                    return
                }
                if let data, !data.isEmpty {
                    continuation.resume(returning: [UInt8](data))
                    return
                }
                // Empty read: EOF if the peer is done, otherwise a spurious wake-up that the
                // caller treats as EOF as well. Both are represented as an empty array, which the
                // handshake reads as a truncated response.
                continuation.resume(returning: isComplete ? [] : [])
            }
        }
    }

    public func close() async {
        guard !isClosed else { return }
        isClosed = true
        connection?.stateUpdateHandler = nil
        connection?.cancel()
        connection = nil
    }

    /// Hands the live connection to the relay after a successful handshake, so the tunnel is not
    /// torn down when this transport goes out of scope.
    ///
    /// Ownership transfers to the caller: this transport will not cancel the connection
    /// afterwards.
    public func takeConnection() -> NWConnection? {
        defer {
            connection = nil
            isClosed = true
        }
        return connection
    }

    /// Bytes that arrived but were not consumed by the handshake.
    public func takePendingBytes() -> [UInt8] {
        defer { pendingBytes = [] }
        return pendingBytes
    }

    private static let queue = DispatchQueue(label: "dev.cofe.splitlane.socks5.transport", qos: .userInitiated)
}

/// One-shot claim flag.
///
/// `NWConnection.stateUpdateHandler` can report `.ready` and later `.cancelled` for the same
/// connection; resuming a continuation twice is undefined behaviour, so the first caller wins.
private final class ResumeGuard: @unchecked Sendable {
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
