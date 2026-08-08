import Foundation

/// A bidirectional byte stream the SOCKS5 handshake can run over.
///
/// The abstraction exists so ``SOCKS5Client`` can be driven by a scripted in-memory transport in
/// unit tests and by a real `NWConnection` in the extension, with the same code path in both. It
/// deliberately says nothing about sockets, endpoints or queues — everything the handshake needs
/// is "give me bytes" and "take these bytes".
public protocol SOCKS5Transport: Sendable {
    /// Establishes the underlying connection. Called once, before any send or receive.
    func connect() async throws

    func send(_ bytes: [UInt8]) async throws

    /// Reads whatever is available. An empty array means the peer closed cleanly (EOF).
    func receive() async throws -> [UInt8]

    /// Tears down the connection. Idempotent.
    func close() async
}

/// Runs the SOCKS5 handshake over a transport.
///
/// The client owns timing, cancellation and I/O ordering; ``SOCKS5Negotiator`` owns the protocol.
/// Keeping those apart is what allows the protocol to be tested without a clock or a socket.
public enum SOCKS5Client {

    /// Connects the transport and completes a SOCKS5 CONNECT to `destination:port`.
    ///
    /// On any failure the transport is closed and the error is thrown. There is no fallback path:
    /// a selected application whose proxy handshake fails must see a failed connection, not a
    /// direct one (ADR 0003).
    ///
    /// - Returns: the bound address plus any bytes the server coalesced after its reply.
    public static func connect(
        through transport: SOCKS5Transport,
        to destination: SOCKS5Address,
        port: UInt16,
        credential: SOCKS5Credential? = nil,
        timeout: TimeInterval = 10
    ) async throws -> SOCKS5ConnectionInfo {
        do {
            return try await withTimeout(timeout) {
                try await performHandshake(
                    transport: transport,
                    destination: destination,
                    port: port,
                    credential: credential
                )
            }
        } catch {
            await transport.close()
            throw error
        }
    }

    private static func performHandshake(
        transport: SOCKS5Transport,
        destination: SOCKS5Address,
        port: UInt16,
        credential: SOCKS5Credential?
    ) async throws -> SOCKS5ConnectionInfo {
        try await transport.connect()

        var negotiator = SOCKS5Negotiator(
            destination: destination,
            port: port,
            credential: credential
        )

        var step = try negotiator.start()

        while true {
            try Task.checkCancellation()

            switch step {
            case .established(let info):
                return info

            case .send(let bytes):
                try await transport.send(bytes)
                let received = try await transport.receive()
                guard !received.isEmpty else {
                    // EOF mid-handshake. Overwhelmingly this is a server that accepted the TCP
                    // connection and then hung up — a wrong port, or something on the port that
                    // is not a SOCKS5 server at all.
                    throw SOCKS5Error.incompleteResponse
                }
                step = try negotiator.receive(received)

            case .needMoreBytes:
                let received = try await transport.receive()
                guard !received.isEmpty else { throw SOCKS5Error.incompleteResponse }
                step = try negotiator.receive(received)
            }
        }
    }

    /// Races an operation against a deadline.
    ///
    /// Written with an explicit task group rather than a helper so the losing child is always
    /// cancelled: leaving a pending `receive()` alive after a timeout would hold the transport
    /// open and, in the provider, leak one connection per timed-out flow.
    static func withTimeout<T: Sendable>(
        _ seconds: TimeInterval,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        guard seconds > 0 else { return try await operation() }

        return try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                throw SOCKS5Error.timedOut
            }
            defer { group.cancelAll() }
            guard let result = try await group.next() else {
                throw SOCKS5Error.cancelled
            }
            return result
        }
    }
}
