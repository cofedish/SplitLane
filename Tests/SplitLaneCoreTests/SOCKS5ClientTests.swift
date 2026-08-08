import Testing
import Foundation
@testable import SplitLaneCore

/// A transport driven by a script of canned server responses.
///
/// Lets the client's I/O ordering, timeout and cancellation behaviour be tested deterministically,
/// with no socket and no clock dependency beyond the timeout under test.
actor ScriptedTransport: SOCKS5Transport {

    enum Event: Sendable {
        /// Deliver these bytes to the next receive.
        case reply([UInt8])
        /// Deliver EOF (an empty read).
        case eof
        /// Fail the next receive.
        case failure(SOCKS5Error)
        /// Never complete — used to exercise the timeout.
        case hang
    }

    private var script: [Event]
    private(set) var sentBytes: [[UInt8]] = []
    private(set) var isConnected = false
    private(set) var closeCount = 0
    private let failOnConnect: SOCKS5Error?

    init(script: [Event], failOnConnect: SOCKS5Error? = nil) {
        self.script = script
        self.failOnConnect = failOnConnect
    }

    func connect() async throws {
        if let failOnConnect { throw failOnConnect }
        isConnected = true
    }

    func send(_ bytes: [UInt8]) async throws {
        sentBytes.append(bytes)
    }

    func receive() async throws -> [UInt8] {
        guard !script.isEmpty else { return [] }
        switch script.removeFirst() {
        case .reply(let bytes):
            return bytes
        case .eof:
            return []
        case .failure(let error):
            throw error
        case .hang:
            // Sleep far beyond any test timeout; cancellation propagates through Task.sleep.
            try await Task.sleep(nanoseconds: 60_000_000_000)
            return []
        }
    }

    func close() async {
        closeCount += 1
        isConnected = false
    }
}

@Suite("SOCKS5 client")
struct SOCKS5ClientTests {

    private let successReply: [UInt8] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]

    @Test("A no-auth handshake completes and sends the right bytes in the right order")
    func noAuthHandshake() async throws {
        let transport = ScriptedTransport(script: [
            .reply([0x05, 0x00]),
            .reply(successReply),
        ])

        let info = try await SOCKS5Client.connect(
            through: transport,
            to: .domain("example.com"),
            port: 443
        )

        #expect(info.method == .noAuthentication)

        let sent = await transport.sentBytes
        #expect(sent.count == 2)
        let expectedGreeting: [UInt8] = [0x05, 0x01, 0x00]
        var expectedConnect: [UInt8] = [0x05, 0x01, 0x00, 0x03, 11]
        expectedConnect += Array("example.com".utf8)
        expectedConnect += [0x01, 0xBB]

        #expect(sent[0] == expectedGreeting)
        #expect(sent[1] == expectedConnect)
    }

    @Test("An authenticated handshake sends greeting, credentials, then CONNECT")
    func authenticatedHandshake() async throws {
        let transport = ScriptedTransport(script: [
            .reply([0x05, 0x02]),
            .reply([0x01, 0x00]),
            .reply(successReply),
        ])

        let info = try await SOCKS5Client.connect(
            through: transport,
            to: .ipv4([1, 2, 3, 4]),
            port: 80,
            credential: SOCKS5Credential(username: "alice", password: "secret")
        )

        #expect(info.method == .usernamePassword)
        let sent = await transport.sentBytes
        #expect(sent.count == 3)
        let expectedGreeting: [UInt8] = [0x05, 0x02, 0x00, 0x02]
        var expectedAuth: [UInt8] = [0x01, 5]
        expectedAuth += Array("alice".utf8)
        expectedAuth += [6]
        expectedAuth += Array("secret".utf8)

        #expect(sent[0] == expectedGreeting)
        #expect(sent[1] == expectedAuth)
    }

    @Test("A handshake arriving in fragments completes")
    func fragmentedHandshake() async throws {
        let transport = ScriptedTransport(script: [
            .reply([0x05]),
            .reply([0x00]),
            .reply(Array(successReply.prefix(4))),
            .reply(Array(successReply.suffix(from: 4))),
        ])

        let info = try await SOCKS5Client.connect(
            through: transport, to: .domain("example.com"), port: 443
        )
        #expect(info.boundPort == 0)
    }

    @Test("A failed connect closes the transport and does not fall back")
    func connectFailureClosesTransport() async throws {
        let transport = ScriptedTransport(
            script: [],
            failOnConnect: .transportFailure("connection refused")
        )

        await #expect(throws: SOCKS5Error.self) {
            _ = try await SOCKS5Client.connect(
                through: transport, to: .domain("example.com"), port: 443
            )
        }
        // ADR 0003: the caller gets an error. There is no code path here that returns success
        // with a direct connection.
        let closeCount = await transport.closeCount
        #expect(closeCount == 1)
    }

    @Test("EOF mid-handshake is reported as a truncated response")
    func eofMidHandshake() async throws {
        // Almost always a wrong port: something accepted the TCP connection and hung up.
        let transport = ScriptedTransport(script: [.eof])

        await #expect(throws: SOCKS5Error.incompleteResponse) {
            _ = try await SOCKS5Client.connect(
                through: transport, to: .domain("example.com"), port: 443
            )
        }
        let closeCount = await transport.closeCount
        #expect(closeCount == 1)
    }

    @Test("EOF after the greeting is reported")
    func eofAfterGreeting() async throws {
        let transport = ScriptedTransport(script: [.reply([0x05, 0x00]), .eof])

        await #expect(throws: SOCKS5Error.incompleteResponse) {
            _ = try await SOCKS5Client.connect(
                through: transport, to: .domain("example.com"), port: 443
            )
        }
    }

    @Test("A rejected connection propagates the reply code and closes the transport")
    func rejectedConnection() async throws {
        let transport = ScriptedTransport(script: [
            .reply([0x05, 0x00]),
            .reply([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),   // connection refused
        ])

        await #expect(throws: SOCKS5Error.requestRejected(.connectionRefused)) {
            _ = try await SOCKS5Client.connect(
                through: transport, to: .domain("example.com"), port: 443
            )
        }
        let closeCount = await transport.closeCount
        #expect(closeCount == 1)
    }

    @Test("Authentication failure propagates and closes the transport")
    func authenticationFailure() async throws {
        let transport = ScriptedTransport(script: [
            .reply([0x05, 0x02]),
            .reply([0x01, 0x01]),
        ])

        await #expect(throws: SOCKS5Error.authenticationFailed) {
            _ = try await SOCKS5Client.connect(
                through: transport,
                to: .domain("example.com"),
                port: 443,
                credential: SOCKS5Credential(username: "u", password: "wrong")
            )
        }
        let closeCount = await transport.closeCount
        #expect(closeCount == 1)
    }

    @Test("A hung server hits the timeout and the transport is closed")
    func timeout() async throws {
        let transport = ScriptedTransport(script: [.hang])
        let started = Date()

        await #expect(throws: SOCKS5Error.timedOut) {
            _ = try await SOCKS5Client.connect(
                through: transport,
                to: .domain("example.com"),
                port: 443,
                timeout: 0.2
            )
        }

        let elapsed = Date().timeIntervalSince(started)
        #expect(elapsed < 5, "the timeout should fire promptly, took \(elapsed)s")
        // A leaked pending receive would hold one connection open per timed-out flow.
        let closeCount = await transport.closeCount
        #expect(closeCount == 1)
    }

    @Test("A transport error propagates and closes the transport")
    func transportError() async throws {
        let transport = ScriptedTransport(script: [.failure(.transportFailure("reset by peer"))])

        await #expect(throws: SOCKS5Error.self) {
            _ = try await SOCKS5Client.connect(
                through: transport, to: .domain("example.com"), port: 443
            )
        }
        let closeCount = await transport.closeCount
        #expect(closeCount == 1)
    }

    @Test("Cancellation closes the transport")
    func cancellation() async throws {
        let transport = ScriptedTransport(script: [.hang])

        let task = Task {
            try await SOCKS5Client.connect(
                through: transport,
                to: .domain("example.com"),
                port: 443,
                timeout: 30
            )
        }
        // Let the handshake reach the hanging receive before cancelling.
        try await Task.sleep(nanoseconds: 50_000_000)
        task.cancel()

        await #expect(throws: (any Error).self) { _ = try await task.value }
        let closeCount = await transport.closeCount
        #expect(closeCount == 1)
    }

    @Test("Bytes coalesced after the reply survive the client layer")
    func leftoverBytesSurvive() async throws {
        let payload = Array("early data".utf8)
        let transport = ScriptedTransport(script: [
            .reply([0x05, 0x00]),
            .reply(successReply + payload),
        ])

        let info = try await SOCKS5Client.connect(
            through: transport, to: .domain("example.com"), port: 443
        )
        #expect(info.leftoverBytes == payload)
    }

    @Test("Every SOCKS5 error maps to a user-facing category")
    func errorCategoryMapping() {
        let cases: [(SOCKS5Error, ConnectionErrorCategory)] = [
            (.transportFailure("x"), .upstreamUnreachable),
            (.incompleteResponse, .upstreamUnreachable),
            (.authenticationFailed, .authenticationFailed),
            (.noAcceptableAuthenticationMethod, .authenticationUnsupported),
            (.authenticationRequired, .authenticationUnsupported),
            (.requestRejected(.connectionRefused), .rejectedByProxy),
            (.unknownReplyCode(0x42), .rejectedByProxy),
            (.timedOut, .timedOut),
            (.cancelled, .cancelled),
            (.malformedResponse("x"), .internalError),
        ]
        for (error, expected) in cases {
            #expect(ConnectionErrorCategory(error) == expected, "\(error) should map to \(expected)")
        }
    }

    @Test("Error descriptions never echo credential values")
    func errorDescriptionsAreSafe() async throws {
        // Error text reaches the UI and the log. What matters is that no credential *value*
        // appears — not that the word "password" is absent, since "Username or password exceeds
        // 255 bytes" is a perfectly good message that discloses nothing.
        let username = "alice-uniq-username"
        let password = "sup3rs3cret-uniq-value"
        let credential = SOCKS5Credential(username: username, password: password)

        // Drive real failures through the client so the errors are the ones users actually see.
        var produced: [SOCKS5Error] = [
            .credentialTooLong, .authenticationRequired, .noAcceptableAuthenticationMethod,
        ]

        let rejecting = ScriptedTransport(script: [.reply([0x05, 0x02]), .reply([0x01, 0x01])])
        do {
            _ = try await SOCKS5Client.connect(
                through: rejecting, to: .domain("example.com"), port: 443, credential: credential
            )
            Issue.record("expected authentication to fail")
        } catch let error as SOCKS5Error {
            produced.append(error)
        }

        let overlong = SOCKS5Credential(
            username: String(repeating: "u", count: 300),
            password: password
        )
        var negotiator = SOCKS5Negotiator(
            destination: .domain("example.com"), port: 443, credential: overlong
        )
        do {
            _ = try negotiator.start()
            Issue.record("expected an over-long credential to be rejected")
        } catch let error as SOCKS5Error {
            produced.append(error)
        }

        for error in produced {
            let text = error.localizedDescription
            #expect(!text.contains(password), "\(error.logCategory) leaked the password")
            #expect(!text.contains(username), "\(error.logCategory) leaked the username")
            // The stable log token must be free of both as well.
            #expect(!error.logCategory.contains(password))
        }
    }
}
