import Testing
import Foundation
import Network
@testable import SplitLaneCore

/// End-to-end tests against a real SOCKS5 server.
///
/// These exercise ``NWConnectionTransport`` — the transport the extension actually uses — rather
/// than a mock, so they cover the parts a scripted transport cannot: real TCP, real fragmentation,
/// real server behaviour, real failure modes.
///
/// **The origin server is not reachable from the host.** `Tools/socks5-testbed` puts nginx on a
/// Docker network with no published ports, so a successful HTTP response through the proxy is
/// positive proof that the bytes went through the proxy. A test against a host-reachable server
/// would pass whether or not the SOCKS5 layer did anything.
///
/// Opt-in, so `swift test` stays hermetic:
/// ```
/// Tools/socks5-testbed/up.sh
/// SPLITLANE_SOCKS5_INTEGRATION=1 swift test
/// Tools/socks5-testbed/down.sh
/// ```
@Suite(
    "SOCKS5 integration",
    .enabled(if: ProcessInfo.processInfo.environment["SPLITLANE_SOCKS5_INTEGRATION"] == "1",
             "set SPLITLANE_SOCKS5_INTEGRATION=1 and start Tools/socks5-testbed")
)
struct SOCKS5IntegrationTests {

    private static let noAuthPort: UInt16 = 11080
    private static let authPort: UInt16 = 11081
    private static let credential = SOCKS5Credential(username: "splitlane", password: "lane-secret")

    /// Hostname of the origin, resolvable only inside the Docker network — which is exactly why
    /// it exercises ATYP=DOMAIN properly: the *proxy* has to resolve it, because the host cannot.
    private static let originHost = "origin.test"

    private func transport(port: UInt16) -> NWConnectionTransport {
        NWConnectionTransport(host: "127.0.0.1", port: port)
    }

    // MARK: - Handshake

    @Test("CONNECT succeeds through a no-auth proxy using ATYP=DOMAIN")
    func domainConnectNoAuth() async throws {
        let transport = transport(port: Self.noAuthPort)
        let info = try await SOCKS5Client.connect(
            through: transport,
            to: .domain(Self.originHost),
            port: 80,
            timeout: 10
        )

        #expect(info.method == .noAuthentication)
        await transport.close()
    }

    @Test("CONNECT succeeds through an authenticating proxy")
    func domainConnectWithAuth() async throws {
        let transport = transport(port: Self.authPort)
        let info = try await SOCKS5Client.connect(
            through: transport,
            to: .domain(Self.originHost),
            port: 80,
            credential: Self.credential,
            timeout: 10
        )

        #expect(info.method == .usernamePassword)
        await transport.close()
    }

    @Test("Wrong credentials are rejected")
    func wrongCredentialsRejected() async throws {
        let transport = transport(port: Self.authPort)

        await #expect(throws: SOCKS5Error.self) {
            _ = try await SOCKS5Client.connect(
                through: transport,
                to: .domain(Self.originHost),
                port: 80,
                credential: SOCKS5Credential(username: "splitlane", password: "wrong"),
                timeout: 10
            )
        }
    }

    @Test("A proxy requiring auth refuses an unauthenticated client")
    func authRequiredButNotOffered() async throws {
        let transport = transport(port: Self.authPort)

        // No credential means only NO AUTH is offered, and the server has nothing acceptable.
        await #expect(throws: SOCKS5Error.self) {
            _ = try await SOCKS5Client.connect(
                through: transport, to: .domain(Self.originHost), port: 80, timeout: 10
            )
        }
    }

    // MARK: - Real data transfer

    @Test("An HTTP request and response traverse the proxy end to end")
    func httpThroughProxy() async throws {
        let transport = transport(port: Self.noAuthPort)
        _ = try await SOCKS5Client.connect(
            through: transport, to: .domain(Self.originHost), port: 80, timeout: 10
        )

        let request = "GET / HTTP/1.1\r\nHost: \(Self.originHost)\r\nConnection: close\r\n\r\n"
        try await transport.send(Array(request.utf8))

        var response = [UInt8]()
        // Read until the server closes; `Connection: close` guarantees it will.
        while response.count < 64 * 1024 {
            let chunk = try await transport.receive()
            if chunk.isEmpty { break }
            response.append(contentsOf: chunk)
            if String(decoding: response, as: UTF8.self).contains("</html>") { break }
        }
        await transport.close()

        let text = String(decoding: response, as: UTF8.self)
        // The host has no route to `origin.test`. Receiving this at all proves the SOCKS5 relay
        // carried the bytes.
        #expect(text.hasPrefix("HTTP/1.1 200"), "unexpected response: \(text.prefix(120))")
        #expect(text.lowercased().contains("nginx"))
    }

    @Test("A larger response is relayed intact")
    func largerPayloadIntegrity() async throws {
        let transport = transport(port: Self.noAuthPort)
        _ = try await SOCKS5Client.connect(
            through: transport, to: .domain(Self.originHost), port: 80, timeout: 10
        )

        // nginx's 404 body plus headers spans more than one read on most runs, so this exercises
        // reassembly rather than a single lucky packet.
        let request = "GET /nonexistent HTTP/1.1\r\nHost: \(Self.originHost)\r\nConnection: close\r\n\r\n"
        try await transport.send(Array(request.utf8))

        var response = [UInt8]()
        while response.count < 64 * 1024 {
            let chunk = try await transport.receive()
            if chunk.isEmpty { break }
            response.append(contentsOf: chunk)
        }
        await transport.close()

        let text = String(decoding: response, as: UTF8.self)
        #expect(text.hasPrefix("HTTP/1.1 404"))
        // Content-Length must match the body actually delivered — a relay that dropped or
        // duplicated a chunk would show up here.
        if let range = text.range(of: "Content-Length: "),
           let lineEnd = text[range.upperBound...].firstIndex(of: "\r"),
           let declared = Int(text[range.upperBound..<lineEnd]),
           let bodyStart = text.range(of: "\r\n\r\n") {
            let body = text[bodyStart.upperBound...]
            #expect(body.utf8.count == declared, "body length \(body.utf8.count) != declared \(declared)")
        }
    }

    // MARK: - Failure paths (fail-closed behaviour, ADR 0003)

    @Test("An unreachable destination is refused by the proxy, not silently succeeded")
    func unreachableDestination() async throws {
        let transport = transport(port: Self.noAuthPort)

        await #expect(throws: SOCKS5Error.self) {
            _ = try await SOCKS5Client.connect(
                through: transport,
                to: .domain("this-host-does-not-exist.invalid"),
                port: 80,
                timeout: 10
            )
        }
    }

    @Test("A closed port on the origin is refused")
    func refusedPort() async throws {
        let transport = transport(port: Self.noAuthPort)

        await #expect(throws: SOCKS5Error.self) {
            _ = try await SOCKS5Client.connect(
                through: transport, to: .domain(Self.originHost), port: 9, timeout: 10
            )
        }
    }

    @Test("A port with nothing listening fails rather than hanging")
    func deadUpstream() async throws {
        // 11099 has no listener. This is the "user has not started their proxy yet" case, and it
        // must fail promptly and visibly — that is what fail-closed looks like to a user.
        let transport = NWConnectionTransport(host: "127.0.0.1", port: 11099)
        let started = Date()

        await #expect(throws: SOCKS5Error.self) {
            _ = try await SOCKS5Client.connect(
                through: transport, to: .domain(Self.originHost), port: 80, timeout: 5
            )
        }
        #expect(Date().timeIntervalSince(started) < 6)
    }

    @Test("Speaking SOCKS5 to something that is not a SOCKS5 server fails cleanly")
    func nonSocksUpstream() async throws {
        // Point the client at nginx itself via the proxy's published port? No — instead use the
        // auth proxy's port with a deliberately malformed expectation is not possible, so use the
        // Docker daemon-free case: an HTTP server would reply with HTTP, not a SOCKS5 handshake.
        // The nearest reachable non-SOCKS listener is the test process itself, so spin one up.
        let listener = try LocalTCPResponder(reply: Array("HTTP/1.1 400 Bad Request\r\n\r\n".utf8))
        let port = try await listener.start()
        defer { Task { await listener.stop() } }

        let transport = NWConnectionTransport(host: "127.0.0.1", port: port)
        await #expect(throws: SOCKS5Error.self) {
            _ = try await SOCKS5Client.connect(
                through: transport, to: .domain(Self.originHost), port: 80, timeout: 5
            )
        }
    }

    // MARK: - Address types

    @Test("CONNECT with an IPv4 literal works")
    func ipv4Connect() async throws {
        // Resolve the origin's container address from the proxy's perspective by asking Docker.
        guard let address = try? Self.originContainerAddress(), let literal = SOCKS5Address.literal(address) else {
            Issue.record("could not determine the origin container address; is the testbed running?")
            return
        }

        let transport = transport(port: Self.noAuthPort)
        _ = try await SOCKS5Client.connect(
            through: transport, to: literal, port: 80, timeout: 10
        )
        await transport.close()
    }

    /// Asks Docker for the origin container's address on the testbed network.
    private static func originContainerAddress() throws -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [
            "docker", "inspect", "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            "splitlane-origin",
        ]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        let output = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return output.isEmpty ? nil : output
    }
}

/// A minimal TCP listener that sends a fixed reply and closes.
///
/// Used to prove SplitLane fails cleanly when pointed at a port that is open but not speaking
/// SOCKS5 — a very common misconfiguration.
actor LocalTCPResponder {
    private let reply: [UInt8]
    private var listener: NWListener?

    init(reply: [UInt8]) throws {
        self.reply = reply
    }

    func start() async throws -> UInt16 {
        let listener = try NWListener(using: .tcp, on: .any)
        self.listener = listener

        let replyBytes = reply
        listener.newConnectionHandler = { connection in
            connection.start(queue: .global())
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, _, _ in
                connection.send(content: Data(replyBytes), completion: .contentProcessed { _ in
                    connection.cancel()
                })
            }
        }

        return try await withCheckedThrowingContinuation { continuation in
            let resumed = OneShot()
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue, resumed.claim() {
                        continuation.resume(returning: port)
                    }
                case .failed(let error):
                    if resumed.claim() {
                        continuation.resume(throwing: SOCKS5Error.transportFailure(error.debugDescription))
                    }
                default:
                    break
                }
            }
            listener.start(queue: .global())
        }
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }
}

private final class OneShot: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}
