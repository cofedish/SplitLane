import Testing
import Foundation
@testable import SplitLaneCore

@Suite("SOCKS5 negotiator")
struct SOCKS5NegotiatorTests {

    // MARK: - Helpers

    /// Server method-selection reply.
    private func methodSelection(_ method: UInt8, version: UInt8 = 0x05) -> [UInt8] {
        [version, method]
    }

    /// Server CONNECT reply with an IPv4 bound address.
    private func connectReply(
        _ code: UInt8 = 0x00,
        version: UInt8 = 0x05,
        reserved: UInt8 = 0x00,
        address: [UInt8] = [0x01, 0, 0, 0, 0],
        port: [UInt8] = [0x00, 0x00]
    ) -> [UInt8] {
        [version, code, reserved] + address + port
    }

    private func step(_ negotiator: inout SOCKS5Negotiator, _ bytes: [UInt8]) throws -> SOCKS5Step {
        try negotiator.receive(bytes)
    }

    // MARK: - Greeting

    @Test("Greeting offers only NO AUTH when there is no credential")
    func greetingWithoutCredential() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        #expect(try negotiator.start() == .send([0x05, 0x01, 0x00]))
    }

    @Test("Greeting offers NO AUTH and username/password when a credential exists")
    func greetingWithCredential() throws {
        var negotiator = SOCKS5Negotiator(
            destination: .domain("example.com"),
            port: 443,
            credential: SOCKS5Credential(username: "u", password: "p")
        )
        #expect(try negotiator.start() == .send([0x05, 0x02, 0x00, 0x02]))
    }

    @Test("start() twice is a protocol violation")
    func doubleStart() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        #expect(throws: SOCKS5Error.self) { _ = try negotiator.start() }
    }

    @Test("receive() before start() is a protocol violation")
    func receiveBeforeStart() {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        #expect(throws: SOCKS5Error.self) { _ = try negotiator.receive([0x05, 0x00]) }
    }

    // MARK: - CONNECT request encoding

    @Test("CONNECT with a domain destination is encoded per RFC 1928")
    func connectRequestDomain() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()

        guard case .send(let request) = try step(&negotiator, methodSelection(0x00)) else {
            Issue.record("expected a CONNECT request")
            return
        }
        let expected: [UInt8] =
            [0x05, 0x01, 0x00, 0x03, 11] + Array("example.com".utf8) + [0x01, 0xBB]
        #expect(request == expected)
    }

    @Test("CONNECT with an IPv4 destination is encoded per RFC 1928")
    func connectRequestIPv4() throws {
        var negotiator = SOCKS5Negotiator(destination: .ipv4([93, 184, 216, 34]), port: 80)
        _ = try negotiator.start()

        guard case .send(let request) = try step(&negotiator, methodSelection(0x00)) else {
            Issue.record("expected a CONNECT request")
            return
        }
        #expect(request == [0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50])
    }

    @Test("CONNECT with an IPv6 destination is encoded per RFC 1928")
    func connectRequestIPv6() throws {
        let address = [UInt8](repeating: 0, count: 15) + [1]   // ::1
        var negotiator = SOCKS5Negotiator(destination: .ipv6(address), port: 8080)
        _ = try negotiator.start()

        guard case .send(let request) = try step(&negotiator, methodSelection(0x00)) else {
            Issue.record("expected a CONNECT request")
            return
        }
        #expect(request == [0x05, 0x01, 0x00, 0x04] + address + [0x1F, 0x90])
    }

    @Test("Ports are encoded big-endian", arguments: [
        (UInt16(443), [UInt8]([0x01, 0xBB])),
        (UInt16(80), [UInt8]([0x00, 0x50])),
        (UInt16(65535), [UInt8]([0xFF, 0xFF])),
        (UInt16(1), [UInt8]([0x00, 0x01])),
    ])
    func portEncoding(port: UInt16, expected: [UInt8]) throws {
        var negotiator = SOCKS5Negotiator(destination: .ipv4([1, 2, 3, 4]), port: port)
        _ = try negotiator.start()

        guard case .send(let request) = try step(&negotiator, methodSelection(0x00)) else {
            Issue.record("expected a CONNECT request")
            return
        }
        #expect(Array(request.suffix(2)) == expected)
    }

    // MARK: - Authentication

    @Test("Username/password sub-negotiation follows RFC 1929")
    func authenticationEncoding() throws {
        var negotiator = SOCKS5Negotiator(
            destination: .domain("example.com"),
            port: 443,
            credential: SOCKS5Credential(username: "alice", password: "s3cret")
        )
        _ = try negotiator.start()

        guard case .send(let auth) = try step(&negotiator, methodSelection(0x02)) else {
            Issue.record("expected an authentication message")
            return
        }
        // Version byte is 0x01 — RFC 1929 versions itself independently of SOCKS5's 0x05.
        let expected: [UInt8] =
            [0x01, 5] + Array("alice".utf8) + [6] + Array("s3cret".utf8)
        #expect(auth == expected)
    }

    @Test("A successful auth reply is followed by the CONNECT request")
    func authenticationSuccess() throws {
        var negotiator = SOCKS5Negotiator(
            destination: .domain("example.com"),
            port: 443,
            credential: SOCKS5Credential(username: "u", password: "p")
        )
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x02))

        guard case .send(let request) = try step(&negotiator, [0x01, 0x00]) else {
            Issue.record("expected a CONNECT request")
            return
        }
        #expect(request.starts(with: [0x05, 0x01, 0x00, 0x03]))
    }

    @Test("A rejected credential fails the handshake")
    func authenticationFailure() throws {
        var negotiator = SOCKS5Negotiator(
            destination: .domain("example.com"),
            port: 443,
            credential: SOCKS5Credential(username: "u", password: "wrong")
        )
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x02))

        #expect(throws: SOCKS5Error.authenticationFailed) {
            _ = try negotiator.receive([0x01, 0x01])
        }
        #expect(negotiator.state == .failed)
    }

    @Test("An auth reply echoing version 0x05 is tolerated")
    func authenticationVersionTolerance() throws {
        // Some servers mistakenly echo the SOCKS version here. The status byte carries the
        // decision, so rejecting the reply outright would break interoperability for no gain.
        var negotiator = SOCKS5Negotiator(
            destination: .domain("example.com"),
            port: 443,
            credential: SOCKS5Credential(username: "u", password: "p")
        )
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x02))

        guard case .send = try step(&negotiator, [0x05, 0x00]) else {
            Issue.record("expected a CONNECT request")
            return
        }
    }

    @Test("Selecting username/password without a credential fails")
    func authenticationRequiredButAbsent() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()

        #expect(throws: SOCKS5Error.authenticationRequired) {
            _ = try negotiator.receive(methodSelection(0x02))
        }
    }

    @Test("An over-long credential is rejected before anything is sent")
    func credentialTooLong() {
        var negotiator = SOCKS5Negotiator(
            destination: .domain("example.com"),
            port: 443,
            credential: SOCKS5Credential(
                username: String(repeating: "u", count: 256),
                password: "p"
            )
        )
        #expect(throws: SOCKS5Error.credentialTooLong) { _ = try negotiator.start() }
    }

    @Test("An empty username is rejected — RFC 1929 requires at least one byte")
    func emptyUsernameRejected() {
        var negotiator = SOCKS5Negotiator(
            destination: .domain("example.com"),
            port: 443,
            credential: SOCKS5Credential(username: "", password: "p")
        )
        #expect(throws: SOCKS5Error.credentialTooLong) { _ = try negotiator.start() }
    }

    // MARK: - Method selection failures

    @Test("A server accepting no methods fails the handshake")
    func noAcceptableMethods() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()

        #expect(throws: SOCKS5Error.noAcceptableAuthenticationMethod) {
            _ = try negotiator.receive(methodSelection(0xFF))
        }
        #expect(negotiator.state == .failed)
    }

    @Test("A wrong version byte fails the handshake")
    func wrongVersion() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()

        #expect(throws: SOCKS5Error.unexpectedVersion(0x04)) {
            _ = try negotiator.receive(methodSelection(0x00, version: 0x04))
        }
    }

    @Test("An unknown method byte fails the handshake")
    func unknownMethod() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()

        #expect(throws: SOCKS5Error.unsupportedAuthenticationMethod(0x7F)) {
            _ = try negotiator.receive(methodSelection(0x7F))
        }
    }

    @Test("GSSAPI is refused — it is never offered")
    func gssapiRefused() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()

        #expect(throws: SOCKS5Error.unsupportedAuthenticationMethod(0x01)) {
            _ = try negotiator.receive(methodSelection(0x01))
        }
    }

    // MARK: - CONNECT reply

    @Test("A successful reply establishes the tunnel")
    func connectSuccess() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x00))

        guard case .established(let info) = try step(&negotiator, connectReply()) else {
            Issue.record("expected the handshake to complete")
            return
        }
        #expect(info.method == .noAuthentication)
        #expect(info.boundAddress == .ipv4([0, 0, 0, 0]))
        #expect(info.boundPort == 0)
        #expect(info.leftoverBytes.isEmpty)
        #expect(negotiator.state == .established)
    }

    @Test("Every rejection code surfaces as requestRejected", arguments: [
        (UInt8(0x01), SOCKS5.ReplyCode.generalFailure),
        (UInt8(0x02), .connectionNotAllowed),
        (UInt8(0x03), .networkUnreachable),
        (UInt8(0x04), .hostUnreachable),
        (UInt8(0x05), .connectionRefused),
        (UInt8(0x06), .ttlExpired),
        (UInt8(0x07), .commandNotSupported),
        (UInt8(0x08), .addressTypeNotSupported),
    ])
    func connectRejections(raw: UInt8, expected: SOCKS5.ReplyCode) throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x00))

        #expect(throws: SOCKS5Error.requestRejected(expected)) {
            _ = try negotiator.receive(connectReply(raw))
        }
        #expect(negotiator.state == .failed)
    }

    @Test("An out-of-range reply code is reported rather than guessed at")
    func unknownReplyCode() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x00))

        #expect(throws: SOCKS5Error.unknownReplyCode(0x42)) {
            _ = try negotiator.receive(connectReply(0x42))
        }
    }

    @Test("A non-zero reserved byte is a malformed reply")
    func nonZeroReservedByte() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x00))

        #expect(throws: SOCKS5Error.self) {
            _ = try negotiator.receive(connectReply(0x00, reserved: 0x01))
        }
    }

    @Test("A reply with a domain bound address parses")
    func replyWithDomainAddress() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x00))

        let address: [UInt8] = [0x03, 5] + Array("proxy".utf8)
        guard case .established(let info) = try step(
            &negotiator, connectReply(0x00, address: address, port: [0x1F, 0x90])
        ) else {
            Issue.record("expected the handshake to complete")
            return
        }
        #expect(info.boundAddress == .domain("proxy"))
        #expect(info.boundPort == 8080)
    }

    @Test("An unknown address type in a reply is reported")
    func unknownAddressType() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x00))

        #expect(throws: SOCKS5Error.unsupportedAddressType(0x09)) {
            _ = try negotiator.receive([0x05, 0x00, 0x00, 0x09, 0, 0])
        }
    }

    // MARK: - Streaming and truncation (F-7)

    @Test("A handshake split one byte at a time still completes")
    func byteAtATimeDelivery() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()

        // TCP is a stream: a two-byte reply can genuinely arrive as two reads.
        #expect(try negotiator.receive([0x05]) == .needMoreBytes)
        guard case .send = try negotiator.receive([0x00]) else {
            Issue.record("expected a CONNECT request once the reply completed")
            return
        }

        let reply = connectReply()
        for byte in reply.dropLast() {
            #expect(try negotiator.receive([byte]) == .needMoreBytes)
        }
        guard case .established = try negotiator.receive([reply[reply.count - 1]]) else {
            Issue.record("expected the handshake to complete on the final byte")
            return
        }
    }

    @Test("Truncation at every offset yields needMoreBytes, never a crash")
    func truncationAtEveryOffset() throws {
        let reply = connectReply(0x00, address: [0x03, 11] + Array("example.com".utf8))

        // The whole point of ByteReader: a hostile or broken proxy can truncate anywhere, and
        // every prefix must be a clean "wait", not a trap. A trap here kills the provider, which
        // fails every selected app open.
        for prefixLength in 0..<reply.count {
            var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
            _ = try negotiator.start()
            _ = try negotiator.receive(methodSelection(0x00))

            let step = try negotiator.receive(Array(reply.prefix(prefixLength)))
            #expect(step == .needMoreBytes, "prefix of \(prefixLength) bytes should need more")
        }
    }

    @Test("An oversized domain length in a reply cannot over-read")
    func oversizedDomainLength() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x00))

        // Claims 255 bytes of domain, supplies 3. Must wait, not read past the buffer.
        let malicious: [UInt8] = [0x05, 0x00, 0x00, 0x03, 255, 0x41, 0x41, 0x41]
        #expect(try negotiator.receive(malicious) == .needMoreBytes)
    }

    @Test("A zero-length domain in a reply is handled")
    func zeroLengthDomain() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x00))

        guard case .established(let info) = try negotiator.receive(
            [0x05, 0x00, 0x00, 0x03, 0x00, 0x00, 0x50]
        ) else {
            Issue.record("expected the handshake to complete")
            return
        }
        #expect(info.boundAddress == .domain(""))
    }

    @Test("Invalid UTF-8 in a domain reply is a malformed response, not a crash")
    func invalidUTF8Domain() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x00))

        #expect(throws: SOCKS5Error.self) {
            _ = try negotiator.receive([0x05, 0x00, 0x00, 0x03, 0x02, 0xFF, 0xFE, 0x00, 0x50])
        }
    }

    @Test("Bytes coalesced after the reply are returned, not dropped")
    func leftoverBytesArePreserved() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x00))

        // A server may pack its reply and the first application bytes into one segment. Dropping
        // the tail would look like a rare, unreproducible truncation of the first response.
        let payload: [UInt8] = Array("HTTP/1.1 200 OK".utf8)
        guard case .established(let info) = try negotiator.receive(connectReply() + payload) else {
            Issue.record("expected the handshake to complete")
            return
        }
        #expect(info.leftoverBytes == payload)
    }

    @Test("An entire handshake delivered in one buffer works")
    func fullyCoalescedHandshake() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()

        // The method selection and CONNECT reply cannot legitimately be coalesced, since the
        // client must send the request in between — but a buffered method selection followed
        // immediately by a reply exercises the buffer-retention path.
        guard case .send = try negotiator.receive(methodSelection(0x00)) else {
            Issue.record("expected a CONNECT request")
            return
        }
        guard case .established = try negotiator.receive(connectReply()) else {
            Issue.record("expected the handshake to complete")
            return
        }
    }

    @Test("receive() after the handshake completed is a protocol violation")
    func receiveAfterEstablished() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        _ = try step(&negotiator, methodSelection(0x00))
        _ = try step(&negotiator, connectReply())

        #expect(throws: SOCKS5Error.self) { _ = try negotiator.receive([0x00]) }
    }

    @Test("receive() after a failure is a protocol violation")
    func receiveAfterFailure() throws {
        var negotiator = SOCKS5Negotiator(destination: .domain("example.com"), port: 443)
        _ = try negotiator.start()
        _ = try? negotiator.receive(methodSelection(0xFF))

        #expect(negotiator.state == .failed)
        #expect(throws: SOCKS5Error.self) { _ = try negotiator.receive([0x05, 0x00]) }
    }
}
