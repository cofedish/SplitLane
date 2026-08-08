import Foundation

/// SOCKS5 username/password credential (RFC 1929).
///
/// Redacts itself in every textual form. A credential must never reach a log, and the cheapest
/// way to guarantee that is to make the accidental `"\(credential)"` harmless.
public struct SOCKS5Credential: Sendable, Hashable, CustomStringConvertible, CustomDebugStringConvertible {
    public let username: String
    public let password: String

    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }

    /// RFC 1929 length-prefixes both fields with a single byte.
    public var isEncodable: Bool {
        let u = username.utf8.count, p = password.utf8.count
        return u >= 1 && u <= 255 && p <= 255
    }

    public var description: String { "SOCKS5Credential(username: \(username), password: <redacted>)" }
    public var debugDescription: String { description }
}

/// What the caller should do next.
public enum SOCKS5Step: Sendable, Equatable {
    /// Write these bytes to the upstream, then feed any reply back via ``SOCKS5Negotiator/receive(_:)``.
    case send([UInt8])
    /// The current message is incomplete; wait for more bytes.
    case needMoreBytes
    /// The tunnel is open. Any bytes left in the buffer belong to the relayed stream.
    case established(SOCKS5ConnectionInfo)
}

/// Result of a successful CONNECT.
public struct SOCKS5ConnectionInfo: Sendable, Hashable {
    /// The address the proxy bound on our behalf. Informational; most servers return 0.0.0.0:0.
    public let boundAddress: SOCKS5Address
    public let boundPort: UInt16
    /// Which authentication method the server chose.
    public let method: SOCKS5.Method
    /// Bytes that arrived after the CONNECT reply.
    ///
    /// A server may coalesce its reply with the first bytes of the relayed stream into one TCP
    /// segment. Dropping them looks like a rare, unreproducible truncation of the first response,
    /// so they are handed back and prepended to the relay.
    public let leftoverBytes: [UInt8]
}

/// The SOCKS5 handshake as a pure state machine.
///
/// No sockets, no queues, no async: bytes in, actions out. That is what makes the protocol
/// exhaustively testable — every truncation offset, every malformed field, every rejection code —
/// with `swift test` and no network at all. ``SOCKS5Client`` supplies the I/O.
///
/// The negotiator owns an accumulation buffer because TCP is a stream: a two-byte method
/// selection can arrive as two separate one-byte reads, and a CONNECT reply can arrive glued to
/// application data.
public struct SOCKS5Negotiator: Sendable {

    public enum State: Sendable, Equatable {
        case initial
        case awaitingMethodSelection
        case awaitingAuthenticationReply
        case awaitingConnectReply
        case established
        case failed
    }

    public private(set) var state: State = .initial

    private let destination: SOCKS5Address
    private let port: UInt16
    private let credential: SOCKS5Credential?
    private var buffer: [UInt8] = []
    private var selectedMethod: SOCKS5.Method = .noAuthentication

    public init(destination: SOCKS5Address, port: UInt16, credential: SOCKS5Credential? = nil) {
        self.destination = destination
        self.port = port
        self.credential = credential
    }

    /// Produces the client greeting. Must be called exactly once, before ``receive(_:)``.
    public mutating func start() throws -> SOCKS5Step {
        guard state == .initial else {
            throw SOCKS5Error.protocolViolation("start() called in state \(state)")
        }
        if let credential, !credential.isEncodable {
            state = .failed
            throw SOCKS5Error.credentialTooLong
        }

        // Offer username/password only when a credential exists. Offering it unconditionally
        // would invite a server to select it and then be told there is nothing to send.
        var methods: [UInt8] = [SOCKS5.Method.noAuthentication.rawValue]
        if credential != nil {
            methods.append(SOCKS5.Method.usernamePassword.rawValue)
        }

        state = .awaitingMethodSelection
        return .send([SOCKS5.version, UInt8(methods.count)] + methods)
    }

    /// Feeds received bytes into the handshake.
    ///
    /// Safe to call with partial data: whatever cannot be parsed yet stays buffered and
    /// ``SOCKS5Step/needMoreBytes`` is returned.
    public mutating func receive(_ incoming: [UInt8]) throws -> SOCKS5Step {
        guard state != .failed else {
            throw SOCKS5Error.protocolViolation("receive() after failure")
        }
        guard state != .established else {
            throw SOCKS5Error.protocolViolation("receive() after the handshake completed")
        }
        buffer.append(contentsOf: incoming)

        do {
            switch state {
            case .awaitingMethodSelection:
                return try handleMethodSelection()
            case .awaitingAuthenticationReply:
                return try handleAuthenticationReply()
            case .awaitingConnectReply:
                return try handleConnectReply()
            case .initial:
                throw SOCKS5Error.protocolViolation("receive() before start()")
            case .established, .failed:
                throw SOCKS5Error.protocolViolation("unreachable state")
            }
        } catch SOCKS5Error.incompleteResponse {
            // Not a failure — the rest of the message has not arrived. State is unchanged and the
            // buffer still holds everything, so the next call re-parses from the top.
            return .needMoreBytes
        } catch {
            state = .failed
            throw error
        }
    }

    // MARK: - Stages

    private mutating func handleMethodSelection() throws -> SOCKS5Step {
        var reader = ByteReader(buffer)
        let version = try reader.readUInt8()
        let rawMethod = try reader.readUInt8()

        guard version == SOCKS5.version else { throw SOCKS5Error.unexpectedVersion(version) }

        guard let method = SOCKS5.Method(rawValue: rawMethod) else {
            throw SOCKS5Error.unsupportedAuthenticationMethod(rawMethod)
        }
        if method == .noAcceptableMethods { throw SOCKS5Error.noAcceptableAuthenticationMethod }

        buffer.removeFirst(reader.offset)
        selectedMethod = method

        switch method {
        case .noAuthentication:
            state = .awaitingConnectReply
            return .send(try encodeConnectRequest())

        case .usernamePassword:
            guard let credential else { throw SOCKS5Error.authenticationRequired }
            state = .awaitingAuthenticationReply
            return .send(try encodeAuthentication(credential))

        case .gssapi, .noAcceptableMethods:
            // GSSAPI is never offered, so a server selecting it is out of contract.
            throw SOCKS5Error.unsupportedAuthenticationMethod(rawMethod)
        }
    }

    private mutating func handleAuthenticationReply() throws -> SOCKS5Step {
        var reader = ByteReader(buffer)
        let version = try reader.readUInt8()
        let status = try reader.readUInt8()

        // RFC 1929 versions its sub-negotiation independently at 0x01. Some servers mistakenly
        // echo 0x05 here; both are accepted because rejecting the common bug helps nobody, and
        // the status byte is what actually carries the decision.
        guard version == SOCKS5.authSubnegotiationVersion || version == SOCKS5.version else {
            throw SOCKS5Error.unexpectedVersion(version)
        }
        guard status == SOCKS5.authenticationSuccessStatus else {
            throw SOCKS5Error.authenticationFailed
        }

        buffer.removeFirst(reader.offset)
        state = .awaitingConnectReply
        return .send(try encodeConnectRequest())
    }

    private mutating func handleConnectReply() throws -> SOCKS5Step {
        var reader = ByteReader(buffer)
        let version = try reader.readUInt8()
        let rawReply = try reader.readUInt8()
        let reserved = try reader.readUInt8()

        guard version == SOCKS5.version else { throw SOCKS5Error.unexpectedVersion(version) }
        guard reserved == SOCKS5.reserved else {
            throw SOCKS5Error.malformedResponse("reserved byte was 0x\(String(reserved, radix: 16))")
        }
        guard let reply = SOCKS5.ReplyCode(rawValue: rawReply) else {
            throw SOCKS5Error.unknownReplyCode(rawReply)
        }

        // The address is parsed even on failure: the reply is a fixed shape, and consuming it
        // keeps the buffer coherent if a caller ever chooses to continue.
        let boundAddress = try SOCKS5Address.decode(from: &reader)
        let boundPort = try reader.readUInt16()

        guard reply.isSuccess else { throw SOCKS5Error.requestRejected(reply) }

        buffer.removeFirst(reader.offset)
        let leftover = buffer
        buffer = []
        state = .established

        return .established(SOCKS5ConnectionInfo(
            boundAddress: boundAddress,
            boundPort: boundPort,
            method: selectedMethod,
            leftoverBytes: leftover
        ))
    }

    // MARK: - Encoding

    private func encodeConnectRequest() throws -> [UInt8] {
        var bytes: [UInt8] = [
            SOCKS5.version,
            SOCKS5.Command.connect.rawValue,
            SOCKS5.reserved
        ]
        bytes.append(contentsOf: try destination.encoded())
        bytes.append(UInt8(port >> 8))
        bytes.append(UInt8(port & 0xFF))
        return bytes
    }

    private func encodeAuthentication(_ credential: SOCKS5Credential) throws -> [UInt8] {
        let username = Array(credential.username.utf8)
        let password = Array(credential.password.utf8)
        guard username.count >= 1, username.count <= 255, password.count <= 255 else {
            throw SOCKS5Error.credentialTooLong
        }
        var bytes: [UInt8] = [SOCKS5.authSubnegotiationVersion, UInt8(username.count)]
        bytes.append(contentsOf: username)
        bytes.append(UInt8(password.count))
        bytes.append(contentsOf: password)
        return bytes
    }
}
