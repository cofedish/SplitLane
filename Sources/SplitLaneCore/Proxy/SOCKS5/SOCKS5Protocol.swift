import Foundation

/// Wire constants and vocabulary for SOCKS5 (RFC 1928) and its username/password authentication
/// sub-negotiation (RFC 1929).
public enum SOCKS5 {

    /// Protocol version byte, present in every SOCKS5 message.
    public static let version: UInt8 = 0x05

    /// Version byte of the username/password sub-negotiation. Note this is `0x01`, *not* `0x05` —
    /// RFC 1929 versions itself independently, and conflating the two is a classic bug.
    public static let authSubnegotiationVersion: UInt8 = 0x01

    /// Reserved byte, must be zero in requests and is required to be zero in replies.
    public static let reserved: UInt8 = 0x00

    /// Authentication methods offered and selected during the greeting.
    public enum Method: UInt8, Sendable, Hashable {
        case noAuthentication = 0x00
        case gssapi = 0x01
        case usernamePassword = 0x02
        /// Returned by the server when it accepts none of the offered methods.
        case noAcceptableMethods = 0xFF
    }

    /// Request command. Only `connect` is implemented; the others are listed because a reply may
    /// reference them and the parser should name what it saw.
    public enum Command: UInt8, Sendable, Hashable {
        case connect = 0x01
        case bind = 0x02
        case udpAssociate = 0x03
    }

    /// Address type tag.
    public enum AddressType: UInt8, Sendable, Hashable {
        case ipv4 = 0x01
        case domain = 0x03
        case ipv6 = 0x04
    }

    /// Reply status from the server (RFC 1928 §6).
    public enum ReplyCode: UInt8, Sendable, Hashable {
        case succeeded = 0x00
        case generalFailure = 0x01
        case connectionNotAllowed = 0x02
        case networkUnreachable = 0x03
        case hostUnreachable = 0x04
        case connectionRefused = 0x05
        case ttlExpired = 0x06
        case commandNotSupported = 0x07
        case addressTypeNotSupported = 0x08

        public var isSuccess: Bool { self == .succeeded }

        public var localizedDescription: String {
            switch self {
            case .succeeded: "Succeeded"
            case .generalFailure: "General SOCKS server failure"
            case .connectionNotAllowed: "Connection not allowed by ruleset"
            case .networkUnreachable: "Network unreachable"
            case .hostUnreachable: "Host unreachable"
            case .connectionRefused: "Connection refused"
            case .ttlExpired: "TTL expired"
            case .commandNotSupported: "Command not supported"
            case .addressTypeNotSupported: "Address type not supported"
            }
        }
    }

    /// RFC 1929 authentication succeeded when the status byte is zero. Any other value is a
    /// failure; the RFC does not enumerate specific codes.
    public static let authenticationSuccessStatus: UInt8 = 0x00
}

/// Failures the SOCKS5 layer can produce.
///
/// Structured rather than stringly-typed because the UI reports these per application, and
/// "authentication failed" and "the proxy is not running" call for very different user actions.
public enum SOCKS5Error: Error, Sendable, Hashable {

    /// Server replied with a SOCKS version byte other than 0x05.
    case unexpectedVersion(UInt8)

    /// Server accepted none of the methods offered.
    case noAcceptableAuthenticationMethod

    /// Server selected a method that was never offered, or one this client cannot perform.
    case unsupportedAuthenticationMethod(UInt8)

    /// Server requires authentication but no credential is configured.
    case authenticationRequired

    /// RFC 1929 sub-negotiation returned a non-zero status.
    case authenticationFailed

    /// Username or password does not fit RFC 1929's single length byte.
    case credentialTooLong

    /// Server returned a non-success reply code.
    case requestRejected(SOCKS5.ReplyCode)

    /// Server returned a reply code outside the RFC 1928 range.
    case unknownReplyCode(UInt8)

    /// Server sent an address type tag this client does not recognise.
    case unsupportedAddressType(UInt8)

    /// Fewer bytes have arrived than the message needs. Recoverable: the caller waits for more.
    case incompleteResponse

    /// Bytes arrived but violate the protocol.
    case malformedResponse(String)

    /// Destination hostname exceeds the 255 bytes a single length byte can express.
    case domainNameTooLong

    /// Destination address could not be encoded — not a valid IP literal and not a usable name.
    case invalidDestinationAddress(String)

    /// Handshake exceeded the configured timeout.
    case timedOut

    /// The operation was cancelled (provider stopping, flow closed, task cancelled).
    case cancelled

    /// The underlying transport failed. `String` rather than the original error to keep this type
    /// `Hashable` and `Sendable` across the module boundary.
    case transportFailure(String)

    /// Bytes were received in a state that expects none.
    case protocolViolation(String)

    public var localizedDescription: String {
        switch self {
        case .unexpectedVersion(let byte):
            "Proxy replied with SOCKS version \(byte), expected 5"
        case .noAcceptableAuthenticationMethod:
            "Proxy rejected all offered authentication methods"
        case .unsupportedAuthenticationMethod(let byte):
            "Proxy selected unsupported authentication method 0x\(String(byte, radix: 16))"
        case .authenticationRequired:
            "Proxy requires authentication but none is configured"
        case .authenticationFailed:
            "Proxy rejected the credentials"
        case .credentialTooLong:
            "Username or password exceeds 255 bytes"
        case .requestRejected(let code):
            "Proxy rejected the connection: \(code.localizedDescription)"
        case .unknownReplyCode(let byte):
            "Proxy returned unknown reply code 0x\(String(byte, radix: 16))"
        case .unsupportedAddressType(let byte):
            "Proxy returned unsupported address type 0x\(String(byte, radix: 16))"
        case .incompleteResponse:
            "Proxy response was truncated"
        case .malformedResponse(let detail):
            "Malformed proxy response: \(detail)"
        case .domainNameTooLong:
            "Destination hostname exceeds 255 bytes"
        case .invalidDestinationAddress(let address):
            "Invalid destination address: \(address)"
        case .timedOut:
            "Proxy handshake timed out"
        case .cancelled:
            "Proxy connection cancelled"
        case .transportFailure(let detail):
            "Proxy transport failure: \(detail)"
        case .protocolViolation(let detail):
            "Proxy protocol violation: \(detail)"
        }
    }

    /// Whether retrying could plausibly succeed. Used to decide log level, never to silently
    /// downgrade a selected app to DIRECT — that never happens (ADR 0003).
    public var isTransient: Bool {
        switch self {
        case .timedOut, .transportFailure, .incompleteResponse:
            true
        case .requestRejected(let code):
            code == .ttlExpired || code == .networkUnreachable || code == .hostUnreachable
        default:
            false
        }
    }
}
