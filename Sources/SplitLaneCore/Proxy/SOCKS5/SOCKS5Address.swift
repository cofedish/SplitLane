import Darwin
import Foundation

/// A SOCKS5 destination or bound address.
public enum SOCKS5Address: Sendable, Hashable {
    case ipv4([UInt8])      // exactly 4 bytes
    case ipv6([UInt8])      // exactly 16 bytes
    case domain(String)     // 1...255 bytes when UTF-8 encoded

    /// Builds an address from an IP literal, or nil if the string is not one.
    public static func literal(_ address: String) -> SOCKS5Address? {
        if let v4 = NetworkAddress.parseIPv4(address) {
            return .ipv4([v4.0, v4.1, v4.2, v4.3])
        }
        if let v6 = NetworkAddress.parseIPv6(address) {
            return .ipv6(v6)
        }
        return nil
    }

    /// Builds the address to put in a CONNECT request.
    ///
    /// A hostname is preferred over an IP whenever one is available, so the *upstream* resolves
    /// the name. The alternative — sending the IP the client already resolved locally — pins the
    /// connection to whatever the local resolver returned, which for a CDN means the proxy
    /// connects to an edge node chosen for the client's location rather than its own. See
    /// docs/NETWORKING.md §6.
    ///
    /// A hostname that happens to be an IP literal is emitted as that literal, because
    /// `ATYP=DOMAIN` carrying "93.184.216.34" makes the server do a pointless lookup.
    public static func destination(hostname: String?, address: String?) throws -> SOCKS5Address {
        if let hostname, !hostname.isEmpty {
            if let literal = literal(hostname) { return literal }
            let byteCount = hostname.utf8.count
            guard byteCount > 0 else { throw SOCKS5Error.invalidDestinationAddress(hostname) }
            guard byteCount <= 255 else { throw SOCKS5Error.domainNameTooLong }
            return .domain(hostname)
        }
        if let address, let literal = literal(address) {
            return literal
        }
        throw SOCKS5Error.invalidDestinationAddress(address ?? hostname ?? "<none>")
    }

    public var addressType: SOCKS5.AddressType {
        switch self {
        case .ipv4: .ipv4
        case .ipv6: .ipv6
        case .domain: .domain
        }
    }

    /// Wire encoding of the address, excluding the type tag and the port.
    public func encodedBody() throws -> [UInt8] {
        switch self {
        case .ipv4(let bytes):
            guard bytes.count == 4 else {
                throw SOCKS5Error.malformedResponse("IPv4 address must be 4 bytes")
            }
            return bytes
        case .ipv6(let bytes):
            guard bytes.count == 16 else {
                throw SOCKS5Error.malformedResponse("IPv6 address must be 16 bytes")
            }
            return bytes
        case .domain(let name):
            let utf8 = Array(name.utf8)
            guard !utf8.isEmpty else { throw SOCKS5Error.invalidDestinationAddress(name) }
            guard utf8.count <= 255 else { throw SOCKS5Error.domainNameTooLong }
            return [UInt8(utf8.count)] + utf8
        }
    }

    /// Type tag followed by the encoded body.
    public func encoded() throws -> [UInt8] {
        try [addressType.rawValue] + encodedBody()
    }

    /// Parses an address from a reply. Advances the reader only on success.
    static func decode(from reader: inout ByteReader) throws -> SOCKS5Address {
        let rawType = try reader.readUInt8()
        guard let type = SOCKS5.AddressType(rawValue: rawType) else {
            throw SOCKS5Error.unsupportedAddressType(rawType)
        }
        switch type {
        case .ipv4:
            return .ipv4(try reader.readBytes(4))
        case .ipv6:
            return .ipv6(try reader.readBytes(16))
        case .domain:
            // The length byte is chosen by the server. `readLengthPrefixedBytes` bounds-checks it;
            // a hostile length can only produce `.incompleteResponse`, never a trap.
            let bytes = try reader.readLengthPrefixedBytes()
            guard let name = String(bytes: bytes, encoding: .utf8) else {
                throw SOCKS5Error.malformedResponse("domain name is not valid UTF-8")
            }
            return .domain(name)
        }
    }

    /// Human-readable form for logging. Contains no secrets — destinations are loggable, payloads
    /// and credentials are not.
    public var displayString: String {
        switch self {
        case .ipv4(let bytes):
            bytes.map(String.init).joined(separator: ".")
        case .ipv6(let bytes):
            Self.formatIPv6(bytes)
        case .domain(let name):
            name
        }
    }

    private static func formatIPv6(_ bytes: [UInt8]) -> String {
        guard bytes.count == 16 else { return bytes.map { String($0, radix: 16) }.joined() }
        var storage = in6_addr()
        withUnsafeMutableBytes(of: &storage) { raw in
            raw.copyBytes(from: bytes)
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let result = withUnsafePointer(to: &storage) { pointer in
            inet_ntop(AF_INET6, pointer, &buffer, socklen_t(INET6_ADDRSTRLEN))
        }
        guard result != nil else { return "::" }
        // inet_ntop NUL-terminates; drop the terminator and everything after it before decoding.
        let text = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(decoding: text, as: UTF8.self)
    }
}
