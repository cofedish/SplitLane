import Darwin
import Foundation

/// Address classification used by the router.
///
/// The only questions asked here are "is this destination on this machine or this link?", which
/// is the third layer of proxy-loop defence: a selected app talking to `127.0.0.1` is never
/// proxied, so even a mistaken network rule degrades to "not proxied" rather than recursion
/// (docs/NETWORKING.md §3).
///
/// Parsing goes through `inet_pton` rather than string prefix tests. `"127.1"` is a valid and
/// commonly accepted spelling of loopback, and `"::ffff:127.0.0.1"` is loopback wearing an IPv6
/// hat; a `hasPrefix("127.")` check misses both.
public enum NetworkAddress {

    /// True for IPv4 `127.0.0.0/8`, IPv6 `::1`, and IPv4-mapped IPv6 forms of either.
    public static func isLoopbackAddress(_ address: String) -> Bool {
        if let v4 = parseIPv4(address) {
            return v4.0 == 127
        }
        if let v6 = parseIPv6(address) {
            if let mapped = ipv4Mapped(v6) { return mapped.0 == 127 }
            // ::1
            return v6.prefix(15).allSatisfy { $0 == 0 } && v6[15] == 1
        }
        return false
    }

    /// True for IPv4 `169.254.0.0/16` and IPv6 `fe80::/10`.
    ///
    /// Link-local is grouped with loopback for routing purposes: it never makes sense to send
    /// link-scoped traffic to a proxy, and Apple's own service discovery lives there.
    public static func isLinkLocalAddress(_ address: String) -> Bool {
        if let v4 = parseIPv4(address) {
            return v4.0 == 169 && v4.1 == 254
        }
        if let v6 = parseIPv6(address) {
            if let mapped = ipv4Mapped(v6) { return mapped.0 == 169 && mapped.1 == 254 }
            return v6[0] == 0xFE && (v6[1] & 0xC0) == 0x80
        }
        return false
    }

    /// Destinations that must never enter the proxy lane, whatever the rules say.
    public static func isLocalDestination(_ address: String) -> Bool {
        isLoopbackAddress(address) || isLinkLocalAddress(address)
    }

    /// Hostname-or-address form of ``isLoopbackAddress(_:)``, accepting the textual names the
    /// system resolves to loopback.
    public static func isLoopbackHost(_ host: String) -> Bool {
        let normalized = host.lowercased()
        if normalized == "localhost" || normalized.hasSuffix(".localhost") { return true }
        return isLoopbackAddress(host)
    }

    /// True if the string parses as an IP literal in either family.
    public static func isIPLiteral(_ address: String) -> Bool {
        parseIPv4(address) != nil || parseIPv6(address) != nil
    }

    // MARK: - Parsing

    /// Returns the four octets of a dotted-quad, or nil.
    ///
    /// Note that `inet_pton` (unlike `inet_aton`) rejects the short forms such as `"127.1"`, so
    /// this deliberately falls back to `inet_aton`, which accepts them — as does the resolver an
    /// application would use. Accepting only the strict form here would let `"127.1"` through as
    /// "not loopback".
    static func parseIPv4(_ address: String) -> (UInt8, UInt8, UInt8, UInt8)? {
        guard !address.isEmpty, !address.contains(":") else { return nil }
        var addr = in_addr()
        guard address.withCString({ inet_aton($0, &addr) }) == 1 else { return nil }
        let raw = addr.s_addr.bigEndian
        return (
            UInt8((raw >> 24) & 0xFF),
            UInt8((raw >> 16) & 0xFF),
            UInt8((raw >> 8) & 0xFF),
            UInt8(raw & 0xFF)
        )
    }

    /// Returns the 16 bytes of an IPv6 literal, or nil. A zone suffix (`%en0`) is stripped first.
    static func parseIPv6(_ address: String) -> [UInt8]? {
        guard !address.isEmpty else { return nil }
        let withoutZone = address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address
        var bytes = [UInt8](repeating: 0, count: 16)
        let ok = withoutZone.withCString { cstr in
            bytes.withUnsafeMutableBytes { buffer in
                inet_pton(AF_INET6, cstr, buffer.baseAddress) == 1
            }
        }
        return ok ? bytes : nil
    }

    /// Extracts the embedded IPv4 address from `::ffff:a.b.c.d`, or nil.
    private static func ipv4Mapped(_ v6: [UInt8]) -> (UInt8, UInt8, UInt8, UInt8)? {
        guard v6.count == 16,
              v6.prefix(10).allSatisfy({ $0 == 0 }),
              v6[10] == 0xFF, v6[11] == 0xFF
        else { return nil }
        return (v6[12], v6[13], v6[14], v6[15])
    }
}
