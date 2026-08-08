import Testing
import Foundation
@testable import SplitLaneCore

@Suite("Network address classification")
struct NetworkAddressTests {

    @Test("IPv4 loopback is recognised across the whole /8 and its short forms", arguments: [
        "127.0.0.1", "127.0.0.53", "127.1.2.3", "127.255.255.254",
        "127.1",            // short form: inet_aton accepts it, so the resolver would too
        "127.0.1",
    ])
    func ipv4Loopback(address: String) {
        // A hasPrefix("127.") check passes these, but a strict inet_pton check would reject the
        // short forms and classify them as routable — which would let a selected app's connection
        // to "127.1" enter the proxy lane and loop.
        #expect(NetworkAddress.isLoopbackAddress(address), "\(address) should be loopback")
    }

    @Test("IPv6 loopback is recognised", arguments: ["::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1"])
    func ipv6Loopback(address: String) {
        #expect(NetworkAddress.isLoopbackAddress(address), "\(address) should be loopback")
    }

    @Test("Routable addresses are not loopback", arguments: [
        "93.184.216.34", "8.8.8.8", "10.0.0.1", "192.168.1.1", "172.16.0.1",
        "2606:2800:220:1:248:1893:25c8:1946", "::", "0.0.0.0", "128.0.0.1", "126.255.255.255",
    ])
    func routableIsNotLoopback(address: String) {
        #expect(!NetworkAddress.isLoopbackAddress(address), "\(address) should not be loopback")
    }

    @Test("Link-local is recognised", arguments: [
        "169.254.0.1", "169.254.255.254", "fe80::1", "fe80::abcd:1234", "febf::1",
    ])
    func linkLocal(address: String) {
        #expect(NetworkAddress.isLinkLocalAddress(address), "\(address) should be link-local")
    }

    @Test("Addresses adjacent to link-local ranges are not link-local", arguments: [
        "169.253.0.1", "169.255.0.1", "fec0::1", "fe7f::1", "ff80::1",
    ])
    func notLinkLocal(address: String) {
        #expect(!NetworkAddress.isLinkLocalAddress(address), "\(address) should not be link-local")
    }

    @Test("A zone identifier does not defeat link-local detection")
    func zonedLinkLocal() {
        #expect(NetworkAddress.isLinkLocalAddress("fe80::1%en0"))
    }

    @Test("Garbage is classified as neither", arguments: [
        "", "not-an-address", "999.999.999.999", "127.0.0.1.5", "::gggg", "example.com",
    ])
    func garbageIsNeither(address: String) {
        #expect(!NetworkAddress.isLoopbackAddress(address))
        #expect(!NetworkAddress.isLinkLocalAddress(address))
    }

    @Test("Local destinations combine loopback and link-local")
    func localDestination() {
        #expect(NetworkAddress.isLocalDestination("127.0.0.1"))
        #expect(NetworkAddress.isLocalDestination("fe80::1"))
        #expect(!NetworkAddress.isLocalDestination("93.184.216.34"))
    }

    @Test("Loopback hostnames are recognised", arguments: [
        "localhost", "LOCALHOST", "LocalHost", "foo.localhost", "127.0.0.1", "::1",
    ])
    func loopbackHostnames(host: String) {
        #expect(NetworkAddress.isLoopbackHost(host), "\(host) should be a loopback host")
    }

    @Test("Names that merely contain 'localhost' are not loopback", arguments: [
        "localhost.evil.com", "notlocalhost", "mylocalhost.com", "localhostings.net",
    ])
    func nonLoopbackHostnames(host: String) {
        #expect(!NetworkAddress.isLoopbackHost(host), "\(host) should not be a loopback host")
    }

    @Test("IP literals are distinguished from names")
    func literalDetection() {
        #expect(NetworkAddress.isIPLiteral("127.0.0.1"))
        #expect(NetworkAddress.isIPLiteral("::1"))
        #expect(NetworkAddress.isIPLiteral("2606:2800:220:1:248:1893:25c8:1946"))
        #expect(!NetworkAddress.isIPLiteral("example.com"))
        #expect(!NetworkAddress.isIPLiteral(""))
    }

    @Test("The proxy endpoint knows whether it is local")
    func endpointLoopbackFlag() {
        #expect(ProxyEndpoint(host: "127.0.0.1", port: 10808).isLoopback)
        #expect(ProxyEndpoint(host: "localhost", port: 10808).isLoopback)
        #expect(ProxyEndpoint(host: "::1", port: 10808).isLoopback)
        #expect(!ProxyEndpoint(host: "proxy.example.com", port: 1080).isLoopback)
    }

    @Test("IPv6 endpoints display in bracket form")
    func endpointDisplay() {
        #expect(ProxyEndpoint(host: "127.0.0.1", port: 10808).displayString == "127.0.0.1:10808")
        #expect(ProxyEndpoint(host: "::1", port: 10808).displayString == "[::1]:10808")
    }
}

@Suite("SOCKS5 address encoding")
struct SOCKS5AddressTests {

    @Test("IPv4 literals encode with ATYP 0x01")
    func ipv4Encoding() throws {
        let address = try #require(SOCKS5Address.literal("93.184.216.34"))
        #expect(address == .ipv4([93, 184, 216, 34]))
        #expect(try address.encoded() == [0x01, 93, 184, 216, 34])
    }

    @Test("IPv6 literals encode with ATYP 0x04")
    func ipv6Encoding() throws {
        let address = try #require(SOCKS5Address.literal("::1"))
        let expected = [UInt8](repeating: 0, count: 15) + [1]
        #expect(address == .ipv6(expected))
        #expect(try address.encoded() == [0x04] + expected)
    }

    @Test("Domains encode with ATYP 0x03 and a length prefix")
    func domainEncoding() throws {
        #expect(try SOCKS5Address.domain("example.com").encoded()
                == [0x03, 11] + Array("example.com".utf8))
    }

    @Test("A hostname is preferred over an address so the upstream resolves it")
    func hostnamePreferred() throws {
        // Sending the locally resolved IP would pin a CDN connection to an edge node chosen for
        // the client's location rather than the proxy's (docs/NETWORKING.md §6).
        let address = try SOCKS5Address.destination(
            hostname: "example.com",
            address: "93.184.216.34"
        )
        #expect(address == .domain("example.com"))
    }

    @Test("A hostname that is really an IP literal is sent as an IP")
    func literalHostnameBecomesLiteral() throws {
        // ATYP=DOMAIN carrying "93.184.216.34" would make the server do a pointless lookup.
        let address = try SOCKS5Address.destination(hostname: "93.184.216.34", address: nil)
        #expect(address == .ipv4([93, 184, 216, 34]))
    }

    @Test("The address is used when no hostname is available")
    func addressFallback() throws {
        let address = try SOCKS5Address.destination(hostname: nil, address: "93.184.216.34")
        #expect(address == .ipv4([93, 184, 216, 34]))
    }

    @Test("An empty hostname falls through to the address")
    func emptyHostnameFallsThrough() throws {
        let address = try SOCKS5Address.destination(hostname: "", address: "1.2.3.4")
        #expect(address == .ipv4([1, 2, 3, 4]))
    }

    @Test("A destination with neither hostname nor address is an error")
    func noDestination() {
        #expect(throws: SOCKS5Error.self) {
            _ = try SOCKS5Address.destination(hostname: nil, address: nil)
        }
    }

    @Test("A 255-byte hostname is allowed and 256 is not")
    func domainLengthBoundary() throws {
        // The length is a single byte, so 255 is the exact ceiling.
        let maxLabel = String(repeating: "a", count: 255)
        #expect(try SOCKS5Address.destination(hostname: maxLabel, address: nil) == .domain(maxLabel))

        #expect(throws: SOCKS5Error.domainNameTooLong) {
            _ = try SOCKS5Address.destination(hostname: String(repeating: "a", count: 256), address: nil)
        }
    }

    @Test("A multi-byte hostname is measured in UTF-8 bytes, not characters")
    func domainLengthIsBytes() {
        // 128 two-byte characters is 256 bytes: over the limit even though it is 128 characters.
        let name = String(repeating: "é", count: 128)
        #expect(name.count == 128)
        #expect(name.utf8.count == 256)
        #expect(throws: SOCKS5Error.domainNameTooLong) {
            _ = try SOCKS5Address.destination(hostname: name, address: nil)
        }
    }

    @Test("A malformed IPv4 body is rejected at encode time")
    func malformedIPv4Body() {
        #expect(throws: SOCKS5Error.self) { _ = try SOCKS5Address.ipv4([1, 2, 3]).encoded() }
    }

    @Test("A malformed IPv6 body is rejected at encode time")
    func malformedIPv6Body() {
        #expect(throws: SOCKS5Error.self) { _ = try SOCKS5Address.ipv6([1, 2, 3]).encoded() }
    }

    @Test("Display strings are readable")
    func displayStrings() {
        #expect(SOCKS5Address.ipv4([93, 184, 216, 34]).displayString == "93.184.216.34")
        #expect(SOCKS5Address.domain("example.com").displayString == "example.com")
        #expect(SOCKS5Address.ipv6([UInt8](repeating: 0, count: 15) + [1]).displayString == "::1")
    }

    @Test("A credential never reveals its password in string form")
    func credentialRedaction() {
        // The cheapest guarantee that a password does not reach a log is that interpolating it
        // produces nothing useful.
        let credential = SOCKS5Credential(username: "alice", password: "sup3rs3cret")

        #expect(!"\(credential)".contains("sup3rs3cret"))
        #expect(!String(describing: credential).contains("sup3rs3cret"))
        #expect(!String(reflecting: credential).contains("sup3rs3cret"))
        #expect("\(credential)".contains("alice"))
    }
}
