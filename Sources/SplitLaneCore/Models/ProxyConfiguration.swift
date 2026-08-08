import Foundation

/// Upstream proxy protocol. Only SOCKS5 is implemented; the enum exists so that adding HTTP
/// CONNECT later does not require reshaping stored configuration.
public enum ProxyProtocolType: String, Codable, Sendable, Hashable, CaseIterable {
    case socks5

    public var displayName: String {
        switch self {
        case .socks5: "SOCKS5"
        }
    }

    public var defaultPort: UInt16 {
        switch self {
        case .socks5: 1080
        }
    }
}

/// Where the upstream proxy lives.
public struct ProxyEndpoint: Codable, Sendable, Hashable {
    public var host: String
    public var port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    /// SplitLane's first target: a local SOCKS5 listener.
    public static let localSOCKS5 = ProxyEndpoint(host: "127.0.0.1", port: 10808)

    /// True when the endpoint is on this machine. Used to decide whether plaintext SOCKS5
    /// username/password authentication is a real exposure or a non-issue (F-6).
    public var isLoopback: Bool {
        NetworkAddress.isLoopbackHost(host)
    }

    public var displayString: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
}

/// Reference to a credential held in the Keychain.
///
/// This type carries **no secret material**, only an opaque locator, and that is the whole point.
/// `ProxyConfiguration` is serialised into `NETunnelProviderProtocol.providerConfiguration`, which
/// lives in system NE preferences and is readable by root and visible to `scutil --nc`. Putting a
/// password there would be the obvious move and the wrong one — see F-5 in docs/THREAT_MODEL.md.
/// `ConfigurationCodecTests.testEncodedConfigurationNeverContainsSecrets` enforces it.
public struct CredentialReference: Codable, Sendable, Hashable {
    /// Keychain account name (the SOCKS5 username). Not a secret.
    public let username: String

    /// Base64 of a `kSecClassGenericPassword` persistent reference, or nil when the credential is
    /// delivered out-of-band via `NEVPNProtocol.passwordReference`.
    public let persistentReference: String?

    public init(username: String, persistentReference: String? = nil) {
        self.username = username
        self.persistentReference = persistentReference
    }
}

/// The upstream proxy the PROXY lane points at.
public struct ProxyConfiguration: Codable, Sendable, Hashable, Identifiable {

    public var id: UUID
    public var displayName: String
    public var type: ProxyProtocolType
    public var endpoint: ProxyEndpoint

    /// Nil when the proxy needs no authentication.
    public var credential: CredentialReference?

    public var isEnabled: Bool

    /// Seconds allowed for TCP connect plus the full SOCKS5 handshake.
    public var handshakeTimeout: TimeInterval

    /// When true, a selected application whose flow cannot be proxied falls back to DIRECT
    /// instead of failing.
    ///
    /// **Defaults to false and has no UI in the MVP.** Silent fallback turns a visible error into
    /// an invisible leak, which is the exact failure this product exists to prevent (ADR 0003).
    /// The field exists so the future opt-in is a deliberate, documented downgrade rather than a
    /// retrofit.
    public var allowDirectFallback: Bool

    public var requiresAuthentication: Bool { credential != nil }

    /// True when credentials would cross a real network in the clear. RFC 1929 sends the
    /// username and password unencrypted, which is irrelevant on loopback and not irrelevant
    /// anywhere else (F-6).
    public var hasPlaintextCredentialExposure: Bool {
        requiresAuthentication && !endpoint.isLoopback
    }

    public init(
        id: UUID = UUID(),
        displayName: String = "Local SOCKS5",
        type: ProxyProtocolType = .socks5,
        endpoint: ProxyEndpoint = .localSOCKS5,
        credential: CredentialReference? = nil,
        isEnabled: Bool = true,
        handshakeTimeout: TimeInterval = 10,
        allowDirectFallback: Bool = false
    ) {
        self.id = id
        self.displayName = displayName
        self.type = type
        self.endpoint = endpoint
        self.credential = credential
        self.isEnabled = isEnabled
        self.handshakeTimeout = handshakeTimeout
        self.allowDirectFallback = allowDirectFallback
    }

    /// The MVP default: SOCKS5 on 127.0.0.1:10808, no auth, fail closed.
    public static let `default` = ProxyConfiguration()
}
