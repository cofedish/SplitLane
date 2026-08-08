import Foundation

/// Why a configuration was rejected.
public enum ConfigurationValidationError: Error, Sendable, Hashable {
    case emptySigningIdentifier
    case duplicateSigningIdentifier(String)
    case emptyProxyHost
    case invalidProxyPort(UInt16)
    case invalidProxyHost(String)
    case emptyUsername
    case unsupportedSchemaVersion(found: Int, supported: Int)
    case nonPositiveTimeout(TimeInterval)

    public var localizedDescription: String {
        switch self {
        case .emptySigningIdentifier:
            "An application rule has an empty signing identifier"
        case .duplicateSigningIdentifier(let id):
            "Duplicate rule for signing identifier \(id)"
        case .emptyProxyHost:
            "Proxy host is empty"
        case .invalidProxyPort(let port):
            "Proxy port \(port) is not valid"
        case .invalidProxyHost(let host):
            "Proxy host \(host) is neither a valid IP address nor a valid hostname"
        case .emptyUsername:
            "Proxy authentication is enabled but the username is empty"
        case .unsupportedSchemaVersion(let found, let supported):
            "Configuration schema version \(found) is newer than the supported version \(supported)"
        case .nonPositiveTimeout(let value):
            "Handshake timeout \(value) must be greater than zero"
        }
    }
}

/// Validates a configuration before it is persisted or applied.
///
/// Two of these checks are load-bearing rather than cosmetic:
///
/// - **Empty signing identifier.** `NEFlowMetaData` documents that
///   `sourceAppSigningIdentifier` may be empty for system-process flows. If an empty string were
///   ever allowed as a rule key, every unidentified system flow would match it and be proxied.
///   Rejecting it here means the key cannot exist (G-6).
/// - **Duplicate identifiers.** Rules are keyed by identifier in the snapshot, so a duplicate
///   would silently drop one rule. Better to refuse the configuration than to apply half of it.
public enum ConfigurationValidator {

    public static func validate(_ configuration: RuntimeConfiguration) throws {
        guard configuration.version.isReadable else {
            throw ConfigurationValidationError.unsupportedSchemaVersion(
                found: configuration.version.schemaVersion,
                supported: ConfigurationVersion.currentSchema
            )
        }

        var seen = Set<String>()
        for rule in configuration.rules {
            let identifier = rule.identity.signingIdentifier
            guard !identifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw ConfigurationValidationError.emptySigningIdentifier
            }
            guard seen.insert(identifier).inserted else {
                throw ConfigurationValidationError.duplicateSigningIdentifier(identifier)
            }
        }

        try validate(configuration.proxy)
    }

    public static func validate(_ proxy: ProxyConfiguration) throws {
        let host = proxy.endpoint.host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else { throw ConfigurationValidationError.emptyProxyHost }
        guard isPlausibleHost(host) else {
            throw ConfigurationValidationError.invalidProxyHost(host)
        }
        guard proxy.endpoint.port > 0 else {
            throw ConfigurationValidationError.invalidProxyPort(proxy.endpoint.port)
        }
        guard proxy.handshakeTimeout > 0 else {
            throw ConfigurationValidationError.nonPositiveTimeout(proxy.handshakeTimeout)
        }
        if let credential = proxy.credential {
            guard !credential.username.isEmpty else {
                throw ConfigurationValidationError.emptyUsername
            }
        }
    }

    /// Accepts an IP literal or something shaped like a DNS name.
    ///
    /// Intentionally permissive: this is a typo guard for the Proxy screen, not a hostname
    /// grammar. Rejecting an unusual but working name would be worse than accepting a nonsense
    /// one, which simply fails to connect and says so.
    static func isPlausibleHost(_ host: String) -> Bool {
        if NetworkAddress.isIPLiteral(host) { return true }
        guard host.utf8.count <= 253 else { return false }
        guard !host.hasPrefix("."), !host.hasSuffix(".") else { return false }

        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return false }

        for label in labels {
            guard !label.isEmpty, label.utf8.count <= 63 else { return false }
            guard !label.hasPrefix("-"), !label.hasSuffix("-") else { return false }
            let allowed = label.allSatisfy { character in
                character.isLetter || character.isNumber || character == "-" || character == "_"
            }
            guard allowed else { return false }
        }
        return true
    }
}
