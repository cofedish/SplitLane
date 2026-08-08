import Foundation

/// Encodes and decodes ``RuntimeConfiguration`` for transport between the host app and the
/// provider.
///
/// The encoded form is a property-list dictionary because that is what
/// `NETunnelProviderProtocol.providerConfiguration` accepts, and JSON `Data` inside it because a
/// single opaque blob round-trips `Codable` types exactly, with no plist type coercion in the
/// middle.
///
/// **Nothing secret is ever encoded here.** `providerConfiguration` is stored in system NE
/// preferences: root-readable and visible to `scutil --nc`. Only a credential *reference* travels
/// in the dictionary; the password itself reaches the provider through
/// `NEVPNProtocol.passwordReference`, which is the Keychain-backed channel Apple provides for
/// exactly this. See F-5 in docs/THREAT_MODEL.md — and
/// `ConfigurationCodecTests.testEncodedConfigurationContainsNoSecretMaterial`, which is the part
/// that actually holds the line.
public enum ConfigurationCodec {

    /// Key under which the encoded blob is stored in `providerConfiguration`.
    public static let payloadKey = "dev.cofe.splitlane.configuration"

    /// Schema version, duplicated outside the blob so a provider can check compatibility without
    /// first decoding a payload it may not understand.
    public static let schemaVersionKey = "dev.cofe.splitlane.schemaVersion"

    /// Generation counter, exposed outside the blob so a reload can be recognised as stale
    /// cheaply.
    public static let generationKey = "dev.cofe.splitlane.generation"

    public enum CodecError: Error, Sendable, Hashable {
        case missingPayload
        case malformedPayload(String)
        case unsupportedSchemaVersion(found: Int, supported: Int)
    }

    // MARK: - Encoding

    /// Validates and encodes a configuration into a `providerConfiguration` dictionary.
    ///
    /// Validation happens here rather than at the call sites so there is no path that persists an
    /// invalid configuration.
    public static func encode(_ configuration: RuntimeConfiguration) throws -> [String: Any] {
        try ConfigurationValidator.validate(configuration)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]   // deterministic, so tests can compare bytes
        let payload = try encoder.encode(configuration)

        return [
            payloadKey: payload,
            schemaVersionKey: configuration.version.schemaVersion,
            generationKey: String(configuration.version.generation)
        ]
    }

    // MARK: - Decoding

    /// Decodes a configuration produced by ``encode(_:)``.
    ///
    /// A payload stamped with a newer schema is **refused**, not best-effort decoded. An
    /// extension that guesses at fields it does not understand can silently route traffic
    /// somewhere the user did not ask for, and a failed reload that says so is recoverable in a
    /// way that a wrong reload is not (G-9).
    public static func decode(from dictionary: [String: Any]) throws -> RuntimeConfiguration {
        if let declared = dictionary[schemaVersionKey] as? Int {
            guard declared <= ConfigurationVersion.currentSchema else {
                throw CodecError.unsupportedSchemaVersion(
                    found: declared,
                    supported: ConfigurationVersion.currentSchema
                )
            }
        }

        guard let payload = dictionary[payloadKey] as? Data else {
            throw CodecError.missingPayload
        }

        let configuration: RuntimeConfiguration
        do {
            configuration = try JSONDecoder().decode(RuntimeConfiguration.self, from: payload)
        } catch {
            throw CodecError.malformedPayload(String(describing: error))
        }

        guard configuration.version.isReadable else {
            throw CodecError.unsupportedSchemaVersion(
                found: configuration.version.schemaVersion,
                supported: ConfigurationVersion.currentSchema
            )
        }
        // Decoding is not a place to be lenient: a payload that survived JSON but violates the
        // invariants would otherwise become a snapshot with, say, an empty-string rule key.
        try ConfigurationValidator.validate(configuration)
        return configuration
    }

    /// Reads the generation without decoding the payload, for cheap staleness checks.
    public static func generation(from dictionary: [String: Any]) -> UInt64? {
        if let text = dictionary[generationKey] as? String { return UInt64(text) }
        if let number = dictionary[generationKey] as? UInt64 { return number }
        return nil
    }
}
