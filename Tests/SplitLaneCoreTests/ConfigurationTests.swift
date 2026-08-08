import Testing
import Foundation
@testable import SplitLaneCore

@Suite("Configuration")
struct ConfigurationTests {

    private func identity(_ id: String) -> AppIdentity {
        AppIdentity(
            signingIdentifier: id,
            teamIdentifier: "ABCDE12345",
            bundleIdentifier: id,
            displayName: id
        )
    }

    // MARK: - Validation

    @Test("A default configuration is valid")
    func defaultIsValid() throws {
        try ConfigurationValidator.validate(RuntimeConfiguration())
    }

    @Test("An empty signing identifier is rejected", arguments: ["", "   ", "\t", "\n"])
    func emptyIdentifierRejected(identifier: String) {
        // If an empty key ever reached the snapshot it would match every unidentified system
        // flow, since NEFlowMetaData documents that the identifier can be empty (G-6).
        let configuration = RuntimeConfiguration(rules: [AppRule(identity: identity(identifier))])
        #expect(throws: ConfigurationValidationError.emptySigningIdentifier) {
            try ConfigurationValidator.validate(configuration)
        }
    }

    @Test("Duplicate rules are rejected rather than silently deduplicated")
    func duplicateRejected() {
        let configuration = RuntimeConfiguration(rules: [
            AppRule(identity: identity("com.openai.codex")),
            AppRule(identity: identity("com.openai.codex"), action: .direct),
        ])
        #expect(throws: ConfigurationValidationError.duplicateSigningIdentifier("com.openai.codex")) {
            try ConfigurationValidator.validate(configuration)
        }
    }

    @Test("An empty proxy host is rejected")
    func emptyHostRejected() {
        let proxy = ProxyConfiguration(endpoint: ProxyEndpoint(host: "", port: 10808))
        #expect(throws: ConfigurationValidationError.emptyProxyHost) {
            try ConfigurationValidator.validate(proxy)
        }
    }

    @Test("Port zero is rejected")
    func zeroPortRejected() {
        let proxy = ProxyConfiguration(endpoint: ProxyEndpoint(host: "127.0.0.1", port: 0))
        #expect(throws: ConfigurationValidationError.invalidProxyPort(0)) {
            try ConfigurationValidator.validate(proxy)
        }
    }

    @Test("A non-positive timeout is rejected", arguments: [0.0, -1.0])
    func nonPositiveTimeoutRejected(timeout: TimeInterval) {
        let proxy = ProxyConfiguration(handshakeTimeout: timeout)
        #expect(throws: ConfigurationValidationError.nonPositiveTimeout(timeout)) {
            try ConfigurationValidator.validate(proxy)
        }
    }

    @Test("Authentication with an empty username is rejected")
    func emptyUsernameRejected() {
        let proxy = ProxyConfiguration(credential: CredentialReference(username: ""))
        #expect(throws: ConfigurationValidationError.emptyUsername) {
            try ConfigurationValidator.validate(proxy)
        }
    }

    @Test("Valid hosts are accepted", arguments: [
        "127.0.0.1", "::1", "10.0.0.1", "localhost",
        "proxy.example.com", "my-proxy", "a.b.c.d.e.f", "proxy_1.internal",
    ])
    func validHostsAccepted(host: String) throws {
        try ConfigurationValidator.validate(
            ProxyConfiguration(endpoint: ProxyEndpoint(host: host, port: 1080))
        )
    }

    @Test("Malformed hosts are rejected", arguments: [
        ".leading.dot", "trailing.dot.", "double..dot", "-leading-hyphen.com",
        "trailing-hyphen-.com", "has space.com", "has/slash.com",
    ])
    func malformedHostsRejected(host: String) {
        #expect(throws: ConfigurationValidationError.self) {
            try ConfigurationValidator.validate(
                ProxyConfiguration(endpoint: ProxyEndpoint(host: host, port: 1080))
            )
        }
    }

    @Test("A future schema version is refused")
    func futureSchemaRefused() {
        let configuration = RuntimeConfiguration(
            version: ConfigurationVersion(schemaVersion: ConfigurationVersion.currentSchema + 1)
        )
        #expect(throws: ConfigurationValidationError.self) {
            try ConfigurationValidator.validate(configuration)
        }
    }

    // MARK: - Codec

    @Test("A configuration round-trips exactly")
    func roundTrip() throws {
        let original = RuntimeConfiguration(
            version: ConfigurationVersion(generation: 42),
            rules: [
                AppRule(identity: identity("com.openai.codex")),
                AppRule(identity: identity("com.example.Other"), action: .direct, matchMode: .exact),
            ],
            proxy: ProxyConfiguration(
                displayName: "Local SOCKS5",
                endpoint: ProxyEndpoint(host: "127.0.0.1", port: 10808),
                credential: CredentialReference(username: "alice", persistentReference: "cmVm"),
                handshakeTimeout: 15
            ),
            isRoutingEnabled: true,
            logsDirectFlows: true
        )

        let encoded = try ConfigurationCodec.encode(original)
        let decoded = try ConfigurationCodec.decode(from: encoded)

        #expect(decoded == original)
    }

    @Test("The encoded dictionary never contains secret material")
    func encodedConfigurationContainsNoSecretMaterial() throws {
        // F-5. providerConfiguration lives in system NE preferences: root-readable and dumped by
        // `scutil --nc`. This test is the enforcement mechanism for "no credentials in there",
        // not a comment in a header.
        let secret = "sup3rs3cretpassw0rd"
        let configuration = RuntimeConfiguration(
            rules: [AppRule(identity: identity("com.openai.codex"))],
            proxy: ProxyConfiguration(
                credential: CredentialReference(username: "alice", persistentReference: "cmVmZXJlbmNl")
            )
        )

        let encoded = try ConfigurationCodec.encode(configuration)
        let payload = try #require(encoded[ConfigurationCodec.payloadKey] as? Data)
        let text = String(decoding: payload, as: UTF8.self)

        #expect(!text.contains(secret))
        #expect(!text.lowercased().contains("password"))
        #expect(!text.lowercased().contains("passwd"))
        // The reference and username are not secrets and are expected to be present.
        #expect(text.contains("alice"))

        // There is also no way to put a password in: CredentialReference has no such field.
        let mirror = Mirror(reflecting: CredentialReference(username: "u"))
        let fields = mirror.children.compactMap(\.label).map { $0.lowercased() }
        #expect(!fields.contains { $0.contains("password") || $0.contains("secret") })
    }

    @Test("Encoding is deterministic")
    func encodingIsDeterministic() throws {
        let configuration = RuntimeConfiguration(
            rules: [AppRule(identity: identity("com.openai.codex"))]
        )
        let first = try ConfigurationCodec.encode(configuration)
        let second = try ConfigurationCodec.encode(configuration)

        #expect(first[ConfigurationCodec.payloadKey] as? Data
                == second[ConfigurationCodec.payloadKey] as? Data)
    }

    @Test("Encoding refuses an invalid configuration")
    func encodingValidates() {
        // There must be no path that persists something the provider will later choke on.
        let configuration = RuntimeConfiguration(rules: [AppRule(identity: identity(""))])
        #expect(throws: (any Error).self) { _ = try ConfigurationCodec.encode(configuration) }
    }

    @Test("A missing payload is reported")
    func missingPayload() {
        #expect(throws: ConfigurationCodec.CodecError.missingPayload) {
            _ = try ConfigurationCodec.decode(from: [:])
        }
    }

    @Test("A corrupt payload is reported rather than partially applied")
    func corruptPayload() {
        let dictionary: [String: Any] = [
            ConfigurationCodec.payloadKey: Data("not json".utf8)
        ]
        #expect(throws: ConfigurationCodec.CodecError.self) {
            _ = try ConfigurationCodec.decode(from: dictionary)
        }
    }

    @Test("A newer schema is refused instead of best-effort decoded")
    func futureSchemaRefusedByCodec() {
        // Guessing at fields an older build does not understand could silently route traffic
        // somewhere the user did not ask for. A failed reload is recoverable; a wrong one is not.
        let dictionary: [String: Any] = [
            ConfigurationCodec.schemaVersionKey: ConfigurationVersion.currentSchema + 1,
            ConfigurationCodec.payloadKey: Data("{}".utf8),
        ]
        #expect(throws: ConfigurationCodec.CodecError.self) {
            _ = try ConfigurationCodec.decode(from: dictionary)
        }
    }

    @Test("The generation can be read without decoding the payload")
    func generationWithoutDecoding() throws {
        let configuration = RuntimeConfiguration(version: ConfigurationVersion(generation: 99))
        let encoded = try ConfigurationCodec.encode(configuration)

        #expect(ConfigurationCodec.generation(from: encoded) == 99)
    }

    // MARK: - Versioning

    @Test("Generations increase monotonically and wrap safely")
    func generationMonotonic() {
        let first = ConfigurationVersion(generation: 0)
        let second = first.nextGeneration()

        #expect(second.generation == 1)
        #expect(first < second)
        #expect(second.schemaVersion == ConfigurationVersion.currentSchema)

        // &+ rather than +, so a pathological counter cannot trap in the provider.
        #expect(ConfigurationVersion(generation: .max).nextGeneration().generation == 0)
    }

    @Test("Readability is decided by schema version, not generation")
    func readability() {
        #expect(ConfigurationVersion(schemaVersion: 1, generation: .max).isReadable)
        #expect(!ConfigurationVersion(schemaVersion: 99, generation: 0).isReadable)
    }

    // MARK: - Defaults that encode policy

    @Test("Direct fallback is off by default")
    func directFallbackDefaultsOff() {
        // ADR 0003. If this ever flips, selected apps start leaking silently.
        #expect(ProxyConfiguration.default.allowDirectFallback == false)
    }

    @Test("The default upstream is the local SOCKS5 target")
    func defaultUpstream() {
        #expect(ProxyConfiguration.default.endpoint == ProxyEndpoint.localSOCKS5)
        #expect(ProxyConfiguration.default.endpoint.port == 10808)
        #expect(ProxyConfiguration.default.type == .socks5)
    }

    @Test("Rules default to bundle-family matching")
    func defaultMatchMode() {
        // ADR 0006: exact-by-default would silently fail to proxy Electron helpers.
        #expect(AppRule(identity: identity("com.openai.codex")).matchMode == .bundleFamily)
    }

    @Test("Plaintext credential exposure is flagged only for remote proxies")
    func plaintextExposureFlag() {
        let local = ProxyConfiguration(credential: CredentialReference(username: "u"))
        #expect(local.hasPlaintextCredentialExposure == false)

        let remote = ProxyConfiguration(
            endpoint: ProxyEndpoint(host: "proxy.example.com", port: 1080),
            credential: CredentialReference(username: "u")
        )
        #expect(remote.hasPlaintextCredentialExposure)

        let remoteNoAuth = ProxyConfiguration(
            endpoint: ProxyEndpoint(host: "proxy.example.com", port: 1080)
        )
        #expect(remoteNoAuth.hasPlaintextCredentialExposure == false)
    }

    // MARK: - IPC

    @Test("Provider messages round-trip", arguments: [
        ProviderMessage.reloadConfiguration(generation: 7),
        .requestStatus,
        .testProxyConnection,
        .resetStatistics,
        .setDirectFlowLogging(enabled: true),
    ])
    func providerMessageRoundTrip(message: ProviderMessage) throws {
        let data = try ProviderMessageCodec.encode(message)
        #expect(try ProviderMessageCodec.decodeMessage(data) == message)
    }

    @Test("Provider responses round-trip")
    func providerResponseRoundTrip() throws {
        let status = ProviderStatus(
            configurationGeneration: 3,
            isRoutingEnabled: true,
            activeRuleCount: 2,
            activeProxiedFlows: 5,
            directFlowCount: 1000,
            proxiedFlowCount: 42,
            blockedFlowCount: 7,
            lastError: "Proxy unreachable",
            startedAt: nil
        )
        let responses: [ProviderResponse] = [
            .acknowledged,
            .status(status),
            .proxyTestResult(ProxyTestResult(succeeded: true, latency: 0.01, negotiatedMethod: "none")),
            .failure(reason: "boom"),
        ]

        for response in responses {
            let data = try ProviderMessageCodec.encode(response)
            #expect(try ProviderMessageCodec.decodeResponse(data) == response)
        }
    }
}
