import Testing
import Foundation
@testable import SplitLaneCore

@Suite("RuleEngine")
struct RuleEngineTests {

    // MARK: - Helpers

    private func rule(
        _ signingIdentifier: String,
        action: RouteAction = .proxy,
        matchMode: AppRule.MatchMode = .bundleFamily,
        isEnabled: Bool = true
    ) -> AppRule {
        AppRule(
            identity: AppIdentity(
                signingIdentifier: signingIdentifier,
                teamIdentifier: "ABCDE12345",
                bundleIdentifier: signingIdentifier,
                displayName: signingIdentifier
            ),
            action: action,
            matchMode: matchMode,
            isEnabled: isEnabled
        )
    }

    private func engine(_ rules: [AppRule], routingEnabled: Bool = true) -> RuleEngine {
        RuleEngine(configuration: RuntimeConfiguration(
            rules: rules,
            isRoutingEnabled: routingEnabled
        ))
    }

    private func flow(
        _ signingIdentifier: String,
        host: String? = "example.com",
        address: String? = "93.184.216.34",
        port: UInt16 = 443,
        proto: FlowProtocol = .tcp
    ) -> FlowDescriptor {
        FlowDescriptor(
            sourceSigningIdentifier: signingIdentifier,
            remoteHostname: host,
            remoteAddress: address,
            remotePort: port,
            flowProtocol: proto
        )
    }

    // MARK: - The core contract

    @Test("Unselected applications are DIRECT — the product default")
    func unselectedIsDirect() {
        let engine = engine([rule("com.openai.codex")])
        let decision = engine.decide(for: flow("com.apple.Safari"))

        #expect(decision.action == .direct)
        #expect(decision.reason == .noMatchingRule)
        #expect(decision.matchedRuleID == nil)
    }

    @Test("A selected application's TCP flow is proxied")
    func selectedIsProxied() {
        let engine = engine([rule("com.openai.codex")])
        let decision = engine.decide(for: flow("com.openai.codex"))

        #expect(decision.action == .proxy)
        #expect(decision.matchedRuleID == "com.openai.codex")
        #expect(decision.reason == .exactRule(signingIdentifier: "com.openai.codex"))
    }

    @Test("An empty rule set routes everything DIRECT")
    func emptyRuleSet() {
        #expect(engine([]).decide(for: flow("com.openai.codex")).action == .direct)
    }

    // MARK: - Bundle-family matching (ADR 0006 / G-3)

    @Test("Electron helper processes match their parent rule", arguments: [
        "com.openai.codex.helper",
        "com.openai.codex.helper.Renderer",
        "com.openai.codex.helper.GPU",
        "com.openai.codex.helper.Plugin",
    ])
    func helperProcessesMatch(identifier: String) {
        let engine = engine([rule("com.openai.codex")])
        let decision = engine.decide(for: flow(identifier))

        // This is the case that would silently fail under exact matching: the app appears to work
        // perfectly while every one of its connections goes DIRECT.
        #expect(decision.action == .proxy, "\(identifier) must match its parent rule")
        #expect(decision.matchedRuleID == "com.openai.codex")
        #expect(decision.reason == .bundleFamilyRule(
            ruleIdentifier: "com.openai.codex",
            matchedIdentifier: identifier
        ))
    }

    @Test("Prefix look-alikes do NOT match — matching is on label boundaries", arguments: [
        "com.openai.codexal",
        "com.openai.codex2",
        "com.openai.codexevil",
        "com.openai.codexal.helper",
    ])
    func lookAlikesDoNotMatch(identifier: String) {
        let engine = engine([rule("com.openai.codex")])

        // A naive hasPrefix("com.openai.codex") would let every one of these into the proxy lane.
        // This is the security-relevant half of ADR 0006.
        #expect(engine.decide(for: flow(identifier)).action == .direct,
                "\(identifier) is not a dotted descendant and must not match")
    }

    @Test("Ancestors of a rule do not match its descendants' rule")
    func ancestorsDoNotMatch() {
        let engine = engine([rule("com.openai.codex.helper")])
        #expect(engine.decide(for: flow("com.openai.codex")).action == .direct)
        #expect(engine.decide(for: flow("com.openai")).action == .direct)
    }

    @Test("Exact mode refuses to match helpers")
    func exactModeIsStrict() {
        let engine = engine([rule("com.openai.codex", matchMode: .exact)])

        #expect(engine.decide(for: flow("com.openai.codex")).action == .proxy)
        #expect(engine.decide(for: flow("com.openai.codex.helper")).action == .direct)
    }

    @Test("A more specific rule wins over a general one")
    func mostSpecificRuleWins() {
        let engine = engine([
            rule("com.example.App", action: .proxy),
            rule("com.example.App.helper", action: .direct),
        ])

        #expect(engine.decide(for: flow("com.example.App")).action == .proxy)
        #expect(engine.decide(for: flow("com.example.App.helper")).action == .direct)
        // A descendant of the specific rule follows the specific rule, not the general one.
        #expect(engine.decide(for: flow("com.example.App.helper.Renderer")).action == .direct)
        // A descendant of only the general rule follows it.
        #expect(engine.decide(for: flow("com.example.App.other")).action == .proxy)
    }

    @Test("The ancestor walk is bounded")
    func ancestorWalkIsBounded() {
        let engine = engine([rule("a")])
        // 20 labels: deeper than the walk limit, so no match — and, more importantly, the lookup
        // does not do 20 dictionary probes on the flow path.
        let deep = (0..<20).map { "label\($0)" }.joined(separator: ".")
        #expect(engine.decide(for: flow("a." + deep)).action == .direct)

        // Within the limit, it still matches.
        #expect(engine.decide(for: flow("a.b.c")).action == .proxy)
    }

    // MARK: - Identity edge cases (G-6)

    @Test("An empty signing identifier is always DIRECT")
    func emptyIdentifierIsDirect() {
        let engine = engine([rule("com.openai.codex")])
        let decision = engine.decide(for: flow(""))

        #expect(decision.action == .direct)
        #expect(decision.reason == .unidentifiedSource)
    }

    @Test("An empty-identifier rule can never enter the snapshot")
    func emptyIdentifierRuleIsDropped() {
        // The validator rejects these, but the snapshot drops them too: an empty key would match
        // every unidentified system flow.
        let engine = engine([rule("")])
        #expect(engine.snapshot.activeRuleCount == 0)
        #expect(engine.decide(for: flow("")).action == .direct)
    }

    @Test("A disabled rule does not route")
    func disabledRuleIsInert() {
        let engine = engine([rule("com.openai.codex", isEnabled: false)])
        #expect(engine.decide(for: flow("com.openai.codex")).action == .direct)
        #expect(engine.snapshot.activeRuleCount == 0)
    }

    @Test("Matching is case-sensitive, as signing identifiers are")
    func matchingIsCaseSensitive() {
        let engine = engine([rule("com.openai.codex")])
        #expect(engine.decide(for: flow("com.OpenAI.Codex")).action == .direct)
    }

    // MARK: - Loop prevention (docs/NETWORKING.md §3)

    @Test("Loopback destinations are never proxied", arguments: [
        "127.0.0.1", "127.0.0.53", "127.1", "::1", "::ffff:127.0.0.1",
    ])
    func loopbackIsNeverProxied(address: String) {
        let engine = engine([rule("com.openai.codex")])
        let decision = engine.decide(for: flow("com.openai.codex", host: nil, address: address, port: 10808))

        // Third layer of loop defence: even a selected app talking to the SOCKS5 port goes direct.
        #expect(decision.action == .direct)
        #expect(decision.reason == .localDestination)
    }

    @Test("Link-local destinations are never proxied", arguments: ["169.254.1.1", "fe80::1"])
    func linkLocalIsNeverProxied(address: String) {
        let engine = engine([rule("com.openai.codex")])
        #expect(engine.decide(for: flow("com.openai.codex", host: nil, address: address)).action == .direct)
    }

    @Test("A loopback hostname is treated as local when no address is known")
    func loopbackHostnameIsLocal() {
        let engine = engine([rule("com.openai.codex")])
        let decision = engine.decide(for: flow("com.openai.codex", host: "localhost", address: nil))
        #expect(decision.reason == .localDestination)
    }

    @Test("A routable address is proxied even if the hostname looks local")
    func addressWinsOverHostname() {
        // The address is where packets actually go, so it is authoritative.
        let engine = engine([rule("com.openai.codex")])
        let decision = engine.decide(
            for: flow("com.openai.codex", host: "localhost.example.com", address: "93.184.216.34")
        )
        #expect(decision.action == .proxy)
    }

    // MARK: - UDP fail-closed (ADR 0004 / F-3)

    @Test("A selected application's UDP flow is blocked, never DIRECT")
    func selectedUDPIsBlocked() {
        let engine = engine([rule("com.openai.codex")])
        let decision = engine.decide(for: flow("com.openai.codex", port: 443, proto: .udp))

        // Returning .direct here would be exactly the silent QUIC bypass the design forbids.
        #expect(decision.action == .block)
        #expect(decision.reason == .udpNotSupported)
        #expect(decision.matchedRuleID == "com.openai.codex")
    }

    @Test("An unselected application's UDP flow stays DIRECT")
    func unselectedUDPIsDirect() {
        let engine = engine([rule("com.openai.codex")])
        #expect(engine.decide(for: flow("com.apple.Safari", proto: .udp)).action == .direct)
    }

    @Test("A helper process's UDP flow is blocked too")
    func helperUDPIsBlocked() {
        let engine = engine([rule("com.openai.codex")])
        #expect(engine.decide(for: flow("com.openai.codex.helper", proto: .udp)).action == .block)
    }

    @Test("A rule set to DIRECT does not block its UDP")
    func directRuleDoesNotBlockUDP() {
        let engine = engine([rule("com.openai.codex", action: .direct)])
        #expect(engine.decide(for: flow("com.openai.codex", proto: .udp)).action == .direct)
    }

    @Test("A rule set to BLOCK blocks both transports")
    func blockRuleBlocksEverything() {
        let engine = engine([rule("com.evil.app", action: .block)])
        #expect(engine.decide(for: flow("com.evil.app", proto: .tcp)).action == .block)
        #expect(engine.decide(for: flow("com.evil.app", proto: .udp)).action == .block)
    }

    // MARK: - Master switch

    @Test("Disabling routing makes everything DIRECT")
    func routingDisabled() {
        let engine = engine([rule("com.openai.codex")], routingEnabled: false)

        #expect(engine.decide(for: flow("com.openai.codex")).action == .direct)
        // Notably including UDP: a paused SplitLane must be inert, not half-blocking.
        #expect(engine.decide(for: flow("com.openai.codex", proto: .udp)).action == .direct)
    }

    // MARK: - Snapshot reload

    @Test("A new snapshot replaces the old decisions wholesale")
    func snapshotReload() {
        let before = engine([rule("com.openai.codex")])
        #expect(before.decide(for: flow("com.openai.codex")).action == .proxy)
        #expect(before.decide(for: flow("com.example.Other")).action == .direct)

        let after = engine([rule("com.example.Other")])
        #expect(after.decide(for: flow("com.openai.codex")).action == .direct)
        #expect(after.decide(for: flow("com.example.Other")).action == .proxy)
    }

    @Test("The snapshot carries the proxy configuration and version through")
    func snapshotCarriesConfiguration() {
        let configuration = RuntimeConfiguration(
            version: ConfigurationVersion(generation: 7),
            rules: [rule("com.openai.codex")],
            proxy: ProxyConfiguration(endpoint: ProxyEndpoint(host: "127.0.0.1", port: 10808))
        )
        let snapshot = RuleSnapshot(configuration: configuration)

        #expect(snapshot.version.generation == 7)
        #expect(snapshot.proxy.endpoint.port == 10808)
        #expect(snapshot.activeRuleCount == 1)
    }
}
