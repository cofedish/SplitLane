# SplitLane Threat Model & Specification Gap Analysis

Two parts:

- **Part A** — security analysis of the design as built.
- **Part B** — gaps, contradictions and unsafe assumptions found in the original SplitLane
  specification, with the disposition of each.

Both are grounded in the SDK facts recorded in `docs/NETWORKING.md §1`.

---

## Part A — Threat model

### A.0 What SplitLane promises

> Traffic from a selected application does not reach the internet outside the configured proxy
> lane, and traffic from an unselected application is not touched.

It does **not** promise anonymity, traffic-analysis resistance, or protection against an attacker
with code execution on the machine.

### A.1 Assets

| Asset | Why it matters |
|---|---|
| The routing decision itself | A wrong `.direct` for a selected app is the product's core failure |
| The proxy credential | Grants use of the upstream proxy |
| The selected-app list | Reveals which apps the user wants hidden from their network |
| Connection metadata (Activity) | Destination hostnames for proxied apps |

### A.2 Adversaries

| # | Adversary | In scope |
|---|---|---|
| T1 | Passive network observer (ISP, café Wi-Fi) | **Yes** — the primary adversary |
| T2 | A non-malicious app that leaks around the proxy (QUIC, own resolver) | **Yes** |
| T3 | A malicious unprivileged app on the same Mac | Partially |
| T4 | Root / kernel-level attacker on the same Mac | **No** — game over regardless |
| T5 | The upstream proxy operator | **No** — trusted by definition |

### A.3 Findings

---

#### F-1 · DNS queries for proxied destinations leak to the network observer
**Severity: High · Status: Structural, documented, roadmapped**

The name lookup for a proxied connection happens locally before SplitLane sees the flow. T1 learns
every hostname a "hidden" app contacts, which for most users is the majority of what they wanted
to hide.

Three independent SDK constraints make this unfixable inside a transparent proxy provider — port
53 rules are prohibited, connect-by-name flows explicitly do not bypass resolution, and most DNS
originates from `mDNSResponder` rather than the app. Full reasoning in `docs/NETWORKING.md §4`.

*Mitigated:* `ATYP=DOMAIN` is used whenever `remoteHostname` is available, so the *connection* is
established from the proxy's vantage point and the local resolver's answer is not used for
routing. *Not mitigated:* the query itself.

*Fix path (post-M10):* a companion `NEDNSProxyProvider`, or system-wide DoH via
`NEDNSSettingsManager`. Both are separate providers and separate entitlements.

**This is the single most important thing to state honestly in the product UI.** A user who
believes SplitLane hides an app's activity, and is wrong about DNS, is worse off than a user who
knows.

---

#### F-2 · `sourceAppSigningIdentifier` alone is not proof of identity
**Severity: Medium · Status: Mitigated in design, hardening deferred to M6.5**

Any local binary can be ad-hoc signed with an arbitrary signing identifier
(`codesign -s - -i com.openai.codex ./evil`). A T3 attacker can therefore present themselves as a
selected app.

The consequence is asymmetric, and the asymmetry is what makes this Medium rather than Critical:

- **Impersonating a selected app** ⇒ the attacker's traffic gets *proxied*. They gain use of the
  user's proxy. They do **not** gain a bypass.
- **Impersonating an unselected app** ⇒ DIRECT, which is the default anyway. No gain.

So the failure mode is proxy theft, not leakage — the security property SplitLane exists to
provide is not violated. Note also that an attacker who wants to reach the network directly simply
does so; SplitLane is not, and cannot be, an egress firewall.

*Mitigation in place:* `AppIdentity` records `teamIdentifier` and `signingIdentifier`, both
extracted through `SecStaticCode` at pick time, and both are persisted. The rule stores the team
identifier even though M6 matches only on signing identifier.

*Hardening (M6.5, `FlowIdentityVerifier`):* resolve `sourceAppAuditToken` →
`SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit:)` → validate against a designated
requirement pinning both identifier and team. Because that is far too expensive per flow, it is
cached keyed on `(pid, pidversion)` from the audit token — `pidversion` is what makes the cache
safe against PID reuse. Uncached verification happens once per process, not once per flow.

---

#### F-3 · Selected-app UDP is blocked, which can break apps
**Severity: Medium (availability) · Status: Accepted, surfaced in UI**

Blocking is the correct choice over leaking (see `docs/NETWORKING.md §5`), but an app with no TCP
fallback breaks when selected, and the user needs to understand why. The Applications row shows a
warning when a selected app has had UDP flows refused, so the cause is visible.

---

#### F-4 · Provider downtime silently reverts selected apps to DIRECT
**Severity: Medium · Status: Cannot be fixed in-provider; made visible**

If the extension is not installed, not approved, disabled, or crashed and restarting, there is no
provider to consult and flows take the normal path. The window is small but it is a genuine leak
and it happens exactly when something is already going wrong.

*Mitigation:* Overview shows provider state as the primary status, not a footnote. A selected app
with a non-running provider is rendered as an error state, not as "ON".

*Not attempted:* a kill-switch (e.g. a content filter that blocks selected apps when the proxy is
down) would need a second system extension and a second entitlement. Post-MVP consideration.

---

#### F-5 · Credentials must not be placed in `providerConfiguration`
**Severity: High if violated · Status: Prevented by design**

`providerConfiguration` is a plist in system NE preferences, readable by root and dumped by
`scutil --nc`. It is the obvious place to put a password and the wrong one.

*Design:* `ConfigurationCodec` encodes only a `credentialReference` (an opaque Keychain persistent
reference), never a password. The password reaches the provider through
`NEVPNProtocol.passwordReference`. A unit test asserts that no encoded configuration dictionary
ever contains a password field — that is the enforcement, not a comment.

---

#### F-6 · SOCKS5 username/password auth is plaintext on the wire
**Severity: Low for the localhost target · Status: Documented, warned in UI**

RFC 1929 sends credentials unencrypted. Irrelevant for `127.0.0.1`, relevant the moment a user
points SplitLane at a remote SOCKS5 server. The Proxy screen warns when authentication is
configured with a non-loopback host.

---

#### F-7 · Untrusted input parsing in the SOCKS5 reply path
**Severity: Medium · Status: Mitigated by construction + tests**

The upstream's bytes are attacker-controlled if the proxy is hostile or MITM'd. A naive parser
reading a `DOMAIN` length byte and slicing that many bytes is a crash (Swift traps on out-of-range
slicing, which in a system extension means the provider dies and **every** selected app fails
open on restart — so a parser bug is a security bug here, not just a stability bug).

*Mitigation:* all parsing goes through `ByteReader`, a bounds-checked cursor that returns
`nil`/throws instead of trapping. There is no direct subscripting of received buffers anywhere in
the SOCKS5 layer. Tests cover truncation at every offset, oversized domain lengths, unknown
`ATYP`, unknown method, and reserved-byte violations.

---

#### F-8 · Unbounded buffering between flow and upstream
**Severity: Medium (resource exhaustion) · Status: Mitigated by design**

A fast app writing to a slow proxy, with a relay that reads eagerly and queues, is an unbounded
memory sink in a root process. The relay is strictly ping-pong: one read outstanding per
direction, next read issued only after the corresponding write completes. Memory per flow is
therefore bounded by one buffer per direction.

---

#### F-9 · The selected-app list is not secret
**Severity: Low · Status: Accepted**

Stored in NE preferences, root-readable. Acceptable: a root attacker (T4) is out of scope.

---

#### F-10 · Toggling a rule does not affect established connections
**Severity: Low · Status: Documented**

Turning a rule ON leaves existing connections DIRECT until they close. Users expect a toggle to be
instant. The UI states that new connections are affected; a "restart app to apply fully" hint
appears when a selected app has active DIRECT flows.

---

## Part B — Specification gap analysis

The original spec was substantially correct — the transparent-proxy choice, the DIRECT default,
and the fail-closed rule are all right, and they are the decisions that are expensive to get
wrong. These are the places where it was incomplete, self-contradictory, or unsafe.

---

### G-1 · "TCP → PROXY, UDP → BLOCK" contradicts DNS, as originally stated
**Severity: Would have broken every selected app · Fixed**

Blocking all selected-app UDP blocks UDP/53. An app using its own resolver (Chromium's async DNS,
Go's pure-Go resolver) would have been unable to resolve anything, and the failure would have
looked like "SplitLane breaks Codex" with no obvious cause.

The SDK resolves this in our favour and the spec did not know it: `includedNetworkRules` **may not
contain a port-53 rule at all**, so DNS is structurally outside the intercept set. The policy is
safe as written — but for a reason the spec did not state, and it is worth knowing *why* a design
is safe, because that reason is what tells you when it stops being safe.

*Disposition:* documented in `docs/NETWORKING.md §4–5`. No code change needed. A regression test
would be meaningless here (it is a platform constraint), so the protection is that rule
construction lives in one audited function.

---

### G-2 · Proxy loop prevention was left as "verify there is no recursion"
**Severity: Would have been an infinite loop or a hang · Fixed**

"Explicitly check the absence of recursion" is not a mechanism. The actual answer is a documented
platform guarantee: wildcard-address rules do not match loopback (`NENetworkRule.h`, quoted twice
in `docs/NETWORKING.md §1.4`).

*Disposition:* three-layer defence (platform guarantee → single audited rule-construction site →
`FlowRouter` loopback short-circuit) plus a concrete verification procedure, in
`docs/NETWORKING.md §3`.

---

### G-3 · Electron/helper processes have different signing identifiers
**Severity: Would have made the flagship use case silently not work · Fixed**

The spec's rule engine was `signing identifier ∈ selected apps → PROXY`, exact match. Electron and
Chromium apps do essentially all of their networking from a **helper** process
(`com.example.App.helper`, `…helper.Renderer`, `…helper.Plugin`), not from the main bundle
identifier. With exact matching, the user selects Codex, the provider sees
`com.openai.codex.helper`, misses, and returns DIRECT — the app appears to work perfectly while
being entirely unproxied. **A silent leak that looks like success is the worst possible failure
mode for this product.**

*Disposition:* `RuleEngine` matches exact identifier first, then walks dotted-prefix ancestors up
to a bounded depth. `com.openai.codex.helper.Renderer` matches a rule for `com.openai.codex`.
Match mode is per-rule (`.exact` / `.bundleFamily`, default `.bundleFamily`). Unit-tested,
including the near-miss that must **not** match: `com.openai.codexal` is not a descendant of
`com.openai.codex`. Suffix matching without the dot boundary would be a real vulnerability, so the
boundary is the thing the test targets. See ADR 0006.

---

### G-4 · App Group container is the wrong IPC channel for a system extension
**Severity: Would have wasted a milestone on entitlement debugging · Fixed**

The spec proposed a shared App Group container for configuration. For a macOS **system**
extension this is a known trap: the sysext runs as root with a different container root, and
macOS App Groups need the team-identifier prefix, so the app writes to one path and the extension
reads another and neither errors — it just silently sees an empty config.

*Disposition:* App Group removed from the critical path. Configuration travels via
`providerConfiguration` (authoritative, survives restart, delivered by the system at provider
start) plus `sendProviderMessage` (live reload). Both are verified to exist in the SDK. See
ADR 0005.

---

### G-5 · Credentials in configuration
**Severity: High · Fixed** — see F-5. The spec said "use Keychain" but also described a
configuration model that would naturally carry credentials into `providerConfiguration`. The
codec makes it structurally impossible and a test enforces it.

---

### G-6 · No stated policy for empty `sourceAppSigningIdentifier`
**Severity: Medium · Fixed**

The header says the identifier "may be empty in cases where the flow originates from a system
process". The spec had no rule for this, and an empty string would match an empty-string key if
one ever got into the rule set.

*Disposition:* `RuleEngine` returns `.direct` immediately for an empty identifier, and
`ConfigurationValidator` rejects any rule with an empty signing identifier so such a key can never
exist. Both are unit-tested.

---

### G-7 · Deprecated-API drift on macOS 15
**Severity: Low (warning noise, future breakage) · Fixed**

Nearly every flow API gained an `nw_endpoint_t` replacement in macOS 15.0 and the `NWEndpoint`/
`NWHostEndpoint` forms are deprecated. Following the spec literally would have produced a
warning-laden build, and the project's own rule is that warnings in networking-lifecycle code
matter.

*Disposition:* deployment target macOS 15.0, non-deprecated APIs only.

---

### G-8 · No definition of what happens on provider crash
**Severity: Medium · Documented** — see F-4. Not fixable in-provider; made visible in the UI.

---

### G-9 · Configuration versioning was named but not specified
**Severity: Low · Fixed**

`ConfigurationVersion` appeared in the model list with no semantics. Without a rule, an
older/newer extension paired with a mismatched app would misread the dictionary.

*Disposition:* `ConfigurationVersion` is a monotonic `schemaVersion` + `generation` pair. The
provider refuses a configuration whose `schemaVersion` exceeds what it understands, and reports
the mismatch rather than guessing. Unit-tested round-trip plus forward-incompatibility test.

---

### G-10 · `xcodebuild` was assumed available
**Severity: Blocking for M1+ · Surfaced**

The spec assumed a full Xcode install. This machine has Command Line Tools only, and no code
signing identity. Rather than block, the project is structured so the entire pure layer builds and
tests today via SwiftPM, and the Xcode project is generated from `project.yml` rather than
hand-written.

*Disposition:* recorded as external gates in `CLAUDE.md` and `docs/DEVELOPMENT.md`. See ADR 0007.

---

### G-11 · Free Apple developer accounts cannot ship this
**Severity: Blocking for M3+ · Surfaced**

`com.apple.developer.networking.networkextension` with `app-proxy-provider-systemextension` is not
issuable to a personal team. This is not a signing misconfiguration to debug later; it is a
prerequisite. Documented in `docs/DEVELOPMENT.md` → External gates so it is discovered now rather
than at M3.

---

### G-12 · Activity UI showing DIRECT flows conflicts with "untouched"
**Severity: Low · Clarified**

The spec's Activity mockup lists `Safari … DIRECT`. SplitLane *can* log these, because it is
consulted for every matching flow before returning false — logging the decision costs nothing and
touches nothing. But the volume is large and the value is low.

*Disposition:* DIRECT flows are counted, not enumerated, by default. A "Show direct flows"
diagnostic toggle enumerates them. No extra interception is added for the sake of the UI, per the
spec's own instruction.

---

## Summary

| ID | Issue | Severity | Status |
|---|---|---|---|
| F-1 | DNS leak for proxied apps | High | Structural — documented, roadmapped |
| F-2 | Signing identifier is spoofable | Medium | Asymmetric impact; hardening at M6.5 |
| F-3 | UDP block breaks no-fallback apps | Medium | Accepted, surfaced |
| F-4 | Provider downtime = DIRECT | Medium | Made visible |
| F-5 | Credentials in provider config | High | Prevented + test |
| F-6 | SOCKS5 auth plaintext | Low | Documented, UI warning |
| F-7 | SOCKS5 reply parsing | Medium | Bounds-checked + tests |
| F-8 | Unbounded buffering | Medium | Ping-pong relay |
| F-9 | App list not secret | Low | Accepted |
| F-10 | Toggle vs established conns | Low | Documented |
| G-1 | UDP block vs DNS | Critical if wrong | Safe — reason now known |
| G-2 | Loop prevention unspecified | High | Platform guarantee + 3 layers |
| G-3 | Electron helper identifiers | High | Prefix matching + tests |
| G-4 | App Group IPC | Medium | Replaced |
| G-5 | Credentials in config | High | Structural + test |
| G-6 | Empty signing identifier | Medium | Explicit `.direct` + validator |
| G-7 | Deprecated APIs | Low | macOS 15 target |
| G-8 | Crash behaviour | Medium | Documented |
| G-9 | Config versioning | Low | Specified + tested |
| G-10 | No Xcode | Blocking M1+ | External gate |
| G-11 | No NE entitlement | Blocking M3+ | External gate |
| G-12 | Activity vs untouched | Low | Counted, not enumerated |
