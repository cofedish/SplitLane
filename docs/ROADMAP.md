# SplitLane Roadmap

The gate that matters is **M10**: Codex end-to-end through SOCKS5 with nothing else disturbed.
Everything before it is in service of that. Nothing after it starts before it passes.

## Status

| Milestone | State |
|---|---|
| M0 · Repository bootstrap | ✅ done |
| M1 · Native host app shell | ⛔ blocked — Gate 1 (Xcode) |
| M2 · Transparent proxy extension skeleton | ⛔ blocked — Gate 1, Gate 2 |
| M3 · Extension lifecycle | ⛔ blocked — Gate 2, Gate 3 |
| M4 · Flow diagnostics | ⛔ blocked — Gate 3 |
| M5 · Application picker and identity | 🟡 core done, UI blocked |
| M6 · Rule Engine | ✅ done (unit-tested) |
| M6.5 · Audit-token identity hardening | ⬜ planned |
| M7 · SOCKS5 client | ✅ done (unit + integration tested) |
| M8 · TCP relay | 🟡 written, not runtime-verified |
| M9 · UDP leak prevention | 🟡 written, not runtime-verified |
| M10 · **Codex end-to-end gate** | ⛔ blocked |
| M11 · Runtime rule reload | 🟡 written, not runtime-verified |
| M12 · Proxy configuration UI | ⬜ |
| M13 · Activity UI | ⬜ |
| M14 · Menu bar UX | ⬜ |

Milestones are being worked out of numeric order because the pure-Swift layers (M5 core, M6, M7)
are fully buildable and testable on this machine today, while M1–M4 require Xcode and an Apple
Developer account. Ordering by what can actually be verified beats ordering by number. See
`docs/DEVELOPMENT.md` → External gates.

"Written, not runtime-verified" means the code exists and compiles as part of the extension target
but has never handled a real flow. It is not done.

---

## M0 · Repository bootstrap ✅

Repo, `.gitignore`, `CLAUDE.md`, docs, ADRs, project-local skills, verified architecture,
SDK-grounded networking notes, threat model and spec gap analysis.

## M1 · Native host app shell

Minimal SwiftUI `SplitLane.app` with the five-item sidebar. No networking.
**DoD:** `xcodebuild` succeeds; the app launches; the shell exists.

## M2 · Transparent proxy extension skeleton

`SplitLaneProxyExtension` target, correct bundle identifiers, embedding in
`Contents/Library/SystemExtensions`, NE + SystemExtension capabilities, entitlements, signing.
**DoD:** both targets build; the extension is correctly embedded; the signing structure is valid
enough to attempt activation.

## M3 · Extension lifecycle

`OSSystemExtensionRequest` activation, approval-state handling, `NETransparentProxyManager`
configuration, start/stop/status, error reporting.
**DoD:** the provider activates and starts on this Mac, or the repo is cleanly stopped at a real
approval/signing gate with the exact manual action written down.

## M4 · Flow diagnostics

No proxying. Log `sourceAppSigningIdentifier`, audit token, `remoteHostname`, remote endpoint,
flow type, timestamp. All traffic continues normally.
**DoD:** flow attribution verified against at least Codex, Safari, and one other app; internet
still works; **Codex's real signing identifier(s) recorded**, including helper processes — this is
what validates the G-3 prefix-matching decision against reality.

## M5 · Application picker and identity

`+ Add Application` via `NSOpenPanel`; extract display name, bundle identifier, signing
identifier, team identifier, path, icon; persist the rule.
**DoD:** Codex can be added; the rule persists; the identity matches M4's runtime observation.
*Core (`ApplicationInspector`, `AppIdentity`) is done; the UI needs Gate 1.*

## M6 · Rule Engine ✅

Selected → PROXY, unselected → DIRECT, with bundle-family matching for helper processes.
**DoD met:** exact and family matching, near-miss rejection, empty-identifier handling, loopback
short-circuit, and snapshot reload are unit-tested.

## M6.5 · Audit-token identity hardening

`FlowIdentityVerifier`: audit token → `SecCodeCopyGuestWithAttributes` → designated-requirement
validation pinning signing identifier **and** team identifier, cached on `(pid, pidversion)`.
Addresses F-2. Requires a live provider, so it follows M4.

## M7 · SOCKS5 client ✅

Method negotiation, NO AUTH, RFC 1929 username/password, CONNECT, IPv4/IPv6/DOMAIN, reply
parsing, timeouts, cancellation, structured errors, bounds-checked parsing.
**DoD met:** unit tests pass; real connections through Dante in Docker succeed for no-auth,
username/password, domain, IPv4, and the failure paths.

## M8 · TCP relay

`NEAppProxyTCPFlow ⇄ TCPFlowRelay ⇄ SOCKS5Client ⇄ NWConnection`, bidirectional, half-close,
ping-pong backpressure.
**DoD:** a selected TCP flow traverses SOCKS5; closure works; proxy failure closes the flow
without crashing the provider.

## M9 · UDP leak prevention

Selected-app UDP fails closed. Verify the target app falls back to TCP.
**DoD:** selected-app traffic cannot silently escape over unsupported UDP.

## M10 · Codex end-to-end gate ⭐

SOCKS5 `127.0.0.1:10808`, Codex selected. Verify: Codex launches from Dock and works; HTTPS and
WebSocket traffic work; selected TCP goes through SOCKS5; no silent bypass; Safari/Firefox/brew
stay DIRECT; toggling OFF restores normal networking; toggling ON needs no launcher; restarting
Codex keeps routing working.

Proof must come from SplitLane structured logs, provider flow metadata, and observable upstream
connections. "The Codex UI loaded" is not proof.

## After M10

SOCKS5 UDP ASSOCIATE, real UDP proxying, DNS lane (F-1), multiple lanes, BLOCK lane, multiple
upstreams, profiles, domain overrides, launch at login, advanced activity, kill-switch (F-4).

Explicitly **not** before M10: VLESS, Xray embedding, subscriptions, Clash rules, geo routing,
country databases, cloud sync, iOS, statistics DB, charts, auto-update, localization, themes.
