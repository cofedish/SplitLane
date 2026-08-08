# CLAUDE.md — SplitLane operational memory

Short, practical, and kept current. Full detail lives in `docs/`. Update this file only when
architecture, build workflow, milestone, constraints, or development rules actually change.

## SplitLane mission

Route traffic from user-selected macOS applications through a configured proxy while leaving every
unselected application completely untouched and DIRECT.

First real target: `Codex.app → SplitLane → SOCKS5 127.0.0.1:10808 → Internet`, with Safari,
Firefox, App Store, `brew`, and everything else staying DIRECT. Codex must launch normally from
Dock/Finder — no wrapper, no `HTTP_PROXY`, no special launcher.

## Current architecture

```
macOS outbound flow
        │
        ▼
NETransparentProxyProvider (SplitLaneProxyExtension, a System Extension)
        │  handleNewFlow(_:) / handleNewUDPFlow(_:initialRemoteFlowEndpoint:)
        ▼
FlowRouter ── asks ──▶ RuleEngine (immutable in-memory snapshot)
        │
   ┌────┴─────────────────────┐
   │                          │
return false             return true
   │                          │
DIRECT (kernel handles)   SplitLane handles it
                              │
                    ┌─────────┴─────────┐
                    │                   │
              TCPFlowRelay          UDP: fail closed
                    │
              SOCKS5Client ──▶ NWConnection ──▶ 127.0.0.1:10808
```

Three modules with a strict one-way dependency graph:

- `SplitLaneCore` — pure Swift, no UI, no NetworkExtension imports in the rule/protocol layer.
  Models, RuleEngine, SOCKS5 protocol codec + state machine, configuration, IPC messages, logging.
  Builds and tests with plain `swift build` / `swift test` (no Xcode needed).
- `SplitLane` (host app) — SwiftUI. Owns extension lifecycle, configuration UI, Keychain.
- `SplitLaneProxyExtension` — the NETransparentProxyProvider system extension. Owns flows only.

## Hard architectural rules

- Project name is SplitLane.
- NETransparentProxyProvider is the MVP architecture.
- Do not introduce PacketTunnel/TUN without an ADR and explicit reason.
- Default for unselected apps is DIRECT.
- Selected apps must never silently fall back to DIRECT.
- TCP-first.
- Selected-app UDP must not silently bypass the proxy.
- Application routing identity is based on verified code signing identity.
- No networking/business logic inside SwiftUI views.
- Prefer Apple frameworks; no third-party dependencies without an ADR.
- Credentials belong in Keychain (never in `providerConfiguration`, JSON, or UserDefaults).
- Structured OSLog; never `print()` in production paths; never log secrets or payloads.
- Git pre-flight before meaningful changes.

## Repository layout

```
Package.swift                 SwiftPM: SplitLaneCore + SplitLaneCoreTests (works without Xcode)
project.yml                   XcodeGen spec -> SplitLane.xcodeproj (generated, git-ignored)
Sources/SplitLaneCore/        Models, Rules, Proxy/SOCKS5, IPC, Configuration, Logging
Tests/SplitLaneCoreTests/     Unit tests for everything pure
SplitLane/                    Host app (App, UI, Services, Resources)
SplitLaneProxyExtension/      Provider, FlowRouter, TCP, UDP, Runtime, Resources
Tools/socks5-testbed/         Docker SOCKS5 server used by integration tests
docs/, docs/adr/              Architecture, networking, threat model, decisions
.claude/skills/               Project-local skills
```

## Build commands

Core (works today, Command Line Tools only — no Xcode required):

```bash
swift build                       # build SplitLaneCore
swift build -c release
swift test                        # all unit tests
Tools/typecheck-targets.sh        # type-check app + extension against the real SDK, no Xcode
```

`Tools/typecheck-targets.sh` is how the app and extension are verified before Xcode exists on the
machine. It catches missing overrides, wrong signatures and concurrency errors — everything short
of linking, signing and embedding.

App + extension (requires full Xcode — see "Current external/manual gates"):

```bash
Tools/generate-project.sh         # regenerate SplitLane.xcodeproj from project.yml
xcodebuild -project SplitLane.xcodeproj -scheme SplitLane -configuration Debug build
xcodebuild -project SplitLane.xcodeproj -list      # discover schemes before inventing args
```

Never hand-edit `project.pbxproj`. It is generated. Edit `project.yml` and regenerate.

## Test commands

```bash
swift test                                       # unit tests, no network
Tools/socks5-testbed/up.sh                       # SOCKS5 on 127.0.0.1:11080 (+11081 auth)
SPLITLANE_SOCKS5_INTEGRATION=1 swift test
Tools/socks5-testbed/down.sh
```

Integration tests are skipped unless `SPLITLANE_SOCKS5_INTEGRATION=1` is set, so `swift test`
stays hermetic by default.

## Git pre-flight

Before every meaningful series of changes:

```bash
git status --short && git branch --show-current && git remote -v
git fetch --all --prune          # if any remote exists
git status -sb
git rev-list --left-right --count HEAD...@{upstream}   # if upstream exists
```

Never run `reset --hard`, `clean -fd`, force push, blind stash/pop, or history rewrite
automatically. On divergence: stop and describe the state. See `docs/GIT_WORKFLOW.md`.

## Current milestone

M0 complete. Core (M6 RuleEngine, M7 SOCKS5) done and tested. App, extension, provider, relay and
XcodeGen spec written and type-checking; none of it has ever run. Blocked on Gate 1 (Xcode) and
Gate 2 (Apple Developer membership) for M1–M4.

Milestones are being worked out of numeric order because the pure layers are verifiable today and
M1–M4 are not. See `docs/ROADMAP.md`.

## Current known limitations

- **DNS resolution is not proxied.** NETransparentProxyProvider cannot intercept port 53 via
  address rules, and connect-by-name flows still resolve locally. The name is forwarded to the
  SOCKS5 server as `ATYP=DOMAIN` when available, but the local DNS query already happened.
  See `docs/THREAT_MODEL.md`.
- **Selected-app UDP is blocked, not proxied.** QUIC/HTTP3 for selected apps fails closed so the
  app falls back to TCP. Apps with no TCP fallback will break.
- **Signing-identifier matching is not cryptographic proof by itself.** See ADR 0002 and
  `docs/THREAT_MODEL.md`; team-identifier verification via audit token is the hardening path.
- Provider downtime (crash/restart) means flows go DIRECT for that window. Fail-open by platform
  design; cannot be prevented from within the provider.
- **The extension target builds in Swift 5 language mode** (strict concurrency still complete).
  Under Swift 6 the only overridable UDP entry point is not visible on the class, so UDP could not
  be handled at all. Verified by compilation; see ADR 0008.
- **UNVERIFIED / highest open risk:** that macOS still dispatches UDP flows to the deprecated
  `handleNewUDPFlow(_:initialRemoteEndpoint:)`. If it does not, selected-app UDP escapes DIRECT
  silently. Must be confirmed at M9 before M10 can pass.

## Current external/manual gates

1. **Xcode is not installed on this machine** (only Command Line Tools; `xcodebuild` unavailable).
   Required for M1 onward. Install from the App Store or developer.apple.com, then
   `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`.
2. **No code signing identity is present** (`security find-identity -v -p codesigning` → 0).
   A paid Apple Developer Program membership is required: the NetworkExtension entitlement
   `com.apple.developer.networking.networkextension` with the `app-proxy-provider-systemextension`
   value is not available to free/personal teams.
3. **System Extension approval** is a user action in System Settings → General → Login Items &
   Extensions → Network Extensions, and on Apple Silicon may require reduced security or a reboot
   for a locally-built, non-notarized extension.

Full instructions: `docs/DEVELOPMENT.md` → "External gates".

## Definition of Done (per milestone)

- Affected targets build with zero new warnings, or accepted warnings are documented.
- Relevant unit tests pass; new logic has tests.
- `git diff` and `git status` inspected; no secrets committed.
- Docs/CLAUDE.md updated if architecture, build, milestone, or constraints changed.
- Report distinguishes: implemented / compiled / unit-tested / integration-tested / manually verified.
  Never claim a level that was not actually reached.

## Available project skills

- `splitlane-architecture` — system architecture, boundaries, routing semantics, anti-patterns.
  Read before any architecture or refactor task.
- `build-and-test` — canonical build/test commands, DerivedData strategy, error triage.
- `network-extension-debug` — sysext/NE diagnostics, entitlements, approval, provider logs.
- `git-project-workflow` — pre-flight, branching, committing, divergence handling.
