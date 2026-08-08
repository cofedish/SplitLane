---
name: splitlane-architecture
description: SplitLane system architecture, module responsibilities, dependency boundaries, routing semantics, fail-closed policy, TCP flow lifecycle, configuration lifecycle, proxy loop prevention, and architectural anti-patterns. Use before any architecture, refactor, or new-subsystem task, and before changing how flows are routed or configuration is delivered.
---

# SplitLane architecture reference

Read this before designing anything. Read `docs/ARCHITECTURE.md`, `docs/NETWORKING.md` and
`docs/THREAT_MODEL.md` before changing anything load-bearing.

## The one-sentence contract

Selected applications go through the proxy or fail; every other application is untouched and
DIRECT.

Every design question resolves against that sentence. If a change makes an unselected app's
traffic take a different path, or lets a selected app's traffic reach the internet outside the
proxy, it is wrong regardless of how convenient it is.

## Routing semantics

```
DEFAULT:            DIRECT      (handleNewFlow returns false — kernel handles it natively)
SELECTED APP:       PROXY       (return true, relay through SOCKS5)
PROXY UNAVAILABLE:  FAIL CLOSED (close the flow; never silently DIRECT)
SELECTED APP UDP:   FAIL CLOSED (until SOCKS5 UDP ASSOCIATE exists)
LOOPBACK / LINK-LOCAL: DIRECT   (always, for any app — loop prevention)
EMPTY SIGNING ID:   DIRECT      (system-process flows)
```

`return false` from `handleNewFlow` is a documented platform guarantee of
`NETransparentProxyProvider`, not something SplitLane implements. That is why "untouched" is
literally true — no socket is recreated, no bytes are copied.

## Module boundaries

```
SwiftUI  ──▶  Application Services  ──▶  SplitLaneCore
SplitLaneProxyExtension            ──▶  SplitLaneCore
```

Never write:

- `SwiftUI → SOCKS5` or `SwiftUI → NE flow handling`
- `SplitLaneProxyExtension → SwiftUI`
- `SplitLaneCore → UI` or `SplitLaneCore/{Rules,Proxy} → NetworkExtension`

`SplitLaneCore` must keep building with `swift build` under Command Line Tools alone. If a change
would make it import NetworkExtension or AppKit, the change belongs in a different module. This is
not stylistic — it is what keeps the logic testable while the app itself is blocked on external
gates.

## Where things live

| Need | Put it in |
|---|---|
| A routing decision | `SplitLaneCore/Rules/RuleEngine` |
| SOCKS5 bytes | `SplitLaneCore/Proxy/SOCKS5` (pure; no NE, no NWConnection) |
| Config shape / validation / coding | `SplitLaneCore/Configuration` |
| Talking to the provider | `SplitLaneCore/IPC` (messages) + host `Services` |
| Flow handling | `SplitLaneProxyExtension` only |
| System extension lifecycle | host `Services/ExtensionManager` |
| Anything a View needs to know | `AppState`, never the View itself |

`SOCKS5Negotiator` is a pure state machine: bytes in, actions out, no I/O. `SOCKS5Client` drives
it over a transport protocol. That separation is what makes the protocol testable without a
network, and it is why the negotiator must never gain a transport reference.

## TCP flow lifecycle

```
handleNewFlow(flow) ─▶ FlowRouter.route(flow)
   .direct ─▶ return false                    ← done, kernel owns it
   .block  ─▶ close flow with .refused, return true
   .proxy  ─▶ return true, then async:
                 flow.openWithLocalFlowEndpoint(nil)     ← MUST complete before read/write
                 NWConnection ─▶ SOCKS5 CONNECT
                    failure ─▶ close flow (FAIL CLOSED)
                    success ─▶ bidirectional ping-pong relay
```

Ping-pong, not eager: one read outstanding per direction, the next read issued only after the
matching write completes. That is the backpressure mechanism and the reason memory per flow is
bounded. Do not "optimise" it into a queue.

Half-close both ways. One broken flow must never affect another or take down the provider — a
crash in the provider fails every selected app open, so error containment here is a security
property, not a robustness nicety.

## Configuration lifecycle

```
UI change ─▶ validate ─▶ bump version ─▶ persist to providerConfiguration
          ─▶ sendProviderMessage(.reloadConfiguration) ─▶ atomic snapshot swap
```

Rules:
- Never read from disk in `handleNewFlow`.
- Never put a secret in `providerConfiguration` — it is root-readable NE preferences. Passwords go
  to the Keychain, referenced by `passwordReference`.
- The provider holds one immutable `RuntimeConfiguration`. Reload replaces the whole value; a lock
  is held only for the pointer swap. In-flight flows keep the snapshot they started with.

## Proxy loop prevention

Three layers, in order of authority:

1. **Platform:** `NENetworkRule` wildcard/nil remote addresses do not match loopback. Documented
   in the header. This is the actual guarantee.
2. **Design:** rules are constructed in exactly one function, so "we never add a loopback rule" is
   auditable in one place.
3. **Defence in depth:** `FlowRouter` returns `.direct` for loopback/link-local remotes regardless
   of app, so a future rule mistake degrades to "not proxied" rather than recursion.

Verification procedure in `docs/NETWORKING.md §3`.

## Anti-patterns

- Disk I/O or `SecCode` evaluation inside `handleNewFlow`.
- Falling back to DIRECT when the proxy is down. That is a leak wearing a resilience costume.
- Blocking the main thread on a reachability test.
- SOCKS5 parsing that subscripts a received buffer directly — use `ByteReader`. A trap in the
  provider is a fail-open for every selected app.
- Raw `hasPrefix` for identifier matching. Match dotted label boundaries (ADR 0006) or
  `com.openai.codexal` matches a rule for `com.openai.codex`.
- Unbounded buffering between flow and upstream.
- Hand-editing `project.pbxproj` — it is generated from `project.yml`.
- Adding a dependency instead of writing the SOCKS5 client.
- Expanding scope before the M10 Codex gate passes.

## Before you change architecture

1. Check whether an ADR already decided it (`docs/adr/`).
2. Verify the Apple API against the installed SDK headers — never from memory. Path in
   `docs/NETWORKING.md §1`.
3. If the SDK contradicts the plan, record assumption → observed behaviour → adjustment in
   `docs/NETWORKING.md` or a new ADR. Do not work around it silently.
4. Update `CLAUDE.md` if a hard rule, the build workflow, or a constraint changed.
