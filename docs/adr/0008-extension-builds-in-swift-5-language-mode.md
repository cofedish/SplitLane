# ADR 0008 — The proxy extension builds in Swift 5 language mode

**Status:** Accepted · **Date:** 2026-08-08

## Context

`SplitLaneCore` and the host app build in Swift 6 language mode. The proxy extension cannot,
and the reason is specific rather than general reluctance.

Handling UDP flows is mandatory. If the provider does not decide on a UDP flow, that flow goes out
DIRECT — so a selected application's QUIC/HTTP3 traffic would bypass the proxy silently, which is
the exact failure ADR 0003 and ADR 0004 exist to prevent.

The only entry point for UDP flows is `handleNewUDPFlow`. Three variants were tested against the
installed macOS 15.5 SDK (Swift 6.1.2), by compilation rather than by reading documentation:

| Attempt | Result |
|---|---|
| `override func handleNewUDPFlow(_:initialRemoteFlowEndpoint:)` — the macOS 15 replacement, `Network.NWEndpoint` | **"method does not override any method from its superclass"**, in both Swift 5 and Swift 6. `swift-api-digester` shows this method with no owning class: it is imported as an extension member, and Swift cannot override those. |
| `@objc(handleNewUDPFlow:initialRemoteFlowEndpoint:)` declared directly | **"method cannot be marked @objc because the type of the parameter cannot be represented in Objective-C"** — `Network.NWEndpoint` is a Swift-only enum. |
| `override func handleNewUDPFlow(_:initialRemoteEndpoint:)` — deprecated, `NetworkExtension.NWEndpoint` | **Compiles in Swift 5. Fails in Swift 6**, where the method is absent from the class entirely (the compiler offers no "potential overridden method" note at all, whereas in Swift 5 it names it). |

So under Swift 6 there is no way, from Swift, to handle a UDP flow in an `NEAppProxyProvider`
subclass.

## Decision

1. The `SplitLaneProxyExtension` target sets `SWIFT_VERSION = 5.0`.
2. `SWIFT_STRICT_CONCURRENCY = complete` stays on, so Swift 6's concurrency diagnostics still
   apply — as warnings rather than errors.
3. `SplitLaneCore` and the host app remain Swift 6.
4. The UDP override lives in its own file that does **not** `import Network`. NetworkExtension
   re-exports Network and both define `NWEndpoint`, which makes even the qualified
   `NetworkExtension.NWEndpoint` ambiguous ("ambiguous type name 'NWEndpoint' in module
   'NetworkExtension'"). Keeping Network out of that one file is what makes the signature
   expressible.

## Rationale

Correct UDP handling is worth more than a language-mode number on one target. Losing it would
reintroduce the silent QUIC bypass, and a silent leak is the worst failure this product can have.

Keeping `-strict-concurrency=complete` means almost nothing is actually given up: the concurrency
model is still checked, just not enforced as hard errors. The extension currently type-checks with
**zero** warnings under that setting.

Confining the deprecated API to one small file keeps the blast radius small and makes the eventual
migration a single-file change.

## Consequences

- Two language modes in one repository. Documented here, in `project.yml`, in `CLAUDE.md`, and in
  the file itself, so it does not read as an oversight.
- The extension depends on a deprecated API. Deprecated is not removed, and the fallback if it
  ever is removed is an Objective-C shim implementing the modern selector and forwarding into
  Swift — about twenty lines, but it drags a bridging header into the target, which is why it is
  the fallback rather than the first choice.
- **UNVERIFIED, and the most important open risk in the project:** that macOS 15.x still dispatches
  UDP flows to the deprecated selector. The assumption is that the framework's implementation of
  the new selector forwards to the old one, which is Apple's usual source-compatibility pattern.
  If it does not, selected-app UDP escapes DIRECT and the fail-closed guarantee is quietly broken —
  with no error anywhere.

  **M9 experiment:** select a QUIC-capable app, generate UDP/443 traffic, and confirm a
  `BLOCK udp` line appears in
  `log stream --predicate 'subsystem == "dev.cofe.splitlane" AND category == "routing"'`.
  Absence of that line means the override is dead code and the Objective-C shim is required.
  This must be checked before M10 can be called passed.

## Revisiting

Re-test the Swift 6 override on every macOS and Xcode update. If Apple makes the modern method a
real class member, this ADR is superseded: delete the deprecated override, drop the file's import
restriction, and move the target to Swift 6.
