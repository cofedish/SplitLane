# SplitLane Architecture

## 1. Mission

Route traffic from user-selected macOS applications through a configured proxy while leaving every
unselected application completely untouched and DIRECT.

```
                         SplitLane
                            │
                 identify source application
                            │
              ┌─────────────┴─────────────┐
              │                           │
        selected app                unselected app
              │                           │
          PROXY lane                 DIRECT lane
              │                           │
              ▼                           ▼
    SOCKS5 127.0.0.1:10808          normal macOS
              │                     networking
              ▼
           Internet
```

## 2. Why NETransparentProxyProvider

The decisive property is documented by Apple in `NETransparentProxyProvider.h`:

> Returning NO from `handleNewFlow:` and `handleNewUDPFlow:initialRemoteEndpoint:` causes the flow
> to proceed to communicate directly with the flow's ultimate destination, instead of closing the
> flow with a "Connection Refused" error.

This is exactly the reverse-split-routing semantic SplitLane needs, and it is a platform
guarantee rather than something we implement. `NEAppProxyProvider` (the superclass) refuses such
flows instead; `NEPacketTunnelProvider` would force us to own a TUN device and a full TCP/IP
stack. See ADR 0001.

Consequences we accept:

- The provider is consulted for every flow matching `includedNetworkRules`, even ones it will not
  handle. The decision must therefore be O(1) and allocation-light.
- "Untouched" means *the kernel routes it normally*, not *the provider never saw it*. No socket is
  recreated and no data is copied for DIRECT flows.

## 3. Runtime topology

```
┌─────────────────────────────── SplitLane.app (user) ───────────────────────────────┐
│                                                                                     │
│  SwiftUI views ──▶ AppState ──▶ Services                                            │
│                                   ├── ExtensionManager     (OSSystemExtensionRequest)│
│                                   ├── ConfigurationService (NETransparentProxyManager)│
│                                   ├── ApplicationInspector (Security.framework)      │
│                                   └── KeychainService      (Security.framework)      │
│                                            │                                         │
└────────────────────────────────────────────┼─────────────────────────────────────────┘
                                             │
              NE preferences (providerConfiguration) + sendProviderMessage
                                             │
┌────────────────────────── SplitLaneProxyExtension (root) ──────────────────────────┐
│                                             ▼                                       │
│  TransparentProxyProvider                                                           │
│      ├── ProviderRuntime      immutable RuntimeConfiguration snapshot, atomic swap  │
│      ├── FlowRouter           flow ──▶ RouteAction                                  │
│      ├── TCPFlowRelay         NEAppProxyTCPFlow ⇄ SOCKS5Client ⇄ NWConnection       │
│      └── UDPFlowHandler       fail-closed for selected apps                         │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                             │
                                             ▼
                                   SOCKS5 127.0.0.1:10808
```

The host app is a normal user-space GUI app. The extension is a system extension installed into
`/Library/SystemExtensions` and run by `nesessionmanager` as root. They share no memory and no
filesystem container on the critical path (see ADR 0005) — only NE preferences and provider
messages.

## 4. Modules and dependency boundaries

```
SwiftUI  ──▶  Application Services  ──▶  SplitLaneCore
SplitLaneProxyExtension            ──▶  SplitLaneCore
```

Forbidden, enforced by review and by module membership:

| Forbidden                                  | Why |
|--------------------------------------------|-----|
| `SwiftUI → raw SOCKS5 implementation`       | Protocol code must be testable headless |
| `SwiftUI → direct NE flow handling`         | Views must not own network lifecycle |
| `SplitLaneProxyExtension → SwiftUI`         | The extension has no UI and must stay small |
| `SplitLaneCore → UI`                        | Core must build and test without AppKit |
| `SplitLaneCore/Rules,Proxy → NetworkExtension` | Keeps the rule engine and SOCKS5 codec unit-testable |

`SplitLaneCore` is a SwiftPM library so that `swift build` / `swift test` work with only the
Command Line Tools installed. This is deliberate: the majority of the logic that can actually
contain bugs is testable without Xcode, without signing, and without an approved system extension.

### SplitLaneCore contents

| Area | Types |
|------|-------|
| `Models` | `AppIdentity`, `AppRule`, `RouteAction`, `ProxyEndpoint`, `ProxyConfiguration`, `ConnectionEvent`, `ConnectionState`, `RuntimeConfiguration`, `ConfigurationVersion` |
| `Rules` | `RuleEngine`, `RuleSnapshot`, `FlowDescriptor` |
| `Proxy/SOCKS5` | `SOCKS5Address`, `SOCKS5Request`, `SOCKS5Reply`, `SOCKS5Handshake`, `SOCKS5Negotiator` (pure state machine), `SOCKS5Client` (transport-driven), `ByteReader` |
| `Configuration` | `ConfigurationCodec`, `ConfigurationValidator` |
| `IPC` | `ProviderMessage`, `ProviderResponse` |
| `Logging` | `SplitLaneLog` category factory |

## 5. Routing semantics

```
DEFAULT:            DIRECT
SELECTED APP:       PROXY
PROXY UNAVAILABLE:  FAIL CLOSED (never silent DIRECT)
```

`RuleEngine.decide(for:)` is a pure function of an immutable snapshot:

```swift
func decide(for flow: FlowDescriptor) -> RouteDecision
```

Lookup is a dictionary hit on the signing identifier plus, when the exact key misses, a bounded
walk up dotted-prefix ancestors to catch helper processes (`com.example.App.helper` matching a
rule for `com.example.App`). No disk I/O, no code-signature evaluation, no allocation of
collections per flow. See ADR 0006 for why prefix matching is required.

## 6. Configuration lifecycle

```
UI change
   │
   ▼ validate            ConfigurationValidator — reject bad host/port/empty rules
   ▼ version bump        ConfigurationVersion (monotonic)
   ▼ persist             NETransparentProxyManager.protocolConfiguration.providerConfiguration
   ▼ notify              NETunnelProviderSession.sendProviderMessage(.reloadConfiguration)
   ▼ atomic swap         ProviderRuntime replaces the immutable snapshot in one store
```

The provider never reads JSON from disk per flow. It holds one immutable
`RuntimeConfiguration` value; reload replaces the whole value behind a lock held only for the
pointer swap. In-flight flows keep the snapshot they started with.

Secrets never enter `providerConfiguration` — it is stored in system NE preferences and is
readable by root. The proxy password lives in the Keychain and is referenced by
`NEVPNProtocol.passwordReference` (a `kSecClassGenericPassword` persistent reference), which is
the Apple-sanctioned channel for handing a credential to a provider.

## 7. TCP flow lifecycle

```
handleNewFlow(flow)
   │
   ├─ decision == .direct ──▶ return false          (kernel takes over; we never touch it)
   │
   ├─ decision == .block  ──▶ close flow, return true
   │
   └─ decision == .proxy
         │
         ▼ return true, then asynchronously:
         flow.openWithLocalFlowEndpoint(nil) ─────────── must complete before any read/write
         NWConnection to SOCKS5 upstream
         SOCKS5 CONNECT (DOMAIN if remoteHostname is present, else IP)
         │
         ├─ any failure ──▶ closeReadWithError / closeWriteWithError  (FAIL CLOSED)
         │
         └─ success ──▶ bidirectional relay until EOF on both sides
```

Half-close is honoured in both directions: EOF from the app closes the write side of the upstream
connection, EOF from upstream closes the read side of the flow. One broken flow never affects
another and never takes down the provider — every relay owns its own state and errors are
contained.

## 8. Proxy loop prevention

This is a platform guarantee, not a heuristic. From `NENetworkRule.h`:

> If the address is a wildcard address (0.0.0.0 or ::) then the rule will match all destinations
> **except for loopback** (127.0.0.1 or ::1). To match loopback traffic set the address to the
> loopback address.

SplitLane's `includedNetworkRules` use wildcard remote addresses, so loopback destinations are
outside the intercept set by construction. The extension's own `NWConnection` to
`127.0.0.1:10808` therefore cannot be re-intercepted. SplitLane additionally never installs a
loopback-matching rule. Detail and verification procedure in `docs/NETWORKING.md`.

## 9. Architectural anti-patterns

- Reading configuration from disk inside `handleNewFlow`.
- Doing `SecCode` evaluation per flow without a cache.
- Falling back to DIRECT when the proxy is down (that is a leak, not resilience).
- Blocking the main thread on a proxy reachability test.
- Putting SOCKS5 byte parsing anywhere near NE flow objects or SwiftUI.
- Growing an unbounded buffer between flow and upstream instead of applying backpressure.
- Hand-editing `project.pbxproj`.
- Adding a dependency to avoid writing 400 lines of SOCKS5.

## 10. Deferred by design

Full UDP proxying (SOCKS5 UDP ASSOCIATE), multiple upstreams, BLOCK lane UI, profiles, domain
overrides, geo routing, subscriptions, statistics database, localization. None of these are
started before the Codex end-to-end gate (M10) passes. See `docs/ROADMAP.md`.
