# SplitLane

Per-application network routing for macOS. Put selected apps in a proxy lane; leave everything
else alone.

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

Selected apps launch normally from the Dock. No wrapper script, no `HTTP_PROXY`, no launcher.

## What makes it different

**Unselected applications are genuinely untouched.** SplitLane is built on
`NETransparentProxyProvider`, where returning `false` from `handleNewFlow` hands the flow back to
the kernel unmodified. Safari, Firefox, the App Store and `brew` do not get a recreated socket,
a rewritten route, or a copied byte.

**Selected applications never silently fall back to DIRECT.** If the proxy is unreachable, the
connection fails and the UI says so. A silent fallback is a leak the user cannot see, which is
worse than a visible error.

## Status

Early development. `SplitLaneCore` — the rule engine and SOCKS5 implementation — is built and
tested. The app and system extension require a full Xcode install and an Apple Developer
membership, which are tracked as external gates in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md#external-gates).

Milestone-by-milestone state: [docs/ROADMAP.md](docs/ROADMAP.md).

## Requirements

- macOS 15.0 or later, Apple Silicon or Intel
- To build the core: Command Line Tools (`swift build`)
- To build the app: Xcode, plus a paid Apple Developer Program membership — the
  NetworkExtension entitlement is not available to free teams

## Build

```bash
swift build && swift test          # core: works with Command Line Tools alone

xcodegen generate                  # app + extension: needs Xcode
xcodebuild -project SplitLane.xcodeproj -scheme SplitLane build
```

`SplitLane.xcodeproj` is generated from `project.yml` and is not committed.

## Architecture

```
SplitLaneCore              pure Swift — models, rule engine, SOCKS5, configuration, IPC
SplitLane.app              SwiftUI host — extension lifecycle, configuration, Keychain
SplitLaneProxyExtension    NETransparentProxyProvider system extension — flows only
```

Dependencies run one way: `SwiftUI → Services → SplitLaneCore`, and
`SplitLaneProxyExtension → SplitLaneCore`. The core never imports UI or NetworkExtension, which
is what keeps it testable with `swift test` and no Xcode.

## Honest limitations

- **DNS is not proxied.** Name resolution happens before SplitLane sees the flow, and the
  NetworkExtension API prohibits intercepting port 53 by address. A network observer still sees
  which hostnames a proxied app contacts. Reasoning in
  [docs/NETWORKING.md §4](docs/NETWORKING.md); tracked as F-1 in the threat model.
- **Selected-app UDP is blocked, not proxied.** QUIC fails closed so apps fall back to TCP. Apps
  with no TCP fallback will break when selected.
- **Signing-identifier matching is not cryptographic proof.** The impact is asymmetric — a forged
  identifier gets traffic *into* the proxy lane, not out of it — but it is documented as F-2.
- **Provider downtime means DIRECT.** If the extension is not running there is no rule to consult.

The full analysis, including a review of the original specification's own gaps, is in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Documentation

| | |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modules, boundaries, flow and configuration lifecycles |
| [NETWORKING.md](docs/NETWORKING.md) | Verified SDK behaviour, network rules, DNS, UDP, loop prevention |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Security analysis and specification gap analysis |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Build commands, external gates, identifiers |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Build, extension and runtime failure modes |
| [ROADMAP.md](docs/ROADMAP.md) | Milestones M0–M14 |
| [GIT_WORKFLOW.md](docs/GIT_WORKFLOW.md) | Pre-flight, branching, commit and push policy |
| [adr/](docs/adr/) | Architecture decision records |

## License

Not yet chosen.
