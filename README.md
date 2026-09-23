# SplitLane

Per-application proxy routing. Traffic from the applications you select goes through a SOCKS5
proxy; every other application goes DIRECT, with its traffic unmodified. Selected applications start
the normal way: no wrapper script, no `HTTP_PROXY`, no special launcher.

**SplitLane works today on Windows.** The client in [`windows/`](windows/) installs from an MSI, runs
as a Windows service, and has routed real traffic on a live machine. The macOS build in the
repository root is the original design and is not finished: its core is tested, but its app and
system extension have never run. See [Status](#status).

![SplitLane for Windows: the Overview page while routing](windows/docs/screenshots/1-overview.png)

## How it works on Windows

Windows offers no user-mode equivalent of the macOS transparent proxy provider, so SplitLane
intercepts packets with [WinDivert](https://github.com/basil00/WinDivert), a signed kernel driver
with a user-mode API. The routing decision is made when a connection is opened, from the process
that opened it; the packet path then only looks that decision up.

```
           outbound connection from any application
                               │
                               ▼
       SplitLane.Engine: LocalSystem service + WinDivert
           socket event ─▶ pid ─▶ image ─▶ identity
                               │
                       RuleEngine.Decide
                               │
      ┌───────────────┬────────┴────────┬───────────────┐
      ▼               ▼                 ▼               ▼
    DIRECT          PROXY             BLOCK            HOLD
                      │
                      ▼
 SOCKS5 CONNECT (TCP) / UDP ASSOCIATE (UDP)
                      │
                      ▼
    configured SOCKS5 proxy ──▶ Internet
```

- **DIRECT**: no rule selects the application, or its rule says DIRECT. Its packets are reinjected
  byte-for-byte.
- **PROXY**: a selected application. The connection is rewritten to a loopback relay inside the
  engine, which carries it to the proxy over SOCKS5; the application's socket never sees the change.
- **BLOCK**: a rule says block, or the file at a rule's recorded location is no longer that
  application.
- **HOLD**: the process claims a rule but its file has not been verified yet. Its packets are dropped
  until verification finishes, then the connection is decided again; the first connection of a new
  build waits about a second.

Three components, with dependencies running one way (`App → Core`, `Engine → Core`):

- **`SplitLane.Core`**: the routing model, rule engine, SOCKS5 codec, configuration and policy. It
  targets plain `net10.0` and calls nothing Windows-specific, so all of routing is testable with
  `dotnet test` alone.
- **`SplitLane.Engine`**: the only privileged component. The MSI installs it as a LocalSystem
  service that starts with Windows. It owns WinDivert, the loopback NAT, the SOCKS5 relay and
  identity verification.
- **`SplitLane.App`**: WPF, never elevated. It talks to the engine over a named pipe that accepts
  eleven fixed request kinds; none of them names a file to open, a command to run or a library to
  load.

**A rule is an application, not a path** ([ADR W-0013](windows/docs/adr/0013-match-applications-by-verified-identity.md)).
A signed application is recognised by its verified Authenticode publisher, product name and file
name; a Store/MSIX application by the package family Windows records in the process token; an
unsigned one by the SHA-256 of its file. A rule therefore keeps matching when an application updates
itself into a new directory or is moved. Unsigned applications are pinned to their exact bytes, so
they have to be selected again after every update.

The guarantees:

- **A selected application never silently falls back to DIRECT.** If the proxy is unreachable, the
  connection fails and the app says why.
- **Selected-application UDP is relayed or dropped, never sent DIRECT**
  ([ADR W-0012](windows/docs/adr/0012-proxy-udp-over-loopback.md)). Datagrams go through a SOCKS5 UDP
  association; when that is impossible (relaying switched off, a proxy that refuses `UDP ASSOCIATE`,
  all 64 lanes in use, or an IPv6 datagram) they are dropped.
- **An unselected application's traffic is never modified.** It is reinjected exactly as it was
  captured; see the first limitation below for what that still costs.

For organisations, an administrator-owned `%ProgramData%\SplitLane\Policy\policy.json` can mandate
rules that users cannot override ([ADR W-0014](windows/docs/adr/0014-managed-policy.md)). The engine
enforces it; the app does not yet show managed rules.

## Status

| | Windows client (`windows/`) | macOS build (repository root) |
|---|---|---|
| Mechanism | WinDivert packet interception, loopback NAT, SOCKS5 relay | `NETransparentProxyProvider` system extension |
| Code | Core, engine service, WPF app and MSI written; builds with warnings as errors | Core, SwiftUI app and extension written; app and extension only type-check |
| Tests | 586 (`dotnet test`): unit and integration, no network, driver or elevation needed | `swift test`: rule engine unit-tested, SOCKS5 unit- and integration-tested |
| Run on a real machine | Yes. TCP interception verified live, including under load (six applications, 600/600 requests proxied); UDP relay verified live on IPv4; the MSI installed, routed through the service, and uninstalled | Never. No line of the app or extension has executed |
| Application identity | Verified-identity rules and managed policy: unit- and integration-tested; not yet run under the driver (`windows/tools/verify-identity.ps1` pending an elevated run); newer than the latest release | Signing-identifier matching, unverified |
| Releases | [v0.1.0 to v0.9.1](https://github.com/cofedish/SplitLane/releases): MSI, portable zip, `SHA256SUMS.txt`. Not code-signed | None |
| Blocked on | Code signing and the gaps in [ENTERPRISE_READINESS.md](windows/docs/ENTERPRISE_READINESS.md) before any fleet use | Xcode, a paid Apple Developer Program membership, System Extension approval |

Not yet exercised on Windows: IPv6 interception, sleep and resume, network changes mid-flow, a reboot
with the service installed, an update installed through the built-in updater, and any version of
Windows other than 11. Details are in
[windows/CLAUDE.md](windows/CLAUDE.md) ("State") and
[windows/docs/DEVELOPMENT.md](windows/docs/DEVELOPMENT.md) ("What is not done"). The macOS
milestones are in [docs/ROADMAP.md](docs/ROADMAP.md).

## Repository layout

```
windows/                       Windows client (the working implementation)
  SplitLane.Windows.slnx
  src/SplitLane.Core/          pure C#: models, rules, identity, policy, SOCKS5, configuration, IPC
  src/SplitLane.Engine/        LocalSystem service: WinDivert, NAT, relay, identity catalog, control pipe
  src/SplitLane.App/           WPF app, never elevated
  src/Shared/                  identity readers compiled into both App and Engine
  tests/                       SplitLane.Core.Tests, SplitLane.Engine.Tests
  installer/                   WiX 5 MSI sources
  tools/                       driver fetch, installer build, SOCKS5 testbed, live verification scripts
  docs/, docs/adr/             Windows architecture, networking, threat model, decisions

Package.swift                  macOS: SwiftPM package for SplitLaneCore
project.yml                    macOS: XcodeGen spec for the app and extension (project is generated)
Sources/SplitLaneCore/         macOS: models, rule engine, SOCKS5, configuration, IPC
Tests/SplitLaneCoreTests/      macOS: unit tests, plus opt-in SOCKS5 integration tests
SplitLane/                     macOS: SwiftUI host app
SplitLaneProxyExtension/       macOS: NETransparentProxyProvider system extension
Tools/                         macOS: project generation, SDK type-check, Docker SOCKS5 testbed
docs/, docs/adr/               macOS architecture, networking, threat model, roadmap, decisions
```

The two builds share the routing model and its vocabulary, not code.

## Quick start (Windows)

**Install.** Download the MSI from [Releases](https://github.com/cofedish/SplitLane/releases), run
it, and open SplitLane. The driver is included and the engine is registered as a service, so there
is nothing else to start. Installing needs administrator rights; running does not. Requires Windows
10 2004 or later, 64-bit. The binaries are not code-signed, so SmartScreen will warn: check the
download against `SHA256SUMS.txt` from the same release. The latest release, v0.9.1, predates
verified-identity rules: it matches applications by executable path, and Store applications by
package family.

**Build from source** (needs the .NET 10 SDK):

```powershell
cd windows
dotnet build SplitLane.Windows.slnx
dotnet test  SplitLane.Windows.slnx      # 586 tests, no network, no driver, no elevation
```

Running a source build needs the driver (`.\tools\fetch-windivert.ps1`) and an elevated prompt for
the engine; [windows/README.md](windows/README.md) has the steps, including `--no-divert`, which runs
everything except interception.

**macOS:** the core builds and tests with `swift build && swift test` on Command Line Tools alone.
The app and extension need Xcode and a paid Apple Developer membership; see [CLAUDE.md](CLAUDE.md)
and [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md#external-gates).

## Documentation

| Windows | |
|---|---|
| [windows/README.md](windows/README.md) | Screenshots, requirements, running, how it differs from macOS |
| [ARCHITECTURE.md](windows/docs/ARCHITECTURE.md) | Modules, the routing path, application identity |
| [NETWORKING.md](windows/docs/NETWORKING.md) | How interception works, and what it costs |
| [THREAT_MODEL.md](windows/docs/THREAT_MODEL.md) | Security analysis, and what a live run established |
| [ENTERPRISE_READINESS.md](windows/docs/ENTERPRISE_READINESS.md) | What stands between this and a managed fleet |
| [DEVELOPMENT.md](windows/docs/DEVELOPMENT.md) | Build, run, verify, package, CI |
| [adr/](windows/docs/adr/) | Windows decision records, including identity (W-0013) and managed policy (W-0014) |

| macOS | |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modules, boundaries, flow and configuration lifecycles |
| [NETWORKING.md](docs/NETWORKING.md) | Verified SDK behaviour, DNS, UDP, loop prevention |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Security analysis and specification gap analysis |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Build commands, external gates, identifiers |
| [ROADMAP.md](docs/ROADMAP.md) | Milestones M0 to M14 |
| [adr/](docs/adr/) | macOS decision records |

## Honest limitations (Windows)

- **Unselected traffic passes through user mode.** While the engine is routing, every outbound TCP
  and UDP packet on the machine (loopback aside) is copied to the engine and reinjected unmodified,
  including while routing is paused. Unmodified, not untouched. See
  [NETWORKING.md](windows/docs/NETWORKING.md) §5.
- **DNS is not proxied** when an application resolves names through Windows' DNS Client: the local
  resolver and network see which hosts a selected application looks up, and names that are blocked
  locally or exist only on the proxy's side do not resolve. Accepted for the intended use; what it
  costs and when proxied DNS is really needed is in §7 of the same document.
- **Engine downtime means DIRECT.** If the service is stopped, crashed, upgrading or not yet started,
  selected applications go DIRECT: when the engine exits, its interception goes with it. The gap is
  short: the service is set to restart on failure, and a running engine restarts routing itself if its
  interception threads die ([ENTERPRISE_READINESS.md](windows/docs/ENTERPRISE_READINESS.md)).
- **Selected-application UDP that cannot be relayed is dropped**, so an application with no TCP
  fallback then fails rather than leaking. IPv6 UDP is always dropped.
- **Identity is checked on the file on disk, not on the running image.** Tricks that make the two
  differ need local code execution; application control (WDAC/AppLocker) is the defence (W-2 in
  [THREAT_MODEL.md](windows/docs/THREAT_MODEL.md)).
- **Not ready for fleet deployment.** Unsigned binaries, no health reporting, no fail-closed state
  while the engine is down, and no managed-rule UI. See
  [ENTERPRISE_READINESS.md](windows/docs/ENTERPRISE_READINESS.md).

The macOS build's limitations are in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## License

Not yet chosen. The Windows packages redistribute WinDivert unmodified, with its own licence; see
[ADR W-0009](windows/docs/adr/0009-ship-the-driver-in-the-package.md).
