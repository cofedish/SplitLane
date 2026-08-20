# SplitLane for Windows

Per-application network routing for Windows. Put selected applications in a proxy lane; leave
everything else alone.

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
    SOCKS5 127.0.0.1:10808          normal Windows
              │                     networking
              ▼
           Internet
```

Selected applications launch normally from the Start menu. No wrapper script, no `HTTP_PROXY`, no
launcher.

This is the Windows counterpart of the macOS build in the repository root. It is a port of the
design, not of the code: the routing model, the vocabulary and the guarantees are the same, and
almost nothing underneath them is.

## What makes it different

**Selected applications never silently fall back to DIRECT.** If the proxy is unreachable, the
connection fails and the UI says why. A silent fallback is a leak the user cannot see, which is
worse than a visible error.

**Selected-application UDP is refused, not proxied.** QUIC fails closed so applications fall back to
TCP, which is proxied correctly.

**Nothing is intercepted until something needs routing.** With routing paused, or with no enabled
rule pointing at the proxy, no divert handle is open and not one packet is touched.

## How it differs from the macOS build

This is the honest headline, and it is worth reading before anything else.

macOS gives SplitLane `NETransparentProxyProvider`. The provider is handed each new flow and returns
`false` for the ones it does not want, at which point the kernel keeps the flow and **nothing is
recreated, rewritten or copied**. That is what makes "unselected applications are untouched"
literally true there.

Windows has no supported equivalent. What it has is packet interception. So on Windows:

| | macOS | Windows |
|---|---|---|
| Interception point | flow, before a socket exists | packets, via WinDivert |
| Application identity | code signing identifier on the flow | process id at connect time → image path |
| Unselected traffic | never leaves the kernel | copied to user mode and reinjected byte-for-byte |
| Selected TCP | new socket, relayed | destination-NATed to a loopback listener, relayed |
| Selected UDP | flow refused | packets dropped |
| Privilege | system extension + Apple entitlement | administrator + a signed third-party driver |

Unselected applications are **unmodified**, and SplitLane never changes a byte of their traffic. But
they are not *untouched*, and claiming otherwise would be dishonest. The cost is real: on a busy
machine the engine sees every outbound packet. See [docs/NETWORKING.md](docs/NETWORKING.md).

## Requirements

- Windows 10 2004 or later, 64-bit. Windows 11 for the glass interface at its best.
- .NET 10 SDK to build.
- [WinDivert](https://github.com/basil00/WinDivert) 2.2 or later, fetched by a script — not
  committed to this repository.
- Administrator rights to run the engine. The app itself runs as a normal user.

## Build

```powershell
cd windows

dotnet build SplitLane.Windows.slnx      # everything
dotnet test  SplitLane.Windows.slnx      # 327 tests, no network, no driver, no elevation
```

`SplitLane.Core` targets plain `net10.0`, has no package references and P/Invokes nothing, so the
whole routing model is testable with `dotnet test` alone. That mirrors the macOS project's promise
that `swift test` works without Xcode.

## Run

**Installed**, there is nothing to run: the MSI includes the divert driver and registers the engine
as a service that starts with Windows. Open SplitLane and it is already routing.

From a source checkout the driver is not in the tree and the engine is not a service, so:

```powershell
# 1. Fetch the divert driver (once). Verified against a pinned hash.
.\tools\fetch-windivert.ps1

# 2. Check the machine can actually load it. Runs unelevated on purpose.
.\src\SplitLane.Engine\bin\Debug\net10.0-windows\win-x64\SplitLane.Engine.exe --check

# 3. Start the engine from an ELEVATED prompt.
.\src\SplitLane.Engine\bin\Debug\net10.0-windows\win-x64\SplitLane.Engine.exe

# 4. Start the app as a normal user.
.\src\SplitLane.App\bin\Debug\net10.0-windows\SplitLane.exe
```

Without a driver, the engine still runs everything except interception:

```powershell
SplitLane.Engine.exe --no-divert
```

The control channel, the rule engine, the SOCKS5 relay and the redirect listener all work; the UI
says plainly that nothing is being routed. This is how the interface is developed and demonstrated,
and how you can verify your proxy settings before installing a kernel driver.

## Architecture

```
SplitLane.Core        pure C# — models, rule engine, SOCKS5 codec, configuration, IPC contracts
SplitLane.Engine      elevated — WinDivert, NAT redirector, relay, control channel
SplitLane.App         WPF — rules, proxy, activity, settings. Never elevated.
```

Dependencies run one way: `App → Core`, `Engine → Core`. The core imports neither WPF nor WinDivert,
which is what keeps it testable.

The engine is the only component with administrative rights, and the named pipe between the two is
the trust boundary. Everything the app can ask the engine to do is a closed enum with nine members;
there is deliberately no message that names a file to open, a command to run, or a library to load.

## Honest limitations

- **DNS is not proxied.** Windows resolves the name in the DNS Client service before SplitLane sees
  the connection. A network observer still learns which hosts a proxied application contacts. The
  engine sniffs DNS *answers* to recover hostnames for `ATYP=DOMAIN`, which improves CDN behaviour
  and does nothing whatsoever for privacy.
- **Unselected traffic transits user mode.** See the comparison table above. This is the single
  largest behavioural difference from macOS.
- **Selected-application UDP is blocked, not proxied.** Applications with no TCP fallback will break
  when selected.
- **Path matching is not cryptographic proof.** It is stronger than the macOS equivalent — the image
  path comes from the kernel and writing to a Program Files path requires administrator — but the
  publisher is captured and not enforced. Tracked as W-2.
- **Family matching is refused for shared directories.** Ticking "include folder" on a binary in
  `C:\Windows\System32` would put the operating system in the proxy lane, so it is not allowed
  (ADR W-0003).
- **Interception is verified, the rest of the product is young.** A selected application's traffic
  has been confirmed reaching the proxy on a live machine, from the upstream side. What has *not*
  been exercised is everything past a single connection: sustained load, many applications at once,
  IPv6, sleep and resume, or a network that changes underneath it.

## Documentation

| | |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Modules, boundaries, the flow lifecycle |
| [NETWORKING.md](docs/NETWORKING.md) | How interception actually works, and what it costs |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | Security analysis and what is unverified |
| [DEVELOPMENT.md](docs/DEVELOPMENT.md) | Build, run, test, and the UI screenshot harness |
| [adr/](docs/adr/) | Decision records for the Windows-specific choices |
