# CLAUDE.md — SplitLane for Windows

Read the repository-root `CLAUDE.md` first; it defines the product. This file covers what is
different on Windows. Full detail lives in `windows/docs/`.

## What this is

A port of the SplitLane design to Windows. Same mission, same vocabulary, same guarantees, almost
entirely different mechanism.

```
SplitLane.Core        net10.0            pure — no WPF, no WinDivert, no P/Invoke
SplitLane.Engine      net10.0-windows    elevated — the only component that sees packets
SplitLane.App         net10.0-windows    WPF — never elevated
```

Dependencies run one way: `App → Core`, `Engine → Core`. The core targets plain `net10.0`, so a
Windows-only API would not compile there at all — that is what keeps routing testable with
`dotnet test` alone, the same promise macOS makes about `swift test` and Xcode.

## The one thing to understand first

macOS has `NETransparentProxyProvider`: return `false` from `handleNewFlow` and the kernel keeps the
flow untouched. **Windows has no equivalent.** SplitLane intercepts packets with WinDivert, so
unselected traffic is copied to user mode and reinjected byte-for-byte. It is unmodified. It is not
untouched, and the docs, the README and the Settings page all say so.

Identity also arrives separately from packets: the socket layer gives a process id at connect time,
the network layer gives packets with no process at all. So the routing decision is made in advance
and the packet path is a NAT-table lookup keyed on the source port. See `docs/NETWORKING.md §2`.

## Hard rules, Windows-specific

- Routing keys on the **normalised image path** (ADR W-0002). Never on process name.
- Family matching cuts on the **path separator**, and is **refused for shared directories** — a
  family rule on `C:\Windows\System32` would proxy the operating system (ADR W-0003). The check
  appears in three places on purpose; do not remove any of them.
- The **engine is the only elevated component**. Everything the app can ask it to do is
  `EngineRequestKind`, nine members, none of which names a file, a command or a library.
- Packet rewriting and checksums stay in **pure functions over a buffer** with no WinDivert types in
  the signature. A NAT bug produces a silently hanging connection, not an error, so it has to be
  reachable from a unit test.
- The process cache keys on **(pid, start time)**. A bare pid is reused within seconds.
- Warnings are errors, project-wide.

## Commands

```powershell
cd windows
dotnet build SplitLane.Windows.slnx
dotnet test  SplitLane.Windows.slnx          # 322 tests, no network/driver/elevation needed

SplitLane.Engine.exe --check                 # why the divert layer will not start
SplitLane.Engine.exe --no-divert             # everything except interception
SplitLane.Engine.exe                         # needs an elevated prompt

.\tools\fetch-windivert.ps1                  # downloads the driver, prints its hash to verify
.\tools\uiprobe\uiprobe.ps1 -Exe ... -OutDir ... -Steps @("click:NavProxy","shot:proxy")
```

`uiprobe` drives the app through UI Automation by `AutomationId` and captures screenshots. Because it
prefers automation patterns over synthetic clicks, anything it cannot reach a screen reader cannot
reach either — that is how the bug was found where selecting a sidebar item moved the highlight
without changing the page.

## State

Core, engine and app are written, build with zero warnings, and 322 tests pass. The app has been run,
driven end to end, and screenshotted. The engine has been run in `--no-divert` mode and its control
channel, rule engine, redirect listener and SOCKS5 relay verified against a real proxy.

**Interception works, verified end to end on a live machine.** A selected application's connection
reaches the proxy: the upstream logs `CONNECT example.com:80`, the relay reports the handshake, and
the result is repeatable. The destination arrives as a hostname, so the DNS observer and
`ATYP=DOMAIN` work too. Reproduce with `tools/verify-divert.ps1`.

Three bugs stood in the way, all invisible without instrumentation, and the lesson is the same each
time — **in this codebase a silent failure is the bug**:

- Direction was being asserted on reinjection. WinDivert accepts such a packet and the stack discards
  it, with no error at either end. Rewrite addresses; leave direction alone.
- A packet whose source is one of the machine's own addresses is rejected as a spoof on a physical
  interface. Both endpoints must be loopback.
- **The SYN raced its own routing decision.** The socket event and the packet travel through separate
  queues on separate threads. When the packet loop won, the SYN went out un-redirected and the
  *later* packets were rewritten, breaking an established connection. Only a packet capture found it.
  A SYN now waits briefly for its decision, and a connection is only redirected if its SYN was.

Packaged applications (W-4) now warn in the UI, and there is an MSI plus a GitHub Actions pipeline
that builds it. Not written: a Windows service host, and code signing.

The live run also found three bugs of one family — failures that reported nothing. A failed
`WinDivertRecv` was slept through, a failed `WinDivertSend` was discarded, and console logging could
hang the whole engine from a stray click in an elevated window. All three are fixed, and the lesson
generalises: in this codebase, a silent failure is the bug.

## Definition of Done

Same as the root project, plus: report distinguishes implemented / compiled / unit-tested /
integration-tested / driver-verified, and never claims a level that was not reached.
