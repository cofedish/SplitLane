# CLAUDE.md — SplitLane for Windows

Read the repository-root `CLAUDE.md` first; it defines the product. This file covers what is
different on Windows. Full detail lives in `windows/docs/`.

## What this is

A port of the SplitLane design to Windows. Same mission, same vocabulary, same guarantees, almost
entirely different mechanism.

```
SplitLane.Core        net10.0            pure — no WPF, no WinDivert, no P/Invoke
SplitLane.Engine      net10.0-windows    a LocalSystem service — the only component that sees packets
SplitLane.App         net10.0-windows    WPF — never elevated
```

The engine is installed as a Windows service and starts with the machine, so opening SplitLane is
one action. It used to be two: run the engine as administrator, then open the application. The
privilege split is right and stays; what was wrong was making the person perform it.

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
- Family matching **climbs out of a versioned directory**. An application selected in
  `Discordpp-1.0.9250` must still be routed from `Discordpp-1.0.9254`, or every self-update
  silently drops it back to DIRECT - which is what happened, in front of a user, to Discord. The
  detection is narrow on purpose (`app-1.2.3` and `1.2.3`, nothing else): every level climbed widens
  what a family rule captures.
- Family matching cuts on the **path separator**, and is **refused for shared directories** — a
  family rule on `C:\Windows\System32` would proxy the operating system (ADR W-0003). The check
  appears in three places on purpose; do not remove any of them.
- The **engine is the only elevated component**, and runs as `LocalSystem`. Everything the app can
  ask it to do is `EngineRequestKind`, nine members, none of which names a file, a command or a
  library. The control channel's ACL was built for this: LocalSystem full control, interactive user
  read and write, so neither side gains anything from the other.
- The **driver is in the package, and so is its licence** (ADR W-0009). `build-installer.ps1`
  fetches it against a pinned SHA-256 and refuses to produce a package without
  `WinDivert-LICENSE.txt` beside the binaries. WinDivert is LGPLv3 or GPLv2, redistributed
  unmodified and reached through P/Invoke; `THIRD-PARTY-NOTICES.txt` names it, quoting
  upstream rather than paraphrasing it.
- Packet rewriting and checksums stay in **pure functions over a buffer** with no WinDivert types in
  the signature. A NAT bug produces a silently hanging connection, not an error, so it has to be
  reachable from a unit test.
- The process cache keys on **(pid, start time)**. A bare pid is reused within seconds.
- Warnings are errors, project-wide.

## Commands

```powershell
cd windows
dotnet build SplitLane.Windows.slnx
dotnet test  SplitLane.Windows.slnx          # 344 tests, no network/driver/elevation needed

SplitLane.Engine.exe --check                 # why the divert layer will not start
SplitLane.Engine.exe --no-divert             # everything except interception
SplitLane.Engine.exe                         # needs an elevated prompt

.\tools\fetch-windivert.ps1                  # source checkouts only; the package ships it
.\tools\uiprobe\uiprobe.ps1 -Exe ... -OutDir ... -Steps @("click:NavProxy","shot:proxy")
```

```powershell
.\tools\verify-divert.ps1                    # does one connection reach the proxy
.\tools\stress-divert.ps1 -Apps 6 -Requests 100 -Concurrency 25 -PayloadKb 1024
.\tools\measure-direct-cost.ps1              # what an unselected application pays, in ms
```

The last two need an elevated prompt and clean up after themselves. Each prints which engine binary
it ran and when it was built, because a stale one once made a fix look like it did nothing.

`uiprobe` drives the app through UI Automation by `AutomationId` and captures screenshots. Because it
prefers automation patterns over synthetic clicks, anything it cannot reach a screen reader cannot
reach either — that is how the bug was found where selecting a sidebar item moved the highlight
without changing the page.

## State

Core, engine and app are written, build with zero warnings, and 344 tests pass. The app has been run,
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

**It holds up under load.** Six applications at once, 100 requests each, 25 in flight, 1 MB
responses: 600/600 proxied, every payload intact, 600 MB at 20 MB/s, no send failures, and the
unselected control 0/100 - it was aimed at TEST-NET, which routes nowhere, so a control that
succeeded would have meant traffic reaching a destination without the proxy. `tools/stress-divert.ps1`.

The load test then found a cost nobody had measured. A SYN with no routing decision waits for one,
and a DIRECT decision was recorded nowhere, so the packet loop could not tell "not decided yet" from
"decided to leave alone" - and every connection an unselected application opened waited out the full
window. Measured: **8.16 ms per connection, against 0.68 ms with the engine down**. Decisions that
produce no redirect are now recorded too, with their destination so a recycled port cannot answer for
someone else's connection. Same probe afterwards: **0.14 ms**, and the timeout counter across a full
load run went from 19 to 0 while the two genuinely racing SYNs still waited and still got their
answer. `tools/measure-direct-cost.ps1`.

That measurement was nearly lost to the tooling: the scripts ran a fixed path under `bin\Debug` while
the solution build writes to `bin\x64\Debug`, so the fix measured identical to the code it replaced.
The tools now take the newest engine binary and print its build time - see `tools/engine-binary.ps1`.
A stale binary is forgivable; one that passes for a result is not.

**The installer has been installed.** The MSI from CI was verified against its published hash,
installed, and the installed product driven end to end: the app launched, the engine started from
`C:\Program Files\SplitLane\Engine`, loaded WinDivert 2.2, bound its redirect listener, and the app
showed it as routing. Then uninstalled and the machine checked clean.

That found one defect. The driver is fetched after installation and never shipped (ADR W-0001), so
Windows does not consider the installer responsible for it - and an uninstall left a kernel-mode
driver on disk. The uninstall now removes it by name along with the Engine folder.

Released as `v0.1.0`: MSI, portable archive and `SHA256SUMS.txt`, built by the pipeline from the
tag. The release path is no longer theoretical - the download's hash was checked against the
published one.

**The engine is a Windows service.** Installed by the MSI as `SplitLane`, LocalSystem, automatic
start. Verified on a live machine: the service starts on install, the unelevated application talks to
it across the privilege boundary, and routing works through it - a selected application reached
TEST-NET, which routes nowhere, so the only way there was the proxy, while the unselected control
timed out. Uninstall stops and removes it.

Not written: code signing.

The live run also found three bugs of one family — failures that reported nothing. A failed
`WinDivertRecv` was slept through, a failed `WinDivertSend` was discarded, and console logging could
hang the whole engine from a stray click in an elevated window. All three are fixed, and the lesson
generalises: in this codebase, a silent failure is the bug.

## Definition of Done

Same as the root project, plus: report distinguishes implemented / compiled / unit-tested /
integration-tested / driver-verified, and never claims a level that was not reached.
