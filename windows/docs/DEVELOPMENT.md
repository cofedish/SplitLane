# Development

## Build and test

```powershell
cd windows

dotnet build SplitLane.Windows.slnx
dotnet test  SplitLane.Windows.slnx
```

327 tests. None of them needs a network, a driver, elevation, or a daemon to be started first — the
SOCKS5 integration tests run against an in-process server in `tools/socks5-testbed`, so they run on
every `dotnet test` rather than being skipped like the macOS project's Docker-based equivalents.

Warnings are errors, project-wide. The macOS Definition of Done asks for "zero new warnings"; making
the build enforce it is cheaper than reviewing for it.

## Running it

### Without a driver

```powershell
SplitLane.Engine.exe --no-divert
```

The control channel, rule engine, redirect listener and SOCKS5 relay all run. Nothing is intercepted,
and the UI says so plainly rather than looking healthy. This is the mode to develop the interface in,
and the mode to check your proxy settings in before installing a kernel driver.

### With a driver

```powershell
.\tools\fetch-windivert.ps1                # once
SplitLane.Engine.exe --check               # unelevated on purpose
SplitLane.Engine.exe                       # from an ELEVATED prompt
```

`--check` reports the three things that independently prevent the divert layer from starting —
missing driver, no elevation, driver blocked by policy — because they need three different fixes and
a single "it did not work" tells you nothing. Its exit codes are `0` ready, `2` not elevated, `3` no
driver, `4` driver refused to load.

The engine's manifest is `asInvoker`, not `requireAdministrator`. Requiring elevation would make
`--check` — the one command written for a machine that cannot run the engine — itself unrunnable.

## Driving the interface

`tools/uiprobe/uiprobe.ps1` launches the app, drives it through UI Automation, and captures
screenshots. It is how the interface is reviewed without a person sitting in front of it.

```powershell
.\tools\uiprobe\uiprobe.ps1 `
    -Exe .\src\SplitLane.App\bin\Debug\net10.0-windows\SplitLane.exe `
    -OutDir .\artifacts\shots `
    -Steps @(
        "shot:overview",
        "click:NavApplications",
        "click:AddApplicationEmptyButton", "wait:2500", "shot:picker",
        "read:EngineStateLabel")
```

Steps are `click:<AutomationId>`, `set:<AutomationId>=<value>`, `read:<AutomationId>`, `shot:<name>`
and `wait:<ms>`.

Because it addresses controls by `AutomationId` and prefers UI Automation patterns over synthetic
mouse clicks, it doubles as an accessibility check: anything the probe cannot reach, a screen reader
cannot reach either. That is not hypothetical — it is how the navigation bug was found where
selecting a sidebar item moved the highlight without changing the page.

## Verifying the relay end to end

```powershell
# 1. A real SOCKS5 server on an ephemeral loopback port.
.\tools\socks5-testbed\bin\Debug\net10.0\SplitLane.Testbed.Socks5.exe

# 2. Point SplitLane at the port it printed, on the Proxy page, then press Test connection.
```

The test runs *inside the engine*, not in the app. The app's own connection to a proxy proves nothing
about the engine's: they are different processes at different integrity levels, and a per-user proxy
reachable only from the interactive session is a real and common configuration on Windows.

Pass `--auth` to the testbed to exercise the RFC 1929 path (`splitlane` / `testbed`).

## Packaging

```powershell
.\tools\build-installer.ps1 -Version 0.1.0
```

Publishes both applications self-contained, builds the MSI with WiX 5, and writes a portable zip
beside it in `artifacts/release`.

Self-contained roughly doubles the download and buys an installer that works on a machine with no
.NET runtime, which is most machines and exactly the one someone installing a network tool is likely
to be on. The result is about 53 MB for the MSI; that weight is two copies of the .NET and WPF
runtime, not anything SplitLane ships.

The installer project is deliberately **not** in `SplitLane.Windows.slnx`. The WiX SDK is a separate
toolchain that must be restored before MSBuild can parse the file, and including it would mean
`dotnet build` fails on a clean machine for someone who only wanted to run the tests.

Three things the installer does not do, each on purpose:

- **It does not bundle WinDivert.** The driver is third-party, dual-licensed, and this repository has
  not chosen a licence of its own. `fetch-windivert.ps1` is installed alongside instead.
- **It does not register a service.** There is no service host yet.
- **It carries no licence dialog**, because there is no licence. Every stock WiX UI set includes one,
  so the MSI ships with the basic progress UI rather than presenting terms that do not exist.

## Continuous integration

`.github/workflows/windows.yml`, scoped to `windows/**` so a change to the macOS Swift sources does
not spend ten minutes building an MSI.

| Job | Runs on | Does |
|---|---|---|
| `test` | every push and PR | restore, build Release, run all tests, upload the `.trx` |
| `package` | after `test` | `build-installer.ps1`, hash the output, upload MSI + zip |
| `release` | tags matching `v*` | attach the packaged output to a GitHub release |

Because warnings are errors project-wide, the build step is also the style and API-hygiene gate.

A tag is the version. Anything else becomes `0.1.0.<run number>`, so untagged builds stay ordered and
never collide with a real release. The version is validated against the MSI four-field format in the
workflow, because `msiexec` rejects a malformed one at *install* time — which would mean shipping an
artifact that cannot be installed.

Nothing is code-signed. The workflow writes `SHA256SUMS.txt` and the release notes say plainly that
SmartScreen will warn, rather than leaving each person to wonder whether their download was tampered
with.

## Verifying interception

This is the test that decides whether SplitLane works. Everything else is covered by `dotnet test`;
interception is not, because it needs a kernel driver and elevation.

```powershell
.\tools\verify-divert.ps1 -Mode loopback -Trace
.\tools\verify-divert.ps1 -Mode local -Trace
```

The script starts the bundled SOCKS5 server, writes a configuration with one rule for `curl.exe`,
starts the engine elevated (accept the UAC prompt), runs curl, and reports the verdict. It cleans up
after itself unless you pass `-KeepRunning`.

The proof comes from the **upstream side**: the test server logs every CONNECT it is asked for. If a
selected application's connection was really intercepted and relayed, it appears there by name. A
count of redirected packets proves only that SplitLane rewrote something.

`-Trace` opens a sniffing handle on the redirect port and reports what the stack actually carries.
That distinguishes the two possible failures, which need opposite investigations: a redirected SYN
that appears means the injection worked and the listening socket is the problem; one that never
appears means the injection is being discarded.

Two things about the test itself are load-bearing:

- **`curl` is told to ignore the machine's proxy settings.** On a machine running a local proxy
  client almost every application connects to `127.0.0.1`, and SplitLane correctly declines to proxy
  loopback destinations. Without that flag the test measures the loop defence rather than the
  redirect — which is exactly what happened the first time it was run.
- **`curl.exe` lives in System32**, so the rule is matched exactly. That also exercises the
  shared-directory guard of ADR W-0003, which refuses family matching there.

### Mode

| | |
|---|---|
| `loopback` | Both endpoints move to `127.0.0.1`. This is the shape that works, and the default. |
| `local` | Only the destination changes, to the machine's own address. Kept because it distinguishes an injection that is discarded from one that is refused: a packet whose source is one of the machine's own addresses is rejected as a spoof on a physical interface, which is how the second of the three bugs was identified. The listener then has to accept on all local addresses — see W-5. |

## Under load

One connection working and a hundred and fifty working are different claims, and the second is the
one a person routing their traffic through this cares about.

```powershell
.\tools\stress-divert.ps1 -Apps 6 -Requests 100 -Concurrency 25 -PayloadKb 1024
```

Several copies of `curl.exe` at distinct paths become distinct applications — SplitLane routes on the
image path, so this exercises several routing keys rather than one rule hit repeatedly — and one more
copy is left unselected as a control.

Requests are aimed at **TEST-NET-3 (`203.0.113.0/24`)**, reserved for documentation and routed
nowhere, and the SOCKS5 testbed answers as the origin as well as the proxy so the address never has
to exist. That is what makes the result unambiguous in both directions: a selected application can
only succeed through the proxy, and the control is *required to fail*. A control that succeeded would
mean traffic reached a destination without a routing decision.

An earlier version served the payload from this machine's own LAN address and measured nothing at
all — traffic from a machine to its own address is loopback as far as the stack is concerned, the
divert filter excludes loopback, and not one packet was ever redirected.

Last run: 600/600 proxied, every payload intact, 600 MB at 20 MB/s, zero send failures, control 0/100.

### What it costs an application nobody selected

```powershell
.\tools\measure-direct-cost.ps1
```

The promise is that unselected applications are left alone; on Windows that promise has a caveat, and
this measures its size in milliseconds on the operation that pays for it. It times TCP connection
setup to a destination on the local network with the engine down and up. Loopback is deliberately not
used: the divert filter excludes it, so a loopback probe would report a reassuring zero.

It found a real cost. A SYN with no routing decision waits briefly for one, and a DIRECT decision was
recorded nowhere — so the packet loop could not distinguish "not decided yet" from "decided to leave
alone", and every connection an unselected application opened waited out the full window: **8.16 ms,
against 0.68 ms with the engine down**. Decisions that produce no redirect are now recorded too, with
their destination so a recycled ephemeral port cannot answer for an unrelated connection. Afterwards:
**0.14 ms**, with the wait-timeout counter over a full load run down from 19 to 0 while the SYNs that
genuinely raced still waited and still got their answer.

That fix nearly went unnoticed. The tools ran a fixed path under `bin/Debug` while a solution build
writes to `bin/x64/Debug`, so the first measurement after the change came back identical to the one
before it — correct to three digits, and about the wrong program. Every tool now resolves the newest
engine binary and prints its build time.

## Layout

```
SplitLane.Windows.slnx
src/SplitLane.Core/          models, rules, SOCKS5, configuration, IPC contracts, logging
src/SplitLane.Engine/        WinDivert interop, divert pipeline, NAT, relay, control server
src/SplitLane.App/           WPF — Theme, Views, ViewModels, Services, Infrastructure
tests/SplitLane.Core.Tests/  261 tests: rules, paths, addresses, SOCKS5, configuration
tests/SplitLane.Engine.Tests/ 66 tests: packet rewrite, NAT table, DNS parser, relay integration
tools/socks5-testbed/        the SOCKS5 server used by tests and by hand
tools/fetch-windivert.ps1    downloads the driver; never commits it
tools/build-installer.ps1    publishes both apps and builds the MSI; CI runs this same script
tools/verify-divert.ps1      the elevated end-to-end interception test
tools/stress-divert.ps1      several applications at once, under load, with a control
tools/measure-direct-cost.ps1 what SplitLane costs an application it was not asked to touch
tools/engine-binary.ps1      picks the newest engine build, so no tool runs a stale one
tools/uiprobe/               the screenshot and UI-automation harness
installer/                   WiX 5 sources. Not in the solution; see Packaging.
runtime/windivert/           where the driver lands. Git-ignored.
docs/screenshots/            captures of the running application
```

## What is not done

- The engine runs as a console process. A Windows service host, so routing survives a logout, is not
  written.
- Nothing is code-signed, so SmartScreen warns and the driver has to be trusted on the strength of
  its own signature rather than ours.
- Interception has been verified on IPv4 only. IPv6, sleep and resume, and adapter changes mid-flow
  are untested.
