# Development

## Build and test

```powershell
cd windows

dotnet build SplitLane.Windows.slnx
dotnet test  SplitLane.Windows.slnx
```

309 tests. None of them needs a network, a driver, elevation, or a daemon to be started first — the
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

## Layout

```
SplitLane.Windows.slnx
src/SplitLane.Core/          models, rules, SOCKS5, configuration, IPC contracts, logging
src/SplitLane.Engine/        WinDivert interop, divert pipeline, NAT, relay, control server
src/SplitLane.App/           WPF — Theme, Views, ViewModels, Services, Infrastructure
tests/SplitLane.Core.Tests/  248 tests: rules, paths, addresses, SOCKS5, configuration
tests/SplitLane.Engine.Tests/ 61 tests: packet rewrite, NAT table, DNS parser, relay integration
tools/socks5-testbed/        the SOCKS5 server used by tests and by hand
tools/fetch-windivert.ps1    downloads the driver; never commits it
tools/uiprobe/               the screenshot and UI-automation harness
runtime/windivert/           where the driver lands. Git-ignored.
```

## What is not done

- The divert layer has never run against the driver. See
  [THREAT_MODEL.md § Unverified](THREAT_MODEL.md#unverified). This is the next thing to do and it
  needs a machine with WinDivert installed and an elevated prompt.
- The engine runs as a console process. A Windows service host, so routing survives a logout, is not
  written.
- Packaged (MSIX/Store) applications are detected but the UI does not yet warn that their path
  changes on update (W-4).
- There is no installer.
