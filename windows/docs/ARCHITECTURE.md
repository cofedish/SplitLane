# Architecture

## Modules

```
SplitLane.Core        net10.0            pure — no WPF, no WinDivert, no P/Invoke
SplitLane.Engine      net10.0-windows    elevated — the only component that sees packets
SplitLane.App         net10.0-windows    WPF — never elevated
SplitLane.Testbed     net10.0            a real SOCKS5 server, for tests and manual verification
```

Dependencies run one way: `App → Core`, `Engine → Core`, and nothing points back. The rule is
enforceable by reading the project files: `SplitLane.Core` targets plain `net10.0` rather than
`net10.0-windows`, so a Windows-only API would not compile there at all.

That boundary is the whole reason the routing model can be tested exhaustively without a driver,
without elevation and without a network — the same promise the macOS project makes about
`swift test` and Xcode.

## The routing path

```
                       ┌──────────────────────────────┐
   connect()  ────────▶│  SOCKET layer (sniff only)   │
                       │  pid, local port, remote      │
                       └──────────────┬───────────────┘
                                      │
                            ProcessResolver
                        pid ──▶ image path (cached on
                              pid + process start time)
                                      │
                                      ▼
                              FlowDescriptor
                       (a plain value; no WinDivert types)
                                      │
                                      ▼
                       ┌──────────────────────────────┐
                       │  RuleEngine.Decide            │
                       │  pure, synchronous, no I/O    │
                       └──────┬───────┬───────┬───────┘
                              │       │       │
                         DIRECT    PROXY    BLOCK
                              │       │       │
                       count only  NAT     count; the
                                   entry   packet layer
                                           drops it
```

The decision itself is seven ordered checks in `RuleEngine.Decide`, and each early return encodes a
rule from the threat model:

1. Engine self-traffic → DIRECT. Loop defence, first for a reason.
2. Routing disabled → DIRECT. A paused SplitLane must be inert, not half-active.
3. Local destination → DIRECT, for every application. Second layer of loop defence.
4. Unidentified source → DIRECT. A process that could not be resolved is not a selected app.
5. No rule → DIRECT. The product's default.
6. Selected + UDP → BLOCK. Fail closed rather than let QUIC escape.
7. Selected + TCP → PROXY.

## Configuration lifecycle

One immutable `RuntimeConfiguration` at a time, swapped by a single volatile store:

```
App edits ──▶ ConfigurationService.Save
                  ├─ validate
                  ├─ atomic write to %ProgramData%\SplitLane\configuration.json
                  └─ generation++
                        │
                        ▼
              EngineRequestKind.ReloadConfiguration(generation)
                        │
              EngineRuntime.LoadConfiguration
                  ├─ read + sanitise
                  ├─ build a whole new RuleSnapshot
                  └─ _engine = new RuleEngine(...)      ← single store
```

Nothing is mutated in place. A connection that started under generation *n* keeps reading a coherent
generation *n* for its lifetime, and the divert threads never observe a half-built table.

The generation is carried on the reload message so the engine can discard one that arrives after a
newer one has already been applied — requests are not ordered with respect to the file write that
produced them.

`Sanitize` corrects rather than rejects on load: a rule asking for family matching on a shared
directory is downgraded to exact matching. Refusing to start because one rule is too broad would
leave the user with no routing at all.

## The trust boundary

```
   SplitLane.exe                          SplitLane.Engine.exe
   (interactive user)                     (administrator)
        │                                          │
        │   \\.\pipe\SplitLane.Engine.Control      │
        │   length-prefixed JSON                   │
        │   EngineRequestKind — nine members       │
        └──────────────────────────────────────────┘
```

Everything the unprivileged side can ask the privileged side to do is enumerated. There is no message
that names a file to open, a command to run, or a library to load — that absence is the design, not
an oversight.

The pipe's ACL grants the interactive user, administrators and SYSTEM. Message length is bounded
before any allocation, because a length prefix an unprivileged caller controls is an allocation an
unprivileged caller controls.

## The app

WPF, MVVM, no third-party packages. One `MainViewModel` owns the configuration and the engine
connection; five page view models edit it through that object, because the alternative — each page
owning a copy — is five chances for the file on disk and the screen to disagree.

Status is polled once a second rather than pushed. A push channel would need the elevated engine to
hold a callback for an unprivileged process, and the thing being displayed changes slowly.

The window renders on a composition backdrop with translucent surfaces. Everything is drawn over an
opaque-enough scrim so that when the backdrop is unavailable — Windows 10, a remote session,
transparency switched off in Accessibility — the interface degrades to a dark window rather than an
illegible one.

Every interactive control carries an `AutomationProperties.AutomationId`. That is what
`tools/uiprobe/uiprobe.ps1` drives to walk the interface and capture screenshots, and it is why
navigation binds selection rather than handling `Click`: a command on `Click` meant anything that
*selected* an item without clicking it moved the highlight without changing the page.
