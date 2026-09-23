# Architecture

## Modules

```
SplitLane.Core        net10.0            pure — no WPF, no WinDivert, no P/Invoke
SplitLane.Engine      net10.0-windows    a LocalSystem service — the only component that sees packets
SplitLane.App         net10.0-windows    WPF — never elevated
SplitLane.Testbed     net10.0            a real SOCKS5 server, for tests and manual verification
src/Shared            (linked source)    reads an application's identity; compiled into App and Engine
```

Dependencies run one way: `App → Core`, `Engine → Core`, and nothing points back. The rule is
enforceable by reading the project files: `SplitLane.Core` targets plain `net10.0` rather than
`net10.0-windows`, so a Windows-only API would not compile there at all.

That boundary is the whole reason the routing model can be tested exhaustively without a driver,
without elevation and without a network — the same promise the macOS project makes about
`swift test` and Xcode.

`src/Shared` is the exception that proves it, and it is not a project. Reading a file's stamp, its
Authenticode signer, its hash and a process's package family needs Win32, so it cannot live in the
core; and the app building a rule and the engine checking a process must compute byte-identical
identities from the same file, or every rule would match nothing the day the two disagreed. So one
copy of the source (`src/Shared/ImageInspection`, `src/Shared/Identity`) is compiled into both.

The MSI installs the engine as the `SplitLane` service: LocalSystem, automatic start. A source
checkout or the portable archive runs the same executable as a console process from an elevated
prompt instead; nothing else differs.

## The routing path

```
                       ┌──────────────────────────────┐
   connect()  ────────▶│  SOCKET layer (sniff only)   │
                       │  pid, local port, remote      │
                       └──────────────┬───────────────┘
                                      │
                            ProcessResolver
                  pid ──▶ image path + package family from the
                        token (cached on pid + process start time)
                                      │
                                      ▼
                              ImageCatalog
                  what is already known about this file version;
                  reads its stamp once per new process, never
                  waits for a signature
                                      │
                                      ▼
                              FlowDescriptor
                       (a plain value; no WinDivert types)
                                      │
                                      ▼
                       ┌──────────────────────────────┐
                       │  RuleEngine.Decide            │
                       │  pure, synchronous, no I/O    │
                       └──┬───────┬───────┬───────┬───┘
                          │       │       │       │
                     DIRECT    PROXY    BLOCK    HOLD
                          │       │       │       │
                   NAT row:   NAT      NAT row:  NAT row: Pending;
                   Direct,    entry    Block;    packets dropped until
                   so the SYN          packets   the file is verified,
                   need not            dropped   then decided again
                   wait
```

The decision itself is eight ordered checks in `RuleEngine.Decide`, and each early return encodes a
rule from the threat model:

1. Engine self-traffic → DIRECT. Loop defence, first for a reason.
2. Routing disabled → DIRECT. A paused SplitLane routes nothing, though its divert handles stay open
   (NETWORKING §4).
3. Local destination → DIRECT, for every application. Second layer of loop defence.
4. Unidentified source → DIRECT. A process that could not be resolved is not a selected app.
5. A claim on a rule with no verdict yet → BLOCK (`IdentityPending`). Held, not refused: decided
   again when verification finishes. See "Application identity" below.
6. A file at a rule's recorded location that is no longer that application → BLOCK
   (`IdentityMismatch`). DIRECT only if the rule itself sent the application DIRECT.
7. No rule → DIRECT. The product's default.
8. The rule's lane: DIRECT, BLOCK or PROXY. A PROXY rule's UDP is relayed through the proxy
   (ADR W-0012), or refused with `UdpNotSupported` when relaying is off. It is never DIRECT.

## Application identity

A rule records what an application *is* (ADR W-0013), not where it was:

| Kind | Identity |
|---|---|
| `Signed` | verified signer subject + product name (when there is one) + file name, and the signed `OriginalFilename` when there is one |
| `Package` | package family, read from the process token |
| `Unsigned` | SHA-256 of the file |
| `Path` | a schema 1 rule not yet migrated |

The difficulty is time. Verifying the signature of a 320 MB executable takes about 1.5 s, and the
socket pump that decides every connection on the machine cannot wait for that. So identity is split
into cheap evidence and an expensive verdict:

```
new process ──▶ ProcessResolver: image path, package family from the token
                    │
                    ▼
               ImageCatalog.Refresh: file stamp (size, write time, file id), once per new process;
                    │                a changed stamp is a new record, so a verdict never outlives
                    │                its file
                    ▼
               RuleSnapshot.Match(evidence)
                    │   managed tier first; the user's rules only if no managed rule is involved
                    │   within a tier: package family → identity claims → schema 1 path rules
                    │
                    ├─ matched          ──▶ decided now
                    ├─ mismatch at pin  ──▶ BLOCK (IdentityMismatch)
                    └─ claim, no verdict ─▶ IdentityPending
                                              │  TCP: NatTable verdict Pending, the SYN is dropped
                                              │  UDP: the socket's datagrams are dropped
                                              │  ImageCatalog queues the file (two background workers,
                                              │  WinVerifyTrust, and a hash where a rule needs one)
                                              ▼
                                          Verified event ──▶ held flows decided again
```

A *claim* is evidence that points at a rule without proving it: the file name, product name or
install folder of a signed rule, or the size or location of a pinned unsigned file. Deciding on a
claim either way is the bug — DIRECT leaks a selected application, PROXY hands its lane to an
impostor with the right file name — so the flow is held instead. TCP retransmits the SYN after the
initial RTO (1 s on Windows 11), so the first connection of a newly updated application pays about a
second, once; later connections from the same file version find the verdict cached.

Nothing is verified that no rule asked about: only a file that claims a rule is queued, the version
resource is read for its product name only when some rule matches by product, and a claim on which
every candidate rule sends the application DIRECT is not held at all. Nothing off the machine is
opened: the engine is LocalSystem, and reading `\\host\share\x.exe` would authenticate the machine
account to that host, so a UNC or remote-drive image is never verified and never any selected
application (`ImageFile.IsLocalPath`). A verification that fails or throws completes the evidence as
not verifying, so nothing is held forever.

The managed tier differs in two ways. Its claims on DIRECT rules are verified too, because a
managed DIRECT has to shadow the user's rules rather than step aside for them; and nothing in it is
pinned to a recorded location, because that location was recorded on the administrator's machine.

`SplitLane.Engine.exe --explain` runs this same path against the processes running now, without
elevation and without touching the service, and prints the result.

## Configuration lifecycle

One immutable `RuntimeConfiguration` at a time, swapped by a single volatile store:

```
App edits ──▶ ConfigurationService.Save
                  ├─ validate
                  ├─ generation++
                  └─ atomic write to %ProgramData%\SplitLane\configuration.v2.json
                        │
                        ▼
              EngineRequestKind.ReloadConfiguration(generation)
                        │
              EngineRuntime.LoadConfiguration
                  ├─ read the managed policy, if it is trusted          (PolicyStore)
                  ├─ read + sanitise the user's configuration           (ConfigurationStore)
                  ├─ put the policy on top                              (PolicyMerger)
                  ├─ build a whole new RuleSnapshot: managed tier + user tables
                  ├─ _engine = new RuleEngine(...)      ← single store
                  └─ schema 1 rules left? migrate in the background, save, apply again
```

Nothing is mutated in place. A connection that started under generation *n* keeps reading a coherent
generation *n* for its lifetime, and the divert threads never observe a half-built table. Three
threads apply configurations — the control channel, the migration task and the policy watcher — and
they take one lock to do it, so each builds on what the others last applied.

The generation is carried on the reload message so the engine can discard one that arrives after a
newer one has already been applied — requests are not ordered with respect to the file write that
produced them.

`Sanitize` corrects rather than rejects on load: a rule asking for family matching on a shared
directory is downgraded to exact matching. Refusing to start because one rule is too broad would
leave the user with no routing at all.

### Two files, for a rollback

Schema 2 lives in `configuration.v2.json`. The schema 1 `configuration.json` is read to migrate from
and is **never written** by this build, by the app or the engine: a build from before schema 2 refuses
a document stamped with a newer schema and would start with no rules at all, so the old file is left
exactly as it was for a rollback to find. Both sides read whichever of the two is newer, so changes
made under a rolled-back build are what gets migrated when the newer build returns.

### Migration

Path rules become identity rules by the same code in the app and the engine (`ConfigurationMigrator`,
over `src/Shared`). For each rule: a file where the rule says is verified and its identity recorded; a
missing one is looked for in the sibling version or hash directories and adopted only if it is validly
signed by the publisher the rule recorded; anything else — including a rule that recorded no
publisher, whose file is now signed — becomes `NeedsReselection` and routes nothing, with the reason
on the rule. Migration never hands a rule to a different application.

It runs in the background on both sides. It verifies the signature of every file a rule names, which
is seconds for a large executable, and the service control manager gives a starting service 30.
Until it finishes the rules keep the meaning they had before. The engine saves its result to
`configuration.v2.json` and applies it, unless the rules changed meanwhile, in which case the result
is discarded. The app shows its result on screen without writing it; the next save the user makes
writes it.

### The managed policy

`%ProgramData%\SplitLane\Policy\policy.json` (ADR W-0014) is read only if neither it nor its folder
is a link, both are owned by SYSTEM, Administrators or TrustedInstaller, and no one else can modify the
file or add, delete or re-permission files in the folder (`PolicyFileTrust`). The file is opened once
and judged and read through that one handle. A file that fails is rejected, logged as an error and
reported in the status; if an earlier policy verified, that one stays in force, and otherwise the
user's configuration applies alone. The engine creates the `Policy` folder when it is missing — with
inheritance cut and no entry for Users — resets an existing folder that is not safe, and watches it,
so a changed policy is re-read and re-judged within seconds and a rule removed from it stops
applying. The trust check is unit-tested; a file placed as SYSTEM on a live install has not been
tried. THREAT_MODEL W-10 has the reasoning.

`PolicyMerger` marks managed rules `IsManaged` — they must carry an identity, never a path — drops
the user's rules for the same applications (or all of them, under `allowUserRules: false`), and
applies `forceRoutingEnabled` and a managed `proxy`. Under `forceRoutingEnabled` a policy reload also
starts routing again if it was stopped or had faulted. `RuleSnapshot` puts the managed rules in a tier
of their own, consulted first, so precedence is structural rather than a question of which rule is
more specific.

## The trust boundary

```
   SplitLane.exe                          SplitLane.Engine.exe
   (interactive user)                     (LocalSystem service)
        │                                          │
        │   \\.\pipe\SplitLane.Engine.Control      │
        │   length-prefixed JSON                   │
        │   EngineRequestKind — eleven members     │
        └──────────────────────────────────────────┘
```

Everything the unprivileged side can ask the privileged side to do is enumerated. There is no message
that names a file to open, a command to run, or a library to load — that absence is the design, not
an oversight. `CheckForUpdate` and `ApplyUpdate` carry nothing at all: what is installed is decided
by a manifest the engine fetched and verified (ADR W-0011).

The pipe's ACL grants the interactive user read and write, and Administrators and LocalSystem full
control. Message length is bounded before any allocation, because a length prefix an unprivileged
caller controls is an allocation an unprivileged caller controls.

A managed policy narrows what the pipe can do: under `forceRoutingEnabled` the engine refuses
`StopRouting`, under `disableSelfUpdate` it refuses to check for or install updates, and
`ApplyConfiguration` still sets the user's own rules but cannot change or override managed ones.

## The app

WPF, MVVM, no third-party packages. One `MainViewModel` owns the configuration and the engine
connection; five page view models edit it through that object, because the alternative — each page
owning a copy — is five chances for the file on disk and the screen to disagree.

Status is polled once a second rather than pushed. A push channel would need the elevated engine to
hold a callback for an unprivileged process, and the thing being displayed changes slowly.

The status carries `PolicyState`, `PolicyDetail`, `ManagedRuleCount` and `RoutingLockedByPolicy`, but
the app does not display them yet: it shows the user's own rules, not the managed ones, and does not
say when a policy is in force.

The window renders on a composition backdrop with translucent surfaces. Everything is drawn over an
opaque-enough scrim so that when the backdrop is unavailable — Windows 10, a remote session,
transparency switched off in Accessibility — the interface degrades to a dark window rather than an
illegible one.

Every interactive control carries an `AutomationProperties.AutomationId`. That is what
`tools/uiprobe/uiprobe.ps1` drives to walk the interface and capture screenshots, and it is why
navigation binds selection rather than handling `Click`: a command on `Click` meant anything that
*selected* an item without clicking it moved the highlight without changing the page.
