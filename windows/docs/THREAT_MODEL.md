# Threat model

What SplitLane for Windows protects, what it does not, and what has not been verified.

The macOS threat model in `../../docs/THREAT_MODEL.md` applies wherever the design is shared. This
file covers what is specific to Windows, numbered W-*n* to keep the two sets distinguishable.

## Assets

1. **Routing correctness.** A selected application's traffic reaches the proxy or fails visibly. It
   never reaches the network directly without the user knowing.
2. **Non-interference.** An unselected application's traffic is not modified.
3. **The proxy credential.** Never in the configuration file, never in a log, never readable back
   through the UI.
4. **The elevated engine's integrity.** An unprivileged local process must not be able to use the
   control channel to do anything the design does not intend.

## Findings

### W-1 — Unselected traffic transits user mode

**Severity: accepted, documented.**

Every outbound packet on the machine is copied to the engine and reinjected. Unselected traffic is
returned byte-for-byte identical, but it passes through a user-mode process. This holds for as long as
the engine is routing — paused or not, with rules or without; only stopping routing closes the
handles ([NETWORKING.md §4](NETWORKING.md#4-the-divert-filters)).

The consequences are honest ones: a bug in the engine can affect traffic it has no interest in, and a
crash mid-packet drops that packet. It also means the phrase "unselected applications are untouched",
which is literally true on macOS, is not literally true here.

Not fixable without a kernel callout driver of our own. See
[NETWORKING.md §5](NETWORKING.md#5-what-this-costs).

### W-2 — Identity is verified on the file, not on the running image

**Severity: low. Impact is asymmetric.**

This finding used to read "path matching is not cryptographic proof", and the path is no longer what a
rule matches. Since ADR W-0013 a rule records an identity: a signed application by its verified signer
subject, product name and file name; a packaged one by the package family in its process token (W-4);
an unsigned one by the SHA-256 of its file. Schema 1 path rules keep their old meaning only until they
are migrated. Where a signed binary carries an `OriginalFilename`, that is part of the identity too, so
a copy of another binary from the same publisher renamed to the selected name does not inherit the
rule — every inbox Windows tool shares its signer and product name. Version strings are read
language-neutral, from the signed image rather than a MUI satellite the signature does not cover.

What bounds it:

- The image path comes from `QueryFullProcessImageName` against the kernel's view of the mapped image.
  It cannot be spoofed by the target process itself, unlike anything read out of the PEB, and it
  follows a rename of the running image — so the file at the reported path is the running image's
  file, not whatever was later put at its old name.
- A file name, product name, folder or size that points at a rule is only a claim. Nothing is routed
  on a claim: the flow is held until the signature or hash has been checked (W-11).
- A file at a rule's recorded location that is no longer that application — unsigned, another signer,
  other bytes — is blocked (`IdentityMismatch`), not routed and not sent DIRECT.
- The LocalSystem engine opens nothing off this machine (`ImageFile.IsLocalPath`). Opening
  `\\host\share\x.exe` would authenticate the machine account to a host a user chose, so a UNC or
  remote-drive path — a rule's, or a running image's — is never verified, and an executable there is
  never any selected application.

What remains:

- **The signature is checked on the file on disk**, not on the image mapped into the process.
  Herpaderping- and ghosting-style techniques can make the two differ. They need local code execution,
  and application control (WDAC/AppLocker) is the control for them, not a routing product.
- **A publisher that changes its certificate subject loses its rules, visibly.** The thumbprint and the
  issuing CA are deliberately not part of the identity (two real `codex.exe` builds differ in both),
  but the subject is. The application is blocked at its recorded location and DIRECT elsewhere,
  logged either way; selecting it again fixes it.
- **Unsigned applications are pinned by hash.** An update changes the bytes, so the file at the rule's
  path is refused until the application is selected again, and no family is ever built around an
  unsigned file — anything a copy could not also have is all there is to go on.
- **Several installations of one signed application are one application.** A rule for one copy
  routes every copy with the same publisher, product and file name.

The impact is asymmetric in the same way as macOS F-2: a forged identity gets traffic *into* the proxy
lane, not out of it.

### W-3 — Family matching over a shared directory

**Severity: would be critical. Prevented by construction.**

macOS bundle-family matching has no dangerous case: the family of `com.apple.Safari` is Safari. The
Windows equivalent does — the "family" of `C:\Windows\System32\curl.exe` is every system binary on
the machine, and a user ticking "include helper processes" on a system tool would silently put the
operating system into the proxy lane.

`ExecutablePath.IsSafeFamilyRoot` refuses shared directories as family roots, `AppRule.UsesFamilyMatching`
consults it, and `RuleSnapshot` checks it *again* when building the family table so that no future
edit to that property can smuggle `System32` in. `ConfigurationValidator.Sanitize` downgrades an
offending stored rule to exact matching rather than failing the whole load.

Identity rules (W-0013) have the same hazard in a second form: the family of a signed application is
also "the same publisher's binaries with the same product name", and some product names belong to a
platform rather than an application. `ProductFamily` refuses a product family for Windows, .NET,
Electron, Node.js, OpenJDK, Python, PowerShell and WebView2, and for anything signed by the
certificates Windows itself is signed with, because the product names of Windows components are
localised and no list of names can keep up. The shared-directory guard applies to signed families as
well.

Covered by `RuleEngineTests.FamilyMatchingOnASharedSystemDirectoryIsRefused` and
`ExecutablePathTests`. See [ADR W-0003](adr/0003-family-matching-safety.md).

### W-4 — Packaged applications move on update

**Severity: was a silent leak. Fixed by matching the package family from the process token.**

MSIX/Store applications run from a versioned directory under `C:\Program Files\WindowsApps\...`. The
path changes on every update, so a path-keyed rule stopped matching silently — the application kept
working and quietly went DIRECT, which is exactly the failure mode this product exists to prevent.

ADR W-0010 matched packaged applications on their package family, computed from the path. W-0013
reads it from the process token instead (`GetPackageFamilyName` on a
`PROCESS_QUERY_LIMITED_INFORMATION` handle), where Windows sets it when it activates the package. A
packaged rule now survives an update and a move to another drive, and a directory that merely looks
like `WindowsApps` — which anyone can create — claims nothing. A package registered from an unsigned
layout (Developer Mode) is not treated as a package identity, because its family comes from a
manifest the user wrote.

Writing the tests for W-0010 also surfaced a real gap: `C:\Program Files\WindowsApps` was not in the
shared-directory list, so family matching there would have been the W-3 mistake in a different
folder — every packaged application on the machine in one rule. It is now refused.

### W-5 — The redirect listener is a local TCP port

**Severity: mitigated.**

The listener is a real port on loopback that any local process can connect to. Without a check it
would be an open proxy that forwards anywhere the caller names.

`RedirectListener` closes any connection whose source port has no NAT entry. Since entries are only
created by the socket-layer pump for connections SplitLane itself decided to proxy, an uninvited
caller has no entry and is refused. It binds loopback only — never the wildcard — so it is not
reachable off the machine at all.

Covered by `RelayIntegrationTests.AConnectionFromAnUnknownPortIsRefusedRatherThanProxied`.

### W-6 — NAT table collision on a reused source port

**Severity: theoretical.**

The NAT table is keyed on the local port alone. A port is unique per protocol *per local address*, so
two sockets bound to the same port on different local addresses would collide, and one application's
connection could be attributed to another's rule.

Windows allocates ephemeral ports from a shared pool and the case requires a deliberate
`SO_REUSEADDR` bind to a specific address, so it is theoretical rather than practical. It is recorded
rather than defended against, because defending against it would mean keying on an address the
redirect listener never sees.

Entries expire after five minutes, which bounds the window in which a recycled port can be
mis-attributed at all.

### W-7 — The control channel is the trust boundary

**Severity: designed for.**

The engine runs as LocalSystem; the app does not. Everything the app can make the engine do is
`EngineRequestKind`, a closed enum with eleven members. There is deliberately no message that names a
file to open, a command to run, or a library to load; the two update requests carry nothing at all
(W-12).

- The pipe's ACL grants the interactive user read and write, Administrators and LocalSystem full
  control, and nobody else. Without an explicit ACL a pipe created by a service is reachable by every
  account on the machine.
- Message length is bounded *before* a byte is allocated. A length prefix an unprivileged caller
  controls is an allocation an unprivileged caller controls.
- The configuration the app can hand over is validated by the same `ConfigurationValidator` the
  engine uses for its own file, so an app-supplied rule cannot bypass the family-matching guard.

"Interactive user" is every interactive user, not the one who installed SplitLane, so the pipe does
not distinguish the person who configured the machine from anyone else who logs on to it. A managed
policy (ADR W-0014, W-10) narrows it: under `forceRoutingEnabled` the engine refuses `StopRouting`,
under `disableSelfUpdate` it refuses to check for or install updates, and `ApplyConfiguration` can
still set the user's own rules but cannot change, remove or override a managed one. Without a policy,
any interactive user can stop routing, replace the rules, or install a signed release.

### W-8 — Configuration is machine-wide, and every interactive user can write it

**Severity: accepted for a personal machine; not acceptable for a managed one, where W-10 is the
answer.**

Configuration lives in `%ProgramData%\SplitLane` because the engine runs as a service account and the
app runs as the user; a per-user path would be readable by exactly one of them. On a shared computer
every account's rules are visible to every other account.

And writable by every one of them. The unelevated app saves the configuration itself, so the folder
has to accept writes from ordinary users, and any interactive user — or any process running as one —
can change the rules, the proxy and the routing switch, by editing the file or through the control
channel (W-7).

This is a real property, not an oversight: the divert layer is machine-wide, so per-user rules would
be a promise the engine could not keep. The Settings page says the configuration is machine-wide. For
an organisation that needs rules a user cannot change, the answer is the managed policy (ADR W-0014,
W-10), which lives in a folder of its own and is judged by its owner and permissions rather than by
where it is.

### W-9 — The credential at rest

**Severity: mitigated off the machine; open on it.**

The proxy password is a DPAPI blob scoped to the local machine,
`%ProgramData%\SplitLane\credential.bin`, stored outside the configuration file. It is meaningless if
copied to another machine, and it never appears in the JSON that someone would attach to a bug
report.

It is not protected from this machine. `LocalMachine` scope means any process on the machine that can
read the file can decrypt it, and no code sets an ACL on the file: it has whatever permissions it
inherits from `%ProgramData%\SplitLane`. Restricting it to SYSTEM is planned
([ENTERPRISE_READINESS.md](ENTERPRISE_READINESS.md), P1-5).

`ConfigurationTests.EncodedConfigurationNeverContainsSecrets` enforces the structural property: there
is no field on `ProxyConfiguration` that could hold a password, only a locator. The UI can report
that a password exists; it has no path to read one back.

RFC 1929 still sends the credential to the proxy unencrypted. On loopback that is irrelevant; to a
remote proxy it is not, and the Proxy page warns when the endpoint is not loopback.

### W-10 — The managed policy is trusted by its owner and permissions

**Severity: designed for. Not verified on a live install.**

`%ProgramData%\SplitLane\Policy\policy.json` (ADR W-0014) lets an administrator mandate rules that no
user rule can override. It lives in a tree ordinary users can write (W-8), so where it is proves
nothing. The engine reads it only if (`PolicyFileTrust`):

- neither the file nor its folder is a link — a junction or symbolic link would let the file judged
  and the file read be different files;
- the file and its folder are owned by SYSTEM, Administrators or TrustedInstaller — a file or folder a
  user creates is owned by that user, and an owner can always rewrite its permissions;
- no allow entry on the file lets anyone else write, append, delete, change its permissions or take
  ownership;
- no allow entry on the folder lets anyone else create or delete files in it, delete it, or change its
  permissions or owner.

The file is opened once, sharing read only; its owner and permissions are read from that handle and
its contents from the same stream, so what was judged is what is applied. It is capped at 1 MB.

The engine creates the `Policy` folder when it is missing, with inheritance cut and no entry for Users
at all: SYSTEM and Administrators only. An existing folder that is not safe — one a user created before
the service first ran, or one that inherited the tree's permissions — has its owner and permissions
reset. Users are kept out entirely because the first version let them read the folder, and a user who
could open `policy.json` without sharing made the engine's read fail, which dropped the policy and
forced routing with it.

**The last policy that verified stays in force.** A failed read or a failed trust check is logged as an
error and reported — `Rejected` in the status and in `--explain` — and changes nothing that is already
enforced. Only a file that reads and verifies, or the file's absence, changes the policy
(`ManagedPolicyEngineTests.APolicyFileHeldOpenByAUserDoesNotDropTheLastPolicyThatVerified`).

**Fail-open when nothing ever verified.** A policy that fails the check on a machine with no earlier
verified policy is not applied, and the engine routes by the user's configuration alone. Failing
closed would let any user who can plant a file decide what the engine enforces. The cost is that a
rejected policy is visible only on the machine itself — there is no Event Log channel or telemetry
yet ([ENTERPRISE_READINESS.md](ENTERPRISE_READINESS.md), P0-4).

Managed rules must carry an identity; a path rule in the policy is ignored and reported. Removing a
rule from the file revokes it: the folder is watched and the policy re-read and re-judged on change.
A policy with managed PROXY rules and no `proxy` of its own is reported, because the user's proxy
then decides where "must be proxied" traffic goes.

Not covered: a signed policy, a policy-delivered proxy credential, and anything while the engine is
not running. The trust check is unit-tested as a pure function and once against a real file (one
created by the test account is refused,
`ManagedPolicyEngineTests.APolicyFileCreatedByTheTestAccountIsRefusedForReal`). A file placed as
SYSTEM, and the folder created by the installed service, have not been exercised on a live install.

### W-11 — Held flows, and who pays for verification

**Severity: low. Accepted.**

A process whose file name, product name, folder or size points at a rule is not routed on that claim
(W-2). Its TCP SYN and its datagrams are dropped while a background worker verifies the file, and the
held flows are then decided again (ADR W-0013). Two consequences:

- **The first connection of a newly updated selected application waits about a second.** The held SYN
  is lost; TCP retransmits it after the initial RTO, 1 s on Windows 11, and by then the verdict is
  usually in. Verification costs up to about 1.5 s cold for the 320 MB `codex.exe`, 45-250 ms warm,
  and 4-18 ms for a catalog-signed system binary. Later connections from the same file version find
  the verdict cached. QUIC and DNS retransmit too, so held datagrams cost the same kind of delay.
- **A user-level process can make the LocalSystem engine hash files.** Anything that claims a rule —
  a file named like a selected application, run from any local folder — is verified with
  WinVerifyTrust, and hashed where an unsigned rule needs it, by the service. That is bounded by one
  verification per file version (`ImageCatalog`, keyed on path, size, write time and file id), on two
  worker threads. A flood of claims delays the verdicts for genuine applications, whose flows stay
  held meanwhile; it cannot make any of them go DIRECT.

A verification that fails or throws, or a hash that cannot be computed, completes the evidence as not
verifying, so a flow is never held forever waiting for an answer that will not come.

Deciding on the claim instead would be worse in both directions: DIRECT leaks a selected application,
PROXY hands its lane to an impostor with the right file name.

### W-12 — The self-update surface

**Severity: designed for. A policy can close it.**

The engine checks a signed manifest once a day, and installs the release it describes when asked
(ADR W-0011). Two things make that a surface:

- **Any interactive user can trigger an install.** `CheckForUpdate` and `ApplyUpdate` are on the
  control channel (W-7). They carry no version, URL or file name, so a caller chooses *when* a release
  signed by the release key is installed, never *what*; the MSI refuses a downgrade. Installing runs
  `msiexec` as SYSTEM and restarts the service, which drops every relayed connection. Under a policy
  with `disableSelfUpdate` the engine refuses both requests and does not check on its own.
- **The release key is a root of trust for SYSTEM.** The manifest's ECDSA P-256 signature is checked
  before the document is parsed, the installer is hashed against it, and the installer URL must be
  HTTPS on `github.com`, `*.github.com` or `objects.githubusercontent.com`. Whoever holds the private
  key can run code as SYSTEM on every installation that checks.

Verified: the signing pipeline end to end, a published manifest accepted by the key the build ships,
and an edited copy refused. `releases/latest/download/update.json` answers an anonymous request (HTTP
200, checked 2026-09-23). An install through the updater has not been run. Nothing SplitLane ships is
code-signed, so the manifest signature protects the delivery channel, not the binaries' reputation.

## What a live run established

The divert layer has now been run against the driver on a real machine, elevated, with a selected
application and a controlled SOCKS5 upstream. This section records what that proved and what it did
not, because "we tried it" is not a result.

**Verified against the driver:**

- WinDivert 2.2 loads, and all three handles open. The socket, network and DNS filter strings are
  accepted by the driver — previously all four of those were guesses.
- The socket layer delivers events and `WINDIVERT_DATA_SOCKET` is laid out correctly: process ids,
  ports and protocol all read back sensibly.
- `ProcessResolver` turns a pid into the right image path on live traffic. Decisions were logged
  naming `curl.exe`, `firefox.exe`, `Code.exe` correctly.
- `RuleEngine` decides correctly on real connections. A selected application produced
  `PROXY curl.exe :51849 -> example.com:80`.
- **Loop defence works on real traffic, and caught a genuine case.** On a machine with a local proxy
  client, almost every application connects to `127.0.0.1:10808`; SplitLane declined every one of
  them with "destination is loopback or link-local". The first test run looked like a failure and was
  the second layer of loop defence doing its job.
- The DNS observer works. The destination was reported as `example.com`, recovered from a sniffed
  answer rather than from the address the socket carried, which is what lets the SOCKS5 request use
  `ATYP=DOMAIN`.
- The NAT table records on CONNECT and expires as designed.
- The packet layer captures, rewrites and reinjects. WinDivert **accepted** every injection —
  `send failures 0` across every run.

**It works.** A selected application's traffic reaches the proxy, confirmed from the upstream side:
the test SOCKS5 server logs `CONNECT example.com:80` and the relay reports
`relaying curl.exe -> example.com:80 (105ms handshake)`. Repeatable across runs. The destination
arrives as a hostname rather than an address, so the DNS observer and `ATYP=DOMAIN` are working too.

Three things had to be fixed to get there, and each was invisible from the outside:

1. **Direction was being asserted.** A redirected packet was flipped to inbound because "it is going
   to a socket on this machine", and the reply flipped for the same reason. WinDivert accepts such a
   packet and the stack discards it, with no error at either end. Leaving the direction exactly as
   captured and rewriting only the addresses lets the stack route it.

2. **A packet whose source is one of the machine's own addresses is rejected as a spoof** when it
   arrives on a physical interface. That ruled out the local-address shape: the stack answered RST
   and the listener never saw a connection. Both endpoints on loopback satisfies the rule.

3. **The SYN raced its own routing decision, and lost.** This was the real bug, and only a packet
   capture found it. Windows generates the socket-layer event before the SYN, but the two travel
   through separate WinDivert queues on separate threads and arrive in either order. When the packet
   loop won, the SYN left un-redirected, the connection established with the real server, and the
   *later* packets got rewritten - the capture showed an ACK and a 75-byte HTTP request being
   dropped with "transport endpoint was not found". Now a SYN waits up to eight milliseconds for its
   decision, and a connection is only redirected if its SYN was.

Later runs added load (six applications at once, 600/600 proxied, `tools/stress-divert.ps1`), the
cost to unselected applications (`tools/measure-direct-cost.ps1`), and routing through the installed
service. See [DEVELOPMENT.md](DEVELOPMENT.md).

**Not yet verified against the driver: application identity** (ADR W-0013). Matching by verified
identity, migration and the managed policy are unit- and integration-tested — including real processes
started from copies of a signed binary, verified with WinVerifyTrust and relayed through the SOCKS5
testbed — and `--explain` has been run against the live configuration and processes, unelevated. The
held-SYN path under WinDivert — a connection dropped while its image is verified and redirected on
retransmission — has not. `tools/verify-identity.ps1` tests it and needs an elevated terminal; it has
not been run elevated.

## Bugs the live run found

Three, all of the same family — a failure that reported nothing:

- **`WinDivertRecv` failures were slept through.** The socket pump returned a bare false and the loop
  spun on a one-millisecond sleep forever, routing nothing. From the outside it was indistinguishable
  from a machine with no traffic on it. The Win32 error is now reported.
- **`WinDivertSend` results were discarded.** A refused injection is a connection that hangs with no
  error anywhere. Now counted and logged.
- **Console logging can hang the entire engine.** The engine logs to a file and to the console. In an
  elevated console window with QuickEdit enabled, a stray selection blocks `Console.WriteLine`, and
  with it every thread that logs — the engine stopped after one line and never opened its control
  channel. This is a real hang in a process that is meant to run unattended.
