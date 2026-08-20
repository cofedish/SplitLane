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
returned byte-for-byte identical, but it passes through a user-mode process.

The consequences are honest ones: a bug in the engine can affect traffic it has no interest in, and a
crash mid-packet drops that packet. It also means the phrase "unselected applications are untouched",
which is literally true on macOS, is not literally true here.

Not fixable without a kernel callout driver of our own. See
[NETWORKING.md §5](NETWORKING.md#5-what-this-costs).

### W-2 — Path matching is not cryptographic proof

**Severity: low. Impact is asymmetric.**

Routing keys on the process image path. An attacker who can write to the path of a selected
application can get their traffic *into* the proxy lane.

Two things bound this:

- The path comes from `QueryFullProcessImageName` against the kernel's view of the mapped image. It
  cannot be spoofed by the target process itself, unlike anything read out of the PEB.
- Writing to a path under `Program Files` already requires administrator, at which point the attacker
  has better options than proxy misrouting.

The impact is asymmetric in the same way as macOS F-2: a forged identity gets traffic *into* the
proxy lane, not out of it. The publisher is captured at pick time and displayed, but is deliberately
**not** enforced on the hot path — verifying an Authenticode chain costs milliseconds and can block
on a revocation check, and the routing decision runs once per connection on the machine.

Hardening path: pin the publisher on the rule and verify asynchronously after the fact, reporting a
mismatch rather than blocking the connection.

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

Covered by `RuleEngineTests.FamilyMatchingOnASharedSystemDirectoryIsRefused` and
`ExecutablePathTests`. See [ADR W-0003](adr/0003-family-matching-safety.md).

### W-4 — Packaged applications move on update

**Severity: low, cosmetic-adjacent.**

MSIX/Store applications run from a versioned directory under `C:\Program Files\WindowsApps\...`. The
path changes on every update, so a path-keyed rule stops matching silently — the application keeps
working and quietly goes DIRECT, which is exactly the failure mode this product exists to prevent.

`AppIdentity.IsPackaged` detects the case. The UI does not yet warn about it. This is the most
user-visible unfinished edge in the port.

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

The engine runs elevated; the app does not. Everything the app can make the engine do is
`EngineRequestKind`, a closed enum with nine members. There is deliberately no message that names a
file to open, a command to run, or a library to load.

- The pipe's ACL grants the interactive user, administrators and SYSTEM, and nobody else. Without an
  explicit ACL a pipe created by a service is reachable by every account on the machine.
- Message length is bounded *before* a byte is allocated. A length prefix an unprivileged caller
  controls is an allocation an unprivileged caller controls.
- The configuration the app can hand over is validated by the same `ConfigurationValidator` the
  engine uses for its own file, so an app-supplied rule cannot bypass the family-matching guard.

### W-8 — Configuration is machine-wide

**Severity: accepted, documented in the UI.**

Configuration lives in `%ProgramData%\SplitLane` because the engine runs as a service account and the
app runs as the user; a per-user path would be readable by exactly one of them. On a shared computer
every account's rules are visible to every other account.

This is a real property, not an oversight: the divert layer is machine-wide, so per-user rules would
be a promise the engine could not keep. The Settings page says so.

### W-9 — The credential at rest

**Severity: mitigated.**

The proxy password is a DPAPI blob scoped to the local machine, stored outside the configuration
file. It is meaningless if copied to another machine, and it never appears in the JSON that someone
would attach to a bug report.

`ConfigurationTests.EncodedConfigurationNeverContainsSecrets` enforces the structural property: there
is no field on `ProxyConfiguration` that could hold a password, only a locator. The UI can report
that a password exists; it has no path to read one back.

RFC 1929 still sends the credential to the proxy unencrypted. On loopback that is irrelevant; to a
remote proxy it is not, and the Proxy page warns when the endpoint is not loopback.

## Unverified

This section is the Windows equivalent of the macOS project's "highest open risk", and it is the most
important part of this document.

### The WinDivert reinjection path has never run against the driver

Everything in this repository builds with zero warnings, and 309 tests pass. Those tests cover the
rule engine exhaustively, the SOCKS5 codec byte by byte, the packet rewrite and its checksums against
constructed packets, the NAT table including expiry, the DNS parser including malformed input, and
the relay end-to-end against a real SOCKS5 server.

What they do **not** cover, because it needs an installed kernel driver and an elevated process:

1. **The reinjection flags.** Whether setting `Loopback` on a redirected outbound packet, and
   clearing `Outbound` on a restored reply, produces delivery the Windows stack accepts. This is the
   single most likely thing to be wrong.
2. **`WINDIVERT_ADDRESS` layout.** The struct is mirrored by hand from the ABI. It is exercised only
   by construction, never by the driver filling it in.
3. **IPv6 address word order** in socket-layer events. This is why `SocketAddressReader` calls
   WinDivert's own formatter for IPv6 rather than unpacking the words itself — but the call itself is
   unexercised.
4. **Filter acceptance.** The filter strings are written to the documented grammar and have never
   been compiled by the driver.

Until an elevated run on a machine with the driver installed confirms a selected application's
connection completing through the proxy, the correct description of the divert layer is
**implemented, compiled and unit-tested — not verified**. Anything stronger would be a claim this
work has not earned.
