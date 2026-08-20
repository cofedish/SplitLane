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

**Severity: was a silent leak. Now reported.**

MSIX/Store applications run from a versioned directory under `C:\Program Files\WindowsApps\...`. The
path changes on every update, so a path-keyed rule stops matching silently — the application keeps
working and quietly goes DIRECT, which is exactly the failure mode this product exists to prevent.
Nothing else in the interface would have reported it.

Three things now do:

- `AppIdentity.VersionedSegment` names the directory that will change, so the warning can say *what*
  rather than gesture at a risk.
- The Applications list marks any packaged rule at the moment it is created, and every rule whose
  executable is no longer on disk — the caveat having already come true — with the plain statement
  that its traffic is going DIRECT.
- Adding a packaged application says so in the banner rather than waiting for the update to break it.

The disk check runs once per configuration load, not on the routing path.

Writing the tests for this also surfaced a real gap: `C:\Program Files\WindowsApps` was not in the
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

**Still not working, but much more precisely:**

A selected application's connection does not complete. What the trace established, in order:

1. **Loopback shape (`--redirect-loopback`, the default): the injected packet never reaches the
   stack at all.** The trace sniffer on the redirect port saw nothing, the application's SYN
   retransmitted for twenty seconds, and the connection timed out. Both injection directions were
   tried. Windows appears not to accept an injected packet onto the loopback path.

2. **Direction flipping was the mistake, not the addresses.** Asserting a direction — flipping a
   redirected packet to inbound because "it is going to a socket on this machine" — produces a packet
   WinDivert accepts and the stack discards. Leaving the direction exactly as captured and rewriting
   only the addresses lets the stack route it, which is what routing is for: a packet addressed to
   the machine's own address loops back on its own.

3. **With that corrected, the local-address shape (`--redirect-local`) delivers.** The packet now
   reaches the stack and the stack answers — the trace shows real responses on the redirect port and
   the application fails in 70 milliseconds instead of timing out after twenty seconds.

4. **The handshake still does not complete.** The response is a RST from the listener's port back to
   the application. The listener is confirmed bound and listening (`netstat` shows
   `0.0.0.0:<port> LISTENING`), so a SYN reaching it should be answered with SYN-ACK, not RST.

The remaining question is what the stack does with a segment whose source and destination are the
same local address. Answering it properly needs a packet capture — `pktmon` or Wireshark on the
loopback adapter — rather than another round of inference from counters. Everything before that point
is now confirmed working on live traffic.

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
