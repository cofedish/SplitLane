# ADR W-0001 — Intercept with WinDivert and redirect through a loopback NAT

**Status:** accepted; superseded in part by [W-0009](0009-ship-the-driver-in-the-package.md), which
ships the driver in the package, fetched at build time against a pinned SHA-256. The choice of
WinDivert and the loopback NAT stand.
**Date:** 2026-08-20
**Supersedes on Windows:** ADR 0001 (use a transparent proxy provider)

## Context

The macOS build is built on `NETransparentProxyProvider`. The provider is handed each new flow before
a socket exists and returns `false` for the flows it does not want, at which point the kernel keeps
the flow untouched. Every guarantee in the product's README follows from that one API.

Windows has no user-mode equivalent. The options are:

1. **WFP from user mode** (`fwpuclnt.dll`). Can permit and block by application. Cannot redirect —
   `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4` is reachable only from a kernel callout driver.
2. **Our own WFP callout driver.** The closest technical match to macOS. Requires either an
   EV-attested signature or asking every user to enable test signing.
3. **DLL injection** into target processes, hooking `connect`/`WSAConnect`. What Proxifier does. No
   driver, but it writes into other people's processes, fails on protected processes, and looks like
   malware to endpoint protection.
4. **Packet interception** via a third-party signed driver — WinDivert, or Windows Packet Filter.

## Decision

Use **WinDivert** at two layers, and destination-NAT selected connections to a loopback listener.

The socket layer supplies the process id at `connect()` time and makes the routing decision in
advance. The network layer rewrites packets for connections already decided, and reinjects everything
else byte-for-byte.

## Rationale

**Against our own driver.** It is the technically correct answer and the wrong one to make quietly. A
driver means an attestation signature or test signing, and either is a decision a port should surface
to its users rather than inherit for them. This can be revisited; it should be revisited by someone
who has decided to ship, not by someone doing a port.

**Against injection.** It would let SplitLane claim "unselected apps are untouched" more literally
than packet interception does, because it touches nothing but the selected process. But it requires
writing into other processes, and a network tool that behaves like malware is a network tool nobody
can deploy on a managed machine.

**For WinDivert.** It is signed, widely deployed, has a stable documented API, and — critically for
this design — its socket layer solves the identity problem that the network layer cannot. Without a
layer that reports a process id, per-application routing on Windows is guesswork correlated through
`GetExtendedTcpTable`, which races.

**For loopback NAT over other redirection shapes.** Once packets are the medium, the destination has
to move somewhere a user-mode listener can accept it. Both endpoints must move to loopback together:
a packet addressed `192.168.1.5 → 127.0.0.1` is a martian and the stack drops it.

## Consequences

**Accepted:** every outbound packet on the machine transits user mode while routing is active. This
is the largest behavioural difference from macOS and is stated plainly in the README, in the
Settings page, and in the threat model as W-1. Loopback is excluded from the outbound filter, which
removes the majority of traffic on a developer machine. The handles are *not* closed when nothing
needs routing: they stay open while routing is paused and while no rule selects anything, and only
stopping routing closes them. An earlier version of this record said otherwise.

**Accepted:** SplitLane depends on a third-party kernel driver. The repository does not vendor it,
because committing a driver binary is a supply-chain decision that should not be inherited by
everyone who clones; `fetch-windivert.ps1` is how a source checkout gets one. **Superseded for the
product by W-0009:** the installer and the portable archive ship the driver and its licence, fetched
during packaging against a pinned SHA-256, because an installed product that has to be sent to a
script before it works is not installed.

**Accepted:** correctness now depends on packet arithmetic — address rewriting and checksums — that
fails silently when wrong. Mitigated by keeping that arithmetic in pure functions over a buffer
(`PacketView`, `RedirectRewriter`) with no WinDivert types in the signature, covered by tests that
run with no driver.
