# ADR W-0002 — Route on the process image path, not the signature

**Status:** accepted
**Date:** 2026-08-20
**Windows counterpart of:** ADR 0002 (use the signing identifier for routing)

## Context

macOS routes on the code signing identifier because that is the only application identity
`NEFlowMetaData` puts on a flow. There is no equivalent string on a Windows connection. What the
socket layer gives us is a **process id**, and a pid means nothing on its own — Windows recycles them
within seconds.

Candidates for a routing key derived from a pid:

1. **Full image path**, from `QueryFullProcessImageName`.
2. **Authenticode publisher**, extracted from the executable's embedded signature.
3. **Package family name**, for MSIX/Store applications only.
4. **Process name**, e.g. `chrome.exe`.

## Decision

Route on the **normalised full image path**. Capture the publisher at pick time for display and for
the hardening path, and do not consult it on the routing path.

## Rationale

**Process name is out immediately.** `chrome.exe` in `Downloads` and `chrome.exe` in `Program Files`
are not the same application, and treating them as one is a rule that routes an attacker's binary.

**Package family name is out as a primary key** because it exists only for packaged applications, and
most of what a user wants to route is not packaged.

**Publisher is out as a primary key** for two independent reasons. It is far too coarse — routing
"anything signed by Microsoft Corporation" is not a rule anyone means — and verifying it costs a
certificate chain build that can block on a revocation check. The routing decision runs once per
outbound connection on the machine; it must not touch the disk, let alone the network.

**Path wins.** It is precise, it is what a user means by "this application", and it is cheap: one
`OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` plus a cache.

The Windows key is arguably *stronger* than the macOS one. `QueryFullProcessImageName` reports the
kernel's view of the mapped image; unlike anything read from the PEB, the target process cannot lie
about it. Substituting the binary requires write access to the path, which under `Program Files`
already means administrator.

## Consequences

**Pid reuse must be handled explicitly.** `ProcessResolver` caches on `(pid, process start time)`, so
a recycled id is a cache miss rather than one application inheriting another's rule.

**A moved application stops matching.** On macOS an app that moves keeps working, because its signing
identity did not change. Here the rule is the path, so moving the executable breaks the rule. This is
the right trade — the alternative is a rule that follows a binary to wherever an attacker put it —
but it is a real difference and it is why `AppIdentity` records the capture time.

**Packaged applications will drift.** Their path contains a version, so it changes on update. Recorded
as W-4 in the threat model; `AppIdentity.IsPackaged` detects the case and the UI does not yet warn.

**The cache is bounded and cleared wholesale.** An unbounded dictionary keyed on a 32-bit pid, in an
elevated long-running service, is a slow memory leak. Carrying LRU bookkeeping on the hot path to
avoid an occasional full rebuild would be the more expensive choice.

**The publisher field exists now, unused.** Adding it later would mean every stored rule needed
re-picking, since capturing it requires the executable still to be on disk.
