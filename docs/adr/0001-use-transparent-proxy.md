# ADR 0001 — Use NETransparentProxyProvider for selective routing

**Status:** Accepted · **Date:** 2026-08-08

## Context

SplitLane must route selected applications through a proxy while leaving every other application
completely untouched. The candidate mechanisms on macOS are `NEPacketTunnelProvider`,
`NEAppProxyProvider`, and `NETransparentProxyProvider`.

## Decision

Use `NETransparentProxyProvider`.

## Rationale

Verified in `NETransparentProxyProvider.h` on the installed SDK:

> Returning NO from `handleNewFlow:` and `handleNewUDPFlow:initialRemoteEndpoint:` causes the flow
> to proceed to communicate directly with the flow's ultimate destination, instead of closing the
> flow with a "Connection Refused" error.

That single sentence is the whole reason. "Unselected apps are DIRECT" becomes a platform
guarantee rather than something we implement and can get wrong.

- `NEAppProxyProvider` refuses unhandled flows instead of passing them through — the exact
  opposite of what is needed.
- `NEPacketTunnelProvider` would require owning a TUN device and writing a userspace TCP/IP stack,
  which is a large amount of high-risk code for no benefit here, and it captures all traffic by
  default, making "untouched" impossible to honour.

We also get application identity for free via `NEFlowMetaData`, which a packet-level design would
have to reconstruct from socket tables.

## Consequences

- The provider is consulted for every flow matching the network rules, so the routing decision
  must be O(1) and allocation-light.
- We work with flows, not packets: no IP/TCP reassembly, no MTU handling, no checksums.
- UDP proxying requires SOCKS5 UDP ASSOCIATE later; until then selected-app UDP fails closed.
- macOS 11.0+ minimum from this API alone; macOS 15.0 in practice (ADR 0004).

## Alternatives rejected

Packet tunnel + userspace stack (too large, wrong default); `pf` rules (no per-app identity);
`DYLD_INSERT_LIBRARIES` shim (needs a launcher, defeats "launch normally from Dock", breaks under
hardened runtime).
