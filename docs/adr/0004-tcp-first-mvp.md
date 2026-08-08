# ADR 0004 — TCP-first, with UDP failed closed, and a macOS 15.0 deployment target

**Status:** Accepted · **Date:** 2026-08-08

## Context

SOCKS5 UDP ASSOCIATE is significantly more work than CONNECT and needs its own relay lifecycle.
But ignoring UDP entirely would let a selected app's QUIC/HTTP3 traffic bypass the proxy — a
silent leak, which ADR 0003 forbids.

## Decision

1. Proxy TCP via SOCKS5 CONNECT.
2. Include UDP in `includedNetworkRules` and **fail selected-app UDP closed**.
3. Unselected-app UDP returns `false` → DIRECT, exactly as before.
4. Deployment target macOS 15.0.

## Rationale

Including UDP in the rules is what makes fail-closed possible at all — excluded traffic never
reaches the provider and escapes DIRECT. Blocking pushes QUIC-capable apps onto their TCP
fallback, which Chromium, Electron and `URLSession` all implement.

DNS is not affected: `NETransparentProxyNetworkSettings` prohibits port-53 rules outright, so DNS
is structurally outside the intercept set. This was the spec's most dangerous unexamined
assumption (G-1) and it happens to be safe — but for a reason worth writing down.

macOS 15.0 because the entire modern flow API landed there: `openWithLocalFlowEndpoint:`,
`remoteFlowEndpoint`, `handleNewUDPFlow:initialRemoteFlowEndpoint:`,
`readDatagramsAndFlowEndpointsWithCompletionHandler:`, and the `nw_endpoint_t` `NENetworkRule`
initialisers. The pre-15 forms are all deprecated. Targeting 15.0 keeps the code free of
availability branches and deprecation warnings, which matters because this project treats
warnings in networking-lifecycle code as errors.

## Consequences

- Apps with no TCP fallback break when selected. Surfaced in the UI, not silent.
- macOS 14 and earlier are unsupported. Acceptable: the development machine is 15.6 and the
  target audience is current.
- SOCKS5 UDP ASSOCIATE is the first post-M10 item.
