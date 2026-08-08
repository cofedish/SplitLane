# ADR 0003 — Selected applications fail closed

**Status:** Accepted · **Date:** 2026-08-08

## Context

When a selected application's traffic cannot be delivered through the proxy — upstream refused,
authentication rejected, handshake timed out, protocol unsupported — the provider must either fall
back to DIRECT or fail the connection.

## Decision

Fail closed. Never fall back to DIRECT for a selected application.

## Rationale

Silent fallback converts a visible error into an invisible leak. The user believes the app is
proxied; it is not; nothing tells them. For a tool whose entire promise is "selected traffic does
not leak", that is a total failure of the product's one guarantee — and it fails in the direction
the user cannot detect.

A failed connection is loud, diagnosable, and correct.

## Consequences

- A misconfigured or stopped proxy makes selected apps lose connectivity. The Proxy and
  Applications screens must surface the reason clearly, or this becomes "SplitLane is broken".
- Applies to: connection refused, SOCKS negotiation failure, auth failure, non-zero SOCKS reply,
  timeout, and unsupported protocols (UDP, until UDP ASSOCIATE lands).
- `ProxyConfiguration.allowDirectFallback` exists, defaults to `false`, and has no UI in the MVP.
  It is a deliberate future opt-in, documented as a downgrade of the security property.
- Not covered: provider downtime. If the provider is not running there is nothing to fail closed
  *with*; the kernel routes normally. See F-4.
