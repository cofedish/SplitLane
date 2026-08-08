# ADR 0002 — Route on code signing identifier, not path or bundle identifier

**Status:** Accepted · **Date:** 2026-08-08

## Context

The routing key must match what `NEFlowMetaData` actually provides at runtime. Candidates: file
path, bundle identifier, signing identifier, audit token.

## Decision

`AppRule.signingIdentifier` is the primary routing key, matched against
`flow.metaData.sourceAppSigningIdentifier`. Path, bundle identifier and team identifier are stored
for display and future verification, never as the routing key.

## Rationale

- The provider is only ever handed the signing identifier and an audit token. A path is not
  available, so path matching would require resolving the audit token to a process to a
  executable on every flow — expensive and racy.
- `NEFlowMetaData.h` says the signing identifier is "almost always equivalent to the bundle
  identifier". "Almost always" is not "always", so the two are captured separately at pick time
  and the runtime one is used for matching. `ApplicationInspector` reads the signing identifier
  from `SecStaticCode`, so a mismatch is visible in the UI rather than a silent non-match.
- The audit token is the only cryptographically meaningful identity, but resolving it properly
  costs a `SecCode` evaluation. That is the M6.5 hardening path (F-2), cached on
  `(pid, pidversion)`, not the per-flow default.

## Consequences

- An empty signing identifier (system-process flows) routes DIRECT, and the validator rejects
  empty identifiers in rules so an empty key can never exist. See G-6.
- Signing identifiers can be forged by any local binary. The impact is asymmetric — an attacker
  gains use of the proxy, not a bypass of it — which is why this is acceptable for the MVP. See
  F-2 in `docs/THREAT_MODEL.md`.
- Moving or renaming an app does not break its rule. Re-signing it with a different identifier
  does, which is the correct behaviour.
