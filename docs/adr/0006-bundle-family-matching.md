# ADR 0006 — Match the bundle family, not just the exact signing identifier

**Status:** Accepted · **Date:** 2026-08-08

## Context

The original rule engine was an exact set membership test:
`signingIdentifier ∈ selectedApps → PROXY`.

Electron and Chromium applications perform essentially all networking from **helper** processes,
not from the main bundle. Those helpers have their own signing identifiers:

```
com.openai.codex
com.openai.codex.helper
com.openai.codex.helper.Renderer
com.openai.codex.helper.GPU
```

With exact matching the user selects Codex, the provider sees `com.openai.codex.helper`, misses,
and returns DIRECT. **The app works perfectly and is completely unproxied.** A silent leak that
presents as success is the worst failure mode this product can have, and it would have hit the
flagship use case on day one.

## Decision

`RuleEngine` resolves an identifier by:

1. Exact dictionary lookup.
2. On miss, walk dotted-prefix ancestors, longest first, up to a bounded depth (8):
   `a.b.c.d` → `a.b.c` → `a.b` → `a`.
3. A rule matches an ancestor only in `.bundleFamily` mode (the default). `.exact` mode stops
   after step 1.

Matching is on **dot-separated label boundaries**, never raw string prefixes.

## Rationale

The dot boundary is the security-relevant part. `hasPrefix("com.openai.codex")` would also match
`com.openai.codexal.evil` — a trivial way for an unrelated app to enter the proxy lane. Splitting
on `.` and comparing whole labels makes that impossible. The unit test that matters most here is
the near-miss rejection, not the positive case.

Bounded depth keeps the lookup O(1)-ish and prevents a pathological identifier from causing
unbounded work on the flow path.

Longest-first means a specific rule for `com.example.App.helper` wins over a general rule for
`com.example.App` when both exist.

## Consequences

- Selecting an app captures its helpers, which is what the user means by "route this app".
- It also captures genuinely separate apps that happen to be dotted descendants — e.g. a rule for
  `com.google.Chrome` captures `com.google.Chrome.canary`. Acceptable, and `.exact` mode is
  available per rule for users who need precision.
- M4 must record Codex's actual helper identifiers so this decision is validated against reality
  rather than against an assumption about how Codex is built.
