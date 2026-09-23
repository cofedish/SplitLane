# Tasks: stable application identity (Windows)

## Phase 1 — reproduce
- [x] T1 Regression tests that fail on the current code (5 scenarios red before the fix; TCP Block
      shown by code reading: recorded as "leave alone").

## Phase 2 — core identity (SplitLane.Core, pure)
- [x] T2 `PublisherName`, `ImageEvidence`, `IdentityKind`, `RuleStatus`.
- [x] T3 `RuleSnapshot.Match(evidence)`: package, signed exact/product/location, unsigned hash,
      location pin, legacy path; `IdentityPending`/`IdentityMismatch`.
- [x] T4 Volatile directories and `FamilyScope` (narrowed after the live run).
- [x] T5 Migration schema 1 -> 2 behind `IImageInspector`.
### Checkpoint A: core tests green, zero warnings. ✔

## Phase 3 — Windows evidence
- [x] T6 WinVerifyTrust (embedded + catalog), stamp, SHA-256, package family (agent, reviewed).

## Phase 4 — engine
- [x] T7 ProcessResolver package family + `ImageCatalog`.
- [x] T8 Held TCP SYN / UDP until verified; re-decide on completion.
- [x] T9 NAT verdicts: Block and Pending drop.
- [x] T10 Background migration, v2 beside v1.
- [x] T11 `--explain`, `--describe`.
### Checkpoint B: all tests green; `--explain` on live processes. ✔

## Phase 5 — app
- [x] T12 Picker/rows/migration in the app (agent; reviewed by reading; run via uiprobe without saving).

## Phase 6 — verification, enterprise stage, docs, review
- [x] T13a Unelevated runtime evidence on this machine (`--explain`, engine tests with real processes).
- [x] T13b Elevated divert script written; `-DryRun` validated unelevated. **Not run elevated.**
- [x] T14 Enterprise readiness plan + managed policy (engine side).
- [x] T15 ADR W-0013/W-0014, ENTERPRISE_READINESS, CLAUDE.md; doc drift (agent).
- [x] T16 Two reviews (correctness, security); all Critical/High/Medium fixed; residuals documented.
- [x] T17 Security re-review of the fixes; its findings (policy folder ancestry) fixed.

## Phase 7 — owner decisions (2026-09-23)
- [x] T18 README rewritten for the Windows client; macOS kept as a section.
- [x] T19 Engine restarts routing itself when a divert thread dies (backoff 2 s → 5 min); a fault during
  a restart is not lost (regression test fails without the fix).
- [x] T20 MSI sets service recovery (sc failure + failureflag). MSI built, 0 warnings, tables checked;
  **not installed**, needs elevation. A routing start that fails at boot is retried by the engine (tested).
- [x] T21 DNS: why an unproxied lookup is bad and when it matters (NETWORKING §7).
- [x] T22 Residuals: PDB name discriminator and stale-pin blocking fixed; the rest documented with reasons.
- [ ] T23 Live: `tools/verify-identity.ps1` elevated; MSI on a clean VM, kill the engine, `sc qfailure`.
