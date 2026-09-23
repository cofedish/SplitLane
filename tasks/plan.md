# Implementation Plan: stable application identity (Windows)

Scope: `windows/` only. The macOS build in the repository root is not touched.

## Overview

A rule for a selected application stops matching after the application updates or its folder moves,
and the application's traffic silently goes DIRECT. Observed live on the development machine: two of
three Codex rules point at `...\OpenAI\Codex\bin\247581e40ee272fb\codex.exe` and
`...\runtimes\cua_node\df473e5367fa2b42\...`, both directories are gone after an update, and the
running `codex.exe` is in `...\bin\d375f7df50d3b421\`.

Root cause: the persistent identity of a Win32 rule is its image path (ADR W-0002). "Include folder"
climbs out of `app-1.2.3`/`1.2.3` directories only, so a content-hash directory, a version directory
that is not the direct parent, a renamed install folder, a moved folder, a packaged app moved to
another drive, or an 8.3 path spelling all break the match. Path-folder matching is also too broad in
the other direction: any unsigned file dropped into the folder inherits the rule.

## Architecture decisions

- **Identity kinds** (`AppIdentity.Kind`): `Signed` (verified Authenticode subject + product name +
  file name), `Package` (package family name, read from the process token), `Unsigned` (SHA-256 of the
  file), `Path` (the v1 behaviour, kept for migration and tests). Path is never the persistent identity
  of a new rule.
- **Publisher key** = canonical CN/O/L/S/C of the leaf signer subject. Not the thumbprint and not the
  issuer: the two installed `codex.exe` builds are signed by different certificates from different
  intermediate CAs with the same subject.
- **Scope** (`MatchMode`): Exact = this binary of this publisher, any location/version. Family = also
  the same publisher's binaries of the same product, or under the same install root with
  version/hash directories stripped. Family is refused for unsigned binaries and for shared runtime
  products (Windows, .NET, Electron, Node.js, OpenJDK), mirroring the W-0003 shared-directory guard.
- **Location pin**: a file at the rule's recorded path whose identity no longer matches is BLOCKED and
  reported, not sent DIRECT and not proxied.
- **Verification off the hot path.** A 320 MB `codex.exe` takes ~1.5 s to verify. The socket pump
  decides with cheap evidence (path, file name, package family from the token, product name when
  needed); a flow whose rule depends on an unverified claim is held (SYN dropped, datagrams dropped)
  while a background worker verifies once per file version; TCP retransmits the SYN (initial RTO 1 s).
- **TCP Block must block.** Today a TCP `Block` decision is recorded as "leave alone" and goes out.
- **Migration** schema 1 -> 2 is done by both App and Engine with the same code; the result is
  written to a new file so an older build can still start after a rollback.

## Task list

See `tasks/todo.md`.

## Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Held SYN delays the first connection of a newly updated app by ~1-3 s | Med | Once per file version; cache keyed on file stamp; documented |
| Verification wrongly fails (catalog, policy) and blocks a selected app | High | Explicit Invalid/Unsigned states, logged once per image, visible in UI and `--explain` |
| Publisher renames its certificate subject | Med | Location pin blocks + reports at the old path; elsewhere DIRECT and logged as a near miss |
| Rollback to <= 0.9.x with a schema 2 file | High | v2 written beside v1; v1 left untouched |
| Signed-file TOCTOU (herpaderping/ghosting) | Low | Requires local code execution; documented; WDAC/AppLocker is the control for hostile local code |

## Open questions

- Should product-family matching require a minimum file version (AppLocker style)? Not now.
- Fleet-managed rules need identity-only rules (no path). Covered by the enterprise stage.
