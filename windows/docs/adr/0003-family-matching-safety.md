# ADR W-0003 — Family matching cuts on the path separator, and is refused for shared directories

**Status:** accepted
**Date:** 2026-08-20
**Windows counterpart of:** ADR 0006 (bundle-family matching)

## Context

Electron and Chromium applications do most of their networking from helper processes. On macOS those
helpers carry a signing identifier that is a dotted descendant of the parent's
(`com.example.App.helper.Renderer`), so bundle-family matching walks the dots and a rule for the app
covers its helpers.

On Windows the situation is different in two ways:

- Chromium helpers are usually the **same executable** re-launched with `--type=renderer`, so an exact
  rule already covers them. Family matching is needed less often than on macOS.
- When it *is* needed — an application that ships a separate networking helper, an updater, or a
  sandboxed child in a subdirectory — the natural analogue of "dotted descendant" is "lives under the
  same install directory".

Which introduces a hazard macOS does not have.

## Decision

Family matching means **"anything under the executable's directory"**, cut on the path-separator
boundary, and it is **refused entirely when that directory is one shared by unrelated programs**.

## Rationale

### The separator boundary

A raw prefix test would make a rule for `C:\Program Files\Codex` also match
`C:\Program Files\CodexEvil\evil.exe`. Requiring a separator at the cut point is exactly the macOS
reasoning about `com.openai.codex` and `com.openai.codexal`, transposed to paths.

`ExecutablePath.IsUnderFamilyRoot` enforces it; `RuleEngineTests.FamilyRuleDoesNotMatchASiblingDirectoryWithASharedPrefix`
covers it.

### The shared-directory guard

This is the part with no macOS counterpart, and it is the most important Windows-specific safety
check in the product.

The family of `com.apple.Safari` is Safari and its helpers, and nothing else can be in it. The
"family" of `C:\Windows\System32\curl.exe` is **every system binary on the machine**. A user ticking
"include helper processes" on a system tool would silently put the operating system into the proxy
lane — the failure would look like "my whole computer got slow and my VPN sees everything", and
nothing in the UI would explain why.

So `ExecutablePath.IsSafeFamilyRoot` refuses:

- drive roots and UNC share roots;
- `Windows`, `Windows\System32`, `Windows\SysWOW64`, `Windows\Temp`;
- `Program Files`, `Program Files (x86)`, `ProgramData`, `Users`, `Temp`;
- per-user directories matched structurally — `Users\<name>` and below it `AppData`,
  `AppData\Local`, `AppData\Roaming`, `AppData\Local\Programs`, `Desktop`, `Downloads`, `Documents`.

`C:\Program Files\Codex` is safe. `C:\Program Files` is not.

### Defence in depth

The check appears three times on purpose:

1. `AppIdentity.SupportsFamilyMatching` — so the picker can default a new rule to exact matching.
2. `AppRule.UsesFamilyMatching` — so a hand-edited or older configuration cannot request it.
3. `RuleSnapshot`'s constructor — so no future edit to either property can put `System32` into the
   family table.

`ConfigurationValidator.Sanitize` downgrades an offending stored rule rather than failing the load.
Refusing to start because one rule is too broad would leave the user with no routing at all, and the
downgrade is both safe and visible in the UI.

## Consequences

**The UI must explain a disabled control.** The "include folder" checkbox is disabled rather than
hidden for these applications, with the reason in its tooltip. "Why can I not turn this on" is a
question worth answering in place.

**Bounded ancestor walk.** Resolving a path against the family table walks at most
`ExecutablePath.AncestorWalkLimit` (12) ancestors, so a pathological path cannot turn one connection
into an unbounded number of dictionary probes on the hot path. Deriving the bound from the configured
rules instead is wrong for the same reason it is on macOS: the walk length depends on how deep the
*flow's* path is relative to the rule, not on the rule's own depth.

**Nearest ancestor wins**, so a rule on `...\App\bin` beats one on `...\App` for a binary in `bin`,
and an exact rule beats both.
