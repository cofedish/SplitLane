# ADR W-0010 — Match packaged applications by package family

**Status:** Accepted; extended by [W-0013](0013-match-applications-by-verified-identity.md), which reads
the package family from the process token instead of the path, so a package moved to another drive
still matches and a directory that merely looks like `WindowsApps` claims nothing.
**Date:** 2026-08-21
**Relates to:** [W-0002](0002-route-on-image-path.md) (route on image path), [W-0003](0003-family-matching-safety.md) (shared-directory refusal)

## Context

W-0002 routes on the normalised image path. For a packaged application - anything installed from the
Store - that path is:

```
C:\Program Files\WindowsApps\OpenAI.Codex_26.818.3698.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe
```

The version is in the directory name, and an update installs beside the old one under a different
name. So an exact rule on a packaged application is guaranteed to stop matching, silently, at its
next update. The UI said as much, in a warning that offered nothing to do about it.

The fix that works elsewhere does not work here. For an application that installs itself into
versioned directories - Squirrel's `app-1.0.9254`, which Discord and Slack ship - the family root
climbs one level and covers every version. For a packaged application the level above is
`WindowsApps`, shared by every packaged application on the machine, and W-0003 refuses it. Correctly:
a family rule rooted there would put every Store application into the proxy lane at once.

## Decision

**A packaged application is matched on its package family name.**

The family name is the package's name and its publisher hash, with the version and architecture
between them discarded: `openai.codex_2p2nqsd0c76g0`. It is stable for as long as the application is
installed, and it is no broader than an exact rule - one application, one publisher. The publisher
hash is derived from the publisher's certificate subject, so a different publisher shipping a package
of the same name produces a different family.

`MatchMode.PackageFamily` is the stored form, and it is the default for a packaged application. The
lookup is a dictionary hit on the family computed from the candidate path, tried before the ancestor
walk - a packaged application's ancestors are `WindowsApps` and above, which no rule may be rooted
at, so walking them for it can only ever come up empty.

**A rule asking for `ExecutableFamily` on a packaged application is honoured as package matching.**
It means the same thing the person meant when they ticked the box - cover the rest of this
application, not only the file I picked - and the install directory cannot deliver it. This also
means rules written before this existed start working rather than waiting to be re-made.

An `Exact` rule on a packaged application stays exact. Somebody who asked for one executable gets one
executable.

## Consequences

- A selected packaged application keeps working across its updates, which is the entire point.
- One checkbox now drives two mechanisms. The person is not asked to know which; picking the wrong
  one for them is the difference between a rule that survives an update and one that does not.
- The warning on packaged rules is gone when the rule matches by package, and the view model asks
  `AppRule.UsesPackageMatching` rather than re-deriving the answer - a second copy of that reasoning
  disagreed with the engine once already, and the visible form of the disagreement was a warning
  telling somebody to repair a rule that was working.
- Matching identity is now two things rather than one: a path, or a package family. W-0002 still
  holds for everything that is not packaged.
- The publisher hash is trusted as an identifier without the signature being checked at match time.
  Since W-0013 it is read from the process token, which Windows sets at activation, rather than from
  the path; packages registered from unsigned layouts (Developer Mode) are not treated as package
  identities at all. See `docs/THREAT_MODEL.md`.
