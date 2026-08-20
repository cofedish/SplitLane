# ADR W-0009 — Ship the divert driver in the package

**Status:** Accepted
**Date:** 2026-08-21
**Supersedes:** the "fetch it yourself" half of [W-0001](0001-windivert-and-loopback-nat.md). The
choice of WinDivert itself stands unchanged.

## Context

W-0001 chose WinDivert and, separately, decided not to redistribute it: the repository has not chosen
a licence of its own, and vendoring somebody else's signed kernel driver seemed like a decision that
should be made explicitly rather than inherited by everyone who clones the repository. The installer
shipped `fetch-windivert.ps1` instead, and the engine's error message pointed at it.

That reasoning was about the repository. It was applied to the product, and the product is where it
did damage.

What it produced, observed on a real machine immediately after installing v0.2.0:

- The service starts and reports **Faulted**, because there is no driver.
- The remedy names `tools\fetch-windivert.ps1`, a path that exists in a source checkout and not on
  the machine reading the message, where it is `C:\Program Files\SplitLane\Tools\`.
- Running the installed script put the driver in `C:\Program Files\SplitLane\runtime\windivert`,
  because its default destination was written for the repository layout. The engine looks next to
  itself. So following the instruction exactly still left the product Faulted.

Somebody who runs an installer has installed the thing. Handing them a PowerShell script, an
undocumented path and a wrong default afterwards is not a product, and no amount of correctness in
the reasoning behind it changes that.

## Decision

**The driver ships inside the installer and the portable archive.**

`build-installer.ps1` downloads it during packaging, from the official WinDivert release, pinned by
SHA-256, and refuses to produce a package if the binaries or their licence are missing.

Licence compliance is part of the decision, not an afterthought:

- WinDivert is dual-licensed **LGPL v3 or GPL v2**, and redistribution is permitted on those terms.
- `WinDivert-LICENSE.txt` — the upstream `LICENSE`, unmodified — is installed next to the binaries,
  and the packaging step fails if it is absent.
- `THIRD-PARTY-NOTICES.txt` at the install root names the component, its version, its copyright, its
  upstream URL and its licence.
- The binaries are redistributed **unmodified**, and SplitLane reaches them through P/Invoke rather
  than static linking, so a user may substitute another build of the same version. That is what
  LGPL v3 §4 asks of a work that uses the library.

`fetch-windivert.ps1` stays, for development checkouts and for anyone who would rather fetch the
driver themselves. Its default destination now depends on the layout it finds itself in, and the
download is verified against the pinned hash by default rather than on request.

## Consequences

- Installing SplitLane produces a working SplitLane. This is the entire point.
- The package is ~140 KB larger.
- The project now redistributes third-party software and carries the obligations that come with it.
  Changing the pinned WinDivert version means checking the new archive's hash and confirming the
  licence file still travels with it — the packaging step enforces the second automatically.
- A build machine needs network access at packaging time. It already did, for NuGet.
- The pinned hash is now load-bearing in a way it was not before: what this downloads is what gets
  handed to other people's kernels. It is checked by default, and the version and the hash are
  changed together or not at all.

## Alternatives considered

**Keep fetching, but fix the paths and add a button to the app.** Would have removed the wrong-path
defect and most of the friction, and it was the smaller change. Rejected because it keeps a working
installation two steps away from an installation, and because the first of those steps is a download
the user has no way to verify.

**Fetch during installation, from a custom action.** Puts a network operation inside an elevated MSI
transaction, where a failure has to be handled as a rollback and an offline machine cannot install at
all. The download belongs at packaging time, where it is done once and checked once.

**Bundle only for the MSI, not the portable archive.** Two artifacts of the same release differing in
whether the product works is precisely the kind of divergence that produced the last defect here.
